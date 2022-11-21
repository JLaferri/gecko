package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

var useBatching bool
var compileWaitGroup sync.WaitGroup
var toCompileCount uint32
var compileJobs []compileJob
var jobMtx sync.Mutex

type symbolInfo struct {
	name    string
	linePos int
}

type labelInfo struct {
	name    string
	num     int
	linePos int
}

type compileResponse struct {
	code    []byte
	address string
}

type compileJob struct {
	inputFile  string
	tempFile   string
	outFile    string
	addressExp string
	response   chan compileResponse
}

func execBatchCompile(jobs []compileJob) {
	const asCmdLinux string = "powerpc-eabi-as"
	const objcopyCmdLinux string = "powerpc-eabi-objcopy"

	deleteFile := func(fp string) {
		defer compileWaitGroup.Done()
		os.Remove(fp)
	}

	outputFilePath := path.Join(argConfig.ProjectRoot, "compiled.elf")
	compileWaitGroup.Add(1)
	defer deleteFile(outputFilePath)

	// Generate temp file names
	for idx, job := range jobs {
		file := job.inputFile
		fileExt := filepath.Ext(file)
		fileNoExt := file[0 : len(file)-len(fileExt)]
		jobs[idx].tempFile = fmt.Sprintf("%s-file%d.asmtemp", fileNoExt, idx)
		jobs[idx].outFile = fmt.Sprintf("%s-file%d.out", fileNoExt, idx)
	}

	// Set base args
	args := []string{"-a32", "-mbig", "-mregnames", "-mgekko", "-W"}

	// If defsym is defined, add it to the args
	if argConfig.DefSym != "" {
		args = append(args, "-defsym", argConfig.DefSym)
	}

	args = append(args, "-I", argConfig.ProjectRoot)

	// Add local paths to look at when resolving includes
	for _, job := range jobs {
		file := job.inputFile
		fileDir := filepath.Dir(file)
		args = append(args, "-I", fileDir)
	}

	// Set output file
	args = append(args, "-o", outputFilePath)

	// Iterate through jobs, create temp files, and add them to the files to assemble
	for idx, job := range jobs {
		compileWaitGroup.Add(1)
		defer deleteFile(job.tempFile)

		buildTempAsmFile(job.inputFile, job.addressExp, job.tempFile, fmt.Sprintf(".file%d", idx))
		args = append(args, job.tempFile)
	}

	cmd := exec.Command(asCmdLinux, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to compile files")
		fmt.Printf("%s", output)
		panic("as failure")
	}

	args = []string{outputFilePath}
	for idx, job := range jobs {
		compileWaitGroup.Add(1)
		defer deleteFile(job.outFile)

		args = append(args, "--dump-section", fmt.Sprintf(".file%d=%s", idx, job.outFile))
	}

	cmd = exec.Command(objcopyCmdLinux, args...)
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to pull extract code sections\n")
		fmt.Printf("%s", output)
		panic("objcopy failure")
	}

	for _, job := range jobs {
		contents, err := ioutil.ReadFile(job.outFile)
		if err != nil {
			log.Panicf("Failed to read compiled file %s\n%s\n", job.outFile, err.Error())
		}

		code := contents[:len(contents)-4]
		address := contents[len(contents)-4:]
		if address[0] != 0x80 && address[0] != 0x81 {
			log.Panicf(
				"Injection address in file %s evaluated to a value that does not start with 0x80 or 0x81"+
					", probably an invalid address\n",
				job.inputFile,
			)
		}

		job.response <- compileResponse{code: code, address: fmt.Sprintf("%x", address)}
	}
}

func batchCompile(file, addressExp string) ([]byte, string) {
	c := make(chan compileResponse)
	jobMtx.Lock()
	compileJobs = append(compileJobs, compileJob{
		inputFile:  file,
		addressExp: addressExp,
		response:   c,
	})

	if len(compileJobs) >= int(toCompileCount) {
		go execBatchCompile(compileJobs)
	}
	jobMtx.Unlock()

	result := <-c
	return result.code, result.address
}

func compile(file, addressExp string) ([]byte, string) {
	if useBatching {
		return batchCompile(file, addressExp)
	}

	fileExt := filepath.Ext(file)
	outputFilePath := file[0:len(file)-len(fileExt)] + ".out"
	compileFilePath := file[0:len(file)-len(fileExt)] + ".asmtemp"

	// Clean up files
	defer os.Remove(outputFilePath)
	defer os.Remove(compileFilePath)

	// First we are gonna load all the data from file and write it into temp file
	// Technically this shouldn't be necessary but for some reason if the last line
	// or the asm file has one of more spaces at the end and no new line, the last
	// instruction is ignored and not compiled
	buildTempAsmFile(file, addressExp, compileFilePath, "")

	fileDir := filepath.Dir(file)

	const asCmdLinux string = "powerpc-eabi-as"
	const objcopyCmdLinux string = "powerpc-eabi-objcopy"

	// Set base args
	args := []string{"-a32", "-mbig", "-mregnames", "-mgekko"}

	// If defsym is defined, add it to the args
	if argConfig.DefSym != "" {
		args = append(args, "-defsym", argConfig.DefSym)
	}

	// Add paths to look at when resolving includes
	args = append(args, "-I", fileDir, "-I", argConfig.ProjectRoot)

	// Set output file
	args = append(args, "-o", outputFilePath, compileFilePath)

	cmd := exec.Command(asCmdLinux, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to compile file: %s\n", file)
		fmt.Printf("%s", output)
		panic("as failure")
	}

	cmd = exec.Command(objcopyCmdLinux, "-O", "binary", outputFilePath, outputFilePath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to pull out .text section: %s\n", file)
		fmt.Printf("%s", output)
		panic("objcopy failure")
	}
	contents, err := ioutil.ReadFile(outputFilePath)
	if err != nil {
		log.Panicf("Failed to read compiled file %s\n%s\n", file, err.Error())
	}

	code := contents[:len(contents)-4]
	address := contents[len(contents)-4:]
	if address[0] != 0x80 && address[0] != 0x81 {
		log.Panicf(
			"Injection address in file %s evaluated to a value that does not start with 0x80 or 0x81"+
				", probably an invalid address\n",
			file,
		)
	}

	return code, fmt.Sprintf("%x", address)
}

func isSymbolRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_'
}

func splitAny(s string, seps string) []string {
	splitter := func(r rune) bool {
		return strings.ContainsRune(seps, r)
	}
	return strings.FieldsFunc(s, splitter)
}

func removeComments(asmContents []byte) []byte {
	body := string(asmContents)

	// Remove block comments
	newBody := ""
	idx := strings.Index(body, "/*")
	for idx > -1 {
		newBody += body[:idx]
		body = body[idx:]
		end := strings.Index(body, "*/")
		if end > -1 {
			body = body[end+2:]
		}
		idx = strings.Index(body, "/*")
	}
	newBody += body

	// Remove line comments
	lines := strings.Split(newBody, "\n")
	newLines := []string{}
	for _, line := range lines {
		// Remove any comments
		commentSplit := strings.Split(line, "#")
		if len(commentSplit) == 0 {
			newLines = append(newLines, line)
			continue
		}
		newLines = append(newLines, strings.TrimSpace(commentSplit[0]))
	}

	return []byte(strings.Join(newLines, "\n"))
}

func isolateLabelNames(asmContents []byte) []byte {
	// Start logic to isolate label names
	// First we're going to extract all label positions as well as replace them with a number
	// based label which functions as a local label. This will prevent errors from using
	// the same label name in multiple files
	lines := strings.Split(string(asmContents), "\n")
	labels := map[string]labelInfo{}
	newLines := []string{}
	labelIdx := 100 // Start at 100 because hopefully no macros will use labels that high
	for lineNum, line := range lines {
		isLabel := len(line) > 0 && line[len(line)-1] == ':'
		if !isLabel {
			newLines = append(newLines, line)
			continue
		}

		name := line[:len(line)-1]
		labels[name] = labelInfo{name, labelIdx, lineNum}
		newLines = append(newLines, fmt.Sprintf("%d:", labelIdx))
		labelIdx += 1
	}

	// Now let's convert all the branch instructions we can find to use the local labels
	// instead of the original label names
	// TODO: It might be possible to throw errors here if referencing a label that doesn't exist
	// TODO: I didn't do it yet because currently instructions like `branchl r12, ...` might
	// TODO: trigger the easy form of detection. We'd probably have to detect all possible branch
	// TODO: instructions in order to do this
	finalLines := []string{}
	for lineNum, line := range newLines {
		parts := splitAny(line, " \t")
		if len(parts) == 0 {
			finalLines = append(finalLines, line)
			continue
		}

		label := parts[len(parts)-1]
		li, labelExists := labels[label]
		isBranch := len(parts) >= 2 && line[0] == 'b' && labelExists
		if !isBranch {
			finalLines = append(finalLines, line)
			continue
		}

		dir := "f"
		if lineNum > li.linePos {
			dir = "b"
		}

		parts[len(parts)-1] = fmt.Sprintf("%d%s", li.num, dir)
		finalLines = append(finalLines, strings.Join(parts, " "))
	}

	return []byte(strings.Join(finalLines, "\n"))
}

func isolateSymbolNames(asmContents []byte, section string) []byte {
	lines := strings.Split(string(asmContents), "\n")
	symbolMap := map[string][]symbolInfo{}
	newLines := []string{}
	for idx, line := range lines {
		parts := splitAny(line, " \t,")
		if len(parts) == 0 {
			newLines = append(newLines, line)
			continue
		}

		isSet := parts[0] == ".set" && len(parts) >= 3
		if !isSet {
			newLines = append(newLines, line)
			continue
		}

		newSymbol := fmt.Sprintf("__%s_symbol_%d", section, idx)

		// Add this symbol to map
		_, exists := symbolMap[parts[1]]
		if !exists {
			symbolMap[parts[1]] = []symbolInfo{}
		}
		symbolMap[parts[1]] = append(symbolMap[parts[1]], symbolInfo{newSymbol, idx})

		newLines = append(newLines, strings.Replace(line, parts[1], newSymbol, 1))
	}

	finalLines := []string{}
	for lineIdx, line := range newLines {
		if len(line) == 0 {
			finalLines = append(finalLines, line)
			continue
		}

		symbolParts := strings.FieldsFunc(line, func(r rune) bool { return !isSymbolRune(r) })
		connectingParts := strings.FieldsFunc(line, isSymbolRune)

		for symbolIdx, symbol := range symbolParts {
			instances, exists := symbolMap[symbol]
			if !exists {
				continue
			}

			remap := instances[0].name
			for _, instance := range instances {
				if instance.linePos > lineIdx {
					break
				}
				remap = instance.name
			}

			symbolParts[symbolIdx] = remap
		}

		reconnected := []string{}
		first, second := symbolParts, connectingParts
		shouldSwap := !isSymbolRune(rune(line[0]))
		if shouldSwap {
			first, second = connectingParts, symbolParts
		}

		for partIdx, part1 := range first {
			reconnected = append(reconnected, part1)
			if partIdx < len(second) {
				reconnected = append(reconnected, second[partIdx])
			}
		}

		finalLines = append(finalLines, strings.Join(reconnected, ""))
	}

	return []byte(strings.Join(finalLines, "\n"))
}

func buildTempAsmFile(sourceFilePath, addressExp, targetFilePath, section string) {
	asmContents, err := ioutil.ReadFile(sourceFilePath)
	if err != nil {
		log.Panicf("Failed to read asm file: %s\n%s\n", sourceFilePath, err.Error())
	}

	// If section provided, we need to take some precautions to isolate the code from others
	if section != "" {
		// Add the section label at the top so the code can be extracted individually
		asmContents = append([]byte(fmt.Sprintf(".section %s\n", section)), asmContents...)

		asmContents = removeComments(asmContents)
		asmContents = isolateLabelNames(asmContents)
		asmContents = isolateSymbolNames(asmContents, section)
	}

	// Add new line before .set for address
	asmContents = append(asmContents, []byte("\n")...)

	// Add .set to get file injection address
	setLine := fmt.Sprintf(".long %s\n", addressExp)
	asmContents = append(asmContents, []byte(setLine)...)

	// Explicitly add a new line at the end of the file, which should prevent line skip
	asmContents = append(asmContents, []byte("\n")...)
	err = ioutil.WriteFile(targetFilePath, asmContents, 0644)
	if err != nil {
		log.Panicf("Failed to write temporary asm file: %s\n%s\n", targetFilePath, err.Error())
	}
}
