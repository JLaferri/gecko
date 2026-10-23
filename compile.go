package main

import (
	"debug/elf"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"unicode"
)

var useBatching bool
var useWarnings bool
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
	failed  bool
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

	// This runs on its own goroutine where a panic would crash the process with a stack trace.
	// Instead every job still waiting is told the batch failed so the panic happens on the
	// goroutine that asked for the job, which recovers from it. Jobs are answered in order
	answered := 0
	defer func() {
		if r := recover(); r != nil {
			for _, job := range jobs[answered:] {
				job.response <- compileResponse{failed: true}
			}
		}
	}()

	requested := []cacheResult{}
	for _, job := range jobs {
		requested = append(requested, cacheResult{File: job.inputFile, AddressExp: job.addressExp})
	}

	// Files assembled together can see each other's symbols and macros so a change to any one of
	// them can change the code of the rest. Because of that a batch is cached as a whole
	slot := ""
	if useCache {
		slot = cacheSlot("batched", argConfig.InputPath)
		results := cacheLookup(slot, requested)
		if results != nil {
			resultsByKey := map[string]cacheResult{}
			for _, result := range results {
				resultsByKey[cacheResultKey(result)] = result
			}

			for idx, job := range jobs {
				result := resultsByKey[cacheResultKey(requested[idx])]
				job.response <- compileResponse{code: result.Code, address: result.Address}
				answered++
			}
			return
		}
	}

	// Keep intermediate files in a temp directory unique to this build so they can't collide
	// with the files of another build running at the same time
	tempDir := makeTempDir()
	compileWaitGroup.Add(1)
	defer func() {
		defer compileWaitGroup.Done()
		os.RemoveAll(tempDir)
	}()

	outputFilePath := filepath.Join(tempDir, "compiled.elf")
	copyFilePath := filepath.Join(tempDir, "copied.elf")
	depFilePath := filepath.Join(tempDir, "compiled.d")

	// Generate temp file names
	for idx := range jobs {
		jobs[idx].tempFile = filepath.Join(tempDir, fmt.Sprintf("file%d.asmtemp", idx))
		jobs[idx].outFile = filepath.Join(tempDir, fmt.Sprintf("file%d.out", idx))
	}

	// Set base args
	args := []string{"-a32", "-mbig", "-mregnames", "-mgekko"}
	if !useWarnings {
		args = append(args, "--fatal-warnings")
	}

	// If defsym is defined, add it to the args
	args = append(args, defsymArgs()...)

	includeDirs := []string{argConfig.ProjectRoot}

	// Add local paths to look at when resolving includes
	for _, job := range jobs {
		file := job.inputFile
		fileDir := filepath.Dir(file)
		includeDirs = append(includeDirs, fileDir)
	}

	for _, dir := range includeDirs {
		args = append(args, "-I", dir)
	}

	// Have the assembler list every file it reads so the cache can tell when the code is out of date
	if useCache {
		args = append(args, "--MD", depFilePath)
	}

	// Set output file
	args = append(args, "-o", outputFilePath)

	// Iterate through jobs, create temp files, and add them to the files to assemble
	for idx, job := range jobs {
		buildTempAsmFile(job.inputFile, job.addressExp, job.tempFile, fmt.Sprintf(".file%d", idx))
		args = append(args, job.tempFile)
	}

	cmd := exec.Command(asCmdLinux, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// Show errors against the names the temp files used to have next to their sources so it's
		// clear which source each error came from
		pathPairs := []string{}
		for idx, job := range jobs {
			file := job.inputFile
			fileNoExt := file[0 : len(file)-len(filepath.Ext(file))]
			pathPairs = append(pathPairs, job.tempFile, fmt.Sprintf("%s-file%d.asmtemp", fileNoExt, idx))
		}

		fmt.Printf("Failed to compile files\n")
		fmt.Printf("%s", strings.NewReplacer(pathPairs...).Replace(string(output)))
		panic("as failure")
	}

	// Only the .fileN sections are pulled out into codes
	messages := findUnresolvedSymbols(outputFilePath, func(section *elf.Section) (string, bool) {
		var idx int
		_, err := fmt.Sscanf(section.Name, ".file%d", &idx)
		if err != nil || section.Name != fmt.Sprintf(".file%d", idx) || idx >= len(jobs) {
			return "", false
		}

		return jobs[idx].inputFile, true
	})
	if len(messages) > 0 {
		fmt.Printf("Failed to compile files\n")
		fmt.Printf("%s\n", strings.Join(messages, "\n"))
		panic("unresolved symbols")
	}

	// Give objcopy an output file. Without one it converts in place by way of a temp file it
	// creates next to the input, which can fail (see compile)
	args = []string{outputFilePath, copyFilePath}
	for idx, job := range jobs {
		args = append(args, "--dump-section", fmt.Sprintf(".file%d=%s", idx, job.outFile))
	}

	cmd = exec.Command(objcopyCmdLinux, args...)
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to pull extract code sections\n")
		fmt.Printf("%s", output)
		panic("objcopy failure")
	}

	results := []cacheResult{}
	sources := []string{}
	asmFiles := []string{}
	for idx, job := range jobs {
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

		result := requested[idx]
		result.Code = code
		result.Address = fmt.Sprintf("%x", address)
		results = append(results, result)
		sources = append(sources, job.inputFile)
		asmFiles = append(asmFiles, job.tempFile)

		job.response <- compileResponse{code: result.Code, address: result.Address}
		answered++
	}

	// The order of the include paths after the project root depends on the order the jobs came in,
	// which varies from build to build
	if useCache {
		cacheStore(slot, results, sources, depFilePath, asmFiles, includeDirs, 1)
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
	if result.failed {
		// The batch already printed why it failed
		panic("batch compile failure")
	}

	return result.code, result.address
}

// defsymArgs returns the assembler args for the symbols given with -defsym. The assembler takes one
// symbol per -defsym and quietly ignores anything after the first, so each gets its own
func defsymArgs() []string {
	args := []string{}
	for _, def := range argConfig.DefSyms {
		args = append(args, "-defsym", def)
	}

	return args
}

func makeTempDir() string {
	tempDir, err := os.MkdirTemp("", "gecko-")
	if err != nil {
		log.Panicf("Failed to create temp directory\n%s\n", err.Error())
	}

	return tempDir
}

func compile(file, addressExp string) ([]byte, string) {
	if useBatching {
		return batchCompile(file, addressExp)
	}

	slot := ""
	if useCache {
		slot = cacheSlot("single", file, addressExp)
		results := cacheLookup(slot, []cacheResult{{File: file, AddressExp: addressExp}})
		if results != nil {
			return results[0].Code, results[0].Address
		}
	}

	// Keep intermediate files in a temp directory unique to this compile. They used to sit next
	// to the source file and objcopy converted them in place, which makes it create a temp file
	// of its own in that directory. objcopy picks the same temp names in every process, so
	// compiling files from the same folder at once would sometimes fail with "Permission denied"
	// when one process tried to create a name another had just deleted
	tempDir := makeTempDir()
	defer os.RemoveAll(tempDir)

	compileFilePath := filepath.Join(tempDir, "code.asmtemp")
	outputFilePath := filepath.Join(tempDir, "code.elf")
	binaryFilePath := filepath.Join(tempDir, "code.bin")
	depFilePath := filepath.Join(tempDir, "code.d")

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
	if !useWarnings {
		args = append(args, "--fatal-warnings")
	}

	// If defsym is defined, add it to the args
	args = append(args, defsymArgs()...)

	// Add paths to look at when resolving includes
	includeDirs := []string{fileDir, argConfig.ProjectRoot}
	for _, dir := range includeDirs {
		args = append(args, "-I", dir)
	}

	// Have the assembler list every file it reads so the cache can tell when the code is out of date
	if useCache {
		args = append(args, "--MD", depFilePath)
	}

	// Set output file
	args = append(args, "-o", outputFilePath, compileFilePath)

	cmd := exec.Command(asCmdLinux, args...)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// The temp file has the same lines as the source file so point errors at the source
		fmt.Printf("Failed to compile file: %s\n", file)
		fmt.Printf("%s", strings.ReplaceAll(string(output), compileFilePath, file))
		panic("as failure")
	}

	// Converting to binary puts every section that's loaded into memory into the code
	messages := findUnresolvedSymbols(outputFilePath, func(section *elf.Section) (string, bool) {
		return file, section.Flags&elf.SHF_ALLOC != 0
	})
	if len(messages) > 0 {
		fmt.Printf("Failed to compile file: %s\n", file)
		fmt.Printf("%s\n", strings.Join(messages, "\n"))
		panic("unresolved symbols")
	}

	cmd = exec.Command(objcopyCmdLinux, "-O", "binary", outputFilePath, binaryFilePath)
	output, err = cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to pull out .text section: %s\n", file)
		fmt.Printf("%s", output)
		panic("objcopy failure")
	}
	contents, err := ioutil.ReadFile(binaryFilePath)
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

	result := cacheResult{File: file, AddressExp: addressExp, Code: code, Address: fmt.Sprintf("%x", address)}
	if useCache {
		cacheStore(slot, []cacheResult{result}, []string{file}, depFilePath, []string{compileFilePath}, includeDirs, len(includeDirs))
	}

	return result.Code, result.Address
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
