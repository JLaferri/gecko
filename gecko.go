package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	OutputFiles []string
	Codes       []CodeDescription
}

type CodeDescription struct {
	Name        string
	Authors     []string
	Description []string
	Build       []GeckoCode
}

type GeckoCode struct {
	Type          string
	Address       string
	TargetAddress string
	Annotation    string
	IsRecursive   bool
	SourceFile    string
	SourceFolder  string
	Value         string
}

type compileResult struct {
	Order int
	Lines []string
}

const (
	Replace          = "replace"
	Inject           = "inject"
	ReplaceCodeBlock = "replaceCodeBlock"
	Branch           = "branch"
	BranchAndLink    = "branchAndLink"
	InjectFolder     = "injectFolder"
	ReplaceBinary    = "replaceBinary"
)

var output []string

func timeTrack(start time.Time) {
	elapsed := time.Since(start)
	fmt.Printf("Process time was %s\n", elapsed)
}

func main() {
	defer func(startTime time.Time) {
		// Recover from panic to prevent printing stack trace
		r := recover()
		if r == nil {
			// Here we completed successfully, in that case, show time output
			timeTrack(startTime)
		}
	}(time.Now())

	if len(os.Args) < 2 {
		log.Panic("Must provide a command. Try typing 'gecko build'\n")
	}

	outputFilePaths := []string{}

	command := os.Args[1]
	switch command {
	case "build":
		config := readConfigFile()
		if len(config.OutputFiles) < 1 {
			log.Panic("Must have at least one output file configured in the outputFiles field\n")
		}

		buildBody(config)
		outputFilePaths = config.OutputFiles
	case "assemble":
		assembleFlags := flag.NewFlagSet("assemble", flag.ExitOnError)
		outputFilePtr := assembleFlags.String(
			"o",
			"Codes.txt",
			"The output file path. Using a .gct extension will output a gct. Everything else will output text.",
		)
		assemblePathPtr := assembleFlags.String(
			"p",
			".",
			"The root directory to assemble. Will default to the current directory.",
		)
		isRecursivePtr := assembleFlags.Bool(
			"r",
			true,
			"If true, will recursively find all .asm files within the sub-directories as well as the root directory.",
		)
		assembleFlags.Parse(os.Args[2:])

		outputFilePaths = append(outputFilePaths, *outputFilePtr)
		output = generateInjectionFolderLines(*assemblePathPtr, *isRecursivePtr)
	default:
		log.Panic("Currently only the build and assemble commands are supported. Try typing 'gecko build'\n")
	}

	// Write output
	for _, file := range outputFilePaths {
		writeOutput(file)
	}
}

func readConfigFile() Config {
	contents, err := ioutil.ReadFile("codes.json")
	if err != nil {
		log.Panic("Failed to read config file codes.json\n", err)
	}

	var result Config
	err = json.Unmarshal(contents, &result)
	if err != nil {
		log.Panic(
			"Failed to get json content from config file. Check for syntax error/valid json\n",
			err,
		)
	}

	return result
}

func buildBody(config Config) {
	// go through every code and print a header and the codes that make it up
	for _, code := range config.Codes {
		headerLines := generateHeaderLines(code)
		output = append(output, headerLines...)

		codeLines := generateCodeLines(code)
		// TODO: Add description
		output = append(output, codeLines...)
		output = append(output, "")
	}
}

func generateHeaderLines(desc CodeDescription) []string {
	result := []string{}

	authorString := strings.Join(desc.Authors, ", ")
	result = append(result, fmt.Sprintf("$%s [%s]", desc.Name, authorString))

	for _, line := range desc.Description {
		result = append(result, fmt.Sprintf("*%s", line))
	}

	return result
}

func generateCodeLines(desc CodeDescription) []string {
	result := []string{}

	for _, geckoCode := range desc.Build {
		switch geckoCode.Type {
		case Replace:
			line := generateReplaceCodeLine(geckoCode.Address, geckoCode.Value)
			line = addLineAnnotation(line, geckoCode.Annotation)
			result = append(result, line)
		case Inject:
			lines := generateInjectionCodeLines(geckoCode.Address, geckoCode.SourceFile)
			lines[0] = addLineAnnotation(lines[0], geckoCode.Annotation)
			result = append(result, lines...)
		case ReplaceCodeBlock:
			lines := generateReplaceCodeBlockLines(geckoCode.Address, geckoCode.SourceFile)
			lines[0] = addLineAnnotation(lines[0], geckoCode.Annotation)
			result = append(result, lines...)
		case ReplaceBinary:
			lines := generateReplaceBinaryLines(geckoCode.Address, geckoCode.SourceFile)
			lines[0] = addLineAnnotation(lines[0], geckoCode.Annotation)
			result = append(result, lines...)
		case Branch:
			fallthrough
		case BranchAndLink:
			shouldLink := geckoCode.Type == BranchAndLink
			line := generateBranchCodeLine(geckoCode.Address, geckoCode.TargetAddress, shouldLink)
			line = addLineAnnotation(line, geckoCode.Annotation)
			result = append(result, line)
		case InjectFolder:
			lines := generateInjectionFolderLines(geckoCode.SourceFolder, geckoCode.IsRecursive)
			result = append(result, lines...)
		}
	}

	return result
}

func generateReplaceCodeLine(address, value string) string {
	// TODO: Add error if address or value is incorrect length/format
	return fmt.Sprintf("04%s %s", strings.ToUpper(address[2:]), strings.ToUpper(value))
}

func generateBranchCodeLine(address, targetAddress string, shouldLink bool) string {
	// TODO: Add error if address or value is incorrect length/format

	addressUint, err := strconv.ParseUint(address[2:], 16, 32)
	targetAddressUint, err := strconv.ParseUint(targetAddress[2:], 16, 32)
	if err != nil {
		log.Panic("Failed to parse address or target address.", err)
	}

	addressDiff := targetAddressUint - addressUint
	prefix := "48"
	if addressDiff < 0 {
		prefix = "4B"
	}

	if shouldLink {
		addressDiff += 1
	}

	// TODO: Add error if diff is going to be more than 6 characters long

	// Convert diff to hex string, and then for negative values, we
	addressDiffStr := fmt.Sprintf("%06X", addressDiff)
	addressDiffStr = addressDiffStr[len(addressDiffStr)-6:]

	return fmt.Sprintf("04%s %s%s", strings.ToUpper(address[2:]), prefix, addressDiffStr)
}

func addLineAnnotation(line, annotation string) string {
	if annotation == "" {
		return line
	}

	return fmt.Sprintf("%s #%s", line, annotation)
}

func generateInjectionFolderLines(rootFolder string, isRecursive bool) []string {
	lines := []string{}
	asmFilePaths := []string{}

	// First collect all of the asm files we need to process
	folders := []string{rootFolder}
	for len(folders) > 0 {
		folder := folders[0]
		folders = folders[1:]

		contents, err := ioutil.ReadDir(folder)
		if err != nil {
			log.Panic("Failed to read directory.", err)
		}

		newFolders := []string{}

		// Go through the files in this directory and collect asm files
		for _, file := range contents {
			// If this file is a directory and we are recursing,
			// add this folder to folders for finding new files
			if file.IsDir() && isRecursive {
				folderName := file.Name()
				folderPath := filepath.Join(folder, folderName)
				newFolders = append(newFolders, folderPath)
				continue
			}

			fileName := file.Name()
			ext := filepath.Ext(fileName)
			if ext != ".asm" {
				continue
			}

			// Here we have an asm file, let's collect it
			filePath := filepath.Join(folder, fileName)
			asmFilePaths = append(asmFilePaths, filePath)
		}

		// Add new folders to front to do depth-first ordering
		folders = append(newFolders, folders...)
	}

	processedFileCount := 0
	resultsChan := make(chan compileResult, len(asmFilePaths))
	for _, filePath := range asmFilePaths {
		file, err := os.Open(filePath)
		if err != nil {
			log.Panicf("Failed to read file at %s\n%s\n", filePath, err.Error())
		}
		defer file.Close()

		// Read first line from file to get address
		scanner := bufio.NewScanner(file)
		scanner.Scan()
		firstLine := scanner.Text()

		// Prepare injection address error
		indicateAddressError := func(errStr ...string) {
			errMsg := fmt.Sprintf(
				"File at %s needs to specify the 4 byte injection address "+
					"at the end of the first line of the file\n",
				filePath,
			)

			if len(errStr) > 0 {
				errMsg += errStr[0] + "\n"
			}

			log.Panic(errMsg)
		}

		// Get address
		lineLength := len(firstLine)
		if lineLength < 8 {
			indicateAddressError()
		}
		address := firstLine[lineLength-8:]

		_, err = hex.DecodeString(address)
		if err != nil {
			indicateAddressError(err.Error())
		}

		go func(address, filePath string, orderNum int) {
			// Compile file and add lines
			fileLines := generateInjectionCodeLines(address, filePath)
			fileLines[0] = addLineAnnotation(fileLines[0], filePath)
			resultsChan <- compileResult{Order: orderNum, Lines: fileLines}
		}(address, filePath, processedFileCount)

		processedFileCount++
	}

	// Aggregate all of the results from our channel
	results := []compileResult{}
	for i := 0; i < processedFileCount; i++ {
		results = append(results, <-resultsChan)
	}

	// Sort the results based on their order
	sort.Slice(results, func(i, j int) bool {
		return results[i].Order < results[j].Order
	})

	// Add the results back to lines
	for _, result := range results {
		lines = append(lines, result.Lines...)
	}

	return lines
}

func generateInjectionCodeLines(address, file string) []string {
	// TODO: Add error if address or value is incorrect length/format
	lines := []string{}

	instructions := compile(file)
	instructionLen := len(instructions)

	if instructionLen == 0 {
		log.Panicf("Did not find any code in file: %s\n", file)
	}

	if instructionLen == 4 {
		// If instructionLen is 4, this can be a 04 code instead of C2
		instructionStr := hex.EncodeToString(instructions[0:4])
		replaceLine := generateReplaceCodeLine(address, instructionStr)
		lines = append(lines, replaceLine)

		return lines
	}

	// Fixes code to always end with 0x00000000 and have an even number of words
	if instructionLen%8 == 0 {
		instructions = append(instructions, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	} else {
		instructions = append(instructions, 0x00, 0x00, 0x00, 0x00)
	}

	lines = append(lines, fmt.Sprintf("C2%s %08X", strings.ToUpper(address[2:]), len(instructions)/8))

	for i := 0; i < len(instructions); i += 8 {
		left := strings.ToUpper(hex.EncodeToString(instructions[i : i+4]))
		right := strings.ToUpper(hex.EncodeToString(instructions[i+4 : i+8]))
		lines = append(lines, fmt.Sprintf("%s %s", left, right))
	}

	return lines
}

func generateReplaceCodeBlockLines(address, file string) []string {
	// TODO: Add error if address or value is incorrect length/format
	lines := []string{}

	instructions := compile(file)

	// Fixes code to have an even number of words
	if len(instructions)%8 != 0 {
		instructions = append(instructions, 0x60, 0x00, 0x00, 0x00)
	}

	lines = append(lines, fmt.Sprintf("06%s %08X", strings.ToUpper(address[2:]), len(instructions)))

	for i := 0; i < len(instructions); i += 8 {
		left := strings.ToUpper(hex.EncodeToString(instructions[i : i+4]))
		right := strings.ToUpper(hex.EncodeToString(instructions[i+4 : i+8]))
		lines = append(lines, fmt.Sprintf("%s %s", left, right))
	}

	return lines
}

func generateReplaceBinaryLines(address, file string) []string {
	// TODO: Add error if address or value is incorrect length/format
	lines := []string{}

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panicf("Failed to read binary file %s\n%s\n", file, err.Error())
	}

	instructions := contents

	// Fixes code to have an even number of words
	if len(instructions)%8 != 0 {
		instructions = append(instructions, 0x60, 0x00, 0x00, 0x00)
	}

	lines = append(lines, fmt.Sprintf("06%s %08X", strings.ToUpper(address[2:]), len(instructions)))

	for i := 0; i < len(instructions); i += 8 {
		left := strings.ToUpper(hex.EncodeToString(instructions[i : i+4]))
		right := strings.ToUpper(hex.EncodeToString(instructions[i+4 : i+8]))
		lines = append(lines, fmt.Sprintf("%s %s", left, right))
	}

	return lines
}

func compile(file string) []byte {
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
	asmContents, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panicf("Failed to read asm file: %s\n%s\n", file, err.Error())
	}

	// Explicitly add a new line at the end of the file, which should prevent line skip
	asmContents = append(asmContents, []byte("\r\n")...)
	err = ioutil.WriteFile(compileFilePath, asmContents, 0644)
	if err != nil {
		log.Panicf("Failed to write temporary asm file\n%s\n", err.Error())
	}

	if runtime.GOOS == "windows" {
		cmd := exec.Command("powerpc-gekko-as.exe", "-a32", "-mbig", "-mregnames", "-mgekko", "-o", outputFilePath, compileFilePath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Failed to compile file: %s\n", file)
			fmt.Printf("%s", output)
			panic("as failure")
		}
		contents, err := ioutil.ReadFile(outputFilePath)
		if err != nil {
			log.Panicf("Failed to read compiled file %s\n%s\n", file, err.Error())
		}

		// I don't understand how this works (?)
		codeEndIndex := bytes.Index(contents, []byte{0x00, 0x2E, 0x73, 0x79, 0x6D, 0x74, 0x61, 0x62})
		return contents[52:codeEndIndex]
	}

	// Just pray that powerpc-eabi-{as,objcopy} are in the user's $PATH, lol
	if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
		cmd := exec.Command("powerpc-eabi-as", "-a32", "-mbig", "-mregnames", "-o", outputFilePath, compileFilePath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("Failed to compile file: %s\n", file)
			fmt.Printf("%s", output)
			panic("as failure")
		}
		cmd = exec.Command("powerpc-eabi-objcopy", "-O", "binary", outputFilePath, outputFilePath)
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
		return contents
	}

	log.Panicf("Platform unsupported\n")
	return nil
}

func writeOutput(outputFile string) {
	fmt.Printf("Writing to %s...\n", outputFile)
	ext := filepath.Ext(outputFile)
	switch ext {
	case ".gct":
		writeGctOutput(outputFile)
	default:
		writeTextOutput(outputFile)
	}

	fmt.Printf("Successfuly wrote codes to %s\n", outputFile)
}

func writeTextOutput(outputFile string) {
	fullText := strings.Join(output, "\n")
	ioutil.WriteFile(outputFile, []byte(fullText), 0644)
}

func writeGctOutput(outputFile string) {
	gctBytes := []byte{0x00, 0xD0, 0xC0, 0xDE, 0x00, 0xD0, 0xC0, 0xDE}

	for _, line := range output {
		if len(line) < 17 {
			// lines with less than 17 characters cannot be code lines
			continue
		}

		lineBytes, err := hex.DecodeString(line[0:8] + line[9:17])
		if err != nil {
			// If parse fails that likely means this is a header or something
			continue
		}

		gctBytes = append(gctBytes, lineBytes...)
	}

	gctBytes = append(gctBytes, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	ioutil.WriteFile(outputFile, gctBytes, 0644)
}
