package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

type Config struct {
	OutputFiles []FileDetails
	Codes       []CodeDescription
}

type FileDetails struct {
	File   string
	Header []string
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

type lineAggregateResult struct {
	Order   int
	Lines   []string
	IsError bool
}

const (
	Inject        = "inject"
	InjectFolder  = "injectFolder"
	ReplaceBinary = "replaceBinary"
	Binary        = "binary"
)

type assemblerArgConfig struct {
	ProjectRoot string
	DefSym      string
}

type asmFileHeader struct {
	Address    string
	Codetype   string
	Annotation string
	Tags       string
}

var argConfig assemblerArgConfig

var output []string

func timeTrack(start time.Time) {
	elapsed := time.Since(start)
	fmt.Printf("Assembled %d files. Process time was %s\n", toCompileCount, elapsed)
}

func main() {
	defer func(startTime time.Time) {
		// Recover from panic to prevent printing stack trace
		r := recover()
		if r == nil {
			// Here we completed successfully, in that case, show time output
			timeTrack(startTime)
		} else {
			os.Exit(1)
		}
	}(time.Now())

	if len(os.Args) < 2 {
		log.Panic("Must provide a command. Try typing 'gecko build'\n")
	}

	outputFiles := []FileDetails{}

	// Ensure assembler files can be found
	confirmAssembler()

	addDefsymFlag := func(fs *flag.FlagSet) *string {
		return fs.String(
			"defsym",
			"",
			"Allows the defining of symbols from the command line. Example: \"EX_SYM1=10,EX_SYM2=0xABC\"",
		)
	}

	addIsRecursiveFlag := func(fs *flag.FlagSet) *bool {
		return fs.Bool(
			"r",
			true,
			"If true, will recursively find all .asm files within the sub-directories as well as the root directory.",
		)
	}

	addBatchedFlag := func(fs *flag.FlagSet) *bool {
		return fs.Bool(
			"batched",
			false,
			"If true, all files will be batched and assembled together. This does have some quirks, visit github for details.",
		)
	}

	addWarningsFlag := func(fs *flag.FlagSet) *bool {
		return fs.Bool(
			"warn",
			false,
			"If true, warnings will not be treated as errors",
		)
	}

	command := os.Args[1]
	switch command {
	case "build":
		buildFlags := flag.NewFlagSet("build", flag.ExitOnError)
		configFilePathPtr := buildFlags.String(
			"c",
			"codes.json",
			"Used to specify a path to a config file.",
		)
		outputFilePtr := buildFlags.String(
			"o",
			"",
			"Additional output file path. Using a .gct extension will output a gct. Everything else will output text. Will be appended to the files in the config file.",
		)
		defsymPtr := addDefsymFlag(buildFlags)
		batchedPtr := addBatchedFlag(buildFlags)
		warnPtr := addWarningsFlag(buildFlags)
		buildFlags.Parse(os.Args[2:])

		useBatching = *batchedPtr
		useWarnings = *warnPtr

		config := readConfigFile(*configFilePathPtr)
		outputFiles = config.OutputFiles
		if *outputFilePtr != "" {
			outputFiles = append(outputFiles, FileDetails{File: *outputFilePtr})
		}
		if len(outputFiles) < 1 {
			log.Panic("Must have at least one output file configured in the outputFiles field\n")
		}

		configDir := filepath.Dir(*configFilePathPtr)
		projectRootTemp, err := filepath.Abs(configDir)
		if err != nil {
			log.Panic("Failed to convert project root dir\n", err)
		}

		argConfig.ProjectRoot = projectRootTemp
		argConfig.DefSym = *defsymPtr

		countFilesToCompile(config)
		buildBody(config)
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
		isRecursivePtr := addIsRecursiveFlag(assembleFlags)
		defsymPtr := addDefsymFlag(assembleFlags)
		batchedPtr := addBatchedFlag(assembleFlags)
		warnPtr := addWarningsFlag(assembleFlags)
		assembleFlags.Parse(os.Args[2:])

		useBatching = *batchedPtr
		useWarnings = *warnPtr

		configDir := filepath.Dir(*assemblePathPtr)
		projectRootTemp, err := filepath.Abs(configDir)
		if err != nil {
			log.Panic("Failed to convert project root dir\n", err)
		}

		argConfig.ProjectRoot = projectRootTemp
		argConfig.DefSym = *defsymPtr

		// Calculate the number of files that will be compiled
		asmFilePaths := collectFilesFromFolder(*assemblePathPtr, *isRecursivePtr)
		atomic.AddUint32(&toCompileCount, uint32(len(asmFilePaths)))

		outputFiles = append(outputFiles, FileDetails{File: *outputFilePtr})
		output = generateInjectionFolderLines(*assemblePathPtr, *isRecursivePtr)
	case "list":
		listFlags := flag.NewFlagSet("list", flag.ExitOnError)
		inputPtr := listFlags.String(
			"i",
			"codes.json",
			"Input to use for generating the list. Can be a json file as used with build or a path as used with assemble.",
		)
		outputFilePtr := listFlags.String(
			"o",
			"injection-list.json",
			"Output file name where the list will be saved.",
		)
		isRecursivePtr := addIsRecursiveFlag(listFlags)
		listFlags.Parse(os.Args[2:])
		listInjections(*inputPtr, *outputFilePtr, *isRecursivePtr)
	case "-h":
		// Print help information
		fmt.Println("Usage: gecko <command> [flags]")
		fmt.Println()
		fmt.Println("Supported commands:")
		fmt.Println("\tbuild - Uses a configuration file to build codes. Recommended for larger projects.")
		fmt.Println("\tassemble - Assembles asm files in a given directory.")
		fmt.Println("\tlist - Outputs a list of all the injections ")
		fmt.Println()
		fmt.Println("Use gecko <command> -h for information about the flags for the different commands")
		os.Exit(1)
	default:
		log.Panic("Currently only the build and assemble commands are supported. Try typing 'gecko build'\n")
	}

	// Write output
	for _, file := range outputFiles {
		writeOutput(file)
	}

	compileWaitGroup.Wait()
}

func readConfigFile(path string) Config {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		log.Panic("Failed to read config file\n", err)
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

func countFilesToCompile(config Config) {
	for _, desc := range config.Codes {
		for _, geckoCode := range desc.Build {
			switch geckoCode.Type {
			case Inject:
				atomic.AddUint32(&toCompileCount, 1)
			case InjectFolder:
				asmFilePaths := collectFilesFromFolder(geckoCode.SourceFolder, geckoCode.IsRecursive)
				atomic.AddUint32(&toCompileCount, uint32(len(asmFilePaths)))
			}
		}
	}
}

func buildBody(config Config) {
	// go through every code and print a header and the codes that make it up
	resultsChan := make(chan lineAggregateResult, len(config.Codes))
	for idx, code := range config.Codes {
		go func(code CodeDescription, orderNum int) {
			defer func() {
				if r := recover(); r != nil {
					// Add recover to prevent stack traces
					resultsChan <- lineAggregateResult{IsError: true}
				}
			}()

			lines := []string{}

			headerLines := generateHeaderLines(code)
			lines = append(lines, headerLines...)

			codeLines := generateCodeLines(code)

			lines = append(lines, codeLines...)
			lines = append(lines, "")

			resultsChan <- lineAggregateResult{Order: orderNum, Lines: lines}
		}(code, idx)
	}

	results := processLineAggregators(resultsChan, len(config.Codes))
	output = append(output, results...)
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

func processLineAggregators(resultsChan chan lineAggregateResult, length int) []string {
	// Aggregate all of the results from our channel
	results := []lineAggregateResult{}
	for i := 0; i < length; i++ {
		var result = <-resultsChan
		results = append(results, result)
	}

	// If any results returned an error, panic after all goroutines complete,
	// this is primarily done so that all of the defer calls actually execute
	for _, result := range results {
		if result.IsError {
			log.Panicf("Failed to process at least one line aggregator\n")
		}
	}

	// Sort the results based on their order
	sort.Slice(results, func(i, j int) bool {
		return results[i].Order < results[j].Order
	})

	// Add the results back to lines
	lines := []string{}
	for _, result := range results {
		lines = append(lines, result.Lines...)
	}

	return lines
}

func generateCodeLines(desc CodeDescription) []string {
	resultsChan := make(chan lineAggregateResult, len(desc.Build))
	for idx, geckoCode := range desc.Build {
		go func(geckoCode GeckoCode, orderNum int) {
			defer func() {
				if r := recover(); r != nil {
					// Add recover to prevent stack traces
					resultsChan <- lineAggregateResult{IsError: true}
				}
			}()

			switch geckoCode.Type {
			case Inject:
				header := parseAsmFileHeader(geckoCode.SourceFile)
				codetype := header.Codetype
				address := header.Address
				if codetype == "" {
					codetype = geckoCode.Type
				}
				if address == "" {
					address = geckoCode.TargetAddress
				}
				// Compile file and add lines
				lines := generateCompiledCodeLines(address, codetype, geckoCode.SourceFile)
				lineAnnotation := filepath.ToSlash(geckoCode.SourceFile)
				if header.Annotation != "" {
					lineAnnotation = fmt.Sprintf("%s | %s", header.Annotation, lineAnnotation)
				}
				if geckoCode.Annotation != "" {
					lineAnnotation = fmt.Sprintf("%s | %s", geckoCode.Annotation, lineAnnotation)
				}
				lines[0] = addLineAnnotation(lines[0], lineAnnotation)
				resultsChan <- lineAggregateResult{Order: orderNum, Lines: lines}
			case ReplaceBinary:
				lines := generateReplaceBinaryLines(geckoCode.Address, geckoCode.SourceFile)
				lines[0] = addLineAnnotation(lines[0], geckoCode.Annotation)
				resultsChan <- lineAggregateResult{Order: orderNum, Lines: lines}
			case Binary:
				lines := generateBinaryLines(geckoCode.SourceFile)
				lines[0] = addLineAnnotation(lines[0], geckoCode.Annotation)
				resultsChan <- lineAggregateResult{Order: orderNum, Lines: lines}
			case InjectFolder:
				lines := generateInjectionFolderLines(geckoCode.SourceFolder, geckoCode.IsRecursive)
				resultsChan <- lineAggregateResult{Order: orderNum, Lines: lines}
			default:
				log.Panicf("Unsupported build type: %s\n", geckoCode.Type)
			}
		}(geckoCode, idx)
	}

	return processLineAggregators(resultsChan, len(desc.Build))
}

func generateReplaceCodeLine(address, value string) string {
	return fmt.Sprintf("%s %s", combineCodetypeAndAddress("04", address), strings.ToUpper(value))
}

func addLineAnnotation(line, annotation string) string {
	if annotation == "" {
		return line
	}

	return fmt.Sprintf("%s #%s", line, annotation)
}

func collectFilesFromFolder(rootFolder string, isRecursive bool) []string {
	asmFilePaths := []string{}

	// First collect all of the asm files we need to process
	folders := []string{rootFolder}
	for len(folders) > 0 {
		folder := folders[0]
		folders = folders[1:]

		contents, err := ioutil.ReadDir(folder)
		if err != nil {
			log.Panicf("Failed to read directory at \"%s\"\n%s\n", folder, err.Error())
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

	return asmFilePaths
}

func generateInjectionFolderLines(rootFolder string, isRecursive bool) []string {
	asmFilePaths := collectFilesFromFolder(rootFolder, isRecursive)

	resultsChan := make(chan lineAggregateResult, len(asmFilePaths))
	for idx, filePath := range asmFilePaths {
		go func(filePath string, orderNum int) {
			defer func() {
				if r := recover(); r != nil {
					// Add recover to prevent stack traces
					resultsChan <- lineAggregateResult{IsError: true}
				}
			}()

			header := parseAsmFileHeader(filePath)

			// Compile file and add lines
			fileLines := generateCompiledCodeLines(header.Address, header.Codetype, filePath)
			lineAnnotation := filepath.ToSlash(filePath)
			if header.Annotation != "" {
				lineAnnotation = fmt.Sprintf("%s | %s", header.Annotation, lineAnnotation)
			}

			fileLines[0] = addLineAnnotation(fileLines[0], lineAnnotation)
			resultsChan <- lineAggregateResult{Order: orderNum, Lines: fileLines}
		}(filePath, idx)
	}

	return processLineAggregators(resultsChan, len(asmFilePaths))
}

func parseAsmFileHeader(filePath string) asmFileHeader {
	file, err := os.Open(filePath)
	if err != nil {
		log.Panicf("Failed to read file at %s\n%s\n", filePath, err.Error())
	}
	defer file.Close()

	// Prepare injection address error
	indicateParseError := func(errStr ...string) {
		errMsg := fmt.Sprintf(
			"File at %s has an invalid header format.",
			filePath,
		)

		if len(errStr) > 0 {
			errMsg += " " + errStr[0]
		}

		log.Panic(errMsg + "\n")
	}

	result := asmFileHeader{"", "Auto", "", ""}

	// Read header lines from file
	scanner := bufio.NewScanner(file)
	for i := 0; i < 5; i++ {
		scanner.Scan()
		line := strings.TrimSpace(scanner.Text())
		if i == 0 {
			// For the first line, attempt to support the old header style
			lineLength := len(line)
			if lineLength < 8 {
				indicateParseError("First line too short.")
			}
			result.Address = fmt.Sprintf("0x%s", line[lineLength-8:])
		}

		sections := strings.SplitN(line, " ", 3)
		if len(sections) < 3 || sections[0] != "#" {
			continue
		}

		key := sections[1]
		value := sections[2]

		switch key {
		case "Address:":
			// Special case: handle address without 0x
			_, err = hex.DecodeString(value)
			if err == nil && len(value) == 8 {
				value = fmt.Sprintf("0x%s", value)
			}

			result.Address = value
		case "Codetype:":
			result.Codetype = value
		case "Annotation:":
			result.Annotation = value
		case "Tags:":
			result.Tags = value
		}
	}

	// Note that address here can be any string. It will get added to a .set to evaluate injection
	// address

	// Error if Address is empty or is not length 8
	if result.Address == "" {
		indicateParseError("Address is missing")
	}

	// Check to make sure codetype is valid
	ct := result.Codetype
	if ct != "Auto" && ct != "C2" && ct != "04" && ct != "06" {
		indicateParseError("Codetype not supported. Valid options: Auto, C2, 04, 06")
	}

	return result
}

func generateCompiledCodeLines(addressExp, codetype, file string) []string {
	instructions, address := compile(file, addressExp)
	instructionLen := len(instructions)

	if instructionLen == 0 {
		log.Panicf("Did not find any code in file: %s\n", file)
	}

	forcedCt := codetype
	if codetype == "Auto" && instructionLen == 4 {
		forcedCt = "04"
	} else if codetype == "Auto" {
		forcedCt = "C2"
	}

	switch forcedCt {
	case "04":
		if instructionLen != 4 {
			log.Panicf("File %s is configured to be a 04 code and should contain only one instruction\n", file)
		}

		instructionStr := hex.EncodeToString(instructions[0:4])
		replaceLine := generateReplaceCodeLine(address, instructionStr)

		return []string{replaceLine}
	case "06":
		return getReplaceLinesFromInstructions(address, instructions)
	case "C2":
		return getInjectLinesFromInstructions(address, instructions)
	default:
		log.Panicf("File %s has an invalid codetype\n", file)
		return []string{}
	}
}

func combineCodetypeAndAddress(codetype, address string) string {
	addressBytes, err := hex.DecodeString(address)
	if err != nil {
		log.Panicf("Failed to parse address from hex string: %s", address)
	}

	codetypeBytes, err := hex.DecodeString(codetype)
	if err != nil {
		log.Panicf("Failed to parse codetype from hex string: %s", codetype)
	}

	addressBytes[0] = (addressBytes[0] & 1) + codetypeBytes[0]
	return strings.ToUpper(hex.EncodeToString(addressBytes))
}

func getInjectLinesFromInstructions(address string, instructions []byte) []string {
	lines := []string{}
	instructionLen := len(instructions)

	// Fixes code to always end with 0x00000000 and have an even number of words
	if instructionLen%8 == 0 {
		instructions = append(instructions, 0x60, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	} else {
		instructions = append(instructions, 0x00, 0x00, 0x00, 0x00)
	}

	lines = append(lines, fmt.Sprintf("%s %08X", combineCodetypeAndAddress("C2", address), len(instructions)/8))

	for i := 0; i < len(instructions); i += 8 {
		left := strings.ToUpper(hex.EncodeToString(instructions[i : i+4]))
		right := strings.ToUpper(hex.EncodeToString(instructions[i+4 : i+8]))
		lines = append(lines, fmt.Sprintf("%s %s", left, right))
	}

	return lines
}

func getReplaceLinesFromInstructions(address string, instructions []byte) []string {
	lines := []string{}
	codeBlockLen := len(instructions)

	// Fixes code to have an even number of words
	if len(instructions)%8 != 0 {
		instructions = append(instructions, 0x00, 0x00, 0x00, 0x00)
	}

	lines = append(lines, fmt.Sprintf("%s %08X", combineCodetypeAndAddress("06", address), codeBlockLen))

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
	contentBlockLen := len(instructions)

	// Fixes code to have an even number of words
	if len(instructions)%8 != 0 {
		instructions = append(instructions, 0x00, 0x00, 0x00, 0x00)
	}

	lines = append(lines, fmt.Sprintf("%s %08X", combineCodetypeAndAddress("06", address), contentBlockLen))

	for i := 0; i < len(instructions); i += 8 {
		left := strings.ToUpper(hex.EncodeToString(instructions[i : i+4]))
		right := strings.ToUpper(hex.EncodeToString(instructions[i+4 : i+8]))
		lines = append(lines, fmt.Sprintf("%s %s", left, right))
	}

	return lines
}

func generateBinaryLines(file string) []string {
	lines := []string{}

	contents, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panicf("Failed to read binary file %s\n%s\n", file, err.Error())
	}

	instructions := contents

	if len(instructions) == 0 {
		log.Panicf("Binary file must not be empty: %s\n", file)
	}

	// Fixes code to have an even number of words
	if len(instructions)%8 != 0 {
		log.Panicf("Binary file must have byte count divisable by 8: %s\n", file)
	}

	for i := 0; i < len(instructions); i += 8 {
		left := strings.ToUpper(hex.EncodeToString(instructions[i : i+4]))
		right := strings.ToUpper(hex.EncodeToString(instructions[i+4 : i+8]))
		lines = append(lines, fmt.Sprintf("%s %s", left, right))
	}

	return lines
}

func confirmAssembler() {
	const asCmdLinux string = "powerpc-eabi-as"
	const objcopyCmdLinux string = "powerpc-eabi-objcopy"

	// Try user's default $PATH
	_, aserr := exec.LookPath(asCmdLinux)
	_, objcopyerr := exec.LookPath(objcopyCmdLinux)
	if aserr != nil || objcopyerr != nil {
		// Add $DEVKITPPC/bin to $PATH and try again
		if envDEVKITPPC, exists := os.LookupEnv("DEVKITPPC"); exists {
			os.Setenv("PATH", envDEVKITPPC+"/bin"+":"+os.Getenv("PATH"))
			_, err := exec.LookPath(asCmdLinux)
			if err != nil {
				log.Panicf("%s not available in $PATH. You may need to install devkitPPC", asCmdLinux)
			}
			_, err = exec.LookPath(objcopyCmdLinux)
			if err != nil {
				log.Panicf("%s not available in $PATH. You may need to install devkitPPC", objcopyCmdLinux)
			}
		} else {
			log.Panicf("%s and %s are not available in $PATH, and $DEVKITPPC has not been set. You may need to install devkit-env", asCmdLinux, objcopyCmdLinux)
		}
	}
}

func writeOutput(details FileDetails) {
	fmt.Printf("Writing to %s...\n", details.File)
	ext := filepath.Ext(details.File)
	switch ext {
	case ".gct":
		writeGctOutput(details)
	case ".bin":
		writeBinOutput(details)
	default:
		writeTextOutput(details)
	}

	fmt.Printf("Successfuly wrote codes to %s\n", details.File)
}

func writeTextOutput(details FileDetails) {
	outputWithHeader := append(details.Header, output...)
	fullText := strings.Join(outputWithHeader, "\n")
	writeFile(details.File, []byte(fullText))
}

func writeGctOutput(details FileDetails) {
	gctBytes := []byte{0x00, 0xD0, 0xC0, 0xDE, 0x00, 0xD0, 0xC0, 0xDE}

	outputBytes := convertLinesToBinary(output)
	gctBytes = append(gctBytes, outputBytes...)

	gctBytes = append(gctBytes, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	writeFile(details.File, gctBytes)
}

func writeBinOutput(details FileDetails) {
	outputBytes := convertLinesToBinary(output)

	writeFile(details.File, outputBytes)
}

func convertLinesToBinary(lines []string) []byte {
	bytes := []byte{}

	for _, line := range lines {
		if len(line) < 17 {
			// lines with less than 17 characters cannot be code lines
			continue
		}

		lineBytes, err := hex.DecodeString(line[0:8] + line[9:17])
		if err != nil {
			// If parse fails that likely means this is a header or something
			continue
		}

		bytes = append(bytes, lineBytes...)
	}

	return bytes
}

func writeFile(filePath string, bytes []byte) {
	dirPath := filepath.Dir(filePath)
	os.MkdirAll(dirPath, os.ModePerm)

	err := ioutil.WriteFile(filePath, bytes, 0644)
	if err != nil {
		log.Panic("Failed to write file\n", err)
	}
}
