package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type Config struct {
	OutputFile string
	Codes      []CodeDescription
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
	SourceFile    string
	SourceFolder  string
	Value         string
}

const (
	Replace          = "replace"
	Inject           = "inject"
	ReplaceCodeBlock = "replaceCodeBlock"
	Branch           = "branch"
	BranchAndLink    = "branchAndLink"
	InjectFolder     = "injectFolder"
)

var output []string

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Must provide a command. Try typing 'gecko build'.")
	}

	if os.Args[1] != "build" {
		log.Fatal("Currently only the build command is supported. Try typing 'gecko build'.")
	}

	config := readConfigFile()
	buildBody(config)
	writeOutput(config.OutputFile)

	fmt.Printf("Successfuly wrote codes to %s.\n", config.OutputFile)
}

func readConfigFile() Config {
	contents, err := ioutil.ReadFile("codes.json")
	if err != nil {
		log.Fatal("Failed to read config file codes.json\n", err)
	}

	var result Config
	err = json.Unmarshal(contents, &result)
	if err != nil {
		log.Fatal(
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
		case Branch:
			fallthrough
		case BranchAndLink:
			shouldLink := geckoCode.Type == BranchAndLink
			line := generateBranchCodeLine(geckoCode.Address, geckoCode.TargetAddress, shouldLink)
			line = addLineAnnotation(line, geckoCode.Annotation)
			result = append(result, line)
		case InjectFolder:
			lines := generateInjectionFolderLines(geckoCode.SourceFolder)
			lines[0] = addLineAnnotation(lines[0], geckoCode.Annotation)
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
		log.Fatal("Failed to parse address or target address.", err)
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

func generateInjectionFolderLines(folder string) []string {
	lines := []string{}

	files, err := ioutil.ReadDir(folder)
	if err != nil {
		log.Fatal("Failed to read directory.", err)
	}

	for _, file := range files {
		fileName := file.Name()
		ext := filepath.Ext(fileName)
		if ext != ".asm" {
			continue
		}

		// Get full filepath for file
		filePath := filepath.Join(folder, fileName)

		file, err := os.Open(filePath)
		if err != nil {
			log.Fatal("Failed to read file.", err)
		}
		defer file.Close()

		// Read first line from file to get address
		scanner := bufio.NewScanner(file)
		scanner.Scan()
		firstLine := scanner.Text()

		// Get address
		lineLength := len(firstLine)
		address := firstLine[lineLength-8:]

		// Compile file and add lines
		fileLines := generateInjectionCodeLines(address, filePath)
		lines = append(lines, fileLines...)
	}

	return lines
}

func generateInjectionCodeLines(address, file string) []string {
	// TODO: Add error if address or value is incorrect length/format
	lines := []string{}

	instructions := compile(file)

	// Fixes code to always end with 0x00000000 and have an even number of words
	if len(instructions)%8 == 0 {
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

func compile(file string) []byte {
	defer os.Remove("a.out")

	cmd := exec.Command("powerpc-gekko-as.exe", "-a32", "-mbig", "-mregnames", "-mgekko", file)
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Failed to compile file: %s\n", file)
		fmt.Printf("%s", output)
		os.Exit(1)
	}

	contents, err := ioutil.ReadFile("a.out")
	if err != nil {
		log.Fatal(fmt.Sprintf("Failed to read compiled file %s\n", file), err)
	}
	codeEndIndex := bytes.Index(contents, []byte{0x00, 0x2E, 0x73, 0x79, 0x6D, 0x74, 0x61, 0x62})

	return contents[52:codeEndIndex]
}

func writeOutput(outputFile string) {
	fullText := strings.Join(output, "\n")
	ioutil.WriteFile(outputFile, []byte(fullText), 0644)
}
