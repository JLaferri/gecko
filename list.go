package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

type injectionDetails struct {
	InjectionAddress string
	Name             string
	Codetype         string
	Annotation       string
	Tags             string
}

type injectionList struct {
	Details []injectionDetails
}

func listInjections(input, output string, isRecursive bool) {
	result := injectionList{}

	loc, err := os.Stat(input)
	if err != nil {
		log.Panicf("Could not find input %s for injection list.", input)
	}

	if loc.IsDir() {
		populateInjectionsFromFolder("N/A", input, isRecursive, &result)
	} else {
		populateInjectionsFromFile(input, &result)
	}

	// Write out the results
	writeInjectionList(output, &result)
}

func writeInjectionList(output string, list *injectionList) {
	contents, err := json.MarshalIndent(list, "", " ")
	if err != nil {
		log.Panicf("Failed to prepare injection list data for writing. %s", err.Error())
	}

	err = ioutil.WriteFile(output, contents, 0644)
	if err != nil {
		log.Panicf("Failed to write injection list file to: %s. %s", output, err.Error())
	}
}

func populateInjectionsFromFile(input string, list *injectionList) {
	config := readConfigFile(input)
	for _, code := range config.Codes {
		for _, geckoCode := range code.Build {
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
				lineAnnotation := filepath.ToSlash(geckoCode.SourceFile)
				if header.Annotation != "" {
					lineAnnotation = fmt.Sprintf("%s | %s", header.Annotation, lineAnnotation)
				}
				if geckoCode.Annotation != "" {
					lineAnnotation = fmt.Sprintf("%s | %s", geckoCode.Annotation, lineAnnotation)
				}

				// Make sure address format is good
				address, err := parseAddressFromString(address)
				if err != nil {
					log.Panicf("Address %s has invalid format for injection entry in: %s. %s", address, input, err.Error())
				}

				list.Details = append(list.Details, injectionDetails{
					Name:             code.Name,
					InjectionAddress: address,
					Codetype:         codetype,
					Annotation:       lineAnnotation,
				})
			case ReplaceBinary:
				// Make sure address format is good
				address, err := parseAddressFromString(geckoCode.Address)
				if err != nil {
					log.Panicf("Address %s has invalid format for replace binary entry in: %s. %s", address, input, err.Error())
				}

				list.Details = append(list.Details, injectionDetails{
					Name:             code.Name,
					InjectionAddress: address,
					Codetype:         "06",
					Annotation:       geckoCode.Annotation,
				})
			case Binary:
				populateInjectionsFromBinary(code.Name, geckoCode.SourceFile, list)
			case InjectFolder:
				populateInjectionsFromFolder(code.Name, geckoCode.SourceFolder, geckoCode.IsRecursive, list)
			default:
				log.Panicf("Unsupported build type: %s\n", geckoCode.Type)
			}
		}
	}
}

func populateInjectionsFromBinary(name, file string, list *injectionList) {
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

	i := 0
	for i < len(instructions) {
		codetype := strings.ToUpper(hex.EncodeToString([]byte{instructions[i] & 0xFE}))
		address := instructions[i : i+4]
		address[0] = (address[0] & 1) + 0x80

		list.Details = append(list.Details, injectionDetails{
			Name:             name,
			InjectionAddress: strings.ToUpper(hex.EncodeToString(address)),
			Codetype:         codetype,
		})

		// Move to next code in the list
		switch codetype {
		case "04":
			i += 8
		case "06":
			var byteLen uint64
			b := []byte{0, 0, 0, 0, instructions[i+4], instructions[i+5], instructions[i+6], instructions[i+7]}
			err := binary.Read(bytes.NewReader(b), binary.BigEndian, &byteLen)
			if err != nil {
				log.Panicf("Idx: %d. Failed to parse size on 06 code in binary: %s. %s", i, file, err.Error())
			}
			i += 8 + ((int(byteLen) + 7) & 0xFFFFFFF8) // Round up to next 8 bytes and add the first 8 bytes
		case "08":
			i += 16
		case "C2":
			var lineCount uint64
			b := []byte{0, 0, 0, 0, instructions[i+4], instructions[i+5], instructions[i+6], instructions[i+7]}
			err := binary.Read(bytes.NewReader(b), binary.BigEndian, &lineCount)
			if err != nil {
				log.Panicf("Idx: %d. Failed to parse size on C2 code in binary: %s. %s", i, file, err.Error())
			}
			i += 8 + (int(lineCount) * 8)
		default:
			log.Panicf("Idx: %d. Codetype %s in binary %s not supported.", i, codetype, file)
		}
	}
}

func populateInjectionsFromFolder(name, input string, isRecursive bool, list *injectionList) {
	asmFilePaths := collectFilesFromFolder(input, isRecursive)

	for _, filePath := range asmFilePaths {
		header := parseAsmFileHeader(filePath)
		address := parseAddressFromFile(header.Address, filePath)

		lineAnnotation := filepath.ToSlash(filePath)
		if header.Annotation != "" {
			lineAnnotation = fmt.Sprintf("%s | %s", header.Annotation, lineAnnotation)
		}

		list.Details = append(list.Details, injectionDetails{
			Name:             name,
			InjectionAddress: address,
			Codetype:         header.Codetype,
			Annotation:       lineAnnotation,
			Tags:             header.Tags,
		})
	}
}

func parseAddressFromString(address string) (string, error) {
	str := strings.TrimSpace(address)
	if strings.HasPrefix(str, "0x") {
		str = str[2:10]
	} else {
		str = str[:8]
	}

	_, err := hex.DecodeString(str)
	if err != nil {
		return "", err
	}

	return strings.ToUpper(str), nil
}

func parseAddressFromFile(headerAddress, filePath string) string {
	address, err := parseAddressFromString(headerAddress)
	if err == nil {
		return address
	}

	// Here the address is probably a symbol, we need to actually compile the file to get the address
	_, address = compile(filePath, headerAddress)
	return strings.ToUpper(address)
}
