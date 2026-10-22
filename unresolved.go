package main

import (
	"debug/elf"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

// findUnresolvedSymbols returns an error message for every value in the object file at objectPath
// that the assembler left for a linker to fill in. Gecko codes are never linked so those values would
// be left as zeros, which is what happens to a misspelled symbol. sourceFor gives the source file of
// each section that ends up in the code, or false for sections that don't
func findUnresolvedSymbols(objectPath string, sourceFor func(section *elf.Section) (string, bool)) []string {
	f, err := elf.Open(objectPath)
	if err != nil {
		log.Panicf("Failed to read compiled file %s\n%s\n", objectPath, err.Error())
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil && err != elf.ErrNoSymbols {
		log.Panicf("Failed to read symbols of compiled file %s\n%s\n", objectPath, err.Error())
	}

	messages := []string{}
	for _, section := range f.Sections {
		if section.Type != elf.SHT_RELA && section.Type != elf.SHT_REL {
			continue
		}

		target := f.Sections[section.Info]
		sourceFile, isCode := sourceFor(target)
		if !isCode {
			continue
		}

		data, err := section.Data()
		if err != nil {
			log.Panicf("Failed to read relocations of compiled file %s\n%s\n", objectPath, err.Error())
		}

		// The assembler is run with -a32 so entries are the 32 bit kind
		entrySize := 8
		if section.Type == elf.SHT_RELA {
			entrySize = 12
		}

		sourceLines := []string{}
		contents, err := ioutil.ReadFile(sourceFile)
		if err == nil {
			sourceLines = strings.Split(string(contents), "\n")
		}

		reported := map[string]bool{}
		for pos := 0; pos+entrySize <= len(data); pos += entrySize {
			// Point at the start of the instruction rather than the field within it
			offset := f.ByteOrder.Uint32(data[pos:]) &^ 3
			symbolIdx := elf.R_SYM32(f.ByteOrder.Uint32(data[pos+4:]))

			name := ""
			isUndefined := false
			if symbolIdx > 0 && int(symbolIdx) <= len(symbols) {
				symbol := symbols[symbolIdx-1]
				name = symbol.Name
				isUndefined = symbol.Section == elf.SHN_UNDEF

				// The assembler refers to a label by its section and its offset in it, so look up which
				// label is at that offset
				if elf.ST_TYPE(symbol.Info) == elf.STT_SECTION && section.Type == elf.SHT_RELA {
					addend := uint64(f.ByteOrder.Uint32(data[pos+8:]))
					for _, label := range symbols {
						isLabel := elf.ST_TYPE(label.Info) != elf.STT_SECTION && label.Name != ""
						if isLabel && label.Section == symbol.Section && label.Value == addend {
							name = label.Name
							break
						}
					}
				}
			}

			problem := fmt.Sprintf("undefined symbol `%s'", name)
			if !isUndefined && name != "" {
				problem = fmt.Sprintf("the address of `%s' isn't known until the code is placed in memory", name)
			} else if !isUndefined {
				problem = "the address of a label isn't known until the code is placed in memory"
			}

			// The injection address is added as the last word of the code
			isAddress := uint64(offset)+4 == target.Size
			if isAddress {
				messages = append(messages, fmt.Sprintf("%s: Error: injection address: %s", sourceFile, problem))
				continue
			}

			// Every use of a symbol is pointed out the first time it's found so only report it once
			if reported[name] {
				continue
			}
			reported[name] = true

			lineNums := []int{}
			if name != "" {
				lineNums = findSymbolLines(sourceLines, name)
			}
			for _, lineNum := range lineNums {
				messages = append(messages, fmt.Sprintf("%s:%d: Error: %s", sourceFile, lineNum, problem))
			}
			if len(lineNums) == 0 {
				where := "used through an include or macro"
				if name == "" {
					where = "used by the code"
				}

				messages = append(messages, fmt.Sprintf(
					"%s: Error: %s, %s at code offset 0x%X",
					sourceFile,
					problem,
					where,
					offset,
				))
			}
		}
	}

	return messages
}

// findSymbolLines returns the line numbers of the lines that use a symbol, ignoring comments, the
// symbol's definition as a label and checks for whether it's defined
func findSymbolLines(lines []string, name string) []int {
	isSymbolChar := func(c byte) bool {
		return isSymbolRune(rune(c)) || c == '.' || c == '$'
	}

	lineNums := []int{}
	for idx, line := range lines {
		line = strings.SplitN(line, "#", 2)[0]

		// A line can hold several statements separated by ;
		statements := []string{}
		for _, statement := range strings.Split(line, ";") {
			directive := strings.ToLower(strings.TrimSpace(statement))
			isDefinedCheck := strings.HasPrefix(directive, ".ifdef") ||
				strings.HasPrefix(directive, ".ifndef") ||
				strings.HasPrefix(directive, ".ifnotdef")
			if !isDefinedCheck {
				statements = append(statements, statement)
			}
		}
		line = strings.Join(statements, ";")

		for start := 0; start < len(line); {
			found := strings.Index(line[start:], name)
			if found < 0 {
				break
			}

			begin := start + found
			end := begin + len(name)
			isWhole := (begin == 0 || !isSymbolChar(line[begin-1])) && (end == len(line) || !isSymbolChar(line[end]))
			isLabel := strings.HasPrefix(strings.TrimSpace(line[end:]), ":")
			if isWhole && !isLabel {
				lineNums = append(lineNums, idx+1)
				break
			}
			start = begin + 1
		}
	}

	return lineNums
}
