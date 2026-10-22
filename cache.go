package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Bump this whenever the entry format or the way entries are validated changes
const cacheVersion = 1

// Results are not cached if any file they were assembled from was modified within this long of the
// start of the run or after it. The file may have changed between the assembler reading it and us
// hashing it, and not every file system records modification times precisely
const cacheRacyWindow = 5 * time.Second

var useCache bool
var cacheHits uint32
var cacheRunStart = time.Now()
var cacheDir string
var cacheWorkDir string
var cacheContext string

var fileHashes = map[string]string{}
var fileHashesMtx sync.Mutex

type cacheResult struct {
	File       string
	AddressExp string
	Code       []byte
	Address    string
}

type cacheEntry struct {
	// Identifies gecko and the assembler tools that produced the results
	Context string
	// Hash of every file the results were assembled from, keyed by the path the file was read from
	Inputs map[string]string
	// Paths that could have been read in place of one of the inputs. Each must either not exist, when
	// its hash is empty, or have the same contents as the input it could have replaced
	Shadows map[string]string
	Results []cacheResult
}

func setupCache() {
	disable := func(err error) {
		fmt.Printf("Not using the cache: %s\n", err.Error())
		useCache = false
	}

	// Anything that changes how gecko or the tools behave could change the code they produce, so
	// entries are only valid for the exact binaries that made them
	context := sha256.New()
	fmt.Fprintf(context, "version %d\n", cacheVersion)

	geckoPath, err := os.Executable()
	if err != nil {
		disable(err)
		return
	}
	geckoHash, err := hashFile(geckoPath)
	if err != nil {
		disable(err)
		return
	}
	fmt.Fprintf(context, "gecko %s\n", geckoHash)

	for _, tool := range []string{"powerpc-eabi-as", "powerpc-eabi-objcopy"} {
		toolPath, err := exec.LookPath(tool)
		if err != nil {
			disable(err)
			return
		}
		toolHash, err := hashFile(toolPath)
		if err != nil {
			disable(err)
			return
		}
		fmt.Fprintf(context, "%s %s %s\n", tool, toolPath, toolHash)
	}

	cacheContext = hex.EncodeToString(context.Sum(nil))

	cacheWorkDir, err = os.Getwd()
	if err != nil {
		disable(err)
		return
	}

	geckoDir := filepath.Join(argConfig.ProjectRoot, ".gecko")
	cacheDir = filepath.Join(geckoDir, "cache")
	err = os.MkdirAll(cacheDir, 0755)
	if err != nil {
		disable(err)
		return
	}

	// Keep the cache out of source control without needing the project to ignore it
	gitignorePath := filepath.Join(geckoDir, ".gitignore")
	if _, err := os.Stat(gitignorePath); os.IsNotExist(err) {
		ioutil.WriteFile(gitignorePath, []byte("*\n"), 0644)
	}
}

// hashFile returns the hash of a file's contents. Each file is only hashed once per run
func hashFile(path string) (string, error) {
	fileHashesMtx.Lock()
	hash, exists := fileHashes[path]
	fileHashesMtx.Unlock()
	if exists {
		return hash, nil
	}

	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return "", err
	}

	sum := sha256.Sum256(contents)
	hash = hex.EncodeToString(sum[:])

	fileHashesMtx.Lock()
	fileHashes[path] = hash
	fileHashesMtx.Unlock()

	return hash, nil
}

// cacheSlot names the file an entry is stored in. Everything about how the build was set up goes into
// it so that builds alternating between setups, such as different -defsym values, keep their own entries
func cacheSlot(parts ...string) string {
	defsyms := strings.Join(argConfig.DefSyms, ",")
	parts = append([]string{cacheWorkDir, argConfig.ProjectRoot, defsyms, fmt.Sprint(useWarnings)}, parts...)

	slot := sha256.New()
	for _, part := range parts {
		fmt.Fprintf(slot, "%d:%s\n", len(part), part)
	}

	return filepath.Join(cacheDir, hex.EncodeToString(slot.Sum(nil))+".json")
}

func cacheResultKey(result cacheResult) string {
	return result.File + "\x00" + result.AddressExp
}

func sortCacheResults(results []cacheResult) {
	sort.Slice(results, func(i, j int) bool {
		return cacheResultKey(results[i]) < cacheResultKey(results[j])
	})
}

// cacheLookup returns the results stored in slot if they were assembled from the files and addresses
// requested and nothing they were assembled from has changed. Otherwise it returns nil
func cacheLookup(slot string, requested []cacheResult) []cacheResult {
	contents, err := ioutil.ReadFile(slot)
	if err != nil {
		return nil
	}

	var entry cacheEntry
	err = json.Unmarshal(contents, &entry)
	if err != nil || entry.Context != cacheContext || len(entry.Results) != len(requested) {
		return nil
	}

	requested = append([]cacheResult{}, requested...)
	sortCacheResults(requested)
	for idx, result := range entry.Results {
		if cacheResultKey(result) != cacheResultKey(requested[idx]) {
			return nil
		}
	}

	for path, hash := range entry.Inputs {
		currentHash, err := hashFile(path)
		if err != nil || currentHash != hash {
			return nil
		}
	}

	for path, hash := range entry.Shadows {
		if shadowHash(path) != hash {
			return nil
		}
	}

	atomic.AddUint32(&cacheHits, uint32(len(entry.Results)))
	return entry.Results
}

// cacheStore stores results in slot along with what is needed to tell later whether they're still
// valid. sources are the files given to gecko, depFile is the dependency file written by the assembler,
// asmFiles are the temp files given to the assembler and includeDirs are the -I paths in the order
// given. includeDirs from unorderedFrom onward are in no particular order. Results are not stored if
// there's any doubt about what they were assembled from
func cacheStore(
	slot string,
	results []cacheResult,
	sources []string,
	depFile string,
	asmFiles []string,
	includeDirs []string,
	unorderedFrom int,
) {
	deps, err := readDepFile(depFile)
	if err != nil {
		return
	}

	// Make sure the dependency file was read correctly by checking it lists every file assembled
	isAsmFile := map[string]bool{}
	for _, asmFile := range asmFiles {
		isAsmFile[asmFile] = true
	}
	foundAsmFiles := map[string]bool{}
	for _, dep := range deps {
		if isAsmFile[dep] {
			foundAsmFiles[dep] = true
		}
	}
	if len(foundAsmFiles) != len(isAsmFile) {
		return
	}

	entry := cacheEntry{Context: cacheContext, Inputs: map[string]string{}, Shadows: map[string]string{}}

	inputs := append([]string{}, sources...)
	for _, dep := range deps {
		if !isAsmFile[dep] {
			inputs = append(inputs, dep)
		}
	}

	for _, path := range inputs {
		hash, err := hashFile(path)
		if err != nil {
			return
		}

		// Checked after hashing so a change made at any point after the assembler read the file shows up
		info, err := os.Stat(path)
		if err != nil || !info.ModTime().Before(cacheRunStart.Add(-cacheRacyWindow)) {
			return
		}

		entry.Inputs[path] = hash
	}

	// A file in one of these places with different contents was either created after the assembler
	// looked for it or, for include paths in no particular order, could be found instead by another
	// build. The same contents can be found in more than one place, such as ../ paths that lead back
	// to the same file from different include paths, and make no difference to the code
	for _, dep := range deps {
		if isAsmFile[dep] {
			continue
		}

		for _, path := range shadowingPaths(dep, includeDirs, unorderedFrom) {
			hash := shadowHash(path)
			existingHash, exists := entry.Shadows[path]
			if (hash != "" && hash != entry.Inputs[dep]) || (exists && existingHash != hash) {
				return
			}

			entry.Shadows[path] = hash
		}
	}

	entry.Results = append([]cacheResult{}, results...)
	sortCacheResults(entry.Results)

	// The same file can be built more than once. If the copies came out differently the results can't
	// be told apart when read back
	for idx := 1; idx < len(entry.Results); idx++ {
		prev, cur := entry.Results[idx-1], entry.Results[idx]
		if cacheResultKey(prev) == cacheResultKey(cur) &&
			(string(prev.Code) != string(cur.Code) || prev.Address != cur.Address) {
			return
		}
	}

	contents, err := json.Marshal(entry)
	if err != nil {
		return
	}

	// Write to a temp file first so a build reading the entry never sees it partially written
	tempFile, err := ioutil.TempFile(cacheDir, "entry-*.tmp")
	if err != nil {
		return
	}
	_, writeErr := tempFile.Write(contents)
	closeErr := tempFile.Close()
	if writeErr != nil || closeErr != nil || os.Rename(tempFile.Name(), slot) != nil {
		os.Remove(tempFile.Name())
	}
}

// shadowHash returns the hash of the file at path, an empty string if nothing is there or "?" if it
// can't be read, which never matches a stored hash
func shadowHash(path string) string {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return ""
	}

	hash, err := hashFile(path)
	if err != nil {
		return "?"
	}

	return hash
}

// shadowingPaths returns the paths that the assembler would have read in place of dep had they existed.
// The assembler looks for an included file in the working directory and then in each include path in
// order, and refers to the file it finds as dir/name
func shadowingPaths(dep string, includeDirs []string, unorderedFrom int) []string {
	// Searching a directory a second time can't find anything new so only the first time counts
	searchDirs := []string{"."}
	isSearched := map[string]bool{".": true}
	for idx, dir := range includeDirs {
		if isSearched[dir] {
			if idx < unorderedFrom {
				unorderedFrom--
			}
			continue
		}

		isSearched[dir] = true
		searchDirs = append(searchDirs, dir)
	}
	unorderedFrom++

	paths := []string{}
	for i, dir := range searchDirs {
		prefix := dir + "/"
		if !strings.HasPrefix(dep, prefix) {
			continue
		}

		name := dep[len(prefix):]
		for j, otherDir := range searchDirs {
			bothUnordered := i >= unorderedFrom && j >= unorderedFrom
			if j < i || (j != i && bothUnordered) {
				path := otherDir + "/" + name
				if path != dep {
					paths = append(paths, path)
				}
			}
		}
	}

	return paths
}

// readDepFile returns the files listed in a dependency file written by the assembler's --MD option
func readDepFile(path string) ([]string, error) {
	contents, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(contents)

	// The file is a make rule of the form "target: deps". The target can contain the colon of a drive
	// letter so look for the colon that ends it, which is followed by white space
	for idx := 0; idx < len(text); idx++ {
		if text[idx] == ':' && (idx+1 == len(text) || strings.ContainsRune(" \t\r\n", rune(text[idx+1]))) {
			return splitMakeWords(text[idx+1:]), nil
		}
	}

	return nil, fmt.Errorf("no rule found in dependency file %s", path)
}

// splitMakeWords splits a list of file names quoted for make. A space is escaped by a backslash,
// backslashes in front of a space or the end of a name are doubled, $ is written as $$ and a
// backslash at the end of a line continues the list on the next line
func splitMakeWords(text string) []string {
	words := []string{}
	word := strings.Builder{}
	inWord := false

	endWord := func() {
		if inWord {
			words = append(words, word.String())
			word.Reset()
			inWord = false
		}
	}

	for idx := 0; idx < len(text); idx++ {
		c := text[idx]
		switch {
		case c == '\\':
			end := idx
			for end < len(text) && text[end] == '\\' {
				end++
			}
			count := end - idx

			if end < len(text) && !strings.ContainsRune(" \t\r\n", rune(text[end])) {
				// Backslashes not in front of white space are just part of the name
				word.WriteString(text[idx:end])
				inWord = true
				idx = end - 1
				continue
			}

			if count >= 2 {
				word.WriteString(strings.Repeat("\\", count/2))
				inWord = true
			}

			if count%2 == 1 && end < len(text) && (text[end] == ' ' || text[end] == '\t') {
				// An escaped space or tab is part of the name
				word.WriteByte(text[end])
				inWord = true
				idx = end
				continue
			}

			// Either the end of a name or a line continuation, both of which end the word
			endWord()
			idx = end - 1
		case c == '$' && idx+1 < len(text) && text[idx+1] == '$':
			word.WriteByte('$')
			inWord = true
			idx++
		case strings.ContainsRune(" \t\r\n", rune(c)):
			endWord()
		default:
			word.WriteByte(c)
			inWord = true
		}
	}
	endWord()

	return words
}
