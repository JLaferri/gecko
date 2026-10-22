package main

import (
	"io/ioutil"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadDepFile(t *testing.T) {
	cases := []struct {
		name     string
		contents string
		expected []string
	}{
		{
			name: "spaces, dollar signs and line continuations",
			contents: "out.elf: src\\ dir/blob.bin src\\ dir/Mac$$ro.s inc/Nested.s \\\n" +
				" src\\ dir/./Hdr2.s src\\ dir/main\\ asm.s\n",
			expected: []string{"src dir/blob.bin", "src dir/Mac$ro.s", "inc/Nested.s", "src dir/./Hdr2.s", "src dir/main asm.s"},
		},
		{
			name:     "windows paths and line endings",
			contents: "C:\\Temp\\gecko-1\\code.elf: C:\\Temp\\gecko-1\\code.asmtemp \\\r\n C:\\Proj/Common/Common.s\r\n",
			expected: []string{"C:\\Temp\\gecko-1\\code.asmtemp", "C:\\Proj/Common/Common.s"},
		},
		{
			name:     "backslashes in front of spaces",
			contents: "out.elf: a\\\\ b\\\\\\ c d\\\\\n",
			expected: []string{"a\\", "b\\ c", "d\\"},
		},
	}

	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "deps.d")
		if err := ioutil.WriteFile(path, []byte(c.contents), 0644); err != nil {
			t.Fatal(err)
		}

		deps, err := readDepFile(path)
		if err != nil {
			t.Fatalf("%s: %s", c.name, err.Error())
		}
		if !reflect.DeepEqual(deps, c.expected) {
			t.Errorf("%s: got %q, expected %q", c.name, deps, c.expected)
		}
	}
}

func TestShadowingPaths(t *testing.T) {
	cases := []struct {
		name          string
		dep           string
		includeDirs   []string
		unorderedFrom int
		expected      []string
	}{
		{
			name:          "found in working directory",
			dep:           "./Common/Common.s",
			includeDirs:   []string{"src dir", "C:\\root"},
			unorderedFrom: 2,
			expected:      []string{},
		},
		{
			name:          "found in first include path",
			dep:           "src dir/./Hdr.s",
			includeDirs:   []string{"src dir", "C:\\root"},
			unorderedFrom: 2,
			expected:      []string{"././Hdr.s"},
		},
		{
			name:          "found in last include path",
			dep:           "C:\\root/Hdr.s",
			includeDirs:   []string{"src dir", "C:\\root"},
			unorderedFrom: 2,
			expected:      []string{"./Hdr.s", "src dir/Hdr.s"},
		},
		{
			name:          "found in an unordered include path",
			dep:           "B/Hdr.s",
			includeDirs:   []string{"C:\\root", "A", "B", "C", "B"},
			unorderedFrom: 1,
			expected:      []string{"./Hdr.s", "C:\\root/Hdr.s", "A/Hdr.s", "C/Hdr.s"},
		},
		{
			name:          "repeated include paths",
			dep:           "C:\\root/Hdr.s",
			includeDirs:   []string{".", "C:\\root", "A", "C:\\root"},
			unorderedFrom: 2,
			expected:      []string{"./Hdr.s"},
		},
		{
			name:          "include paths nested in each other",
			dep:           "A/B/Hdr.s",
			includeDirs:   []string{"A", "A/B"},
			unorderedFrom: 0,
			expected:      []string{"./B/Hdr.s", "A/B/B/Hdr.s", "./Hdr.s", "A/Hdr.s"},
		},
		{
			name:          "found without searching",
			dep:           "C:/abs/Hdr.s",
			includeDirs:   []string{"src dir"},
			unorderedFrom: 1,
			expected:      []string{},
		},
	}

	for _, c := range cases {
		paths := shadowingPaths(c.dep, c.includeDirs, c.unorderedFrom)
		if !reflect.DeepEqual(paths, c.expected) {
			t.Errorf("%s: got %q, expected %q", c.name, paths, c.expected)
		}
	}
}
