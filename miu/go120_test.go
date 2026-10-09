package miu

import (
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The module asks for a recent Go because of what its other packages depend on, but this package is
// meant to be usable — by copying its files — in projects that still build with Go 1.20 (see
// docs/mihomo.md). This test keeps it that way: the non-test files have to type-check as Go 1.20 and
// may only import packages that existed then.
func TestStaysWithinGo120(t *testing.T) {
	// Standard library packages added after Go 1.20.
	tooNew := map[string]bool{
		"cmp": true, "iter": true, "log/slog": true, "maps": true, "math/rand/v2": true, "slices": true,
		"structs": true, "testing/slogtest": true, "testing/synctest": true, "unique": true, "weak": true,
		"crypto/hkdf": true, "crypto/mlkem": true, "crypto/pbkdf2": true, "crypto/sha3": true,
	}
	fset := token.NewFileSet()
	for _, goos := range []string{"linux", "darwin", "windows"} {
		ctx := build.Default
		ctx.GOOS, ctx.CgoEnabled = goos, false
		pkg, err := ctx.ImportDir(".", 0)
		if _, noSource := err.(*build.NoGoError); noSource {
			t.Skip("the package sources are not here (a compiled test binary run elsewhere)")
		}
		if err != nil {
			t.Fatal(err)
		}
		var files []*ast.File
		for _, name := range pkg.GoFiles {
			f, err := parser.ParseFile(fset, filepath.Join(".", name), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range f.Imports {
				path, _ := strconv.Unquote(imp.Path.Value)
				if tooNew[path] {
					t.Errorf("%s imports %s, which Go 1.20 does not have", name, path)
				}
				if first, _, _ := strings.Cut(path, "/"); strings.Contains(first, ".") {
					t.Errorf("%s imports %s: this package depends on the standard library only", name, path)
				}
			}
			files = append(files, f)
		}
		conf := types.Config{
			GoVersion: "go1.20",
			Importer:  importer.ForCompiler(fset, "source", nil),
			Error:     func(err error) { t.Errorf("GOOS=%s: %v", goos, err) },
		}
		if goos != build.Default.GOOS {
			// Foreign platforms: syscall differs per platform and cannot be loaded from here, so only
			// the syntax and imports of their files are checked.
			continue
		}
		_, _ = conf.Check("miu", fset, files, nil)
	}
}
