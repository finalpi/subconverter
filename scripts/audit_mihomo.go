// Extract the native proxy option schema from a pinned Mihomo checkout.
// Uses only the Go standard library; it does not build or run Mihomo.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
)

type Field struct {
	Type string `json:"go_type"`
}
type Structure struct {
	Fields map[string]Field `json:"fields"`
	Embeds []string         `json:"embeds,omitempty"`
}
type Protocol struct {
	Option string `json:"option_struct"`
}

func main() {
	source := flag.String("source", "", "Mihomo checkout")
	output := flag.String("out", "", "JSON inventory")
	flag.Parse()
	if *source == "" || *output == "" {
		panic("--source and --out are required")
	}
	fset := token.NewFileSet()
	structs := map[string]Structure{}
	paths, err := filepath.Glob(filepath.Join(*source, "adapter", "outbound", "*.go"))
	must(err)
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") || strings.HasSuffix(path, "_stub.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		must(err)
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			body, ok := spec.Type.(*ast.StructType)
			if !ok {
				return true
			}
			entry := Structure{Fields: map[string]Field{}}
			for _, f := range body.Fields.List {
				var buf bytes.Buffer
				must(format.Node(&buf, fset, f.Type))
				typ := buf.String()
				if len(f.Names) == 0 {
					entry.Embeds = append(entry.Embeds, typ)
					continue
				}
				if f.Tag == nil {
					continue
				}
				tag, err := strconv.Unquote(f.Tag.Value)
				must(err)
				key := strings.Split(reflect.StructTag(tag).Get("proxy"), ",")[0]
				if key != "" && key != "-" {
					entry.Fields[key] = Field{Type: typ}
				}
			}
			if len(entry.Fields) > 0 {
				structs[spec.Name.Name] = entry
			}
			return false
		})
	}
	protocols := map[string]Protocol{}
	file, err := parser.ParseFile(fset, filepath.Join(*source, "adapter", "parser.go"), nil, 0)
	must(err)
	ast.Inspect(file, func(n ast.Node) bool {
		clause, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		option := ""
		for _, statement := range clause.Body {
			ast.Inspect(statement, func(child ast.Node) bool {
				literal, ok := child.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := literal.Type.(*ast.SelectorExpr)
				if ok && strings.HasSuffix(sel.Sel.Name, "Option") {
					option = sel.Sel.Name
				}
				return true
			})
			if option != "" {
				break
			}
		}
		if option != "" {
			if _, ok := structs[option]; !ok {
				panic("Missing option struct: " + option)
			}
			for _, value := range clause.List {
				literal, ok := value.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				name, err := strconv.Unquote(literal.Value)
				must(err)
				protocols[name] = Protocol{Option: option}
			}
		}
		return false
	})
	revision, err := exec.Command("git", "-C", *source, "rev-parse", "HEAD").Output()
	must(err)
	report := map[string]any{"source": map[string]string{"repository": "https://github.com/MetaCubeX/mihomo", "revision": strings.TrimSpace(string(revision)), "parser": "adapter/parser.go"}, "protocols": protocols, "structs": structs}
	body, err := json.MarshalIndent(report, "", "  ")
	must(err)
	must(os.WriteFile(*output, append(body, '\n'), 0644))
	fmt.Printf("Audited %d protocols and %d option structs\n", len(protocols), len(structs))
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}
