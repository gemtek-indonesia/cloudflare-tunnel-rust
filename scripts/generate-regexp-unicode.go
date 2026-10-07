package main

import (
	"encoding/json"
	"os"
	"runtime"
	"unicode"
)

func main() {
	if runtime.Version() != "go1.26.0" || unicode.Version != "15.0.0" {
		panic("generator requires pinned Go1.26.0 Unicode15.0.0")
	}
	properties := map[string][][3]uint32{}
	appendTable := func(name string, table *unicode.RangeTable) {
		ranges := make([][3]uint32, 0, len(table.R16)+len(table.R32))
		for _, r := range table.R16 {
			ranges = append(ranges, [3]uint32{uint32(r.Lo), uint32(r.Hi), uint32(r.Stride)})
		}
		for _, r := range table.R32 {
			ranges = append(ranges, [3]uint32{r.Lo, r.Hi, r.Stride})
		}
		properties[name] = ranges
	}
	for name, table := range unicode.Categories {
		appendTable(name, table)
	}
	for name, table := range unicode.Scripts {
		appendTable(name, table)
	}
	properties["Any"] = [][3]uint32{{0, 0x10ffff, 1}}
	properties["ASCII"] = [][3]uint32{{0, 127, 1}}
	folds := [][]uint32{}
	seen := map[rune]bool{}
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if seen[r] || unicode.SimpleFold(r) == r {
			continue
		}
		cycle := []uint32{}
		for next := r; !seen[next]; next = unicode.SimpleFold(next) {
			cycle = append(cycle, uint32(next))
			seen[next] = true
		}
		folds = append(folds, cycle)
	}
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(map[string]any{"go_toolchain": runtime.Version(), "unicode_version": unicode.Version, "properties": properties, "folds": folds, "category_aliases": unicode.CategoryAliases}); err != nil {
		panic(err)
	}
}
