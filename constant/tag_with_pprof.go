//go:build with_pprof

package constant

func init() {
	buildTags = append(buildTags, "with_pprof")
}
