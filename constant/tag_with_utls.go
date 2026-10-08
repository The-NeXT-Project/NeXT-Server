//go:build with_utls

package constant

func init() {
	buildTags = append(buildTags, "with_utls")
}
