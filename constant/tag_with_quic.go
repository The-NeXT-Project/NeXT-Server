//go:build with_quic

package constant

func init() {
	buildTags = append(buildTags, "with_quic")
}
