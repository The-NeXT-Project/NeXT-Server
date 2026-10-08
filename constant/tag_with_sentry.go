//go:build with_sentry

package constant

func init() {
	buildTags = append(buildTags, "with_sentry")
}
