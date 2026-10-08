package constant

import "slices"

// Version is set at release build time with -ldflags "-X".
var Version = "unknown"

// DefaultBuildTags are the tags every official build enables. Go has no way
// to make them the default for a plain `go build`, so builds without them are
// reported at startup.
var DefaultBuildTags = []string{"with_acme", "with_utls", "with_quic"}

// buildTags is filled by the init functions of tag-guarded files.
var buildTags []string

func BuildTags() []string {
	return slices.Clone(buildTags)
}

func MissingDefaultBuildTags() []string {
	var missing []string
	for _, tag := range DefaultBuildTags {
		if !slices.Contains(buildTags, tag) {
			missing = append(missing, tag)
		}
	}
	return missing
}
