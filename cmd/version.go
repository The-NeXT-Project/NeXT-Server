package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "0.3.8"
	codename = "NeXT-Server"
	intro    = "Next generation proxy server."
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print current version of NeXT-Server",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
}
