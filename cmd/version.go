package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "0.1.4"
	codename = "UIM-Server"
	intro    = "UIM Server (XrayR Edition)"
)

func init() {
	rootCmd.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print current version of UIM-Server",
		Run: func(cmd *cobra.Command, args []string) {
			showVersion()
		},
	})
}

func showVersion() {
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
}
