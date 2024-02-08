package main

import (
	"github.com/pkg/profile"
	"log"

	"github.com/SSPanel-UIM/UIM-Server/cmd"
)

var enableProfile bool

func main() {
	if enableProfile {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	}

	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
