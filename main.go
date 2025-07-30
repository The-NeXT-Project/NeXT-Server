package main

import (
	"log"
	"os"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/pkg/profile"

	"github.com/The-NeXT-Project/NeXT-Server/cmd"
)

var enableProfile bool
var enableSentry bool

func main() {
	if enableProfile {
		defer profile.Start(profile.CPUProfile, profile.ProfilePath(".")).Stop()
	}

	if enableSentry {
		err := sentry.Init(sentry.ClientOptions{
			Dsn: os.Getenv("SENTRY_DSN"),
		})
		if err != nil {
			log.Fatal(err)
		}

		defer sentry.Flush(2 * time.Second)
	}

	err := cmd.Execute()
	if err != nil {
		log.Fatal(err)
	}
}
