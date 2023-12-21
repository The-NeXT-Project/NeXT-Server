package main

import (
	"log"

	"github.com/SSPanel-UIM/UIM-Server/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
