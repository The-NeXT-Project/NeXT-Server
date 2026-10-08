package main

import (
	"os"
	"os/exec"
)

func main() {
	var args []string
	args = append(args, "-tiny")
	args = append(args, os.Args[1:]...)
	command := exec.Command("garble", args...)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		os.Exit(1)
	}
}
