/*
The main package is the entry point for the vaultx CLI application.

It invokes the RootCommand function from the cmd package to initialize and run
the CLI, and exits the program with an error code if command execution fails.

This file should remain minimal, delegating all CLI setup and logic to the cmd package.
*/

package main

import (
	"log"

	"github.com/razahuss02/vaultx/cmd"
)

func main() {
	if err := cmd.RootCommand(); err != nil {
		log.Fatal(err)
	}
}
