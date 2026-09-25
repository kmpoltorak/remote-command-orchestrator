// Command rco runs commands, scripts and file uploads on many Linux hosts over SSH.
package main

import (
	"os"

	"github.com/kmpoltorak/remote-command-orchestrator/internal/cli"
)

func main() { os.Exit(cli.Main(os.Args[1:], os.Stdout, os.Stderr)) }
