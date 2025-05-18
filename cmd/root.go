/*
Package cmd defines the root command for the vaultx CLI.

The root command initializes the CLI application, sets up global context such as Vault authentication,
and registers all top-level subcommands. Currently, it includes the "secrets" subcommand for managing Vault secrets.

Usage:
  vaultx [command] [subcommand] [flags]

Features:
  - Initializes a Vault client context shared across subcommands
  - Registers CLI commands using urfave/cli
  - Supports versioning via the Version variable

This package serves as the entry point for the CLI and should be called from the main function.
*/

package cmd

import (
	"os"

	"github.com/razahuss02/vaultx/cmd/secrets"
	"github.com/razahuss02/vaultx/internal/vaultclient"
	"github.com/urfave/cli/v3"
)

var Version = "dev"

func RootCommand() error {

	ctx, err := vaultclient.InitVaultContext()
	if err != nil {
		return err
	}

	cmd := &cli.Command{
		Name:    "vaultx",
		Usage:   "Vault extension CLI",
		Version: Version,
		Commands: []*cli.Command{
			secrets.SecretsCommand(),
		},
	}

	return cmd.Run(ctx, os.Args)
}
