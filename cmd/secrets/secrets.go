/*
Package secrets defines the "secrets" subcommand for the vaultx CLI.

The secrets subcommand provides operations for managing secrets, and includes
subcommands such as "copy" and "create" for handling secret duplication and
creation respectively.

Usage hierarchy:
  vaultx secrets [subcommand]

Available subcommands:
  copy    - Copy secrets between locations or formats.
  create  - Create new secrets with specified parameters.

This package integrates with urfave/cli to expose structured and extensible CLI behavior.
*/

package secrets

import (
	"github.com/urfave/cli/v3"
)

func SecretsCommand() *cli.Command {
	return &cli.Command{
		Name: "secrets",
		Commands: []*cli.Command{
			CopyCommand(),
			CreateCommand(),
		},
	}
}
