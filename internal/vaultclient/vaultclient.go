/*
Package vaultclient provides a simplified Vault client initialization and access pattern for the vaultx CLI.

It handles:
  - Initialization of a HashiCorp Vault client using environment variables (VAULT_ADDR, VAULT_TOKEN)
  - Attaching the client to a context for easy retrieval throughout the application
  - Graceful logging when configuration is missing or the client is not found

Environment Variables:
  VAULT_ADDR   - The address of the Vault server (e.g., https://vault.example.com)
  VAULT_TOKEN  - The Vault token used for authentication

This package is intended to centralize Vault client setup and promote safe and consistent access
to the client across subcommands.
*/

package vaultclient

import (
	"context"
	"log/slog"
	"os"

	vault "github.com/hashicorp/vault-client-go"
)

type ctxKey string

const vaultClientKey ctxKey = "vault-client"

func GetVaultClient(ctx context.Context) *vault.Client {
	client, ok := ctx.Value(vaultClientKey).(*vault.Client)
	if !ok {
		slog.Error("Vault client not found in context")
		return nil
	}
	return client
}

func InitVaultContext() (context.Context, error) {
	addr := os.Getenv("VAULT_ADDR")
	token := os.Getenv("VAULT_TOKEN")

	if addr == "" || token == "" {
		slog.Error("VAULT_ADDR and VAULT_TOKEN environment variables must be set.")
		os.Exit(1)
	}

	client, err := vault.New(vault.WithEnvironment())
	if err != nil {
		slog.Error("Failed to initialize vault client", "error", err)
		return nil, err
	}

	ctx := context.WithValue(context.Background(), vaultClientKey, client)
	return ctx, nil
}
