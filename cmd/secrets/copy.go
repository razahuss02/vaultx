/*
Package secrets implements the "copy" subcommand under the "secrets" command in the vaultx CLI.

The "copy" command enables users to recursively copy secrets from one Vault mount path to another,
potentially between different Vault instances. It detects the KV (Key-Value) engine version and
handles traversing secret paths accordingly.

Usage:
  vaultx secrets copy --source-mount=<mount-path>

Key Features:
  - Detects KV engine version (v1 or v2)
  - Recursively traverses secret paths under the specified mount
  - Prepares a list of secrets for copying

This subcommand is intended for operators who need to migrate or duplicate secrets between Vault environments.
*/

package secrets

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/razahuss02/vaultx/internal/vaultclient"
	"github.com/urfave/cli/v3"
)

func CopyCommand() *cli.Command {
	return &cli.Command{
		Name:  "copy",
		Usage: "Copy secrets from one vault instance to another",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name: "source-mount",
			},
			&cli.StringFlag{
				Name: "target-mount",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if err := ValidateFlags(cmd); err != nil {
				return err
			}
			CopySecrets(ctx, cmd)
			return nil
		},
	}
}

func ValidateFlags(cmd *cli.Command) error {
	// Validate --source-mount flag
	sourceMount := cmd.String("source-mount")
	if sourceMount == "" {
		slog.Error("--source-mount flag is required")
		os.Exit(1)
	}

	// Validate --target-mount flag
	targetMount := cmd.String("target-mount")
	if targetMount == "" {
		slog.Error("--target-mount flag is required")
		os.Exit(1)
	}

	return nil
}

func GetSourceMountVersion(ctx context.Context, cmd *cli.Command) (string, error) {
	client := vaultclient.GetVaultClient(ctx)

	sourceMount := cmd.String("source-mount")

	if !strings.HasSuffix(sourceMount, "/") {
		sourceMount += "/"
	}

	response, err := client.System.MountsListSecretsEngines(ctx)
	if err != nil {
		slog.Error("Failed to list secret engines", "error", err)
	}

	version := fmt.Sprintf("%v", response.Data[sourceMount].(map[string]interface{})["options"].(map[string]interface{})["version"])

	return version, err
}

func ListSecrets(ctx context.Context, cmd *cli.Command) ([]string, error) {
	client := vaultclient.GetVaultClient(ctx)
	sourceMount := cmd.String("source-mount")

	kvVersion, err := GetSourceMountVersion(ctx, cmd)
	if err != nil {
		slog.Error("Failed to get source mount version", "error", err)
		return nil, err
	}

	var secretsList []string

	var traverse func(string) error
	traverse = func(currentPath string) error {

		var keys []string

		switch kvVersion {
		case "1":
			response, err := client.Secrets.KvV1List(ctx, currentPath, vault.WithMountPath(sourceMount))
			if err != nil {
				if strings.Contains(err.Error(), "404") {
					slog.Error("404 Not Found at:", "path", currentPath)
					return nil
				}
				return fmt.Errorf("kv v1 list failed at path %q: %w", currentPath, err)
			}
			keys = response.Data.Keys

		case "2":
			response, err := client.Secrets.KvV2List(ctx, currentPath, vault.WithMountPath(sourceMount))
			if err != nil {
				if strings.Contains(err.Error(), "404") {
					slog.Error("404 Not Found at:", "path", currentPath)
					return nil
				}
				return fmt.Errorf("kv v2 list failed at path %q: %w", currentPath, err)
			}
			keys = response.Data.Keys

		default:
			return fmt.Errorf("unsupported kv version: %s", kvVersion)
		}

		for _, key := range keys {
			full := path.Join(currentPath, key)
			if strings.HasSuffix(key, "/") {
				if err := traverse(full); err != nil {
					return err
				}
			} else {
				finalPath := path.Join(sourceMount, full)
				secretsList = append(secretsList, finalPath)
			}
		}

		return nil
	}

	if err := traverse(""); err != nil {
		return nil, err
	}

	return secretsList, nil
}

// Read and Create secret
func CopySecrets(ctx context.Context, cmd *cli.Command) error {
	sourceClient := vaultclient.GetVaultClient(ctx)

	targetAddr := os.Getenv("VAULT_TARGET_ADDR")
	targetToken := os.Getenv("VAULT_TARGET_TOKEN")

	if targetAddr == "" || targetToken == "" {
		slog.Error("VAULT_TARGET_ADDR and VAULT_TARGET_TOKEN environment variables are required")
		os.Exit(1)
	}

	targetClient, _ := vault.New(
		vault.WithAddress(targetAddr),
	)

	if err := targetClient.SetToken(targetToken); err != nil {
		slog.Error("Failed to initialize target vault client", "error", err)
	}

	sourceMount := cmd.String("source-mount")
	targetMount := cmd.String("target-mount")

	kvVersion, err := GetSourceMountVersion(ctx, cmd)
	if err != nil {
		slog.Error("failed to detect source mount version", "error", err)
		os.Exit(1)
	}

	secretsList, err := ListSecrets(ctx, cmd)
	if err != nil {
		slog.Error("failed to list secrets under source mount", "error", err)
		os.Exit(1)
	}

	for _, fullPath := range secretsList {
		relativePath := strings.TrimPrefix(fullPath, strings.TrimSuffix(sourceMount, "/")+"/")

		switch kvVersion {
		case "1":
			secret, err := sourceClient.Secrets.KvV1Read(ctx, relativePath, vault.WithMountPath(sourceMount))
			if err != nil {
				slog.Error("failed to read KV v1 secret", "path", fullPath, "error", err)
				continue
			}

			if secret.Data == nil {
				slog.Warn("no data found at KV v1 secret", "path", fullPath)
			}

			_, err = targetClient.Secrets.KvV1Write(ctx, relativePath, secret.Data, vault.WithMountPath(targetMount))
			if err != nil {
				slog.Error("failed to write KV v1 secret to target mount", "path", relativePath, "error", err)
				continue
			}

			slog.Info("successfully copied KV v1 secret", "path", relativePath)

		case "2":
			secret, err := sourceClient.Secrets.KvV2Read(ctx, relativePath, vault.WithMountPath(sourceMount))
			if err != nil {
				slog.Error("failed to read KV v2 secret", "path", fullPath, "error", err)
			}

			if secret.Data.Data == nil {
				slog.Warn("no data found at KV v2 secret", "path", fullPath)
			}

			req := schema.KvV2WriteRequest{
				Data: secret.Data.Data,
			}
			_, err = targetClient.Secrets.KvV2Write(ctx, relativePath, req, vault.WithMountPath(targetMount))
			if err != nil {
				slog.Error("failed to write KV v2 secret to target mount", "path", relativePath, "error", err)
				continue
			}
			slog.Info("copied KV v2 secret", "path", relativePath)

		default:
			slog.Error("unsupported KV version", "version", kvVersion)
			return fmt.Errorf("unsupported KV version: %s", kvVersion)
		}
	}

	return nil
}
