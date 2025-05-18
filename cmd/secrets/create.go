/*
Package secrets implements the "create" subcommand under the "secrets" command in the vaultx CLI.

The "create" command allows users to create secrets in a Vault instance from a structured JSON file.
It supports both KV engine versions v1 and v2, and automatically detects the appropriate engine and mount path
for each secret based on the Vault server configuration.

Usage:
  vaultx secrets create --from-file=<path-to-file.json>

Flags:
  --from-file, -f   Path to the JSON file containing secret key/value pairs.

Key Features:
  - Parses secret data from a user-provided JSON file
	- Supports both KV v1 and KV v2 engines
  - Automatically detects KV engine version and mount path
  - Intended for use in bootstrapping or automation scenarios involving Vault

This subcommand is ideal for quickly importing predefined secrets into a Vault instance.
*/

package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"strings"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/razahuss02/vaultx/internal/vaultclient"
	"github.com/urfave/cli/v3"
)

type MountInfo struct {
	MountPath string
	Version   string // "v1" or "v2"
}

func CreateCommand() *cli.Command {
	return &cli.Command{
		Name:  "create",
		Usage: "Create secrets from JSON file",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "from-file",
				Aliases: []string{"f"},
			},
			// TODO: add --skip-existing flag
			// &cli.StringFlag{
			// 	Name:    "skip-existing",
			// },
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return CreateSecrets(ctx, cmd)
		},
	}
}

// CreateSecrets reads a structured JSON file containing secrets and writes them to a Vault instance.
//
// The function supports both KV v1 and KV v2 secret engines, automatically determining the correct
// mount and version for each secret path based on the enabled secret engines in Vault.
//
// For each secret, it computes the appropriate mount and relative path, and then writes the data
// to Vault. KV v2 secrets are versioned automatically; KV v1 secrets are overwritten directly.
//
// This function is typically used for bootstrapping secrets in automation workflows.
// It will overwrite existing secrets without prompting. Secrets with an unknown or unsupported
// engine version will be skipped and logged.
func CreateSecrets(ctx context.Context, cmd *cli.Command) error {
	client := vaultclient.GetVaultClient(ctx)
	if client == nil {
		return errors.New("vault client not found in context")
	}

	// validate --from-file flag
	filePath := cmd.String("from-file")
	if filePath == "" {
		slog.Error("--from-file flag is required")
		os.Exit(1)
	}

	raw, err := os.ReadFile(filePath)
	if err != nil {
		slog.Error("failed to load file", "error", err)
		os.Exit(1)
	}

	// load JSON
	var secrets map[string]map[string]interface{}
	if err := json.Unmarshal(raw, &secrets); err != nil {
		slog.Error("invalid JSON structure", "error", err)
		os.Exit(1)
	}

	mountsMap, err := GetSecretEngines(ctx)
	if err != nil {
		slog.Error("unable to list KV secret engines", "error", err)
		os.Exit(1)
	}

	for secretPath, secretData := range secrets {
		mountInfo, relativePath, err := findMountForSecret(ctx, secretPath, mountsMap)
		if err != nil {
			slog.Error("mount not found for secret", "path", secretPath)
			continue
		}

		mount := strings.TrimSuffix(mountInfo.MountPath, "/")
		switch mountInfo.Version {
		case "2":
			req := schema.KvV2WriteRequest{
				Data: secretData,
			}
			resp, err := client.Secrets.KvV2Write(ctx, relativePath, req, vault.WithMountPath(mount))
			if err != nil {
				slog.Error("failed to write KV v2 secret", "path", secretPath, "error", err)
				continue
			}
			slog.Info("KV v2 secret written", "path", secretPath, "version", resp.Data.Version)
		case "1":
			_, err := client.Secrets.KvV1Write(ctx, relativePath, secretData, vault.WithMountPath(mount))
			if err != nil {
				slog.Error("failed to write KV v1 secret", "path", secretPath, "error", err)
				continue
			}
			slog.Info("KV v1 secret written", "path", secretPath)
		default:
			slog.Error("unsupported KV version", "version", mountInfo.Version, "path", secretPath)
		}
	}

	return nil
}

// GetSecretEngines retrieves all enabled secret engine mounts from the Vault server
// and returns a map of mount paths to their associated MountInfo.
//
// It inspects each mount's options to determine whether it is a KV v1 or v2 engine.
// If the version is not explicitly set in the mount's options, it defaults to an
// empty string, which should be treated as v1 by convention.
//
// This function is used to dynamically discover available KV mounts and their versions
// for secret write operations.
func GetSecretEngines(ctx context.Context) (map[string]MountInfo, error) {
	client := vaultclient.GetVaultClient(ctx)
	if client == nil {
		return nil, errors.New("vault client not found in context")
	}

	resp, err := client.System.MountsListSecretsEngines(ctx)
	if err != nil {
		slog.Error("Failed to list secret engines", "error", err)
		return nil, err
	}

	mounts := make(map[string]MountInfo)
	for mountPath, raw := range resp.Data {
		data, ok := raw.(map[string]interface{})
		if !ok {
			slog.Warn("unexpected mount data format", "mountPath", mountPath)
			continue
		}

		version := ""
		if options, ok := data["options"].(map[string]interface{}); ok {
			if v, ok := options["version"].(string); ok {
				version = v
				if version == "" {
					slog.Warn("version not found")
				}
			}
		}

		mounts[mountPath] = MountInfo{
			MountPath: mountPath,
			Version:   version,
		}
	}

	return mounts, nil
}

// findMountForSecret determines the Vault mount that a secret path belongs to
// and returns the corresponding MountInfo along with the path relative to the mount.
//
// It selects the longest matching mount prefix from the available mounts to ensure
// the most specific match is chosen. This is important when mounts overlap, such as
// "secrets/" and "secrets/internal/".
//
// For example, given a secretPath of "secrets/users/user1" and a mount "secrets/",
// it will return the MountInfo for "secrets/" and the relative path "users/user1".
func findMountForSecret(ctx context.Context, secretPath string, mounts map[string]MountInfo) (MountInfo, string, error) {
	client := vaultclient.GetVaultClient(ctx)
	if client == nil {
		return MountInfo{}, "", errors.New("vault client not found in context")
	}

	var bestMatch string
	for mount := range mounts {
		if strings.HasPrefix(secretPath, mount) && len(mount) > len(bestMatch) {
			bestMatch = mount
		}
	}

	relativePath := strings.TrimPrefix(secretPath, bestMatch)
	relativePath = strings.TrimSuffix(relativePath, "/")

	return mounts[bestMatch], relativePath, nil
}
