# vaultx

**vaultx** is a lightweight and powerful CLI tool that extends [HashiCorp Vault](https://www.vaultproject.io/) by providing automation-friendly commands to **create** and **copy** secrets across environments or Vault instances.

## ✨ Features

- 🔐 **Create secrets from JSON**
  - Create secrets in Vault directly from structured `.json` files
  - Supports both KV v1 and v2 engines
  - Automatically detects the correct secret engine and mount path
- 🔁 **Copy secrets between Vaults**
  - Recursively traverse and copy secrets from one mount path to another
  - Supports copying between **Vault instances**
  - Detects and uses the appropriate KV version for each mount

## 📦 Installation

### Homebrew (recommended)

```sh
brew tap razahuss02/vaultx
brew install vaultx
```

### Build from source

```sh
git clone https://github.com/razahuss02/vaultx.git
cd vaultx
go build -o vaultx
```

## Usage

### Export variables

```sh
export VAULT_ADDR=""
export VAULT_TOKEN=""
```

### Create Secrets from JSON

```sh
vaultx secrets create --from-file=secrets.json
```

### Copy Secrets Between Vault

```sh
export VAULT_TARGET_ADDR=""
export VAULT_TARGET_TOKEN=""

vaultx secrets copy --source-mount=secrets --target-mount=secrets-backup
```