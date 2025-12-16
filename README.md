# kseal

[![PyPI](https://img.shields.io/pypi/v/kseal)](https://pypi.org/project/kseal/)
[![Python](https://img.shields.io/pypi/pyversions/kseal)](https://pypi.org/project/kseal/)
[![License](https://img.shields.io/github/license/eznix86/kseal)](LICENSE)
[![Tests](https://github.com/eznix86/kseal/actions/workflows/test.yml/badge.svg)](https://github.com/eznix86/kseal/actions/workflows/test.yml)

A kubeseal companion CLI for viewing, exporting, encrypting, and **offline decrypting** Kubernetes Secrets.

## Installation

```bash
pipx install kseal
```

<details>
<summary>Other installation methods</summary>

With [uv](https://github.com/astral-sh/uv):

```bash
uv tool install kseal
```

With pip:

```bash
pip install kseal
```

</details>

### Requirements

- Python 3.12+
- Kubernetes cluster access (not required for offline decryption)
- Sealed Secrets controller installed in cluster

## Quick Start

```bash
# View a decrypted secret (requires cluster access)
kseal cat secrets/app.yaml

# Export all secrets to files
kseal export --all

# Encrypt a plaintext secret
kseal encrypt secret.yaml -o sealed.yaml

# Offline decryption (no cluster access needed)
kseal export-keys                              # Backup keys while you have access
kseal decrypt sealed.yaml                      # Decrypt using local keys
kseal decrypt-all --in-place                   # Decrypt all SealedSecrets
```

## Commands

### `kseal cat`

View decrypted secret contents with syntax highlighting.

```bash
kseal cat path/to/sealed-secret.yaml
kseal cat sealed.yaml --no-color
```

### `kseal export`

Export decrypted secrets to files.

```bash
# Single file
kseal export sealed.yaml
kseal export sealed.yaml -o output.yaml

# All local SealedSecrets
kseal export --all

# All secrets from cluster
kseal export --all --from-cluster
```

Default output: `.unsealed/<original-path>` or `.unsealed/<namespace>/<name>.yaml`

### `kseal encrypt`

Encrypt plaintext secrets using kubeseal.

```bash
# To stdout
kseal encrypt secret.yaml

# To file
kseal encrypt secret.yaml -o sealed.yaml

# Replace original file
kseal encrypt secret.yaml --in-place
```

### `kseal export-keys`

Export sealed-secrets private keys from cluster for offline decryption.

```bash
# Export to default location
kseal export-keys                      # → .kseal-keys/

# Custom output directory
kseal export-keys -o ./backup

# From different namespace
kseal export-keys -n kube-system
```

### `kseal decrypt`

Decrypt a SealedSecret using local private keys (no cluster access needed).

```bash
# Using keys from default location
kseal decrypt sealed.yaml

# Using specific key file
kseal decrypt sealed.yaml --private-key ./key.pem

# From stdin
cat sealed.yaml | kseal decrypt

# Filter keys by pattern
kseal decrypt sealed.yaml --private-keys-regex "2025"
```

### `kseal decrypt-all`

Decrypt all SealedSecrets in a directory using local private keys.

```bash
# Search current directory, output to stdout
kseal decrypt-all

# Search specific directory
kseal decrypt-all ./manifests

# Replace files in-place
kseal decrypt-all --in-place

# Custom keys location
kseal decrypt-all --private-keys-path ./backup
```

### `kseal init`

Create a configuration file with the latest kubeseal version pinned.

```bash
kseal init
kseal init --force  # Overwrite existing
```

### `kseal version`

Manage kubeseal binary versions.

```bash
# List downloaded versions
kseal version list

# Download the latest version
kseal version update

# Set global default version
kseal version set 0.27.0

# Clear default (use highest downloaded)
kseal version set --clear
```

## Configuration

Configuration priority: Environment variables > `.kseal-config.yaml` > Global settings

| Option | Environment Variable | Default |
|--------|---------------------|---------|
| `version` | `KSEAL_VERSION` | Global default or highest downloaded |
| `controller_name` | `KSEAL_CONTROLLER_NAME` | `sealed-secrets` |
| `controller_namespace` | `KSEAL_CONTROLLER_NAMESPACE` | `sealed-secrets` |
| `unsealed_dir` | `KSEAL_UNSEALED_DIR` | `.unsealed` |

<details>
<summary>Example config file</summary>

```yaml
# .kseal-config.yaml
version: "0.27.0"
controller_name: sealed-secrets
controller_namespace: kube-system
unsealed_dir: .secrets
```

</details>

## Version Management

kseal automatically manages kubeseal binary versions:

- Binaries are stored at `~/.local/share/kseal/kubeseal-<version>`
- Each project can pin a specific version in `.kseal-config.yaml`
- Global settings are stored in `~/.local/share/kseal/settings.yaml`

**Version resolution order:**
1. Project config version (`.kseal-config.yaml`)
2. Global default version (`kseal version set`)
3. Highest downloaded version
4. Fetch latest from GitHub (first run only)

## Security

- Add `.unsealed/` and `.kseal-keys/` to your `.gitignore`
- Never commit plaintext secrets or private keys to version control
- Store exported keys securely (e.g., password manager, encrypted backup)
- Offline decryption with `kseal decrypt` requires the private keys - keep them safe

## Contributing

```bash
git clone https://github.com/eznix86/kseal.git
cd kseal
uv sync

# Run tests
make test

# Run linter
make lint
```

## License

[MIT](LICENSE)
