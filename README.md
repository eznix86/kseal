# kseal

[![PyPI](https://img.shields.io/pypi/v/kseal)](https://pypi.org/project/kseal/)
[![Python](https://img.shields.io/pypi/pyversions/kseal)](https://pypi.org/project/kseal/)
[![License](https://img.shields.io/github/license/eznix86/kseal)](LICENSE)
[![Tests](https://github.com/eznix86/kseal/actions/workflows/test.yml/badge.svg)](https://github.com/eznix86/kseal/actions/workflows/test.yml)

A kubeseal companion CLI - view, export, and encrypt Kubernetes SealedSecrets.

## Features

```bash
# View decrypted secret from cluster
kseal cat secrets/app-secret.yaml
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: app-secret
  namespace: production
stringData:
  DATABASE_URL: postgres://user:pass@localhost/db
  API_KEY: sk-1234567890
```

```bash
# Export all SealedSecrets to plaintext files
kseal export --all
```

```bash
# Encrypt a plaintext Secret
kseal encrypt secret.yaml -o sealed-secret.yaml
```

## Key Features

- **View secrets** - Decrypt SealedSecrets by fetching actual values from cluster
- **Export secrets** - Bulk export all SealedSecrets to plaintext files
- **Encrypt secrets** - Convert plaintext Secrets to SealedSecrets using kubeseal
- **Auto-managed binary** - Automatically downloads and manages kubeseal binary
- **Syntax highlighting** - Colored YAML output in terminal

## Installation

```bash
pipx install kseal
```

Or with [uv](https://github.com/astral-sh/uv):

```bash
uv tool install kseal
```

Or with pip:

```bash
pip install kseal
```

### Requirements

- Python 3.12+
- Access to a Kubernetes cluster (for decrypt/export operations)
- Sealed Secrets controller installed in cluster

## Usage

### View a decrypted secret

```bash
kseal cat path/to/sealed-secret.yaml
```

Reads the SealedSecret file, fetches the actual Secret from the cluster, and displays the decrypted values with syntax highlighting.

### Export secrets

```bash
# Export single file
kseal export sealed-secret.yaml

# Export to specific location
kseal export sealed-secret.yaml -o decrypted.yaml

# Export all SealedSecrets recursively (from local files)
kseal export --all

# Export all SealedSecrets directly from cluster
kseal export --all --from-cluster
```

Exported files are saved to `.unsealed/` by default. When using `--from-cluster`, files are organized as `.unsealed/<namespace>/<name>.yaml`.

### Encrypt a secret

```bash
# Output to stdout
kseal encrypt secret.yaml

# Save to file
kseal encrypt secret.yaml -o sealed-secret.yaml

# Replace original file
kseal encrypt secret.yaml --replace
```

### Initialize configuration

```bash
kseal init
```

Creates `.kseal-config.yaml` with default settings.

## Configuration

Configuration is loaded from (in priority order):

1. Environment variables
2. `.kseal-config.yaml` in current directory
3. Default values

| Option | Env Variable | Default | Description |
|--------|--------------|---------|-------------|
| `kubeseal_path` | `KSEAL_KUBESEAL_PATH` | `~/.local/share/kseal/kubeseal` | Path to kubeseal binary |
| `version` | `KSEAL_VERSION` | `latest` | Kubeseal version to download |
| `controller_name` | `KSEAL_CONTROLLER_NAME` | `sealed-secrets` | Sealed Secrets controller name |
| `controller_namespace` | `KSEAL_CONTROLLER_NAMESPACE` | `sealed-secrets` | Controller namespace |
| `unsealed_dir` | `KSEAL_UNSEALED_DIR` | `.unsealed` | Directory for exported secrets |

### Example config file

```yaml
# .kseal-config.yaml
kubeseal_path: /usr/local/bin/kubeseal
version: "0.27.0"
controller_name: sealed-secrets
controller_namespace: kube-system
unsealed_dir: .secrets
```

## Commands

| Command | Description |
|---------|-------------|
| `kseal cat <file>` | View decrypted secret contents |
| `kseal export <file>` | Export decrypted secret to file |
| `kseal export --all` | Export all SealedSecrets recursively from local files |
| `kseal export --all --from-cluster` | Export all SealedSecrets directly from cluster |
| `kseal encrypt <file>` | Encrypt plaintext Secret to SealedSecret |
| `kseal init` | Create configuration file |

## Security

- Exported plaintext secrets are saved to `.unsealed/` which should be in your `.gitignore`
- Never commit plaintext secrets to version control
- The tool requires access to your Kubernetes cluster to decrypt secrets

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

```bash
# Clone and install dev dependencies
git clone https://github.com/eznix86/kseal.git
cd kseal
uv sync

# Run tests
make test

# Run linter
make lint
```

## License

MIT License - see [LICENSE](LICENSE) for details.
