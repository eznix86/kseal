# kseal

[![PyPI](https://img.shields.io/pypi/v/kseal)](https://pypi.org/project/kseal/)
[![Python](https://img.shields.io/pypi/pyversions/kseal)](https://pypi.org/project/kseal/)
[![License](https://img.shields.io/github/license/eznix86/kseal)](LICENSE)
[![Tests](https://github.com/eznix86/kseal/actions/workflows/test.yml/badge.svg)](https://github.com/eznix86/kseal/actions/workflows/test.yml)

A kubeseal companion CLI for viewing, exporting, and encrypting Kubernetes SealedSecrets.

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
- Kubernetes cluster access
- Sealed Secrets controller installed in cluster

## Quick Start

```bash
# View a decrypted secret
kseal cat secrets/app.yaml

# Export all secrets to files
kseal export --all

# Encrypt a plaintext secret
kseal encrypt secret.yaml -o sealed.yaml
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

# Replace original
kseal encrypt secret.yaml --replace
```

### `kseal init`

Create a configuration file.

```bash
kseal init
kseal init --force  # Overwrite existing
```

## Configuration

Configuration priority: Environment variables > `.kseal-config.yaml` > Defaults

| Option | Environment Variable | Default |
|--------|---------------------|---------|
| `kubeseal_path` | `KSEAL_KUBESEAL_PATH` | `~/.local/share/kseal/kubeseal` |
| `version` | `KSEAL_VERSION` | `latest` |
| `controller_name` | `KSEAL_CONTROLLER_NAME` | `sealed-secrets` |
| `controller_namespace` | `KSEAL_CONTROLLER_NAMESPACE` | `sealed-secrets` |
| `unsealed_dir` | `KSEAL_UNSEALED_DIR` | `.unsealed` |

<details>
<summary>Example config file</summary>

```yaml
# .kseal-config.yaml
kubeseal_path: /usr/local/bin/kubeseal
version: "0.27.0"
controller_name: sealed-secrets
controller_namespace: kube-system
unsealed_dir: .secrets
```

</details>

## Security

- Add `.unsealed/` to your `.gitignore`
- Never commit plaintext secrets to version control
- Requires cluster access to decrypt secrets

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
