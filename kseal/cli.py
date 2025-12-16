"""CLI commands for kseal."""

import base64
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.status import Status
from rich.syntax import Syntax

from .binary import download_kubeseal, get_default_binary_path, get_latest_version
from .config import CONFIG_FILE_NAME, create_config_file, get_unsealed_dir
from .decrypt import get_private_key_paths
from .exceptions import KsealError
from .secrets import (
    decrypt_sealed_secret,
    decrypt_secret,
    encrypt_secret,
    find_sealed_secrets,
    format_secrets_yaml,
)
from .services import FileSystem, Kubernetes, Kubeseal
from .services.filesystem import DefaultFileSystem
from .services.kubernetes import DefaultKubernetes, Secret
from .services.kubeseal import DefaultKubeseal
from .settings import (
    clear_default_version,
    get_downloaded_versions,
    load_settings,
    set_default_version,
)
from .yaml_utils import YamlDoc

DEFAULT_KEYS_PATH = Path(".kseal-keys")

console = Console()
err_console = Console(stderr=True)


def _build_secret_from_cluster_data(cluster_data: Secret) -> YamlDoc:
    """Build a Secret dict from cluster data."""
    metadata: dict[str, Any] = {
        "name": cluster_data.name,
        "namespace": cluster_data.namespace,
    }
    string_data: dict[str, str] = {}

    if cluster_data.labels:
        metadata["labels"] = cluster_data.labels

    if cluster_data.annotations:
        filtered = {
            k: v
            for k, v in cluster_data.annotations.items()
            if not k.startswith("kubectl.kubernetes.io/")
        }
        if filtered:
            metadata["annotations"] = filtered

    for key, value in cluster_data.data.items():
        try:
            decoded = base64.b64decode(value).decode("utf-8")
            string_data[key] = decoded
        except Exception:
            string_data[key] = f"<binary data: {len(value)} bytes>"

    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": metadata,
        "stringData": string_data,
    }


def print_yaml(content: str, *, color: bool = True) -> None:
    """Print YAML content with optional syntax highlighting."""
    if color and console.is_terminal:
        syntax = Syntax(content, "yaml", theme="monokai", background_color="default")
        console.print(syntax)
    else:
        click.echo(content, nl=False)


def cat_secret(
    path: Path,
    kubernetes: Kubernetes,
    fs: FileSystem,
    *,
    color: bool = True,
) -> None:
    """View decrypted secret contents to stdout."""
    secrets = decrypt_sealed_secret(path, kubernetes, fs)
    yaml_content = format_secrets_yaml(secrets)
    print_yaml(yaml_content, color=color)


def export_single(
    path: Path,
    kubernetes: Kubernetes,
    fs: FileSystem,
    output: Path | None = None,
) -> Path:
    """Export a single SealedSecret to file. Returns the output path."""
    secrets = decrypt_sealed_secret(path, kubernetes, fs)
    yaml_content = format_secrets_yaml(secrets)

    if output is None:
        unsealed_dir = get_unsealed_dir()
        output = unsealed_dir / path

    fs.mkdir(output.parent, parents=True, exist_ok=True)
    fs.write_text(output, yaml_content)
    return output


def export_all(
    kubernetes: Kubernetes,
    fs: FileSystem,
    *,
    show_progress: bool = True,
) -> tuple[int, list[str]]:
    """Export all SealedSecrets recursively from local files.

    Returns tuple of (exported_count, error_messages).
    """
    sealed_secrets = find_sealed_secrets(Path("."), fs)

    if not sealed_secrets:
        return 0, []

    unsealed_dir = get_unsealed_dir()
    exported_count = 0
    errors: list[str] = []

    if show_progress:
        with Progress(
            TextColumn("[bold blue]Exporting secrets..."),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("export", total=len(sealed_secrets))

            for sealed_path in sealed_secrets:
                try:
                    secrets: list[YamlDoc] = decrypt_sealed_secret(sealed_path, kubernetes, fs)
                    yaml_content = format_secrets_yaml(secrets)

                    output_path = unsealed_dir / sealed_path
                    fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                    fs.write_text(output_path, yaml_content)
                    exported_count += 1
                except KsealError as e:
                    errors.append(f"{sealed_path}: {e}")
                _ = progress.update(task, advance=1)
    else:
        for sealed_path in sealed_secrets:
            try:
                secrets = decrypt_sealed_secret(sealed_path, kubernetes, fs)
                yaml_content = format_secrets_yaml(secrets)

                output_path = unsealed_dir / sealed_path
                fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                fs.write_text(output_path, yaml_content)
                exported_count += 1
            except KsealError as e:
                errors.append(f"{sealed_path}: {e}")

    return exported_count, errors


def export_all_from_cluster(
    kubernetes: Kubernetes,
    fs: FileSystem,
    *,
    show_progress: bool = True,
) -> tuple[int, list[str]]:
    """Export all SealedSecrets directly from the cluster.

    Returns tuple of (exported_count, error_messages).
    """
    if show_progress:
        with Status("[bold blue]Fetching secrets from cluster...", console=console):
            cluster_secrets = kubernetes.list_sealed_secrets()
    else:
        cluster_secrets = kubernetes.list_sealed_secrets()

    if not cluster_secrets:
        return 0, []

    unsealed_dir = get_unsealed_dir()
    exported_count = 0
    errors: list[str] = []

    if show_progress:
        with Progress(
            TextColumn("[bold blue]Exporting secrets from cluster..."),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("export", total=len(cluster_secrets))

            for cluster_data in cluster_secrets:
                try:
                    secret: YamlDoc = _build_secret_from_cluster_data(cluster_data)
                    yaml_content = format_secrets_yaml([secret])

                    output_path = (
                        unsealed_dir / cluster_data.namespace / f"{cluster_data.name}.yaml"
                    )
                    fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                    fs.write_text(output_path, yaml_content)
                    exported_count += 1
                except KsealError as e:
                    errors.append(f"{cluster_data.namespace}/{cluster_data.name}: {e}")
                _ = progress.update(task, advance=1)
    else:
        for cluster_data in cluster_secrets:
            try:
                secret = _build_secret_from_cluster_data(cluster_data)
                yaml_content = format_secrets_yaml([secret])

                output_path = unsealed_dir / cluster_data.namespace / f"{cluster_data.name}.yaml"
                fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                fs.write_text(output_path, yaml_content)
                exported_count += 1
            except KsealError as e:
                errors.append(f"{cluster_data.namespace}/{cluster_data.name}: {e}")

    return exported_count, errors


def encrypt_to_sealed(path: Path, kubeseal: Kubeseal, fs: FileSystem) -> str:
    """Encrypt a plaintext Secret to SealedSecret. Returns sealed YAML."""
    return encrypt_secret(path, kubeseal, fs)


def export_sealing_keys(
    output: Path,
    kubernetes: Kubernetes,
    fs: FileSystem,
    namespace: str = "sealed-secrets",
) -> int:
    """Export sealed-secrets private keys from cluster.

    Returns the number of keys exported.
    """
    keys = kubernetes.get_sealing_keys(namespace)

    if not keys:
        return 0

    fs.mkdir(output, parents=True, exist_ok=True)

    for key_data in keys:
        key_path = output / f"{key_data.name}.key"
        fs.write_text(key_path, key_data.tls_key.decode())

    return len(keys)


def decrypt_offline_single(
    path: Path | None,
    private_key_paths: list[Path],
    fs: FileSystem,
    kubeseal: Kubeseal,
    stdin_content: str | None = None,
) -> str:
    """Decrypt a single SealedSecret file using kubeseal CLI.

    Returns decrypted Secret YAML.
    """
    if path:
        content = fs.read_text(path)
    elif stdin_content:
        content = stdin_content
    else:
        raise KsealError("No input provided")

    return kubeseal.decrypt(content, private_key_paths)


def decrypt_offline_all(
    search_path: Path,
    private_key_paths: list[Path],
    fs: FileSystem,
    kubeseal: Kubeseal,
    *,
    show_progress: bool = True,
    preserve_other_docs: bool = False,
) -> tuple[list[tuple[Path, str]], list[str]]:
    """Decrypt all SealedSecrets in a directory using kubeseal CLI.

    Args:
        preserve_other_docs: If True, preserves non-SealedSecret documents
            (ConfigMaps, etc.) in their original positions. Use for --in-place.

    Returns tuple of (decrypted_results, errors).
    """
    sealed_secrets = find_sealed_secrets(search_path, fs)

    if not sealed_secrets:
        return [], []

    results: list[tuple[Path, str]] = []
    errors: list[str] = []

    def process_file(sealed_path: Path) -> None:
        try:
            content = fs.read_text(sealed_path)
            if preserve_other_docs:
                decrypted = decrypt_secret(content, kubeseal, private_key_paths)
            else:
                decrypted = kubeseal.decrypt(content, private_key_paths)
            results.append((sealed_path, decrypted))
        except KsealError as e:
            errors.append(f"{sealed_path}: {e}")

    if show_progress:
        with Progress(
            TextColumn("[bold blue]Decrypting secrets..."),
            BarColumn(),
            MofNCompleteColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("decrypt", total=len(sealed_secrets))

            for sealed_path in sealed_secrets:
                process_file(sealed_path)
                _ = progress.update(task, advance=1)
    else:
        for sealed_path in sealed_secrets:
            process_file(sealed_path)

    return results, errors


@click.group()
@click.version_option()
def main():
    """kseal - A kubeseal companion CLI.

    Easily view, export, and encrypt Kubernetes SealedSecrets.
    Automatically manages kubeseal binary download and configuration.

    \b
    Examples:
      kseal cat k8s/secrets/app.yaml
      kseal export --all
      kseal encrypt secret.yaml -o sealed.yaml
      kseal decrypt sealed.yaml --private-keys-path .kseal-keys/
      kseal version list
    """
    pass


@main.command()
@click.option("-f", "--force", is_flag=True, help="Overwrite existing config file")
def init(force: bool):
    """Initialize kseal configuration file.

    Creates a .kseal-config.yaml file in the current directory.
    Fetches the latest kubeseal version from GitHub and pins it in the config.

    \b
    Config options:
    - version: Kubeseal version for this project
    - controller_name: Sealed-secrets controller name
    - controller_namespace: Sealed-secrets controller namespace
    - unsealed_dir: Default directory for exported secrets
    """
    try:
        with Status("[bold blue]Fetching latest kubeseal version...", console=console):
            config_path = create_config_file(overwrite=force)
        console.print(f"[bold green]✓[/] Created {config_path}")
    except FileExistsError:
        err_console.print(
            f"[bold red]✗[/] {CONFIG_FILE_NAME} already exists. Use --force to overwrite.",
        )
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--no-color", is_flag=True, help="Disable colored output")
def cat(path: Path, no_color: bool):
    """View decrypted secret contents to stdout.

    Reads SealedSecret from file, fetches the actual Secret from the cluster,
    and outputs decrypted stringData to stdout as YAML with syntax highlighting.
    """
    try:
        cat_secret(path, DefaultKubernetes(), DefaultFileSystem(), color=not no_color)
    except KsealError as e:
        err_console.print(f"[bold red]✗[/] {e}")
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), required=False)
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file path")
@click.option("--all", "export_all_flag", is_flag=True, help="Export all SealedSecrets recursively")
@click.option("--from-cluster", is_flag=True, help="Export secrets directly from cluster")
def export(path: Path | None, output: Path | None, export_all_flag: bool, from_cluster: bool):
    """Export decrypted secret to file.

    Without --all: exports a single SealedSecret file.
    With --all: finds and exports all SealedSecrets in current directory.
    With --all --from-cluster: exports all SealedSecrets directly from the cluster.

    Default output location is .unsealed/<original-path>
    """
    if from_cluster and not export_all_flag:
        err_console.print("[bold red]✗[/] --from-cluster requires --all")
        sys.exit(2)

    kubernetes = DefaultKubernetes()
    fs = DefaultFileSystem()

    if export_all_flag:
        if from_cluster:
            exported_count, errors = export_all_from_cluster(kubernetes, fs)
        else:
            exported_count, errors = export_all(kubernetes, fs)

        if exported_count == 0 and not errors:
            console.print("[yellow]No SealedSecrets found.[/]")
            return

        unsealed_dir = get_unsealed_dir()
        console.print(f"[bold green]✓[/] Exported {exported_count} secrets to {unsealed_dir}/")

        if errors:
            err_console.print("\n[bold red]Errors:[/]")
            for error in errors:
                err_console.print(f"  [red]•[/] {error}")
            sys.exit(1)
    elif path:
        try:
            output_path = export_single(path, kubernetes, fs, output)
            console.print(f"[bold green]✓[/] Exported to {output_path}")
        except KsealError as e:
            err_console.print(f"[bold red]✗[/] {e}")
            sys.exit(1)
    else:
        err_console.print("[bold red]✗[/] Either provide a path or use --all")
        sys.exit(2)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("-i", "--in-place", is_flag=True, help="Replace input file with encrypted output")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file path")
def encrypt(path: Path, in_place: bool, output: Path | None):
    """Encrypt a plaintext Secret to SealedSecret.

    Reads a plaintext Secret (kind: Secret) and encrypts it using kubeseal.

    Output options:
    - Default: stdout
    - --in-place: overwrites input file
    - -o: writes to specified path
    """
    if in_place and output:
        err_console.print("[bold red]✗[/] Cannot use both --in-place and --output")
        sys.exit(2)

    try:
        sealed_yaml = encrypt_to_sealed(path, DefaultKubeseal(), DefaultFileSystem())

        if in_place:
            path.write_text(sealed_yaml)
            console.print(f"[bold green]✓[/] Encrypted and replaced {path}")
        elif output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(sealed_yaml)
            console.print(f"[bold green]✓[/] Encrypted to {output}")
        else:
            click.echo(sealed_yaml, nl=False)
    except KsealError as e:
        err_console.print(f"[bold red]✗[/] {e}")
        sys.exit(1)


@main.command("export-keys")
@click.option(
    "-o",
    "--output",
    type=click.Path(path_type=Path),
    default=DEFAULT_KEYS_PATH,
    help="Output directory for keys",
)
@click.option(
    "-n",
    "--namespace",
    default="sealed-secrets",
    help="Namespace where sealed-secrets controller is installed",
)
def export_keys_cmd(output: Path, namespace: str):
    """Export sealed-secrets private keys from cluster.

    Fetches all sealing keys from the sealed-secrets controller and saves
    them as .key files in the output directory.

    \b
    Examples:
      kseal export-keys                    Export to .kseal-keys/
      kseal export-keys -o ./backup        Export to ./backup/
      kseal export-keys -n kube-system     From different namespace
    """
    try:
        with Status("[bold blue]Fetching sealing keys from cluster...", console=console):
            count = export_sealing_keys(output, DefaultKubernetes(), DefaultFileSystem(), namespace)

        if count == 0:
            console.print("[yellow]No sealing keys found.[/]")
        else:
            console.print(f"[bold green]✓[/] Exported {count} key(s) to {output}/")
    except KsealError as e:
        err_console.print(f"[bold red]✗[/] {e}")
        sys.exit(1)


@main.command()
@click.argument("path", type=click.Path(path_type=Path), required=False)
@click.option(
    "--private-keys-path",
    type=click.Path(path_type=Path),
    default=DEFAULT_KEYS_PATH,
    help="Directory containing private keys",
)
@click.option(
    "--private-key",
    type=click.Path(exists=True, path_type=Path),
    help="Single private key file",
)
@click.option(
    "--private-keys-regex",
    default=".*",
    help="Regex pattern to filter key files",
)
@click.option("--no-color", is_flag=True, help="Disable colored output")
def decrypt(
    path: Path | None,
    private_keys_path: Path,
    private_key: Path | None,
    private_keys_regex: str,
    no_color: bool,
):
    """Decrypt a SealedSecret using kubeseal CLI.

    Reads a SealedSecret file and decrypts it using the provided
    private keys via kubeseal --recovery-unseal.

    \b
    Examples:
      kseal decrypt sealed.yaml                         Use .kseal-keys/
      kseal decrypt sealed.yaml --private-key key.pem   Use specific key
      cat sealed.yaml | kseal decrypt                   From stdin
    """
    fs = DefaultFileSystem()
    kubeseal = DefaultKubeseal()

    try:
        # Get private key paths
        if private_key:
            key_paths = [private_key]
        else:
            key_paths = get_private_key_paths(private_keys_path, private_keys_regex, fs)

        # Get input content
        if path:
            stdin_content = None
        else:
            # Read from stdin
            stdin_content = click.get_text_stream("stdin").read()
            if not stdin_content.strip():
                err_console.print("[bold red]✗[/] No input provided (use path or stdin)")
                sys.exit(2)

        decrypted = decrypt_offline_single(path, key_paths, fs, kubeseal, stdin_content)
        print_yaml(decrypted, color=not no_color)

    except KsealError as e:
        err_console.print(f"[bold red]✗[/] {e}")
        sys.exit(1)


@main.command("decrypt-all")
@click.argument("path", type=click.Path(path_type=Path), default=".")
@click.option(
    "--private-keys-path",
    type=click.Path(path_type=Path),
    default=DEFAULT_KEYS_PATH,
    help="Directory containing private keys",
)
@click.option(
    "--private-keys-regex",
    default=".*",
    help="Regex pattern to filter key files",
)
@click.option("-i", "--in-place", is_flag=True, help="Replace files in-place")
@click.option("--no-color", is_flag=True, help="Disable colored output")
def decrypt_all_cmd(
    path: Path,
    private_keys_path: Path,
    private_keys_regex: str,
    in_place: bool,
    no_color: bool,
):
    """Decrypt all SealedSecrets using kubeseal CLI.

    Finds all SealedSecret files in a directory and decrypts them
    using kubeseal --recovery-unseal.

    \b
    Output modes:
    - Default: prints decrypted secrets to stdout as multi-doc YAML
    - --in-place: replaces original files with decrypted versions

    \b
    Examples:
      kseal decrypt-all                               Search from current dir
      kseal decrypt-all ./manifests                   Search from ./manifests
      kseal decrypt-all --in-place                    Replace files in-place
      kseal decrypt-all --private-keys-regex "2025"   Filter keys by pattern
    """
    fs = DefaultFileSystem()
    kubeseal = DefaultKubeseal()

    try:
        # Get private key paths
        key_paths = get_private_key_paths(private_keys_path, private_keys_regex, fs)

        # Decrypt all (preserve other docs like ConfigMaps when replacing in-place)
        results, errors = decrypt_offline_all(
            Path(path), key_paths, fs, kubeseal, preserve_other_docs=in_place
        )

        if not results and not errors:
            console.print("[yellow]No SealedSecrets found.[/]")
            return

        if in_place:
            # Write decrypted content back to original files
            for file_path, decrypted in results:
                fs.write_text(file_path, decrypted)
            console.print(f"[bold green]✓[/] Decrypted {len(results)} file(s) in-place")
        else:
            # Output to stdout
            for i, (file_path, decrypted) in enumerate(results):
                if i > 0:
                    click.echo("---")
                click.echo(f"# Source: {file_path}")
                print_yaml(decrypted, color=not no_color)

        if errors:
            err_console.print("\n[bold red]Errors:[/]")
            for error in errors:
                err_console.print(f"  [red]•[/] {error}")
            sys.exit(1)

    except KsealError as e:
        err_console.print(f"[bold red]✗[/] {e}")
        sys.exit(1)


@main.group()
def version():
    """Manage kubeseal versions."""
    pass


@version.command("list")
def version_list():
    """List all downloaded kubeseal versions."""
    versions = get_downloaded_versions()
    settings = load_settings()
    explicit_default = settings.kubeseal_version_default

    if not versions:
        console.print("[yellow]No kubeseal versions downloaded yet.[/]")
        return

    console.print("[bold]Downloaded versions:[/]")
    for v in versions:
        if explicit_default and v == explicit_default:
            console.print(f"  [green]{v}[/] [dim](default)[/]")
        elif not explicit_default and v == versions[0]:
            console.print(f"  [green]{v}[/] [dim](latest downloaded)[/]")
        else:
            console.print(f"  {v}")


@version.command("update")
def version_update():
    """Download the latest kubeseal version from GitHub."""
    try:
        with Status("[bold blue]Checking latest version...", console=console):
            latest = get_latest_version()
        path = get_default_binary_path(latest)

        if path.exists():
            console.print(f"[green]Already up to date:[/] v{latest}")
        else:
            download_kubeseal(latest, path)
    except Exception as e:
        err_console.print(f"[bold red]✗[/] Failed to update: {e}")
        sys.exit(1)


@version.command("set")
@click.argument("ver", required=False)
@click.option("--clear", is_flag=True, help="Clear default, use highest downloaded version")
def version_set(ver: str | None, clear: bool):
    """Set the global default kubeseal version.

    \b
    Examples:
      kseal version set 0.25.0    Set default to specific version
      kseal version set --clear   Clear default, use highest downloaded
    """
    if clear:
        clear_default_version()
        console.print("[green]✓[/] Cleared default version (will use highest downloaded)")
        return

    if not ver:
        err_console.print("[bold red]✗[/] Provide a version or use --clear")
        sys.exit(2)

    set_default_version(ver)
    console.print(f"[green]✓[/] Default version set to: {ver}")


if __name__ == "__main__":
    main()
