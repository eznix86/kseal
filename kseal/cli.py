"""CLI commands for kseal."""

import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn
from rich.status import Status
from rich.syntax import Syntax

from .config import CONFIG_FILE_NAME, create_config_file, get_unsealed_dir
from .exceptions import KsealError
from .secrets import (
    build_secret_from_cluster_data,
    decrypt_sealed_secret,
    encrypt_secret,
    find_sealed_secrets,
    format_secret_yaml,
)
from .services import FileSystem, Kubernetes, Kubeseal
from .services.filesystem import DefaultFileSystem
from .services.kubernetes import DefaultKubernetes
from .services.kubeseal import DefaultKubeseal

console = Console()
err_console = Console(stderr=True)

_default_fs = DefaultFileSystem()


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
    fs: FileSystem = _default_fs,
    *,
    color: bool = True,
) -> None:
    """View decrypted secret contents to stdout."""
    secret = decrypt_sealed_secret(path, kubernetes, fs)
    yaml_content = format_secret_yaml(secret)
    print_yaml(yaml_content, color=color)


def export_single(
    path: Path,
    kubernetes: Kubernetes,
    output: Path | None = None,
    fs: FileSystem = _default_fs,
) -> Path:
    """Export a single SealedSecret to file. Returns the output path."""
    secret = decrypt_sealed_secret(path, kubernetes, fs)
    yaml_content = format_secret_yaml(secret)

    if output is None:
        unsealed_dir = get_unsealed_dir()
        output = unsealed_dir / path

    fs.mkdir(output.parent, parents=True, exist_ok=True)
    fs.write_text(output, yaml_content)
    return output


def export_all(
    kubernetes: Kubernetes,
    fs: FileSystem = _default_fs,
    *,
    show_progress: bool = True,
) -> tuple[int, list[str]]:
    """Export all SealedSecrets recursively from local files.

    Returns tuple of (exported_count, error_messages).
    """
    sealed_secrets = find_sealed_secrets(fs=fs)

    if not sealed_secrets:
        return 0, []

    unsealed_dir = get_unsealed_dir()
    exported_count = 0
    errors = []

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
                    secret = decrypt_sealed_secret(sealed_path, kubernetes, fs)
                    yaml_content = format_secret_yaml(secret)

                    output_path = unsealed_dir / sealed_path
                    fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                    fs.write_text(output_path, yaml_content)
                    exported_count += 1
                except KsealError as e:
                    errors.append(f"{sealed_path}: {e}")
                progress.update(task, advance=1)
    else:
        for sealed_path in sealed_secrets:
            try:
                secret = decrypt_sealed_secret(sealed_path, kubernetes, fs)
                yaml_content = format_secret_yaml(secret)

                output_path = unsealed_dir / sealed_path
                fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                fs.write_text(output_path, yaml_content)
                exported_count += 1
            except KsealError as e:
                errors.append(f"{sealed_path}: {e}")

    return exported_count, errors


def export_all_from_cluster(
    kubernetes: Kubernetes,
    fs: FileSystem = _default_fs,
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
    errors = []

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
                    secret = build_secret_from_cluster_data(cluster_data)
                    yaml_content = format_secret_yaml(secret)

                    namespace = cluster_data["namespace"]
                    name = cluster_data["name"]
                    output_path = unsealed_dir / namespace / f"{name}.yaml"
                    fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                    fs.write_text(output_path, yaml_content)
                    exported_count += 1
                except KsealError as e:
                    errors.append(f"{cluster_data['namespace']}/{cluster_data['name']}: {e}")
                progress.update(task, advance=1)
    else:
        for cluster_data in cluster_secrets:
            try:
                secret = build_secret_from_cluster_data(cluster_data)
                yaml_content = format_secret_yaml(secret)

                namespace = cluster_data["namespace"]
                name = cluster_data["name"]
                output_path = unsealed_dir / namespace / f"{name}.yaml"
                fs.mkdir(output_path.parent, parents=True, exist_ok=True)
                fs.write_text(output_path, yaml_content)
                exported_count += 1
            except KsealError as e:
                errors.append(f"{cluster_data['namespace']}/{cluster_data['name']}: {e}")

    return exported_count, errors


def encrypt_to_sealed(
    path: Path, kubeseal: Kubeseal, fs: FileSystem = _default_fs
) -> str:
    """Encrypt a plaintext Secret to SealedSecret. Returns sealed YAML."""
    return encrypt_secret(path, kubeseal, fs)


@click.group()
@click.version_option()
def main():
    """kseal - A kubeseal companion CLI.

    Easily view, export, and encrypt Kubernetes SealedSecrets.
    Automatically manages kubeseal binary download and configuration.

    \b
    Commands:
      cat      View decrypted secret from cluster
      export   Export decrypted secrets to files
      encrypt  Encrypt plaintext secrets using kubeseal
      init     Create configuration file

    \b
    Examples:
      kseal cat k8s/secrets/app.yaml
      kseal export --all
      kseal encrypt secret.yaml -o sealed.yaml
    """
    pass


@main.command()
@click.option("-f", "--force", is_flag=True, help="Overwrite existing config file")
def init(force: bool):
    """Initialize kseal configuration file.

    Creates a .kseal-config.yaml file in the current directory with default values.
    You can then edit this file to customize:

    \b
    - kubeseal_path: Path to kubeseal binary
    - version: Kubeseal version to download (or 'latest')
    - controller_name: Sealed-secrets controller name
    - controller_namespace: Sealed-secrets controller namespace
    - unsealed_dir: Default directory for exported secrets
    """
    try:
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
        cat_secret(path, DefaultKubernetes(), color=not no_color)
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

    if export_all_flag:
        if from_cluster:
            exported_count, errors = export_all_from_cluster(kubernetes)
        else:
            exported_count, errors = export_all(kubernetes)

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
            output_path = export_single(path, kubernetes, output)
            console.print(f"[bold green]✓[/] Exported to {output_path}")
        except KsealError as e:
            err_console.print(f"[bold red]✗[/] {e}")
            sys.exit(1)
    else:
        err_console.print("[bold red]✗[/] Either provide a path or use --all")
        sys.exit(2)


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--replace", is_flag=True, help="Replace input file with encrypted output")
@click.option("-o", "--output", type=click.Path(path_type=Path), help="Output file path")
def encrypt(path: Path, replace: bool, output: Path | None):
    """Encrypt a plaintext Secret to SealedSecret.

    Reads a plaintext Secret (kind: Secret) and encrypts it using kubeseal.

    Output options:
    - Default: stdout
    - --replace: overwrites input file
    - -o: writes to specified path
    """
    if replace and output:
        err_console.print("[bold red]✗[/] Cannot use both --replace and --output")
        sys.exit(2)

    try:
        sealed_yaml = encrypt_to_sealed(path, DefaultKubeseal())

        if replace:
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


if __name__ == "__main__":
    main()
