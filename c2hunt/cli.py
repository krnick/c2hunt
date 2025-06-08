import click

from c2hunt.main import analyze_target, get_smali


@click.command()
@click.option(
    "-f", "--file",
    required=True,
    type=click.Path(exists=True),
    help="Target APK or DEX file."
)
@click.option(
    "-o", "--opcode",
    default="custom-opcode/switch-equals.json",
    show_default=True,
    type=click.Path(exists=True),
    help="Path to the custom opcode JSON file.",
)
@click.option(
    "-p", "--print-smali",
    is_flag=True,
    help="Print all smali methods from the target APK/DEX instead of scanning."
)
def cli(file: str, opcode: str, print_smali: bool) -> None:
    """
    C2Hunt - Analyze Android APK/DEX files for C2 commands.
    """
    if print_smali:
        click.secho(f"[INFO] Extracting smali from: {file}", fg="cyan")
        get_smali(file)
    else:
        click.secho(f"[INFO] Analyzing: {file}", fg="cyan")
        click.secho(f"[INFO] Using OPcode & Android API Pattern Rule: {opcode}", fg="cyan")
        analyze_target(file, opcode)


if __name__ == "__main__":
    cli()
