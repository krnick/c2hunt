import json
from typing import Dict, Any

import click
from loguru import logger

from c2hunt.analysis.apkinfo import APKinfo, print_c2c, print_all_smali
from c2hunt.c2cdetect import C2Detect


def load_opcode_rules(opcode_path: str) -> Dict[str, Any]:
    """
    Load opcode and API rules from a JSON file.
    """
    try:
        with open(opcode_path, "r") as file:
            json_data = json.load(file)
            opcode_dict = json_data.get("opcode", {})
            api_dict = json_data.get("api", {})
            merge_dict = opcode_dict | api_dict
            return merge_dict
    except Exception as e:
        logger.error(f"Failed to load opcode rules: {e}")
        raise


def analyze_target(target_file: str, opcode_path: str) -> None:
    """
    Analyze the given APK for potential C2 command methods.
    """
    logger.remove()  # Remove default logger to reduce noise
    counter_dict = load_opcode_rules(opcode_path)

    click.secho(f"[INFO] Opcode & APIs threshold: {counter_dict}", fg="cyan")
    apk = APKinfo(target_file)

    results = {}
    for method in apk.get_external_methods():
        c2 = C2Detect(counter_dict)
        matched_method = c2.find_c2_command_method(method)
        if matched_method:
            results[matched_method] = c2.get_counter()

    if results:
        click.secho(
            "\n[+] The following functions potentially contain C2 commands:\n",
            fg="green",
            bold=True,
        )
        for method, counter in results.items():
            click.secho(f"Function: {method.full_name}", fg="yellow")
            click.secho(f"Opcode & APIs count: {counter}", fg="yellow")
            click.echo("=" * 80)
            print_c2c(method)
            click.echo("\n")
    else:
        click.secho("[-] No potential C2 command functions found.", fg="red")


def get_smali(target_file: str) -> None:
    """
    Print all smali files for the given APK.
    """
    logger.remove()
    apk = APKinfo(target_file)
    print_all_smali(apk)
