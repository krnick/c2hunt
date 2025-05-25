import os
import re
from typing import Set, Any

import click
from androguard.core import androconf
from androguard.misc import AnalyzeAPK, AnalyzeDex
from prettytable import PrettyTable

from c2hunt.analysis.exclude_package import EXCLUDE_PACKAGE
from c2hunt.analysis.opcode import CONST_STRING


def is_valid_apk(path: str) -> bool:
    """Check if the file is a valid APK."""
    return androconf.is_android(path) == "APK"


def is_valid_dex(path: str) -> bool:
    """Check if the file is a valid DEX."""
    return androconf.is_android(path) == "DEX"


def exclude_package(method_name: str) -> bool:
    """Return True if the method should be excluded based on EXCLUDE_PACKAGE rules."""
    for exclude_p in EXCLUDE_PACKAGE:
        if exclude_p in str(method_name) or str(method_name).startswith(exclude_p):
            return True
    return False


def print_method_smali(method_analysis: Any) -> None:
    """Print the smali code for a given method analysis object."""
    for _, ins in method_analysis.get_method().get_instructions_idx():
        print(ins)


def print_c2c(method_analysis: Any) -> None:
    """
    Print constant strings found in a method's instructions, typically for C2 detection.
    """
    rstring = re.compile(r'"([^"]+)"')
    op_stack = []
    for _, ins in method_analysis.get_method().get_instructions_idx():
        ins_str = str(ins)
        if op_stack and CONST_STRING in ins_str:
            match = rstring.search(ins_str)
            if match:
                print(match.group(1))
        op_stack.append(ins_str)


def print_all_methods(apkinfo: "APKinfo") -> None:
    """Print a table of all methods found in the APK/DEX."""
    table = PrettyTable()
    table.field_names = ["Class", "Method", "Descriptor"]
    for item in apkinfo.get_external_methods():
        table.add_row([item.class_name, item.name, item.descriptor])
    table.align["Class"] = "l"
    table.align["Method"] = "l"
    table.align["Descriptor"] = "l"
    table.max_width["Descriptor"] = 50
    print(table)


def print_all_smali(apkinfo: "APKinfo") -> None:
    """Print smali code for all methods in the APK/DEX."""
    for item in apkinfo.get_external_methods():
        click.secho(f"[INFO] smali from: [{item.full_name}]", fg="cyan")
        print_method_smali(item)
        print("=" * 80)


class APKinfo:
    """
    Utility class for analyzing APK and DEX files.
    Provides methods for extracting external methods and string analysis.
    """

    def __init__(self, path: str):
        self.path = path
        self._filename = os.path.basename(path)
        self.apk = None
        self.dvm = None
        self.analysis = None

        if is_valid_apk(path):
            self.apk, self.dvm, self.analysis = AnalyzeAPK(path)
        elif is_valid_dex(path):
            _, _, self.analysis = AnalyzeDex(path)
        else:
            raise ValueError("APK or DEX file required.")

    @property
    def filename(self) -> str:
        return self._filename

    @property
    def external_methods(self) -> Set[Any]:
        """
        Return all external methods from given DEX.
        :return: a set of all external methods MethodAnalysis
        """
        return {
            meth_analysis
            for meth_analysis in self.analysis.get_methods()
            if not meth_analysis.is_external()
        }

    def get_external_methods(self) -> Set[Any]:
        """
        Return all non-external methods, excluding those from excluded packages.
        """
        return {
            meth_analysis
            for meth_analysis in self.analysis.get_methods()
            if not meth_analysis.is_external()
            and not exclude_package(meth_analysis.class_name)
        }

    def get_string_analysis(self) -> Set[Any]:
        """
        Return all strings from the DEX.
        :return: a set of all strings
        """
        return set(self.analysis.get_strings())
