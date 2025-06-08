# c2hunt

```
  ____ ____  _                 _   
 / ___|___ \| |__  _   _ _ __ | |_ 
| |     __) | '_ \| | | | '_ \| __|
| |___ / __/| | | | |_| | | | | |_ 
 \____|_____|_| |_|\__,_|_| |_|\__|
Hunting potential C2 commands in Android malware via Smali string comparison and control flow analysis
```

C2Hunt is a command-line tool for analyzing Android APK or DEX files to detect Command and Control (C2) commands within given target file. The tool supports scanning for C2 commands based on custom opcode definitions and can also extract strings or smali methods from APK/DEX files for further analysis.

## Features

- Analyze Android APK/DEX files for C2 commands handling structures
- Print all smali methods from the target APK/DEX
- Support for custom opcode/API definition in JSON format

## Installation

You can use either `pip` or `pipenv` to install dependencies.

### Using pip

```bash
pip install -r requirements.txt
```

### Using pipenv

```bash
pipenv install
```

## Usage

After installation, you can run the tool directly with the `c2hunt` command:

```bash
c2hunt --file <APK_OR_DEX_PATH> [--opcode <OPCODE_JSON>] [--print-smali]
```

or with short options:

```bash
c2hunt -f <APK_OR_DEX_PATH> [-o <OPCODE_JSON>] [-p]
```

### Options

- `-f, --file PATH` (required):  
  Path to the target APK or DEX file

- `-o, --opcode PATH` (optional, default: `custom-opcode/switch-equals.json`):  
  Path to the custom opcode JSON file

- `-p, --print-smali` (flag, optional):  
  Print all smali methods from the target APK/DEX instead of scanning for C2 commands

### Examples

#### Analyze an APK with the default opcode file

```bash
c2hunt -f target.apk
```

#### Analyze a DEX file with a custom opcode file

```bash
c2hunt -f classes.dex -o my-opcodes.json
```

#### Print all smali methods (no analysis)

```bash
c2hunt -f target.apk -p
```

## How It Works

- By default, C2Hunt scans the specified APK or DEX file for C2 commands using the given opcode definition file.
- If the `--print-smali` flag is provided, it will only print all smali methods without analysis.
