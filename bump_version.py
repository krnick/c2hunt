import re
import sys
from pathlib import Path

def bump_version(version: str) -> str:
    parts = version.strip().split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"Invalid version: {version}")
    parts[2] = str(int(parts[2]) + 1)
    return ".".join(parts)

def update_file_version(file_path: Path, pattern: str, replace_fmt: str):
    text = file_path.read_text(encoding="utf-8")
    match = re.search(pattern, text)
    if not match:
        print(f"Version not found in {file_path}")
        return False
    old_version = match.group(1)
    new_version = bump_version(old_version)
    new_text = re.sub(pattern, replace_fmt.format(new_version), text)
    file_path.write_text(new_text, encoding="utf-8")
    print(f"{file_path}: {old_version} -> {new_version}")
    return True

def main():
    updated = False
    # pyproject.toml
    pyproject = Path("pyproject.toml")
    if pyproject.exists():
        updated |= update_file_version(
            pyproject,
            r'version\s*=\s*"([^"]+)"',
            'version = "{}"'
        )
    # setup.py
    setup = Path("setup.py")
    if setup.exists():
        updated |= update_file_version(
            setup,
            r'version\s*=\s*"([^"]+)"',
            'version="{}"'
        )
    if not updated:
        print("No version updated.")
        sys.exit(1)

if __name__ == "__main__":
    main()
