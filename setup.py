from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="c2hunt",
    version="0.0.4",
    description="Hunting Potential C2 Commands in Android Malware via Smali String Comparison and Control Flow Analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="JunWei Song",
    author_email="junwei.song1994@email.com",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=["click", "loguru", "androguard", "black"],
    entry_points={
        "console_scripts": [
            "c2hunt=c2hunt.cli:cli",
        ],
    },
)
