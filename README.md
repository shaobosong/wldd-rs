# wldd-rs - Windows DLL Dependency Analyzer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation of a Windows PE (Portable Executable) dependency analyzer, similar to the Linux `ldd` tool.

## Features

- Analyze DLL dependencies of Windows executables
- Search for dependencies in specified directories
- Report missing dependencies
- Clean, formatted output

## Installation

### From Source

```bash
git clone https://github.com/shaobosong/wldd-rs.git
cd wldd-rs
cargo install --path .
```

## Usage
Basic usage to analyze an executable:

```bash
wldd-rs program.exe
```

Specify additional search directories:

```bash
wldd-rs -d C:\Windows\System32 -d C:\MyLibs program.exe
```

Analyze multiple files:

```bash
wldd-rs program.exe dynamic.dll
```

## Output Format

The output shows each dependency and where it was found:

```text
program.exe:
    KERNEL32.dll => C:\Windows\System32
    USER32.dll   => C:\Windows\System32
    MYLIB.dll    => Not found
```

## Configuration

The tool accepts the following arguments:
- `-d`, `--dir`: Additional directories to search for dependencies (can be specified multiple times)
- `files`: List of files to analyze (required)

## Limitations

- Currently only analyzes direct dependencies (not recursive)
- Only supports PE files (Windows executables and DLLs)
- Doesn't handle delay-loaded dependencies

## License

MIT - See LICENSE for details.
