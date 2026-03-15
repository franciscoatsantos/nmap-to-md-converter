# nmap-to-md-converter

Convert Nmap XML output into a Markdown report.

## Requirements

- Python 3
- Nmap

## Usage

### 1) Pipe Nmap XML directly to the script

```bash
nmap <target> -T4 -A -v -oX - | ./nmap_to_md.py
```

Important: This script expects XML input. Use `-oX -` when piping from Nmap.

### 2) Read from an XML file

```bash
./nmap_to_md.py -i test.xml
```

Default behavior in this mode: saves the report to `output.md`.

### 3) Save output to a file

```bash
./nmap_to_md.py -i test.xml -o report.md
```

Or with stdin:

```bash
nmap <target> -T4 -A -v -oX - | ./nmap_to_md.py -o report.md
```

## Notes

- If you run `nmap_to_md.py` without `./`, your shell may execute a different script from your system PATH.
- To ensure you use this project version, run it as `./nmap_to_md.py`.
- Output defaults:
	- Stdin input without `-o`: writes Markdown to stdout.
	- File input (`-i`) without `-o`: writes Markdown to `output.md`.
- If Nmap returns no explicit `<port>` entries (for example all scanned ports are filtered), the report shows a **Port Summary** table using Nmap `extraports` data.

## Example

```bash
cat test.xml | ./nmap_to_md.py > test.md
```
