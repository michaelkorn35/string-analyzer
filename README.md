# String Analyzer (Prototype)

When staticaly analyzing a file, the biggest headache is reviewin the strings. Most executables contain at least a couple of thousands of strings and it can go up to millions as the size goes up. Around 85% of the strings if not more are short blobs that have no meaning or strings that have no meaning to the analysis process. For that reason I created the String Analyzer, to automate the process of gathering the important details.

Extracts printable strings from executables (EXE/DLL/etc.) and reports potentially interesting indicators (URLs, domains, IPs, paths, filenames, errors/keywords, and encoded/encrypted-looking strings).

## Usage

Analyze one file and write a JSON report:

```bash
python -m string_analyzer "C:\Windows\System32\notepad.exe" --out report.json
```

Or if installed as a script (optional):

```bash
string-analyzer "C:\Windows\System32\notepad.exe" --out report.json
```

## Output (JSON schema v1)

Top-level keys:
- `input_path`: input file path
- `file_size`: bytes
- `sha256`: SHA-256 hex digest of file bytes
- `generated_at`: UTC ISO-8601 timestamp
- `settings`: extraction/detection settings used
- `counts`: total extracted + unique strings
- `categories`: per-category `count` and `matches`

## Extending

Easy next steps:
- Add scoring/ranking (`top_n`) without changing detectors.
- Add PE-aware extraction (sections, resources).
- Add IPv6 parsing, better domain parsing, and IOC enrichment.
