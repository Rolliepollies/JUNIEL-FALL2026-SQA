Team name: JUNIEL

Team members: Justin Diehl, Daniel Choi

## Running the fuzzer

From the repo root:

```bash
pip install -r slikube/requirements.txt
python fuzz.py
python fuzz.py --strict
```

## Forensics (audit log)

Set `SLIKUBE_AUDIT` to a file path to record an audit entry for each call to
the 10 instrumented methods in `slikube/parser.py`. Leave it unset to turn
logging off.

PowerShell:

```powershell
$env:SLIKUBE_AUDIT = Join-Path (Get-Location).Path 'slikube-audit.jsonl'
python fuzz.py
```

Bash:

```bash
SLIKUBE_AUDIT="$PWD/slikube-audit.jsonl" python fuzz.py
```

GitHub Actions runs the fuzzer with logging on for every push and PR, and
uploads `fuzz_report.json` and `slikube-audit.jsonl` as the
`fuzz-and-forensics` artifact.
