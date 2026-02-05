import subprocess
import json
from pathlib import Path

def run_nuclei_scan(target_url: str, scan_id: str):
    out_dir = Path("work") / scan_id
    out_dir.mkdir(parents=True, exist_ok=True)

    output_file = out_dir / "nuclei.jsonl"

    cmd = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-o", str(output_file),
        "-severity", "info,low,medium,high,critical",
        "-stats",
        "-timeout", "10"
    ]

    subprocess.run(cmd, check=False)

    findings = []
    if output_file.exists():
        for line in output_file.read_text(encoding="utf-8").splitlines():
            try:
                findings.append(json.loads(line))
            except:
                pass
    return findings
