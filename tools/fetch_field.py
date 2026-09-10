"""Fetch a validated Field artifact from a nightly that actually produced one.

The latest successful workflow may be the catch-up no-op. Walk successful
runs until an unexpired, current-layout artifact is found; never deploy a
partial download or silently omit the instrument's data.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from pipeline import contracts, field_export


def validate(directory: Path, *, allow_sample: bool = False) -> dict:
    meta = json.loads((directory / 'field.json').read_text(encoding='utf8'))
    contracts.validate('field.json', meta)
    if meta.get('sample') and not allow_sample:
        raise ValueError('Refusing to deploy sample Field data')
    if meta['layout']['version'] != field_export.LAYOUT_VERSION:
        raise ValueError('Run the nightly with this code to produce a current Field layout')
    packed = (directory / meta['bin']).read_bytes()
    if len(packed) != meta['bin_bytes'] or hashlib.sha256(packed).hexdigest() != meta['sha256']:
        raise ValueError('Field compressed size/checksum mismatch')
    raw = gzip.decompress(packed)
    if len(raw) != meta['raw_bytes']:
        raise ValueError('Field raw size mismatch')
    for row in field_export.decode(raw):
        if row[6] >= len(meta['cnas']) or row[8] >= len(meta['vendors']) or not 0 <= row[12] <= 4:
            raise ValueError('Field record contains an invalid dictionary index or EPSS bucket')
    return meta


def gh(*args: str) -> str:
    return subprocess.check_output(['gh', *args], text=True)


def fetch(destination: Path) -> None:
    runs = json.loads(gh('run', 'list', '--workflow=nightly.yml', '--branch=main',
                         '--status=success', '--limit', '30', '--json', 'databaseId'))
    for run in runs:
        run_id = str(run['databaseId'])
        artifacts = json.loads(gh('api', f'repos/{{owner}}/{{repo}}/actions/runs/{run_id}/artifacts'))
        if not any(a['name'] == 'field-latest' and not a['expired'] for a in artifacts['artifacts']):
            continue
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            try:
                gh('run', 'download', run_id, '--name', 'field-latest', '--dir', tmp)
                meta = validate(directory)
            except (OSError, ValueError, subprocess.CalledProcessError) as exc:
                print(f'Skipping nightly {run_id}: {exc}', file=sys.stderr)
                continue
            destination.mkdir(parents=True, exist_ok=True)
            shutil.copy2(directory / meta['bin'], destination / meta['bin'])
            shutil.copy2(directory / 'field.json', destination / 'field.json')
            print(f"Field from nightly {run_id}: {meta['n']:,} records, {meta['generated_at']}")
            return
    raise RuntimeError('No valid current-layout Field artifact. Run the nightly on this revision before deploying.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=Path('site/field'))
    parser.add_argument('--validate-only', action='store_true')
    args = parser.parse_args()
    if args.validate_only:
        print(json.dumps(validate(args.out), indent=2))
    else:
        fetch(args.out)
