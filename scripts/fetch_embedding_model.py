#!/usr/bin/env python
"""Fetch the local embedding model into the repository, once.

Run this before clustering can use embeddings, and at image build time so the
container never reaches the network at request time. The Pi's DNS is
intermittent (see .planning/STATE.md), so a lazy download on first page render
would be a latent outage rather than a convenience.

    uv run python scripts/fetch_embedding_model.py

Idempotent: an existing, loadable model is left alone unless --force is given.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from pestilentia.ai.embeddings import DEFAULT_MODEL_DIR, DEFAULT_MODEL_ID

# Files model2vec needs to reconstruct a StaticModel offline. Listed explicitly
# rather than mirroring the whole repo: a snapshot pulls READMEs and ONNX
# variants we would then ship in the image for nothing.
REQUIRED_FILES = ("config.json", "model.safetensors", "tokenizer.json")


def verify(directory: Path) -> tuple[bool, str]:
    """Load the model and encode one string — the only check that means
    anything. Present-but-truncated files pass a file-exists check and then
    fail at request time, which is exactly the failure this script exists to
    prevent."""
    missing = [name for name in REQUIRED_FILES if not (directory / name).is_file()]
    if missing:
        return False, f"missing files: {', '.join(missing)}"
    try:
        from model2vec import StaticModel

        model = StaticModel.from_pretrained(str(directory))
        vector = model.encode(["ransomware campaign attribution"])
    except Exception as exc:  # any failure here means unusable
        return False, f"model did not load: {exc}"
    if getattr(vector, "shape", (0, 0))[-1] < 1:
        return False, "model produced an empty vector"
    return True, f"ok, {vector.shape[-1]} dimensions"


def download(model_id: str, directory: Path) -> None:
    from huggingface_hub import hf_hub_download

    directory.mkdir(parents=True, exist_ok=True)
    for name in REQUIRED_FILES:
        print(f"  fetching {name} ...", flush=True)
        cached = hf_hub_download(repo_id=model_id, filename=name)
        shutil.copyfile(cached, directory / name)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-id", default=DEFAULT_MODEL_ID)
    parser.add_argument("--dest", type=Path, default=DEFAULT_MODEL_DIR)
    parser.add_argument("--force", action="store_true", help="re-download even if present")
    args = parser.parse_args()

    print(f"Model:       {args.model_id}")
    print(f"Destination: {args.dest}")

    if not args.force:
        ok, detail = verify(args.dest)
        if ok:
            print(f"Already present and loadable ({detail}). Nothing to do.")
            return 0

    download(args.model_id, args.dest)

    ok, detail = verify(args.dest)
    if not ok:
        print(f"FAILED after download: {detail}", file=sys.stderr)
        return 1

    total = sum(f.stat().st_size for f in args.dest.iterdir() if f.is_file())
    print(f"Verified ({detail}); {total / 1_048_576:.1f} MB on disk.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
