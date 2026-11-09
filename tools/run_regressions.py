"""Run the packaged native Xtensa suite in a disposable, network-isolated BN container."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

def export_bundled_plugin(destination: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / "manifest.json").read_text())
    hashes = manifest["files"]
    if hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest() != manifest["payload_sha256"]:
        raise ValueError("Plugin manifest digest mismatch")
    for relative, expected in hashes.items():
        path = (root / relative).resolve()
        if not path.is_relative_to(root) or digest(path) != expected:
            raise ValueError(f"Plugin input mismatch: {relative}")
    destination.mkdir()
    for relative in [*hashes, "manifest.json"]:
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / relative, target)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bn-install", type=Path, required=True)
    parser.add_argument("--bn-license", type=Path, required=True)
    parser.add_argument("--image", default="matteroverwatch-job-runner:latest")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    suite = Path(__file__).resolve().parents[1] / "regressions/xtensa"
    manifest = json.loads((suite / "suite_manifest.json").read_text())
    for relative, expected in manifest["files"].items():
        path = (suite / relative).resolve()
        if not path.is_relative_to(suite) or digest(path) != expected:
            raise ValueError(f"Packaged regression input mismatch: {relative}")
    installation, license_path = args.bn_install.resolve(), args.bn_license.resolve()
    if not (installation / "bnpython3").is_file() or not license_path.is_file():
        parser.error("BN installation must contain bnpython3 and license must exist")
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=False)
    for relative in manifest["files"]:
        destination = output / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(suite / relative, destination)
    export_bundled_plugin(output / "plugin")
    settings = output / "settings.json"
    settings.write_text(json.dumps({"warp.container.loadBundledFiles": False,
                                    "warp.container.loadUserFiles": False}) + "\n")
    provenance = {"suite_manifest_sha256": digest(suite / "suite_manifest.json"),
                  "launcher_sha256": digest(Path(__file__)), "image": args.image,
                  "plugin_manifest": json.loads((output / "plugin/manifest.json").read_text()),
                  "status": "started"}
    evidence = output / "launcher_manifest.json"
    evidence.write_text(json.dumps(provenance, indent=2) + "\n")
    command = ["docker", "run", "--rm", "--network", "none", "--user", "0",
               "-e", "PYTHONUTF8=1", "-e", "BN_USER_DIRECTORY=/home/matter/.binaryninja",
               "--entrypoint", "/opt/binaryninja/bnpython3",
               "-v", f"{installation}:/opt/binaryninja:ro",
               "-v", f"{license_path}:/home/matter/.binaryninja/license.dat:ro",
               "-v", f"{output / 'plugin'}:/home/matter/.binaryninja/plugins/binja-xtensa:ro",
               "-v", f"{settings}:/home/matter/.binaryninja/settings.json:ro",
               "-v", f"{output}:/port", args.image, "/port/run_regressions.py"]
    with (output / "suite.log").open("x") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    provenance.update(status="passed" if result.returncode == 0 else "failed",
                      returncode=result.returncode)
    evidence.write_text(json.dumps(provenance, indent=2) + "\n")
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
