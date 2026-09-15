#!/usr/bin/env python3
"""Validate Git-only releases and generate deterministic source manifests."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tomllib

ROOT = Path(__file__).resolve().parent.parent
VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args])


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_state():
    package = tomllib.loads((ROOT / "Cargo.toml").read_text())["package"]
    version = package["version"]
    require(VERSION.fullmatch(version), "version must be a three-part SemVer release")
    require(package.get("publish") is False, "publish must remain false")
    require(package.get("repository") == "https://github.com/Dastari/agql-auth",
            "repository metadata must identify Dastari/agql-auth")
    headings = re.findall(r"^## (.+)$", (ROOT / "CHANGELOG.md").read_text(), re.M)
    require(headings and headings[0] == version,
            "top changelog entry must equal the package version (no Unreleased entry)")
    require((ROOT / "Cargo.lock").is_file(), "a reviewed Cargo.lock is required")
    require(not tomllib.loads((ROOT / "Cargo.toml").read_text()).get("features"),
            "new Cargo features require explicit validation lanes before release")
    return version


def latest_tag():
    tags = git("tag", "--merged", "HEAD", "--list", "v*").decode().splitlines()
    tags = [tag for tag in tags if VERSION.fullmatch(tag[1:])]
    require(tags, "no historical v<version> baseline tag exists")
    return max(tags, key=lambda tag: tuple(map(int, tag[1:].split("."))))


def check_policy(base=None):
    version = check_state()
    base = base or latest_tag()
    git("merge-base", "--is-ancestor", base, "HEAD")
    previous = tomllib.loads(git("show", f"{base}:Cargo.toml").decode())["package"]["version"]
    require(VERSION.fullmatch(previous), "baseline version is not a release SemVer")
    current_tuple = tuple(map(int, version.split(".")))
    previous_tuple = tuple(map(int, previous.split(".")))
    require(current_tuple >= previous_tuple, "package version must not move backwards")
    # Compare the working tree too, so this gate also reviews uncommitted release preparation.
    changed = git("diff", "--name-only", base, "--", "src", "Cargo.toml", "build.rs").decode()
    if changed:
        require(current_tuple > previous_tuple, "source/manifest changes require a version bump")
        require(git("show", f"{base}:CHANGELOG.md") != (ROOT / "CHANGELOG.md").read_bytes(),
                "source changes require a changelog entry")
    print(f"release-policy: {base} -> {version} passed")


def release_identity():
    version = check_state()
    require(not git("status", "--porcelain", "--untracked-files=no").strip(),
            "a clean committed tree is required")
    git("ls-files", "--error-unmatch", "Cargo.lock")
    return version, git("rev-parse", "HEAD").decode().strip()


def manifest(output):
    version, commit = release_identity()
    data = {"commit": commit, "version": version, "tag": f"v{version}",
            "cargoLock": hashlib.sha256(git("show", "HEAD:Cargo.lock")).hexdigest()}
    Path(output).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def render_notes(version, commit):
    return "\n".join([
        f"# v{version}",
        "",
        "This is an immutable, Git-only source release.",
        f'Consumers pin the annotated release tag (`tag = "v{version}"`) as the Git',
        f"reference for this library, and record the commit `{commit}` from the",
        "attached manifest in their own reviewed pin record.",
        "A published release tag is annotated and is never moved, so the tag and the",
        "recorded commit remain one identity.",
        "",
        "The attached `v<version>.json` manifest is the canonical release record; see",
        "`CHANGELOG.md` and `MIGRATION.md` at this tag.",
        "",
    ])


def notes(output):
    version, commit = release_identity()
    Path(output).write_text(render_notes(version, commit))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check-state")
    policy = commands.add_parser("check-policy")
    policy.add_argument("base", nargs="?")
    commands.add_parser("baseline")
    generate = commands.add_parser("manifest")
    generate.add_argument("--output", required=True)
    body = commands.add_parser("notes")
    body.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.command == "check-state":
        print(f"release-state: {check_state()} passed")
    elif args.command == "check-policy":
        check_policy(args.base)
    elif args.command == "baseline":
        print(latest_tag())
    elif args.command == "notes":
        notes(args.output)
    else:
        manifest(args.output)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.CalledProcessError) as error:
        print(f"release: {error}", file=sys.stderr)
        sys.exit(1)
