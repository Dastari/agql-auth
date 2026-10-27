#!/usr/bin/env python3
"""Assert an independently resolved `cargo metadata --locked` GraphQL graph."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("lane", choices=["minimal", "additive"])
parser.add_argument("metadata", type=Path)
args = parser.parse_args()
metadata = json.loads(args.metadata.read_text())
packages = {p["id"]: p for p in metadata["packages"]}
nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
# Inspect only reachable activated nodes, not unused Cargo.lock entries.
pending = [metadata["resolve"]["root"]]
reachable = set()
while pending:
    package_id = pending.pop()
    if package_id in reachable:
        continue
    reachable.add(package_id)
    pending.extend(d["pkg"] for d in nodes[package_id]["deps"])
names = {packages[p]["name"] for p in reachable}
graphql = [p for p in reachable if packages[p]["name"] == "async-graphql"]
assert len(graphql) == 1, "expected one async-graphql source identity"
features = set(nodes[graphql[0]]["features"])
assert not names.intersection({"fast_chemail", "ascii_utils"}), names
assert not features.intersection({"default", "email-validator"}), features
extras = {"graphiql", "playground", "dynamic-schema", "tempfile"}
if args.lane == "minimal":
    assert not features.intersection(extras), features
    assert "tempfile" not in names, names
else:
    assert extras <= features, features
    assert "tempfile" in names, names
auth = [p for p in reachable if packages[p]["name"] == "agql-auth"]
assert len(auth) == 1, "expected one Auth source identity"
edge = [d for d in packages[auth[0]]["dependencies"] if d["name"] == "async-graphql"]
assert len(edge) == 1 and not edge[0]["uses_default_features"] and not edge[0]["features"], edge
print(f"{args.lane}: {len(reachable)} activated packages; async-graphql features={sorted(features)}; Auth contributes no defaults/named features")
