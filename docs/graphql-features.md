# GraphQL feature selection

Since 0.24.0, Auth declares:

```toml
async-graphql = { version = "7", default-features = false }
```

Auth needs no named async-graphql features. Its guards, context/request data,
errors/extensions, response sanitization and static schema integration use core
APIs. Domain UUID/time values do not require GraphQL scalar features. No Auth
API, SDL, wire format, storage or authentication behavior changes.

This deliberately removes the previous transitive default-feature contribution.
Hosts using extra capabilities must enable them directly on the same resolved
async-graphql package, for example:

```toml
async-graphql = { version = "7", default-features = false, features = ["graphiql", "playground", "dynamic-schema", "tempfile"] }
```

Choose only needed capabilities; `email-validator` is also an explicit host
choice. `tempfile` selects file-backed `UploadValue::content`; without it the
content is bytes-backed. See [migration](../MIGRATION.md). Cargo feature
unification remains additive: another consumer can enable defaults or named
features, but Auth itself contributes none. This is not a complete host license
audit or a guarantee that another dependency's features disappear.

## Independent consumer verification

The two manifests below are separate workspaces with separate committed locks.
Do not put them into one workspace: that would mask feature leakage through
unification. Both compile and execute the same real Auth guard/context/error
and response-sanitization tests. The additive consumer also exercises GraphiQL,
playground, dynamic schema and the file-backed upload representation. It does
not enable email validation.

Use Rust 1.90.0 and the repository's bounded Cargo runner where required.
For each standalone lane (defaults and `--no-default-features`), retain
`cargo tree --locked -e features` and `cargo metadata --locked --format-version 1`
output, then check the metadata with:

```bash
python3 scripts/check-graphql-feature-graph.py minimal /path/to/metadata.json
```

Run each independent consumer from the repository root:

```bash
cargo +1.90.0 test --locked --manifest-path testdata/graphql-features/minimal/Cargo.toml
cargo +1.90.0 test --locked --manifest-path testdata/graphql-features/additive/Cargo.toml
# Repeat metadata/tree collection with each --manifest-path, then:
python3 scripts/check-graphql-feature-graph.py minimal /path/to/minimal-metadata.json
python3 scripts/check-graphql-feature-graph.py additive /path/to/additive-metadata.json
```

The assertions inspect activated resolved nodes/features, not unused lockfile
entries. Minimal graphs must omit async-graphql defaults, email-validator,
fast_chemail, ascii_utils, GraphiQL, playground, dynamic-schema and tempfile.
Additive graphs must contain the explicit host features, without attributing
them to Auth. Keep dependency versions fixed when refreshing these locks.

Auth is database/provider neutral. These fixtures need no database, credentials
or live provider. They do not establish combined ORM/AI graph minimality or
SQLite/PostgreSQL/MSSQL adapter compatibility; composing hosts own those checks.
