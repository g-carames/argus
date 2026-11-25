# Milestone 2.1: CLI path compatibility and diagnostics

This maintenance milestone corrects user-selected path handling and adds fixed,
sanitized operational diagnostics. Inventory recognition, analysis capabilities,
report schema, dependency requirements, and package version remain unchanged.
No Milestone 3 implementation is included.

## Path behavior and safety

Input and output directory selections accept relative paths, absolute paths, `.`,
and repeated `..` components against the caller's current working directory.
Every directory component must exist and be accessible. Examples from a checkout
with an adjacent testing laboratory:

```sh
uv run argus scan ../test_programs_argus/01_clean_python
uv run argus scan ../test_programs_argus/01_clean_python --output ../new-report.json
uv run argus scan /authorized/work/../project --output /private/tmp/new-report.json
```

Previously `Path.absolute()` was compared with `Path.resolve()`. The first
preserves parent segments and the second collapses them, so valid `..` paths were
mistakenly rejected as symbolic links. That comparison has been removed.

The directory opener walks actual components in order using POSIX directory
descriptors, non-following stat observations, and `O_DIRECTORY | O_NOFOLLOW`
opens. It never collapses `link/../project` to `project` before inspecting `link`.
Missing components followed by `..` are also rejected, as normal filesystem path
resolution requires. Stat observations classify errors; no-follow opens enforce
the safety boundary even if a component changes between stat and open.

The final input descriptor stays pinned throughout discovery. Child entries are
still obtained from directory listings and inspected/opened relative to authorized
directory descriptors. Repository-derived traversal paths are not passed through
the user-selection helper. User selection through `..` establishes a root; it
does not authorize following repository symlinks or escaping that selected root.

The final output parent descriptor is likewise pinned. Output creation retains
the `.json`/`.txt` suffix requirement, `O_CREAT | O_EXCL | O_NOFOLLOW`, and mode
`0600` (subject to a more restrictive process umask). Existing files, directories,
hard links, symlinks, and dangling symlinks are not overwritten. A concurrent
destination creation also fails without replacement. A write failure may leave
the newly created partial file; Argus does not delete or replace existing objects.

All actual symlink directory components remain prohibited. This includes safe
internal aliases and macOS `/tmp`, which is a symlink to `/private/tmp`. Use the
non-symlink `/private/tmp` spelling. Diagnostics offer that trusted fixed hint;
no automatic alias exception or arbitrary symlink resolution has been added.

## Stable, sanitized diagnostics

Expected operational errors have the form `argus: CODE: trusted message` on stderr.
They never interpolate user paths, argument values, source, configuration values,
or raw exception strings. Argument parsing also avoids echoing invalid arguments.

| Code | Meaning | Exit |
| --- | --- | ---: |
| `ARGUS_ARGUMENTS_INVALID` | Invalid command-line arguments; consult help | 2 |
| `ARGUS_INPUT_UNAVAILABLE` | Input is not an existing accessible directory | 2 |
| `ARGUS_INPUT_SYMLINK_COMPONENT` | Input selection contains a symlink; includes the `/private/tmp` hint | 2 |
| `ARGUS_CONFIG_INVALID` | Configuration or exclusion patterns are invalid/unreadable | 2 |
| `ARGUS_OUTPUT_PARENT_UNAVAILABLE` | Output parent is not an existing accessible directory | 2 |
| `ARGUS_OUTPUT_PARENT_SYMLINK` | Output parent contains a symlink; includes the `/private/tmp` hint | 2 |
| `ARGUS_OUTPUT_ALREADY_EXISTS` | Destination already exists and cannot be overwritten | 2 |
| `ARGUS_OUTPUT_SUFFIX_INVALID` | Output filename does not end in `.json` or `.txt` | 2 |
| `ARGUS_OUTPUT_WRITE_FAILED` | File or stdout write failed; a new partial file may remain | 2 |
| `ARGUS_INTERNAL_ERROR` | Unexpected internal exception; details deliberately withheld | 70 |

Inventory limitations still use exit 1 with the structured report; normal
exclusions/unavailable analysis can return 0. Cancellation remains exit 130.
Input errors occur before report serialization. Output errors may occur after a
scan has completed; a zero-length or partial new destination is not a valid report.

## Automated regression validation

On Python 3.12.16/macOS, `uv run --offline pytest -q` passed **222 tests**: the
existing 164 tests plus 58 new path/diagnostic regression cases. Coverage includes:

- Relative and absolute parent segments, repeated parents, dot selections, and
  relative output destinations.
- Input/output symlinks followed by parents, dangling links, missing components,
  and the macOS `/tmp` restriction with helpful diagnostics.
- Repository containment and no-follow behavior during a swapped-component race.
- Pinned input/output directory descriptors during rename/replacement.
- Existing output files, directories, hard links and symlinks; concurrent
  destination creation; missing parents; allowed suffixes; owner-only permissions.
- Exact trusted diagnostic messages; fictional sensitive exception/path/config
  data is never echoed; distinct internal-failure exit status.
- Descriptor cleanup and partial output behavior on write failures, including
  stdout failure.

The sdist and wheel build offline with `uv build --offline`. The wheel was installed
with `uv pip install --offline` into a fresh uv-created Python 3.12 environment,
using the already cached pathspec 0.12.1 dependency. Installed help/version and
all seven fixture scans succeeded. No target dependencies were installed, target
code executed, or external services accessed.

## Independent inventory revalidation

The approved independent laboratory and its ground truth were not changed.
Seven new reports were generated by the installed wheel into fresh temporary
destinations, using `../test_programs_argus/<fixture>` as each input. The original
independent 23 comparison checks per fixture were repeated: **161 checks passed**.
Every new report also exactly matches its previously approved JSON report.

| Synthetic repository | Ground-truth regular files | Inventoried files | Gaps | Result |
| --- | ---: | ---: | ---: | --- |
| `01_clean_python` | 13 | 13 | 0 | Pass |
| `02_flawed_python` | 7 | 7 | 0 | Pass |
| `03_clean_fullstack` | 22 | 22 | 0 | Pass |
| `04_vibecoded_fullstack` | 17 | 17 | 0 | Pass |
| `05_unsupported_languages` | 22 | 22 | 0 | Pass |
| `06_discovery_edge_cases` | 28 | 22 | 11 | Pass; expected exclusions |
| `07_large_monorepo` | 1,003 | 1,003 | 0 | Pass |

The discovery fixture's 11 gaps are six pruned directories (`.venv`, `build`,
`dist`, `ignored`, `node_modules`, `src/deep/private`) and five skipped symlinks.
Six regular files are inside pruned directories. Four individually excluded
regular files remain in inventory with unavailable line counts; 18 regular files
are eligible for content inspection. A scratch Git reference confirms the
manifest's ten ignored regular files. Nested negations work as expected. Unicode
filenames are present under documented privacy-masked names.

Language comparisons normalize JSX/TSX family labels and C#/C++ names. Markdown
and Git ignore recognition are valid extra format observations. Framework
recognition is limited to the documented manifest/configuration registry; absence
of Vite, sqlite3, pytest, setuptools, requests, or a fictional model observation
does not establish a scanner regression. Ambiguous `.m`/`.h` candidates and unknown
formats remain disclosed. Malformed source is inventoried without syntax parsing;
arbitrary configuration files are not all syntax-validated.

All reports retain the exact mandatory disclaimer, complete Not Reviewed Portions
of the Code records, explicit unsupported capabilities/categories, valid containment
hierarchies and evidence references, and source-free credential-safe output. The
1,003-file monorepo is complete, with 132 directory nodes and 100 inferred packages.
Fingerprint checks confirm the laboratory, ground truth, and original reports
remained unchanged. A separate installed scan also verifies relative output with
parent segments.

These are inventory compatibility/completeness results, not static analysis
accuracy, architectural/security safety, or production-scale performance
benchmarks. Every analysis report remains partial with unavailable analysis
capabilities. POSIX APIs are required; Windows compatibility, filesystem snapshots,
hard process-memory/wall-clock bounds, and protection against arbitrary unlabelled
secrets in filenames remain outside the guarantees. No language adapters, analysis
rules, UI, frontend assets, or advanced features were implemented.
