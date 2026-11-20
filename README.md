# Ilmarinen: Borealis File Integrity agent

Ilmarinen detects **unexpected content changes to files you choose**. It records their SHA-256 hashes in a baseline, then later reports which files changed, disappeared, appeared, or were replaced by links.

It is one independent specialist agent of [Borealis Research](https://github.com/borealis-research-lab). It works on its own and reports in the shared [Borealis agent report format](https://github.com/borealis-research-lab/.github/tree/main/standards) (`borealis-agent-report/1`).

> **Experimental.** Not a production security product.
>
> **Read-only.** Ilmarinen never restores, deletes, quarantines or modifies the files it monitors. It reports; you decide.

## ⚠ Protect the baseline digest

When you create a baseline, Ilmarinen prints its **digest**. **Store that digest somewhere other than this computer**, for example in a password manager or on paper, and pass it to every check:

```
ilmarinen check --config ilmarinen.json --expected-digest <digest>
```

The baseline also contains its own digest, but that **only detects accidental corruption**. An attacker who can change both your files and the baseline can recompute the embedded digest and hide their changes. **Only the independently stored digest catches that.** Each report states whether it was used (`extensions.digest_verified_independently`).

## What it checks, and what it doesn't

- **Checked:** the content (SHA-256) of regular files; whether entries are added or deleted; whether a file became a link or a special file; where links point. Links are fingerprinted, never followed.
- **Not checked:** permissions, ACLs, ownership, timestamps and alternate data streams. Size and modification time are recorded for information only.
- **Not checked:** FIFOs, sockets and devices. They are never opened; they're reported as `unsupported-entry`.
- **Renames** show up as one file deleted plus one added.
- **A non-recursive root** monitors only the entries directly inside it.

## Usage

```bash
python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"   # Windows paths shown

ilmarinen baseline create  --config ilmarinen.json
ilmarinen check            --config ilmarinen.json --expected-digest <digest>          # JSON (default)
ilmarinen check            --config ilmarinen.json --expected-digest <digest> --text   # human-readable
ilmarinen baseline replace --config ilmarinen.json --confirm-replace <current digest>
ilmarinen describe
```

- **`baseline create`** only succeeds after a **complete** scan. If any entry is unreadable, changing, vanished, special, unrepresentable or colliding, it lists the problems and writes nothing; fix or exclude those entries first. The baseline is written atomically and is never overwritten.
- **`baseline replace`** needs the current baseline's digest typed back. It archives the old baseline as `<name>.<time>.replaced.json`, and the next check records that a replacement happened.
- **`check`** writes one JSON report to stdout (exit code 0 whenever a report was written). `--out FILE` also saves it, and never overwrites an existing file. A configuration error exits with 2 and writes no report.

### Configuration (`ilmarinen.json`)

```json
{
  "roots": [
    {"id": "documents", "path": "C:/Users/me/Documents/contracts", "recursive": true, "exclude": ["**/*.tmp", "drafts/"]},
    {"id": "hosts", "path": "C:/Windows/System32/drivers/etc/hosts", "recursive": false, "exclude": []}
  ],
  "baseline": "D:/ilmarinen/baseline.json"
}
```

- **`id`** matches `[a-z][a-z0-9-]{0,31}`. A root is a directory or a single file, and there can be at most 50 roots.
- **Ilmarinen refuses to run** with:
  - duplicate ids;
  - duplicate or nested roots;
  - a root that is itself a link or junction;
  - a missing root;
  - a baseline stored inside a root;
  - an invalid pattern.
- **Exclusion patterns:**
  - match the path relative to the root, using `/` separators, and must match the whole path;
  - `*` and `?` match within one path segment, and `**` matches any number of whole segments;
  - a trailing `/` matches directories only, and an excluded directory isn't entered;
  - **matching ignores case on every platform**;
  - no other syntax exists: no character classes, braces, negation or escapes.

  Excluded entries are counted in the report.

## What reports contain (privacy)

Reports identify entries by **root id and relative path**, e.g. `file:documents:contracts/2026/offer%20letter.pdf`. They therefore reveal **file names and folder structure below each root**, plus hashes, sizes and modification times. `describe` declares this as `personal_data: ["file-names", "relative-file-paths"]`.

Reports never contain absolute paths, root paths, path hashes, user names or host names. **Review reports before sharing them outside this computer.**

**Reference encoding:**
- each path segment's raw bytes are percent-encoded, except `A–Z a–z 0–9 - . _ ~`;
- references are pure ASCII and can be decoded back exactly;
- `:` and `%` in names can't be confused with the format;
- names that differ only in Unicode normalisation stay distinct.

## Platforms and safety

Ilmarinen establishes each entry's type and identity on a handle that **cannot read it**. It then reads only regular files, **through that same object** without looking the path up again, and re-checks identity before and after hashing. This means a file swapped for a link, FIFO or device between listing and reading is reported (`changed-during-scan`), never followed or read.

| Platform | How |
|---|---|
| Windows | A query-only `CreateFileW` handle (`FILE_FLAG_OPEN_REPARSE_POINT`); file type, file ID and final-path checks; then `ReOpenFile` for reading |
| Linux | Directory descriptors with `O_NOFOLLOW`; candidates opened with `O_PATH` (no I/O open); reading through `/proc/self/fd/<n>` |
| Other systems | Not supported: the check fails closed with `unsafe-platform` rather than claim a safe check |

If a root is deleted and recreated at the same path, Ilmarinen reports `root-replaced`; if the configured path changes, `root-changed`. Both need a deliberate `baseline replace`. The same happens after legitimately restoring or moving a root, and on filesystems that change device numbers when remounted.

**Linux limitation:** some Linux filesystems (e.g. overlayfs, often used by containers) give a recreated directory the same inode number as the deleted one. Then `root-replaced` cannot be detected. File contents are still compared, so a recreated root with different files is still reported through the file findings; only a recreation with identical contents goes unnoticed.

## Tests

`python -m pytest`. All tests use temporary directories and synthetic files. Linux-only cases (FIFOs, device nodes, byte-level file names) are skipped on Windows. `tests/standards/` holds unmodified copies of the reporting standard's checker and vectors.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
