# Ilmarinen: instructions for Claude Code

Ilmarinen is the Borealis File Integrity agent. Its single responsibility is to detect unexpected content changes to user-selected files. It is a Specialist Agent in [Borealis Architecture v1](https://github.com/borealis-research-lab/.github/blob/main/architecture/borealis-architecture-v1.md).

- **Read-only, always.** Never add restore, delete, quarantine or any write to monitored files.
- **Fail closed.** Only read regular files through the type-first, same-object path in `fsaccess.py`. If a platform can't guarantee it, report `unsafe-platform`. Never fall back to path-based reads.
- **Never silently omit an entry.** Every entry is recorded, counted as excluded, or reported as an error.
- **Baselines** are created only from complete scans, written atomically, and never overwritten without the current digest.
- **Privacy:** reports contain root ids and encoded relative paths only. No absolute paths, user names, host names or path hashes.
- **Output** must conform to `borealis-agent-report/1`, with JSON the default. `tests/standards/` holds vendored, unmodified copies; never edit them.
- No AI, networking, remediation or features beyond this responsibility. Keep it standard library only.
- Use synthetic or temporary data only. Never read real reports or baselines into the conversation.

Run tests with `python -m pytest`.
