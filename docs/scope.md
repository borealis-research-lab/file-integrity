# Ilmarinen scope

- **Responsibility:** detect unexpected content changes to user-selected files.
- **Input:** files under configured roots (directories or single files), with exclusion patterns.
- **Method:** SHA-256 content hashes compared with a baseline that is created only from a complete scan and protected by an independently stored digest.
- **Output:** one `borealis-agent-report/1` JSON report per check. Text output is optional.
- **Execution:** local and read-only. No changes to monitored files, no network.
- **Platforms:** Windows and Linux. Other platforms fail closed.

## Non-goals

- Restoring, deleting, quarantining or otherwise changing files.
- Monitoring permissions, ACLs, ownership, timestamps or alternate data streams.
- Real-time monitoring or file-system watchers. Checks run when invoked.
- Malware scanning, content inspection, or judging whether a change is malicious.
- Correlation with other agents, networking, central services or AI.
