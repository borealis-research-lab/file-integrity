# Protecting the baseline: the expected digest

Ilmarinen compares your files with a **baseline**. So a check is only as trustworthy as that baseline. This guide explains how to make sure you're comparing against the baseline you actually created.

> **In one sentence:** store the baseline's digest **somewhere other than the monitored computer**, pass it to every check with `--expected-digest`, and periodically compare it with your stored copy yourself.

## Two digests, two different protections

| | Embedded digest | Expected digest (`--expected-digest`) |
|---|---|---|
| **Where it is** | Inside `baseline.json` (the `digest` field) | Wherever you keep it, ideally off this computer |
| **Detects** | Accidental corruption: a damaged or partly edited baseline | **Deliberate tampering**, including a baseline rewritten with a freshly recomputed digest |
| **Defeated by** | Anyone who can edit the baseline **and recompute** the digest (it's a public algorithm) | Anyone who can also change the stored copy you compare against |

The embedded digest protects against accidents, not attackers. Without an expected digest, a check can't tell your original baseline from one an attacker rewrote to hide their changes. The worked example below shows exactly that.

## 1. Record the digest when you create the baseline

`ilmarinen baseline create` prints the digest:

```
Baseline created with 2 entries.
Baseline digest: 38c6a75ff5b729c0b4d32fc9ca35fad2ed7ea0de7d4f3f490ea9312740a0c167
```

Record it **right away**, together with:
- the date;
- the machine;
- which roots the baseline covers.

The same value is in the baseline file's `digest` field. Only trust that copy at the moment of creation, though: later it could have been rewritten.

## 2. Keep it somewhere the monitored computer can't change

**Good places:**
- a password manager **on another device**;
- a printed or handwritten note;
- a document or repository on a **separate, trusted system**;
- read-only removable media kept apart from the machine.

**Not independent:**
- any file on the monitored computer, including `node.json`;
- an email you can only open from that computer;
- a cloud folder that the monitored computer syncs and can edit.

The digest isn't secret, since it reveals nothing about your files. What matters is that **an attacker on the monitored computer can't change your copy**.

## 3. Use it in every check

On the command line:

```
ilmarinen check --config ilmarinen.json --expected-digest 38c6a75ff5b729c0b4d32fc9ca35fad2ed7ea0de7d4f3f490ea9312740a0c167
```

Upper or lower case both work. In Borealis Node, put it in Ilmarinen's arguments in `node.json`:

```json
{"config_name": "ilmarinen", "expected_name": "ilmarinen",
 "executable": "C:/borealis/file-integrity/.venv/Scripts/ilmarinen.exe",
 "args": ["check", "--config", "C:/borealis/ilmarinen.json",
          "--expected-digest", "38c6a75ff5b729c0b4d32fc9ca35fad2ed7ea0de7d4f3f490ea9312740a0c167"],
 "timeout_s": 600}
```

**Reading the result:**

| Situation | Status | Report shows |
|---|---|---|
| Digest matches | as normal | `extensions.digest_verified_independently: true`; text view: `Independently verified: yes` |
| Digest differs | `error`, no file comparison | A high-severity `baseline-integrity-failure` finding: "the baseline's digest differs from the independently supplied digest". In Borealis Node, the Ilmarinen entry is `failed` and the Node outcome isn't `ok` |
| No digest supplied | as normal | `digest_verified_independently: false`; text view: `Independently verified: NO (use --expected-digest)` |

A mismatch shows that the baseline isn't the one you recorded. It **doesn't** tell you why: it could be tampering, a forgotten replacement, or a mistake in your stored copy. Investigate before trusting anything.

## 4. Understand the limits of keeping the digest in `node.json`

Putting the digest in `node.json` is much better than nothing. It protects against:
- a process or user that can write to the baseline's folder but **can't** edit `node.json` (which should be administrator-only);
- an accidentally replaced or restored baseline.

It **doesn't** protect against an attacker with **administrator rights on the monitored computer**. Such an attacker can change the baseline, recompute its digest, *and* update `node.json` to match. Every check then looks clean.

More generally, **a fully compromised computer can't vouch for itself**: it could also change Ilmarinen, the Node, or their output. That's why the periodic check below compares against a copy the computer can't reach.

## 5. Periodic verification (e.g. weekly, and after any security incident)

1. **Get the digest from your stored copy**, not from the monitored computer.
2. **Run a check by hand**, typing that digest in rather than relying on `node.json`:
   ```
   ilmarinen check --config ilmarinen.json --text --expected-digest <digest from your stored copy>
   ```
   Confirm `Independently verified: yes` and review any findings.
3. **Compare the digest in `node.json`** with your stored copy as well. A change you didn't make is a warning sign in itself.
4. **For a stronger check, verify on a separate trusted computer.**
   - Copy `baseline.json` there (e.g. on removable media).
   - With Ilmarinen installed there, run this in the folder containing the copy:
     ```
     python -c "from pathlib import Path; from ilmarinen.baseline import load; print(load(Path('baseline.json')).digest)"
     ```
     It checks the file's structure and embedded digest and prints the digest. **The printed value must equal your stored copy.** An altered baseline either fails to load ("the baseline's digest does not match its content") or prints a different digest.
   - This checks the baseline itself without relying on any software on the monitored computer.
   - It doesn't re-check the monitored files. That still has to happen on the monitored computer, so if you suspect that computer is compromised, treat its file check results with caution too.
5. **If anything doesn't match,** don't replace the baseline to make the warning go away. Treat it as a possible security incident: preserve the evidence, including the baseline and its `*.replaced.json` archives, and investigate.

## 6. When you replace a baseline

`ilmarinen baseline replace --config ilmarinen.json --confirm-replace <current digest>` archives the old baseline and prints a **new** digest. Update **every** copy at once:
- your stored copy;
- `node.json`.

Until you do, checks will fail with `baseline-integrity-failure`, because the old digest no longer matches. That's the intended behaviour. Record why and when you replaced it.

## Worked example (synthetic test data)

This comes from the Borealis five-stage integration test on synthetic files. A baseline was created, and its digest recorded. Then:
- `config/app.conf` was modified, so a correct check should report it;
- a copy of the baseline was then edited to give `app.conf` its new hash, **and the embedded digest was recomputed**, the way a capable attacker would.

| Check | Result |
|---|---|
| Tampered baseline, **no** `--expected-digest` | Status `ok`, 2 findings. **The `app.conf` change is silently missing** |
| Tampered baseline, **with** the recorded digest | Status `error`: "the baseline's digest differs from the independently supplied digest". No file comparison is made |
| Original baseline, with the recorded digest | Status `ok`, 3 findings, **including** `file-changed` on `config/app.conf` |

The same behaviour is covered by Ilmarinen's automated test `test_recomputed_digest_is_caught_by_expected_digest`.

## Checklist

- [ ] The digest was recorded at creation, **off** the monitored computer.
- [ ] Every scheduled or Node-run check passes `--expected-digest`.
- [ ] `node.json` can only be edited by administrators.
- [ ] Periodic manual verification from the stored copy.
- [ ] After every `baseline replace`, all copies of the digest are updated and the reason recorded.
- [ ] A digest mismatch is treated as a possible incident, not an inconvenience.
