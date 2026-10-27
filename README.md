# Encrypted archive

The content and research workspace are encrypted **before commit**. No content password is stored here. The account, repository name, file sizes, timestamps, encryption format, and commit history are public metadata if this repository is public.

- `docs/`: generic unlock page and encrypted website payload.
- `research/continuation.enc.json`: separately encrypted research, structured data, source code, historical material, and AI continuation instructions.
- `tools/archive.mjs`: generic, dependency-free Node.js 20+ build, restore, and encryption tests.

The website decrypts locally with Web Crypto: AES-256-GCM, a fresh 32-byte salt and 12-byte nonce per bundle, PBKDF2-HMAC-SHA256 (600,000 iterations), and authenticated format context. Encryption cannot compensate for a guessable password. Anyone can download ciphertext and try passwords offline; anyone with the password can copy decrypted content. The unlock script and GitHub account must remain trustworthy. This is not per-person access control.

## Authorized continuation

Obtain the password privately from the owner. Never put it in an issue, commit, command-line argument, source file, or workflow secret. Use a local terminal with shell tracing off:

```bash
read -r -s -p 'Archive password: ' ARCHIVE_SECRET; printf '\n'
printf '%s' "$ARCHIVE_SECRET" | node tools/archive.mjs restore private
unset ARCHIVE_SECRET
```

Read `private/AGENTS.md` and `private/research/CONTINUE_HERE.md` before editing. The restore command refuses to overwrite an existing directory. `private/dist/archive.json` is the current structured dataset. Historical files are not canonical.

After editing, run validation from `private/`, then supply the password through stdin to `node tools/archive.mjs build` and `node tools/archive.mjs test`. Commit only the allowlisted generic files and the two ciphertext envelopes. Never use `git add .` on a decrypted workspace. Keep commit messages generic. Changing the password cannot revoke access to ciphertext preserved in old Git history.

Publish the `/docs` folder through GitHub Pages. The research envelope outside `/docs` remains obtainable from the repository; its contents are encrypted. An identical encrypted research envelope is mirrored at docs/research/continuation.enc.json for the browser download. No analytics, remote fonts, or automatic source-image requests are used. Source links are opened only when a reader chooses them.
