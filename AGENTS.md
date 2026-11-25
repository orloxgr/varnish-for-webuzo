# Repository workflow and privacy

- Work on `main`. Do not create feature branches or worktrees for routine work.
- Treat the latest `origin/main` as authoritative. Never restore an old version,
  native experiment or VCL draft over it because a historical branch differs.
- Before removing refs/worktrees, privately preserve all refs and complete local
  files, including dirty, untracked and ignored files. Verify the backup outside
  every repository. Do not publish recovery refs, checkpoints or private evidence.
- Never commit real customer domains, deployment names, server hostnames/IPs,
  account names, personal filesystem paths, credentials or live request tokens.
  Runnable tests receive real connection details from non-tracked configuration
  or environment variables. Unit fixtures use synthetic accounts, `.test` domains
  and documentation address ranges. Keep documentation and receipts anonymous.
- Preserve required author/copyright attribution, licensed provider data, public
  reference URLs, public signing-key fingerprints and synthetic protocol vectors.
- Run `python3 tools/privacy_check.py` and the configured Gitleaks check before
  publishing. Review docs, filenames, release notes and package contents as well;
  an automated check cannot recognize every customer brand or contextual leak.
- Do not rewrite published history, use force pushes or replace an existing
  release asset/checksum without a specifically coordinated plan.
