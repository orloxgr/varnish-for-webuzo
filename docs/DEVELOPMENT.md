## Development guide

Work on `main`; keep deployment configuration and validation evidence outside Git.
Use synthetic accounts and `.test` domains in examples. Do not commit private
keys, live tokens, customer hostnames or personal filesystem paths.

Before publishing, run `python3 tools/privacy_check.py` and
`gitleaks git . --config .gitleaks.toml --log-opts='--all --full-history' --ignore-gitleaks-allow --redact=100`.
The configured exceptions cover only known synthetic protocol vectors and public
signing-key fingerprints. Review names and release notes as well as scanner output.

Build: `python3 tools/build.py`. Packaging checks its actual input files for
private deployment references before writing the ZIP. To check an existing ZIP,
use `python3 tools/privacy_check.py --archive /path/to/package.zip`.

Run backend tests as root on a disposable Linux host: `python3 -m unittest discover -s tests -v`. The tests use isolated temporary state. Runtime integration checks must also cover real HTTP/HTTPS, static assets, cache exclusions, purge isolation, service failure, native rebuilds and plugin deactivation.

Verification results and runtime test instructions: [Testing](TESTING.md).
