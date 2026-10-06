# Release checks

Run the repository checker and pinned [Gitleaks v8.30.1](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1):

```sh
python3 scripts/check-publication.py --self-test
python3 scripts/check-publication.py --ref HEAD
gitleaks git --log-opts=HEAD --redact --no-banner
```

The repository checker covers selected credential/path patterns; Gitleaks and manual review provide broader coverage. Reports must redact matching values. Check the exact release refs and artifacts.

Exclude credentials, local configuration, logs, diagnostic archives and build caches. Preserve license notices and generated-source provenance.
