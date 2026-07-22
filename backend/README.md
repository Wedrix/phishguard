# PhishGuard trusted application

The package contains the trusted web application, job worker, persistence,
decision engine, and evaluation commands. Target-controlled network retrieval
lives in the separately deployed fetcher.

```sh
uv sync --extra test
uv run alembic upgrade head
uv run python -m phishguard.cli web
uv run pytest
```

Research evaluation records ECE and Brier scores but does not select a
candidate until the governed thresholds are supplied:

```sh
uv run python -m phishguard.cli evaluate input.csv output/ \
  --max-ece "$APPROVED_MAX_ECE" --max-brier "$APPROVED_MAX_BRIER"
```

Local development requires `DATABASE_URL`, `PHISHGUARD_HMAC_KEY`, and either
`PHISHGUARD_ENCRYPTION_KEY` or `KMS_KEY_NAME`. See `phishguard.config.Settings`
for all deployment settings.

The provider, policy, model, audit, and research endpoints persist governed
registry state. Google Web Risk enablement is effective immediately. Model and
decision-policy activation are deliberately deployment-scoped in this release:
the approved `MODEL_*` artifact and code-reviewed policy constants are loaded
at process start, so a registry activation requires a trusted rollout rather
than silently changing live decisions in one pod.
