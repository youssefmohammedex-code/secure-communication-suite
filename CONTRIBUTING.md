# Team workflow

The spec asks for **version control, code reviews and regular meetings**. This is how we
do them, and the Git history and PRs are the evidence we show in the report.

## Branches & PRs
* `main` always passes `pytest`. Nobody pushes to `main` directly.
* One branch per task: `feature/public-key`, `feature/auth-lockout`, `fix/replay-check`, `docs/literature-aes`.
* Open a pull request and ask **one other member** to review it. The reviewer checks:
  - tests added/updated and passing
  - no secrets logged, no hard-coded keys, parameters come from `suite/config.py`
  - library-specific errors converted to `suite.errors` types
* Merge after approval.

## Definition of done (per function)
1. Implemented (replace the `raise NotImplementedError`).
2. Its tests in `tests/` pass (they were *skipped* before, so run `pytest -rs` to see what's left).
3. Docstring explains *why*, ready to paste into the report.

## Commands
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
pytest -rs                          # run tests, list unimplemented parts
python -m benchmarks.bench_crypto   # performance numbers for the report
python -m suite.server              # Phase 4
python -m suite.client              # Phase 4
```

## Meetings
Twice a week, 30 min. Copy `docs/meetings/TEMPLATE.md` to `docs/meetings/YYYY-MM-DD.md`.
