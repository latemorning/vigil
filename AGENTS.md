# Repository Guidelines

## Project Structure & Module Organization

This is a Python 3.12 CLI package using a `src/` layout. Application code lives in `src/vigil/`: `cli.py` defines the command line interface, `scanner.py` walks files and applies detectors, `report.py` writes and prints results, `log_format.py` parses logger names, and `detectors/` contains detector implementations. Tests live in `tests/`, with reusable sample inputs under `tests/fixtures/`. Local scan inputs under `source/` and generated reports such as `vigil-report.json` are ignored and should not be committed.

## Build, Test, and Development Commands

Install the package and test dependencies:

```bash
python -m pip install -e ".[dev]"
```

Run the full test suite:

```bash
python -m pytest -v
```

Run a focused test file:

```bash
python -m pytest tests/test_detectors_korean.py -v
```

Smoke-test the CLI with fixture data:

```bash
python -m vigil scan tests/fixtures/logs/clean.log --detector email,rrn --quiet --output /tmp/vigil-report.json
```

## Coding Style & Naming Conventions

Use 4-space indentation, type hints, `pathlib.Path` for paths, and `dataclass` models where they fit existing patterns. Prefer small, explicit functions and absolute imports from `vigil`. Detector classes should expose clear detector names such as `email`, `rrn`, or `name_korean`, and new detector modules should be registered through `src/vigil/detectors/__init__.py`. Keep comments sparse and useful; most behavior should be clear from names and tests.

## Testing Guidelines

The project uses `pytest` with `tests` as the configured test path and `src` on `pythonpath`. Name test files `test_<module>.py` and test functions `test_<behavior>()`. Add fixture logs under `tests/fixtures/logs/` and stopword samples under `tests/fixtures/name_stopwords/` when needed. For detector changes, cover true positives, false positives, confidence levels, and validation checks. For CLI changes, assert exit codes: `0` for clean scans, `1` for detected PII, and `2` for execution errors.

## Commit & Pull Request Guidelines

Recent history uses concise Conventional Commit-style prefixes: `feat:`, `fix:`, `docs:`, and `chore:`. Keep subjects short and specific, for example `fix: reduce false positives in email detector`. Pull requests should describe the behavior change, list tests run, link related issues when available, and include representative CLI output or JSON report snippets when output formats change.

## Security & Configuration Tips

Do not commit real logs, PII, generated scan reports, virtual environments, coverage output, or files from ignored `source/`. Use synthetic fixtures for tests and write temporary reports to `/tmp` during local validation.
