# Repository Guidelines

This repo mirrors Claude Code documentation for fast local access and version tracking. Keep changes minimal, scripted, and reversible.

## Project Structure & Module Organization
- `docs/` — mirrored Markdown files plus `docs_manifest.json` (index of available topics and source URLs). Filenames are kebab-case; nested paths are flattened using double underscores, e.g., `sdk__sdk-python.md`.
- `scripts/` — updater utilities (`fetch_claude_docs.py`, `requirements.txt`).
- Root scripts — `install.sh`, `uninstall.sh` for local `/docs` command integration.
- CI — `.github/workflows/update-docs.yml` runs every 3 hours to refresh `docs/`.
- Reference — `README.md`, `CLAUDE.md`, `LICENSE`.

## Build, Test, and Development Commands
- Setup (Python 3.11):
  - `python -m pip install -r scripts/requirements.txt`
- Update docs locally:
  - `python scripts/fetch_claude_docs.py`
  - Inspect changes: `git diff --name-status docs/`
- Install CLI helper (optional):
  - `bash install.sh`  |  Uninstall: `~/.claude-code-docs/uninstall.sh` or `./uninstall.sh`

## Coding Style & Naming Conventions
- Python: PEP 8, 4‑space indentation, type hints where practical, standard `logging` (see `fetch_claude_docs.py`). Prefer `pathlib` and small, pure functions. Keep dependencies minimal (`requests` only).
- Shell: POSIX/bash, defensive checks, idempotent operations. Do not hardcode user paths beyond `~/.claude*` conventions in existing scripts.
- Docs: Markdown only in `docs/`. Preserve existing filename pattern `section__subsection.md`; avoid renames that break links and the manifest.

## Testing Guidelines
- No unit test suite. Validate by running the updater and reviewing logs for “Successful/Failed” and by spot‑checking changed files.
- Sanity checks: open `docs_manifest.json`, verify `base_url`, `last_updated`, and listed files match the repo.

## Commit & Pull Request Guidelines
- Messages: imperative mood, concise subject. Use scopes like `docs:`, `scripts:`, `ci:`, `install:`.
- For bulk doc refreshes, match CI style: `Update Claude Code docs - YYYY-MM-DD | Updated: … | Added: … | Removed: …`.
- PRs must include: purpose, affected files, screenshots/log excerpts (for script changes), and any related issue links. Avoid committing binaries or unrelated changes.

## Security & Agent-Specific Notes
- Never commit secrets; CI uses the ephemeral `GITHUB_TOKEN` only. Respect rate limits and headers in `fetch_claude_docs.py`.
- Agents/tools should read from `docs/` and prefer `docs_manifest.json` for topic discovery. Do not alter `docs/` structure without updating the manifest logic and CI.

