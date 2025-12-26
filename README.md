# justhtml-xss-bench

A tiny, standalone headless-browser harness for detecting whether a sanitized HTML payload can execute JavaScript when embedded into the initial HTML page ("server-side" style).

## Quickstart

```bash
cd /home/emilstenstrom/Projects/justhtml-xss-bench
python -m pip install -e ".[test]"
python -m playwright install chromium
pytest
```

## Linting / formatting (pre-commit)

This repo is set up with `pre-commit` hooks for:

- Python: Ruff (minimal lint + formatting)
- JavaScript + JSON: Biome

Setup:

```bash
python -m pip install -e ".[dev,test]"
pre-commit install
pre-commit run --all-files
```

Note: the Biome hook requires a working Node.js installation.

## Running the benchmark

This repo also ships a small CLI that runs **many vectors** across **many sanitizers** and reports which combinations executed JavaScript in a real browser.

```bash
# Run all vector files in ./vectors against the default (rich) sanitizer set
xssbench

# By default it runs across all browser engines (Chromium, Firefox, WebKit)
# Override with e.g.:
xssbench --browser chromium

# List sanitizers available in this environment
xssbench --list-sanitizers

# Run a subset
xssbench --vectors vectors/bleach.json --sanitizers noop

# Write a machine-readable run artifact (repo-local; git-ignored via .xssbench/)
xssbench --json-out .xssbench

# By default, `xssbench` runs all `vectors/*.json`.
# If you have a large pack, run a smaller subset by passing `--vectors`.

# Timeout is adaptive by default; override if you have slower / async vectors:
xssbench --timeout-ms 800
```

### Optional: benchmark third-party sanitizers

If you install the optional extras, the CLI will automatically include them (when importable):

```bash
python -m pip install -e ".[test,sanitizers]"
```

### Installing browser engines

The harness uses Playwright browser engines. Install what you want to run:

```bash
python -m playwright install chromium
python -m playwright install firefox
python -m playwright install webkit
```

## Vector schema

Each vector file is a JSON object wrapper (v1) with header metadata:

	- `schema`: must be `"xssbench.vectorfile.v1"`
	- `meta`: file-level metadata (including a `license.file` pointing at a `xssbench-*-LICENSE.txt` file)
	- `vectors`: list of vector objects

Each vector object has (at minimum):

- `id`: stable identifier
- `description`: where the vector came from
- `payload_html`: the payload string
- `payload_context`: where `payload_html` should be injected (string enum, or a list of enums)
- `expected_tags`: list of tag names that are expected to still be present after sanitization.
	If any of these tags are missing from the sanitized output, the benchmark marks the case as `lossy`.
	If the list is empty (`[]`), the benchmark expects the sanitized output to contain no tags at all.

	`expected_tags` is required for HTML-fragment contexts (`html`, `html_head`, `html_outer`, `onerror_attr`).
	It is forbidden for `href` and all `js*` contexts.

`payload_context` is an enum:

- `html`: embed into the initial HTML body (default)
- `html_head`: inject into the document `<head>` (useful for `<meta>`, `<base>`, `<link>`, `<title>`)
- `html_outer`: inject as a direct child of `<html>` after the instrumented `<head>` (useful for `<body>` / `<frameset>` examples)
- `href`: inject into an `<a href="…">` and click it (helps for `javascript:` URIs)
- `js`: inject directly into a `<script>` tag
- `js_arg`: inject into a JavaScript function-argument position (`setTimeout(fn, PAYLOAD)`)
- `js_string`: inject into a JavaScript single-quoted string inside a `<script>` tag
- `js_string_double`: inject into a JavaScript double-quoted string inside a `<script>` tag
- `onerror_attr`: inject into an `onerror="..."` attribute on an `<img>` (useful for HTML-entity encoded JS)

## What it does

- Treats JavaScript execution as a failure. Easiest signal is a dialog (`alert/confirm/prompt`).
- Embeds sanitized HTML into a real browser page before load ("server-side" style).
- Treats any attempted external script fetch (e.g. `<script src="https://…">`) as XSS executed.
- Fails a test if the marker was hit.
