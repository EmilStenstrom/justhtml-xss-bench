# justhtml-xss-bench

A tiny, standalone headless-browser harness for detecting whether a sanitized HTML payload can execute JavaScript when embedded into the initial HTML page ("server-side" style).

## Latest run (2025-12-29)

Command (Chromium-only for reasonable runtime):

```bash
xssbench --browser chromium --workers 28 --json-out .xssbench/results-latest.json --no-progress
```

Totals: 35,040 cases (5 sanitizers × 7,008 vectors) on Chromium.

Engine: Playwright 1.57.0 (Chromium 143.0.7499.4).

| sanitizer         | version | pass | xss  | external | skip | error | lossy |
|-------------------|:--------|-----:|-----:|---------:|-----:|------:|------:|
| `bleach`          | 6.3.0   | 6913 |    0 |        3 |   92 |     0 |    79 |
| `nh3`             | 0.3.2   | 6913 |    0 |        3 |   92 |     0 |    18 |
| `lxml_html_clean` | 0.4.3   | 6913 |    0 |        3 |   92 |     0 |  6120 |
| `justhtml`        | 0.18.0  | 6916 |    0 |        0 |   92 |     0 |     0 |
| `noop`            | —       |  927 | 6065 |        8 |    8 |     0 |  6585 |

Why the results look like this:

- **`noop` is the baseline**: it returns the payload unchanged, so it shows how many vectors *actually execute* in the browser when nothing is sanitized. The reason that not all vectors execute is because they are designed to execute only after unsuccessful cleaning (ie. `<script<script>>`)

- **`xss=0` for the real sanitizers** (in this run) means the harness didn’t observe any execution signals (dialogs, dangerous URLs, unexpected navigations, external script fetch attempts). All cleaners in this test are working well.

- **`external` counts are not “passed”**: the harness blocks network for determinism and records attempted external requests. We track these separately because they’re useful risk signals even when they’re not immediate JS execution. Note that only justhtml has built-in link rewriting, so this is not something that's expected from the others.

- **`skip` happens for out-of-scope contexts**: the suite includes some non-HTML contexts (e.g. JS-string/JS-code injection) that HTML sanitizers intentionally don’t support. These have to take attribute escaping into account, and no sanitizers have support for that currently.

- **`lossy` is a fidelity metric**, not a security metric: it means the sanitizer output didn’t match the vector file’s `expected_tags`.

	One way to think about it: if we deleted all input HTML we’d be “safe”, but we wouldn’t have a useful sanitizer.

	The most common reasons for `lossy` in this run:

	- **`nh3`**: Most lossy cases are *attribute fidelity* mismatches. nh3 often keeps safe URL attributes like `href`/`src` (sometimes normalized to empty strings) in cases where the vector expectations only require the tag (`a`, `img`) without attributes.
	- **`bleach`**: Similar attribute-fidelity mismatches (safe `href`/`src` surviving when the expectation is a bare `a`/`img`), plus some vectors rely on HTML tag-name quirks like `<image>` being treated as `<img>`.
	- **`lxml_html_clean`**: `lossy` is high mostly because it aggressively *rewrites* input into safe placeholder markup (often `div`/`span`/`p`) rather than dropping everything. Many vectors expect “no tags”, but lxml’s cleaner preserves safe text inside wrapper elements and may also insert implied structure like `tbody`.
	- **`noop`**: `lossy` is high because it intentionally doesn’t change the input, while many vectors expect the output to contain no tags at all.

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

	`expected_tags` is an ordered sequence describing the exact sanitized output.
	The sanitized output must contain exactly those tags, in that order (same count, no extras).
	Each entry is matched 1:1 against the corresponding surviving element.

	Each entry may either be a bare tag name (tag must exist with no attributes)
	or a tag with an attribute list:
	- `"p"` (tag must exist; at least one surviving `<p>` must have no attributes)
	- `"p[class]"` (tag must exist and have a `class` attribute)
	- `"a[href, style]"` (tag must exist and have both `href` and `style` attributes)

	Each entry is checked as: there must be at least one surviving element of that tag
	that has all listed attributes.

	Allowed attribute names must come from the shared sanitizer allowlist policy.

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
