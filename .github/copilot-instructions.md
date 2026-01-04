# Copilot instructions for `justhtml-xss-bench`

## What this project is

This repository is an adversarial test suite / benchmark for HTML sanitizers.

- Input: untrusted, hostile HTML vectors (in `vectors/*.json`).
- Process: run sanitizer(s), render the sanitized output in a real browser (Playwright), and observe outcomes.
- Output: comparable results so users can understand differences between sanitizers.

The goal is **comparison and measurement**, not to make any single sanitizer “look good”.

## Core concepts

- **XSS**: any JavaScript execution (dialogs, hook signals, `javascript:` URL execution, or external script loads).
- **HTTP leak**: non-script network requests (images, stylesheets, fonts, etc.).
- **Lossy**: sanitizer output does not match the vector’s `expected_tags` contract.

## The `noop` sanitizer

This repo includes a `noop` sanitizer adapter that returns the input HTML unchanged.

- It is the baseline for harness correctness: it should trigger XSS/HTTP-leak signals for many vectors.
- It should also be **non-lossy** for as many vectors as possible.
  - If `noop` is lossy, that often indicates the vector’s `expected_tags` contract is unrealistically strict or that normalization/extraction in the bench is wrong.
  - “Passing” here means matching `expected_tags` (structure/attributes), not being safe.

The harness aims to be deterministic: network is blocked, but attempted requests are detected and recorded.

## Non-negotiable guardrails

1. **DO NOT: Change vectors to match a sanitizer output** unless the user explicitly asks for expectation updates.
   - The vectors are adversarial ground truth.
   - Updating `expected_tags` is a *policy decision* and must be deliberate.

2. **DO NOT: Mute failures by weakening detection**.
   - Only adjust harness classification if it was objectively misclassifying the signal.

3. **DO NOT: Expand allowlists casually**.
   - Tag/attribute/CSS property allowlists are part of the benchmark’s shared policy.
   - Any broadening may hide real risk (or change what gets measured). Do it only with clear justification.

4. **DO NOT: Add features/UX not requested**.
   - Keep changes scoped to the requested benchmarking behavior.

5. **DO NOT: “Fix” `noop` by making it safer**.
  - `noop` exists to be unsafe; it is used to validate that the harness detects real execution and leak attempts.

## Working with vectors (`vectors/*.json`)

- `expected_tags` describes the expected surviving element structure after sanitization.
  - Tags are ordered and matched against the sanitized HTML.
  - Attributes in `expected_tags` are part of the contract.
- `sanitizer_allow_tags` exists only for `payload_context: "http_leak"`.
  - Each vector declares the *exact* tags/attrs the sanitizer is allowed to preserve.
  - This avoids runtime inference and keeps comparisons honest.

If you must edit vectors, prefer:
- Minimal diffs.
- Clear rationale (e.g., harness semantics changed, schema changed, or a vector was incorrect).

## Working with the harness (`src/xssbench/harness.py`)

- The harness is the measurement instrument. Treat it as sensitive.
- Avoid rules that assume “navigation == XSS”.
  - In adversarial HTML, navigations can be caused by benign document loading, iframes, meta refresh, etc.
  - XSS should map to **script execution** or **external script loads**.
- `iframe srcdoc` should not be counted as execution by virtue of navigating to `about:srcdoc`.
  - Instead, treat `srcdoc` as a full subdocument: what runs/loads inside it should be detected normally.

Implementation tips:
- Prefer installing execution hooks in all frames (e.g., Playwright init scripts) so `srcdoc` and other frames are covered.
- Keep the network blocking behavior deterministic; record attempted requests and classify as `http_leak`.

## Working with sanitizer adapters (`src/xssbench/sanitizers.py`)

- Sanitizer adapters should be thin and predictable.
- Avoid sanitizer-specific hacks that distort comparisons.
- If a library cannot represent an allowlist safely (e.g., config panics/unsupported combinations), raise `SanitizerConfigUnsupported` or return a clear error.

## Tests and validation

Before finishing any change:

- Run `pytest -q`.
- If behavior changes are intended, add/adjust a focused test in `tests/`.
- For harness changes, add at least one regression test that reproduces the classification bug.

## Style and scope

- Keep edits minimal and targeted.
- Don’t reformat unrelated code.
- Prefer clarity over cleverness; this is a benchmark, not a framework.
