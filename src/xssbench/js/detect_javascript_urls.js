() => {
	const attrs = [
		"href",
		"src",
		"action",
		"formaction",
		"data",
		"xlink:href",
		"content",
		"to",
		"from",
		"values",
	];
	const hits = [];

	// Approximate what browsers do for scheme detection:
	// - Trim leading/trailing ASCII whitespace and C0 control characters
	// - Do NOT remove internal whitespace (e.g. `jav   ascript:` is not `javascript:`)
	const normalizeForScheme = (value) => {
		if (value == null) return "";
		const s = String(value);
		// Strip leading/trailing chars <= 0x20.
		// biome-ignore lint/suspicious/noControlCharactersInRegex: intended to trim ASCII whitespace + C0 control chars.
		const stripped = s.replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, "");
		return stripped.toLowerCase();
	};

	const resolvedValue = (el, attr) => {
		// Use DOM properties where available; these reflect browser URL parsing.
		try {
			if (attr === "href" && typeof el.href === "string") return el.href;
			if (attr === "src" && typeof el.src === "string") return el.src;
			if (attr === "action" && typeof el.action === "string") return el.action;
			if (attr === "formaction" && typeof el.formAction === "string")
				return el.formAction;
		} catch {
			// ignore
		}
		return "";
	};

	const isDangerousDataUri = (value) => {
		if (!value.startsWith("data:")) return false;
		// Check for dangerous MIME types
		if (value.startsWith("data:text/html")) return true;
		if (value.startsWith("data:image/svg+xml")) return true;
		if (value.startsWith("data:application/xhtml+xml")) return true;
		if (value.startsWith("data:text/xml")) return true;
		if (value.startsWith("data:application/xml")) return true;
		return false;
	};

	const elements = document.querySelectorAll("*");
	for (const el of elements) {
		// Check for inline style with javascript: or data:
		try {
			if (el.hasAttribute("style")) {
				const style = el.getAttribute("style");
				const normalized = normalizeForScheme(style);
				// Simple check for url(javascript:...) or url(data:...)
				// This is a heuristic, but effective for common vectors.
				if (
					/url\s*\(\s*['"]?\s*javascript:/i.test(normalized) ||
					/url\s*\(\s*['"]?\s*data:/i.test(normalized)
				) {
					hits.push({
						tag: (el.tagName || "").toLowerCase(),
						attr: "style",
						value: style,
					});
				}
			}
		} catch {
			// ignore
		}

		// Check for on* event handlers
		try {
			for (const attr of el.getAttributeNames()) {
				if (attr.toLowerCase().startsWith("on")) {
					hits.push({
						tag: (el.tagName || "").toLowerCase(),
						attr: attr,
						value: el.getAttribute(attr),
					});
				}
			}
		} catch {
			// ignore
		}

		for (const attr of attrs) {
			try {
				if (!el.hasAttribute(attr)) continue;
				const raw = el.getAttribute(attr);
				const schemeish = normalizeForScheme(raw);
				// Primary check: raw attribute after trimming.
				let isJavascript = schemeish.startsWith("javascript:");
				let isData = isDangerousDataUri(schemeish);

				if (attr === "content") {
					// Handle meta refresh: content="0;url=javascript:..."
					if (/url\s*=\s*javascript:/i.test(schemeish)) {
						isJavascript = true;
					}
					// Check for data URI in meta refresh
					const match = schemeish.match(/url\s*=\s*(data:[^;"'\s]+)/i);
					if (match && isDangerousDataUri(match[1])) {
						isData = true;
					}
				}

				if (attr === "values") {
					// Handle SVG animation values list: values="...; javascript:..."
					const parts = schemeish.split(";");
					for (const part of parts) {
						const p = part.trim();
						if (p.startsWith("javascript:")) isJavascript = true;
						if (isDangerousDataUri(p)) isData = true;
					}
				}

				// Secondary check: resolved property (more accurate for browser behavior).
				if (!isJavascript && !isData) {
					const resolved = normalizeForScheme(resolvedValue(el, attr));
					isJavascript = resolved.startsWith("javascript:");
					isData = isDangerousDataUri(resolved);
				}

				if (isJavascript || isData) {
					hits.push({
						tag: (el.tagName || "").toLowerCase(),
						attr,
						value: raw,
					});
					if (hits.length >= 5) return hits;
				}
			} catch {
				// ignore
			}
		}
	}
	return hits;
};
