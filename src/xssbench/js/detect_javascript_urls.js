() => {
    const attrs = ['href', 'src', 'action', 'formaction', 'data'];
    const hits = [];

    // Approximate what browsers do for scheme detection:
    // - Trim leading/trailing ASCII whitespace and C0 control characters
    // - Do NOT remove internal whitespace (e.g. `jav   ascript:` is not `javascript:`)
    const normalizeForScheme = (value) => {
        if (value == null) return '';
        const s = String(value);
        // Strip leading/trailing chars <= 0x20.
        const stripped = s.replace(/^[\u0000-\u0020]+|[\u0000-\u0020]+$/g, '');
        return stripped.toLowerCase();
    };

    const resolvedValue = (el, attr) => {
        // Use DOM properties where available; these reflect browser URL parsing.
        try {
            if (attr === 'href' && typeof el.href === 'string') return el.href;
            if (attr === 'src' && typeof el.src === 'string') return el.src;
            if (attr === 'action' && typeof el.action === 'string') return el.action;
            if (attr === 'formaction' && typeof el.formAction === 'string') return el.formAction;
        } catch {
            // ignore
        }
        return '';
    };

    const elements = document.querySelectorAll('*');
    for (const el of elements) {
        for (const attr of attrs) {
            try {
                if (!el.hasAttribute(attr)) continue;
                const raw = el.getAttribute(attr);
                const schemeish = normalizeForScheme(raw);
                // Primary check: raw attribute after trimming.
                let isJavascript = schemeish.startsWith('javascript:');
                // Secondary check: resolved property (more accurate for browser behavior).
                if (!isJavascript) {
                    const resolved = normalizeForScheme(resolvedValue(el, attr));
                    isJavascript = resolved.startsWith('javascript:');
                }

                if (isJavascript) {
                    hits.push({ tag: (el.tagName || '').toLowerCase(), attr, value: raw });
                    if (hits.length >= 5) return hits;
                }
            } catch {
                // ignore
            }
        }
    }
    return hits;
}
