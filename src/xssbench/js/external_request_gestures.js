() => {
	try {
		// Click ping-enabled links/areas to trigger the browser's ping mechanism.
		const pingEls = Array.from(
			document.querySelectorAll("a[ping], area[ping]"),
		);
		for (const el of pingEls) {
			try {
				el.click();
			} catch {
				/* ignore */
			}
		}

		// Submit forms that may have external `action`/`formaction`.
		const forms = Array.from(document.querySelectorAll("form"));
		for (const f of forms) {
			try {
				if (typeof f.requestSubmit === "function") {
					f.requestSubmit();
				} else {
					f.submit();
				}
			} catch {
				/* ignore */
			}
		}

		// Click buttons with formaction to trigger navigation without requiring a selector.
		const formactionBtns = Array.from(
			document.querySelectorAll("button[formaction], input[formaction]"),
		);
		for (const b of formactionBtns) {
			try {
				b.click();
			} catch {
				/* ignore */
			}
		}
	} catch {
		/* ignore */
	}
};
