(() => {
	try {
		if (!window.__xssbench)
			window.__xssbench = { executed: false, details: "" };

		// Track timers so a payload can't schedule work that leaks into the next
		// vector run (the Python harness reuses a single Page).
		const __origSetTimeout = window.setTimeout.bind(window);
		const __origClearTimeout = window.clearTimeout.bind(window);
		const __origSetInterval = window.setInterval.bind(window);
		const __origClearInterval = window.clearInterval.bind(window);
		const __timeouts = new Set();
		const __intervals = new Set();

		window.setTimeout = (...args) => {
			const id = __origSetTimeout(...args);
			__timeouts.add(id);
			return id;
		};
		window.clearTimeout = (id) => {
			try {
				__timeouts.delete(id);
			} catch {
				/* ignore */
			}
			return __origClearTimeout(id);
		};
		window.setInterval = (...args) => {
			const id = __origSetInterval(...args);
			__intervals.add(id);
			return id;
		};
		window.clearInterval = (id) => {
			try {
				__intervals.delete(id);
			} catch {
				/* ignore */
			}
			return __origClearInterval(id);
		};

		window.__xssbench.cleanup = () => {
			try {
				for (const id of __timeouts) {
					try {
						__origClearTimeout(id);
					} catch {
						/* ignore */
					}
				}
				for (const id of __intervals) {
					try {
						__origClearInterval(id);
					} catch {
						/* ignore */
					}
				}
				__timeouts.clear();
				__intervals.clear();
			} catch {
				/* ignore */
			}
		};
		const mark = (kind, args) => {
			try {
				if (window.__xssbench.executed) return;
				window.__xssbench.executed = true;
				const msg = args?.length ? String(args[0]) : "";
				window.__xssbench.details = `${kind}:${msg}`;
			} catch {
				/* ignore */
			}
		};

		window.alert = (...args) => {
			mark("alert", args);
		};
		window.confirm = (...args) => {
			mark("confirm", args);
			return true;
		};
		window.prompt = (...args) => {
			mark("prompt", args);
			return "";
		};
	} catch {
		/* ignore */
	}
})();
