(() => {
	try {
		if (!window.__xssbench)
			window.__xssbench = { executed: false, details: "" };
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
