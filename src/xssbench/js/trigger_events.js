() => {
  const root = document.getElementById('root');
  const scope = root || document;

    // Our synthetic event triggering should not cause the browser to actually navigate
    // away from the synthetic document (e.g. clicking a normal <a href="https://...">).
    // Preventing default keeps inline/DOM event handlers running, but avoids treating
    // benign navigations as XSS.
    try {
        document.addEventListener('click', (e) => { try { e.preventDefault(); } catch {} }, true);
        document.addEventListener('submit', (e) => { try { e.preventDefault(); } catch {} }, true);
    } catch { /* ignore */ }

  const elements = Array.from(scope.querySelectorAll('*'));
        const mouseEvents = [
            'mouseover',
            'mouseenter',
            'mouseleave',
            'mousedown',
            'mousemove',
            'mouseout',
            'mouseup',
            'click',
            'dblclick',
        ];
        const focusEvents = ['focus', 'focusin', 'focusout', 'blur'];
        const directEvents = ['load', 'error'];
        const keyboardEvents = ['keydown', 'keypress', 'keyup'];
        const clipboardEvents = ['copy', 'cut', 'paste'];
        const otherEvents = [
            'auxclick',
            'contextmenu',
            'toggle',
            'scroll',
            'wheel',
            'input',
            'change',
            'beforeinput',
            'select',
            'submit',
            'reset',
            'invalid',
            'search',
            'loadstart',
            'loadend',
            'readystatechange',
            // Low-frequency legacy/lifecycle handler names seen in corpora.
            'begin',
            'start',
            'end',
            'repeat',
            'finish',
            'bounce',
            'show',
            'help',
            // Legacy clipboard events sometimes used in payload corpora.
            'beforecopy',
            'beforecut',
            'beforepaste',
        ];
        const dragEvents = [
            'drag',
            'dragstart',
            'dragend',
            'dragenter',
            'dragleave',
            'dragover',
            'drop',
        ];
        const animationEvents = ['animationstart', 'animationiteration', 'animationend', 'animationcancel'];
        const transitionEvents = ['transitionrun', 'transitionstart', 'transitionend', 'transitioncancel'];
        const pointerEvents = [
            'pointerdown',
            'pointerup',
            'pointermove',
            'pointerover',
            'pointerenter',
            'pointerout',
            'pointerleave',
        ];
        const touchEvents = ['touchstart', 'touchend', 'touchmove', 'touchcancel'];
        const mediaEvents = [
            'play',
            'playing',
            'pause',
            'ended',
            'seeking',
            'seeked',
            'timeupdate',
            'volumechange',
            'loadedmetadata',
            'loadeddata',
            'canplay',
            'canplaythrough',
            'waiting',
        ];

        const windowEvents = [
            'hashchange',
            'message',
            'popstate',
            'pageshow',
            'resize',
            'orientationchange',
            'beforeprint',
            'afterprint',
            'unhandledrejection',
        ];

  for (const el of elements) {
        for (const type of mouseEvents) {
            try {
                el.dispatchEvent(new MouseEvent(type, { bubbles: true, cancelable: true, view: window }));
            } catch {
                try { el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true })); } catch { /* ignore */ }
            }
        }

        for (const type of focusEvents) {
            try {
                el.dispatchEvent(new FocusEvent(type, { bubbles: true, cancelable: true }));
            } catch {
                try { el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true })); } catch { /* ignore */ }
            }
        }

        for (const type of keyboardEvents) {
            try {
                el.dispatchEvent(new KeyboardEvent(type, { bubbles: true, cancelable: true, key: 'A', code: 'KeyA' }));
            } catch {
                try { el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true })); } catch { /* ignore */ }
            }
        }

        for (const type of clipboardEvents) {
            try {
                // ClipboardEvent may be restricted in some engines; fall back to a plain Event.
                el.dispatchEvent(new ClipboardEvent(type, { bubbles: true, cancelable: true }));
            } catch {
                try { el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true })); } catch { /* ignore */ }
            }
        }

        for (const type of otherEvents) {
            try {
                el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
            } catch { /* ignore */ }
        }

        for (const type of dragEvents) {
            try {
                // DragEvent / DataTransfer constructors vary by engine; fall back to plain Event.
                let dt = undefined;
                try { dt = new DataTransfer(); } catch { /* ignore */ }
                el.dispatchEvent(new DragEvent(type, { bubbles: true, cancelable: true, dataTransfer: dt }));
            } catch {
                try { el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true })); } catch { /* ignore */ }
            }
        }

        for (const type of animationEvents) {
            try {
                el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
            } catch { /* ignore */ }
        }

        for (const type of transitionEvents) {
            try {
                el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
            } catch { /* ignore */ }
        }

        for (const type of pointerEvents) {
            try {
                el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
            } catch { /* ignore */ }
        }

        for (const type of touchEvents) {
            try {
                el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
            } catch { /* ignore */ }
        }

        for (const type of mediaEvents) {
            try {
                el.dispatchEvent(new Event(type, { bubbles: true, cancelable: true }));
            } catch { /* ignore */ }
        }

    for (const type of directEvents) {
      try {
        el.dispatchEvent(new Event(type));
      } catch { /* ignore */ }
    }

    try {
      if (typeof el.focus === 'function') el.focus();
    } catch { /* ignore */ }
  }

    // Fire a few common window/document events.
    // Avoid beforeunload/unload, which can tear down the execution context.
    try {
        for (const type of windowEvents) {
            try { window.dispatchEvent(new Event(type)); } catch { /* ignore */ }
            try { document.dispatchEvent(new Event(type)); } catch { /* ignore */ }
        }
    } catch { /* ignore */ }

    // More realistic triggers for certain window events.
    try {
        // hashchange
        try { location.hash = 'xssbench'; } catch { /* ignore */ }
        // message
        try { window.postMessage('xssbench', '*'); } catch { /* ignore */ }
    } catch { /* ignore */ }
}
