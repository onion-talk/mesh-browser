(() => {
  'use strict';

  const nativeMap = new WeakMap();
  const origToString = Function.prototype.toString;
  const fakeToString = function toString() {
    if (nativeMap.has(this)) return nativeMap.get(this);
    return origToString.call(this);
  };
  nativeMap.set(fakeToString, 'function toString() { [native code] }');
  try {
    Object.defineProperty(Function.prototype, 'toString', {
      value: fakeToString, writable: true, configurable: true
    });
  } catch (_) {}

  const markNative = (fn, label) => {
    nativeMap.set(fn, `function ${label}() { [native code] }`);
    return fn;
  };

  const defGetter = (obj, prop, valOrFn, isFn = false) => {
    if (!obj) return;
    try {
      const getter = markNative(
        isFn ? function() { return valOrFn.call(this); } : function() { return valOrFn; },
        `get ${prop}`
      );
      Object.defineProperty(obj, prop, { get: getter, enumerable: true, configurable: true });
    } catch (_) {}
  };

  const defMethod = (obj, prop, fn) => {
    if (!obj) return;
    try {
      markNative(fn, prop);
      Object.defineProperty(obj, prop, { value: fn, writable: true, enumerable: true, configurable: true });
    } catch (_) {}
  };

  // --- 1. Consistent Firefox 115 (Win64) Navigator ---
  const navProto = typeof Navigator !== 'undefined' ? Navigator.prototype : navigator;
  defGetter(navProto, 'platform', 'Win32');
  defGetter(navProto, 'oscpu', 'Windows NT 10.0; Win64; x64');
  defGetter(navProto, 'appVersion', '5.0 (Windows)');
  defGetter(navProto, 'vendor', '');
  defGetter(navProto, 'productSub', '20100101');
  defGetter(navProto, 'buildID', '20181001000000');
  defGetter(navProto, 'hardwareConcurrency', 2);
  defGetter(navProto, 'deviceMemory', 8);
  defGetter(navProto, 'language', 'en-US');
  defGetter(navProto, 'languages', Object.freeze(['en-US', 'en']));
  defGetter(navProto, 'doNotTrack', 'unspecified');
  defGetter(navProto, 'maxTouchPoints', 0);
  defGetter(navProto, 'webdriver', false);
  defGetter(navProto, 'pdfViewerEnabled', false);

  const emptyList = Object.freeze({ length: 0, item: () => null, namedItem: () => null, [Symbol.iterator]: function*() {} });
  defGetter(navProto, 'plugins', emptyList);
  defGetter(navProto, 'mimeTypes', emptyList);
  defGetter(navProto, 'connection', undefined);
  defGetter(navProto, 'getBattery', undefined);
  defGetter(navProto, 'keyboard', undefined);
  defGetter(navProto, 'bluetooth', undefined);
  defGetter(navProto, 'usb', undefined);
  defGetter(navProto, 'serial', undefined);
  defGetter(navProto, 'hid', undefined);

  if (typeof MediaDevices !== 'undefined') {
    defMethod(MediaDevices.prototype, 'enumerateDevices', () => Promise.resolve([]));
    defMethod(MediaDevices.prototype, 'getUserMedia', () => Promise.reject(new DOMException('Permission denied', 'NotAllowedError')));
    defMethod(MediaDevices.prototype, 'getDisplayMedia', () => Promise.reject(new DOMException('Permission denied', 'NotAllowedError')));
  }
  if (typeof SpeechSynthesis !== 'undefined') {
    defMethod(SpeechSynthesis.prototype, 'getVoices', () => []);
  }
  if (typeof Permissions !== 'undefined') {
    defMethod(Permissions.prototype, 'query', (desc) => {
      const name = desc && desc.name ? String(desc.name) : '';
      const state = ['notifications', 'geolocation', 'camera', 'microphone'].includes(name) ? 'denied' : 'prompt';
      return Promise.resolve({ state, status: state, onchange: null });
    });
  }

  // --- 2. Uniform Screen, Window & Media Queries ---
  if (typeof Screen !== 'undefined') {
    for (const [k, v] of [['width', 1600], ['height', 840], ['availWidth', 1600], ['availHeight', 840], ['availLeft', 0], ['availTop', 0], ['colorDepth', 24], ['pixelDepth', 24]]) {
      defGetter(Screen.prototype, k, v);
    }
    if (typeof ScreenOrientation !== 'undefined') {
      defGetter(ScreenOrientation.prototype, 'type', 'landscape-primary');
      defGetter(ScreenOrientation.prototype, 'angle', 0);
    }
  }
  defGetter(window, 'devicePixelRatio', 1);
  defGetter(window, 'screenX', 0);
  defGetter(window, 'screenY', 0);
  defGetter(window, 'screenLeft', 0);
  defGetter(window, 'screenTop', 0);
  defGetter(window, 'outerWidth', () => window.innerWidth, true);
  defGetter(window, 'outerHeight', () => window.innerHeight, true);

  if (typeof window.matchMedia === 'function') {
    const origMM = window.matchMedia.bind(window);
    const fixedMM = [
      [/prefers-color-scheme:\s*dark/i, false],
      [/prefers-color-scheme:\s*light/i, true],
      [/prefers-reduced-motion:\s*reduce/i, false],
      [/prefers-reduced-motion:\s*no-preference/i, true],
      [/prefers-contrast:\s*(more|less|custom)/i, false],
      [/prefers-contrast:\s*no-preference/i, true],
      [/forced-colors:\s*active/i, false],
      [/inverted-colors:\s*inverted/i, false],
      [/pointer:\s*coarse/i, false],
      [/pointer:\s*fine/i, true],
      [/any-pointer:\s*coarse/i, false],
      [/any-pointer:\s*fine/i, true],
      [/hover:\s*none/i, false],
      [/hover:\s*hover/i, true],
      [/color-gamut:\s*(p3|rec2020)/i, false],
      [/color-gamut:\s*srgb/i, true],
    ];
    defMethod(window, 'matchMedia', function(q) {
      const mql = origMM(q);
      const s = String(q || '');
      for (const [rx, forced] of fixedMM) {
        if (rx.test(s)) {
          return {
            matches: forced, media: s, onchange: null,
            addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent: () => false
          };
        }
      }
      return mql;
    });
  }

  // --- 3. WebGL/WebGPU Block + Canvas Readback & MeasureText Quantization ---
  if (typeof HTMLCanvasElement !== 'undefined') {
    const origGetCtx = HTMLCanvasElement.prototype.getContext;
    defMethod(HTMLCanvasElement.prototype, 'getContext', function(type, ...args) {
      if (typeof type === 'string' && /webgl|webgpu/i.test(type)) return null;
      return origGetCtx.call(this, type, ...args);
    });
    const blank = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=';
    defMethod(HTMLCanvasElement.prototype, 'toDataURL', function() { return blank; });
    if (HTMLCanvasElement.prototype.toBlob) {
      defMethod(HTMLCanvasElement.prototype, 'toBlob', function(cb, type) {
        if (typeof cb === 'function') cb(new Blob([], { type: type || 'image/png' }));
      });
    }
  }
  if (typeof OffscreenCanvas !== 'undefined') {
    const origOffCtx = OffscreenCanvas.prototype.getContext;
    defMethod(OffscreenCanvas.prototype, 'getContext', function(type, ...args) {
      if (typeof type === 'string' && /webgl|webgpu/i.test(type)) return null;
      return origOffCtx.call(this, type, ...args);
    });
  }
  if (typeof CanvasRenderingContext2D !== 'undefined') {
    const proto2d = CanvasRenderingContext2D.prototype;
    if (proto2d.getImageData) {
      const origGID = proto2d.getImageData;
      defMethod(proto2d, 'getImageData', function(sx, sy, sw, sh) {
        const img = origGID.call(this, sx, sy, sw, sh);
        img.data.fill(255);
        return img;
      });
    }
    if (proto2d.measureText) {
      const origMT = proto2d.measureText;
      const q = (v) => (typeof v === 'number' && isFinite(v)) ? Math.round(v * 2) / 2 : v;
      defMethod(proto2d, 'measureText', function(text) {
        const m = origMT.call(this, text);
        return {
          width: q(m.width),
          actualBoundingBoxLeft: q(m.actualBoundingBoxLeft),
          actualBoundingBoxRight: q(m.actualBoundingBoxRight),
          actualBoundingBoxAscent: q(m.actualBoundingBoxAscent),
          actualBoundingBoxDescent: q(m.actualBoundingBoxDescent),
          fontBoundingBoxAscent: q(m.fontBoundingBoxAscent),
          fontBoundingBoxDescent: q(m.fontBoundingBoxDescent),
        };
      });
    }
  }

  // Quantize DOM sub-pixel glyph rects to 0.5px
  const quantRect = (r) => {
    const q = (v) => Math.round(v * 2) / 2;
    return {
      x: q(r.x), y: q(r.y), width: q(r.width), height: q(r.height),
      top: q(r.top), right: q(r.right), bottom: q(r.bottom), left: q(r.left),
      toJSON() { return { x: this.x, y: this.y, width: this.width, height: this.height, top: this.top, right: this.right, bottom: this.bottom, left: this.left }; }
    };
  };
  if (typeof Element !== 'undefined' && Element.prototype.getBoundingClientRect) {
    const origRect = Element.prototype.getBoundingClientRect;
    defMethod(Element.prototype, 'getBoundingClientRect', function() { return quantRect(origRect.call(this)); });
  }
  if (typeof Range !== 'undefined' && Range.prototype.getBoundingClientRect) {
    const origRRect = Range.prototype.getBoundingClientRect;
    defMethod(Range.prototype, 'getBoundingClientRect', function() { return quantRect(origRRect.call(this)); });
  }

  // --- 4. WebAudio Neutralization ---
  if (typeof BaseAudioContext !== 'undefined') {
    defGetter(BaseAudioContext.prototype, 'sampleRate', 48000);
  }
  if (typeof AudioContext !== 'undefined') {
    defGetter(AudioContext.prototype, 'baseLatency', 0.01);
    defGetter(AudioContext.prototype, 'outputLatency', 0.02);
  }
  if (typeof AudioBuffer !== 'undefined') {
    const origGCD = AudioBuffer.prototype.getChannelData;
    defMethod(AudioBuffer.prototype, 'getChannelData', function(ch) {
      const arr = origGCD.call(this, ch);
      arr.fill(0);
      return arr;
    });
    if (AudioBuffer.prototype.copyFromChannel) {
      defMethod(AudioBuffer.prototype, 'copyFromChannel', function(dest) { dest.fill(0); });
    }
  }
  if (typeof AnalyserNode !== 'undefined') {
    defMethod(AnalyserNode.prototype, 'getFloatFrequencyData', (a) => a.fill(-100));
    defMethod(AnalyserNode.prototype, 'getByteFrequencyData', (a) => a.fill(0));
    defMethod(AnalyserNode.prototype, 'getFloatTimeDomainData', (a) => a.fill(0));
    defMethod(AnalyserNode.prototype, 'getByteTimeDomainData', (a) => a.fill(128));
  }

  // --- 5. Intl & Date UTC + en-US Lock ---
  defMethod(Date.prototype, 'getTimezoneOffset', () => 0);
  if (typeof Intl !== 'undefined') {
    for (const name of ['DateTimeFormat', 'NumberFormat', 'Collator', 'PluralRules', 'RelativeTimeFormat']) {
      const Orig = Intl[name];
      if (!Orig) continue;
      const Wrapped = function(locales, options) {
        const opts = name === 'DateTimeFormat' ? Object.assign({ timeZone: 'UTC' }, options || {}) : options;
        return new Orig('en-US', opts);
      };
      Wrapped.prototype = Orig.prototype;
      Wrapped.supportedLocalesOf = (...args) => Orig.supportedLocalesOf(...args);
      markNative(Wrapped, name);
      if (name === 'DateTimeFormat' && Orig.prototype.resolvedOptions) {
        const origRes = Orig.prototype.resolvedOptions;
        defMethod(Orig.prototype, 'resolvedOptions', function() {
          const r = origRes.call(this);
          r.locale = 'en-US';
          r.timeZone = 'UTC';
          r.calendar = 'gregory';
          r.numberingSystem = 'latn';
          return r;
        });
      }
      Intl[name] = Wrapped;
    }
  }

  // --- 6. High-Resolution Timer Clamping (100ms) ---
  if (typeof Performance !== 'undefined') {
    if (Performance.prototype.now) {
      const origNow = Performance.prototype.now;
      defMethod(Performance.prototype, 'now', function() { return Math.floor(origNow.call(this) / 100) * 100; });
    }
    defGetter(Performance.prototype, 'timeOrigin', () => Math.floor(Date.now() / 1000) * 1000, true);
  }
  const origDateNow = Date.now;
  defMethod(Date, 'now', () => Math.floor(origDateNow() / 100) * 100);
  if (typeof Event !== 'undefined') {
    const tsDesc = Object.getOwnPropertyDescriptor(Event.prototype, 'timeStamp');
    if (tsDesc && tsDesc.get) {
      defGetter(Event.prototype, 'timeStamp', function() { return Math.floor(tsDesc.get.call(this) / 100) * 100; }, true);
    }
  }

  // --- 7. Cross-site window.name wipe ---
  try {
    if (window.top === window && document.referrer) {
      const refOrigin = new URL(document.referrer).origin;
      if (refOrigin !== location.origin) window.name = '';
    }
  } catch (_) {}
})();
