"use strict";
var pm = Object.create;
var vi = Object.defineProperty;
var dm = Object.getOwnPropertyDescriptor;
var fm = Object.getOwnPropertyNames;
var mm = Object.getPrototypeOf, hm = Object.prototype.hasOwnProperty;
var xm = (e, t) => () => (e && (t = e(e = 0)), t);
var _ = (e, t) => () => (t || e((t = { exports: {} }).exports, t), t.exports), gm = (e, t) => {
  for (var n in t)
    vi(e, n, { get: t[n], enumerable: !0 });
}, ym = (e, t, n, r) => {
  if (t && typeof t == "object" || typeof t == "function")
    for (let i of fm(t))
      !hm.call(e, i) && i !== n && vi(e, i, { get: () => t[i], enumerable: !(r = dm(t, i)) || r.enumerable });
  return e;
};
var he = (e, t, n) => (n = e != null ? pm(mm(e)) : {}, ym(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  t || !e || !e.__esModule ? vi(n, "default", { value: e, enumerable: !0 }) : n,
  e
));

// node_modules/.pnpm/tsup@8.5.1_tsx@4.22.4_typescript@6.0.3/node_modules/tsup/assets/cjs_shims.js
var c = xm(() => {
  "use strict";
});

// node_modules/.pnpm/dotenv@17.4.2/node_modules/dotenv/lib/main.js
var ko = _((TE, Ke) => {
  "use strict";
  c();
  var bi = require("fs"), Xn = require("path"), vm = require("os"), bm = require("crypto"), _o = [
    "◈ encrypted .env [www.dotenvx.com]",
    "◈ secrets for agents [www.dotenvx.com]",
    "⌁ auth for agents [www.vestauth.com]",
    "⌘ custom filepath { path: '/custom/path/.env' }",
    "⌘ enable debugging { debug: true }",
    "⌘ override existing { override: true }",
    "⌘ suppress logs { quiet: true }",
    "⌘ multiple files { path: ['.env.local', '.env'] }"
  ];
  function wm() {
    return _o[Math.floor(Math.random() * _o.length)];
  }
  function qt(e) {
    return typeof e == "string" ? !["false", "0", "no", "off", ""].includes(e.toLowerCase()) : !!e;
  }
  function _m() {
    return process.stdout.isTTY;
  }
  function Em(e) {
    return _m() ? `\x1B[2m${e}\x1B[0m` : e;
  }
  var Sm = /(?:^|^)\s*(?:export\s+)?([\w.-]+)(?:\s*=\s*?|:\s+?)(\s*'(?:\\'|[^'])*'|\s*"(?:\\"|[^"])*"|\s*`(?:\\`|[^`])*`|[^#\r\n]+)?\s*(?:#.*)?(?:$|$)/mg;
  function Rm(e) {
    let t = {}, n = e.toString();
    n = n.replace(/\r\n?/mg, `
`);
    let r;
    for (; (r = Sm.exec(n)) != null; ) {
      let i = r[1], s = r[2] || "";
      s = s.trim();
      let a = s[0];
      s = s.replace(/^(['"`])([\s\S]*)\1$/mg, "$2"), a === '"' && (s = s.replace(/\\n/g, `
`), s = s.replace(/\\r/g, "\r")), t[i] = s;
    }
    return t;
  }
  function Tm(e) {
    e = e || {};
    let t = To(e);
    e.path = t;
    let n = te.configDotenv(e);
    if (!n.parsed) {
      let a = new Error(`MISSING_DATA: Cannot parse ${t} for an unknown reason`);
      throw a.code = "MISSING_DATA", a;
    }
    let r = Ro(e).split(","), i = r.length, s;
    for (let a = 0; a < i; a++)
      try {
        let o = r[a].trim(), l = Cm(n, o);
        s = te.decrypt(l.ciphertext, l.key);
        break;
      } catch (o) {
        if (a + 1 >= i)
          throw o;
      }
    return te.parse(s);
  }
  function km(e) {
    console.error(`⚠ ${e}`);
  }
  function dn(e) {
    console.log(`┆ ${e}`);
  }
  function So(e) {
    console.log(`◇ ${e}`);
  }
  function Ro(e) {
    return e && e.DOTENV_KEY && e.DOTENV_KEY.length > 0 ? e.DOTENV_KEY : process.env.DOTENV_KEY && process.env.DOTENV_KEY.length > 0 ? process.env.DOTENV_KEY : "";
  }
  function Cm(e, t) {
    let n;
    try {
      n = new URL(t);
    } catch (o) {
      if (o.code === "ERR_INVALID_URL") {
        let l = new Error("INVALID_DOTENV_KEY: Wrong format. Must be in valid uri format like dotenv://:key_1234@dotenvx.com/vault/.env.vault?environment=development");
        throw l.code = "INVALID_DOTENV_KEY", l;
      }
      throw o;
    }
    let r = n.password;
    if (!r) {
      let o = new Error("INVALID_DOTENV_KEY: Missing key part");
      throw o.code = "INVALID_DOTENV_KEY", o;
    }
    let i = n.searchParams.get("environment");
    if (!i) {
      let o = new Error("INVALID_DOTENV_KEY: Missing environment part");
      throw o.code = "INVALID_DOTENV_KEY", o;
    }
    let s = `DOTENV_VAULT_${i.toUpperCase()}`, a = e.parsed[s];
    if (!a) {
      let o = new Error(`NOT_FOUND_DOTENV_ENVIRONMENT: Cannot locate environment ${s} in your .env.vault file.`);
      throw o.code = "NOT_FOUND_DOTENV_ENVIRONMENT", o;
    }
    return { ciphertext: a, key: r };
  }
  function To(e) {
    let t = null;
    if (e && e.path && e.path.length > 0)
      if (Array.isArray(e.path))
        for (let n of e.path)
          bi.existsSync(n) && (t = n.endsWith(".vault") ? n : `${n}.vault`);
      else
        t = e.path.endsWith(".vault") ? e.path : `${e.path}.vault`;
    else
      t = Xn.resolve(process.cwd(), ".env.vault");
    return bi.existsSync(t) ? t : null;
  }
  function Eo(e) {
    return e[0] === "~" ? Xn.join(vm.homedir(), e.slice(1)) : e;
  }
  function Am(e) {
    let t = qt(process.env.DOTENV_CONFIG_DEBUG || e && e.debug), n = qt(process.env.DOTENV_CONFIG_QUIET || e && e.quiet);
    (t || !n) && So("loading env from encrypted .env.vault");
    let r = te._parseVault(e), i = process.env;
    return e && e.processEnv != null && (i = e.processEnv), te.populate(i, r, e), { parsed: r };
  }
  function Om(e) {
    let t = Xn.resolve(process.cwd(), ".env"), n = "utf8", r = process.env;
    e && e.processEnv != null && (r = e.processEnv);
    let i = qt(r.DOTENV_CONFIG_DEBUG || e && e.debug), s = qt(r.DOTENV_CONFIG_QUIET || e && e.quiet);
    e && e.encoding ? n = e.encoding : i && dn("no encoding is specified (UTF-8 is used by default)");
    let a = [t];
    if (e && e.path)
      if (!Array.isArray(e.path))
        a = [Eo(e.path)];
      else {
        a = [];
        for (let u of e.path)
          a.push(Eo(u));
      }
    let o, l = {};
    for (let u of a)
      try {
        let d = te.parse(bi.readFileSync(u, { encoding: n }));
        te.populate(l, d, e);
      } catch (d) {
        i && dn(`failed to load ${u} ${d.message}`), o = d;
      }
    let p = te.populate(r, l, e);
    if (i = qt(r.DOTENV_CONFIG_DEBUG || i), s = qt(r.DOTENV_CONFIG_QUIET || s), i || !s) {
      let u = Object.keys(p).length, d = [];
      for (let m of a)
        try {
          let x = Xn.relative(process.cwd(), m);
          d.push(x);
        } catch (x) {
          i && dn(`failed to load ${m} ${x.message}`), o = x;
        }
      So(`injected env (${u}) from ${d.join(",")} ${Em(`// tip: ${wm()}`)}`);
    }
    return o ? { parsed: l, error: o } : { parsed: l };
  }
  function Pm(e) {
    if (Ro(e).length === 0)
      return te.configDotenv(e);
    let t = To(e);
    return t ? te._configVault(e) : (km(`you set DOTENV_KEY but you are missing a .env.vault file at ${t}`), te.configDotenv(e));
  }
  function jm(e, t) {
    let n = Buffer.from(t.slice(-64), "hex"), r = Buffer.from(e, "base64"), i = r.subarray(0, 12), s = r.subarray(-16);
    r = r.subarray(12, -16);
    try {
      let a = bm.createDecipheriv("aes-256-gcm", n, i);
      return a.setAuthTag(s), `${a.update(r)}${a.final()}`;
    } catch (a) {
      let o = a instanceof RangeError, l = a.message === "Invalid key length", p = a.message === "Unsupported state or unable to authenticate data";
      if (o || l) {
        let u = new Error("INVALID_DOTENV_KEY: It must be 64 characters long (or more)");
        throw u.code = "INVALID_DOTENV_KEY", u;
      } else if (p) {
        let u = new Error("DECRYPTION_FAILED: Please check your DOTENV_KEY");
        throw u.code = "DECRYPTION_FAILED", u;
      } else
        throw a;
    }
  }
  function qm(e, t, n = {}) {
    let r = !!(n && n.debug), i = !!(n && n.override), s = {};
    if (typeof t != "object") {
      let a = new Error("OBJECT_REQUIRED: Please check the processEnv argument being passed to populate");
      throw a.code = "OBJECT_REQUIRED", a;
    }
    for (let a of Object.keys(t))
      Object.prototype.hasOwnProperty.call(e, a) ? (i === !0 && (e[a] = t[a], s[a] = t[a]), r && dn(i === !0 ? `"${a}" is already defined and WAS overwritten` : `"${a}" is already defined and was NOT overwritten`)) : (e[a] = t[a], s[a] = t[a]);
    return s;
  }
  var te = {
    configDotenv: Om,
    _configVault: Am,
    _parseVault: Tm,
    config: Pm,
    decrypt: jm,
    parse: Rm,
    populate: qm
  };
  Ke.exports.configDotenv = te.configDotenv;
  Ke.exports._configVault = te._configVault;
  Ke.exports._parseVault = te._parseVault;
  Ke.exports.config = te.config;
  Ke.exports.decrypt = te.decrypt;
  Ke.exports.parse = te.parse;
  Ke.exports.populate = te.populate;
  Ke.exports = te;
});

// node_modules/.pnpm/dotenv@17.4.2/node_modules/dotenv/lib/env-options.js
var Ao = _((CE, Co) => {
  "use strict";
  c();
  var ht = {};
  process.env.DOTENV_CONFIG_ENCODING != null && (ht.encoding = process.env.DOTENV_CONFIG_ENCODING);
  process.env.DOTENV_CONFIG_PATH != null && (ht.path = process.env.DOTENV_CONFIG_PATH);
  process.env.DOTENV_CONFIG_QUIET != null && (ht.quiet = process.env.DOTENV_CONFIG_QUIET);
  process.env.DOTENV_CONFIG_DEBUG != null && (ht.debug = process.env.DOTENV_CONFIG_DEBUG);
  process.env.DOTENV_CONFIG_OVERRIDE != null && (ht.override = process.env.DOTENV_CONFIG_OVERRIDE);
  process.env.DOTENV_CONFIG_DOTENV_KEY != null && (ht.DOTENV_KEY = process.env.DOTENV_CONFIG_DOTENV_KEY);
  Co.exports = ht;
});

// node_modules/.pnpm/dotenv@17.4.2/node_modules/dotenv/lib/cli-options.js
var Po = _((OE, Oo) => {
  "use strict";
  c();
  var Lm = /^dotenv_config_(encoding|path|quiet|debug|override|DOTENV_KEY)=(.+)$/;
  Oo.exports = function(t) {
    let n = t.reduce(function(r, i) {
      let s = i.match(Lm);
      return s && (r[s[1]] = s[2]), r;
    }, {});
    return "quiet" in n || (n.quiet = "true"), n;
  };
});

// node_modules/.pnpm/delayed-stream@1.0.0/node_modules/delayed-stream/lib/delayed_stream.js
var Go = _((n0, Wo) => {
  "use strict";
  c();
  var Vo = require("stream").Stream, Uh = require("util");
  Wo.exports = Ie;
  function Ie() {
    this.source = null, this.dataSize = 0, this.maxDataSize = 1024 * 1024, this.pauseStream = !0, this._maxDataSizeExceeded = !1, this._released = !1, this._bufferedEvents = [];
  }
  Uh.inherits(Ie, Vo);
  Ie.create = function(e, t) {
    var n = new this();
    t = t || {};
    for (var r in t)
      n[r] = t[r];
    n.source = e;
    var i = e.emit;
    return e.emit = function() {
      return n._handleEmit(arguments), i.apply(e, arguments);
    }, e.on("error", function() {
    }), n.pauseStream && e.pause(), n;
  };
  Object.defineProperty(Ie.prototype, "readable", {
    configurable: !0,
    enumerable: !0,
    get: function() {
      return this.source.readable;
    }
  });
  Ie.prototype.setEncoding = function() {
    return this.source.setEncoding.apply(this.source, arguments);
  };
  Ie.prototype.resume = function() {
    this._released || this.release(), this.source.resume();
  };
  Ie.prototype.pause = function() {
    this.source.pause();
  };
  Ie.prototype.release = function() {
    this._released = !0, this._bufferedEvents.forEach(function(e) {
      this.emit.apply(this, e);
    }.bind(this)), this._bufferedEvents = [];
  };
  Ie.prototype.pipe = function() {
    var e = Vo.prototype.pipe.apply(this, arguments);
    return this.resume(), e;
  };
  Ie.prototype._handleEmit = function(e) {
    if (this._released) {
      this.emit.apply(this, e);
      return;
    }
    e[0] === "data" && (this.dataSize += e[1].length, this._checkIfMaxDataSizeExceeded()), this._bufferedEvents.push(e);
  };
  Ie.prototype._checkIfMaxDataSizeExceeded = function() {
    if (!this._maxDataSizeExceeded && !(this.dataSize <= this.maxDataSize)) {
      this._maxDataSizeExceeded = !0;
      var e = "DelayedStream#maxDataSize of " + this.maxDataSize + " bytes exceeded.";
      this.emit("error", new Error(e));
    }
  };
});

// node_modules/.pnpm/combined-stream@1.0.8/node_modules/combined-stream/lib/combined_stream.js
var Qo = _((i0, Yo) => {
  "use strict";
  c();
  var Dh = require("util"), Jo = require("stream").Stream, Ko = Go();
  Yo.exports = K;
  function K() {
    this.writable = !1, this.readable = !0, this.dataSize = 0, this.maxDataSize = 2 * 1024 * 1024, this.pauseStreams = !0, this._released = !1, this._streams = [], this._currentStream = null, this._insideLoop = !1, this._pendingNext = !1;
  }
  Dh.inherits(K, Jo);
  K.create = function(e) {
    var t = new this();
    e = e || {};
    for (var n in e)
      t[n] = e[n];
    return t;
  };
  K.isStreamLike = function(e) {
    return typeof e != "function" && typeof e != "string" && typeof e != "boolean" && typeof e != "number" && !Buffer.isBuffer(e);
  };
  K.prototype.append = function(e) {
    var t = K.isStreamLike(e);
    if (t) {
      if (!(e instanceof Ko)) {
        var n = Ko.create(e, {
          maxDataSize: 1 / 0,
          pauseStream: this.pauseStreams
        });
        e.on("data", this._checkDataSize.bind(this)), e = n;
      }
      this._handleErrors(e), this.pauseStreams && e.pause();
    }
    return this._streams.push(e), this;
  };
  K.prototype.pipe = function(e, t) {
    return Jo.prototype.pipe.call(this, e, t), this.resume(), e;
  };
  K.prototype._getNext = function() {
    if (this._currentStream = null, this._insideLoop) {
      this._pendingNext = !0;
      return;
    }
    this._insideLoop = !0;
    try {
      do
        this._pendingNext = !1, this._realGetNext();
      while (this._pendingNext);
    } finally {
      this._insideLoop = !1;
    }
  };
  K.prototype._realGetNext = function() {
    var e = this._streams.shift();
    if (typeof e > "u") {
      this.end();
      return;
    }
    if (typeof e != "function") {
      this._pipeNext(e);
      return;
    }
    var t = e;
    t(function(n) {
      var r = K.isStreamLike(n);
      r && (n.on("data", this._checkDataSize.bind(this)), this._handleErrors(n)), this._pipeNext(n);
    }.bind(this));
  };
  K.prototype._pipeNext = function(e) {
    this._currentStream = e;
    var t = K.isStreamLike(e);
    if (t) {
      e.on("end", this._getNext.bind(this)), e.pipe(this, { end: !1 });
      return;
    }
    var n = e;
    this.write(n), this._getNext();
  };
  K.prototype._handleErrors = function(e) {
    var t = this;
    e.on("error", function(n) {
      t._emitError(n);
    });
  };
  K.prototype.write = function(e) {
    this.emit("data", e);
  };
  K.prototype.pause = function() {
    this.pauseStreams && (this.pauseStreams && this._currentStream && typeof this._currentStream.pause == "function" && this._currentStream.pause(), this.emit("pause"));
  };
  K.prototype.resume = function() {
    this._released || (this._released = !0, this.writable = !0, this._getNext()), this.pauseStreams && this._currentStream && typeof this._currentStream.resume == "function" && this._currentStream.resume(), this.emit("resume");
  };
  K.prototype.end = function() {
    this._reset(), this.emit("end");
  };
  K.prototype.destroy = function() {
    this._reset(), this.emit("close");
  };
  K.prototype._reset = function() {
    this.writable = !1, this._streams = [], this._currentStream = null;
  };
  K.prototype._checkDataSize = function() {
    if (this._updateDataSize(), !(this.dataSize <= this.maxDataSize)) {
      var e = "DelayedStream#maxDataSize of " + this.maxDataSize + " bytes exceeded.";
      this._emitError(new Error(e));
    }
  };
  K.prototype._updateDataSize = function() {
    this.dataSize = 0;
    var e = this;
    this._streams.forEach(function(t) {
      t.dataSize && (e.dataSize += t.dataSize);
    }), this._currentStream && this._currentStream.dataSize && (this.dataSize += this._currentStream.dataSize);
  };
  K.prototype._emitError = function(e) {
    this._reset(), this.emit("error", e);
  };
});

// node_modules/.pnpm/mime-db@1.52.0/node_modules/mime-db/db.json
var Xo = _((a0, Ih) => {
  Ih.exports = {
    "application/1d-interleaved-parityfec": {
      source: "iana"
    },
    "application/3gpdash-qoe-report+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/3gpp-ims+xml": {
      source: "iana",
      compressible: !0
    },
    "application/3gpphal+json": {
      source: "iana",
      compressible: !0
    },
    "application/3gpphalforms+json": {
      source: "iana",
      compressible: !0
    },
    "application/a2l": {
      source: "iana"
    },
    "application/ace+cbor": {
      source: "iana"
    },
    "application/activemessage": {
      source: "iana"
    },
    "application/activity+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-costmap+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-costmapfilter+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-directory+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-endpointcost+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-endpointcostparams+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-endpointprop+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-endpointpropparams+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-error+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-networkmap+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-networkmapfilter+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-updatestreamcontrol+json": {
      source: "iana",
      compressible: !0
    },
    "application/alto-updatestreamparams+json": {
      source: "iana",
      compressible: !0
    },
    "application/aml": {
      source: "iana"
    },
    "application/andrew-inset": {
      source: "iana",
      extensions: ["ez"]
    },
    "application/applefile": {
      source: "iana"
    },
    "application/applixware": {
      source: "apache",
      extensions: ["aw"]
    },
    "application/at+jwt": {
      source: "iana"
    },
    "application/atf": {
      source: "iana"
    },
    "application/atfx": {
      source: "iana"
    },
    "application/atom+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["atom"]
    },
    "application/atomcat+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["atomcat"]
    },
    "application/atomdeleted+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["atomdeleted"]
    },
    "application/atomicmail": {
      source: "iana"
    },
    "application/atomsvc+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["atomsvc"]
    },
    "application/atsc-dwd+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["dwd"]
    },
    "application/atsc-dynamic-event-message": {
      source: "iana"
    },
    "application/atsc-held+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["held"]
    },
    "application/atsc-rdt+json": {
      source: "iana",
      compressible: !0
    },
    "application/atsc-rsat+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rsat"]
    },
    "application/atxml": {
      source: "iana"
    },
    "application/auth-policy+xml": {
      source: "iana",
      compressible: !0
    },
    "application/bacnet-xdd+zip": {
      source: "iana",
      compressible: !1
    },
    "application/batch-smtp": {
      source: "iana"
    },
    "application/bdoc": {
      compressible: !1,
      extensions: ["bdoc"]
    },
    "application/beep+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/calendar+json": {
      source: "iana",
      compressible: !0
    },
    "application/calendar+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xcs"]
    },
    "application/call-completion": {
      source: "iana"
    },
    "application/cals-1840": {
      source: "iana"
    },
    "application/captive+json": {
      source: "iana",
      compressible: !0
    },
    "application/cbor": {
      source: "iana"
    },
    "application/cbor-seq": {
      source: "iana"
    },
    "application/cccex": {
      source: "iana"
    },
    "application/ccmp+xml": {
      source: "iana",
      compressible: !0
    },
    "application/ccxml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["ccxml"]
    },
    "application/cdfx+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["cdfx"]
    },
    "application/cdmi-capability": {
      source: "iana",
      extensions: ["cdmia"]
    },
    "application/cdmi-container": {
      source: "iana",
      extensions: ["cdmic"]
    },
    "application/cdmi-domain": {
      source: "iana",
      extensions: ["cdmid"]
    },
    "application/cdmi-object": {
      source: "iana",
      extensions: ["cdmio"]
    },
    "application/cdmi-queue": {
      source: "iana",
      extensions: ["cdmiq"]
    },
    "application/cdni": {
      source: "iana"
    },
    "application/cea": {
      source: "iana"
    },
    "application/cea-2018+xml": {
      source: "iana",
      compressible: !0
    },
    "application/cellml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/cfw": {
      source: "iana"
    },
    "application/city+json": {
      source: "iana",
      compressible: !0
    },
    "application/clr": {
      source: "iana"
    },
    "application/clue+xml": {
      source: "iana",
      compressible: !0
    },
    "application/clue_info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/cms": {
      source: "iana"
    },
    "application/cnrp+xml": {
      source: "iana",
      compressible: !0
    },
    "application/coap-group+json": {
      source: "iana",
      compressible: !0
    },
    "application/coap-payload": {
      source: "iana"
    },
    "application/commonground": {
      source: "iana"
    },
    "application/conference-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/cose": {
      source: "iana"
    },
    "application/cose-key": {
      source: "iana"
    },
    "application/cose-key-set": {
      source: "iana"
    },
    "application/cpl+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["cpl"]
    },
    "application/csrattrs": {
      source: "iana"
    },
    "application/csta+xml": {
      source: "iana",
      compressible: !0
    },
    "application/cstadata+xml": {
      source: "iana",
      compressible: !0
    },
    "application/csvm+json": {
      source: "iana",
      compressible: !0
    },
    "application/cu-seeme": {
      source: "apache",
      extensions: ["cu"]
    },
    "application/cwt": {
      source: "iana"
    },
    "application/cybercash": {
      source: "iana"
    },
    "application/dart": {
      compressible: !0
    },
    "application/dash+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mpd"]
    },
    "application/dash-patch+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mpp"]
    },
    "application/dashdelta": {
      source: "iana"
    },
    "application/davmount+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["davmount"]
    },
    "application/dca-rft": {
      source: "iana"
    },
    "application/dcd": {
      source: "iana"
    },
    "application/dec-dx": {
      source: "iana"
    },
    "application/dialog-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/dicom": {
      source: "iana"
    },
    "application/dicom+json": {
      source: "iana",
      compressible: !0
    },
    "application/dicom+xml": {
      source: "iana",
      compressible: !0
    },
    "application/dii": {
      source: "iana"
    },
    "application/dit": {
      source: "iana"
    },
    "application/dns": {
      source: "iana"
    },
    "application/dns+json": {
      source: "iana",
      compressible: !0
    },
    "application/dns-message": {
      source: "iana"
    },
    "application/docbook+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["dbk"]
    },
    "application/dots+cbor": {
      source: "iana"
    },
    "application/dskpp+xml": {
      source: "iana",
      compressible: !0
    },
    "application/dssc+der": {
      source: "iana",
      extensions: ["dssc"]
    },
    "application/dssc+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xdssc"]
    },
    "application/dvcs": {
      source: "iana"
    },
    "application/ecmascript": {
      source: "iana",
      compressible: !0,
      extensions: ["es", "ecma"]
    },
    "application/edi-consent": {
      source: "iana"
    },
    "application/edi-x12": {
      source: "iana",
      compressible: !1
    },
    "application/edifact": {
      source: "iana",
      compressible: !1
    },
    "application/efi": {
      source: "iana"
    },
    "application/elm+json": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/elm+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emergencycalldata.cap+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/emergencycalldata.comment+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emergencycalldata.control+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emergencycalldata.deviceinfo+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emergencycalldata.ecall.msd": {
      source: "iana"
    },
    "application/emergencycalldata.providerinfo+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emergencycalldata.serviceinfo+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emergencycalldata.subscriberinfo+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emergencycalldata.veds+xml": {
      source: "iana",
      compressible: !0
    },
    "application/emma+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["emma"]
    },
    "application/emotionml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["emotionml"]
    },
    "application/encaprtp": {
      source: "iana"
    },
    "application/epp+xml": {
      source: "iana",
      compressible: !0
    },
    "application/epub+zip": {
      source: "iana",
      compressible: !1,
      extensions: ["epub"]
    },
    "application/eshop": {
      source: "iana"
    },
    "application/exi": {
      source: "iana",
      extensions: ["exi"]
    },
    "application/expect-ct-report+json": {
      source: "iana",
      compressible: !0
    },
    "application/express": {
      source: "iana",
      extensions: ["exp"]
    },
    "application/fastinfoset": {
      source: "iana"
    },
    "application/fastsoap": {
      source: "iana"
    },
    "application/fdt+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["fdt"]
    },
    "application/fhir+json": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/fhir+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/fido.trusted-apps+json": {
      compressible: !0
    },
    "application/fits": {
      source: "iana"
    },
    "application/flexfec": {
      source: "iana"
    },
    "application/font-sfnt": {
      source: "iana"
    },
    "application/font-tdpfr": {
      source: "iana",
      extensions: ["pfr"]
    },
    "application/font-woff": {
      source: "iana",
      compressible: !1
    },
    "application/framework-attributes+xml": {
      source: "iana",
      compressible: !0
    },
    "application/geo+json": {
      source: "iana",
      compressible: !0,
      extensions: ["geojson"]
    },
    "application/geo+json-seq": {
      source: "iana"
    },
    "application/geopackage+sqlite3": {
      source: "iana"
    },
    "application/geoxacml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/gltf-buffer": {
      source: "iana"
    },
    "application/gml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["gml"]
    },
    "application/gpx+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["gpx"]
    },
    "application/gxf": {
      source: "apache",
      extensions: ["gxf"]
    },
    "application/gzip": {
      source: "iana",
      compressible: !1,
      extensions: ["gz"]
    },
    "application/h224": {
      source: "iana"
    },
    "application/held+xml": {
      source: "iana",
      compressible: !0
    },
    "application/hjson": {
      extensions: ["hjson"]
    },
    "application/http": {
      source: "iana"
    },
    "application/hyperstudio": {
      source: "iana",
      extensions: ["stk"]
    },
    "application/ibe-key-request+xml": {
      source: "iana",
      compressible: !0
    },
    "application/ibe-pkg-reply+xml": {
      source: "iana",
      compressible: !0
    },
    "application/ibe-pp-data": {
      source: "iana"
    },
    "application/iges": {
      source: "iana"
    },
    "application/im-iscomposing+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/index": {
      source: "iana"
    },
    "application/index.cmd": {
      source: "iana"
    },
    "application/index.obj": {
      source: "iana"
    },
    "application/index.response": {
      source: "iana"
    },
    "application/index.vnd": {
      source: "iana"
    },
    "application/inkml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["ink", "inkml"]
    },
    "application/iotp": {
      source: "iana"
    },
    "application/ipfix": {
      source: "iana",
      extensions: ["ipfix"]
    },
    "application/ipp": {
      source: "iana"
    },
    "application/isup": {
      source: "iana"
    },
    "application/its+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["its"]
    },
    "application/java-archive": {
      source: "apache",
      compressible: !1,
      extensions: ["jar", "war", "ear"]
    },
    "application/java-serialized-object": {
      source: "apache",
      compressible: !1,
      extensions: ["ser"]
    },
    "application/java-vm": {
      source: "apache",
      compressible: !1,
      extensions: ["class"]
    },
    "application/javascript": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["js", "mjs"]
    },
    "application/jf2feed+json": {
      source: "iana",
      compressible: !0
    },
    "application/jose": {
      source: "iana"
    },
    "application/jose+json": {
      source: "iana",
      compressible: !0
    },
    "application/jrd+json": {
      source: "iana",
      compressible: !0
    },
    "application/jscalendar+json": {
      source: "iana",
      compressible: !0
    },
    "application/json": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["json", "map"]
    },
    "application/json-patch+json": {
      source: "iana",
      compressible: !0
    },
    "application/json-seq": {
      source: "iana"
    },
    "application/json5": {
      extensions: ["json5"]
    },
    "application/jsonml+json": {
      source: "apache",
      compressible: !0,
      extensions: ["jsonml"]
    },
    "application/jwk+json": {
      source: "iana",
      compressible: !0
    },
    "application/jwk-set+json": {
      source: "iana",
      compressible: !0
    },
    "application/jwt": {
      source: "iana"
    },
    "application/kpml-request+xml": {
      source: "iana",
      compressible: !0
    },
    "application/kpml-response+xml": {
      source: "iana",
      compressible: !0
    },
    "application/ld+json": {
      source: "iana",
      compressible: !0,
      extensions: ["jsonld"]
    },
    "application/lgr+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["lgr"]
    },
    "application/link-format": {
      source: "iana"
    },
    "application/load-control+xml": {
      source: "iana",
      compressible: !0
    },
    "application/lost+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["lostxml"]
    },
    "application/lostsync+xml": {
      source: "iana",
      compressible: !0
    },
    "application/lpf+zip": {
      source: "iana",
      compressible: !1
    },
    "application/lxf": {
      source: "iana"
    },
    "application/mac-binhex40": {
      source: "iana",
      extensions: ["hqx"]
    },
    "application/mac-compactpro": {
      source: "apache",
      extensions: ["cpt"]
    },
    "application/macwriteii": {
      source: "iana"
    },
    "application/mads+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mads"]
    },
    "application/manifest+json": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["webmanifest"]
    },
    "application/marc": {
      source: "iana",
      extensions: ["mrc"]
    },
    "application/marcxml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mrcx"]
    },
    "application/mathematica": {
      source: "iana",
      extensions: ["ma", "nb", "mb"]
    },
    "application/mathml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mathml"]
    },
    "application/mathml-content+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mathml-presentation+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-associated-procedure-description+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-deregister+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-envelope+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-msk+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-msk-response+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-protection-description+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-reception-report+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-register+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-register-response+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-schedule+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbms-user-service-description+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mbox": {
      source: "iana",
      extensions: ["mbox"]
    },
    "application/media-policy-dataset+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mpf"]
    },
    "application/media_control+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mediaservercontrol+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mscml"]
    },
    "application/merge-patch+json": {
      source: "iana",
      compressible: !0
    },
    "application/metalink+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["metalink"]
    },
    "application/metalink4+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["meta4"]
    },
    "application/mets+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mets"]
    },
    "application/mf4": {
      source: "iana"
    },
    "application/mikey": {
      source: "iana"
    },
    "application/mipc": {
      source: "iana"
    },
    "application/missing-blocks+cbor-seq": {
      source: "iana"
    },
    "application/mmt-aei+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["maei"]
    },
    "application/mmt-usd+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["musd"]
    },
    "application/mods+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mods"]
    },
    "application/moss-keys": {
      source: "iana"
    },
    "application/moss-signature": {
      source: "iana"
    },
    "application/mosskey-data": {
      source: "iana"
    },
    "application/mosskey-request": {
      source: "iana"
    },
    "application/mp21": {
      source: "iana",
      extensions: ["m21", "mp21"]
    },
    "application/mp4": {
      source: "iana",
      extensions: ["mp4s", "m4p"]
    },
    "application/mpeg4-generic": {
      source: "iana"
    },
    "application/mpeg4-iod": {
      source: "iana"
    },
    "application/mpeg4-iod-xmt": {
      source: "iana"
    },
    "application/mrb-consumer+xml": {
      source: "iana",
      compressible: !0
    },
    "application/mrb-publish+xml": {
      source: "iana",
      compressible: !0
    },
    "application/msc-ivr+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/msc-mixer+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/msword": {
      source: "iana",
      compressible: !1,
      extensions: ["doc", "dot"]
    },
    "application/mud+json": {
      source: "iana",
      compressible: !0
    },
    "application/multipart-core": {
      source: "iana"
    },
    "application/mxf": {
      source: "iana",
      extensions: ["mxf"]
    },
    "application/n-quads": {
      source: "iana",
      extensions: ["nq"]
    },
    "application/n-triples": {
      source: "iana",
      extensions: ["nt"]
    },
    "application/nasdata": {
      source: "iana"
    },
    "application/news-checkgroups": {
      source: "iana",
      charset: "US-ASCII"
    },
    "application/news-groupinfo": {
      source: "iana",
      charset: "US-ASCII"
    },
    "application/news-transmission": {
      source: "iana"
    },
    "application/nlsml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/node": {
      source: "iana",
      extensions: ["cjs"]
    },
    "application/nss": {
      source: "iana"
    },
    "application/oauth-authz-req+jwt": {
      source: "iana"
    },
    "application/oblivious-dns-message": {
      source: "iana"
    },
    "application/ocsp-request": {
      source: "iana"
    },
    "application/ocsp-response": {
      source: "iana"
    },
    "application/octet-stream": {
      source: "iana",
      compressible: !1,
      extensions: ["bin", "dms", "lrf", "mar", "so", "dist", "distz", "pkg", "bpk", "dump", "elc", "deploy", "exe", "dll", "deb", "dmg", "iso", "img", "msi", "msp", "msm", "buffer"]
    },
    "application/oda": {
      source: "iana",
      extensions: ["oda"]
    },
    "application/odm+xml": {
      source: "iana",
      compressible: !0
    },
    "application/odx": {
      source: "iana"
    },
    "application/oebps-package+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["opf"]
    },
    "application/ogg": {
      source: "iana",
      compressible: !1,
      extensions: ["ogx"]
    },
    "application/omdoc+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["omdoc"]
    },
    "application/onenote": {
      source: "apache",
      extensions: ["onetoc", "onetoc2", "onetmp", "onepkg"]
    },
    "application/opc-nodeset+xml": {
      source: "iana",
      compressible: !0
    },
    "application/oscore": {
      source: "iana"
    },
    "application/oxps": {
      source: "iana",
      extensions: ["oxps"]
    },
    "application/p21": {
      source: "iana"
    },
    "application/p21+zip": {
      source: "iana",
      compressible: !1
    },
    "application/p2p-overlay+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["relo"]
    },
    "application/parityfec": {
      source: "iana"
    },
    "application/passport": {
      source: "iana"
    },
    "application/patch-ops-error+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xer"]
    },
    "application/pdf": {
      source: "iana",
      compressible: !1,
      extensions: ["pdf"]
    },
    "application/pdx": {
      source: "iana"
    },
    "application/pem-certificate-chain": {
      source: "iana"
    },
    "application/pgp-encrypted": {
      source: "iana",
      compressible: !1,
      extensions: ["pgp"]
    },
    "application/pgp-keys": {
      source: "iana",
      extensions: ["asc"]
    },
    "application/pgp-signature": {
      source: "iana",
      extensions: ["asc", "sig"]
    },
    "application/pics-rules": {
      source: "apache",
      extensions: ["prf"]
    },
    "application/pidf+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/pidf-diff+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/pkcs10": {
      source: "iana",
      extensions: ["p10"]
    },
    "application/pkcs12": {
      source: "iana"
    },
    "application/pkcs7-mime": {
      source: "iana",
      extensions: ["p7m", "p7c"]
    },
    "application/pkcs7-signature": {
      source: "iana",
      extensions: ["p7s"]
    },
    "application/pkcs8": {
      source: "iana",
      extensions: ["p8"]
    },
    "application/pkcs8-encrypted": {
      source: "iana"
    },
    "application/pkix-attr-cert": {
      source: "iana",
      extensions: ["ac"]
    },
    "application/pkix-cert": {
      source: "iana",
      extensions: ["cer"]
    },
    "application/pkix-crl": {
      source: "iana",
      extensions: ["crl"]
    },
    "application/pkix-pkipath": {
      source: "iana",
      extensions: ["pkipath"]
    },
    "application/pkixcmp": {
      source: "iana",
      extensions: ["pki"]
    },
    "application/pls+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["pls"]
    },
    "application/poc-settings+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/postscript": {
      source: "iana",
      compressible: !0,
      extensions: ["ai", "eps", "ps"]
    },
    "application/ppsp-tracker+json": {
      source: "iana",
      compressible: !0
    },
    "application/problem+json": {
      source: "iana",
      compressible: !0
    },
    "application/problem+xml": {
      source: "iana",
      compressible: !0
    },
    "application/provenance+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["provx"]
    },
    "application/prs.alvestrand.titrax-sheet": {
      source: "iana"
    },
    "application/prs.cww": {
      source: "iana",
      extensions: ["cww"]
    },
    "application/prs.cyn": {
      source: "iana",
      charset: "7-BIT"
    },
    "application/prs.hpub+zip": {
      source: "iana",
      compressible: !1
    },
    "application/prs.nprend": {
      source: "iana"
    },
    "application/prs.plucker": {
      source: "iana"
    },
    "application/prs.rdf-xml-crypt": {
      source: "iana"
    },
    "application/prs.xsf+xml": {
      source: "iana",
      compressible: !0
    },
    "application/pskc+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["pskcxml"]
    },
    "application/pvd+json": {
      source: "iana",
      compressible: !0
    },
    "application/qsig": {
      source: "iana"
    },
    "application/raml+yaml": {
      compressible: !0,
      extensions: ["raml"]
    },
    "application/raptorfec": {
      source: "iana"
    },
    "application/rdap+json": {
      source: "iana",
      compressible: !0
    },
    "application/rdf+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rdf", "owl"]
    },
    "application/reginfo+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rif"]
    },
    "application/relax-ng-compact-syntax": {
      source: "iana",
      extensions: ["rnc"]
    },
    "application/remote-printing": {
      source: "iana"
    },
    "application/reputon+json": {
      source: "iana",
      compressible: !0
    },
    "application/resource-lists+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rl"]
    },
    "application/resource-lists-diff+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rld"]
    },
    "application/rfc+xml": {
      source: "iana",
      compressible: !0
    },
    "application/riscos": {
      source: "iana"
    },
    "application/rlmi+xml": {
      source: "iana",
      compressible: !0
    },
    "application/rls-services+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rs"]
    },
    "application/route-apd+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rapd"]
    },
    "application/route-s-tsid+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["sls"]
    },
    "application/route-usd+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rusd"]
    },
    "application/rpki-ghostbusters": {
      source: "iana",
      extensions: ["gbr"]
    },
    "application/rpki-manifest": {
      source: "iana",
      extensions: ["mft"]
    },
    "application/rpki-publication": {
      source: "iana"
    },
    "application/rpki-roa": {
      source: "iana",
      extensions: ["roa"]
    },
    "application/rpki-updown": {
      source: "iana"
    },
    "application/rsd+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["rsd"]
    },
    "application/rss+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["rss"]
    },
    "application/rtf": {
      source: "iana",
      compressible: !0,
      extensions: ["rtf"]
    },
    "application/rtploopback": {
      source: "iana"
    },
    "application/rtx": {
      source: "iana"
    },
    "application/samlassertion+xml": {
      source: "iana",
      compressible: !0
    },
    "application/samlmetadata+xml": {
      source: "iana",
      compressible: !0
    },
    "application/sarif+json": {
      source: "iana",
      compressible: !0
    },
    "application/sarif-external-properties+json": {
      source: "iana",
      compressible: !0
    },
    "application/sbe": {
      source: "iana"
    },
    "application/sbml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["sbml"]
    },
    "application/scaip+xml": {
      source: "iana",
      compressible: !0
    },
    "application/scim+json": {
      source: "iana",
      compressible: !0
    },
    "application/scvp-cv-request": {
      source: "iana",
      extensions: ["scq"]
    },
    "application/scvp-cv-response": {
      source: "iana",
      extensions: ["scs"]
    },
    "application/scvp-vp-request": {
      source: "iana",
      extensions: ["spq"]
    },
    "application/scvp-vp-response": {
      source: "iana",
      extensions: ["spp"]
    },
    "application/sdp": {
      source: "iana",
      extensions: ["sdp"]
    },
    "application/secevent+jwt": {
      source: "iana"
    },
    "application/senml+cbor": {
      source: "iana"
    },
    "application/senml+json": {
      source: "iana",
      compressible: !0
    },
    "application/senml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["senmlx"]
    },
    "application/senml-etch+cbor": {
      source: "iana"
    },
    "application/senml-etch+json": {
      source: "iana",
      compressible: !0
    },
    "application/senml-exi": {
      source: "iana"
    },
    "application/sensml+cbor": {
      source: "iana"
    },
    "application/sensml+json": {
      source: "iana",
      compressible: !0
    },
    "application/sensml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["sensmlx"]
    },
    "application/sensml-exi": {
      source: "iana"
    },
    "application/sep+xml": {
      source: "iana",
      compressible: !0
    },
    "application/sep-exi": {
      source: "iana"
    },
    "application/session-info": {
      source: "iana"
    },
    "application/set-payment": {
      source: "iana"
    },
    "application/set-payment-initiation": {
      source: "iana",
      extensions: ["setpay"]
    },
    "application/set-registration": {
      source: "iana"
    },
    "application/set-registration-initiation": {
      source: "iana",
      extensions: ["setreg"]
    },
    "application/sgml": {
      source: "iana"
    },
    "application/sgml-open-catalog": {
      source: "iana"
    },
    "application/shf+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["shf"]
    },
    "application/sieve": {
      source: "iana",
      extensions: ["siv", "sieve"]
    },
    "application/simple-filter+xml": {
      source: "iana",
      compressible: !0
    },
    "application/simple-message-summary": {
      source: "iana"
    },
    "application/simplesymbolcontainer": {
      source: "iana"
    },
    "application/sipc": {
      source: "iana"
    },
    "application/slate": {
      source: "iana"
    },
    "application/smil": {
      source: "iana"
    },
    "application/smil+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["smi", "smil"]
    },
    "application/smpte336m": {
      source: "iana"
    },
    "application/soap+fastinfoset": {
      source: "iana"
    },
    "application/soap+xml": {
      source: "iana",
      compressible: !0
    },
    "application/sparql-query": {
      source: "iana",
      extensions: ["rq"]
    },
    "application/sparql-results+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["srx"]
    },
    "application/spdx+json": {
      source: "iana",
      compressible: !0
    },
    "application/spirits-event+xml": {
      source: "iana",
      compressible: !0
    },
    "application/sql": {
      source: "iana"
    },
    "application/srgs": {
      source: "iana",
      extensions: ["gram"]
    },
    "application/srgs+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["grxml"]
    },
    "application/sru+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["sru"]
    },
    "application/ssdl+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["ssdl"]
    },
    "application/ssml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["ssml"]
    },
    "application/stix+json": {
      source: "iana",
      compressible: !0
    },
    "application/swid+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["swidtag"]
    },
    "application/tamp-apex-update": {
      source: "iana"
    },
    "application/tamp-apex-update-confirm": {
      source: "iana"
    },
    "application/tamp-community-update": {
      source: "iana"
    },
    "application/tamp-community-update-confirm": {
      source: "iana"
    },
    "application/tamp-error": {
      source: "iana"
    },
    "application/tamp-sequence-adjust": {
      source: "iana"
    },
    "application/tamp-sequence-adjust-confirm": {
      source: "iana"
    },
    "application/tamp-status-query": {
      source: "iana"
    },
    "application/tamp-status-response": {
      source: "iana"
    },
    "application/tamp-update": {
      source: "iana"
    },
    "application/tamp-update-confirm": {
      source: "iana"
    },
    "application/tar": {
      compressible: !0
    },
    "application/taxii+json": {
      source: "iana",
      compressible: !0
    },
    "application/td+json": {
      source: "iana",
      compressible: !0
    },
    "application/tei+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["tei", "teicorpus"]
    },
    "application/tetra_isi": {
      source: "iana"
    },
    "application/thraud+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["tfi"]
    },
    "application/timestamp-query": {
      source: "iana"
    },
    "application/timestamp-reply": {
      source: "iana"
    },
    "application/timestamped-data": {
      source: "iana",
      extensions: ["tsd"]
    },
    "application/tlsrpt+gzip": {
      source: "iana"
    },
    "application/tlsrpt+json": {
      source: "iana",
      compressible: !0
    },
    "application/tnauthlist": {
      source: "iana"
    },
    "application/token-introspection+jwt": {
      source: "iana"
    },
    "application/toml": {
      compressible: !0,
      extensions: ["toml"]
    },
    "application/trickle-ice-sdpfrag": {
      source: "iana"
    },
    "application/trig": {
      source: "iana",
      extensions: ["trig"]
    },
    "application/ttml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["ttml"]
    },
    "application/tve-trigger": {
      source: "iana"
    },
    "application/tzif": {
      source: "iana"
    },
    "application/tzif-leap": {
      source: "iana"
    },
    "application/ubjson": {
      compressible: !1,
      extensions: ["ubj"]
    },
    "application/ulpfec": {
      source: "iana"
    },
    "application/urc-grpsheet+xml": {
      source: "iana",
      compressible: !0
    },
    "application/urc-ressheet+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["rsheet"]
    },
    "application/urc-targetdesc+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["td"]
    },
    "application/urc-uisocketdesc+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vcard+json": {
      source: "iana",
      compressible: !0
    },
    "application/vcard+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vemmi": {
      source: "iana"
    },
    "application/vividence.scriptfile": {
      source: "apache"
    },
    "application/vnd.1000minds.decision-model+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["1km"]
    },
    "application/vnd.3gpp-prose+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp-prose-pc3ch+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp-v2x-local-service-information": {
      source: "iana"
    },
    "application/vnd.3gpp.5gnas": {
      source: "iana"
    },
    "application/vnd.3gpp.access-transfer-events+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.bsf+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.gmop+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.gtpc": {
      source: "iana"
    },
    "application/vnd.3gpp.interworking-data": {
      source: "iana"
    },
    "application/vnd.3gpp.lpp": {
      source: "iana"
    },
    "application/vnd.3gpp.mc-signalling-ear": {
      source: "iana"
    },
    "application/vnd.3gpp.mcdata-affiliation-command+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcdata-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcdata-payload": {
      source: "iana"
    },
    "application/vnd.3gpp.mcdata-service-config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcdata-signalling": {
      source: "iana"
    },
    "application/vnd.3gpp.mcdata-ue-config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcdata-user-profile+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-affiliation-command+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-floor-request+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-location-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-mbms-usage-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-service-config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-signed+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-ue-config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-ue-init-config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcptt-user-profile+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-affiliation-command+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-affiliation-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-location-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-mbms-usage-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-service-config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-transmission-request+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-ue-config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mcvideo-user-profile+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.mid-call+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.ngap": {
      source: "iana"
    },
    "application/vnd.3gpp.pfcp": {
      source: "iana"
    },
    "application/vnd.3gpp.pic-bw-large": {
      source: "iana",
      extensions: ["plb"]
    },
    "application/vnd.3gpp.pic-bw-small": {
      source: "iana",
      extensions: ["psb"]
    },
    "application/vnd.3gpp.pic-bw-var": {
      source: "iana",
      extensions: ["pvb"]
    },
    "application/vnd.3gpp.s1ap": {
      source: "iana"
    },
    "application/vnd.3gpp.sms": {
      source: "iana"
    },
    "application/vnd.3gpp.sms+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.srvcc-ext+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.srvcc-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.state-and-event-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp.ussd+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp2.bcmcsinfo+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.3gpp2.sms": {
      source: "iana"
    },
    "application/vnd.3gpp2.tcap": {
      source: "iana",
      extensions: ["tcap"]
    },
    "application/vnd.3lightssoftware.imagescal": {
      source: "iana"
    },
    "application/vnd.3m.post-it-notes": {
      source: "iana",
      extensions: ["pwn"]
    },
    "application/vnd.accpac.simply.aso": {
      source: "iana",
      extensions: ["aso"]
    },
    "application/vnd.accpac.simply.imp": {
      source: "iana",
      extensions: ["imp"]
    },
    "application/vnd.acucobol": {
      source: "iana",
      extensions: ["acu"]
    },
    "application/vnd.acucorp": {
      source: "iana",
      extensions: ["atc", "acutc"]
    },
    "application/vnd.adobe.air-application-installer-package+zip": {
      source: "apache",
      compressible: !1,
      extensions: ["air"]
    },
    "application/vnd.adobe.flash.movie": {
      source: "iana"
    },
    "application/vnd.adobe.formscentral.fcdt": {
      source: "iana",
      extensions: ["fcdt"]
    },
    "application/vnd.adobe.fxp": {
      source: "iana",
      extensions: ["fxp", "fxpl"]
    },
    "application/vnd.adobe.partial-upload": {
      source: "iana"
    },
    "application/vnd.adobe.xdp+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xdp"]
    },
    "application/vnd.adobe.xfdf": {
      source: "iana",
      extensions: ["xfdf"]
    },
    "application/vnd.aether.imp": {
      source: "iana"
    },
    "application/vnd.afpc.afplinedata": {
      source: "iana"
    },
    "application/vnd.afpc.afplinedata-pagedef": {
      source: "iana"
    },
    "application/vnd.afpc.cmoca-cmresource": {
      source: "iana"
    },
    "application/vnd.afpc.foca-charset": {
      source: "iana"
    },
    "application/vnd.afpc.foca-codedfont": {
      source: "iana"
    },
    "application/vnd.afpc.foca-codepage": {
      source: "iana"
    },
    "application/vnd.afpc.modca": {
      source: "iana"
    },
    "application/vnd.afpc.modca-cmtable": {
      source: "iana"
    },
    "application/vnd.afpc.modca-formdef": {
      source: "iana"
    },
    "application/vnd.afpc.modca-mediummap": {
      source: "iana"
    },
    "application/vnd.afpc.modca-objectcontainer": {
      source: "iana"
    },
    "application/vnd.afpc.modca-overlay": {
      source: "iana"
    },
    "application/vnd.afpc.modca-pagesegment": {
      source: "iana"
    },
    "application/vnd.age": {
      source: "iana",
      extensions: ["age"]
    },
    "application/vnd.ah-barcode": {
      source: "iana"
    },
    "application/vnd.ahead.space": {
      source: "iana",
      extensions: ["ahead"]
    },
    "application/vnd.airzip.filesecure.azf": {
      source: "iana",
      extensions: ["azf"]
    },
    "application/vnd.airzip.filesecure.azs": {
      source: "iana",
      extensions: ["azs"]
    },
    "application/vnd.amadeus+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.amazon.ebook": {
      source: "apache",
      extensions: ["azw"]
    },
    "application/vnd.amazon.mobi8-ebook": {
      source: "iana"
    },
    "application/vnd.americandynamics.acc": {
      source: "iana",
      extensions: ["acc"]
    },
    "application/vnd.amiga.ami": {
      source: "iana",
      extensions: ["ami"]
    },
    "application/vnd.amundsen.maze+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.android.ota": {
      source: "iana"
    },
    "application/vnd.android.package-archive": {
      source: "apache",
      compressible: !1,
      extensions: ["apk"]
    },
    "application/vnd.anki": {
      source: "iana"
    },
    "application/vnd.anser-web-certificate-issue-initiation": {
      source: "iana",
      extensions: ["cii"]
    },
    "application/vnd.anser-web-funds-transfer-initiation": {
      source: "apache",
      extensions: ["fti"]
    },
    "application/vnd.antix.game-component": {
      source: "iana",
      extensions: ["atx"]
    },
    "application/vnd.apache.arrow.file": {
      source: "iana"
    },
    "application/vnd.apache.arrow.stream": {
      source: "iana"
    },
    "application/vnd.apache.thrift.binary": {
      source: "iana"
    },
    "application/vnd.apache.thrift.compact": {
      source: "iana"
    },
    "application/vnd.apache.thrift.json": {
      source: "iana"
    },
    "application/vnd.api+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.aplextor.warrp+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.apothekende.reservation+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.apple.installer+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mpkg"]
    },
    "application/vnd.apple.keynote": {
      source: "iana",
      extensions: ["key"]
    },
    "application/vnd.apple.mpegurl": {
      source: "iana",
      extensions: ["m3u8"]
    },
    "application/vnd.apple.numbers": {
      source: "iana",
      extensions: ["numbers"]
    },
    "application/vnd.apple.pages": {
      source: "iana",
      extensions: ["pages"]
    },
    "application/vnd.apple.pkpass": {
      compressible: !1,
      extensions: ["pkpass"]
    },
    "application/vnd.arastra.swi": {
      source: "iana"
    },
    "application/vnd.aristanetworks.swi": {
      source: "iana",
      extensions: ["swi"]
    },
    "application/vnd.artisan+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.artsquare": {
      source: "iana"
    },
    "application/vnd.astraea-software.iota": {
      source: "iana",
      extensions: ["iota"]
    },
    "application/vnd.audiograph": {
      source: "iana",
      extensions: ["aep"]
    },
    "application/vnd.autopackage": {
      source: "iana"
    },
    "application/vnd.avalon+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.avistar+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.balsamiq.bmml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["bmml"]
    },
    "application/vnd.balsamiq.bmpr": {
      source: "iana"
    },
    "application/vnd.banana-accounting": {
      source: "iana"
    },
    "application/vnd.bbf.usp.error": {
      source: "iana"
    },
    "application/vnd.bbf.usp.msg": {
      source: "iana"
    },
    "application/vnd.bbf.usp.msg+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.bekitzur-stech+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.bint.med-content": {
      source: "iana"
    },
    "application/vnd.biopax.rdf+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.blink-idb-value-wrapper": {
      source: "iana"
    },
    "application/vnd.blueice.multipass": {
      source: "iana",
      extensions: ["mpm"]
    },
    "application/vnd.bluetooth.ep.oob": {
      source: "iana"
    },
    "application/vnd.bluetooth.le.oob": {
      source: "iana"
    },
    "application/vnd.bmi": {
      source: "iana",
      extensions: ["bmi"]
    },
    "application/vnd.bpf": {
      source: "iana"
    },
    "application/vnd.bpf3": {
      source: "iana"
    },
    "application/vnd.businessobjects": {
      source: "iana",
      extensions: ["rep"]
    },
    "application/vnd.byu.uapi+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.cab-jscript": {
      source: "iana"
    },
    "application/vnd.canon-cpdl": {
      source: "iana"
    },
    "application/vnd.canon-lips": {
      source: "iana"
    },
    "application/vnd.capasystems-pg+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.cendio.thinlinc.clientconf": {
      source: "iana"
    },
    "application/vnd.century-systems.tcp_stream": {
      source: "iana"
    },
    "application/vnd.chemdraw+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["cdxml"]
    },
    "application/vnd.chess-pgn": {
      source: "iana"
    },
    "application/vnd.chipnuts.karaoke-mmd": {
      source: "iana",
      extensions: ["mmd"]
    },
    "application/vnd.ciedi": {
      source: "iana"
    },
    "application/vnd.cinderella": {
      source: "iana",
      extensions: ["cdy"]
    },
    "application/vnd.cirpack.isdn-ext": {
      source: "iana"
    },
    "application/vnd.citationstyles.style+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["csl"]
    },
    "application/vnd.claymore": {
      source: "iana",
      extensions: ["cla"]
    },
    "application/vnd.cloanto.rp9": {
      source: "iana",
      extensions: ["rp9"]
    },
    "application/vnd.clonk.c4group": {
      source: "iana",
      extensions: ["c4g", "c4d", "c4f", "c4p", "c4u"]
    },
    "application/vnd.cluetrust.cartomobile-config": {
      source: "iana",
      extensions: ["c11amc"]
    },
    "application/vnd.cluetrust.cartomobile-config-pkg": {
      source: "iana",
      extensions: ["c11amz"]
    },
    "application/vnd.coffeescript": {
      source: "iana"
    },
    "application/vnd.collabio.xodocuments.document": {
      source: "iana"
    },
    "application/vnd.collabio.xodocuments.document-template": {
      source: "iana"
    },
    "application/vnd.collabio.xodocuments.presentation": {
      source: "iana"
    },
    "application/vnd.collabio.xodocuments.presentation-template": {
      source: "iana"
    },
    "application/vnd.collabio.xodocuments.spreadsheet": {
      source: "iana"
    },
    "application/vnd.collabio.xodocuments.spreadsheet-template": {
      source: "iana"
    },
    "application/vnd.collection+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.collection.doc+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.collection.next+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.comicbook+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.comicbook-rar": {
      source: "iana"
    },
    "application/vnd.commerce-battelle": {
      source: "iana"
    },
    "application/vnd.commonspace": {
      source: "iana",
      extensions: ["csp"]
    },
    "application/vnd.contact.cmsg": {
      source: "iana",
      extensions: ["cdbcmsg"]
    },
    "application/vnd.coreos.ignition+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.cosmocaller": {
      source: "iana",
      extensions: ["cmc"]
    },
    "application/vnd.crick.clicker": {
      source: "iana",
      extensions: ["clkx"]
    },
    "application/vnd.crick.clicker.keyboard": {
      source: "iana",
      extensions: ["clkk"]
    },
    "application/vnd.crick.clicker.palette": {
      source: "iana",
      extensions: ["clkp"]
    },
    "application/vnd.crick.clicker.template": {
      source: "iana",
      extensions: ["clkt"]
    },
    "application/vnd.crick.clicker.wordbank": {
      source: "iana",
      extensions: ["clkw"]
    },
    "application/vnd.criticaltools.wbs+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["wbs"]
    },
    "application/vnd.cryptii.pipe+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.crypto-shade-file": {
      source: "iana"
    },
    "application/vnd.cryptomator.encrypted": {
      source: "iana"
    },
    "application/vnd.cryptomator.vault": {
      source: "iana"
    },
    "application/vnd.ctc-posml": {
      source: "iana",
      extensions: ["pml"]
    },
    "application/vnd.ctct.ws+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.cups-pdf": {
      source: "iana"
    },
    "application/vnd.cups-postscript": {
      source: "iana"
    },
    "application/vnd.cups-ppd": {
      source: "iana",
      extensions: ["ppd"]
    },
    "application/vnd.cups-raster": {
      source: "iana"
    },
    "application/vnd.cups-raw": {
      source: "iana"
    },
    "application/vnd.curl": {
      source: "iana"
    },
    "application/vnd.curl.car": {
      source: "apache",
      extensions: ["car"]
    },
    "application/vnd.curl.pcurl": {
      source: "apache",
      extensions: ["pcurl"]
    },
    "application/vnd.cyan.dean.root+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.cybank": {
      source: "iana"
    },
    "application/vnd.cyclonedx+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.cyclonedx+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.d2l.coursepackage1p0+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.d3m-dataset": {
      source: "iana"
    },
    "application/vnd.d3m-problem": {
      source: "iana"
    },
    "application/vnd.dart": {
      source: "iana",
      compressible: !0,
      extensions: ["dart"]
    },
    "application/vnd.data-vision.rdz": {
      source: "iana",
      extensions: ["rdz"]
    },
    "application/vnd.datapackage+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dataresource+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dbf": {
      source: "iana",
      extensions: ["dbf"]
    },
    "application/vnd.debian.binary-package": {
      source: "iana"
    },
    "application/vnd.dece.data": {
      source: "iana",
      extensions: ["uvf", "uvvf", "uvd", "uvvd"]
    },
    "application/vnd.dece.ttml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["uvt", "uvvt"]
    },
    "application/vnd.dece.unspecified": {
      source: "iana",
      extensions: ["uvx", "uvvx"]
    },
    "application/vnd.dece.zip": {
      source: "iana",
      extensions: ["uvz", "uvvz"]
    },
    "application/vnd.denovo.fcselayout-link": {
      source: "iana",
      extensions: ["fe_launch"]
    },
    "application/vnd.desmume.movie": {
      source: "iana"
    },
    "application/vnd.dir-bi.plate-dl-nosuffix": {
      source: "iana"
    },
    "application/vnd.dm.delegation+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dna": {
      source: "iana",
      extensions: ["dna"]
    },
    "application/vnd.document+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dolby.mlp": {
      source: "apache",
      extensions: ["mlp"]
    },
    "application/vnd.dolby.mobile.1": {
      source: "iana"
    },
    "application/vnd.dolby.mobile.2": {
      source: "iana"
    },
    "application/vnd.doremir.scorecloud-binary-document": {
      source: "iana"
    },
    "application/vnd.dpgraph": {
      source: "iana",
      extensions: ["dpg"]
    },
    "application/vnd.dreamfactory": {
      source: "iana",
      extensions: ["dfac"]
    },
    "application/vnd.drive+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ds-keypoint": {
      source: "apache",
      extensions: ["kpxx"]
    },
    "application/vnd.dtg.local": {
      source: "iana"
    },
    "application/vnd.dtg.local.flash": {
      source: "iana"
    },
    "application/vnd.dtg.local.html": {
      source: "iana"
    },
    "application/vnd.dvb.ait": {
      source: "iana",
      extensions: ["ait"]
    },
    "application/vnd.dvb.dvbisl+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.dvbj": {
      source: "iana"
    },
    "application/vnd.dvb.esgcontainer": {
      source: "iana"
    },
    "application/vnd.dvb.ipdcdftnotifaccess": {
      source: "iana"
    },
    "application/vnd.dvb.ipdcesgaccess": {
      source: "iana"
    },
    "application/vnd.dvb.ipdcesgaccess2": {
      source: "iana"
    },
    "application/vnd.dvb.ipdcesgpdd": {
      source: "iana"
    },
    "application/vnd.dvb.ipdcroaming": {
      source: "iana"
    },
    "application/vnd.dvb.iptv.alfec-base": {
      source: "iana"
    },
    "application/vnd.dvb.iptv.alfec-enhancement": {
      source: "iana"
    },
    "application/vnd.dvb.notif-aggregate-root+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.notif-container+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.notif-generic+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.notif-ia-msglist+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.notif-ia-registration-request+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.notif-ia-registration-response+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.notif-init+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.dvb.pfr": {
      source: "iana"
    },
    "application/vnd.dvb.service": {
      source: "iana",
      extensions: ["svc"]
    },
    "application/vnd.dxr": {
      source: "iana"
    },
    "application/vnd.dynageo": {
      source: "iana",
      extensions: ["geo"]
    },
    "application/vnd.dzr": {
      source: "iana"
    },
    "application/vnd.easykaraoke.cdgdownload": {
      source: "iana"
    },
    "application/vnd.ecdis-update": {
      source: "iana"
    },
    "application/vnd.ecip.rlp": {
      source: "iana"
    },
    "application/vnd.eclipse.ditto+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ecowin.chart": {
      source: "iana",
      extensions: ["mag"]
    },
    "application/vnd.ecowin.filerequest": {
      source: "iana"
    },
    "application/vnd.ecowin.fileupdate": {
      source: "iana"
    },
    "application/vnd.ecowin.series": {
      source: "iana"
    },
    "application/vnd.ecowin.seriesrequest": {
      source: "iana"
    },
    "application/vnd.ecowin.seriesupdate": {
      source: "iana"
    },
    "application/vnd.efi.img": {
      source: "iana"
    },
    "application/vnd.efi.iso": {
      source: "iana"
    },
    "application/vnd.emclient.accessrequest+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.enliven": {
      source: "iana",
      extensions: ["nml"]
    },
    "application/vnd.enphase.envoy": {
      source: "iana"
    },
    "application/vnd.eprints.data+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.epson.esf": {
      source: "iana",
      extensions: ["esf"]
    },
    "application/vnd.epson.msf": {
      source: "iana",
      extensions: ["msf"]
    },
    "application/vnd.epson.quickanime": {
      source: "iana",
      extensions: ["qam"]
    },
    "application/vnd.epson.salt": {
      source: "iana",
      extensions: ["slt"]
    },
    "application/vnd.epson.ssf": {
      source: "iana",
      extensions: ["ssf"]
    },
    "application/vnd.ericsson.quickcall": {
      source: "iana"
    },
    "application/vnd.espass-espass+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.eszigno3+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["es3", "et3"]
    },
    "application/vnd.etsi.aoc+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.asic-e+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.etsi.asic-s+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.etsi.cug+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvcommand+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvdiscovery+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvprofile+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvsad-bc+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvsad-cod+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvsad-npvr+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvservice+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvsync+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.iptvueprofile+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.mcid+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.mheg5": {
      source: "iana"
    },
    "application/vnd.etsi.overload-control-policy-dataset+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.pstn+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.sci+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.simservs+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.timestamp-token": {
      source: "iana"
    },
    "application/vnd.etsi.tsl+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.etsi.tsl.der": {
      source: "iana"
    },
    "application/vnd.eu.kasparian.car+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.eudora.data": {
      source: "iana"
    },
    "application/vnd.evolv.ecig.profile": {
      source: "iana"
    },
    "application/vnd.evolv.ecig.settings": {
      source: "iana"
    },
    "application/vnd.evolv.ecig.theme": {
      source: "iana"
    },
    "application/vnd.exstream-empower+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.exstream-package": {
      source: "iana"
    },
    "application/vnd.ezpix-album": {
      source: "iana",
      extensions: ["ez2"]
    },
    "application/vnd.ezpix-package": {
      source: "iana",
      extensions: ["ez3"]
    },
    "application/vnd.f-secure.mobile": {
      source: "iana"
    },
    "application/vnd.familysearch.gedcom+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.fastcopy-disk-image": {
      source: "iana"
    },
    "application/vnd.fdf": {
      source: "iana",
      extensions: ["fdf"]
    },
    "application/vnd.fdsn.mseed": {
      source: "iana",
      extensions: ["mseed"]
    },
    "application/vnd.fdsn.seed": {
      source: "iana",
      extensions: ["seed", "dataless"]
    },
    "application/vnd.ffsns": {
      source: "iana"
    },
    "application/vnd.ficlab.flb+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.filmit.zfc": {
      source: "iana"
    },
    "application/vnd.fints": {
      source: "iana"
    },
    "application/vnd.firemonkeys.cloudcell": {
      source: "iana"
    },
    "application/vnd.flographit": {
      source: "iana",
      extensions: ["gph"]
    },
    "application/vnd.fluxtime.clip": {
      source: "iana",
      extensions: ["ftc"]
    },
    "application/vnd.font-fontforge-sfd": {
      source: "iana"
    },
    "application/vnd.framemaker": {
      source: "iana",
      extensions: ["fm", "frame", "maker", "book"]
    },
    "application/vnd.frogans.fnc": {
      source: "iana",
      extensions: ["fnc"]
    },
    "application/vnd.frogans.ltf": {
      source: "iana",
      extensions: ["ltf"]
    },
    "application/vnd.fsc.weblaunch": {
      source: "iana",
      extensions: ["fsc"]
    },
    "application/vnd.fujifilm.fb.docuworks": {
      source: "iana"
    },
    "application/vnd.fujifilm.fb.docuworks.binder": {
      source: "iana"
    },
    "application/vnd.fujifilm.fb.docuworks.container": {
      source: "iana"
    },
    "application/vnd.fujifilm.fb.jfi+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.fujitsu.oasys": {
      source: "iana",
      extensions: ["oas"]
    },
    "application/vnd.fujitsu.oasys2": {
      source: "iana",
      extensions: ["oa2"]
    },
    "application/vnd.fujitsu.oasys3": {
      source: "iana",
      extensions: ["oa3"]
    },
    "application/vnd.fujitsu.oasysgp": {
      source: "iana",
      extensions: ["fg5"]
    },
    "application/vnd.fujitsu.oasysprs": {
      source: "iana",
      extensions: ["bh2"]
    },
    "application/vnd.fujixerox.art-ex": {
      source: "iana"
    },
    "application/vnd.fujixerox.art4": {
      source: "iana"
    },
    "application/vnd.fujixerox.ddd": {
      source: "iana",
      extensions: ["ddd"]
    },
    "application/vnd.fujixerox.docuworks": {
      source: "iana",
      extensions: ["xdw"]
    },
    "application/vnd.fujixerox.docuworks.binder": {
      source: "iana",
      extensions: ["xbd"]
    },
    "application/vnd.fujixerox.docuworks.container": {
      source: "iana"
    },
    "application/vnd.fujixerox.hbpl": {
      source: "iana"
    },
    "application/vnd.fut-misnet": {
      source: "iana"
    },
    "application/vnd.futoin+cbor": {
      source: "iana"
    },
    "application/vnd.futoin+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.fuzzysheet": {
      source: "iana",
      extensions: ["fzs"]
    },
    "application/vnd.genomatix.tuxedo": {
      source: "iana",
      extensions: ["txd"]
    },
    "application/vnd.gentics.grd+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.geo+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.geocube+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.geogebra.file": {
      source: "iana",
      extensions: ["ggb"]
    },
    "application/vnd.geogebra.slides": {
      source: "iana"
    },
    "application/vnd.geogebra.tool": {
      source: "iana",
      extensions: ["ggt"]
    },
    "application/vnd.geometry-explorer": {
      source: "iana",
      extensions: ["gex", "gre"]
    },
    "application/vnd.geonext": {
      source: "iana",
      extensions: ["gxt"]
    },
    "application/vnd.geoplan": {
      source: "iana",
      extensions: ["g2w"]
    },
    "application/vnd.geospace": {
      source: "iana",
      extensions: ["g3w"]
    },
    "application/vnd.gerber": {
      source: "iana"
    },
    "application/vnd.globalplatform.card-content-mgt": {
      source: "iana"
    },
    "application/vnd.globalplatform.card-content-mgt-response": {
      source: "iana"
    },
    "application/vnd.gmx": {
      source: "iana",
      extensions: ["gmx"]
    },
    "application/vnd.google-apps.document": {
      compressible: !1,
      extensions: ["gdoc"]
    },
    "application/vnd.google-apps.presentation": {
      compressible: !1,
      extensions: ["gslides"]
    },
    "application/vnd.google-apps.spreadsheet": {
      compressible: !1,
      extensions: ["gsheet"]
    },
    "application/vnd.google-earth.kml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["kml"]
    },
    "application/vnd.google-earth.kmz": {
      source: "iana",
      compressible: !1,
      extensions: ["kmz"]
    },
    "application/vnd.gov.sk.e-form+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.gov.sk.e-form+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.gov.sk.xmldatacontainer+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.grafeq": {
      source: "iana",
      extensions: ["gqf", "gqs"]
    },
    "application/vnd.gridmp": {
      source: "iana"
    },
    "application/vnd.groove-account": {
      source: "iana",
      extensions: ["gac"]
    },
    "application/vnd.groove-help": {
      source: "iana",
      extensions: ["ghf"]
    },
    "application/vnd.groove-identity-message": {
      source: "iana",
      extensions: ["gim"]
    },
    "application/vnd.groove-injector": {
      source: "iana",
      extensions: ["grv"]
    },
    "application/vnd.groove-tool-message": {
      source: "iana",
      extensions: ["gtm"]
    },
    "application/vnd.groove-tool-template": {
      source: "iana",
      extensions: ["tpl"]
    },
    "application/vnd.groove-vcard": {
      source: "iana",
      extensions: ["vcg"]
    },
    "application/vnd.hal+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.hal+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["hal"]
    },
    "application/vnd.handheld-entertainment+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["zmm"]
    },
    "application/vnd.hbci": {
      source: "iana",
      extensions: ["hbci"]
    },
    "application/vnd.hc+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.hcl-bireports": {
      source: "iana"
    },
    "application/vnd.hdt": {
      source: "iana"
    },
    "application/vnd.heroku+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.hhe.lesson-player": {
      source: "iana",
      extensions: ["les"]
    },
    "application/vnd.hl7cda+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/vnd.hl7v2+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/vnd.hp-hpgl": {
      source: "iana",
      extensions: ["hpgl"]
    },
    "application/vnd.hp-hpid": {
      source: "iana",
      extensions: ["hpid"]
    },
    "application/vnd.hp-hps": {
      source: "iana",
      extensions: ["hps"]
    },
    "application/vnd.hp-jlyt": {
      source: "iana",
      extensions: ["jlt"]
    },
    "application/vnd.hp-pcl": {
      source: "iana",
      extensions: ["pcl"]
    },
    "application/vnd.hp-pclxl": {
      source: "iana",
      extensions: ["pclxl"]
    },
    "application/vnd.httphone": {
      source: "iana"
    },
    "application/vnd.hydrostatix.sof-data": {
      source: "iana",
      extensions: ["sfd-hdstx"]
    },
    "application/vnd.hyper+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.hyper-item+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.hyperdrive+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.hzn-3d-crossword": {
      source: "iana"
    },
    "application/vnd.ibm.afplinedata": {
      source: "iana"
    },
    "application/vnd.ibm.electronic-media": {
      source: "iana"
    },
    "application/vnd.ibm.minipay": {
      source: "iana",
      extensions: ["mpy"]
    },
    "application/vnd.ibm.modcap": {
      source: "iana",
      extensions: ["afp", "listafp", "list3820"]
    },
    "application/vnd.ibm.rights-management": {
      source: "iana",
      extensions: ["irm"]
    },
    "application/vnd.ibm.secure-container": {
      source: "iana",
      extensions: ["sc"]
    },
    "application/vnd.iccprofile": {
      source: "iana",
      extensions: ["icc", "icm"]
    },
    "application/vnd.ieee.1905": {
      source: "iana"
    },
    "application/vnd.igloader": {
      source: "iana",
      extensions: ["igl"]
    },
    "application/vnd.imagemeter.folder+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.imagemeter.image+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.immervision-ivp": {
      source: "iana",
      extensions: ["ivp"]
    },
    "application/vnd.immervision-ivu": {
      source: "iana",
      extensions: ["ivu"]
    },
    "application/vnd.ims.imsccv1p1": {
      source: "iana"
    },
    "application/vnd.ims.imsccv1p2": {
      source: "iana"
    },
    "application/vnd.ims.imsccv1p3": {
      source: "iana"
    },
    "application/vnd.ims.lis.v2.result+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ims.lti.v2.toolconsumerprofile+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ims.lti.v2.toolproxy+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ims.lti.v2.toolproxy.id+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ims.lti.v2.toolsettings+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ims.lti.v2.toolsettings.simple+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.informedcontrol.rms+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.informix-visionary": {
      source: "iana"
    },
    "application/vnd.infotech.project": {
      source: "iana"
    },
    "application/vnd.infotech.project+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.innopath.wamp.notification": {
      source: "iana"
    },
    "application/vnd.insors.igm": {
      source: "iana",
      extensions: ["igm"]
    },
    "application/vnd.intercon.formnet": {
      source: "iana",
      extensions: ["xpw", "xpx"]
    },
    "application/vnd.intergeo": {
      source: "iana",
      extensions: ["i2g"]
    },
    "application/vnd.intertrust.digibox": {
      source: "iana"
    },
    "application/vnd.intertrust.nncp": {
      source: "iana"
    },
    "application/vnd.intu.qbo": {
      source: "iana",
      extensions: ["qbo"]
    },
    "application/vnd.intu.qfx": {
      source: "iana",
      extensions: ["qfx"]
    },
    "application/vnd.iptc.g2.catalogitem+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.iptc.g2.conceptitem+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.iptc.g2.knowledgeitem+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.iptc.g2.newsitem+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.iptc.g2.newsmessage+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.iptc.g2.packageitem+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.iptc.g2.planningitem+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ipunplugged.rcprofile": {
      source: "iana",
      extensions: ["rcprofile"]
    },
    "application/vnd.irepository.package+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["irp"]
    },
    "application/vnd.is-xpr": {
      source: "iana",
      extensions: ["xpr"]
    },
    "application/vnd.isac.fcs": {
      source: "iana",
      extensions: ["fcs"]
    },
    "application/vnd.iso11783-10+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.jam": {
      source: "iana",
      extensions: ["jam"]
    },
    "application/vnd.japannet-directory-service": {
      source: "iana"
    },
    "application/vnd.japannet-jpnstore-wakeup": {
      source: "iana"
    },
    "application/vnd.japannet-payment-wakeup": {
      source: "iana"
    },
    "application/vnd.japannet-registration": {
      source: "iana"
    },
    "application/vnd.japannet-registration-wakeup": {
      source: "iana"
    },
    "application/vnd.japannet-setstore-wakeup": {
      source: "iana"
    },
    "application/vnd.japannet-verification": {
      source: "iana"
    },
    "application/vnd.japannet-verification-wakeup": {
      source: "iana"
    },
    "application/vnd.jcp.javame.midlet-rms": {
      source: "iana",
      extensions: ["rms"]
    },
    "application/vnd.jisp": {
      source: "iana",
      extensions: ["jisp"]
    },
    "application/vnd.joost.joda-archive": {
      source: "iana",
      extensions: ["joda"]
    },
    "application/vnd.jsk.isdn-ngn": {
      source: "iana"
    },
    "application/vnd.kahootz": {
      source: "iana",
      extensions: ["ktz", "ktr"]
    },
    "application/vnd.kde.karbon": {
      source: "iana",
      extensions: ["karbon"]
    },
    "application/vnd.kde.kchart": {
      source: "iana",
      extensions: ["chrt"]
    },
    "application/vnd.kde.kformula": {
      source: "iana",
      extensions: ["kfo"]
    },
    "application/vnd.kde.kivio": {
      source: "iana",
      extensions: ["flw"]
    },
    "application/vnd.kde.kontour": {
      source: "iana",
      extensions: ["kon"]
    },
    "application/vnd.kde.kpresenter": {
      source: "iana",
      extensions: ["kpr", "kpt"]
    },
    "application/vnd.kde.kspread": {
      source: "iana",
      extensions: ["ksp"]
    },
    "application/vnd.kde.kword": {
      source: "iana",
      extensions: ["kwd", "kwt"]
    },
    "application/vnd.kenameaapp": {
      source: "iana",
      extensions: ["htke"]
    },
    "application/vnd.kidspiration": {
      source: "iana",
      extensions: ["kia"]
    },
    "application/vnd.kinar": {
      source: "iana",
      extensions: ["kne", "knp"]
    },
    "application/vnd.koan": {
      source: "iana",
      extensions: ["skp", "skd", "skt", "skm"]
    },
    "application/vnd.kodak-descriptor": {
      source: "iana",
      extensions: ["sse"]
    },
    "application/vnd.las": {
      source: "iana"
    },
    "application/vnd.las.las+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.las.las+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["lasxml"]
    },
    "application/vnd.laszip": {
      source: "iana"
    },
    "application/vnd.leap+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.liberty-request+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.llamagraphics.life-balance.desktop": {
      source: "iana",
      extensions: ["lbd"]
    },
    "application/vnd.llamagraphics.life-balance.exchange+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["lbe"]
    },
    "application/vnd.logipipe.circuit+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.loom": {
      source: "iana"
    },
    "application/vnd.lotus-1-2-3": {
      source: "iana",
      extensions: ["123"]
    },
    "application/vnd.lotus-approach": {
      source: "iana",
      extensions: ["apr"]
    },
    "application/vnd.lotus-freelance": {
      source: "iana",
      extensions: ["pre"]
    },
    "application/vnd.lotus-notes": {
      source: "iana",
      extensions: ["nsf"]
    },
    "application/vnd.lotus-organizer": {
      source: "iana",
      extensions: ["org"]
    },
    "application/vnd.lotus-screencam": {
      source: "iana",
      extensions: ["scm"]
    },
    "application/vnd.lotus-wordpro": {
      source: "iana",
      extensions: ["lwp"]
    },
    "application/vnd.macports.portpkg": {
      source: "iana",
      extensions: ["portpkg"]
    },
    "application/vnd.mapbox-vector-tile": {
      source: "iana",
      extensions: ["mvt"]
    },
    "application/vnd.marlin.drm.actiontoken+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.marlin.drm.conftoken+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.marlin.drm.license+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.marlin.drm.mdcf": {
      source: "iana"
    },
    "application/vnd.mason+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.maxar.archive.3tz+zip": {
      source: "iana",
      compressible: !1
    },
    "application/vnd.maxmind.maxmind-db": {
      source: "iana"
    },
    "application/vnd.mcd": {
      source: "iana",
      extensions: ["mcd"]
    },
    "application/vnd.medcalcdata": {
      source: "iana",
      extensions: ["mc1"]
    },
    "application/vnd.mediastation.cdkey": {
      source: "iana",
      extensions: ["cdkey"]
    },
    "application/vnd.meridian-slingshot": {
      source: "iana"
    },
    "application/vnd.mfer": {
      source: "iana",
      extensions: ["mwf"]
    },
    "application/vnd.mfmp": {
      source: "iana",
      extensions: ["mfm"]
    },
    "application/vnd.micro+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.micrografx.flo": {
      source: "iana",
      extensions: ["flo"]
    },
    "application/vnd.micrografx.igx": {
      source: "iana",
      extensions: ["igx"]
    },
    "application/vnd.microsoft.portable-executable": {
      source: "iana"
    },
    "application/vnd.microsoft.windows.thumbnail-cache": {
      source: "iana"
    },
    "application/vnd.miele+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.mif": {
      source: "iana",
      extensions: ["mif"]
    },
    "application/vnd.minisoft-hp3000-save": {
      source: "iana"
    },
    "application/vnd.mitsubishi.misty-guard.trustweb": {
      source: "iana"
    },
    "application/vnd.mobius.daf": {
      source: "iana",
      extensions: ["daf"]
    },
    "application/vnd.mobius.dis": {
      source: "iana",
      extensions: ["dis"]
    },
    "application/vnd.mobius.mbk": {
      source: "iana",
      extensions: ["mbk"]
    },
    "application/vnd.mobius.mqy": {
      source: "iana",
      extensions: ["mqy"]
    },
    "application/vnd.mobius.msl": {
      source: "iana",
      extensions: ["msl"]
    },
    "application/vnd.mobius.plc": {
      source: "iana",
      extensions: ["plc"]
    },
    "application/vnd.mobius.txf": {
      source: "iana",
      extensions: ["txf"]
    },
    "application/vnd.mophun.application": {
      source: "iana",
      extensions: ["mpn"]
    },
    "application/vnd.mophun.certificate": {
      source: "iana",
      extensions: ["mpc"]
    },
    "application/vnd.motorola.flexsuite": {
      source: "iana"
    },
    "application/vnd.motorola.flexsuite.adsi": {
      source: "iana"
    },
    "application/vnd.motorola.flexsuite.fis": {
      source: "iana"
    },
    "application/vnd.motorola.flexsuite.gotap": {
      source: "iana"
    },
    "application/vnd.motorola.flexsuite.kmr": {
      source: "iana"
    },
    "application/vnd.motorola.flexsuite.ttc": {
      source: "iana"
    },
    "application/vnd.motorola.flexsuite.wem": {
      source: "iana"
    },
    "application/vnd.motorola.iprm": {
      source: "iana"
    },
    "application/vnd.mozilla.xul+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xul"]
    },
    "application/vnd.ms-3mfdocument": {
      source: "iana"
    },
    "application/vnd.ms-artgalry": {
      source: "iana",
      extensions: ["cil"]
    },
    "application/vnd.ms-asf": {
      source: "iana"
    },
    "application/vnd.ms-cab-compressed": {
      source: "iana",
      extensions: ["cab"]
    },
    "application/vnd.ms-color.iccprofile": {
      source: "apache"
    },
    "application/vnd.ms-excel": {
      source: "iana",
      compressible: !1,
      extensions: ["xls", "xlm", "xla", "xlc", "xlt", "xlw"]
    },
    "application/vnd.ms-excel.addin.macroenabled.12": {
      source: "iana",
      extensions: ["xlam"]
    },
    "application/vnd.ms-excel.sheet.binary.macroenabled.12": {
      source: "iana",
      extensions: ["xlsb"]
    },
    "application/vnd.ms-excel.sheet.macroenabled.12": {
      source: "iana",
      extensions: ["xlsm"]
    },
    "application/vnd.ms-excel.template.macroenabled.12": {
      source: "iana",
      extensions: ["xltm"]
    },
    "application/vnd.ms-fontobject": {
      source: "iana",
      compressible: !0,
      extensions: ["eot"]
    },
    "application/vnd.ms-htmlhelp": {
      source: "iana",
      extensions: ["chm"]
    },
    "application/vnd.ms-ims": {
      source: "iana",
      extensions: ["ims"]
    },
    "application/vnd.ms-lrm": {
      source: "iana",
      extensions: ["lrm"]
    },
    "application/vnd.ms-office.activex+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ms-officetheme": {
      source: "iana",
      extensions: ["thmx"]
    },
    "application/vnd.ms-opentype": {
      source: "apache",
      compressible: !0
    },
    "application/vnd.ms-outlook": {
      compressible: !1,
      extensions: ["msg"]
    },
    "application/vnd.ms-package.obfuscated-opentype": {
      source: "apache"
    },
    "application/vnd.ms-pki.seccat": {
      source: "apache",
      extensions: ["cat"]
    },
    "application/vnd.ms-pki.stl": {
      source: "apache",
      extensions: ["stl"]
    },
    "application/vnd.ms-playready.initiator+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ms-powerpoint": {
      source: "iana",
      compressible: !1,
      extensions: ["ppt", "pps", "pot"]
    },
    "application/vnd.ms-powerpoint.addin.macroenabled.12": {
      source: "iana",
      extensions: ["ppam"]
    },
    "application/vnd.ms-powerpoint.presentation.macroenabled.12": {
      source: "iana",
      extensions: ["pptm"]
    },
    "application/vnd.ms-powerpoint.slide.macroenabled.12": {
      source: "iana",
      extensions: ["sldm"]
    },
    "application/vnd.ms-powerpoint.slideshow.macroenabled.12": {
      source: "iana",
      extensions: ["ppsm"]
    },
    "application/vnd.ms-powerpoint.template.macroenabled.12": {
      source: "iana",
      extensions: ["potm"]
    },
    "application/vnd.ms-printdevicecapabilities+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ms-printing.printticket+xml": {
      source: "apache",
      compressible: !0
    },
    "application/vnd.ms-printschematicket+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ms-project": {
      source: "iana",
      extensions: ["mpp", "mpt"]
    },
    "application/vnd.ms-tnef": {
      source: "iana"
    },
    "application/vnd.ms-windows.devicepairing": {
      source: "iana"
    },
    "application/vnd.ms-windows.nwprinting.oob": {
      source: "iana"
    },
    "application/vnd.ms-windows.printerpairing": {
      source: "iana"
    },
    "application/vnd.ms-windows.wsd.oob": {
      source: "iana"
    },
    "application/vnd.ms-wmdrm.lic-chlg-req": {
      source: "iana"
    },
    "application/vnd.ms-wmdrm.lic-resp": {
      source: "iana"
    },
    "application/vnd.ms-wmdrm.meter-chlg-req": {
      source: "iana"
    },
    "application/vnd.ms-wmdrm.meter-resp": {
      source: "iana"
    },
    "application/vnd.ms-word.document.macroenabled.12": {
      source: "iana",
      extensions: ["docm"]
    },
    "application/vnd.ms-word.template.macroenabled.12": {
      source: "iana",
      extensions: ["dotm"]
    },
    "application/vnd.ms-works": {
      source: "iana",
      extensions: ["wps", "wks", "wcm", "wdb"]
    },
    "application/vnd.ms-wpl": {
      source: "iana",
      extensions: ["wpl"]
    },
    "application/vnd.ms-xpsdocument": {
      source: "iana",
      compressible: !1,
      extensions: ["xps"]
    },
    "application/vnd.msa-disk-image": {
      source: "iana"
    },
    "application/vnd.mseq": {
      source: "iana",
      extensions: ["mseq"]
    },
    "application/vnd.msign": {
      source: "iana"
    },
    "application/vnd.multiad.creator": {
      source: "iana"
    },
    "application/vnd.multiad.creator.cif": {
      source: "iana"
    },
    "application/vnd.music-niff": {
      source: "iana"
    },
    "application/vnd.musician": {
      source: "iana",
      extensions: ["mus"]
    },
    "application/vnd.muvee.style": {
      source: "iana",
      extensions: ["msty"]
    },
    "application/vnd.mynfc": {
      source: "iana",
      extensions: ["taglet"]
    },
    "application/vnd.nacamar.ybrid+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.ncd.control": {
      source: "iana"
    },
    "application/vnd.ncd.reference": {
      source: "iana"
    },
    "application/vnd.nearst.inv+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.nebumind.line": {
      source: "iana"
    },
    "application/vnd.nervana": {
      source: "iana"
    },
    "application/vnd.netfpx": {
      source: "iana"
    },
    "application/vnd.neurolanguage.nlu": {
      source: "iana",
      extensions: ["nlu"]
    },
    "application/vnd.nimn": {
      source: "iana"
    },
    "application/vnd.nintendo.nitro.rom": {
      source: "iana"
    },
    "application/vnd.nintendo.snes.rom": {
      source: "iana"
    },
    "application/vnd.nitf": {
      source: "iana",
      extensions: ["ntf", "nitf"]
    },
    "application/vnd.noblenet-directory": {
      source: "iana",
      extensions: ["nnd"]
    },
    "application/vnd.noblenet-sealer": {
      source: "iana",
      extensions: ["nns"]
    },
    "application/vnd.noblenet-web": {
      source: "iana",
      extensions: ["nnw"]
    },
    "application/vnd.nokia.catalogs": {
      source: "iana"
    },
    "application/vnd.nokia.conml+wbxml": {
      source: "iana"
    },
    "application/vnd.nokia.conml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.nokia.iptv.config+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.nokia.isds-radio-presets": {
      source: "iana"
    },
    "application/vnd.nokia.landmark+wbxml": {
      source: "iana"
    },
    "application/vnd.nokia.landmark+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.nokia.landmarkcollection+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.nokia.n-gage.ac+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["ac"]
    },
    "application/vnd.nokia.n-gage.data": {
      source: "iana",
      extensions: ["ngdat"]
    },
    "application/vnd.nokia.n-gage.symbian.install": {
      source: "iana",
      extensions: ["n-gage"]
    },
    "application/vnd.nokia.ncd": {
      source: "iana"
    },
    "application/vnd.nokia.pcd+wbxml": {
      source: "iana"
    },
    "application/vnd.nokia.pcd+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.nokia.radio-preset": {
      source: "iana",
      extensions: ["rpst"]
    },
    "application/vnd.nokia.radio-presets": {
      source: "iana",
      extensions: ["rpss"]
    },
    "application/vnd.novadigm.edm": {
      source: "iana",
      extensions: ["edm"]
    },
    "application/vnd.novadigm.edx": {
      source: "iana",
      extensions: ["edx"]
    },
    "application/vnd.novadigm.ext": {
      source: "iana",
      extensions: ["ext"]
    },
    "application/vnd.ntt-local.content-share": {
      source: "iana"
    },
    "application/vnd.ntt-local.file-transfer": {
      source: "iana"
    },
    "application/vnd.ntt-local.ogw_remote-access": {
      source: "iana"
    },
    "application/vnd.ntt-local.sip-ta_remote": {
      source: "iana"
    },
    "application/vnd.ntt-local.sip-ta_tcp_stream": {
      source: "iana"
    },
    "application/vnd.oasis.opendocument.chart": {
      source: "iana",
      extensions: ["odc"]
    },
    "application/vnd.oasis.opendocument.chart-template": {
      source: "iana",
      extensions: ["otc"]
    },
    "application/vnd.oasis.opendocument.database": {
      source: "iana",
      extensions: ["odb"]
    },
    "application/vnd.oasis.opendocument.formula": {
      source: "iana",
      extensions: ["odf"]
    },
    "application/vnd.oasis.opendocument.formula-template": {
      source: "iana",
      extensions: ["odft"]
    },
    "application/vnd.oasis.opendocument.graphics": {
      source: "iana",
      compressible: !1,
      extensions: ["odg"]
    },
    "application/vnd.oasis.opendocument.graphics-template": {
      source: "iana",
      extensions: ["otg"]
    },
    "application/vnd.oasis.opendocument.image": {
      source: "iana",
      extensions: ["odi"]
    },
    "application/vnd.oasis.opendocument.image-template": {
      source: "iana",
      extensions: ["oti"]
    },
    "application/vnd.oasis.opendocument.presentation": {
      source: "iana",
      compressible: !1,
      extensions: ["odp"]
    },
    "application/vnd.oasis.opendocument.presentation-template": {
      source: "iana",
      extensions: ["otp"]
    },
    "application/vnd.oasis.opendocument.spreadsheet": {
      source: "iana",
      compressible: !1,
      extensions: ["ods"]
    },
    "application/vnd.oasis.opendocument.spreadsheet-template": {
      source: "iana",
      extensions: ["ots"]
    },
    "application/vnd.oasis.opendocument.text": {
      source: "iana",
      compressible: !1,
      extensions: ["odt"]
    },
    "application/vnd.oasis.opendocument.text-master": {
      source: "iana",
      extensions: ["odm"]
    },
    "application/vnd.oasis.opendocument.text-template": {
      source: "iana",
      extensions: ["ott"]
    },
    "application/vnd.oasis.opendocument.text-web": {
      source: "iana",
      extensions: ["oth"]
    },
    "application/vnd.obn": {
      source: "iana"
    },
    "application/vnd.ocf+cbor": {
      source: "iana"
    },
    "application/vnd.oci.image.manifest.v1+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oftn.l10n+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.contentaccessdownload+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.contentaccessstreaming+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.cspg-hexbinary": {
      source: "iana"
    },
    "application/vnd.oipf.dae.svg+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.dae.xhtml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.mippvcontrolmessage+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.pae.gem": {
      source: "iana"
    },
    "application/vnd.oipf.spdiscovery+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.spdlist+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.ueprofile+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oipf.userprofile+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.olpc-sugar": {
      source: "iana",
      extensions: ["xo"]
    },
    "application/vnd.oma-scws-config": {
      source: "iana"
    },
    "application/vnd.oma-scws-http-request": {
      source: "iana"
    },
    "application/vnd.oma-scws-http-response": {
      source: "iana"
    },
    "application/vnd.oma.bcast.associated-procedure-parameter+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.bcast.drm-trigger+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.bcast.imd+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.bcast.ltkm": {
      source: "iana"
    },
    "application/vnd.oma.bcast.notification+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.bcast.provisioningtrigger": {
      source: "iana"
    },
    "application/vnd.oma.bcast.sgboot": {
      source: "iana"
    },
    "application/vnd.oma.bcast.sgdd+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.bcast.sgdu": {
      source: "iana"
    },
    "application/vnd.oma.bcast.simple-symbol-container": {
      source: "iana"
    },
    "application/vnd.oma.bcast.smartcard-trigger+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.bcast.sprov+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.bcast.stkm": {
      source: "iana"
    },
    "application/vnd.oma.cab-address-book+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.cab-feature-handler+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.cab-pcc+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.cab-subs-invite+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.cab-user-prefs+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.dcd": {
      source: "iana"
    },
    "application/vnd.oma.dcdc": {
      source: "iana"
    },
    "application/vnd.oma.dd2+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["dd2"]
    },
    "application/vnd.oma.drm.risd+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.group-usage-list+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.lwm2m+cbor": {
      source: "iana"
    },
    "application/vnd.oma.lwm2m+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.lwm2m+tlv": {
      source: "iana"
    },
    "application/vnd.oma.pal+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.poc.detailed-progress-report+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.poc.final-report+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.poc.groups+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.poc.invocation-descriptor+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.poc.optimized-progress-report+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.push": {
      source: "iana"
    },
    "application/vnd.oma.scidm.messages+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oma.xcap-directory+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.omads-email+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/vnd.omads-file+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/vnd.omads-folder+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/vnd.omaloc-supl-init": {
      source: "iana"
    },
    "application/vnd.onepager": {
      source: "iana"
    },
    "application/vnd.onepagertamp": {
      source: "iana"
    },
    "application/vnd.onepagertamx": {
      source: "iana"
    },
    "application/vnd.onepagertat": {
      source: "iana"
    },
    "application/vnd.onepagertatp": {
      source: "iana"
    },
    "application/vnd.onepagertatx": {
      source: "iana"
    },
    "application/vnd.openblox.game+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["obgx"]
    },
    "application/vnd.openblox.game-binary": {
      source: "iana"
    },
    "application/vnd.openeye.oeb": {
      source: "iana"
    },
    "application/vnd.openofficeorg.extension": {
      source: "apache",
      extensions: ["oxt"]
    },
    "application/vnd.openstreetmap.data+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["osm"]
    },
    "application/vnd.opentimestamps.ots": {
      source: "iana"
    },
    "application/vnd.openxmlformats-officedocument.custom-properties+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.customxmlproperties+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.drawing+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.drawingml.chart+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.drawingml.chartshapes+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramcolors+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramdata+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramlayout+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.drawingml.diagramstyle+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.extended-properties+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.commentauthors+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.comments+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.handoutmaster+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.notesmaster+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.notesslide+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": {
      source: "iana",
      compressible: !1,
      extensions: ["pptx"]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.presprops+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slide": {
      source: "iana",
      extensions: ["sldx"]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slide+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slidelayout+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slidemaster+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow": {
      source: "iana",
      extensions: ["ppsx"]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideshow.main+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.slideupdateinfo+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.tablestyles+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.tags+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.template": {
      source: "iana",
      extensions: ["potx"]
    },
    "application/vnd.openxmlformats-officedocument.presentationml.template.main+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.presentationml.viewprops+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.calcchain+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.chartsheet+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.comments+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.connections+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.dialogsheet+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.externallink+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcachedefinition+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivotcacherecords+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.pivottable+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.querytable+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionheaders+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.revisionlog+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedstrings+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {
      source: "iana",
      compressible: !1,
      extensions: ["xlsx"]
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheetmetadata+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.table+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.tablesinglecells+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template": {
      source: "iana",
      extensions: ["xltx"]
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.usernames+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.volatiledependencies+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.theme+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.themeoverride+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.vmldrawing": {
      source: "iana"
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {
      source: "iana",
      compressible: !1,
      extensions: ["docx"]
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.glossary+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.endnotes+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.fonttable+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template": {
      source: "iana",
      extensions: ["dotx"]
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-officedocument.wordprocessingml.websettings+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-package.core-properties+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-package.digital-signature-xmlsignature+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.openxmlformats-package.relationships+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oracle.resource+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.orange.indata": {
      source: "iana"
    },
    "application/vnd.osa.netdeploy": {
      source: "iana"
    },
    "application/vnd.osgeo.mapguide.package": {
      source: "iana",
      extensions: ["mgp"]
    },
    "application/vnd.osgi.bundle": {
      source: "iana"
    },
    "application/vnd.osgi.dp": {
      source: "iana",
      extensions: ["dp"]
    },
    "application/vnd.osgi.subsystem": {
      source: "iana",
      extensions: ["esa"]
    },
    "application/vnd.otps.ct-kip+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.oxli.countgraph": {
      source: "iana"
    },
    "application/vnd.pagerduty+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.palm": {
      source: "iana",
      extensions: ["pdb", "pqa", "oprc"]
    },
    "application/vnd.panoply": {
      source: "iana"
    },
    "application/vnd.paos.xml": {
      source: "iana"
    },
    "application/vnd.patentdive": {
      source: "iana"
    },
    "application/vnd.patientecommsdoc": {
      source: "iana"
    },
    "application/vnd.pawaafile": {
      source: "iana",
      extensions: ["paw"]
    },
    "application/vnd.pcos": {
      source: "iana"
    },
    "application/vnd.pg.format": {
      source: "iana",
      extensions: ["str"]
    },
    "application/vnd.pg.osasli": {
      source: "iana",
      extensions: ["ei6"]
    },
    "application/vnd.piaccess.application-licence": {
      source: "iana"
    },
    "application/vnd.picsel": {
      source: "iana",
      extensions: ["efif"]
    },
    "application/vnd.pmi.widget": {
      source: "iana",
      extensions: ["wg"]
    },
    "application/vnd.poc.group-advertisement+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.pocketlearn": {
      source: "iana",
      extensions: ["plf"]
    },
    "application/vnd.powerbuilder6": {
      source: "iana",
      extensions: ["pbd"]
    },
    "application/vnd.powerbuilder6-s": {
      source: "iana"
    },
    "application/vnd.powerbuilder7": {
      source: "iana"
    },
    "application/vnd.powerbuilder7-s": {
      source: "iana"
    },
    "application/vnd.powerbuilder75": {
      source: "iana"
    },
    "application/vnd.powerbuilder75-s": {
      source: "iana"
    },
    "application/vnd.preminet": {
      source: "iana"
    },
    "application/vnd.previewsystems.box": {
      source: "iana",
      extensions: ["box"]
    },
    "application/vnd.proteus.magazine": {
      source: "iana",
      extensions: ["mgz"]
    },
    "application/vnd.psfs": {
      source: "iana"
    },
    "application/vnd.publishare-delta-tree": {
      source: "iana",
      extensions: ["qps"]
    },
    "application/vnd.pvi.ptid1": {
      source: "iana",
      extensions: ["ptid"]
    },
    "application/vnd.pwg-multiplexed": {
      source: "iana"
    },
    "application/vnd.pwg-xhtml-print+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.qualcomm.brew-app-res": {
      source: "iana"
    },
    "application/vnd.quarantainenet": {
      source: "iana"
    },
    "application/vnd.quark.quarkxpress": {
      source: "iana",
      extensions: ["qxd", "qxt", "qwd", "qwt", "qxl", "qxb"]
    },
    "application/vnd.quobject-quoxdocument": {
      source: "iana"
    },
    "application/vnd.radisys.moml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-audit+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-audit-conf+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-audit-conn+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-audit-dialog+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-audit-stream+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-conf+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-dialog+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-dialog-base+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-dialog-fax-detect+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-dialog-fax-sendrecv+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-dialog-group+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-dialog-speech+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.radisys.msml-dialog-transform+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.rainstor.data": {
      source: "iana"
    },
    "application/vnd.rapid": {
      source: "iana"
    },
    "application/vnd.rar": {
      source: "iana",
      extensions: ["rar"]
    },
    "application/vnd.realvnc.bed": {
      source: "iana",
      extensions: ["bed"]
    },
    "application/vnd.recordare.musicxml": {
      source: "iana",
      extensions: ["mxl"]
    },
    "application/vnd.recordare.musicxml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["musicxml"]
    },
    "application/vnd.renlearn.rlprint": {
      source: "iana"
    },
    "application/vnd.resilient.logic": {
      source: "iana"
    },
    "application/vnd.restful+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.rig.cryptonote": {
      source: "iana",
      extensions: ["cryptonote"]
    },
    "application/vnd.rim.cod": {
      source: "apache",
      extensions: ["cod"]
    },
    "application/vnd.rn-realmedia": {
      source: "apache",
      extensions: ["rm"]
    },
    "application/vnd.rn-realmedia-vbr": {
      source: "apache",
      extensions: ["rmvb"]
    },
    "application/vnd.route66.link66+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["link66"]
    },
    "application/vnd.rs-274x": {
      source: "iana"
    },
    "application/vnd.ruckus.download": {
      source: "iana"
    },
    "application/vnd.s3sms": {
      source: "iana"
    },
    "application/vnd.sailingtracker.track": {
      source: "iana",
      extensions: ["st"]
    },
    "application/vnd.sar": {
      source: "iana"
    },
    "application/vnd.sbm.cid": {
      source: "iana"
    },
    "application/vnd.sbm.mid2": {
      source: "iana"
    },
    "application/vnd.scribus": {
      source: "iana"
    },
    "application/vnd.sealed.3df": {
      source: "iana"
    },
    "application/vnd.sealed.csf": {
      source: "iana"
    },
    "application/vnd.sealed.doc": {
      source: "iana"
    },
    "application/vnd.sealed.eml": {
      source: "iana"
    },
    "application/vnd.sealed.mht": {
      source: "iana"
    },
    "application/vnd.sealed.net": {
      source: "iana"
    },
    "application/vnd.sealed.ppt": {
      source: "iana"
    },
    "application/vnd.sealed.tiff": {
      source: "iana"
    },
    "application/vnd.sealed.xls": {
      source: "iana"
    },
    "application/vnd.sealedmedia.softseal.html": {
      source: "iana"
    },
    "application/vnd.sealedmedia.softseal.pdf": {
      source: "iana"
    },
    "application/vnd.seemail": {
      source: "iana",
      extensions: ["see"]
    },
    "application/vnd.seis+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.sema": {
      source: "iana",
      extensions: ["sema"]
    },
    "application/vnd.semd": {
      source: "iana",
      extensions: ["semd"]
    },
    "application/vnd.semf": {
      source: "iana",
      extensions: ["semf"]
    },
    "application/vnd.shade-save-file": {
      source: "iana"
    },
    "application/vnd.shana.informed.formdata": {
      source: "iana",
      extensions: ["ifm"]
    },
    "application/vnd.shana.informed.formtemplate": {
      source: "iana",
      extensions: ["itp"]
    },
    "application/vnd.shana.informed.interchange": {
      source: "iana",
      extensions: ["iif"]
    },
    "application/vnd.shana.informed.package": {
      source: "iana",
      extensions: ["ipk"]
    },
    "application/vnd.shootproof+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.shopkick+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.shp": {
      source: "iana"
    },
    "application/vnd.shx": {
      source: "iana"
    },
    "application/vnd.sigrok.session": {
      source: "iana"
    },
    "application/vnd.simtech-mindmapper": {
      source: "iana",
      extensions: ["twd", "twds"]
    },
    "application/vnd.siren+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.smaf": {
      source: "iana",
      extensions: ["mmf"]
    },
    "application/vnd.smart.notebook": {
      source: "iana"
    },
    "application/vnd.smart.teacher": {
      source: "iana",
      extensions: ["teacher"]
    },
    "application/vnd.snesdev-page-table": {
      source: "iana"
    },
    "application/vnd.software602.filler.form+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["fo"]
    },
    "application/vnd.software602.filler.form-xml-zip": {
      source: "iana"
    },
    "application/vnd.solent.sdkm+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["sdkm", "sdkd"]
    },
    "application/vnd.spotfire.dxp": {
      source: "iana",
      extensions: ["dxp"]
    },
    "application/vnd.spotfire.sfs": {
      source: "iana",
      extensions: ["sfs"]
    },
    "application/vnd.sqlite3": {
      source: "iana"
    },
    "application/vnd.sss-cod": {
      source: "iana"
    },
    "application/vnd.sss-dtf": {
      source: "iana"
    },
    "application/vnd.sss-ntf": {
      source: "iana"
    },
    "application/vnd.stardivision.calc": {
      source: "apache",
      extensions: ["sdc"]
    },
    "application/vnd.stardivision.draw": {
      source: "apache",
      extensions: ["sda"]
    },
    "application/vnd.stardivision.impress": {
      source: "apache",
      extensions: ["sdd"]
    },
    "application/vnd.stardivision.math": {
      source: "apache",
      extensions: ["smf"]
    },
    "application/vnd.stardivision.writer": {
      source: "apache",
      extensions: ["sdw", "vor"]
    },
    "application/vnd.stardivision.writer-global": {
      source: "apache",
      extensions: ["sgl"]
    },
    "application/vnd.stepmania.package": {
      source: "iana",
      extensions: ["smzip"]
    },
    "application/vnd.stepmania.stepchart": {
      source: "iana",
      extensions: ["sm"]
    },
    "application/vnd.street-stream": {
      source: "iana"
    },
    "application/vnd.sun.wadl+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["wadl"]
    },
    "application/vnd.sun.xml.calc": {
      source: "apache",
      extensions: ["sxc"]
    },
    "application/vnd.sun.xml.calc.template": {
      source: "apache",
      extensions: ["stc"]
    },
    "application/vnd.sun.xml.draw": {
      source: "apache",
      extensions: ["sxd"]
    },
    "application/vnd.sun.xml.draw.template": {
      source: "apache",
      extensions: ["std"]
    },
    "application/vnd.sun.xml.impress": {
      source: "apache",
      extensions: ["sxi"]
    },
    "application/vnd.sun.xml.impress.template": {
      source: "apache",
      extensions: ["sti"]
    },
    "application/vnd.sun.xml.math": {
      source: "apache",
      extensions: ["sxm"]
    },
    "application/vnd.sun.xml.writer": {
      source: "apache",
      extensions: ["sxw"]
    },
    "application/vnd.sun.xml.writer.global": {
      source: "apache",
      extensions: ["sxg"]
    },
    "application/vnd.sun.xml.writer.template": {
      source: "apache",
      extensions: ["stw"]
    },
    "application/vnd.sus-calendar": {
      source: "iana",
      extensions: ["sus", "susp"]
    },
    "application/vnd.svd": {
      source: "iana",
      extensions: ["svd"]
    },
    "application/vnd.swiftview-ics": {
      source: "iana"
    },
    "application/vnd.sycle+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.syft+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.symbian.install": {
      source: "apache",
      extensions: ["sis", "sisx"]
    },
    "application/vnd.syncml+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["xsm"]
    },
    "application/vnd.syncml.dm+wbxml": {
      source: "iana",
      charset: "UTF-8",
      extensions: ["bdm"]
    },
    "application/vnd.syncml.dm+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["xdm"]
    },
    "application/vnd.syncml.dm.notification": {
      source: "iana"
    },
    "application/vnd.syncml.dmddf+wbxml": {
      source: "iana"
    },
    "application/vnd.syncml.dmddf+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["ddf"]
    },
    "application/vnd.syncml.dmtnds+wbxml": {
      source: "iana"
    },
    "application/vnd.syncml.dmtnds+xml": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0
    },
    "application/vnd.syncml.ds.notification": {
      source: "iana"
    },
    "application/vnd.tableschema+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.tao.intent-module-archive": {
      source: "iana",
      extensions: ["tao"]
    },
    "application/vnd.tcpdump.pcap": {
      source: "iana",
      extensions: ["pcap", "cap", "dmp"]
    },
    "application/vnd.think-cell.ppttc+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.tmd.mediaflex.api+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.tml": {
      source: "iana"
    },
    "application/vnd.tmobile-livetv": {
      source: "iana",
      extensions: ["tmo"]
    },
    "application/vnd.tri.onesource": {
      source: "iana"
    },
    "application/vnd.trid.tpt": {
      source: "iana",
      extensions: ["tpt"]
    },
    "application/vnd.triscape.mxs": {
      source: "iana",
      extensions: ["mxs"]
    },
    "application/vnd.trueapp": {
      source: "iana",
      extensions: ["tra"]
    },
    "application/vnd.truedoc": {
      source: "iana"
    },
    "application/vnd.ubisoft.webplayer": {
      source: "iana"
    },
    "application/vnd.ufdl": {
      source: "iana",
      extensions: ["ufd", "ufdl"]
    },
    "application/vnd.uiq.theme": {
      source: "iana",
      extensions: ["utz"]
    },
    "application/vnd.umajin": {
      source: "iana",
      extensions: ["umj"]
    },
    "application/vnd.unity": {
      source: "iana",
      extensions: ["unityweb"]
    },
    "application/vnd.uoml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["uoml"]
    },
    "application/vnd.uplanet.alert": {
      source: "iana"
    },
    "application/vnd.uplanet.alert-wbxml": {
      source: "iana"
    },
    "application/vnd.uplanet.bearer-choice": {
      source: "iana"
    },
    "application/vnd.uplanet.bearer-choice-wbxml": {
      source: "iana"
    },
    "application/vnd.uplanet.cacheop": {
      source: "iana"
    },
    "application/vnd.uplanet.cacheop-wbxml": {
      source: "iana"
    },
    "application/vnd.uplanet.channel": {
      source: "iana"
    },
    "application/vnd.uplanet.channel-wbxml": {
      source: "iana"
    },
    "application/vnd.uplanet.list": {
      source: "iana"
    },
    "application/vnd.uplanet.list-wbxml": {
      source: "iana"
    },
    "application/vnd.uplanet.listcmd": {
      source: "iana"
    },
    "application/vnd.uplanet.listcmd-wbxml": {
      source: "iana"
    },
    "application/vnd.uplanet.signal": {
      source: "iana"
    },
    "application/vnd.uri-map": {
      source: "iana"
    },
    "application/vnd.valve.source.material": {
      source: "iana"
    },
    "application/vnd.vcx": {
      source: "iana",
      extensions: ["vcx"]
    },
    "application/vnd.vd-study": {
      source: "iana"
    },
    "application/vnd.vectorworks": {
      source: "iana"
    },
    "application/vnd.vel+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.verimatrix.vcas": {
      source: "iana"
    },
    "application/vnd.veritone.aion+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.veryant.thin": {
      source: "iana"
    },
    "application/vnd.ves.encrypted": {
      source: "iana"
    },
    "application/vnd.vidsoft.vidconference": {
      source: "iana"
    },
    "application/vnd.visio": {
      source: "iana",
      extensions: ["vsd", "vst", "vss", "vsw"]
    },
    "application/vnd.visionary": {
      source: "iana",
      extensions: ["vis"]
    },
    "application/vnd.vividence.scriptfile": {
      source: "iana"
    },
    "application/vnd.vsf": {
      source: "iana",
      extensions: ["vsf"]
    },
    "application/vnd.wap.sic": {
      source: "iana"
    },
    "application/vnd.wap.slc": {
      source: "iana"
    },
    "application/vnd.wap.wbxml": {
      source: "iana",
      charset: "UTF-8",
      extensions: ["wbxml"]
    },
    "application/vnd.wap.wmlc": {
      source: "iana",
      extensions: ["wmlc"]
    },
    "application/vnd.wap.wmlscriptc": {
      source: "iana",
      extensions: ["wmlsc"]
    },
    "application/vnd.webturbo": {
      source: "iana",
      extensions: ["wtb"]
    },
    "application/vnd.wfa.dpp": {
      source: "iana"
    },
    "application/vnd.wfa.p2p": {
      source: "iana"
    },
    "application/vnd.wfa.wsc": {
      source: "iana"
    },
    "application/vnd.windows.devicepairing": {
      source: "iana"
    },
    "application/vnd.wmc": {
      source: "iana"
    },
    "application/vnd.wmf.bootstrap": {
      source: "iana"
    },
    "application/vnd.wolfram.mathematica": {
      source: "iana"
    },
    "application/vnd.wolfram.mathematica.package": {
      source: "iana"
    },
    "application/vnd.wolfram.player": {
      source: "iana",
      extensions: ["nbp"]
    },
    "application/vnd.wordperfect": {
      source: "iana",
      extensions: ["wpd"]
    },
    "application/vnd.wqd": {
      source: "iana",
      extensions: ["wqd"]
    },
    "application/vnd.wrq-hp3000-labelled": {
      source: "iana"
    },
    "application/vnd.wt.stf": {
      source: "iana",
      extensions: ["stf"]
    },
    "application/vnd.wv.csp+wbxml": {
      source: "iana"
    },
    "application/vnd.wv.csp+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.wv.ssp+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.xacml+json": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.xara": {
      source: "iana",
      extensions: ["xar"]
    },
    "application/vnd.xfdl": {
      source: "iana",
      extensions: ["xfdl"]
    },
    "application/vnd.xfdl.webform": {
      source: "iana"
    },
    "application/vnd.xmi+xml": {
      source: "iana",
      compressible: !0
    },
    "application/vnd.xmpie.cpkg": {
      source: "iana"
    },
    "application/vnd.xmpie.dpkg": {
      source: "iana"
    },
    "application/vnd.xmpie.plan": {
      source: "iana"
    },
    "application/vnd.xmpie.ppkg": {
      source: "iana"
    },
    "application/vnd.xmpie.xlim": {
      source: "iana"
    },
    "application/vnd.yamaha.hv-dic": {
      source: "iana",
      extensions: ["hvd"]
    },
    "application/vnd.yamaha.hv-script": {
      source: "iana",
      extensions: ["hvs"]
    },
    "application/vnd.yamaha.hv-voice": {
      source: "iana",
      extensions: ["hvp"]
    },
    "application/vnd.yamaha.openscoreformat": {
      source: "iana",
      extensions: ["osf"]
    },
    "application/vnd.yamaha.openscoreformat.osfpvg+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["osfpvg"]
    },
    "application/vnd.yamaha.remote-setup": {
      source: "iana"
    },
    "application/vnd.yamaha.smaf-audio": {
      source: "iana",
      extensions: ["saf"]
    },
    "application/vnd.yamaha.smaf-phrase": {
      source: "iana",
      extensions: ["spf"]
    },
    "application/vnd.yamaha.through-ngn": {
      source: "iana"
    },
    "application/vnd.yamaha.tunnel-udpencap": {
      source: "iana"
    },
    "application/vnd.yaoweme": {
      source: "iana"
    },
    "application/vnd.yellowriver-custom-menu": {
      source: "iana",
      extensions: ["cmp"]
    },
    "application/vnd.youtube.yt": {
      source: "iana"
    },
    "application/vnd.zul": {
      source: "iana",
      extensions: ["zir", "zirz"]
    },
    "application/vnd.zzazz.deck+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["zaz"]
    },
    "application/voicexml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["vxml"]
    },
    "application/voucher-cms+json": {
      source: "iana",
      compressible: !0
    },
    "application/vq-rtcpxr": {
      source: "iana"
    },
    "application/wasm": {
      source: "iana",
      compressible: !0,
      extensions: ["wasm"]
    },
    "application/watcherinfo+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["wif"]
    },
    "application/webpush-options+json": {
      source: "iana",
      compressible: !0
    },
    "application/whoispp-query": {
      source: "iana"
    },
    "application/whoispp-response": {
      source: "iana"
    },
    "application/widget": {
      source: "iana",
      extensions: ["wgt"]
    },
    "application/winhlp": {
      source: "apache",
      extensions: ["hlp"]
    },
    "application/wita": {
      source: "iana"
    },
    "application/wordperfect5.1": {
      source: "iana"
    },
    "application/wsdl+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["wsdl"]
    },
    "application/wspolicy+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["wspolicy"]
    },
    "application/x-7z-compressed": {
      source: "apache",
      compressible: !1,
      extensions: ["7z"]
    },
    "application/x-abiword": {
      source: "apache",
      extensions: ["abw"]
    },
    "application/x-ace-compressed": {
      source: "apache",
      extensions: ["ace"]
    },
    "application/x-amf": {
      source: "apache"
    },
    "application/x-apple-diskimage": {
      source: "apache",
      extensions: ["dmg"]
    },
    "application/x-arj": {
      compressible: !1,
      extensions: ["arj"]
    },
    "application/x-authorware-bin": {
      source: "apache",
      extensions: ["aab", "x32", "u32", "vox"]
    },
    "application/x-authorware-map": {
      source: "apache",
      extensions: ["aam"]
    },
    "application/x-authorware-seg": {
      source: "apache",
      extensions: ["aas"]
    },
    "application/x-bcpio": {
      source: "apache",
      extensions: ["bcpio"]
    },
    "application/x-bdoc": {
      compressible: !1,
      extensions: ["bdoc"]
    },
    "application/x-bittorrent": {
      source: "apache",
      extensions: ["torrent"]
    },
    "application/x-blorb": {
      source: "apache",
      extensions: ["blb", "blorb"]
    },
    "application/x-bzip": {
      source: "apache",
      compressible: !1,
      extensions: ["bz"]
    },
    "application/x-bzip2": {
      source: "apache",
      compressible: !1,
      extensions: ["bz2", "boz"]
    },
    "application/x-cbr": {
      source: "apache",
      extensions: ["cbr", "cba", "cbt", "cbz", "cb7"]
    },
    "application/x-cdlink": {
      source: "apache",
      extensions: ["vcd"]
    },
    "application/x-cfs-compressed": {
      source: "apache",
      extensions: ["cfs"]
    },
    "application/x-chat": {
      source: "apache",
      extensions: ["chat"]
    },
    "application/x-chess-pgn": {
      source: "apache",
      extensions: ["pgn"]
    },
    "application/x-chrome-extension": {
      extensions: ["crx"]
    },
    "application/x-cocoa": {
      source: "nginx",
      extensions: ["cco"]
    },
    "application/x-compress": {
      source: "apache"
    },
    "application/x-conference": {
      source: "apache",
      extensions: ["nsc"]
    },
    "application/x-cpio": {
      source: "apache",
      extensions: ["cpio"]
    },
    "application/x-csh": {
      source: "apache",
      extensions: ["csh"]
    },
    "application/x-deb": {
      compressible: !1
    },
    "application/x-debian-package": {
      source: "apache",
      extensions: ["deb", "udeb"]
    },
    "application/x-dgc-compressed": {
      source: "apache",
      extensions: ["dgc"]
    },
    "application/x-director": {
      source: "apache",
      extensions: ["dir", "dcr", "dxr", "cst", "cct", "cxt", "w3d", "fgd", "swa"]
    },
    "application/x-doom": {
      source: "apache",
      extensions: ["wad"]
    },
    "application/x-dtbncx+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["ncx"]
    },
    "application/x-dtbook+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["dtb"]
    },
    "application/x-dtbresource+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["res"]
    },
    "application/x-dvi": {
      source: "apache",
      compressible: !1,
      extensions: ["dvi"]
    },
    "application/x-envoy": {
      source: "apache",
      extensions: ["evy"]
    },
    "application/x-eva": {
      source: "apache",
      extensions: ["eva"]
    },
    "application/x-font-bdf": {
      source: "apache",
      extensions: ["bdf"]
    },
    "application/x-font-dos": {
      source: "apache"
    },
    "application/x-font-framemaker": {
      source: "apache"
    },
    "application/x-font-ghostscript": {
      source: "apache",
      extensions: ["gsf"]
    },
    "application/x-font-libgrx": {
      source: "apache"
    },
    "application/x-font-linux-psf": {
      source: "apache",
      extensions: ["psf"]
    },
    "application/x-font-pcf": {
      source: "apache",
      extensions: ["pcf"]
    },
    "application/x-font-snf": {
      source: "apache",
      extensions: ["snf"]
    },
    "application/x-font-speedo": {
      source: "apache"
    },
    "application/x-font-sunos-news": {
      source: "apache"
    },
    "application/x-font-type1": {
      source: "apache",
      extensions: ["pfa", "pfb", "pfm", "afm"]
    },
    "application/x-font-vfont": {
      source: "apache"
    },
    "application/x-freearc": {
      source: "apache",
      extensions: ["arc"]
    },
    "application/x-futuresplash": {
      source: "apache",
      extensions: ["spl"]
    },
    "application/x-gca-compressed": {
      source: "apache",
      extensions: ["gca"]
    },
    "application/x-glulx": {
      source: "apache",
      extensions: ["ulx"]
    },
    "application/x-gnumeric": {
      source: "apache",
      extensions: ["gnumeric"]
    },
    "application/x-gramps-xml": {
      source: "apache",
      extensions: ["gramps"]
    },
    "application/x-gtar": {
      source: "apache",
      extensions: ["gtar"]
    },
    "application/x-gzip": {
      source: "apache"
    },
    "application/x-hdf": {
      source: "apache",
      extensions: ["hdf"]
    },
    "application/x-httpd-php": {
      compressible: !0,
      extensions: ["php"]
    },
    "application/x-install-instructions": {
      source: "apache",
      extensions: ["install"]
    },
    "application/x-iso9660-image": {
      source: "apache",
      extensions: ["iso"]
    },
    "application/x-iwork-keynote-sffkey": {
      extensions: ["key"]
    },
    "application/x-iwork-numbers-sffnumbers": {
      extensions: ["numbers"]
    },
    "application/x-iwork-pages-sffpages": {
      extensions: ["pages"]
    },
    "application/x-java-archive-diff": {
      source: "nginx",
      extensions: ["jardiff"]
    },
    "application/x-java-jnlp-file": {
      source: "apache",
      compressible: !1,
      extensions: ["jnlp"]
    },
    "application/x-javascript": {
      compressible: !0
    },
    "application/x-keepass2": {
      extensions: ["kdbx"]
    },
    "application/x-latex": {
      source: "apache",
      compressible: !1,
      extensions: ["latex"]
    },
    "application/x-lua-bytecode": {
      extensions: ["luac"]
    },
    "application/x-lzh-compressed": {
      source: "apache",
      extensions: ["lzh", "lha"]
    },
    "application/x-makeself": {
      source: "nginx",
      extensions: ["run"]
    },
    "application/x-mie": {
      source: "apache",
      extensions: ["mie"]
    },
    "application/x-mobipocket-ebook": {
      source: "apache",
      extensions: ["prc", "mobi"]
    },
    "application/x-mpegurl": {
      compressible: !1
    },
    "application/x-ms-application": {
      source: "apache",
      extensions: ["application"]
    },
    "application/x-ms-shortcut": {
      source: "apache",
      extensions: ["lnk"]
    },
    "application/x-ms-wmd": {
      source: "apache",
      extensions: ["wmd"]
    },
    "application/x-ms-wmz": {
      source: "apache",
      extensions: ["wmz"]
    },
    "application/x-ms-xbap": {
      source: "apache",
      extensions: ["xbap"]
    },
    "application/x-msaccess": {
      source: "apache",
      extensions: ["mdb"]
    },
    "application/x-msbinder": {
      source: "apache",
      extensions: ["obd"]
    },
    "application/x-mscardfile": {
      source: "apache",
      extensions: ["crd"]
    },
    "application/x-msclip": {
      source: "apache",
      extensions: ["clp"]
    },
    "application/x-msdos-program": {
      extensions: ["exe"]
    },
    "application/x-msdownload": {
      source: "apache",
      extensions: ["exe", "dll", "com", "bat", "msi"]
    },
    "application/x-msmediaview": {
      source: "apache",
      extensions: ["mvb", "m13", "m14"]
    },
    "application/x-msmetafile": {
      source: "apache",
      extensions: ["wmf", "wmz", "emf", "emz"]
    },
    "application/x-msmoney": {
      source: "apache",
      extensions: ["mny"]
    },
    "application/x-mspublisher": {
      source: "apache",
      extensions: ["pub"]
    },
    "application/x-msschedule": {
      source: "apache",
      extensions: ["scd"]
    },
    "application/x-msterminal": {
      source: "apache",
      extensions: ["trm"]
    },
    "application/x-mswrite": {
      source: "apache",
      extensions: ["wri"]
    },
    "application/x-netcdf": {
      source: "apache",
      extensions: ["nc", "cdf"]
    },
    "application/x-ns-proxy-autoconfig": {
      compressible: !0,
      extensions: ["pac"]
    },
    "application/x-nzb": {
      source: "apache",
      extensions: ["nzb"]
    },
    "application/x-perl": {
      source: "nginx",
      extensions: ["pl", "pm"]
    },
    "application/x-pilot": {
      source: "nginx",
      extensions: ["prc", "pdb"]
    },
    "application/x-pkcs12": {
      source: "apache",
      compressible: !1,
      extensions: ["p12", "pfx"]
    },
    "application/x-pkcs7-certificates": {
      source: "apache",
      extensions: ["p7b", "spc"]
    },
    "application/x-pkcs7-certreqresp": {
      source: "apache",
      extensions: ["p7r"]
    },
    "application/x-pki-message": {
      source: "iana"
    },
    "application/x-rar-compressed": {
      source: "apache",
      compressible: !1,
      extensions: ["rar"]
    },
    "application/x-redhat-package-manager": {
      source: "nginx",
      extensions: ["rpm"]
    },
    "application/x-research-info-systems": {
      source: "apache",
      extensions: ["ris"]
    },
    "application/x-sea": {
      source: "nginx",
      extensions: ["sea"]
    },
    "application/x-sh": {
      source: "apache",
      compressible: !0,
      extensions: ["sh"]
    },
    "application/x-shar": {
      source: "apache",
      extensions: ["shar"]
    },
    "application/x-shockwave-flash": {
      source: "apache",
      compressible: !1,
      extensions: ["swf"]
    },
    "application/x-silverlight-app": {
      source: "apache",
      extensions: ["xap"]
    },
    "application/x-sql": {
      source: "apache",
      extensions: ["sql"]
    },
    "application/x-stuffit": {
      source: "apache",
      compressible: !1,
      extensions: ["sit"]
    },
    "application/x-stuffitx": {
      source: "apache",
      extensions: ["sitx"]
    },
    "application/x-subrip": {
      source: "apache",
      extensions: ["srt"]
    },
    "application/x-sv4cpio": {
      source: "apache",
      extensions: ["sv4cpio"]
    },
    "application/x-sv4crc": {
      source: "apache",
      extensions: ["sv4crc"]
    },
    "application/x-t3vm-image": {
      source: "apache",
      extensions: ["t3"]
    },
    "application/x-tads": {
      source: "apache",
      extensions: ["gam"]
    },
    "application/x-tar": {
      source: "apache",
      compressible: !0,
      extensions: ["tar"]
    },
    "application/x-tcl": {
      source: "apache",
      extensions: ["tcl", "tk"]
    },
    "application/x-tex": {
      source: "apache",
      extensions: ["tex"]
    },
    "application/x-tex-tfm": {
      source: "apache",
      extensions: ["tfm"]
    },
    "application/x-texinfo": {
      source: "apache",
      extensions: ["texinfo", "texi"]
    },
    "application/x-tgif": {
      source: "apache",
      extensions: ["obj"]
    },
    "application/x-ustar": {
      source: "apache",
      extensions: ["ustar"]
    },
    "application/x-virtualbox-hdd": {
      compressible: !0,
      extensions: ["hdd"]
    },
    "application/x-virtualbox-ova": {
      compressible: !0,
      extensions: ["ova"]
    },
    "application/x-virtualbox-ovf": {
      compressible: !0,
      extensions: ["ovf"]
    },
    "application/x-virtualbox-vbox": {
      compressible: !0,
      extensions: ["vbox"]
    },
    "application/x-virtualbox-vbox-extpack": {
      compressible: !1,
      extensions: ["vbox-extpack"]
    },
    "application/x-virtualbox-vdi": {
      compressible: !0,
      extensions: ["vdi"]
    },
    "application/x-virtualbox-vhd": {
      compressible: !0,
      extensions: ["vhd"]
    },
    "application/x-virtualbox-vmdk": {
      compressible: !0,
      extensions: ["vmdk"]
    },
    "application/x-wais-source": {
      source: "apache",
      extensions: ["src"]
    },
    "application/x-web-app-manifest+json": {
      compressible: !0,
      extensions: ["webapp"]
    },
    "application/x-www-form-urlencoded": {
      source: "iana",
      compressible: !0
    },
    "application/x-x509-ca-cert": {
      source: "iana",
      extensions: ["der", "crt", "pem"]
    },
    "application/x-x509-ca-ra-cert": {
      source: "iana"
    },
    "application/x-x509-next-ca-cert": {
      source: "iana"
    },
    "application/x-xfig": {
      source: "apache",
      extensions: ["fig"]
    },
    "application/x-xliff+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["xlf"]
    },
    "application/x-xpinstall": {
      source: "apache",
      compressible: !1,
      extensions: ["xpi"]
    },
    "application/x-xz": {
      source: "apache",
      extensions: ["xz"]
    },
    "application/x-zmachine": {
      source: "apache",
      extensions: ["z1", "z2", "z3", "z4", "z5", "z6", "z7", "z8"]
    },
    "application/x400-bp": {
      source: "iana"
    },
    "application/xacml+xml": {
      source: "iana",
      compressible: !0
    },
    "application/xaml+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["xaml"]
    },
    "application/xcap-att+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xav"]
    },
    "application/xcap-caps+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xca"]
    },
    "application/xcap-diff+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xdf"]
    },
    "application/xcap-el+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xel"]
    },
    "application/xcap-error+xml": {
      source: "iana",
      compressible: !0
    },
    "application/xcap-ns+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xns"]
    },
    "application/xcon-conference-info+xml": {
      source: "iana",
      compressible: !0
    },
    "application/xcon-conference-info-diff+xml": {
      source: "iana",
      compressible: !0
    },
    "application/xenc+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xenc"]
    },
    "application/xhtml+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xhtml", "xht"]
    },
    "application/xhtml-voice+xml": {
      source: "apache",
      compressible: !0
    },
    "application/xliff+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xlf"]
    },
    "application/xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xml", "xsl", "xsd", "rng"]
    },
    "application/xml-dtd": {
      source: "iana",
      compressible: !0,
      extensions: ["dtd"]
    },
    "application/xml-external-parsed-entity": {
      source: "iana"
    },
    "application/xml-patch+xml": {
      source: "iana",
      compressible: !0
    },
    "application/xmpp+xml": {
      source: "iana",
      compressible: !0
    },
    "application/xop+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xop"]
    },
    "application/xproc+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["xpl"]
    },
    "application/xslt+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xsl", "xslt"]
    },
    "application/xspf+xml": {
      source: "apache",
      compressible: !0,
      extensions: ["xspf"]
    },
    "application/xv+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["mxml", "xhvml", "xvml", "xvm"]
    },
    "application/yang": {
      source: "iana",
      extensions: ["yang"]
    },
    "application/yang-data+json": {
      source: "iana",
      compressible: !0
    },
    "application/yang-data+xml": {
      source: "iana",
      compressible: !0
    },
    "application/yang-patch+json": {
      source: "iana",
      compressible: !0
    },
    "application/yang-patch+xml": {
      source: "iana",
      compressible: !0
    },
    "application/yin+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["yin"]
    },
    "application/zip": {
      source: "iana",
      compressible: !1,
      extensions: ["zip"]
    },
    "application/zlib": {
      source: "iana"
    },
    "application/zstd": {
      source: "iana"
    },
    "audio/1d-interleaved-parityfec": {
      source: "iana"
    },
    "audio/32kadpcm": {
      source: "iana"
    },
    "audio/3gpp": {
      source: "iana",
      compressible: !1,
      extensions: ["3gpp"]
    },
    "audio/3gpp2": {
      source: "iana"
    },
    "audio/aac": {
      source: "iana"
    },
    "audio/ac3": {
      source: "iana"
    },
    "audio/adpcm": {
      source: "apache",
      extensions: ["adp"]
    },
    "audio/amr": {
      source: "iana",
      extensions: ["amr"]
    },
    "audio/amr-wb": {
      source: "iana"
    },
    "audio/amr-wb+": {
      source: "iana"
    },
    "audio/aptx": {
      source: "iana"
    },
    "audio/asc": {
      source: "iana"
    },
    "audio/atrac-advanced-lossless": {
      source: "iana"
    },
    "audio/atrac-x": {
      source: "iana"
    },
    "audio/atrac3": {
      source: "iana"
    },
    "audio/basic": {
      source: "iana",
      compressible: !1,
      extensions: ["au", "snd"]
    },
    "audio/bv16": {
      source: "iana"
    },
    "audio/bv32": {
      source: "iana"
    },
    "audio/clearmode": {
      source: "iana"
    },
    "audio/cn": {
      source: "iana"
    },
    "audio/dat12": {
      source: "iana"
    },
    "audio/dls": {
      source: "iana"
    },
    "audio/dsr-es201108": {
      source: "iana"
    },
    "audio/dsr-es202050": {
      source: "iana"
    },
    "audio/dsr-es202211": {
      source: "iana"
    },
    "audio/dsr-es202212": {
      source: "iana"
    },
    "audio/dv": {
      source: "iana"
    },
    "audio/dvi4": {
      source: "iana"
    },
    "audio/eac3": {
      source: "iana"
    },
    "audio/encaprtp": {
      source: "iana"
    },
    "audio/evrc": {
      source: "iana"
    },
    "audio/evrc-qcp": {
      source: "iana"
    },
    "audio/evrc0": {
      source: "iana"
    },
    "audio/evrc1": {
      source: "iana"
    },
    "audio/evrcb": {
      source: "iana"
    },
    "audio/evrcb0": {
      source: "iana"
    },
    "audio/evrcb1": {
      source: "iana"
    },
    "audio/evrcnw": {
      source: "iana"
    },
    "audio/evrcnw0": {
      source: "iana"
    },
    "audio/evrcnw1": {
      source: "iana"
    },
    "audio/evrcwb": {
      source: "iana"
    },
    "audio/evrcwb0": {
      source: "iana"
    },
    "audio/evrcwb1": {
      source: "iana"
    },
    "audio/evs": {
      source: "iana"
    },
    "audio/flexfec": {
      source: "iana"
    },
    "audio/fwdred": {
      source: "iana"
    },
    "audio/g711-0": {
      source: "iana"
    },
    "audio/g719": {
      source: "iana"
    },
    "audio/g722": {
      source: "iana"
    },
    "audio/g7221": {
      source: "iana"
    },
    "audio/g723": {
      source: "iana"
    },
    "audio/g726-16": {
      source: "iana"
    },
    "audio/g726-24": {
      source: "iana"
    },
    "audio/g726-32": {
      source: "iana"
    },
    "audio/g726-40": {
      source: "iana"
    },
    "audio/g728": {
      source: "iana"
    },
    "audio/g729": {
      source: "iana"
    },
    "audio/g7291": {
      source: "iana"
    },
    "audio/g729d": {
      source: "iana"
    },
    "audio/g729e": {
      source: "iana"
    },
    "audio/gsm": {
      source: "iana"
    },
    "audio/gsm-efr": {
      source: "iana"
    },
    "audio/gsm-hr-08": {
      source: "iana"
    },
    "audio/ilbc": {
      source: "iana"
    },
    "audio/ip-mr_v2.5": {
      source: "iana"
    },
    "audio/isac": {
      source: "apache"
    },
    "audio/l16": {
      source: "iana"
    },
    "audio/l20": {
      source: "iana"
    },
    "audio/l24": {
      source: "iana",
      compressible: !1
    },
    "audio/l8": {
      source: "iana"
    },
    "audio/lpc": {
      source: "iana"
    },
    "audio/melp": {
      source: "iana"
    },
    "audio/melp1200": {
      source: "iana"
    },
    "audio/melp2400": {
      source: "iana"
    },
    "audio/melp600": {
      source: "iana"
    },
    "audio/mhas": {
      source: "iana"
    },
    "audio/midi": {
      source: "apache",
      extensions: ["mid", "midi", "kar", "rmi"]
    },
    "audio/mobile-xmf": {
      source: "iana",
      extensions: ["mxmf"]
    },
    "audio/mp3": {
      compressible: !1,
      extensions: ["mp3"]
    },
    "audio/mp4": {
      source: "iana",
      compressible: !1,
      extensions: ["m4a", "mp4a"]
    },
    "audio/mp4a-latm": {
      source: "iana"
    },
    "audio/mpa": {
      source: "iana"
    },
    "audio/mpa-robust": {
      source: "iana"
    },
    "audio/mpeg": {
      source: "iana",
      compressible: !1,
      extensions: ["mpga", "mp2", "mp2a", "mp3", "m2a", "m3a"]
    },
    "audio/mpeg4-generic": {
      source: "iana"
    },
    "audio/musepack": {
      source: "apache"
    },
    "audio/ogg": {
      source: "iana",
      compressible: !1,
      extensions: ["oga", "ogg", "spx", "opus"]
    },
    "audio/opus": {
      source: "iana"
    },
    "audio/parityfec": {
      source: "iana"
    },
    "audio/pcma": {
      source: "iana"
    },
    "audio/pcma-wb": {
      source: "iana"
    },
    "audio/pcmu": {
      source: "iana"
    },
    "audio/pcmu-wb": {
      source: "iana"
    },
    "audio/prs.sid": {
      source: "iana"
    },
    "audio/qcelp": {
      source: "iana"
    },
    "audio/raptorfec": {
      source: "iana"
    },
    "audio/red": {
      source: "iana"
    },
    "audio/rtp-enc-aescm128": {
      source: "iana"
    },
    "audio/rtp-midi": {
      source: "iana"
    },
    "audio/rtploopback": {
      source: "iana"
    },
    "audio/rtx": {
      source: "iana"
    },
    "audio/s3m": {
      source: "apache",
      extensions: ["s3m"]
    },
    "audio/scip": {
      source: "iana"
    },
    "audio/silk": {
      source: "apache",
      extensions: ["sil"]
    },
    "audio/smv": {
      source: "iana"
    },
    "audio/smv-qcp": {
      source: "iana"
    },
    "audio/smv0": {
      source: "iana"
    },
    "audio/sofa": {
      source: "iana"
    },
    "audio/sp-midi": {
      source: "iana"
    },
    "audio/speex": {
      source: "iana"
    },
    "audio/t140c": {
      source: "iana"
    },
    "audio/t38": {
      source: "iana"
    },
    "audio/telephone-event": {
      source: "iana"
    },
    "audio/tetra_acelp": {
      source: "iana"
    },
    "audio/tetra_acelp_bb": {
      source: "iana"
    },
    "audio/tone": {
      source: "iana"
    },
    "audio/tsvcis": {
      source: "iana"
    },
    "audio/uemclip": {
      source: "iana"
    },
    "audio/ulpfec": {
      source: "iana"
    },
    "audio/usac": {
      source: "iana"
    },
    "audio/vdvi": {
      source: "iana"
    },
    "audio/vmr-wb": {
      source: "iana"
    },
    "audio/vnd.3gpp.iufp": {
      source: "iana"
    },
    "audio/vnd.4sb": {
      source: "iana"
    },
    "audio/vnd.audiokoz": {
      source: "iana"
    },
    "audio/vnd.celp": {
      source: "iana"
    },
    "audio/vnd.cisco.nse": {
      source: "iana"
    },
    "audio/vnd.cmles.radio-events": {
      source: "iana"
    },
    "audio/vnd.cns.anp1": {
      source: "iana"
    },
    "audio/vnd.cns.inf1": {
      source: "iana"
    },
    "audio/vnd.dece.audio": {
      source: "iana",
      extensions: ["uva", "uvva"]
    },
    "audio/vnd.digital-winds": {
      source: "iana",
      extensions: ["eol"]
    },
    "audio/vnd.dlna.adts": {
      source: "iana"
    },
    "audio/vnd.dolby.heaac.1": {
      source: "iana"
    },
    "audio/vnd.dolby.heaac.2": {
      source: "iana"
    },
    "audio/vnd.dolby.mlp": {
      source: "iana"
    },
    "audio/vnd.dolby.mps": {
      source: "iana"
    },
    "audio/vnd.dolby.pl2": {
      source: "iana"
    },
    "audio/vnd.dolby.pl2x": {
      source: "iana"
    },
    "audio/vnd.dolby.pl2z": {
      source: "iana"
    },
    "audio/vnd.dolby.pulse.1": {
      source: "iana"
    },
    "audio/vnd.dra": {
      source: "iana",
      extensions: ["dra"]
    },
    "audio/vnd.dts": {
      source: "iana",
      extensions: ["dts"]
    },
    "audio/vnd.dts.hd": {
      source: "iana",
      extensions: ["dtshd"]
    },
    "audio/vnd.dts.uhd": {
      source: "iana"
    },
    "audio/vnd.dvb.file": {
      source: "iana"
    },
    "audio/vnd.everad.plj": {
      source: "iana"
    },
    "audio/vnd.hns.audio": {
      source: "iana"
    },
    "audio/vnd.lucent.voice": {
      source: "iana",
      extensions: ["lvp"]
    },
    "audio/vnd.ms-playready.media.pya": {
      source: "iana",
      extensions: ["pya"]
    },
    "audio/vnd.nokia.mobile-xmf": {
      source: "iana"
    },
    "audio/vnd.nortel.vbk": {
      source: "iana"
    },
    "audio/vnd.nuera.ecelp4800": {
      source: "iana",
      extensions: ["ecelp4800"]
    },
    "audio/vnd.nuera.ecelp7470": {
      source: "iana",
      extensions: ["ecelp7470"]
    },
    "audio/vnd.nuera.ecelp9600": {
      source: "iana",
      extensions: ["ecelp9600"]
    },
    "audio/vnd.octel.sbc": {
      source: "iana"
    },
    "audio/vnd.presonus.multitrack": {
      source: "iana"
    },
    "audio/vnd.qcelp": {
      source: "iana"
    },
    "audio/vnd.rhetorex.32kadpcm": {
      source: "iana"
    },
    "audio/vnd.rip": {
      source: "iana",
      extensions: ["rip"]
    },
    "audio/vnd.rn-realaudio": {
      compressible: !1
    },
    "audio/vnd.sealedmedia.softseal.mpeg": {
      source: "iana"
    },
    "audio/vnd.vmx.cvsd": {
      source: "iana"
    },
    "audio/vnd.wave": {
      compressible: !1
    },
    "audio/vorbis": {
      source: "iana",
      compressible: !1
    },
    "audio/vorbis-config": {
      source: "iana"
    },
    "audio/wav": {
      compressible: !1,
      extensions: ["wav"]
    },
    "audio/wave": {
      compressible: !1,
      extensions: ["wav"]
    },
    "audio/webm": {
      source: "apache",
      compressible: !1,
      extensions: ["weba"]
    },
    "audio/x-aac": {
      source: "apache",
      compressible: !1,
      extensions: ["aac"]
    },
    "audio/x-aiff": {
      source: "apache",
      extensions: ["aif", "aiff", "aifc"]
    },
    "audio/x-caf": {
      source: "apache",
      compressible: !1,
      extensions: ["caf"]
    },
    "audio/x-flac": {
      source: "apache",
      extensions: ["flac"]
    },
    "audio/x-m4a": {
      source: "nginx",
      extensions: ["m4a"]
    },
    "audio/x-matroska": {
      source: "apache",
      extensions: ["mka"]
    },
    "audio/x-mpegurl": {
      source: "apache",
      extensions: ["m3u"]
    },
    "audio/x-ms-wax": {
      source: "apache",
      extensions: ["wax"]
    },
    "audio/x-ms-wma": {
      source: "apache",
      extensions: ["wma"]
    },
    "audio/x-pn-realaudio": {
      source: "apache",
      extensions: ["ram", "ra"]
    },
    "audio/x-pn-realaudio-plugin": {
      source: "apache",
      extensions: ["rmp"]
    },
    "audio/x-realaudio": {
      source: "nginx",
      extensions: ["ra"]
    },
    "audio/x-tta": {
      source: "apache"
    },
    "audio/x-wav": {
      source: "apache",
      extensions: ["wav"]
    },
    "audio/xm": {
      source: "apache",
      extensions: ["xm"]
    },
    "chemical/x-cdx": {
      source: "apache",
      extensions: ["cdx"]
    },
    "chemical/x-cif": {
      source: "apache",
      extensions: ["cif"]
    },
    "chemical/x-cmdf": {
      source: "apache",
      extensions: ["cmdf"]
    },
    "chemical/x-cml": {
      source: "apache",
      extensions: ["cml"]
    },
    "chemical/x-csml": {
      source: "apache",
      extensions: ["csml"]
    },
    "chemical/x-pdb": {
      source: "apache"
    },
    "chemical/x-xyz": {
      source: "apache",
      extensions: ["xyz"]
    },
    "font/collection": {
      source: "iana",
      extensions: ["ttc"]
    },
    "font/otf": {
      source: "iana",
      compressible: !0,
      extensions: ["otf"]
    },
    "font/sfnt": {
      source: "iana"
    },
    "font/ttf": {
      source: "iana",
      compressible: !0,
      extensions: ["ttf"]
    },
    "font/woff": {
      source: "iana",
      extensions: ["woff"]
    },
    "font/woff2": {
      source: "iana",
      extensions: ["woff2"]
    },
    "image/aces": {
      source: "iana",
      extensions: ["exr"]
    },
    "image/apng": {
      compressible: !1,
      extensions: ["apng"]
    },
    "image/avci": {
      source: "iana",
      extensions: ["avci"]
    },
    "image/avcs": {
      source: "iana",
      extensions: ["avcs"]
    },
    "image/avif": {
      source: "iana",
      compressible: !1,
      extensions: ["avif"]
    },
    "image/bmp": {
      source: "iana",
      compressible: !0,
      extensions: ["bmp"]
    },
    "image/cgm": {
      source: "iana",
      extensions: ["cgm"]
    },
    "image/dicom-rle": {
      source: "iana",
      extensions: ["drle"]
    },
    "image/emf": {
      source: "iana",
      extensions: ["emf"]
    },
    "image/fits": {
      source: "iana",
      extensions: ["fits"]
    },
    "image/g3fax": {
      source: "iana",
      extensions: ["g3"]
    },
    "image/gif": {
      source: "iana",
      compressible: !1,
      extensions: ["gif"]
    },
    "image/heic": {
      source: "iana",
      extensions: ["heic"]
    },
    "image/heic-sequence": {
      source: "iana",
      extensions: ["heics"]
    },
    "image/heif": {
      source: "iana",
      extensions: ["heif"]
    },
    "image/heif-sequence": {
      source: "iana",
      extensions: ["heifs"]
    },
    "image/hej2k": {
      source: "iana",
      extensions: ["hej2"]
    },
    "image/hsj2": {
      source: "iana",
      extensions: ["hsj2"]
    },
    "image/ief": {
      source: "iana",
      extensions: ["ief"]
    },
    "image/jls": {
      source: "iana",
      extensions: ["jls"]
    },
    "image/jp2": {
      source: "iana",
      compressible: !1,
      extensions: ["jp2", "jpg2"]
    },
    "image/jpeg": {
      source: "iana",
      compressible: !1,
      extensions: ["jpeg", "jpg", "jpe"]
    },
    "image/jph": {
      source: "iana",
      extensions: ["jph"]
    },
    "image/jphc": {
      source: "iana",
      extensions: ["jhc"]
    },
    "image/jpm": {
      source: "iana",
      compressible: !1,
      extensions: ["jpm"]
    },
    "image/jpx": {
      source: "iana",
      compressible: !1,
      extensions: ["jpx", "jpf"]
    },
    "image/jxr": {
      source: "iana",
      extensions: ["jxr"]
    },
    "image/jxra": {
      source: "iana",
      extensions: ["jxra"]
    },
    "image/jxrs": {
      source: "iana",
      extensions: ["jxrs"]
    },
    "image/jxs": {
      source: "iana",
      extensions: ["jxs"]
    },
    "image/jxsc": {
      source: "iana",
      extensions: ["jxsc"]
    },
    "image/jxsi": {
      source: "iana",
      extensions: ["jxsi"]
    },
    "image/jxss": {
      source: "iana",
      extensions: ["jxss"]
    },
    "image/ktx": {
      source: "iana",
      extensions: ["ktx"]
    },
    "image/ktx2": {
      source: "iana",
      extensions: ["ktx2"]
    },
    "image/naplps": {
      source: "iana"
    },
    "image/pjpeg": {
      compressible: !1
    },
    "image/png": {
      source: "iana",
      compressible: !1,
      extensions: ["png"]
    },
    "image/prs.btif": {
      source: "iana",
      extensions: ["btif"]
    },
    "image/prs.pti": {
      source: "iana",
      extensions: ["pti"]
    },
    "image/pwg-raster": {
      source: "iana"
    },
    "image/sgi": {
      source: "apache",
      extensions: ["sgi"]
    },
    "image/svg+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["svg", "svgz"]
    },
    "image/t38": {
      source: "iana",
      extensions: ["t38"]
    },
    "image/tiff": {
      source: "iana",
      compressible: !1,
      extensions: ["tif", "tiff"]
    },
    "image/tiff-fx": {
      source: "iana",
      extensions: ["tfx"]
    },
    "image/vnd.adobe.photoshop": {
      source: "iana",
      compressible: !0,
      extensions: ["psd"]
    },
    "image/vnd.airzip.accelerator.azv": {
      source: "iana",
      extensions: ["azv"]
    },
    "image/vnd.cns.inf2": {
      source: "iana"
    },
    "image/vnd.dece.graphic": {
      source: "iana",
      extensions: ["uvi", "uvvi", "uvg", "uvvg"]
    },
    "image/vnd.djvu": {
      source: "iana",
      extensions: ["djvu", "djv"]
    },
    "image/vnd.dvb.subtitle": {
      source: "iana",
      extensions: ["sub"]
    },
    "image/vnd.dwg": {
      source: "iana",
      extensions: ["dwg"]
    },
    "image/vnd.dxf": {
      source: "iana",
      extensions: ["dxf"]
    },
    "image/vnd.fastbidsheet": {
      source: "iana",
      extensions: ["fbs"]
    },
    "image/vnd.fpx": {
      source: "iana",
      extensions: ["fpx"]
    },
    "image/vnd.fst": {
      source: "iana",
      extensions: ["fst"]
    },
    "image/vnd.fujixerox.edmics-mmr": {
      source: "iana",
      extensions: ["mmr"]
    },
    "image/vnd.fujixerox.edmics-rlc": {
      source: "iana",
      extensions: ["rlc"]
    },
    "image/vnd.globalgraphics.pgb": {
      source: "iana"
    },
    "image/vnd.microsoft.icon": {
      source: "iana",
      compressible: !0,
      extensions: ["ico"]
    },
    "image/vnd.mix": {
      source: "iana"
    },
    "image/vnd.mozilla.apng": {
      source: "iana"
    },
    "image/vnd.ms-dds": {
      compressible: !0,
      extensions: ["dds"]
    },
    "image/vnd.ms-modi": {
      source: "iana",
      extensions: ["mdi"]
    },
    "image/vnd.ms-photo": {
      source: "apache",
      extensions: ["wdp"]
    },
    "image/vnd.net-fpx": {
      source: "iana",
      extensions: ["npx"]
    },
    "image/vnd.pco.b16": {
      source: "iana",
      extensions: ["b16"]
    },
    "image/vnd.radiance": {
      source: "iana"
    },
    "image/vnd.sealed.png": {
      source: "iana"
    },
    "image/vnd.sealedmedia.softseal.gif": {
      source: "iana"
    },
    "image/vnd.sealedmedia.softseal.jpg": {
      source: "iana"
    },
    "image/vnd.svf": {
      source: "iana"
    },
    "image/vnd.tencent.tap": {
      source: "iana",
      extensions: ["tap"]
    },
    "image/vnd.valve.source.texture": {
      source: "iana",
      extensions: ["vtf"]
    },
    "image/vnd.wap.wbmp": {
      source: "iana",
      extensions: ["wbmp"]
    },
    "image/vnd.xiff": {
      source: "iana",
      extensions: ["xif"]
    },
    "image/vnd.zbrush.pcx": {
      source: "iana",
      extensions: ["pcx"]
    },
    "image/webp": {
      source: "apache",
      extensions: ["webp"]
    },
    "image/wmf": {
      source: "iana",
      extensions: ["wmf"]
    },
    "image/x-3ds": {
      source: "apache",
      extensions: ["3ds"]
    },
    "image/x-cmu-raster": {
      source: "apache",
      extensions: ["ras"]
    },
    "image/x-cmx": {
      source: "apache",
      extensions: ["cmx"]
    },
    "image/x-freehand": {
      source: "apache",
      extensions: ["fh", "fhc", "fh4", "fh5", "fh7"]
    },
    "image/x-icon": {
      source: "apache",
      compressible: !0,
      extensions: ["ico"]
    },
    "image/x-jng": {
      source: "nginx",
      extensions: ["jng"]
    },
    "image/x-mrsid-image": {
      source: "apache",
      extensions: ["sid"]
    },
    "image/x-ms-bmp": {
      source: "nginx",
      compressible: !0,
      extensions: ["bmp"]
    },
    "image/x-pcx": {
      source: "apache",
      extensions: ["pcx"]
    },
    "image/x-pict": {
      source: "apache",
      extensions: ["pic", "pct"]
    },
    "image/x-portable-anymap": {
      source: "apache",
      extensions: ["pnm"]
    },
    "image/x-portable-bitmap": {
      source: "apache",
      extensions: ["pbm"]
    },
    "image/x-portable-graymap": {
      source: "apache",
      extensions: ["pgm"]
    },
    "image/x-portable-pixmap": {
      source: "apache",
      extensions: ["ppm"]
    },
    "image/x-rgb": {
      source: "apache",
      extensions: ["rgb"]
    },
    "image/x-tga": {
      source: "apache",
      extensions: ["tga"]
    },
    "image/x-xbitmap": {
      source: "apache",
      extensions: ["xbm"]
    },
    "image/x-xcf": {
      compressible: !1
    },
    "image/x-xpixmap": {
      source: "apache",
      extensions: ["xpm"]
    },
    "image/x-xwindowdump": {
      source: "apache",
      extensions: ["xwd"]
    },
    "message/cpim": {
      source: "iana"
    },
    "message/delivery-status": {
      source: "iana"
    },
    "message/disposition-notification": {
      source: "iana",
      extensions: [
        "disposition-notification"
      ]
    },
    "message/external-body": {
      source: "iana"
    },
    "message/feedback-report": {
      source: "iana"
    },
    "message/global": {
      source: "iana",
      extensions: ["u8msg"]
    },
    "message/global-delivery-status": {
      source: "iana",
      extensions: ["u8dsn"]
    },
    "message/global-disposition-notification": {
      source: "iana",
      extensions: ["u8mdn"]
    },
    "message/global-headers": {
      source: "iana",
      extensions: ["u8hdr"]
    },
    "message/http": {
      source: "iana",
      compressible: !1
    },
    "message/imdn+xml": {
      source: "iana",
      compressible: !0
    },
    "message/news": {
      source: "iana"
    },
    "message/partial": {
      source: "iana",
      compressible: !1
    },
    "message/rfc822": {
      source: "iana",
      compressible: !0,
      extensions: ["eml", "mime"]
    },
    "message/s-http": {
      source: "iana"
    },
    "message/sip": {
      source: "iana"
    },
    "message/sipfrag": {
      source: "iana"
    },
    "message/tracking-status": {
      source: "iana"
    },
    "message/vnd.si.simp": {
      source: "iana"
    },
    "message/vnd.wfa.wsc": {
      source: "iana",
      extensions: ["wsc"]
    },
    "model/3mf": {
      source: "iana",
      extensions: ["3mf"]
    },
    "model/e57": {
      source: "iana"
    },
    "model/gltf+json": {
      source: "iana",
      compressible: !0,
      extensions: ["gltf"]
    },
    "model/gltf-binary": {
      source: "iana",
      compressible: !0,
      extensions: ["glb"]
    },
    "model/iges": {
      source: "iana",
      compressible: !1,
      extensions: ["igs", "iges"]
    },
    "model/mesh": {
      source: "iana",
      compressible: !1,
      extensions: ["msh", "mesh", "silo"]
    },
    "model/mtl": {
      source: "iana",
      extensions: ["mtl"]
    },
    "model/obj": {
      source: "iana",
      extensions: ["obj"]
    },
    "model/step": {
      source: "iana"
    },
    "model/step+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["stpx"]
    },
    "model/step+zip": {
      source: "iana",
      compressible: !1,
      extensions: ["stpz"]
    },
    "model/step-xml+zip": {
      source: "iana",
      compressible: !1,
      extensions: ["stpxz"]
    },
    "model/stl": {
      source: "iana",
      extensions: ["stl"]
    },
    "model/vnd.collada+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["dae"]
    },
    "model/vnd.dwf": {
      source: "iana",
      extensions: ["dwf"]
    },
    "model/vnd.flatland.3dml": {
      source: "iana"
    },
    "model/vnd.gdl": {
      source: "iana",
      extensions: ["gdl"]
    },
    "model/vnd.gs-gdl": {
      source: "apache"
    },
    "model/vnd.gs.gdl": {
      source: "iana"
    },
    "model/vnd.gtw": {
      source: "iana",
      extensions: ["gtw"]
    },
    "model/vnd.moml+xml": {
      source: "iana",
      compressible: !0
    },
    "model/vnd.mts": {
      source: "iana",
      extensions: ["mts"]
    },
    "model/vnd.opengex": {
      source: "iana",
      extensions: ["ogex"]
    },
    "model/vnd.parasolid.transmit.binary": {
      source: "iana",
      extensions: ["x_b"]
    },
    "model/vnd.parasolid.transmit.text": {
      source: "iana",
      extensions: ["x_t"]
    },
    "model/vnd.pytha.pyox": {
      source: "iana"
    },
    "model/vnd.rosette.annotated-data-model": {
      source: "iana"
    },
    "model/vnd.sap.vds": {
      source: "iana",
      extensions: ["vds"]
    },
    "model/vnd.usdz+zip": {
      source: "iana",
      compressible: !1,
      extensions: ["usdz"]
    },
    "model/vnd.valve.source.compiled-map": {
      source: "iana",
      extensions: ["bsp"]
    },
    "model/vnd.vtu": {
      source: "iana",
      extensions: ["vtu"]
    },
    "model/vrml": {
      source: "iana",
      compressible: !1,
      extensions: ["wrl", "vrml"]
    },
    "model/x3d+binary": {
      source: "apache",
      compressible: !1,
      extensions: ["x3db", "x3dbz"]
    },
    "model/x3d+fastinfoset": {
      source: "iana",
      extensions: ["x3db"]
    },
    "model/x3d+vrml": {
      source: "apache",
      compressible: !1,
      extensions: ["x3dv", "x3dvz"]
    },
    "model/x3d+xml": {
      source: "iana",
      compressible: !0,
      extensions: ["x3d", "x3dz"]
    },
    "model/x3d-vrml": {
      source: "iana",
      extensions: ["x3dv"]
    },
    "multipart/alternative": {
      source: "iana",
      compressible: !1
    },
    "multipart/appledouble": {
      source: "iana"
    },
    "multipart/byteranges": {
      source: "iana"
    },
    "multipart/digest": {
      source: "iana"
    },
    "multipart/encrypted": {
      source: "iana",
      compressible: !1
    },
    "multipart/form-data": {
      source: "iana",
      compressible: !1
    },
    "multipart/header-set": {
      source: "iana"
    },
    "multipart/mixed": {
      source: "iana"
    },
    "multipart/multilingual": {
      source: "iana"
    },
    "multipart/parallel": {
      source: "iana"
    },
    "multipart/related": {
      source: "iana",
      compressible: !1
    },
    "multipart/report": {
      source: "iana"
    },
    "multipart/signed": {
      source: "iana",
      compressible: !1
    },
    "multipart/vnd.bint.med-plus": {
      source: "iana"
    },
    "multipart/voice-message": {
      source: "iana"
    },
    "multipart/x-mixed-replace": {
      source: "iana"
    },
    "text/1d-interleaved-parityfec": {
      source: "iana"
    },
    "text/cache-manifest": {
      source: "iana",
      compressible: !0,
      extensions: ["appcache", "manifest"]
    },
    "text/calendar": {
      source: "iana",
      extensions: ["ics", "ifb"]
    },
    "text/calender": {
      compressible: !0
    },
    "text/cmd": {
      compressible: !0
    },
    "text/coffeescript": {
      extensions: ["coffee", "litcoffee"]
    },
    "text/cql": {
      source: "iana"
    },
    "text/cql-expression": {
      source: "iana"
    },
    "text/cql-identifier": {
      source: "iana"
    },
    "text/css": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["css"]
    },
    "text/csv": {
      source: "iana",
      compressible: !0,
      extensions: ["csv"]
    },
    "text/csv-schema": {
      source: "iana"
    },
    "text/directory": {
      source: "iana"
    },
    "text/dns": {
      source: "iana"
    },
    "text/ecmascript": {
      source: "iana"
    },
    "text/encaprtp": {
      source: "iana"
    },
    "text/enriched": {
      source: "iana"
    },
    "text/fhirpath": {
      source: "iana"
    },
    "text/flexfec": {
      source: "iana"
    },
    "text/fwdred": {
      source: "iana"
    },
    "text/gff3": {
      source: "iana"
    },
    "text/grammar-ref-list": {
      source: "iana"
    },
    "text/html": {
      source: "iana",
      compressible: !0,
      extensions: ["html", "htm", "shtml"]
    },
    "text/jade": {
      extensions: ["jade"]
    },
    "text/javascript": {
      source: "iana",
      compressible: !0
    },
    "text/jcr-cnd": {
      source: "iana"
    },
    "text/jsx": {
      compressible: !0,
      extensions: ["jsx"]
    },
    "text/less": {
      compressible: !0,
      extensions: ["less"]
    },
    "text/markdown": {
      source: "iana",
      compressible: !0,
      extensions: ["markdown", "md"]
    },
    "text/mathml": {
      source: "nginx",
      extensions: ["mml"]
    },
    "text/mdx": {
      compressible: !0,
      extensions: ["mdx"]
    },
    "text/mizar": {
      source: "iana"
    },
    "text/n3": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["n3"]
    },
    "text/parameters": {
      source: "iana",
      charset: "UTF-8"
    },
    "text/parityfec": {
      source: "iana"
    },
    "text/plain": {
      source: "iana",
      compressible: !0,
      extensions: ["txt", "text", "conf", "def", "list", "log", "in", "ini"]
    },
    "text/provenance-notation": {
      source: "iana",
      charset: "UTF-8"
    },
    "text/prs.fallenstein.rst": {
      source: "iana"
    },
    "text/prs.lines.tag": {
      source: "iana",
      extensions: ["dsc"]
    },
    "text/prs.prop.logic": {
      source: "iana"
    },
    "text/raptorfec": {
      source: "iana"
    },
    "text/red": {
      source: "iana"
    },
    "text/rfc822-headers": {
      source: "iana"
    },
    "text/richtext": {
      source: "iana",
      compressible: !0,
      extensions: ["rtx"]
    },
    "text/rtf": {
      source: "iana",
      compressible: !0,
      extensions: ["rtf"]
    },
    "text/rtp-enc-aescm128": {
      source: "iana"
    },
    "text/rtploopback": {
      source: "iana"
    },
    "text/rtx": {
      source: "iana"
    },
    "text/sgml": {
      source: "iana",
      extensions: ["sgml", "sgm"]
    },
    "text/shaclc": {
      source: "iana"
    },
    "text/shex": {
      source: "iana",
      extensions: ["shex"]
    },
    "text/slim": {
      extensions: ["slim", "slm"]
    },
    "text/spdx": {
      source: "iana",
      extensions: ["spdx"]
    },
    "text/strings": {
      source: "iana"
    },
    "text/stylus": {
      extensions: ["stylus", "styl"]
    },
    "text/t140": {
      source: "iana"
    },
    "text/tab-separated-values": {
      source: "iana",
      compressible: !0,
      extensions: ["tsv"]
    },
    "text/troff": {
      source: "iana",
      extensions: ["t", "tr", "roff", "man", "me", "ms"]
    },
    "text/turtle": {
      source: "iana",
      charset: "UTF-8",
      extensions: ["ttl"]
    },
    "text/ulpfec": {
      source: "iana"
    },
    "text/uri-list": {
      source: "iana",
      compressible: !0,
      extensions: ["uri", "uris", "urls"]
    },
    "text/vcard": {
      source: "iana",
      compressible: !0,
      extensions: ["vcard"]
    },
    "text/vnd.a": {
      source: "iana"
    },
    "text/vnd.abc": {
      source: "iana"
    },
    "text/vnd.ascii-art": {
      source: "iana"
    },
    "text/vnd.curl": {
      source: "iana",
      extensions: ["curl"]
    },
    "text/vnd.curl.dcurl": {
      source: "apache",
      extensions: ["dcurl"]
    },
    "text/vnd.curl.mcurl": {
      source: "apache",
      extensions: ["mcurl"]
    },
    "text/vnd.curl.scurl": {
      source: "apache",
      extensions: ["scurl"]
    },
    "text/vnd.debian.copyright": {
      source: "iana",
      charset: "UTF-8"
    },
    "text/vnd.dmclientscript": {
      source: "iana"
    },
    "text/vnd.dvb.subtitle": {
      source: "iana",
      extensions: ["sub"]
    },
    "text/vnd.esmertec.theme-descriptor": {
      source: "iana",
      charset: "UTF-8"
    },
    "text/vnd.familysearch.gedcom": {
      source: "iana",
      extensions: ["ged"]
    },
    "text/vnd.ficlab.flt": {
      source: "iana"
    },
    "text/vnd.fly": {
      source: "iana",
      extensions: ["fly"]
    },
    "text/vnd.fmi.flexstor": {
      source: "iana",
      extensions: ["flx"]
    },
    "text/vnd.gml": {
      source: "iana"
    },
    "text/vnd.graphviz": {
      source: "iana",
      extensions: ["gv"]
    },
    "text/vnd.hans": {
      source: "iana"
    },
    "text/vnd.hgl": {
      source: "iana"
    },
    "text/vnd.in3d.3dml": {
      source: "iana",
      extensions: ["3dml"]
    },
    "text/vnd.in3d.spot": {
      source: "iana",
      extensions: ["spot"]
    },
    "text/vnd.iptc.newsml": {
      source: "iana"
    },
    "text/vnd.iptc.nitf": {
      source: "iana"
    },
    "text/vnd.latex-z": {
      source: "iana"
    },
    "text/vnd.motorola.reflex": {
      source: "iana"
    },
    "text/vnd.ms-mediapackage": {
      source: "iana"
    },
    "text/vnd.net2phone.commcenter.command": {
      source: "iana"
    },
    "text/vnd.radisys.msml-basic-layout": {
      source: "iana"
    },
    "text/vnd.senx.warpscript": {
      source: "iana"
    },
    "text/vnd.si.uricatalogue": {
      source: "iana"
    },
    "text/vnd.sosi": {
      source: "iana"
    },
    "text/vnd.sun.j2me.app-descriptor": {
      source: "iana",
      charset: "UTF-8",
      extensions: ["jad"]
    },
    "text/vnd.trolltech.linguist": {
      source: "iana",
      charset: "UTF-8"
    },
    "text/vnd.wap.si": {
      source: "iana"
    },
    "text/vnd.wap.sl": {
      source: "iana"
    },
    "text/vnd.wap.wml": {
      source: "iana",
      extensions: ["wml"]
    },
    "text/vnd.wap.wmlscript": {
      source: "iana",
      extensions: ["wmls"]
    },
    "text/vtt": {
      source: "iana",
      charset: "UTF-8",
      compressible: !0,
      extensions: ["vtt"]
    },
    "text/x-asm": {
      source: "apache",
      extensions: ["s", "asm"]
    },
    "text/x-c": {
      source: "apache",
      extensions: ["c", "cc", "cxx", "cpp", "h", "hh", "dic"]
    },
    "text/x-component": {
      source: "nginx",
      extensions: ["htc"]
    },
    "text/x-fortran": {
      source: "apache",
      extensions: ["f", "for", "f77", "f90"]
    },
    "text/x-gwt-rpc": {
      compressible: !0
    },
    "text/x-handlebars-template": {
      extensions: ["hbs"]
    },
    "text/x-java-source": {
      source: "apache",
      extensions: ["java"]
    },
    "text/x-jquery-tmpl": {
      compressible: !0
    },
    "text/x-lua": {
      extensions: ["lua"]
    },
    "text/x-markdown": {
      compressible: !0,
      extensions: ["mkd"]
    },
    "text/x-nfo": {
      source: "apache",
      extensions: ["nfo"]
    },
    "text/x-opml": {
      source: "apache",
      extensions: ["opml"]
    },
    "text/x-org": {
      compressible: !0,
      extensions: ["org"]
    },
    "text/x-pascal": {
      source: "apache",
      extensions: ["p", "pas"]
    },
    "text/x-processing": {
      compressible: !0,
      extensions: ["pde"]
    },
    "text/x-sass": {
      extensions: ["sass"]
    },
    "text/x-scss": {
      extensions: ["scss"]
    },
    "text/x-setext": {
      source: "apache",
      extensions: ["etx"]
    },
    "text/x-sfv": {
      source: "apache",
      extensions: ["sfv"]
    },
    "text/x-suse-ymp": {
      compressible: !0,
      extensions: ["ymp"]
    },
    "text/x-uuencode": {
      source: "apache",
      extensions: ["uu"]
    },
    "text/x-vcalendar": {
      source: "apache",
      extensions: ["vcs"]
    },
    "text/x-vcard": {
      source: "apache",
      extensions: ["vcf"]
    },
    "text/xml": {
      source: "iana",
      compressible: !0,
      extensions: ["xml"]
    },
    "text/xml-external-parsed-entity": {
      source: "iana"
    },
    "text/yaml": {
      compressible: !0,
      extensions: ["yaml", "yml"]
    },
    "video/1d-interleaved-parityfec": {
      source: "iana"
    },
    "video/3gpp": {
      source: "iana",
      extensions: ["3gp", "3gpp"]
    },
    "video/3gpp-tt": {
      source: "iana"
    },
    "video/3gpp2": {
      source: "iana",
      extensions: ["3g2"]
    },
    "video/av1": {
      source: "iana"
    },
    "video/bmpeg": {
      source: "iana"
    },
    "video/bt656": {
      source: "iana"
    },
    "video/celb": {
      source: "iana"
    },
    "video/dv": {
      source: "iana"
    },
    "video/encaprtp": {
      source: "iana"
    },
    "video/ffv1": {
      source: "iana"
    },
    "video/flexfec": {
      source: "iana"
    },
    "video/h261": {
      source: "iana",
      extensions: ["h261"]
    },
    "video/h263": {
      source: "iana",
      extensions: ["h263"]
    },
    "video/h263-1998": {
      source: "iana"
    },
    "video/h263-2000": {
      source: "iana"
    },
    "video/h264": {
      source: "iana",
      extensions: ["h264"]
    },
    "video/h264-rcdo": {
      source: "iana"
    },
    "video/h264-svc": {
      source: "iana"
    },
    "video/h265": {
      source: "iana"
    },
    "video/iso.segment": {
      source: "iana",
      extensions: ["m4s"]
    },
    "video/jpeg": {
      source: "iana",
      extensions: ["jpgv"]
    },
    "video/jpeg2000": {
      source: "iana"
    },
    "video/jpm": {
      source: "apache",
      extensions: ["jpm", "jpgm"]
    },
    "video/jxsv": {
      source: "iana"
    },
    "video/mj2": {
      source: "iana",
      extensions: ["mj2", "mjp2"]
    },
    "video/mp1s": {
      source: "iana"
    },
    "video/mp2p": {
      source: "iana"
    },
    "video/mp2t": {
      source: "iana",
      extensions: ["ts"]
    },
    "video/mp4": {
      source: "iana",
      compressible: !1,
      extensions: ["mp4", "mp4v", "mpg4"]
    },
    "video/mp4v-es": {
      source: "iana"
    },
    "video/mpeg": {
      source: "iana",
      compressible: !1,
      extensions: ["mpeg", "mpg", "mpe", "m1v", "m2v"]
    },
    "video/mpeg4-generic": {
      source: "iana"
    },
    "video/mpv": {
      source: "iana"
    },
    "video/nv": {
      source: "iana"
    },
    "video/ogg": {
      source: "iana",
      compressible: !1,
      extensions: ["ogv"]
    },
    "video/parityfec": {
      source: "iana"
    },
    "video/pointer": {
      source: "iana"
    },
    "video/quicktime": {
      source: "iana",
      compressible: !1,
      extensions: ["qt", "mov"]
    },
    "video/raptorfec": {
      source: "iana"
    },
    "video/raw": {
      source: "iana"
    },
    "video/rtp-enc-aescm128": {
      source: "iana"
    },
    "video/rtploopback": {
      source: "iana"
    },
    "video/rtx": {
      source: "iana"
    },
    "video/scip": {
      source: "iana"
    },
    "video/smpte291": {
      source: "iana"
    },
    "video/smpte292m": {
      source: "iana"
    },
    "video/ulpfec": {
      source: "iana"
    },
    "video/vc1": {
      source: "iana"
    },
    "video/vc2": {
      source: "iana"
    },
    "video/vnd.cctv": {
      source: "iana"
    },
    "video/vnd.dece.hd": {
      source: "iana",
      extensions: ["uvh", "uvvh"]
    },
    "video/vnd.dece.mobile": {
      source: "iana",
      extensions: ["uvm", "uvvm"]
    },
    "video/vnd.dece.mp4": {
      source: "iana"
    },
    "video/vnd.dece.pd": {
      source: "iana",
      extensions: ["uvp", "uvvp"]
    },
    "video/vnd.dece.sd": {
      source: "iana",
      extensions: ["uvs", "uvvs"]
    },
    "video/vnd.dece.video": {
      source: "iana",
      extensions: ["uvv", "uvvv"]
    },
    "video/vnd.directv.mpeg": {
      source: "iana"
    },
    "video/vnd.directv.mpeg-tts": {
      source: "iana"
    },
    "video/vnd.dlna.mpeg-tts": {
      source: "iana"
    },
    "video/vnd.dvb.file": {
      source: "iana",
      extensions: ["dvb"]
    },
    "video/vnd.fvt": {
      source: "iana",
      extensions: ["fvt"]
    },
    "video/vnd.hns.video": {
      source: "iana"
    },
    "video/vnd.iptvforum.1dparityfec-1010": {
      source: "iana"
    },
    "video/vnd.iptvforum.1dparityfec-2005": {
      source: "iana"
    },
    "video/vnd.iptvforum.2dparityfec-1010": {
      source: "iana"
    },
    "video/vnd.iptvforum.2dparityfec-2005": {
      source: "iana"
    },
    "video/vnd.iptvforum.ttsavc": {
      source: "iana"
    },
    "video/vnd.iptvforum.ttsmpeg2": {
      source: "iana"
    },
    "video/vnd.motorola.video": {
      source: "iana"
    },
    "video/vnd.motorola.videop": {
      source: "iana"
    },
    "video/vnd.mpegurl": {
      source: "iana",
      extensions: ["mxu", "m4u"]
    },
    "video/vnd.ms-playready.media.pyv": {
      source: "iana",
      extensions: ["pyv"]
    },
    "video/vnd.nokia.interleaved-multimedia": {
      source: "iana"
    },
    "video/vnd.nokia.mp4vr": {
      source: "iana"
    },
    "video/vnd.nokia.videovoip": {
      source: "iana"
    },
    "video/vnd.objectvideo": {
      source: "iana"
    },
    "video/vnd.radgamettools.bink": {
      source: "iana"
    },
    "video/vnd.radgamettools.smacker": {
      source: "iana"
    },
    "video/vnd.sealed.mpeg1": {
      source: "iana"
    },
    "video/vnd.sealed.mpeg4": {
      source: "iana"
    },
    "video/vnd.sealed.swf": {
      source: "iana"
    },
    "video/vnd.sealedmedia.softseal.mov": {
      source: "iana"
    },
    "video/vnd.uvvu.mp4": {
      source: "iana",
      extensions: ["uvu", "uvvu"]
    },
    "video/vnd.vivo": {
      source: "iana",
      extensions: ["viv"]
    },
    "video/vnd.youtube.yt": {
      source: "iana"
    },
    "video/vp8": {
      source: "iana"
    },
    "video/vp9": {
      source: "iana"
    },
    "video/webm": {
      source: "apache",
      compressible: !1,
      extensions: ["webm"]
    },
    "video/x-f4v": {
      source: "apache",
      extensions: ["f4v"]
    },
    "video/x-fli": {
      source: "apache",
      extensions: ["fli"]
    },
    "video/x-flv": {
      source: "apache",
      compressible: !1,
      extensions: ["flv"]
    },
    "video/x-m4v": {
      source: "apache",
      extensions: ["m4v"]
    },
    "video/x-matroska": {
      source: "apache",
      compressible: !1,
      extensions: ["mkv", "mk3d", "mks"]
    },
    "video/x-mng": {
      source: "apache",
      extensions: ["mng"]
    },
    "video/x-ms-asf": {
      source: "apache",
      extensions: ["asf", "asx"]
    },
    "video/x-ms-vob": {
      source: "apache",
      extensions: ["vob"]
    },
    "video/x-ms-wm": {
      source: "apache",
      extensions: ["wm"]
    },
    "video/x-ms-wmv": {
      source: "apache",
      compressible: !1,
      extensions: ["wmv"]
    },
    "video/x-ms-wmx": {
      source: "apache",
      extensions: ["wmx"]
    },
    "video/x-ms-wvx": {
      source: "apache",
      extensions: ["wvx"]
    },
    "video/x-msvideo": {
      source: "apache",
      extensions: ["avi"]
    },
    "video/x-sgi-movie": {
      source: "apache",
      extensions: ["movie"]
    },
    "video/x-smv": {
      source: "apache",
      extensions: ["smv"]
    },
    "x-conference/x-cooltalk": {
      source: "apache",
      extensions: ["ice"]
    },
    "x-shader/x-fragment": {
      compressible: !0
    },
    "x-shader/x-vertex": {
      compressible: !0
    }
  };
});

// node_modules/.pnpm/mime-db@1.52.0/node_modules/mime-db/index.js
var ec = _((o0, Zo) => {
  "use strict";
  c();
  Zo.exports = Xo();
});

// node_modules/.pnpm/mime-types@2.1.35/node_modules/mime-types/index.js
var rc = _((be) => {
  "use strict";
  c();
  var ar = ec(), Fh = require("path").extname, tc = /^\s*([^;\s]*)(?:;|\s|$)/, Nh = /^text\//i;
  be.charset = nc;
  be.charsets = { lookup: nc };
  be.contentType = Bh;
  be.extension = zh;
  be.extensions = /* @__PURE__ */ Object.create(null);
  be.lookup = Hh;
  be.types = /* @__PURE__ */ Object.create(null);
  Mh(be.extensions, be.types);
  function nc(e) {
    if (!e || typeof e != "string")
      return !1;
    var t = tc.exec(e), n = t && ar[t[1].toLowerCase()];
    return n && n.charset ? n.charset : t && Nh.test(t[1]) ? "UTF-8" : !1;
  }
  function Bh(e) {
    if (!e || typeof e != "string")
      return !1;
    var t = e.indexOf("/") === -1 ? be.lookup(e) : e;
    if (!t)
      return !1;
    if (t.indexOf("charset") === -1) {
      var n = be.charset(t);
      n && (t += "; charset=" + n.toLowerCase());
    }
    return t;
  }
  function zh(e) {
    if (!e || typeof e != "string")
      return !1;
    var t = tc.exec(e), n = t && be.extensions[t[1].toLowerCase()];
    return !n || !n.length ? !1 : n[0];
  }
  function Hh(e) {
    if (!e || typeof e != "string")
      return !1;
    var t = Fh("x." + e).toLowerCase().substr(1);
    return t && be.types[t] || !1;
  }
  function Mh(e, t) {
    var n = ["nginx", "apache", void 0, "iana"];
    Object.keys(ar).forEach(function(i) {
      var s = ar[i], a = s.extensions;
      if (!(!a || !a.length)) {
        e[i] = a;
        for (var o = 0; o < a.length; o++) {
          var l = a[o];
          if (t[l]) {
            var p = n.indexOf(ar[t[l]].source), u = n.indexOf(s.source);
            if (t[l] !== "application/octet-stream" && (p > u || p === u && t[l].substr(0, 12) === "application/"))
              continue;
          }
          t[l] = i;
        }
      }
    });
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/lib/defer.js
var sc = _((p0, ic) => {
  "use strict";
  c();
  ic.exports = $h;
  function $h(e) {
    var t = typeof setImmediate == "function" ? setImmediate : typeof process == "object" && typeof process.nextTick == "function" ? process.nextTick : null;
    t ? t(e) : setTimeout(e, 0);
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/lib/async.js
var Ti = _((f0, oc) => {
  "use strict";
  c();
  var ac = sc();
  oc.exports = Vh;
  function Vh(e) {
    var t = !1;
    return ac(function() {
      t = !0;
    }), function(r, i) {
      t ? e(r, i) : ac(function() {
        e(r, i);
      });
    };
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/lib/abort.js
var ki = _((h0, cc) => {
  "use strict";
  c();
  cc.exports = Wh;
  function Wh(e) {
    Object.keys(e.jobs).forEach(Gh.bind(e)), e.jobs = {};
  }
  function Gh(e) {
    typeof this.jobs[e] == "function" && this.jobs[e]();
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/lib/iterate.js
var Ci = _((g0, uc) => {
  "use strict";
  c();
  var lc = Ti(), Kh = ki();
  uc.exports = Jh;
  function Jh(e, t, n, r) {
    var i = n.keyedList ? n.keyedList[n.index] : n.index;
    n.jobs[i] = Yh(t, i, e[i], function(s, a) {
      i in n.jobs && (delete n.jobs[i], s ? Kh(n) : n.results[i] = a, r(s, n.results));
    });
  }
  function Yh(e, t, n, r) {
    var i;
    return e.length == 2 ? i = e(n, lc(r)) : i = e(n, t, lc(r)), i;
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/lib/state.js
var Ai = _((v0, pc) => {
  "use strict";
  c();
  pc.exports = Qh;
  function Qh(e, t) {
    var n = !Array.isArray(e), r = {
      index: 0,
      keyedList: n || t ? Object.keys(e) : null,
      jobs: {},
      results: n ? {} : [],
      size: n ? Object.keys(e).length : e.length
    };
    return t && r.keyedList.sort(n ? t : function(i, s) {
      return t(e[i], e[s]);
    }), r;
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/lib/terminator.js
var Oi = _((w0, dc) => {
  "use strict";
  c();
  var Xh = ki(), Zh = Ti();
  dc.exports = ex;
  function ex(e) {
    Object.keys(this.jobs).length && (this.index = this.size, Xh(this), Zh(e)(null, this.results));
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/parallel.js
var mc = _((E0, fc) => {
  "use strict";
  c();
  var tx = Ci(), nx = Ai(), rx = Oi();
  fc.exports = ix;
  function ix(e, t, n) {
    for (var r = nx(e); r.index < (r.keyedList || e).length; )
      tx(e, t, r, function(i, s) {
        if (i) {
          n(i, s);
          return;
        }
        if (Object.keys(r.jobs).length === 0) {
          n(null, r.results);
          return;
        }
      }), r.index++;
    return rx.bind(r, n);
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/serialOrdered.js
var Pi = _((R0, or) => {
  "use strict";
  c();
  var hc = Ci(), sx = Ai(), ax = Oi();
  or.exports = ox;
  or.exports.ascending = xc;
  or.exports.descending = cx;
  function ox(e, t, n, r) {
    var i = sx(e, n);
    return hc(e, t, i, function s(a, o) {
      if (a) {
        r(a, o);
        return;
      }
      if (i.index++, i.index < (i.keyedList || e).length) {
        hc(e, t, i, s);
        return;
      }
      r(null, i.results);
    }), ax.bind(i, r);
  }
  function xc(e, t) {
    return e < t ? -1 : e > t ? 1 : 0;
  }
  function cx(e, t) {
    return -1 * xc(e, t);
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/serial.js
var yc = _((k0, gc) => {
  "use strict";
  c();
  var lx = Pi();
  gc.exports = ux;
  function ux(e, t, n) {
    return lx(e, t, null, n);
  }
});

// node_modules/.pnpm/asynckit@0.4.0/node_modules/asynckit/index.js
var bc = _((A0, vc) => {
  "use strict";
  c();
  vc.exports = {
    parallel: mc(),
    serial: yc(),
    serialOrdered: Pi()
  };
});

// node_modules/.pnpm/es-object-atoms@1.1.2/node_modules/es-object-atoms/index.js
var ji = _((P0, wc) => {
  "use strict";
  c();
  wc.exports = Object;
});

// node_modules/.pnpm/es-errors@1.3.0/node_modules/es-errors/index.js
var Ec = _((q0, _c) => {
  "use strict";
  c();
  _c.exports = Error;
});

// node_modules/.pnpm/es-errors@1.3.0/node_modules/es-errors/eval.js
var Rc = _((U0, Sc) => {
  "use strict";
  c();
  Sc.exports = EvalError;
});

// node_modules/.pnpm/es-errors@1.3.0/node_modules/es-errors/range.js
var kc = _((I0, Tc) => {
  "use strict";
  c();
  Tc.exports = RangeError;
});

// node_modules/.pnpm/es-errors@1.3.0/node_modules/es-errors/ref.js
var Ac = _((N0, Cc) => {
  "use strict";
  c();
  Cc.exports = ReferenceError;
});

// node_modules/.pnpm/es-errors@1.3.0/node_modules/es-errors/syntax.js
var Pc = _((z0, Oc) => {
  "use strict";
  c();
  Oc.exports = SyntaxError;
});

// node_modules/.pnpm/es-errors@1.3.0/node_modules/es-errors/type.js
var cr = _((M0, jc) => {
  "use strict";
  c();
  jc.exports = TypeError;
});

// node_modules/.pnpm/es-errors@1.3.0/node_modules/es-errors/uri.js
var Lc = _((V0, qc) => {
  "use strict";
  c();
  qc.exports = URIError;
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/abs.js
var Dc = _((G0, Uc) => {
  "use strict";
  c();
  Uc.exports = Math.abs;
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/floor.js
var Fc = _((J0, Ic) => {
  "use strict";
  c();
  Ic.exports = Math.floor;
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/max.js
var Bc = _((Q0, Nc) => {
  "use strict";
  c();
  Nc.exports = Math.max;
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/min.js
var Hc = _((Z0, zc) => {
  "use strict";
  c();
  zc.exports = Math.min;
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/pow.js
var $c = _((tS, Mc) => {
  "use strict";
  c();
  Mc.exports = Math.pow;
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/round.js
var Wc = _((rS, Vc) => {
  "use strict";
  c();
  Vc.exports = Math.round;
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/isNaN.js
var Kc = _((sS, Gc) => {
  "use strict";
  c();
  Gc.exports = Number.isNaN || function(t) {
    return t !== t;
  };
});

// node_modules/.pnpm/math-intrinsics@1.1.0/node_modules/math-intrinsics/sign.js
var Yc = _((oS, Jc) => {
  "use strict";
  c();
  var px = Kc();
  Jc.exports = function(t) {
    return px(t) || t === 0 ? t : t < 0 ? -1 : 1;
  };
});

// node_modules/.pnpm/gopd@1.2.0/node_modules/gopd/gOPD.js
var Xc = _((lS, Qc) => {
  "use strict";
  c();
  Qc.exports = Object.getOwnPropertyDescriptor;
});

// node_modules/.pnpm/gopd@1.2.0/node_modules/gopd/index.js
var qi = _((pS, Zc) => {
  "use strict";
  c();
  var lr = Xc();
  if (lr)
    try {
      lr([], "length");
    } catch {
      lr = null;
    }
  Zc.exports = lr;
});

// node_modules/.pnpm/es-define-property@1.0.1/node_modules/es-define-property/index.js
var tl = _((fS, el) => {
  "use strict";
  c();
  var ur = Object.defineProperty || !1;
  if (ur)
    try {
      ur({}, "a", { value: 1 });
    } catch {
      ur = !1;
    }
  el.exports = ur;
});

// node_modules/.pnpm/has-symbols@1.1.0/node_modules/has-symbols/shams.js
var Li = _((hS, nl) => {
  "use strict";
  c();
  nl.exports = function() {
    if (typeof Symbol != "function" || typeof Object.getOwnPropertySymbols != "function")
      return !1;
    if (typeof Symbol.iterator == "symbol")
      return !0;
    var t = {}, n = /* @__PURE__ */ Symbol("test"), r = Object(n);
    if (typeof n == "string" || Object.prototype.toString.call(n) !== "[object Symbol]" || Object.prototype.toString.call(r) !== "[object Symbol]")
      return !1;
    var i = 42;
    t[n] = i;
    for (var s in t)
      return !1;
    if (typeof Object.keys == "function" && Object.keys(t).length !== 0 || typeof Object.getOwnPropertyNames == "function" && Object.getOwnPropertyNames(t).length !== 0)
      return !1;
    var a = Object.getOwnPropertySymbols(t);
    if (a.length !== 1 || a[0] !== n || !Object.prototype.propertyIsEnumerable.call(t, n))
      return !1;
    if (typeof Object.getOwnPropertyDescriptor == "function") {
      var o = (
        /** @type {PropertyDescriptor} */
        Object.getOwnPropertyDescriptor(t, n)
      );
      if (o.value !== i || o.enumerable !== !0)
        return !1;
    }
    return !0;
  };
});

// node_modules/.pnpm/has-symbols@1.1.0/node_modules/has-symbols/index.js
var sl = _((gS, il) => {
  "use strict";
  c();
  var rl = typeof Symbol < "u" && Symbol, dx = Li();
  il.exports = function() {
    return typeof rl != "function" || typeof Symbol != "function" || typeof rl("foo") != "symbol" || typeof /* @__PURE__ */ Symbol("bar") != "symbol" ? !1 : dx();
  };
});

// node_modules/.pnpm/get-proto@1.0.1/node_modules/get-proto/Reflect.getPrototypeOf.js
var Ui = _((vS, al) => {
  "use strict";
  c();
  al.exports = typeof Reflect < "u" && Reflect.getPrototypeOf || null;
});

// node_modules/.pnpm/get-proto@1.0.1/node_modules/get-proto/Object.getPrototypeOf.js
var Di = _((wS, ol) => {
  "use strict";
  c();
  var fx = ji();
  ol.exports = fx.getPrototypeOf || null;
});

// node_modules/.pnpm/function-bind@1.1.2/node_modules/function-bind/implementation.js
var ul = _((ES, ll) => {
  "use strict";
  c();
  var mx = "Function.prototype.bind called on incompatible ", hx = Object.prototype.toString, xx = Math.max, gx = "[object Function]", cl = function(t, n) {
    for (var r = [], i = 0; i < t.length; i += 1)
      r[i] = t[i];
    for (var s = 0; s < n.length; s += 1)
      r[s + t.length] = n[s];
    return r;
  }, yx = function(t, n) {
    for (var r = [], i = n || 0, s = 0; i < t.length; i += 1, s += 1)
      r[s] = t[i];
    return r;
  }, vx = function(e, t) {
    for (var n = "", r = 0; r < e.length; r += 1)
      n += e[r], r + 1 < e.length && (n += t);
    return n;
  };
  ll.exports = function(t) {
    var n = this;
    if (typeof n != "function" || hx.apply(n) !== gx)
      throw new TypeError(mx + n);
    for (var r = yx(arguments, 1), i, s = function() {
      if (this instanceof i) {
        var u = n.apply(
          this,
          cl(r, arguments)
        );
        return Object(u) === u ? u : this;
      }
      return n.apply(
        t,
        cl(r, arguments)
      );
    }, a = xx(0, n.length - r.length), o = [], l = 0; l < a; l++)
      o[l] = "$" + l;
    if (i = Function("binder", "return function (" + vx(o, ",") + "){ return binder.apply(this,arguments); }")(s), n.prototype) {
      var p = function() {
      };
      p.prototype = n.prototype, i.prototype = new p(), p.prototype = null;
    }
    return i;
  };
});

// node_modules/.pnpm/function-bind@1.1.2/node_modules/function-bind/index.js
var yn = _((RS, pl) => {
  "use strict";
  c();
  var bx = ul();
  pl.exports = Function.prototype.bind || bx;
});

// node_modules/.pnpm/call-bind-apply-helpers@1.0.2/node_modules/call-bind-apply-helpers/functionCall.js
var pr = _((kS, dl) => {
  "use strict";
  c();
  dl.exports = Function.prototype.call;
});

// node_modules/.pnpm/call-bind-apply-helpers@1.0.2/node_modules/call-bind-apply-helpers/functionApply.js
var Ii = _((AS, fl) => {
  "use strict";
  c();
  fl.exports = Function.prototype.apply;
});

// node_modules/.pnpm/call-bind-apply-helpers@1.0.2/node_modules/call-bind-apply-helpers/reflectApply.js
var hl = _((PS, ml) => {
  "use strict";
  c();
  ml.exports = typeof Reflect < "u" && Reflect && Reflect.apply;
});

// node_modules/.pnpm/call-bind-apply-helpers@1.0.2/node_modules/call-bind-apply-helpers/actualApply.js
var gl = _((qS, xl) => {
  "use strict";
  c();
  var wx = yn(), _x = Ii(), Ex = pr(), Sx = hl();
  xl.exports = Sx || wx.call(Ex, _x);
});

// node_modules/.pnpm/call-bind-apply-helpers@1.0.2/node_modules/call-bind-apply-helpers/index.js
var vl = _((US, yl) => {
  "use strict";
  c();
  var Rx = yn(), Tx = cr(), kx = pr(), Cx = gl();
  yl.exports = function(t) {
    if (t.length < 1 || typeof t[0] != "function")
      throw new Tx("a function is required");
    return Cx(Rx, kx, t);
  };
});

// node_modules/.pnpm/dunder-proto@1.0.1/node_modules/dunder-proto/get.js
var Rl = _((IS, Sl) => {
  "use strict";
  c();
  var Ax = vl(), bl = qi(), _l;
  try {
    _l = /** @type {{ __proto__?: typeof Array.prototype }} */
    [].__proto__ === Array.prototype;
  } catch (e) {
    if (!e || typeof e != "object" || !("code" in e) || e.code !== "ERR_PROTO_ACCESS")
      throw e;
  }
  var Fi = !!_l && bl && bl(
    Object.prototype,
    /** @type {keyof typeof Object.prototype} */
    "__proto__"
  ), El = Object, wl = El.getPrototypeOf;
  Sl.exports = Fi && typeof Fi.get == "function" ? Ax([Fi.get]) : typeof wl == "function" ? (
    /** @type {import('./get')} */
    function(t) {
      return wl(t == null ? t : El(t));
    }
  ) : !1;
});

// node_modules/.pnpm/get-proto@1.0.1/node_modules/get-proto/index.js
var Ol = _((NS, Al) => {
  "use strict";
  c();
  var Tl = Ui(), kl = Di(), Cl = Rl();
  Al.exports = Tl ? function(t) {
    return Tl(t);
  } : kl ? function(t) {
    if (!t || typeof t != "object" && typeof t != "function")
      throw new TypeError("getProto: not an object");
    return kl(t);
  } : Cl ? function(t) {
    return Cl(t);
  } : null;
});

// node_modules/.pnpm/hasown@2.0.3/node_modules/hasown/index.js
var dr = _((zS, Pl) => {
  "use strict";
  c();
  var Ox = Function.prototype.call, Px = Object.prototype.hasOwnProperty, jx = yn();
  Pl.exports = jx.call(Ox, Px);
});

// node_modules/.pnpm/get-intrinsic@1.3.0/node_modules/get-intrinsic/index.js
var Fl = _((MS, Il) => {
  "use strict";
  c();
  var P, qx = ji(), Lx = Ec(), Ux = Rc(), Dx = kc(), Ix = Ac(), zt = Pc(), Bt = cr(), Fx = Lc(), Nx = Dc(), Bx = Fc(), zx = Bc(), Hx = Hc(), Mx = $c(), $x = Wc(), Vx = Yc(), Ul = Function, Ni = function(e) {
    try {
      return Ul('"use strict"; return (' + e + ").constructor;")();
    } catch {
    }
  }, vn = qi(), Wx = tl(), Bi = function() {
    throw new Bt();
  }, Gx = vn ? (function() {
    try {
      return arguments.callee, Bi;
    } catch {
      try {
        return vn(arguments, "callee").get;
      } catch {
        return Bi;
      }
    }
  })() : Bi, Ft = sl()(), ae = Ol(), Kx = Di(), Jx = Ui(), Dl = Ii(), bn = pr(), Nt = {}, Yx = typeof Uint8Array > "u" || !ae ? P : ae(Uint8Array), gt = {
    __proto__: null,
    "%AggregateError%": typeof AggregateError > "u" ? P : AggregateError,
    "%Array%": Array,
    "%ArrayBuffer%": typeof ArrayBuffer > "u" ? P : ArrayBuffer,
    "%ArrayIteratorPrototype%": Ft && ae ? ae([][Symbol.iterator]()) : P,
    "%AsyncFromSyncIteratorPrototype%": P,
    "%AsyncFunction%": Nt,
    "%AsyncGenerator%": Nt,
    "%AsyncGeneratorFunction%": Nt,
    "%AsyncIteratorPrototype%": Nt,
    "%Atomics%": typeof Atomics > "u" ? P : Atomics,
    "%BigInt%": typeof BigInt > "u" ? P : BigInt,
    "%BigInt64Array%": typeof BigInt64Array > "u" ? P : BigInt64Array,
    "%BigUint64Array%": typeof BigUint64Array > "u" ? P : BigUint64Array,
    "%Boolean%": Boolean,
    "%DataView%": typeof DataView > "u" ? P : DataView,
    "%Date%": Date,
    "%decodeURI%": decodeURI,
    "%decodeURIComponent%": decodeURIComponent,
    "%encodeURI%": encodeURI,
    "%encodeURIComponent%": encodeURIComponent,
    "%Error%": Lx,
    "%eval%": eval,
    // eslint-disable-line no-eval
    "%EvalError%": Ux,
    "%Float16Array%": typeof Float16Array > "u" ? P : Float16Array,
    "%Float32Array%": typeof Float32Array > "u" ? P : Float32Array,
    "%Float64Array%": typeof Float64Array > "u" ? P : Float64Array,
    "%FinalizationRegistry%": typeof FinalizationRegistry > "u" ? P : FinalizationRegistry,
    "%Function%": Ul,
    "%GeneratorFunction%": Nt,
    "%Int8Array%": typeof Int8Array > "u" ? P : Int8Array,
    "%Int16Array%": typeof Int16Array > "u" ? P : Int16Array,
    "%Int32Array%": typeof Int32Array > "u" ? P : Int32Array,
    "%isFinite%": isFinite,
    "%isNaN%": isNaN,
    "%IteratorPrototype%": Ft && ae ? ae(ae([][Symbol.iterator]())) : P,
    "%JSON%": typeof JSON == "object" ? JSON : P,
    "%Map%": typeof Map > "u" ? P : Map,
    "%MapIteratorPrototype%": typeof Map > "u" || !Ft || !ae ? P : ae((/* @__PURE__ */ new Map())[Symbol.iterator]()),
    "%Math%": Math,
    "%Number%": Number,
    "%Object%": qx,
    "%Object.getOwnPropertyDescriptor%": vn,
    "%parseFloat%": parseFloat,
    "%parseInt%": parseInt,
    "%Promise%": typeof Promise > "u" ? P : Promise,
    "%Proxy%": typeof Proxy > "u" ? P : Proxy,
    "%RangeError%": Dx,
    "%ReferenceError%": Ix,
    "%Reflect%": typeof Reflect > "u" ? P : Reflect,
    "%RegExp%": RegExp,
    "%Set%": typeof Set > "u" ? P : Set,
    "%SetIteratorPrototype%": typeof Set > "u" || !Ft || !ae ? P : ae((/* @__PURE__ */ new Set())[Symbol.iterator]()),
    "%SharedArrayBuffer%": typeof SharedArrayBuffer > "u" ? P : SharedArrayBuffer,
    "%String%": String,
    "%StringIteratorPrototype%": Ft && ae ? ae(""[Symbol.iterator]()) : P,
    "%Symbol%": Ft ? Symbol : P,
    "%SyntaxError%": zt,
    "%ThrowTypeError%": Gx,
    "%TypedArray%": Yx,
    "%TypeError%": Bt,
    "%Uint8Array%": typeof Uint8Array > "u" ? P : Uint8Array,
    "%Uint8ClampedArray%": typeof Uint8ClampedArray > "u" ? P : Uint8ClampedArray,
    "%Uint16Array%": typeof Uint16Array > "u" ? P : Uint16Array,
    "%Uint32Array%": typeof Uint32Array > "u" ? P : Uint32Array,
    "%URIError%": Fx,
    "%WeakMap%": typeof WeakMap > "u" ? P : WeakMap,
    "%WeakRef%": typeof WeakRef > "u" ? P : WeakRef,
    "%WeakSet%": typeof WeakSet > "u" ? P : WeakSet,
    "%Function.prototype.call%": bn,
    "%Function.prototype.apply%": Dl,
    "%Object.defineProperty%": Wx,
    "%Object.getPrototypeOf%": Kx,
    "%Math.abs%": Nx,
    "%Math.floor%": Bx,
    "%Math.max%": zx,
    "%Math.min%": Hx,
    "%Math.pow%": Mx,
    "%Math.round%": $x,
    "%Math.sign%": Vx,
    "%Reflect.getPrototypeOf%": Jx
  };
  if (ae)
    try {
      null.error;
    } catch (e) {
      jl = ae(ae(e)), gt["%Error.prototype%"] = jl;
    }
  var jl, Qx = function e(t) {
    var n;
    if (t === "%AsyncFunction%")
      n = Ni("async function () {}");
    else if (t === "%GeneratorFunction%")
      n = Ni("function* () {}");
    else if (t === "%AsyncGeneratorFunction%")
      n = Ni("async function* () {}");
    else if (t === "%AsyncGenerator%") {
      var r = e("%AsyncGeneratorFunction%");
      r && (n = r.prototype);
    } else if (t === "%AsyncIteratorPrototype%") {
      var i = e("%AsyncGenerator%");
      i && ae && (n = ae(i.prototype));
    }
    return gt[t] = n, n;
  }, ql = {
    __proto__: null,
    "%ArrayBufferPrototype%": ["ArrayBuffer", "prototype"],
    "%ArrayPrototype%": ["Array", "prototype"],
    "%ArrayProto_entries%": ["Array", "prototype", "entries"],
    "%ArrayProto_forEach%": ["Array", "prototype", "forEach"],
    "%ArrayProto_keys%": ["Array", "prototype", "keys"],
    "%ArrayProto_values%": ["Array", "prototype", "values"],
    "%AsyncFunctionPrototype%": ["AsyncFunction", "prototype"],
    "%AsyncGenerator%": ["AsyncGeneratorFunction", "prototype"],
    "%AsyncGeneratorPrototype%": ["AsyncGeneratorFunction", "prototype", "prototype"],
    "%BooleanPrototype%": ["Boolean", "prototype"],
    "%DataViewPrototype%": ["DataView", "prototype"],
    "%DatePrototype%": ["Date", "prototype"],
    "%ErrorPrototype%": ["Error", "prototype"],
    "%EvalErrorPrototype%": ["EvalError", "prototype"],
    "%Float32ArrayPrototype%": ["Float32Array", "prototype"],
    "%Float64ArrayPrototype%": ["Float64Array", "prototype"],
    "%FunctionPrototype%": ["Function", "prototype"],
    "%Generator%": ["GeneratorFunction", "prototype"],
    "%GeneratorPrototype%": ["GeneratorFunction", "prototype", "prototype"],
    "%Int8ArrayPrototype%": ["Int8Array", "prototype"],
    "%Int16ArrayPrototype%": ["Int16Array", "prototype"],
    "%Int32ArrayPrototype%": ["Int32Array", "prototype"],
    "%JSONParse%": ["JSON", "parse"],
    "%JSONStringify%": ["JSON", "stringify"],
    "%MapPrototype%": ["Map", "prototype"],
    "%NumberPrototype%": ["Number", "prototype"],
    "%ObjectPrototype%": ["Object", "prototype"],
    "%ObjProto_toString%": ["Object", "prototype", "toString"],
    "%ObjProto_valueOf%": ["Object", "prototype", "valueOf"],
    "%PromisePrototype%": ["Promise", "prototype"],
    "%PromiseProto_then%": ["Promise", "prototype", "then"],
    "%Promise_all%": ["Promise", "all"],
    "%Promise_reject%": ["Promise", "reject"],
    "%Promise_resolve%": ["Promise", "resolve"],
    "%RangeErrorPrototype%": ["RangeError", "prototype"],
    "%ReferenceErrorPrototype%": ["ReferenceError", "prototype"],
    "%RegExpPrototype%": ["RegExp", "prototype"],
    "%SetPrototype%": ["Set", "prototype"],
    "%SharedArrayBufferPrototype%": ["SharedArrayBuffer", "prototype"],
    "%StringPrototype%": ["String", "prototype"],
    "%SymbolPrototype%": ["Symbol", "prototype"],
    "%SyntaxErrorPrototype%": ["SyntaxError", "prototype"],
    "%TypedArrayPrototype%": ["TypedArray", "prototype"],
    "%TypeErrorPrototype%": ["TypeError", "prototype"],
    "%Uint8ArrayPrototype%": ["Uint8Array", "prototype"],
    "%Uint8ClampedArrayPrototype%": ["Uint8ClampedArray", "prototype"],
    "%Uint16ArrayPrototype%": ["Uint16Array", "prototype"],
    "%Uint32ArrayPrototype%": ["Uint32Array", "prototype"],
    "%URIErrorPrototype%": ["URIError", "prototype"],
    "%WeakMapPrototype%": ["WeakMap", "prototype"],
    "%WeakSetPrototype%": ["WeakSet", "prototype"]
  }, wn = yn(), fr = dr(), Xx = wn.call(bn, Array.prototype.concat), Zx = wn.call(Dl, Array.prototype.splice), Ll = wn.call(bn, String.prototype.replace), mr = wn.call(bn, String.prototype.slice), eg = wn.call(bn, RegExp.prototype.exec), tg = /[^%.[\]]+|\[(?:(-?\d+(?:\.\d+)?)|(["'])((?:(?!\2)[^\\]|\\.)*?)\2)\]|(?=(?:\.|\[\])(?:\.|\[\]|%$))/g, ng = /\\(\\)?/g, rg = function(t) {
    var n = mr(t, 0, 1), r = mr(t, -1);
    if (n === "%" && r !== "%")
      throw new zt("invalid intrinsic syntax, expected closing `%`");
    if (r === "%" && n !== "%")
      throw new zt("invalid intrinsic syntax, expected opening `%`");
    var i = [];
    return Ll(t, tg, function(s, a, o, l) {
      i[i.length] = o ? Ll(l, ng, "$1") : a || s;
    }), i;
  }, ig = function(t, n) {
    var r = t, i;
    if (fr(ql, r) && (i = ql[r], r = "%" + i[0] + "%"), fr(gt, r)) {
      var s = gt[r];
      if (s === Nt && (s = Qx(r)), typeof s > "u" && !n)
        throw new Bt("intrinsic " + t + " exists, but is not available. Please file an issue!");
      return {
        alias: i,
        name: r,
        value: s
      };
    }
    throw new zt("intrinsic " + t + " does not exist!");
  };
  Il.exports = function(t, n) {
    if (typeof t != "string" || t.length === 0)
      throw new Bt("intrinsic name must be a non-empty string");
    if (arguments.length > 1 && typeof n != "boolean")
      throw new Bt('"allowMissing" argument must be a boolean');
    if (eg(/^%?[^%]*%?$/, t) === null)
      throw new zt("`%` may not be present anywhere but at the beginning and end of the intrinsic name");
    var r = rg(t), i = r.length > 0 ? r[0] : "", s = ig("%" + i + "%", n), a = s.name, o = s.value, l = !1, p = s.alias;
    p && (i = p[0], Zx(r, Xx([0, 1], p)));
    for (var u = 1, d = !0; u < r.length; u += 1) {
      var m = r[u], x = mr(m, 0, 1), b = mr(m, -1);
      if ((x === '"' || x === "'" || x === "`" || b === '"' || b === "'" || b === "`") && x !== b)
        throw new zt("property names with quotes must have matching quotes");
      if ((m === "constructor" || !d) && (l = !0), i += "." + m, a = "%" + i + "%", fr(gt, a))
        o = gt[a];
      else if (o != null) {
        if (!(m in o)) {
          if (!n)
            throw new Bt("base intrinsic for " + t + " exists, but the property is not available.");
          return;
        }
        if (vn && u + 1 >= r.length) {
          var v = vn(o, m);
          d = !!v, d && "get" in v && !("originalValue" in v.get) ? o = v.get : o = o[m];
        } else
          d = fr(o, m), o = o[m];
        d && !l && (gt[a] = o);
      }
    }
    return o;
  };
});

// node_modules/.pnpm/has-tostringtag@1.0.2/node_modules/has-tostringtag/shams.js
var Bl = _((VS, Nl) => {
  "use strict";
  c();
  var sg = Li();
  Nl.exports = function() {
    return sg() && !!Symbol.toStringTag;
  };
});

// node_modules/.pnpm/es-set-tostringtag@2.1.0/node_modules/es-set-tostringtag/index.js
var Ml = _((GS, Hl) => {
  "use strict";
  c();
  var ag = Fl(), zl = ag("%Object.defineProperty%", !0), og = Bl()(), cg = dr(), lg = cr(), hr = og ? Symbol.toStringTag : null;
  Hl.exports = function(t, n) {
    var r = arguments.length > 2 && !!arguments[2] && arguments[2].force, i = arguments.length > 2 && !!arguments[2] && arguments[2].nonConfigurable;
    if (typeof r < "u" && typeof r != "boolean" || typeof i < "u" && typeof i != "boolean")
      throw new lg("if provided, the `overrideIfSet` and `nonConfigurable` options must be booleans");
    hr && (r || !cg(t, hr)) && (zl ? zl(t, hr, {
      configurable: !i,
      enumerable: !1,
      value: n,
      writable: !1
    }) : t[hr] = n);
  };
});

// node_modules/.pnpm/form-data@4.0.5/node_modules/form-data/lib/populate.js
var Vl = _((JS, $l) => {
  "use strict";
  c();
  $l.exports = function(e, t) {
    return Object.keys(t).forEach(function(n) {
      e[n] = e[n] || t[n];
    }), e;
  };
});

// node_modules/.pnpm/form-data@4.0.5/node_modules/form-data/lib/form_data.js
var Gl = _((QS, Wl) => {
  "use strict";
  c();
  var $i = Qo(), ug = require("util"), zi = require("path"), pg = require("http"), dg = require("https"), fg = require("url").parse, mg = require("fs"), hg = require("stream").Stream, xg = require("crypto"), Hi = rc(), gg = bc(), yg = Ml(), it = dr(), Mi = Vl();
  function j(e) {
    if (!(this instanceof j))
      return new j(e);
    this._overheadLength = 0, this._valueLength = 0, this._valuesToMeasure = [], $i.call(this), e = e || {};
    for (var t in e)
      this[t] = e[t];
  }
  ug.inherits(j, $i);
  j.LINE_BREAK = `\r
`;
  j.DEFAULT_CONTENT_TYPE = "application/octet-stream";
  j.prototype.append = function(e, t, n) {
    n = n || {}, typeof n == "string" && (n = { filename: n });
    var r = $i.prototype.append.bind(this);
    if ((typeof t == "number" || t == null) && (t = String(t)), Array.isArray(t)) {
      this._error(new Error("Arrays are not supported."));
      return;
    }
    var i = this._multiPartHeader(e, t, n), s = this._multiPartFooter();
    r(i), r(t), r(s), this._trackLength(i, t, n);
  };
  j.prototype._trackLength = function(e, t, n) {
    var r = 0;
    n.knownLength != null ? r += Number(n.knownLength) : Buffer.isBuffer(t) ? r = t.length : typeof t == "string" && (r = Buffer.byteLength(t)), this._valueLength += r, this._overheadLength += Buffer.byteLength(e) + j.LINE_BREAK.length, !(!t || !t.path && !(t.readable && it(t, "httpVersion")) && !(t instanceof hg)) && (n.knownLength || this._valuesToMeasure.push(t));
  };
  j.prototype._lengthRetriever = function(e, t) {
    it(e, "fd") ? e.end != null && e.end != 1 / 0 && e.start != null ? t(null, e.end + 1 - (e.start ? e.start : 0)) : mg.stat(e.path, function(n, r) {
      if (n) {
        t(n);
        return;
      }
      var i = r.size - (e.start ? e.start : 0);
      t(null, i);
    }) : it(e, "httpVersion") ? t(null, Number(e.headers["content-length"])) : it(e, "httpModule") ? (e.on("response", function(n) {
      e.pause(), t(null, Number(n.headers["content-length"]));
    }), e.resume()) : t("Unknown stream");
  };
  j.prototype._multiPartHeader = function(e, t, n) {
    if (typeof n.header == "string")
      return n.header;
    var r = this._getContentDisposition(t, n), i = this._getContentType(t, n), s = "", a = {
      // add custom disposition as third element or keep it two elements if not
      "Content-Disposition": ["form-data", 'name="' + e + '"'].concat(r || []),
      // if no content type. allow it to be empty array
      "Content-Type": [].concat(i || [])
    };
    typeof n.header == "object" && Mi(a, n.header);
    var o;
    for (var l in a)
      if (it(a, l)) {
        if (o = a[l], o == null)
          continue;
        Array.isArray(o) || (o = [o]), o.length && (s += l + ": " + o.join("; ") + j.LINE_BREAK);
      }
    return "--" + this.getBoundary() + j.LINE_BREAK + s + j.LINE_BREAK;
  };
  j.prototype._getContentDisposition = function(e, t) {
    var n;
    if (typeof t.filepath == "string" ? n = zi.normalize(t.filepath).replace(/\\/g, "/") : t.filename || e && (e.name || e.path) ? n = zi.basename(t.filename || e && (e.name || e.path)) : e && e.readable && it(e, "httpVersion") && (n = zi.basename(e.client._httpMessage.path || "")), n)
      return 'filename="' + n + '"';
  };
  j.prototype._getContentType = function(e, t) {
    var n = t.contentType;
    return !n && e && e.name && (n = Hi.lookup(e.name)), !n && e && e.path && (n = Hi.lookup(e.path)), !n && e && e.readable && it(e, "httpVersion") && (n = e.headers["content-type"]), !n && (t.filepath || t.filename) && (n = Hi.lookup(t.filepath || t.filename)), !n && e && typeof e == "object" && (n = j.DEFAULT_CONTENT_TYPE), n;
  };
  j.prototype._multiPartFooter = function() {
    return function(e) {
      var t = j.LINE_BREAK, n = this._streams.length === 0;
      n && (t += this._lastBoundary()), e(t);
    }.bind(this);
  };
  j.prototype._lastBoundary = function() {
    return "--" + this.getBoundary() + "--" + j.LINE_BREAK;
  };
  j.prototype.getHeaders = function(e) {
    var t, n = {
      "content-type": "multipart/form-data; boundary=" + this.getBoundary()
    };
    for (t in e)
      it(e, t) && (n[t.toLowerCase()] = e[t]);
    return n;
  };
  j.prototype.setBoundary = function(e) {
    if (typeof e != "string")
      throw new TypeError("FormData boundary must be a string");
    this._boundary = e;
  };
  j.prototype.getBoundary = function() {
    return this._boundary || this._generateBoundary(), this._boundary;
  };
  j.prototype.getBuffer = function() {
    for (var e = new Buffer.alloc(0), t = this.getBoundary(), n = 0, r = this._streams.length; n < r; n++)
      typeof this._streams[n] != "function" && (Buffer.isBuffer(this._streams[n]) ? e = Buffer.concat([e, this._streams[n]]) : e = Buffer.concat([e, Buffer.from(this._streams[n])]), (typeof this._streams[n] != "string" || this._streams[n].substring(2, t.length + 2) !== t) && (e = Buffer.concat([e, Buffer.from(j.LINE_BREAK)])));
    return Buffer.concat([e, Buffer.from(this._lastBoundary())]);
  };
  j.prototype._generateBoundary = function() {
    this._boundary = "--------------------------" + xg.randomBytes(12).toString("hex");
  };
  j.prototype.getLengthSync = function() {
    var e = this._overheadLength + this._valueLength;
    return this._streams.length && (e += this._lastBoundary().length), this.hasKnownLength() || this._error(new Error("Cannot calculate proper length in synchronous way.")), e;
  };
  j.prototype.hasKnownLength = function() {
    var e = !0;
    return this._valuesToMeasure.length && (e = !1), e;
  };
  j.prototype.getLength = function(e) {
    var t = this._overheadLength + this._valueLength;
    if (this._streams.length && (t += this._lastBoundary().length), !this._valuesToMeasure.length) {
      process.nextTick(e.bind(this, null, t));
      return;
    }
    gg.parallel(this._valuesToMeasure, this._lengthRetriever, function(n, r) {
      if (n) {
        e(n);
        return;
      }
      r.forEach(function(i) {
        t += i;
      }), e(null, t);
    });
  };
  j.prototype.submit = function(e, t) {
    var n, r, i = { method: "post" };
    return typeof e == "string" ? (e = fg(e), r = Mi({
      port: e.port,
      path: e.pathname,
      host: e.hostname,
      protocol: e.protocol
    }, i)) : (r = Mi(e, i), r.port || (r.port = r.protocol === "https:" ? 443 : 80)), r.headers = this.getHeaders(e.headers), r.protocol === "https:" ? n = dg.request(r) : n = pg.request(r), this.getLength(function(s, a) {
      if (s && s !== "Unknown stream") {
        this._error(s);
        return;
      }
      if (a && n.setHeader("Content-Length", a), this.pipe(n), t) {
        var o, l = function(p, u) {
          return n.removeListener("error", l), n.removeListener("response", o), t.call(this, p, u);
        };
        o = l.bind(this, null), n.on("error", l), n.on("response", o);
      }
    }.bind(this)), n;
  };
  j.prototype._error = function(e) {
    this.error || (this.error = e, this.pause(), this.emit("error", e));
  };
  j.prototype.toString = function() {
    return "[object FormData]";
  };
  yg(j.prototype, "FormData");
  Wl.exports = j;
});

// node_modules/.pnpm/ms@2.1.3/node_modules/ms/index.js
var cu = _((mT, ou) => {
  "use strict";
  c();
  var $t = 1e3, Vt = $t * 60, Wt = Vt * 60, bt = Wt * 24, Lg = bt * 7, Ug = bt * 365.25;
  ou.exports = function(e, t) {
    t = t || {};
    var n = typeof e;
    if (n === "string" && e.length > 0)
      return Dg(e);
    if (n === "number" && isFinite(e))
      return t.long ? Fg(e) : Ig(e);
    throw new Error(
      "val is not a non-empty string or a valid number. val=" + JSON.stringify(e)
    );
  };
  function Dg(e) {
    if (e = String(e), !(e.length > 100)) {
      var t = /^(-?(?:\d+)?\.?\d+) *(milliseconds?|msecs?|ms|seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)?$/i.exec(
        e
      );
      if (t) {
        var n = parseFloat(t[1]), r = (t[2] || "ms").toLowerCase();
        switch (r) {
          case "years":
          case "year":
          case "yrs":
          case "yr":
          case "y":
            return n * Ug;
          case "weeks":
          case "week":
          case "w":
            return n * Lg;
          case "days":
          case "day":
          case "d":
            return n * bt;
          case "hours":
          case "hour":
          case "hrs":
          case "hr":
          case "h":
            return n * Wt;
          case "minutes":
          case "minute":
          case "mins":
          case "min":
          case "m":
            return n * Vt;
          case "seconds":
          case "second":
          case "secs":
          case "sec":
          case "s":
            return n * $t;
          case "milliseconds":
          case "millisecond":
          case "msecs":
          case "msec":
          case "ms":
            return n;
          default:
            return;
        }
      }
    }
  }
  function Ig(e) {
    var t = Math.abs(e);
    return t >= bt ? Math.round(e / bt) + "d" : t >= Wt ? Math.round(e / Wt) + "h" : t >= Vt ? Math.round(e / Vt) + "m" : t >= $t ? Math.round(e / $t) + "s" : e + "ms";
  }
  function Fg(e) {
    var t = Math.abs(e);
    return t >= bt ? yr(e, t, bt, "day") : t >= Wt ? yr(e, t, Wt, "hour") : t >= Vt ? yr(e, t, Vt, "minute") : t >= $t ? yr(e, t, $t, "second") : e + " ms";
  }
  function yr(e, t, n, r) {
    var i = t >= n * 1.5;
    return Math.round(e / n) + " " + r + (i ? "s" : "");
  }
});

// node_modules/.pnpm/debug@4.4.3/node_modules/debug/src/common.js
var ss = _((xT, lu) => {
  "use strict";
  c();
  function Ng(e) {
    n.debug = n, n.default = n, n.coerce = l, n.disable = a, n.enable = i, n.enabled = o, n.humanize = cu(), n.destroy = p, Object.keys(e).forEach((u) => {
      n[u] = e[u];
    }), n.names = [], n.skips = [], n.formatters = {};
    function t(u) {
      let d = 0;
      for (let m = 0; m < u.length; m++)
        d = (d << 5) - d + u.charCodeAt(m), d |= 0;
      return n.colors[Math.abs(d) % n.colors.length];
    }
    n.selectColor = t;
    function n(u) {
      let d, m = null, x, b;
      function v(...h) {
        if (!v.enabled)
          return;
        let w = v, T = Number(/* @__PURE__ */ new Date()), A = T - (d || T);
        w.diff = A, w.prev = d, w.curr = T, d = T, h[0] = n.coerce(h[0]), typeof h[0] != "string" && h.unshift("%O");
        let O = 0;
        h[0] = h[0].replace(/%([a-zA-Z%])/g, (W, ne) => {
          if (W === "%%")
            return "%";
          O++;
          let re = n.formatters[ne];
          if (typeof re == "function") {
            let Ce = h[O];
            W = re.call(w, Ce), h.splice(O, 1), O--;
          }
          return W;
        }), n.formatArgs.call(w, h), (w.log || n.log).apply(w, h);
      }
      return v.namespace = u, v.useColors = n.useColors(), v.color = n.selectColor(u), v.extend = r, v.destroy = n.destroy, Object.defineProperty(v, "enabled", {
        enumerable: !0,
        configurable: !1,
        get: () => m !== null ? m : (x !== n.namespaces && (x = n.namespaces, b = n.enabled(u)), b),
        set: (h) => {
          m = h;
        }
      }), typeof n.init == "function" && n.init(v), v;
    }
    function r(u, d) {
      let m = n(this.namespace + (typeof d > "u" ? ":" : d) + u);
      return m.log = this.log, m;
    }
    function i(u) {
      n.save(u), n.namespaces = u, n.names = [], n.skips = [];
      let d = (typeof u == "string" ? u : "").trim().replace(/\s+/g, ",").split(",").filter(Boolean);
      for (let m of d)
        m[0] === "-" ? n.skips.push(m.slice(1)) : n.names.push(m);
    }
    function s(u, d) {
      let m = 0, x = 0, b = -1, v = 0;
      for (; m < u.length; )
        if (x < d.length && (d[x] === u[m] || d[x] === "*"))
          d[x] === "*" ? (b = x, v = m, x++) : (m++, x++);
        else if (b !== -1)
          x = b + 1, v++, m = v;
        else
          return !1;
      for (; x < d.length && d[x] === "*"; )
        x++;
      return x === d.length;
    }
    function a() {
      let u = [
        ...n.names,
        ...n.skips.map((d) => "-" + d)
      ].join(",");
      return n.enable(""), u;
    }
    function o(u) {
      for (let d of n.skips)
        if (s(u, d))
          return !1;
      for (let d of n.names)
        if (s(u, d))
          return !0;
      return !1;
    }
    function l(u) {
      return u instanceof Error ? u.stack || u.message : u;
    }
    function p() {
      console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`.");
    }
    return n.enable(n.load()), n;
  }
  lu.exports = Ng;
});

// node_modules/.pnpm/debug@4.4.3/node_modules/debug/src/browser.js
var uu = _((we, vr) => {
  "use strict";
  c();
  we.formatArgs = zg;
  we.save = Hg;
  we.load = Mg;
  we.useColors = Bg;
  we.storage = $g();
  we.destroy = /* @__PURE__ */ (() => {
    let e = !1;
    return () => {
      e || (e = !0, console.warn("Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`."));
    };
  })();
  we.colors = [
    "#0000CC",
    "#0000FF",
    "#0033CC",
    "#0033FF",
    "#0066CC",
    "#0066FF",
    "#0099CC",
    "#0099FF",
    "#00CC00",
    "#00CC33",
    "#00CC66",
    "#00CC99",
    "#00CCCC",
    "#00CCFF",
    "#3300CC",
    "#3300FF",
    "#3333CC",
    "#3333FF",
    "#3366CC",
    "#3366FF",
    "#3399CC",
    "#3399FF",
    "#33CC00",
    "#33CC33",
    "#33CC66",
    "#33CC99",
    "#33CCCC",
    "#33CCFF",
    "#6600CC",
    "#6600FF",
    "#6633CC",
    "#6633FF",
    "#66CC00",
    "#66CC33",
    "#9900CC",
    "#9900FF",
    "#9933CC",
    "#9933FF",
    "#99CC00",
    "#99CC33",
    "#CC0000",
    "#CC0033",
    "#CC0066",
    "#CC0099",
    "#CC00CC",
    "#CC00FF",
    "#CC3300",
    "#CC3333",
    "#CC3366",
    "#CC3399",
    "#CC33CC",
    "#CC33FF",
    "#CC6600",
    "#CC6633",
    "#CC9900",
    "#CC9933",
    "#CCCC00",
    "#CCCC33",
    "#FF0000",
    "#FF0033",
    "#FF0066",
    "#FF0099",
    "#FF00CC",
    "#FF00FF",
    "#FF3300",
    "#FF3333",
    "#FF3366",
    "#FF3399",
    "#FF33CC",
    "#FF33FF",
    "#FF6600",
    "#FF6633",
    "#FF9900",
    "#FF9933",
    "#FFCC00",
    "#FFCC33"
  ];
  function Bg() {
    if (typeof window < "u" && window.process && (window.process.type === "renderer" || window.process.__nwjs))
      return !0;
    if (typeof navigator < "u" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/(edge|trident)\/(\d+)/))
      return !1;
    let e;
    return typeof document < "u" && document.documentElement && document.documentElement.style && document.documentElement.style.WebkitAppearance || // Is firebug? http://stackoverflow.com/a/398120/376773
    typeof window < "u" && window.console && (window.console.firebug || window.console.exception && window.console.table) || // Is firefox >= v31?
    // https://developer.mozilla.org/en-US/docs/Tools/Web_Console#Styling_messages
    typeof navigator < "u" && navigator.userAgent && (e = navigator.userAgent.toLowerCase().match(/firefox\/(\d+)/)) && parseInt(e[1], 10) >= 31 || // Double check webkit in userAgent just in case we are in a worker
    typeof navigator < "u" && navigator.userAgent && navigator.userAgent.toLowerCase().match(/applewebkit\/(\d+)/);
  }
  function zg(e) {
    if (e[0] = (this.useColors ? "%c" : "") + this.namespace + (this.useColors ? " %c" : " ") + e[0] + (this.useColors ? "%c " : " ") + "+" + vr.exports.humanize(this.diff), !this.useColors)
      return;
    let t = "color: " + this.color;
    e.splice(1, 0, t, "color: inherit");
    let n = 0, r = 0;
    e[0].replace(/%[a-zA-Z%]/g, (i) => {
      i !== "%%" && (n++, i === "%c" && (r = n));
    }), e.splice(r, 0, t);
  }
  we.log = console.debug || console.log || (() => {
  });
  function Hg(e) {
    try {
      e ? we.storage.setItem("debug", e) : we.storage.removeItem("debug");
    } catch {
    }
  }
  function Mg() {
    let e;
    try {
      e = we.storage.getItem("debug") || we.storage.getItem("DEBUG");
    } catch {
    }
    return !e && typeof process < "u" && "env" in process && (e = process.env.DEBUG), e;
  }
  function $g() {
    try {
      return localStorage;
    } catch {
    }
  }
  vr.exports = ss()(we);
  var { formatters: Vg } = vr.exports;
  Vg.j = function(e) {
    try {
      return JSON.stringify(e);
    } catch (t) {
      return "[UnexpectedJSONParseError]: " + t.message;
    }
  };
});

// node_modules/.pnpm/debug@4.4.3/node_modules/debug/src/node.js
var du = _((oe, wr) => {
  "use strict";
  c();
  var Wg = require("tty"), br = require("util");
  oe.init = Zg;
  oe.log = Yg;
  oe.formatArgs = Kg;
  oe.save = Qg;
  oe.load = Xg;
  oe.useColors = Gg;
  oe.destroy = br.deprecate(
    () => {
    },
    "Instance method `debug.destroy()` is deprecated and no longer does anything. It will be removed in the next major version of `debug`."
  );
  oe.colors = [6, 2, 3, 4, 5, 1];
  try {
    let e = require("supports-color");
    e && (e.stderr || e).level >= 2 && (oe.colors = [
      20,
      21,
      26,
      27,
      32,
      33,
      38,
      39,
      40,
      41,
      42,
      43,
      44,
      45,
      56,
      57,
      62,
      63,
      68,
      69,
      74,
      75,
      76,
      77,
      78,
      79,
      80,
      81,
      92,
      93,
      98,
      99,
      112,
      113,
      128,
      129,
      134,
      135,
      148,
      149,
      160,
      161,
      162,
      163,
      164,
      165,
      166,
      167,
      168,
      169,
      170,
      171,
      172,
      173,
      178,
      179,
      184,
      185,
      196,
      197,
      198,
      199,
      200,
      201,
      202,
      203,
      204,
      205,
      206,
      207,
      208,
      209,
      214,
      215,
      220,
      221
    ]);
  } catch {
  }
  oe.inspectOpts = Object.keys(process.env).filter((e) => /^debug_/i.test(e)).reduce((e, t) => {
    let n = t.substring(6).toLowerCase().replace(/_([a-z])/g, (i, s) => s.toUpperCase()), r = process.env[t];
    return /^(yes|on|true|enabled)$/i.test(r) ? r = !0 : /^(no|off|false|disabled)$/i.test(r) ? r = !1 : r === "null" ? r = null : r = Number(r), e[n] = r, e;
  }, {});
  function Gg() {
    return "colors" in oe.inspectOpts ? !!oe.inspectOpts.colors : Wg.isatty(process.stderr.fd);
  }
  function Kg(e) {
    let { namespace: t, useColors: n } = this;
    if (n) {
      let r = this.color, i = "\x1B[3" + (r < 8 ? r : "8;5;" + r), s = `  ${i};1m${t} \x1B[0m`;
      e[0] = s + e[0].split(`
`).join(`
` + s), e.push(i + "m+" + wr.exports.humanize(this.diff) + "\x1B[0m");
    } else
      e[0] = Jg() + t + " " + e[0];
  }
  function Jg() {
    return oe.inspectOpts.hideDate ? "" : (/* @__PURE__ */ new Date()).toISOString() + " ";
  }
  function Yg(...e) {
    return process.stderr.write(br.formatWithOptions(oe.inspectOpts, ...e) + `
`);
  }
  function Qg(e) {
    e ? process.env.DEBUG = e : delete process.env.DEBUG;
  }
  function Xg() {
    return process.env.DEBUG;
  }
  function Zg(e) {
    e.inspectOpts = {};
    let t = Object.keys(oe.inspectOpts);
    for (let n = 0; n < t.length; n++)
      e.inspectOpts[t[n]] = oe.inspectOpts[t[n]];
  }
  wr.exports = ss()(oe);
  var { formatters: pu } = wr.exports;
  pu.o = function(e) {
    return this.inspectOpts.colors = this.useColors, br.inspect(e, this.inspectOpts).split(`
`).map((t) => t.trim()).join(" ");
  };
  pu.O = function(e) {
    return this.inspectOpts.colors = this.useColors, br.inspect(e, this.inspectOpts);
  };
});

// node_modules/.pnpm/debug@4.4.3/node_modules/debug/src/index.js
var Sn = _((bT, as) => {
  "use strict";
  c();
  typeof process > "u" || process.type === "renderer" || process.browser === !0 || process.__nwjs ? as.exports = uu() : as.exports = du();
});

// node_modules/.pnpm/agent-base@6.0.0/node_modules/agent-base/dist/src/promisify.js
var fu = _((os) => {
  "use strict";
  c();
  Object.defineProperty(os, "__esModule", { value: !0 });
  function ey(e) {
    return function(t, n) {
      return new Promise((r, i) => {
        e.call(this, t, n, (s, a) => {
          s ? i(s) : r(a);
        });
      });
    };
  }
  os.default = ey;
});

// node_modules/.pnpm/agent-base@6.0.0/node_modules/agent-base/dist/src/index.js
var xu = _((ls, hu) => {
  "use strict";
  c();
  var mu = ls && ls.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  }, ty = require("events"), ny = mu(Sn()), ry = mu(fu()), Rn = ny.default("agent-base");
  function iy(e) {
    return !!e && typeof e.addRequest == "function";
  }
  function cs() {
    let { stack: e } = new Error();
    return typeof e != "string" ? !1 : e.split(`
`).some((t) => t.indexOf("(https.js:") !== -1);
  }
  function _r(e, t) {
    return new _r.Agent(e, t);
  }
  (function(e) {
    class t extends ty.EventEmitter {
      constructor(r, i) {
        super();
        let s = i;
        typeof r == "function" ? this.callback = r : r && (s = r), this.timeout = null, s && typeof s.timeout == "number" && (this.timeout = s.timeout), this.maxFreeSockets = 1, this.maxSockets = 1, this.sockets = {}, this.requests = {};
      }
      get defaultPort() {
        return typeof this.explicitDefaultPort == "number" ? this.explicitDefaultPort : cs() ? 443 : 80;
      }
      set defaultPort(r) {
        this.explicitDefaultPort = r;
      }
      get protocol() {
        return typeof this.explicitProtocol == "string" ? this.explicitProtocol : cs() ? "https:" : "http:";
      }
      set protocol(r) {
        this.explicitProtocol = r;
      }
      callback(r, i, s) {
        throw new Error('"agent-base" has no default implementation, you must subclass and override `callback()`');
      }
      /**
       * Called by node-core's "_http_client.js" module when creating
       * a new HTTP request with this Agent instance.
       *
       * @api public
       */
      addRequest(r, i) {
        let s = Object.assign({}, i);
        typeof s.secureEndpoint != "boolean" && (s.secureEndpoint = cs()), s.host == null && (s.host = "localhost"), s.port == null && (s.port = s.secureEndpoint ? 443 : 80), s.protocol == null && (s.protocol = s.secureEndpoint ? "https:" : "http:"), s.host && s.path && delete s.path, delete s.agent, delete s.hostname, delete s._defaultAgent, delete s.defaultPort, delete s.createConnection, r._last = !0, r.shouldKeepAlive = !1;
        let a = !1, o = null, l = s.timeout || this.timeout, p = (x) => {
          r._hadError || (r.emit("error", x), r._hadError = !0);
        }, u = () => {
          o = null, a = !0;
          let x = new Error(`A "socket" was not created for HTTP request before ${l}ms`);
          x.code = "ETIMEOUT", p(x);
        }, d = (x) => {
          a || (o !== null && (clearTimeout(o), o = null), p(x));
        }, m = (x) => {
          if (a)
            return;
          if (o != null && (clearTimeout(o), o = null), iy(x)) {
            Rn("Callback returned another Agent instance %o", x.constructor.name), x.addRequest(r, s);
            return;
          }
          if (x) {
            x.once("free", () => {
              this.freeSocket(x, s);
            }), r.onSocket(x);
            return;
          }
          let b = new Error(`no Duplex stream was returned to agent-base for \`${r.method} ${r.path}\``);
          p(b);
        };
        if (typeof this.callback != "function") {
          p(new Error("`callback` is not defined"));
          return;
        }
        this.promisifiedCallback || (this.callback.length >= 3 ? (Rn("Converting legacy callback function to promise"), this.promisifiedCallback = ry.default(this.callback)) : this.promisifiedCallback = this.callback), typeof l == "number" && l > 0 && (o = setTimeout(u, l)), "port" in s && typeof s.port != "number" && (s.port = Number(s.port));
        try {
          Rn("Resolving socket for %o request: %o", s.protocol, `${r.method} ${r.path}`), Promise.resolve(this.promisifiedCallback(r, s)).then(m, d);
        } catch (x) {
          Promise.reject(x).catch(d);
        }
      }
      freeSocket(r, i) {
        Rn("Freeing socket %o %o", r.constructor.name, i), r.destroy();
      }
      destroy() {
        Rn("Destroying agent %o", this.constructor.name);
      }
    }
    e.Agent = t, e.prototype = e.Agent.prototype;
  })(_r || (_r = {}));
  hu.exports = _r;
});

// node_modules/.pnpm/https-proxy-agent@5.0.1/node_modules/https-proxy-agent/dist/parse-proxy-response.js
var gu = _((kn) => {
  "use strict";
  c();
  var sy = kn && kn.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  };
  Object.defineProperty(kn, "__esModule", { value: !0 });
  var ay = sy(Sn()), Tn = ay.default("https-proxy-agent:parse-proxy-response");
  function oy(e) {
    return new Promise((t, n) => {
      let r = 0, i = [];
      function s() {
        let d = e.read();
        d ? u(d) : e.once("readable", s);
      }
      function a() {
        e.removeListener("end", l), e.removeListener("error", p), e.removeListener("close", o), e.removeListener("readable", s);
      }
      function o(d) {
        Tn("onclose had error %o", d);
      }
      function l() {
        Tn("onend");
      }
      function p(d) {
        a(), Tn("onerror %o", d), n(d);
      }
      function u(d) {
        i.push(d), r += d.length;
        let m = Buffer.concat(i, r);
        if (m.indexOf(`\r
\r
`) === -1) {
          Tn("have not received end of HTTP headers yet..."), s();
          return;
        }
        let b = m.toString("ascii", 0, m.indexOf(`\r
`)), v = +b.split(" ")[1];
        Tn("got proxy server response: %o", b), t({
          statusCode: v,
          buffered: m
        });
      }
      e.on("error", p), e.on("close", o), e.on("end", l), s();
    });
  }
  kn.default = oy;
});

// node_modules/.pnpm/https-proxy-agent@5.0.1/node_modules/https-proxy-agent/dist/agent.js
var bu = _((wt) => {
  "use strict";
  c();
  var cy = wt && wt.__awaiter || function(e, t, n, r) {
    function i(s) {
      return s instanceof n ? s : new n(function(a) {
        a(s);
      });
    }
    return new (n || (n = Promise))(function(s, a) {
      function o(u) {
        try {
          p(r.next(u));
        } catch (d) {
          a(d);
        }
      }
      function l(u) {
        try {
          p(r.throw(u));
        } catch (d) {
          a(d);
        }
      }
      function p(u) {
        u.done ? s(u.value) : i(u.value).then(o, l);
      }
      p((r = r.apply(e, t || [])).next());
    });
  }, Gt = wt && wt.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  };
  Object.defineProperty(wt, "__esModule", { value: !0 });
  var yu = Gt(require("net")), vu = Gt(require("tls")), ly = Gt(require("url")), uy = Gt(require("assert")), py = Gt(Sn()), dy = xu(), fy = Gt(gu()), Cn = py.default("https-proxy-agent:agent"), us = class extends dy.Agent {
    constructor(t) {
      let n;
      if (typeof t == "string" ? n = ly.default.parse(t) : n = t, !n)
        throw new Error("an HTTP(S) proxy server `host` and `port` must be specified!");
      Cn("creating new HttpsProxyAgent instance: %o", n), super(n);
      let r = Object.assign({}, n);
      this.secureProxy = n.secureProxy || xy(r.protocol), r.host = r.hostname || r.host, typeof r.port == "string" && (r.port = parseInt(r.port, 10)), !r.port && r.host && (r.port = this.secureProxy ? 443 : 80), this.secureProxy && !("ALPNProtocols" in r) && (r.ALPNProtocols = ["http 1.1"]), r.host && r.path && (delete r.path, delete r.pathname), this.proxy = r;
    }
    /**
     * Called when the node-core HTTP client library is creating a
     * new HTTP request.
     *
     * @api protected
     */
    callback(t, n) {
      return cy(this, void 0, void 0, function* () {
        let { proxy: r, secureProxy: i } = this, s;
        i ? (Cn("Creating `tls.Socket`: %o", r), s = vu.default.connect(r)) : (Cn("Creating `net.Socket`: %o", r), s = yu.default.connect(r));
        let a = Object.assign({}, r.headers), l = `CONNECT ${`${n.host}:${n.port}`} HTTP/1.1\r
`;
        r.auth && (a["Proxy-Authorization"] = `Basic ${Buffer.from(r.auth).toString("base64")}`);
        let { host: p, port: u, secureEndpoint: d } = n;
        hy(u, d) || (p += `:${u}`), a.Host = p, a.Connection = "close";
        for (let h of Object.keys(a))
          l += `${h}: ${a[h]}\r
`;
        let m = fy.default(s);
        s.write(`${l}\r
`);
        let { statusCode: x, buffered: b } = yield m;
        if (x === 200) {
          if (t.once("socket", my), n.secureEndpoint) {
            Cn("Upgrading socket connection to TLS");
            let h = n.servername || n.host;
            return vu.default.connect(Object.assign(Object.assign({}, gy(n, "host", "hostname", "path", "port")), {
              socket: s,
              servername: h
            }));
          }
          return s;
        }
        s.destroy();
        let v = new yu.default.Socket({ writable: !1 });
        return v.readable = !0, t.once("socket", (h) => {
          Cn("replaying proxy buffer for failed request"), uy.default(h.listenerCount("data") > 0), h.push(b), h.push(null);
        }), v;
      });
    }
  };
  wt.default = us;
  function my(e) {
    e.resume();
  }
  function hy(e, t) {
    return !!(!t && e === 80 || t && e === 443);
  }
  function xy(e) {
    return typeof e == "string" ? /^https:?$/i.test(e) : !1;
  }
  function gy(e, ...t) {
    let n = {}, r;
    for (r in e)
      t.includes(r) || (n[r] = e[r]);
    return n;
  }
});

// node_modules/.pnpm/https-proxy-agent@5.0.1/node_modules/https-proxy-agent/dist/index.js
var _u = _((fs, wu) => {
  "use strict";
  c();
  var yy = fs && fs.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  }, ps = yy(bu());
  function ds(e) {
    return new ps.default(e);
  }
  (function(e) {
    e.HttpsProxyAgent = ps.default, e.prototype = ps.default.prototype;
  })(ds || (ds = {}));
  wu.exports = ds;
});

// node_modules/.pnpm/follow-redirects@1.16.0/node_modules/follow-redirects/debug.js
var Su = _((OT, Eu) => {
  "use strict";
  c();
  var An;
  Eu.exports = function() {
    if (!An) {
      try {
        An = Sn()("follow-redirects");
      } catch {
      }
      typeof An != "function" && (An = function() {
      });
    }
    An.apply(null, arguments);
  };
});

// node_modules/.pnpm/follow-redirects@1.16.0/node_modules/follow-redirects/index.js
var Au = _((jT, Rs) => {
  "use strict";
  c();
  var Pn = require("url"), On = Pn.URL, vy = require("http"), by = require("https"), ys = require("stream").Writable, vs = require("assert"), Ru = Su();
  (function() {
    var t = typeof process < "u", n = typeof window < "u" && typeof document < "u", r = Et(Error.captureStackTrace);
    !t && (n || !r) && console.warn("The follow-redirects package should be excluded from browser builds.");
  })();
  var bs = !1;
  try {
    vs(new On(""));
  } catch (e) {
    bs = e.code === "ERR_INVALID_URL";
  }
  var wy = [
    "Authorization",
    "Proxy-Authorization",
    "Cookie"
  ], _y = [
    "auth",
    "host",
    "hostname",
    "href",
    "path",
    "pathname",
    "port",
    "protocol",
    "query",
    "search",
    "hash"
  ], ws = ["abort", "aborted", "connect", "error", "socket", "timeout"], _s = /* @__PURE__ */ Object.create(null);
  ws.forEach(function(e) {
    _s[e] = function(t, n, r) {
      this._redirectable.emit(e, t, n, r);
    };
  });
  var hs = jn(
    "ERR_INVALID_URL",
    "Invalid URL",
    TypeError
  ), xs = jn(
    "ERR_FR_REDIRECTION_FAILURE",
    "Redirected request failed"
  ), Ey = jn(
    "ERR_FR_TOO_MANY_REDIRECTS",
    "Maximum number of redirects exceeded",
    xs
  ), Sy = jn(
    "ERR_FR_MAX_BODY_LENGTH_EXCEEDED",
    "Request body larger than maxBodyLength limit"
  ), Ry = jn(
    "ERR_STREAM_WRITE_AFTER_END",
    "write after end"
  ), Ty = ys.prototype.destroy || ku;
  function _e(e, t) {
    ys.call(this), this._sanitizeOptions(e), this._options = e, this._ended = !1, this._ending = !1, this._redirectCount = 0, this._redirects = [], this._requestBodyLength = 0, this._requestBodyBuffers = [], t && this.on("response", t);
    var n = this;
    this._onNativeResponse = function(r) {
      try {
        n._processResponse(r);
      } catch (i) {
        n.emit("error", i instanceof xs ? i : new xs({ cause: i }));
      }
    }, this._headerFilter = new RegExp("^(?:" + wy.concat(e.sensitiveHeaders).map(jy).join("|") + ")$", "i"), this._performRequest();
  }
  _e.prototype = Object.create(ys.prototype);
  _e.prototype.abort = function() {
    Ss(this._currentRequest), this._currentRequest.abort(), this.emit("abort");
  };
  _e.prototype.destroy = function(e) {
    return Ss(this._currentRequest, e), Ty.call(this, e), this;
  };
  _e.prototype.write = function(e, t, n) {
    if (this._ending)
      throw new Ry();
    if (!_t(e) && !Oy(e))
      throw new TypeError("data should be a string, Buffer or Uint8Array");
    if (Et(t) && (n = t, t = null), e.length === 0) {
      n && n();
      return;
    }
    this._requestBodyLength + e.length <= this._options.maxBodyLength ? (this._requestBodyLength += e.length, this._requestBodyBuffers.push({ data: e, encoding: t }), this._currentRequest.write(e, t, n)) : (this.emit("error", new Sy()), this.abort());
  };
  _e.prototype.end = function(e, t, n) {
    if (Et(e) ? (n = e, e = t = null) : Et(t) && (n = t, t = null), !e)
      this._ended = this._ending = !0, this._currentRequest.end(null, null, n);
    else {
      var r = this, i = this._currentRequest;
      this.write(e, t, function() {
        r._ended = !0, i.end(null, null, n);
      }), this._ending = !0;
    }
  };
  _e.prototype.setHeader = function(e, t) {
    this._options.headers[e] = t, this._currentRequest.setHeader(e, t);
  };
  _e.prototype.removeHeader = function(e) {
    delete this._options.headers[e], this._currentRequest.removeHeader(e);
  };
  _e.prototype.setTimeout = function(e, t) {
    var n = this;
    function r(a) {
      a.setTimeout(e), a.removeListener("timeout", a.destroy), a.addListener("timeout", a.destroy);
    }
    function i(a) {
      n._timeout && clearTimeout(n._timeout), n._timeout = setTimeout(function() {
        n.emit("timeout"), s();
      }, e), r(a);
    }
    function s() {
      n._timeout && (clearTimeout(n._timeout), n._timeout = null), n.removeListener("abort", s), n.removeListener("error", s), n.removeListener("response", s), n.removeListener("close", s), t && n.removeListener("timeout", t), n.socket || n._currentRequest.removeListener("socket", i);
    }
    return t && this.on("timeout", t), this.socket ? i(this.socket) : this._currentRequest.once("socket", i), this.on("socket", r), this.on("abort", s), this.on("error", s), this.on("response", s), this.on("close", s), this;
  };
  [
    "flushHeaders",
    "getHeader",
    "setNoDelay",
    "setSocketKeepAlive"
  ].forEach(function(e) {
    _e.prototype[e] = function(t, n) {
      return this._currentRequest[e](t, n);
    };
  });
  ["aborted", "connection", "socket"].forEach(function(e) {
    Object.defineProperty(_e.prototype, e, {
      get: function() {
        return this._currentRequest[e];
      }
    });
  });
  _e.prototype._sanitizeOptions = function(e) {
    if (e.headers || (e.headers = {}), Ay(e.sensitiveHeaders) || (e.sensitiveHeaders = []), e.host && (e.hostname || (e.hostname = e.host), delete e.host), !e.pathname && e.path) {
      var t = e.path.indexOf("?");
      t < 0 ? e.pathname = e.path : (e.pathname = e.path.substring(0, t), e.search = e.path.substring(t));
    }
  };
  _e.prototype._performRequest = function() {
    var e = this._options.protocol, t = this._options.nativeProtocols[e];
    if (!t)
      throw new TypeError("Unsupported protocol " + e);
    if (this._options.agents) {
      var n = e.slice(0, -1);
      this._options.agent = this._options.agents[n];
    }
    var r = this._currentRequest = t.request(this._options, this._onNativeResponse);
    r._redirectable = this;
    for (var i of ws)
      r.on(i, _s[i]);
    if (this._currentUrl = /^\//.test(this._options.path) ? Pn.format(this._options) : (
      // When making a request to a proxy, […]
      // a client MUST send the target URI in absolute-form […].
      this._options.path
    ), this._isRedirect) {
      var s = 0, a = this, o = this._requestBodyBuffers;
      (function l(p) {
        if (r === a._currentRequest)
          if (p)
            a.emit("error", p);
          else if (s < o.length) {
            var u = o[s++];
            r.finished || r.write(u.data, u.encoding, l);
          } else a._ended && r.end();
      })();
    }
  };
  _e.prototype._processResponse = function(e) {
    var t = e.statusCode;
    this._options.trackRedirects && this._redirects.push({
      url: this._currentUrl,
      headers: e.headers,
      statusCode: t
    });
    var n = e.headers.location;
    if (!n || this._options.followRedirects === !1 || t < 300 || t >= 400) {
      e.responseUrl = this._currentUrl, e.redirects = this._redirects, this.emit("response", e), this._requestBodyBuffers = [];
      return;
    }
    if (Ss(this._currentRequest), e.destroy(), ++this._redirectCount > this._options.maxRedirects)
      throw new Ey();
    var r, i = this._options.beforeRedirect;
    i && (r = Object.assign({
      // The Host header was set by nativeProtocol.request
      Host: e.req.getHeader("host")
    }, this._options.headers));
    var s = this._options.method;
    ((t === 301 || t === 302) && this._options.method === "POST" || // RFC7231§6.4.4: The 303 (See Other) status code indicates that
    // the server is redirecting the user agent to a different resource […]
    // A user agent can perform a retrieval request targeting that URI
    // (a GET or HEAD request if using HTTP) […]
    t === 303 && !/^(?:GET|HEAD)$/.test(this._options.method)) && (this._options.method = "GET", this._requestBodyBuffers = [], ms(/^content-/i, this._options.headers));
    var a = ms(/^host$/i, this._options.headers), o = Es(this._currentUrl), l = a || o.host, p = /^\w+:/.test(n) ? this._currentUrl : Pn.format(Object.assign(o, { host: l })), u = ky(n, p);
    if (Ru("redirecting to", u.href), this._isRedirect = !0, gs(u, this._options), (u.protocol !== o.protocol && u.protocol !== "https:" || u.host !== l && !Cy(u.host, l)) && ms(this._headerFilter, this._options.headers), Et(i)) {
      var d = {
        headers: e.headers,
        statusCode: t
      }, m = {
        url: p,
        method: s,
        headers: r
      };
      i(this._options, d, m), this._sanitizeOptions(this._options);
    }
    this._performRequest();
  };
  function Tu(e) {
    var t = {
      maxRedirects: 21,
      maxBodyLength: 10485760
    }, n = {};
    return Object.keys(e).forEach(function(r) {
      var i = r + ":", s = n[i] = e[r], a = t[r] = Object.create(s);
      function o(p, u, d) {
        return Py(p) ? p = gs(p) : _t(p) ? p = gs(Es(p)) : (d = u, u = Cu(p), p = { protocol: i }), Et(u) && (d = u, u = null), u = Object.assign({
          maxRedirects: t.maxRedirects,
          maxBodyLength: t.maxBodyLength
        }, p, u), u.nativeProtocols = n, !_t(u.host) && !_t(u.hostname) && (u.hostname = "::1"), vs.equal(u.protocol, i, "protocol mismatch"), Ru("options", u), new _e(u, d);
      }
      function l(p, u, d) {
        var m = a.request(p, u, d);
        return m.end(), m;
      }
      Object.defineProperties(a, {
        request: { value: o, configurable: !0, enumerable: !0, writable: !0 },
        get: { value: l, configurable: !0, enumerable: !0, writable: !0 }
      });
    }), t;
  }
  function ku() {
  }
  function Es(e) {
    var t;
    if (bs)
      t = new On(e);
    else if (t = Cu(Pn.parse(e)), !_t(t.protocol))
      throw new hs({ input: e });
    return t;
  }
  function ky(e, t) {
    return bs ? new On(e, t) : Es(Pn.resolve(t, e));
  }
  function Cu(e) {
    if (/^\[/.test(e.hostname) && !/^\[[:0-9a-f]+\]$/i.test(e.hostname))
      throw new hs({ input: e.href || e });
    if (/^\[/.test(e.host) && !/^\[[:0-9a-f]+\](:\d+)?$/i.test(e.host))
      throw new hs({ input: e.href || e });
    return e;
  }
  function gs(e, t) {
    var n = t || {};
    for (var r of _y)
      n[r] = e[r];
    return n.hostname.startsWith("[") && (n.hostname = n.hostname.slice(1, -1)), n.port !== "" && (n.port = Number(n.port)), n.path = n.search ? n.pathname + n.search : n.pathname, n;
  }
  function ms(e, t) {
    var n;
    for (var r in t)
      e.test(r) && (n = t[r], delete t[r]);
    return n === null || typeof n > "u" ? void 0 : String(n).trim();
  }
  function jn(e, t, n) {
    function r(i) {
      Et(Error.captureStackTrace) && Error.captureStackTrace(this, this.constructor), Object.assign(this, i || {}), this.code = e, this.message = this.cause ? t + ": " + this.cause.message : t;
    }
    return r.prototype = new (n || Error)(), Object.defineProperties(r.prototype, {
      constructor: {
        value: r,
        enumerable: !1
      },
      name: {
        value: "Error [" + e + "]",
        enumerable: !1
      }
    }), r;
  }
  function Ss(e, t) {
    for (var n of ws)
      e.removeListener(n, _s[n]);
    e.on("error", ku), e.destroy(t);
  }
  function Cy(e, t) {
    vs(_t(e) && _t(t));
    var n = e.length - t.length - 1;
    return n > 0 && e[n] === "." && e.endsWith(t);
  }
  function Ay(e) {
    return e instanceof Array;
  }
  function _t(e) {
    return typeof e == "string" || e instanceof String;
  }
  function Et(e) {
    return typeof e == "function";
  }
  function Oy(e) {
    return typeof e == "object" && "length" in e;
  }
  function Py(e) {
    return On && e instanceof On;
  }
  function jy(e) {
    return e.replace(/[\]\\/()*+?.$]/g, "\\$&");
  }
  Rs.exports = Tu({ http: vy, https: by });
  Rs.exports.wrap = Tu;
});

// node_modules/.pnpm/@sindresorhus+is@4.0.0/node_modules/@sindresorhus/is/dist/index.js
var Ze = _((Xe, jr) => {
  "use strict";
  c();
  Object.defineProperty(Xe, "__esModule", { value: !0 });
  var gp = [
    "Int8Array",
    "Uint8Array",
    "Uint8ClampedArray",
    "Int16Array",
    "Uint16Array",
    "Int32Array",
    "Uint32Array",
    "Float32Array",
    "Float64Array",
    "BigInt64Array",
    "BigUint64Array"
  ];
  function _v(e) {
    return gp.includes(e);
  }
  var Ev = [
    "Function",
    "Generator",
    "AsyncGenerator",
    "GeneratorFunction",
    "AsyncGeneratorFunction",
    "AsyncFunction",
    "Observable",
    "Array",
    "Buffer",
    "Object",
    "RegExp",
    "Date",
    "Error",
    "Map",
    "Set",
    "WeakMap",
    "WeakSet",
    "ArrayBuffer",
    "SharedArrayBuffer",
    "DataView",
    "Promise",
    "URL",
    "HTMLElement",
    ...gp
  ];
  function Sv(e) {
    return Ev.includes(e);
  }
  var Rv = [
    "null",
    "undefined",
    "string",
    "number",
    "bigint",
    "boolean",
    "symbol"
  ];
  function Tv(e) {
    return Rv.includes(e);
  }
  function Qt(e) {
    return (t) => typeof t === e;
  }
  var { toString: yp } = Object.prototype, Fn = (e) => {
    let t = yp.call(e).slice(8, -1);
    if (/HTML\w+Element/.test(t) && g.domElement(e))
      return "HTMLElement";
    if (Sv(t))
      return t;
  }, V = (e) => (t) => Fn(t) === e;
  function g(e) {
    if (e === null)
      return "null";
    switch (typeof e) {
      case "undefined":
        return "undefined";
      case "string":
        return "string";
      case "number":
        return "number";
      case "boolean":
        return "boolean";
      case "function":
        return "Function";
      case "bigint":
        return "bigint";
      case "symbol":
        return "symbol";
      default:
    }
    if (g.observable(e))
      return "Observable";
    if (g.array(e))
      return "Array";
    if (g.buffer(e))
      return "Buffer";
    let t = Fn(e);
    if (t)
      return t;
    if (e instanceof String || e instanceof Boolean || e instanceof Number)
      throw new TypeError("Please don't use object wrappers for primitive types");
    return "Object";
  }
  g.undefined = Qt("undefined");
  g.string = Qt("string");
  var kv = Qt("number");
  g.number = (e) => kv(e) && !g.nan(e);
  g.bigint = Qt("bigint");
  g.function_ = Qt("function");
  g.null_ = (e) => e === null;
  g.class_ = (e) => g.function_(e) && e.toString().startsWith("class ");
  g.boolean = (e) => e === !0 || e === !1;
  g.symbol = Qt("symbol");
  g.numericString = (e) => g.string(e) && !g.emptyStringOrWhitespace(e) && !Number.isNaN(Number(e));
  g.array = (e, t) => Array.isArray(e) ? g.function_(t) ? e.every(t) : !0 : !1;
  g.buffer = (e) => {
    var t, n, r, i;
    return (i = (r = (n = (t = e) === null || t === void 0 ? void 0 : t.constructor) === null || n === void 0 ? void 0 : n.isBuffer) === null || r === void 0 ? void 0 : r.call(n, e)) !== null && i !== void 0 ? i : !1;
  };
  g.nullOrUndefined = (e) => g.null_(e) || g.undefined(e);
  g.object = (e) => !g.null_(e) && (typeof e == "object" || g.function_(e));
  g.iterable = (e) => {
    var t;
    return g.function_((t = e) === null || t === void 0 ? void 0 : t[Symbol.iterator]);
  };
  g.asyncIterable = (e) => {
    var t;
    return g.function_((t = e) === null || t === void 0 ? void 0 : t[Symbol.asyncIterator]);
  };
  g.generator = (e) => g.iterable(e) && g.function_(e.next) && g.function_(e.throw);
  g.asyncGenerator = (e) => g.asyncIterable(e) && g.function_(e.next) && g.function_(e.throw);
  g.nativePromise = (e) => V("Promise")(e);
  var Cv = (e) => {
    var t, n;
    return g.function_((t = e) === null || t === void 0 ? void 0 : t.then) && g.function_((n = e) === null || n === void 0 ? void 0 : n.catch);
  };
  g.promise = (e) => g.nativePromise(e) || Cv(e);
  g.generatorFunction = V("GeneratorFunction");
  g.asyncGeneratorFunction = (e) => Fn(e) === "AsyncGeneratorFunction";
  g.asyncFunction = (e) => Fn(e) === "AsyncFunction";
  g.boundFunction = (e) => g.function_(e) && !e.hasOwnProperty("prototype");
  g.regExp = V("RegExp");
  g.date = V("Date");
  g.error = V("Error");
  g.map = (e) => V("Map")(e);
  g.set = (e) => V("Set")(e);
  g.weakMap = (e) => V("WeakMap")(e);
  g.weakSet = (e) => V("WeakSet")(e);
  g.int8Array = V("Int8Array");
  g.uint8Array = V("Uint8Array");
  g.uint8ClampedArray = V("Uint8ClampedArray");
  g.int16Array = V("Int16Array");
  g.uint16Array = V("Uint16Array");
  g.int32Array = V("Int32Array");
  g.uint32Array = V("Uint32Array");
  g.float32Array = V("Float32Array");
  g.float64Array = V("Float64Array");
  g.bigInt64Array = V("BigInt64Array");
  g.bigUint64Array = V("BigUint64Array");
  g.arrayBuffer = V("ArrayBuffer");
  g.sharedArrayBuffer = V("SharedArrayBuffer");
  g.dataView = V("DataView");
  g.directInstanceOf = (e, t) => Object.getPrototypeOf(e) === t.prototype;
  g.urlInstance = (e) => V("URL")(e);
  g.urlString = (e) => {
    if (!g.string(e))
      return !1;
    try {
      return new URL(e), !0;
    } catch {
      return !1;
    }
  };
  g.truthy = (e) => !!e;
  g.falsy = (e) => !e;
  g.nan = (e) => Number.isNaN(e);
  g.primitive = (e) => g.null_(e) || Tv(typeof e);
  g.integer = (e) => Number.isInteger(e);
  g.safeInteger = (e) => Number.isSafeInteger(e);
  g.plainObject = (e) => {
    if (yp.call(e) !== "[object Object]")
      return !1;
    let t = Object.getPrototypeOf(e);
    return t === null || t === Object.getPrototypeOf({});
  };
  g.typedArray = (e) => _v(Fn(e));
  var Av = (e) => g.safeInteger(e) && e >= 0;
  g.arrayLike = (e) => !g.nullOrUndefined(e) && !g.function_(e) && Av(e.length);
  g.inRange = (e, t) => {
    if (g.number(t))
      return e >= Math.min(0, t) && e <= Math.max(t, 0);
    if (g.array(t) && t.length === 2)
      return e >= Math.min(...t) && e <= Math.max(...t);
    throw new TypeError(`Invalid range: ${JSON.stringify(t)}`);
  };
  var Ov = 1, Pv = [
    "innerHTML",
    "ownerDocument",
    "style",
    "attributes",
    "nodeValue"
  ];
  g.domElement = (e) => g.object(e) && e.nodeType === Ov && g.string(e.nodeName) && !g.plainObject(e) && Pv.every((t) => t in e);
  g.observable = (e) => {
    var t, n, r, i;
    return e ? e === ((n = (t = e)[Symbol.observable]) === null || n === void 0 ? void 0 : n.call(t)) || e === ((i = (r = e)["@@observable"]) === null || i === void 0 ? void 0 : i.call(r)) : !1;
  };
  g.nodeStream = (e) => g.object(e) && g.function_(e.pipe) && !g.observable(e);
  g.infinite = (e) => e === 1 / 0 || e === -1 / 0;
  var vp = (e) => (t) => g.integer(t) && Math.abs(t % 2) === e;
  g.evenInteger = vp(0);
  g.oddInteger = vp(1);
  g.emptyArray = (e) => g.array(e) && e.length === 0;
  g.nonEmptyArray = (e) => g.array(e) && e.length > 0;
  g.emptyString = (e) => g.string(e) && e.length === 0;
  g.nonEmptyString = (e) => g.string(e) && e.length > 0;
  var jv = (e) => g.string(e) && !/\S/.test(e);
  g.emptyStringOrWhitespace = (e) => g.emptyString(e) || jv(e);
  g.emptyObject = (e) => g.object(e) && !g.map(e) && !g.set(e) && Object.keys(e).length === 0;
  g.nonEmptyObject = (e) => g.object(e) && !g.map(e) && !g.set(e) && Object.keys(e).length > 0;
  g.emptySet = (e) => g.set(e) && e.size === 0;
  g.nonEmptySet = (e) => g.set(e) && e.size > 0;
  g.emptyMap = (e) => g.map(e) && e.size === 0;
  g.nonEmptyMap = (e) => g.map(e) && e.size > 0;
  var bp = (e, t, n) => {
    if (!g.function_(t))
      throw new TypeError(`Invalid predicate: ${JSON.stringify(t)}`);
    if (n.length === 0)
      throw new TypeError("Invalid number of values");
    return e.call(n, t);
  };
  g.any = (e, ...t) => (g.array(e) ? e : [e]).some((r) => bp(Array.prototype.some, r, t));
  g.all = (e, ...t) => bp(Array.prototype.every, e, t);
  var k = (e, t, n) => {
    if (!e)
      throw new TypeError(`Expected value which is \`${t}\`, received value of type \`${g(n)}\`.`);
  };
  Xe.assert = {
    // Unknowns.
    undefined: (e) => k(g.undefined(e), "undefined", e),
    string: (e) => k(g.string(e), "string", e),
    number: (e) => k(g.number(e), "number", e),
    bigint: (e) => k(g.bigint(e), "bigint", e),
    // eslint-disable-next-line @typescript-eslint/ban-types
    function_: (e) => k(g.function_(e), "Function", e),
    null_: (e) => k(g.null_(e), "null", e),
    class_: (e) => k(g.class_(e), "Class", e),
    boolean: (e) => k(g.boolean(e), "boolean", e),
    symbol: (e) => k(g.symbol(e), "symbol", e),
    numericString: (e) => k(g.numericString(e), "string with a number", e),
    array: (e, t) => {
      k(g.array(e), "Array", e), t && e.forEach(t);
    },
    buffer: (e) => k(g.buffer(e), "Buffer", e),
    nullOrUndefined: (e) => k(g.nullOrUndefined(e), "null or undefined", e),
    object: (e) => k(g.object(e), "Object", e),
    iterable: (e) => k(g.iterable(e), "Iterable", e),
    asyncIterable: (e) => k(g.asyncIterable(e), "AsyncIterable", e),
    generator: (e) => k(g.generator(e), "Generator", e),
    asyncGenerator: (e) => k(g.asyncGenerator(e), "AsyncGenerator", e),
    nativePromise: (e) => k(g.nativePromise(e), "native Promise", e),
    promise: (e) => k(g.promise(e), "Promise", e),
    generatorFunction: (e) => k(g.generatorFunction(e), "GeneratorFunction", e),
    asyncGeneratorFunction: (e) => k(g.asyncGeneratorFunction(e), "AsyncGeneratorFunction", e),
    // eslint-disable-next-line @typescript-eslint/ban-types
    asyncFunction: (e) => k(g.asyncFunction(e), "AsyncFunction", e),
    // eslint-disable-next-line @typescript-eslint/ban-types
    boundFunction: (e) => k(g.boundFunction(e), "Function", e),
    regExp: (e) => k(g.regExp(e), "RegExp", e),
    date: (e) => k(g.date(e), "Date", e),
    error: (e) => k(g.error(e), "Error", e),
    map: (e) => k(g.map(e), "Map", e),
    set: (e) => k(g.set(e), "Set", e),
    weakMap: (e) => k(g.weakMap(e), "WeakMap", e),
    weakSet: (e) => k(g.weakSet(e), "WeakSet", e),
    int8Array: (e) => k(g.int8Array(e), "Int8Array", e),
    uint8Array: (e) => k(g.uint8Array(e), "Uint8Array", e),
    uint8ClampedArray: (e) => k(g.uint8ClampedArray(e), "Uint8ClampedArray", e),
    int16Array: (e) => k(g.int16Array(e), "Int16Array", e),
    uint16Array: (e) => k(g.uint16Array(e), "Uint16Array", e),
    int32Array: (e) => k(g.int32Array(e), "Int32Array", e),
    uint32Array: (e) => k(g.uint32Array(e), "Uint32Array", e),
    float32Array: (e) => k(g.float32Array(e), "Float32Array", e),
    float64Array: (e) => k(g.float64Array(e), "Float64Array", e),
    bigInt64Array: (e) => k(g.bigInt64Array(e), "BigInt64Array", e),
    bigUint64Array: (e) => k(g.bigUint64Array(e), "BigUint64Array", e),
    arrayBuffer: (e) => k(g.arrayBuffer(e), "ArrayBuffer", e),
    sharedArrayBuffer: (e) => k(g.sharedArrayBuffer(e), "SharedArrayBuffer", e),
    dataView: (e) => k(g.dataView(e), "DataView", e),
    urlInstance: (e) => k(g.urlInstance(e), "URL", e),
    urlString: (e) => k(g.urlString(e), "string with a URL", e),
    truthy: (e) => k(g.truthy(e), "truthy", e),
    falsy: (e) => k(g.falsy(e), "falsy", e),
    nan: (e) => k(g.nan(e), "NaN", e),
    primitive: (e) => k(g.primitive(e), "primitive", e),
    integer: (e) => k(g.integer(e), "integer", e),
    safeInteger: (e) => k(g.safeInteger(e), "integer", e),
    plainObject: (e) => k(g.plainObject(e), "plain object", e),
    typedArray: (e) => k(g.typedArray(e), "TypedArray", e),
    arrayLike: (e) => k(g.arrayLike(e), "array-like", e),
    domElement: (e) => k(g.domElement(e), "HTMLElement", e),
    observable: (e) => k(g.observable(e), "Observable", e),
    nodeStream: (e) => k(g.nodeStream(e), "Node.js Stream", e),
    infinite: (e) => k(g.infinite(e), "infinite number", e),
    emptyArray: (e) => k(g.emptyArray(e), "empty array", e),
    nonEmptyArray: (e) => k(g.nonEmptyArray(e), "non-empty array", e),
    emptyString: (e) => k(g.emptyString(e), "empty string", e),
    nonEmptyString: (e) => k(g.nonEmptyString(e), "non-empty string", e),
    emptyStringOrWhitespace: (e) => k(g.emptyStringOrWhitespace(e), "empty string or whitespace", e),
    emptyObject: (e) => k(g.emptyObject(e), "empty object", e),
    nonEmptyObject: (e) => k(g.nonEmptyObject(e), "non-empty object", e),
    emptySet: (e) => k(g.emptySet(e), "empty set", e),
    nonEmptySet: (e) => k(g.nonEmptySet(e), "non-empty set", e),
    emptyMap: (e) => k(g.emptyMap(e), "empty map", e),
    nonEmptyMap: (e) => k(g.nonEmptyMap(e), "non-empty map", e),
    // Numbers.
    evenInteger: (e) => k(g.evenInteger(e), "even integer", e),
    oddInteger: (e) => k(g.oddInteger(e), "odd integer", e),
    // Two arguments.
    directInstanceOf: (e, t) => k(g.directInstanceOf(e, t), "T", e),
    inRange: (e, t) => k(g.inRange(e, t), "in range", e),
    // Variadic functions.
    any: (e, ...t) => k(g.any(e, ...t), "predicate returns truthy for any value", t),
    all: (e, ...t) => k(g.all(e, ...t), "predicate returns truthy for all values", t)
  };
  Object.defineProperties(g, {
    class: {
      value: g.class_
    },
    function: {
      value: g.function_
    },
    null: {
      value: g.null_
    }
  });
  Object.defineProperties(Xe.assert, {
    class: {
      value: Xe.assert.class_
    },
    function: {
      value: Xe.assert.function_
    },
    null: {
      value: Xe.assert.null_
    }
  });
  Xe.default = g;
  jr.exports = g;
  jr.exports.default = g;
  jr.exports.assert = Xe.assert;
});

// node_modules/.pnpm/p-cancelable@2.1.1/node_modules/p-cancelable/index.js
var wp = _((hO, Ws) => {
  "use strict";
  c();
  var qr = class extends Error {
    constructor(t) {
      super(t || "Promise was canceled"), this.name = "CancelError";
    }
    get isCanceled() {
      return !0;
    }
  }, Lr = class e {
    static fn(t) {
      return (...n) => new e((r, i, s) => {
        n.push(s), t(...n).then(r, i);
      });
    }
    constructor(t) {
      this._cancelHandlers = [], this._isPending = !0, this._isCanceled = !1, this._rejectOnCancel = !0, this._promise = new Promise((n, r) => {
        this._reject = r;
        let i = (o) => {
          (!this._isCanceled || !a.shouldReject) && (this._isPending = !1, n(o));
        }, s = (o) => {
          this._isPending = !1, r(o);
        }, a = (o) => {
          if (!this._isPending)
            throw new Error("The `onCancel` handler was attached after the promise settled.");
          this._cancelHandlers.push(o);
        };
        return Object.defineProperties(a, {
          shouldReject: {
            get: () => this._rejectOnCancel,
            set: (o) => {
              this._rejectOnCancel = o;
            }
          }
        }), t(i, s, a);
      });
    }
    then(t, n) {
      return this._promise.then(t, n);
    }
    catch(t) {
      return this._promise.catch(t);
    }
    finally(t) {
      return this._promise.finally(t);
    }
    cancel(t) {
      if (!(!this._isPending || this._isCanceled)) {
        if (this._isCanceled = !0, this._cancelHandlers.length > 0)
          try {
            for (let n of this._cancelHandlers)
              n();
          } catch (n) {
            this._reject(n);
            return;
          }
        this._rejectOnCancel && this._reject(new qr(t));
      }
    }
    get isCanceled() {
      return this._isCanceled;
    }
  };
  Object.setPrototypeOf(Lr.prototype, Promise.prototype);
  Ws.exports = Lr;
  Ws.exports.CancelError = qr;
});

// node_modules/.pnpm/defer-to-connect@2.0.1/node_modules/defer-to-connect/dist/source/index.js
var _p = _((Ks, Js) => {
  "use strict";
  c();
  Object.defineProperty(Ks, "__esModule", { value: !0 });
  function qv(e) {
    return e.encrypted;
  }
  var Gs = (e, t) => {
    let n;
    typeof t == "function" ? n = { connect: t } : n = t;
    let r = typeof n.connect == "function", i = typeof n.secureConnect == "function", s = typeof n.close == "function", a = () => {
      r && n.connect(), qv(e) && i && (e.authorized ? n.secureConnect() : e.authorizationError || e.once("secureConnect", n.secureConnect)), s && e.once("close", n.close);
    };
    e.writable && !e.connecting ? a() : e.connecting ? e.once("connect", a) : e.destroyed && s && n.close(e._hadError);
  };
  Ks.default = Gs;
  Js.exports = Gs;
  Js.exports.default = Gs;
});

// node_modules/.pnpm/@szmarczak+http-timer@4.0.6/node_modules/@szmarczak/http-timer/dist/source/index.js
var Ep = _((Qs, Xs) => {
  "use strict";
  c();
  Object.defineProperty(Qs, "__esModule", { value: !0 });
  var Lv = _p(), Uv = require("util"), Dv = Number(process.versions.node.split(".")[0]), Ys = (e) => {
    if (e.timings)
      return e.timings;
    let t = {
      start: Date.now(),
      socket: void 0,
      lookup: void 0,
      connect: void 0,
      secureConnect: void 0,
      upload: void 0,
      response: void 0,
      end: void 0,
      error: void 0,
      abort: void 0,
      phases: {
        wait: void 0,
        dns: void 0,
        tcp: void 0,
        tls: void 0,
        request: void 0,
        firstByte: void 0,
        download: void 0,
        total: void 0
      }
    };
    e.timings = t;
    let n = (o) => {
      let l = o.emit.bind(o);
      o.emit = (p, ...u) => (p === "error" && (t.error = Date.now(), t.phases.total = t.error - t.start, o.emit = l), l(p, ...u));
    };
    n(e);
    let r = () => {
      t.abort = Date.now(), (!t.response || Dv >= 13) && (t.phases.total = Date.now() - t.start);
    };
    e.prependOnceListener("abort", r);
    let i = (o) => {
      if (t.socket = Date.now(), t.phases.wait = t.socket - t.start, Uv.types.isProxy(o))
        return;
      let l = () => {
        t.lookup = Date.now(), t.phases.dns = t.lookup - t.socket;
      };
      o.prependOnceListener("lookup", l), Lv.default(o, {
        connect: () => {
          t.connect = Date.now(), t.lookup === void 0 && (o.removeListener("lookup", l), t.lookup = t.connect, t.phases.dns = t.lookup - t.socket), t.phases.tcp = t.connect - t.lookup;
        },
        secureConnect: () => {
          t.secureConnect = Date.now(), t.phases.tls = t.secureConnect - t.connect;
        }
      });
    };
    e.socket ? i(e.socket) : e.prependOnceListener("socket", i);
    let s = () => {
      var o;
      t.upload = Date.now(), t.phases.request = t.upload - ((o = t.secureConnect) !== null && o !== void 0 ? o : t.connect);
    };
    return (typeof e.writableFinished == "boolean" ? e.writableFinished : e.finished && e.outputSize === 0 && (!e.socket || e.socket.writableLength === 0)) ? s() : e.prependOnceListener("finish", s), e.prependOnceListener("response", (o) => {
      t.response = Date.now(), t.phases.firstByte = t.response - t.upload, o.timings = t, n(o), o.prependOnceListener("end", () => {
        t.end = Date.now(), t.phases.download = t.end - t.response, t.phases.total = t.end - t.start;
      }), o.prependOnceListener("aborted", r);
    }), t;
  };
  Qs.default = Ys;
  Xs.exports = Ys;
  Xs.exports.default = Ys;
});

// node_modules/.pnpm/cacheable-lookup@5.0.4/node_modules/cacheable-lookup/source/index.js
var Op = _((vO, ta) => {
  "use strict";
  c();
  var {
    V4MAPPED: Iv,
    ADDRCONFIG: Fv,
    ALL: Ap,
    promises: {
      Resolver: Sp
    },
    lookup: Nv
  } = require("dns"), { promisify: Zs } = require("util"), Bv = require("os"), Xt = /* @__PURE__ */ Symbol("cacheableLookupCreateConnection"), ea = /* @__PURE__ */ Symbol("cacheableLookupInstance"), Rp = /* @__PURE__ */ Symbol("expires"), zv = typeof Ap == "number", Tp = (e) => {
    if (!(e && typeof e.createConnection == "function"))
      throw new Error("Expected an Agent instance as the first argument");
  }, Hv = (e) => {
    for (let t of e)
      t.family !== 6 && (t.address = `::ffff:${t.address}`, t.family = 6);
  }, kp = () => {
    let e = !1, t = !1;
    for (let n of Object.values(Bv.networkInterfaces()))
      for (let r of n)
        if (!r.internal && (r.family === "IPv6" ? t = !0 : e = !0, e && t))
          return { has4: e, has6: t };
    return { has4: e, has6: t };
  }, Mv = (e) => Symbol.iterator in e, Cp = { ttl: !0 }, $v = { all: !0 }, Ur = class {
    constructor({
      cache: t = /* @__PURE__ */ new Map(),
      maxTtl: n = 1 / 0,
      fallbackDuration: r = 3600,
      errorTtl: i = 0.15,
      resolver: s = new Sp(),
      lookup: a = Nv
    } = {}) {
      if (this.maxTtl = n, this.errorTtl = i, this._cache = t, this._resolver = s, this._dnsLookup = Zs(a), this._resolver instanceof Sp ? (this._resolve4 = this._resolver.resolve4.bind(this._resolver), this._resolve6 = this._resolver.resolve6.bind(this._resolver)) : (this._resolve4 = Zs(this._resolver.resolve4.bind(this._resolver)), this._resolve6 = Zs(this._resolver.resolve6.bind(this._resolver))), this._iface = kp(), this._pending = {}, this._nextRemovalTime = !1, this._hostnamesToFallback = /* @__PURE__ */ new Set(), r < 1)
        this._fallback = !1;
      else {
        this._fallback = !0;
        let o = setInterval(() => {
          this._hostnamesToFallback.clear();
        }, r * 1e3);
        o.unref && o.unref();
      }
      this.lookup = this.lookup.bind(this), this.lookupAsync = this.lookupAsync.bind(this);
    }
    set servers(t) {
      this.clear(), this._resolver.setServers(t);
    }
    get servers() {
      return this._resolver.getServers();
    }
    lookup(t, n, r) {
      if (typeof n == "function" ? (r = n, n = {}) : typeof n == "number" && (n = {
        family: n
      }), !r)
        throw new Error("Callback must be a function.");
      this.lookupAsync(t, n).then((i) => {
        n.all ? r(null, i) : r(null, i.address, i.family, i.expires, i.ttl);
      }, r);
    }
    async lookupAsync(t, n = {}) {
      typeof n == "number" && (n = {
        family: n
      });
      let r = await this.query(t);
      if (n.family === 6) {
        let i = r.filter((s) => s.family === 6);
        n.hints & Iv && (zv && n.hints & Ap || i.length === 0) ? Hv(r) : r = i;
      } else n.family === 4 && (r = r.filter((i) => i.family === 4));
      if (n.hints & Fv) {
        let { _iface: i } = this;
        r = r.filter((s) => s.family === 6 ? i.has6 : i.has4);
      }
      if (r.length === 0) {
        let i = new Error(`cacheableLookup ENOTFOUND ${t}`);
        throw i.code = "ENOTFOUND", i.hostname = t, i;
      }
      return n.all ? r : r[0];
    }
    async query(t) {
      let n = await this._cache.get(t);
      if (!n) {
        let r = this._pending[t];
        if (r)
          n = await r;
        else {
          let i = this.queryAndCache(t);
          this._pending[t] = i;
          try {
            n = await i;
          } finally {
            delete this._pending[t];
          }
        }
      }
      return n = n.map((r) => ({ ...r })), n;
    }
    async _resolve(t) {
      let n = async (p) => {
        try {
          return await p;
        } catch (u) {
          if (u.code === "ENODATA" || u.code === "ENOTFOUND")
            return [];
          throw u;
        }
      }, [r, i] = await Promise.all([
        this._resolve4(t, Cp),
        this._resolve6(t, Cp)
      ].map((p) => n(p))), s = 0, a = 0, o = 0, l = Date.now();
      for (let p of r)
        p.family = 4, p.expires = l + p.ttl * 1e3, s = Math.max(s, p.ttl);
      for (let p of i)
        p.family = 6, p.expires = l + p.ttl * 1e3, a = Math.max(a, p.ttl);
      return r.length > 0 ? i.length > 0 ? o = Math.min(s, a) : o = s : o = a, {
        entries: [
          ...r,
          ...i
        ],
        cacheTtl: o
      };
    }
    async _lookup(t) {
      try {
        return {
          entries: await this._dnsLookup(t, {
            all: !0
          }),
          cacheTtl: 0
        };
      } catch {
        return {
          entries: [],
          cacheTtl: 0
        };
      }
    }
    async _set(t, n, r) {
      if (this.maxTtl > 0 && r > 0) {
        r = Math.min(r, this.maxTtl) * 1e3, n[Rp] = Date.now() + r;
        try {
          await this._cache.set(t, n, r);
        } catch (i) {
          this.lookupAsync = async () => {
            let s = new Error("Cache Error. Please recreate the CacheableLookup instance.");
            throw s.cause = i, s;
          };
        }
        Mv(this._cache) && this._tick(r);
      }
    }
    async queryAndCache(t) {
      if (this._hostnamesToFallback.has(t))
        return this._dnsLookup(t, $v);
      let n = await this._resolve(t);
      n.entries.length === 0 && this._fallback && (n = await this._lookup(t), n.entries.length !== 0 && this._hostnamesToFallback.add(t));
      let r = n.entries.length === 0 ? this.errorTtl : n.cacheTtl;
      return await this._set(t, n.entries, r), n.entries;
    }
    _tick(t) {
      let n = this._nextRemovalTime;
      (!n || t < n) && (clearTimeout(this._removalTimeout), this._nextRemovalTime = t, this._removalTimeout = setTimeout(() => {
        this._nextRemovalTime = !1;
        let r = 1 / 0, i = Date.now();
        for (let [s, a] of this._cache) {
          let o = a[Rp];
          i >= o ? this._cache.delete(s) : o < r && (r = o);
        }
        r !== 1 / 0 && this._tick(r - i);
      }, t), this._removalTimeout.unref && this._removalTimeout.unref());
    }
    install(t) {
      if (Tp(t), Xt in t)
        throw new Error("CacheableLookup has been already installed");
      t[Xt] = t.createConnection, t[ea] = this, t.createConnection = (n, r) => ("lookup" in n || (n.lookup = this.lookup), t[Xt](n, r));
    }
    uninstall(t) {
      if (Tp(t), t[Xt]) {
        if (t[ea] !== this)
          throw new Error("The agent is not owned by this CacheableLookup instance");
        t.createConnection = t[Xt], delete t[Xt], delete t[ea];
      }
    }
    updateInterfaceInfo() {
      let { _iface: t } = this;
      this._iface = kp(), (t.has4 && !this._iface.has4 || t.has6 && !this._iface.has6) && this._cache.clear();
    }
    clear(t) {
      if (t) {
        this._cache.delete(t);
        return;
      }
      this._cache.clear();
    }
  };
  ta.exports = Ur;
  ta.exports.default = Ur;
});

// node_modules/.pnpm/normalize-url@4.1.0/node_modules/normalize-url/index.js
var qp = _((wO, jp) => {
  "use strict";
  c();
  var Vv = typeof URL > "u" ? require("url").URL : URL, Pp = (e, t) => t.some((n) => n instanceof RegExp ? n.test(e) : n === e);
  jp.exports = (e, t) => {
    if (t = {
      defaultProtocol: "http:",
      normalizeProtocol: !0,
      forceHttp: !1,
      forceHttps: !1,
      stripAuthentication: !0,
      stripHash: !1,
      stripWWW: !0,
      removeQueryParameters: [/^utm_\w+/i],
      removeTrailingSlash: !0,
      removeDirectoryIndex: !1,
      sortQueryParameters: !0,
      ...t
    }, Reflect.has(t, "normalizeHttps"))
      throw new Error("options.normalizeHttps is renamed to options.forceHttp");
    if (Reflect.has(t, "normalizeHttp"))
      throw new Error("options.normalizeHttp is renamed to options.forceHttps");
    if (Reflect.has(t, "stripFragment"))
      throw new Error("options.stripFragment is renamed to options.stripHash");
    e = e.trim();
    let n = e.startsWith("//");
    !n && /^\.*\//.test(e) || (e = e.replace(/^(?!(?:\w+:)?\/\/)|^\/\//, t.defaultProtocol));
    let i = new Vv(e);
    if (t.forceHttp && t.forceHttps)
      throw new Error("The `forceHttp` and `forceHttps` options cannot be used together");
    if (t.forceHttp && i.protocol === "https:" && (i.protocol = "http:"), t.forceHttps && i.protocol === "http:" && (i.protocol = "https:"), t.stripAuthentication && (i.username = "", i.password = ""), t.stripHash && (i.hash = ""), i.pathname && (i.pathname = i.pathname.replace(/((?!:).|^)\/{2,}/g, (s, a) => /^(?!\/)/g.test(a) ? `${a}/` : "/")), i.pathname && (i.pathname = decodeURI(i.pathname)), t.removeDirectoryIndex === !0 && (t.removeDirectoryIndex = [/^index\.[a-z]+$/]), Array.isArray(t.removeDirectoryIndex) && t.removeDirectoryIndex.length > 0) {
      let s = i.pathname.split("/"), a = s[s.length - 1];
      Pp(a, t.removeDirectoryIndex) && (s = s.slice(0, s.length - 1), i.pathname = s.slice(1).join("/") + "/");
    }
    if (i.hostname && (i.hostname = i.hostname.replace(/\.$/, ""), t.stripWWW && /^www\.([a-z\-\d]{2,63})\.([a-z.]{2,5})$/.test(i.hostname) && (i.hostname = i.hostname.replace(/^www\./, ""))), Array.isArray(t.removeQueryParameters))
      for (let s of [...i.searchParams.keys()])
        Pp(s, t.removeQueryParameters) && i.searchParams.delete(s);
    return t.sortQueryParameters && i.searchParams.sort(), t.removeTrailingSlash && (i.pathname = i.pathname.replace(/\/$/, "")), e = i.toString(), (t.removeTrailingSlash || i.pathname === "/") && i.hash === "" && (e = e.replace(/\/$/, "")), n && !t.normalizeProtocol && (e = e.replace(/^http:\/\//, "//")), t.stripProtocol && (e = e.replace(/^(?:https?:)?\/\//, "")), e;
  };
});

// node_modules/.pnpm/wrappy@1.0.2/node_modules/wrappy/wrappy.js
var Dp = _((EO, Up) => {
  "use strict";
  c();
  Up.exports = Lp;
  function Lp(e, t) {
    if (e && t) return Lp(e)(t);
    if (typeof e != "function")
      throw new TypeError("need wrapper function");
    return Object.keys(e).forEach(function(r) {
      n[r] = e[r];
    }), n;
    function n() {
      for (var r = new Array(arguments.length), i = 0; i < r.length; i++)
        r[i] = arguments[i];
      var s = e.apply(this, r), a = r[r.length - 1];
      return typeof s == "function" && s !== a && Object.keys(a).forEach(function(o) {
        s[o] = a[o];
      }), s;
    }
  }
});

// node_modules/.pnpm/once@1.4.0/node_modules/once/once.js
var ra = _((RO, na) => {
  "use strict";
  c();
  var Ip = Dp();
  na.exports = Ip(Dr);
  na.exports.strict = Ip(Fp);
  Dr.proto = Dr(function() {
    Object.defineProperty(Function.prototype, "once", {
      value: function() {
        return Dr(this);
      },
      configurable: !0
    }), Object.defineProperty(Function.prototype, "onceStrict", {
      value: function() {
        return Fp(this);
      },
      configurable: !0
    });
  });
  function Dr(e) {
    var t = function() {
      return t.called ? t.value : (t.called = !0, t.value = e.apply(this, arguments));
    };
    return t.called = !1, t;
  }
  function Fp(e) {
    var t = function() {
      if (t.called)
        throw new Error(t.onceError);
      return t.called = !0, t.value = e.apply(this, arguments);
    }, n = e.name || "Function wrapped with `once`";
    return t.onceError = n + " shouldn't be called more than once", t.called = !1, t;
  }
});

// node_modules/.pnpm/end-of-stream@1.4.5/node_modules/end-of-stream/index.js
var zp = _((kO, Bp) => {
  "use strict";
  c();
  var Wv = ra(), Gv = function() {
  }, Kv = global.Bare ? queueMicrotask : process.nextTick.bind(process), Jv = function(e) {
    return e.setHeader && typeof e.abort == "function";
  }, Yv = function(e) {
    return e.stdio && Array.isArray(e.stdio) && e.stdio.length === 3;
  }, Np = function(e, t, n) {
    if (typeof t == "function") return Np(e, null, t);
    t || (t = {}), n = Wv(n || Gv);
    var r = e._writableState, i = e._readableState, s = t.readable || t.readable !== !1 && e.readable, a = t.writable || t.writable !== !1 && e.writable, o = !1, l = function() {
      e.writable || p();
    }, p = function() {
      a = !1, s || n.call(e);
    }, u = function() {
      s = !1, a || n.call(e);
    }, d = function(h) {
      n.call(e, h ? new Error("exited with error code: " + h) : null);
    }, m = function(h) {
      n.call(e, h);
    }, x = function() {
      Kv(b);
    }, b = function() {
      if (!o) {
        if (s && !(i && i.ended && !i.destroyed)) return n.call(e, new Error("premature close"));
        if (a && !(r && r.ended && !r.destroyed)) return n.call(e, new Error("premature close"));
      }
    }, v = function() {
      e.req.on("finish", p);
    };
    return Jv(e) ? (e.on("complete", p), e.on("abort", x), e.req ? v() : e.on("request", v)) : a && !r && (e.on("end", l), e.on("close", l)), Yv(e) && e.on("exit", d), e.on("end", u), e.on("finish", p), t.error !== !1 && e.on("error", m), e.on("close", x), function() {
      o = !0, e.removeListener("complete", p), e.removeListener("abort", x), e.removeListener("request", v), e.req && e.req.removeListener("finish", p), e.removeListener("end", l), e.removeListener("close", l), e.removeListener("finish", p), e.removeListener("exit", d), e.removeListener("end", u), e.removeListener("error", m), e.removeListener("close", x);
    };
  };
  Bp.exports = Np;
});

// node_modules/.pnpm/pump@3.0.4/node_modules/pump/index.js
var $p = _((AO, Mp) => {
  "use strict";
  c();
  var Qv = ra(), Xv = zp(), Ir;
  try {
    Ir = require("fs");
  } catch {
  }
  var Nn = function() {
  }, Zv = typeof process > "u" ? !1 : /^v?\.0/.test(process.version), Fr = function(e) {
    return typeof e == "function";
  }, eb = function(e) {
    return !Zv || !Ir ? !1 : (e instanceof (Ir.ReadStream || Nn) || e instanceof (Ir.WriteStream || Nn)) && Fr(e.close);
  }, tb = function(e) {
    return e.setHeader && Fr(e.abort);
  }, nb = function(e, t, n, r) {
    r = Qv(r);
    var i = !1;
    e.on("close", function() {
      i = !0;
    }), Xv(e, { readable: t, writable: n }, function(a) {
      if (a) return r(a);
      i = !0, r();
    });
    var s = !1;
    return function(a) {
      if (!i && !s) {
        if (s = !0, eb(e)) return e.close(Nn);
        if (tb(e)) return e.abort();
        if (Fr(e.destroy)) return e.destroy();
        r(a || new Error("stream was destroyed"));
      }
    };
  }, Hp = function(e) {
    e();
  }, rb = function(e, t) {
    return e.pipe(t);
  }, ib = function() {
    var e = Array.prototype.slice.call(arguments), t = Fr(e[e.length - 1] || Nn) && e.pop() || Nn;
    if (Array.isArray(e[0]) && (e = e[0]), e.length < 2) throw new Error("pump requires two streams per minimum");
    var n, r = e.map(function(i, s) {
      var a = s < e.length - 1, o = s > 0;
      return nb(i, a, o, function(l) {
        n || (n = l), l && r.forEach(Hp), !a && (r.forEach(Hp), t(n));
      });
    });
    return e.reduce(rb);
  };
  Mp.exports = ib;
});

// node_modules/.pnpm/get-stream@5.2.0/node_modules/get-stream/buffer-stream.js
var Wp = _((PO, Vp) => {
  "use strict";
  c();
  var { PassThrough: sb } = require("stream");
  Vp.exports = (e) => {
    e = { ...e };
    let { array: t } = e, { encoding: n } = e, r = n === "buffer", i = !1;
    t ? i = !(n || r) : n = n || "utf8", r && (n = null);
    let s = new sb({ objectMode: i });
    n && s.setEncoding(n);
    let a = 0, o = [];
    return s.on("data", (l) => {
      o.push(l), i ? a = o.length : a += l.length;
    }), s.getBufferedValue = () => t ? o : r ? Buffer.concat(o, a) : o.join(""), s.getBufferedLength = () => a, s;
  };
});

// node_modules/.pnpm/get-stream@5.2.0/node_modules/get-stream/index.js
var Gp = _((qO, Zt) => {
  "use strict";
  c();
  var { constants: ab } = require("buffer"), ob = $p(), cb = Wp(), Nr = class extends Error {
    constructor() {
      super("maxBuffer exceeded"), this.name = "MaxBufferError";
    }
  };
  async function Br(e, t) {
    if (!e)
      return Promise.reject(new Error("Expected a stream"));
    t = {
      maxBuffer: 1 / 0,
      ...t
    };
    let { maxBuffer: n } = t, r;
    return await new Promise((i, s) => {
      let a = (o) => {
        o && r.getBufferedLength() <= ab.MAX_LENGTH && (o.bufferedData = r.getBufferedValue()), s(o);
      };
      r = ob(e, cb(t), (o) => {
        if (o) {
          a(o);
          return;
        }
        i();
      }), r.on("data", () => {
        r.getBufferedLength() > n && a(new Nr());
      });
    }), r.getBufferedValue();
  }
  Zt.exports = Br;
  Zt.exports.default = Br;
  Zt.exports.buffer = (e, t) => Br(e, { ...t, encoding: "buffer" });
  Zt.exports.array = (e, t) => Br(e, { ...t, array: !0 });
  Zt.exports.MaxBufferError = Nr;
});

// node_modules/.pnpm/http-cache-semantics@4.2.0/node_modules/http-cache-semantics/index.js
var Jp = _((DO, Kp) => {
  "use strict";
  c();
  var lb = /* @__PURE__ */ new Set([
    200,
    203,
    204,
    206,
    300,
    301,
    308,
    404,
    405,
    410,
    414,
    501
  ]), ub = /* @__PURE__ */ new Set([
    200,
    203,
    204,
    300,
    301,
    302,
    303,
    307,
    308,
    404,
    405,
    410,
    414,
    501
  ]), pb = /* @__PURE__ */ new Set([
    500,
    502,
    503,
    504
  ]), db = {
    date: !0,
    // included, because we add Age update Date
    connection: !0,
    "keep-alive": !0,
    "proxy-authenticate": !0,
    "proxy-authorization": !0,
    te: !0,
    trailer: !0,
    "transfer-encoding": !0,
    upgrade: !0
  }, fb = {
    // Since the old body is reused, it doesn't make sense to change properties of the body
    "content-length": !0,
    "content-encoding": !0,
    "transfer-encoding": !0,
    "content-range": !0
  };
  function et(e) {
    let t = parseInt(e, 10);
    return isFinite(t) ? t : 0;
  }
  function mb(e) {
    return e ? pb.has(e.status) : !0;
  }
  function ia(e) {
    let t = {};
    if (!e) return t;
    let n = e.trim().split(/,/);
    for (let r of n) {
      let [i, s] = r.split(/=/, 2);
      t[i.trim()] = s === void 0 ? !0 : s.trim().replace(/^"|"$/g, "");
    }
    return t;
  }
  function hb(e) {
    let t = [];
    for (let n in e) {
      let r = e[n];
      t.push(r === !0 ? n : n + "=" + r);
    }
    if (t.length)
      return t.join(", ");
  }
  Kp.exports = class {
    /**
     * Creates a new CachePolicy instance.
     * @param {HttpRequest} req - Incoming client request.
     * @param {HttpResponse} res - Received server response.
     * @param {Object} [options={}] - Configuration options.
     * @param {boolean} [options.shared=true] - Is the cache shared (a public proxy)? `false` for personal browser caches.
     * @param {number} [options.cacheHeuristic=0.1] - Fallback heuristic (age fraction) for cache duration.
     * @param {number} [options.immutableMinTimeToLive=86400000] - Minimum TTL for immutable responses in milliseconds.
     * @param {boolean} [options.ignoreCargoCult=false] - Detect nonsense cache headers, and override them.
     * @param {any} [options._fromObject] - Internal parameter for deserialization. Do not use.
     */
    constructor(t, n, {
      shared: r,
      cacheHeuristic: i,
      immutableMinTimeToLive: s,
      ignoreCargoCult: a,
      _fromObject: o
    } = {}) {
      if (o) {
        this._fromObject(o);
        return;
      }
      if (!n || !n.headers)
        throw Error("Response headers missing");
      this._assertRequestHasHeaders(t), this._responseTime = this.now(), this._isShared = r !== !1, this._ignoreCargoCult = !!a, this._cacheHeuristic = i !== void 0 ? i : 0.1, this._immutableMinTtl = s !== void 0 ? s : 24 * 3600 * 1e3, this._status = "status" in n ? n.status : 200, this._resHeaders = n.headers, this._rescc = ia(n.headers["cache-control"]), this._method = "method" in t ? t.method : "GET", this._url = t.url, this._host = t.headers.host, this._noAuthorization = !t.headers.authorization, this._reqHeaders = n.headers.vary ? t.headers : null, this._reqcc = ia(t.headers["cache-control"]), this._ignoreCargoCult && "pre-check" in this._rescc && "post-check" in this._rescc && (delete this._rescc["pre-check"], delete this._rescc["post-check"], delete this._rescc["no-cache"], delete this._rescc["no-store"], delete this._rescc["must-revalidate"], this._resHeaders = Object.assign({}, this._resHeaders, {
        "cache-control": hb(this._rescc)
      }), delete this._resHeaders.expires, delete this._resHeaders.pragma), n.headers["cache-control"] == null && /no-cache/.test(n.headers.pragma) && (this._rescc["no-cache"] = !0);
    }
    /**
     * You can monkey-patch it for testing.
     * @returns {number} Current time in milliseconds.
     */
    now() {
      return Date.now();
    }
    /**
     * Determines if the response is storable in a cache.
     * @returns {boolean} `false` if can never be cached.
     */
    storable() {
      return !!(!this._reqcc["no-store"] && // A cache MUST NOT store a response to any request, unless:
      // The request method is understood by the cache and defined as being cacheable, and
      (this._method === "GET" || this._method === "HEAD" || this._method === "POST" && this._hasExplicitExpiration()) && // the response status code is understood by the cache, and
      ub.has(this._status) && // the "no-store" cache directive does not appear in request or response header fields, and
      !this._rescc["no-store"] && // the "private" response directive does not appear in the response, if the cache is shared, and
      (!this._isShared || !this._rescc.private) && // the Authorization header field does not appear in the request, if the cache is shared,
      (!this._isShared || this._noAuthorization || this._allowsStoringAuthenticated()) && // the response either:
      // contains an Expires header field, or
      (this._resHeaders.expires || // contains a max-age response directive, or
      // contains a s-maxage response directive and the cache is shared, or
      // contains a public response directive.
      this._rescc["max-age"] || this._isShared && this._rescc["s-maxage"] || this._rescc.public || // has a status code that is defined as cacheable by default
      lb.has(this._status)));
    }
    /**
     * @returns {boolean} true if expiration is explicitly defined.
     */
    _hasExplicitExpiration() {
      return !!(this._isShared && this._rescc["s-maxage"] || this._rescc["max-age"] || this._resHeaders.expires);
    }
    /**
     * @param {HttpRequest} req - a request
     * @throws {Error} if the headers are missing.
     */
    _assertRequestHasHeaders(t) {
      if (!t || !t.headers)
        throw Error("Request headers missing");
    }
    /**
     * Checks if the request matches the cache and can be satisfied from the cache immediately,
     * without having to make a request to the server.
     *
     * This doesn't support `stale-while-revalidate`. See `evaluateRequest()` for a more complete solution.
     *
     * @param {HttpRequest} req - The new incoming HTTP request.
     * @returns {boolean} `true`` if the cached response used to construct this cache policy satisfies the request without revalidation.
     */
    satisfiesWithoutRevalidation(t) {
      return !this.evaluateRequest(t).revalidation;
    }
    /**
     * @param {{headers: Record<string, string>, synchronous: boolean}|undefined} revalidation - Revalidation information, if any.
     * @returns {{response: {headers: Record<string, string>}, revalidation: {headers: Record<string, string>, synchronous: boolean}|undefined}} An object with a cached response headers and revalidation info.
     */
    _evaluateRequestHitResult(t) {
      return {
        response: {
          headers: this.responseHeaders()
        },
        revalidation: t
      };
    }
    /**
     * @param {HttpRequest} request - new incoming
     * @param {boolean} synchronous - whether revalidation must be synchronous (not s-w-r).
     * @returns {{headers: Record<string, string>, synchronous: boolean}} An object with revalidation headers and a synchronous flag.
     */
    _evaluateRequestRevalidation(t, n) {
      return {
        synchronous: n,
        headers: this.revalidationHeaders(t)
      };
    }
    /**
     * @param {HttpRequest} request - new incoming
     * @returns {{response: undefined, revalidation: {headers: Record<string, string>, synchronous: boolean}}} An object indicating no cached response and revalidation details.
     */
    _evaluateRequestMissResult(t) {
      return {
        response: void 0,
        revalidation: this._evaluateRequestRevalidation(t, !0)
      };
    }
    /**
     * Checks if the given request matches this cache entry, and how the cache can be used to satisfy it. Returns an object with:
     *
     * ```
     * {
     *     // If defined, you must send a request to the server.
     *     revalidation: {
     *         headers: {}, // HTTP headers to use when sending the revalidation response
     *         // If true, you MUST wait for a response from the server before using the cache
     *         // If false, this is stale-while-revalidate. The cache is stale, but you can use it while you update it asynchronously.
     *         synchronous: bool,
     *     },
     *     // If defined, you can use this cached response.
     *     response: {
     *         headers: {}, // Updated cached HTTP headers you must use when responding to the client
     *     },
     * }
     * ```
     * @param {HttpRequest} req - new incoming HTTP request
     * @returns {{response: {headers: Record<string, string>}|undefined, revalidation: {headers: Record<string, string>, synchronous: boolean}|undefined}} An object containing keys:
     *   - revalidation: { headers: Record<string, string>, synchronous: boolean } Set if you should send this to the origin server
     *   - response: { headers: Record<string, string> } Set if you can respond to the client with these cached headers
     */
    evaluateRequest(t) {
      if (this._assertRequestHasHeaders(t), this._rescc["must-revalidate"])
        return this._evaluateRequestMissResult(t);
      if (!this._requestMatches(t, !1))
        return this._evaluateRequestMissResult(t);
      let n = ia(t.headers["cache-control"]);
      return n["no-cache"] || /no-cache/.test(t.headers.pragma) ? this._evaluateRequestMissResult(t) : n["max-age"] && this.age() > et(n["max-age"]) ? this._evaluateRequestMissResult(t) : n["min-fresh"] && this.maxAge() - this.age() < et(n["min-fresh"]) ? this._evaluateRequestMissResult(t) : this.stale() ? "max-stale" in n && (n["max-stale"] === !0 || n["max-stale"] > this.age() - this.maxAge()) ? this._evaluateRequestHitResult(void 0) : this.useStaleWhileRevalidate() ? this._evaluateRequestHitResult(this._evaluateRequestRevalidation(t, !1)) : this._evaluateRequestMissResult(t) : this._evaluateRequestHitResult(void 0);
    }
    /**
     * @param {HttpRequest} req - check if this is for the same cache entry
     * @param {boolean} allowHeadMethod - allow a HEAD method to match.
     * @returns {boolean} `true` if the request matches.
     */
    _requestMatches(t, n) {
      return !!((!this._url || this._url === t.url) && this._host === t.headers.host && // the request method associated with the stored response allows it to be used for the presented request, and
      (!t.method || this._method === t.method || n && t.method === "HEAD") && // selecting header fields nominated by the stored response (if any) match those presented, and
      this._varyMatches(t));
    }
    /**
     * Determines whether storing authenticated responses is allowed.
     * @returns {boolean} `true` if allowed.
     */
    _allowsStoringAuthenticated() {
      return !!(this._rescc["must-revalidate"] || this._rescc.public || this._rescc["s-maxage"]);
    }
    /**
     * Checks whether the Vary header in the response matches the new request.
     * @param {HttpRequest} req - incoming HTTP request
     * @returns {boolean} `true` if the vary headers match.
     */
    _varyMatches(t) {
      if (!this._resHeaders.vary)
        return !0;
      if (this._resHeaders.vary === "*")
        return !1;
      let n = this._resHeaders.vary.trim().toLowerCase().split(/\s*,\s*/);
      for (let r of n)
        if (t.headers[r] !== this._reqHeaders[r]) return !1;
      return !0;
    }
    /**
     * Creates a copy of the given headers without any hop-by-hop headers.
     * @param {Record<string, string>} inHeaders - old headers from the cached response
     * @returns {Record<string, string>} A new headers object without hop-by-hop headers.
     */
    _copyWithoutHopByHopHeaders(t) {
      let n = {};
      for (let r in t)
        db[r] || (n[r] = t[r]);
      if (t.connection) {
        let r = t.connection.trim().split(/\s*,\s*/);
        for (let i of r)
          delete n[i];
      }
      if (n.warning) {
        let r = n.warning.split(/,/).filter((i) => !/^\s*1[0-9][0-9]/.test(i));
        r.length ? n.warning = r.join(",").trim() : delete n.warning;
      }
      return n;
    }
    /**
     * Returns the response headers adjusted for serving the cached response.
     * Removes hop-by-hop headers and updates the Age and Date headers.
     * @returns {Record<string, string>} The adjusted response headers.
     */
    responseHeaders() {
      let t = this._copyWithoutHopByHopHeaders(this._resHeaders), n = this.age();
      return n > 3600 * 24 && !this._hasExplicitExpiration() && this.maxAge() > 3600 * 24 && (t.warning = (t.warning ? `${t.warning}, ` : "") + '113 - "rfc7234 5.5.4"'), t.age = `${Math.round(n)}`, t.date = new Date(this.now()).toUTCString(), t;
    }
    /**
     * Returns the Date header value from the response or the current time if invalid.
     * @returns {number} Timestamp (in milliseconds) representing the Date header or response time.
     */
    date() {
      let t = Date.parse(this._resHeaders.date);
      return isFinite(t) ? t : this._responseTime;
    }
    /**
     * Value of the Age header, in seconds, updated for the current time.
     * May be fractional.
     * @returns {number} The age in seconds.
     */
    age() {
      let t = this._ageValue(), n = (this.now() - this._responseTime) / 1e3;
      return t + n;
    }
    /**
     * @returns {number} The Age header value as a number.
     */
    _ageValue() {
      return et(this._resHeaders.age);
    }
    /**
     * Possibly outdated value of applicable max-age (or heuristic equivalent) in seconds.
     * This counts since response's `Date`.
     *
     * For an up-to-date value, see `timeToLive()`.
     *
     * Returns the maximum age (freshness lifetime) of the response in seconds.
     * @returns {number} The max-age value in seconds.
     */
    maxAge() {
      if (!this.storable() || this._rescc["no-cache"] || this._isShared && this._resHeaders["set-cookie"] && !this._rescc.public && !this._rescc.immutable || this._resHeaders.vary === "*")
        return 0;
      if (this._isShared) {
        if (this._rescc["proxy-revalidate"])
          return 0;
        if (this._rescc["s-maxage"])
          return et(this._rescc["s-maxage"]);
      }
      if (this._rescc["max-age"])
        return et(this._rescc["max-age"]);
      let t = this._rescc.immutable ? this._immutableMinTtl : 0, n = this.date();
      if (this._resHeaders.expires) {
        let r = Date.parse(this._resHeaders.expires);
        return Number.isNaN(r) || r < n ? 0 : Math.max(t, (r - n) / 1e3);
      }
      if (this._resHeaders["last-modified"]) {
        let r = Date.parse(this._resHeaders["last-modified"]);
        if (isFinite(r) && n > r)
          return Math.max(
            t,
            (n - r) / 1e3 * this._cacheHeuristic
          );
      }
      return t;
    }
    /**
     * Remaining time this cache entry may be useful for, in *milliseconds*.
     * You can use this as an expiration time for your cache storage.
     *
     * Prefer this method over `maxAge()`, because it includes other factors like `age` and `stale-while-revalidate`.
     * @returns {number} Time-to-live in milliseconds.
     */
    timeToLive() {
      let t = this.maxAge() - this.age(), n = t + et(this._rescc["stale-if-error"]), r = t + et(this._rescc["stale-while-revalidate"]);
      return Math.round(Math.max(0, t, n, r) * 1e3);
    }
    /**
     * If true, this cache entry is past its expiration date.
     * Note that stale cache may be useful sometimes, see `evaluateRequest()`.
     * @returns {boolean} `false` doesn't mean it's fresh nor usable
     */
    stale() {
      return this.maxAge() <= this.age();
    }
    /**
     * @returns {boolean} `true` if `stale-if-error` condition allows use of a stale response.
     */
    _useStaleIfError() {
      return this.maxAge() + et(this._rescc["stale-if-error"]) > this.age();
    }
    /** See `evaluateRequest()` for a more complete solution
     * @returns {boolean} `true` if `stale-while-revalidate` is currently allowed.
     */
    useStaleWhileRevalidate() {
      let t = et(this._rescc["stale-while-revalidate"]);
      return t > 0 && this.maxAge() + t > this.age();
    }
    /**
     * Creates a `CachePolicy` instance from a serialized object.
     * @param {Object} obj - The serialized object.
     * @returns {CachePolicy} A new CachePolicy instance.
     */
    static fromObject(t) {
      return new this(void 0, void 0, { _fromObject: t });
    }
    /**
     * @param {any} obj - The serialized object.
     * @throws {Error} If already initialized or if the object is invalid.
     */
    _fromObject(t) {
      if (this._responseTime) throw Error("Reinitialized");
      if (!t || t.v !== 1) throw Error("Invalid serialization");
      this._responseTime = t.t, this._isShared = t.sh, this._cacheHeuristic = t.ch, this._immutableMinTtl = t.imm !== void 0 ? t.imm : 24 * 3600 * 1e3, this._ignoreCargoCult = !!t.icc, this._status = t.st, this._resHeaders = t.resh, this._rescc = t.rescc, this._method = t.m, this._url = t.u, this._host = t.h, this._noAuthorization = t.a, this._reqHeaders = t.reqh, this._reqcc = t.reqcc;
    }
    /**
     * Serializes the `CachePolicy` instance into a JSON-serializable object.
     * @returns {Object} The serialized object.
     */
    toObject() {
      return {
        v: 1,
        t: this._responseTime,
        sh: this._isShared,
        ch: this._cacheHeuristic,
        imm: this._immutableMinTtl,
        icc: this._ignoreCargoCult,
        st: this._status,
        resh: this._resHeaders,
        rescc: this._rescc,
        m: this._method,
        u: this._url,
        h: this._host,
        a: this._noAuthorization,
        reqh: this._reqHeaders,
        reqcc: this._reqcc
      };
    }
    /**
     * Headers for sending to the origin server to revalidate stale response.
     * Allows server to return 304 to allow reuse of the previous response.
     *
     * Hop by hop headers are always stripped.
     * Revalidation headers may be added or removed, depending on request.
     * @param {HttpRequest} incomingReq - The incoming HTTP request.
     * @returns {Record<string, string>} The headers for the revalidation request.
     */
    revalidationHeaders(t) {
      this._assertRequestHasHeaders(t);
      let n = this._copyWithoutHopByHopHeaders(t.headers);
      if (delete n["if-range"], !this._requestMatches(t, !0) || !this.storable())
        return delete n["if-none-match"], delete n["if-modified-since"], n;
      if (this._resHeaders.etag && (n["if-none-match"] = n["if-none-match"] ? `${n["if-none-match"]}, ${this._resHeaders.etag}` : this._resHeaders.etag), n["accept-ranges"] || n["if-match"] || n["if-unmodified-since"] || this._method && this._method != "GET") {
        if (delete n["if-modified-since"], n["if-none-match"]) {
          let i = n["if-none-match"].split(/,/).filter((s) => !/^\s*W\//.test(s));
          i.length ? n["if-none-match"] = i.join(",").trim() : delete n["if-none-match"];
        }
      } else this._resHeaders["last-modified"] && !n["if-modified-since"] && (n["if-modified-since"] = this._resHeaders["last-modified"]);
      return n;
    }
    /**
     * Creates new CachePolicy with information combined from the previews response,
     * and the new revalidation response.
     *
     * Returns {policy, modified} where modified is a boolean indicating
     * whether the response body has been modified, and old cached body can't be used.
     *
     * @param {HttpRequest} request - The latest HTTP request asking for the cached entry.
     * @param {HttpResponse} response - The latest revalidation HTTP response from the origin server.
     * @returns {{policy: CachePolicy, modified: boolean, matches: boolean}} The updated policy and modification status.
     * @throws {Error} If the response headers are missing.
     */
    revalidatedPolicy(t, n) {
      if (this._assertRequestHasHeaders(t), this._useStaleIfError() && mb(n))
        return {
          policy: this,
          modified: !1,
          matches: !0
        };
      if (!n || !n.headers)
        throw Error("Response headers missing");
      let r = !1;
      n.status !== void 0 && n.status != 304 ? r = !1 : n.headers.etag && !/^\s*W\//.test(n.headers.etag) ? r = this._resHeaders.etag && this._resHeaders.etag.replace(/^\s*W\//, "") === n.headers.etag : this._resHeaders.etag && n.headers.etag ? r = this._resHeaders.etag.replace(/^\s*W\//, "") === n.headers.etag.replace(/^\s*W\//, "") : this._resHeaders["last-modified"] ? r = this._resHeaders["last-modified"] === n.headers["last-modified"] : !this._resHeaders.etag && !this._resHeaders["last-modified"] && !n.headers.etag && !n.headers["last-modified"] && (r = !0);
      let i = {
        shared: this._isShared,
        cacheHeuristic: this._cacheHeuristic,
        immutableMinTimeToLive: this._immutableMinTtl,
        ignoreCargoCult: this._ignoreCargoCult
      };
      if (!r)
        return {
          policy: new this.constructor(t, n, i),
          // Client receiving 304 without body, even if it's invalid/mismatched has no option
          // but to reuse a cached body. We don't have a good way to tell clients to do
          // error recovery in such case.
          modified: n.status != 304,
          matches: !1
        };
      let s = {};
      for (let o in this._resHeaders)
        s[o] = o in n.headers && !fb[o] ? n.headers[o] : this._resHeaders[o];
      let a = Object.assign({}, n, {
        status: this._status,
        method: this._method,
        headers: s
      });
      return {
        policy: new this.constructor(t, a, i),
        modified: !1,
        matches: !0
      };
    }
  };
});

// node_modules/.pnpm/lowercase-keys@2.0.0/node_modules/lowercase-keys/index.js
var zr = _((FO, Yp) => {
  "use strict";
  c();
  Yp.exports = (e) => {
    let t = {};
    for (let [n, r] of Object.entries(e))
      t[n.toLowerCase()] = r;
    return t;
  };
});

// node_modules/.pnpm/responselike@2.0.1/node_modules/responselike/src/index.js
var Xp = _((BO, Qp) => {
  "use strict";
  c();
  var xb = require("stream").Readable, gb = zr(), sa = class extends xb {
    constructor(t, n, r, i) {
      if (typeof t != "number")
        throw new TypeError("Argument `statusCode` should be a number");
      if (typeof n != "object")
        throw new TypeError("Argument `headers` should be an object");
      if (!(r instanceof Buffer))
        throw new TypeError("Argument `body` should be a buffer");
      if (typeof i != "string")
        throw new TypeError("Argument `url` should be a string");
      super(), this.statusCode = t, this.headers = gb(n), this.body = r, this.url = i;
    }
    _read() {
      this.push(this.body), this.push(null);
    }
  };
  Qp.exports = sa;
});

// node_modules/.pnpm/mimic-response@1.0.1/node_modules/mimic-response/index.js
var ed = _((HO, Zp) => {
  "use strict";
  c();
  var yb = [
    "destroy",
    "setTimeout",
    "socket",
    "headers",
    "trailers",
    "rawHeaders",
    "statusCode",
    "httpVersion",
    "httpVersionMinor",
    "httpVersionMajor",
    "rawTrailers",
    "statusMessage"
  ];
  Zp.exports = (e, t) => {
    let n = new Set(Object.keys(e).concat(yb));
    for (let r of n)
      r in t || (t[r] = typeof e[r] == "function" ? e[r].bind(e) : e[r]);
  };
});

// node_modules/.pnpm/clone-response@1.0.3/node_modules/clone-response/src/index.js
var nd = _(($O, td) => {
  "use strict";
  c();
  var vb = require("stream").PassThrough, bb = ed(), wb = (e) => {
    if (!(e && e.pipe))
      throw new TypeError("Parameter `response` must be a response stream.");
    let t = new vb();
    return bb(e, t), e.pipe(t);
  };
  td.exports = wb;
});

// node_modules/.pnpm/json-buffer@3.0.1/node_modules/json-buffer/index.js
var rd = _((aa) => {
  "use strict";
  c();
  aa.stringify = function e(t) {
    if (typeof t > "u") return t;
    if (t && Buffer.isBuffer(t))
      return JSON.stringify(":base64:" + t.toString("base64"));
    if (t && t.toJSON && (t = t.toJSON()), t && typeof t == "object") {
      var n = "", r = Array.isArray(t);
      n = r ? "[" : "{";
      var i = !0;
      for (var s in t) {
        var a = typeof t[s] == "function" || !r && typeof t[s] > "u";
        Object.hasOwnProperty.call(t, s) && !a && (i || (n += ","), i = !1, r ? t[s] == null ? n += "null" : n += e(t[s]) : t[s] !== void 0 && (n += e(s) + ":" + e(t[s])));
      }
      return n += r ? "]" : "}", n;
    } else return typeof t == "string" ? JSON.stringify(/^:/.test(t) ? ":" + t : t) : typeof t > "u" ? "null" : JSON.stringify(t);
  };
  aa.parse = function(e) {
    return JSON.parse(e, function(t, n) {
      return typeof n == "string" ? /^:base64:/.test(n) ? Buffer.from(n.substring(8), "base64") : /^:/.test(n) ? n.substring(1) : n : n;
    });
  };
});

// node_modules/.pnpm/keyv@4.0.0/node_modules/keyv/src/index.js
var ad = _((KO, sd) => {
  "use strict";
  c();
  var _b = require("events"), id = rd(), Eb = (e) => {
    let t = {
      redis: "@keyv/redis",
      mongodb: "@keyv/mongo",
      mongo: "@keyv/mongo",
      sqlite: "@keyv/sqlite",
      postgresql: "@keyv/postgres",
      postgres: "@keyv/postgres",
      mysql: "@keyv/mysql"
    };
    if (e.adapter || e.uri) {
      let n = e.adapter || /^[^:]*/.exec(e.uri)[0];
      return new (require(t[n]))(e);
    }
    return /* @__PURE__ */ new Map();
  }, oa = class extends _b {
    constructor(t, n) {
      if (super(), this.opts = Object.assign(
        {
          namespace: "keyv",
          serialize: id.stringify,
          deserialize: id.parse
        },
        typeof t == "string" ? { uri: t } : t,
        n
      ), !this.opts.store) {
        let r = Object.assign({}, this.opts);
        this.opts.store = Eb(r);
      }
      typeof this.opts.store.on == "function" && this.opts.store.on("error", (r) => this.emit("error", r)), this.opts.store.namespace = this.opts.namespace;
    }
    _getKeyPrefix(t) {
      return `${this.opts.namespace}:${t}`;
    }
    get(t, n) {
      t = this._getKeyPrefix(t);
      let { store: r } = this.opts;
      return Promise.resolve().then(() => r.get(t)).then((i) => typeof i == "string" ? this.opts.deserialize(i) : i).then((i) => {
        if (i !== void 0) {
          if (typeof i.expires == "number" && Date.now() > i.expires) {
            this.delete(t);
            return;
          }
          return n && n.raw ? i : i.value;
        }
      });
    }
    set(t, n, r) {
      t = this._getKeyPrefix(t), typeof r > "u" && (r = this.opts.ttl), r === 0 && (r = void 0);
      let { store: i } = this.opts;
      return Promise.resolve().then(() => {
        let s = typeof r == "number" ? Date.now() + r : null;
        return n = { value: n, expires: s }, this.opts.serialize(n);
      }).then((s) => i.set(t, s, r)).then(() => !0);
    }
    delete(t) {
      t = this._getKeyPrefix(t);
      let { store: n } = this.opts;
      return Promise.resolve().then(() => n.delete(t));
    }
    clear() {
      let { store: t } = this.opts;
      return Promise.resolve().then(() => t.clear());
    }
  };
  sd.exports = oa;
});

// node_modules/.pnpm/cacheable-request@7.0.1/node_modules/cacheable-request/src/index.js
var ld = _((YO, cd) => {
  "use strict";
  c();
  var Sb = require("events"), Hr = require("url"), Rb = qp(), Tb = Gp(), ca = Jp(), od = Xp(), kb = zr(), Cb = nd(), Ab = ad(), Bn = class e {
    constructor(t, n) {
      if (typeof t != "function")
        throw new TypeError("Parameter `request` must be a function");
      return this.cache = new Ab({
        uri: typeof n == "string" && n,
        store: typeof n != "string" && n,
        namespace: "cacheable-request"
      }), this.createCacheableRequest(t);
    }
    createCacheableRequest(t) {
      return (n, r) => {
        let i;
        if (typeof n == "string")
          i = la(Hr.parse(n)), n = {};
        else if (n instanceof Hr.URL)
          i = la(Hr.parse(n.toString())), n = {};
        else {
          let [d, ...m] = (n.path || "").split("?"), x = m.length > 0 ? `?${m.join("?")}` : "";
          i = la({ ...n, pathname: d, search: x });
        }
        n = {
          headers: {},
          method: "GET",
          cache: !0,
          strictTtl: !1,
          automaticFailover: !1,
          ...n,
          ...Ob(i)
        }, n.headers = kb(n.headers);
        let s = new Sb(), a = Rb(
          Hr.format(i),
          {
            stripWWW: !1,
            removeTrailingSlash: !1,
            stripAuthentication: !1
          }
        ), o = `${n.method}:${a}`, l = !1, p = !1, u = (d) => {
          p = !0;
          let m = !1, x, b = new Promise((h) => {
            x = () => {
              m || (m = !0, h());
            };
          }), v = (h) => {
            if (l && !d.forceRefresh) {
              h.status = h.statusCode;
              let T = ca.fromObject(l.cachePolicy).revalidatedPolicy(d, h);
              if (!T.modified) {
                let A = T.policy.responseHeaders();
                h = new od(l.statusCode, A, l.body, l.url), h.cachePolicy = T.policy, h.fromCache = !0;
              }
            }
            h.fromCache || (h.cachePolicy = new ca(d, h, d), h.fromCache = !1);
            let w;
            d.cache && h.cachePolicy.storable() ? (w = Cb(h), (async () => {
              try {
                let T = Tb.buffer(h);
                if (await Promise.race([
                  b,
                  new Promise((W) => h.once("end", W))
                ]), m)
                  return;
                let A = await T, O = {
                  cachePolicy: h.cachePolicy.toObject(),
                  url: h.url,
                  statusCode: h.fromCache ? l.statusCode : h.statusCode,
                  body: A
                }, q = d.strictTtl ? h.cachePolicy.timeToLive() : void 0;
                d.maxTtl && (q = q ? Math.min(q, d.maxTtl) : d.maxTtl), await this.cache.set(o, O, q);
              } catch (T) {
                s.emit("error", new e.CacheError(T));
              }
            })()) : d.cache && l && (async () => {
              try {
                await this.cache.delete(o);
              } catch (T) {
                s.emit("error", new e.CacheError(T));
              }
            })(), s.emit("response", w || h), typeof r == "function" && r(w || h);
          };
          try {
            let h = t(d, v);
            h.once("error", x), h.once("abort", x), s.emit("request", h);
          } catch (h) {
            s.emit("error", new e.RequestError(h));
          }
        };
        return (async () => {
          let d = async (x) => {
            await Promise.resolve();
            let b = x.cache ? await this.cache.get(o) : void 0;
            if (typeof b > "u")
              return u(x);
            let v = ca.fromObject(b.cachePolicy);
            if (v.satisfiesWithoutRevalidation(x) && !x.forceRefresh) {
              let h = v.responseHeaders(), w = new od(b.statusCode, h, b.body, b.url);
              w.cachePolicy = v, w.fromCache = !0, s.emit("response", w), typeof r == "function" && r(w);
            } else
              l = b, x.headers = v.revalidationHeaders(x), u(x);
          }, m = (x) => s.emit("error", new e.CacheError(x));
          this.cache.once("error", m), s.on("response", () => this.cache.removeListener("error", m));
          try {
            await d(n);
          } catch (x) {
            n.automaticFailover && !p && u(n), s.emit("error", new e.CacheError(x));
          }
        })(), s;
      };
    }
  };
  function Ob(e) {
    let t = { ...e };
    return t.path = `${e.pathname || "/"}${e.search || ""}`, delete t.pathname, delete t.search, t;
  }
  function la(e) {
    return {
      protocol: e.protocol,
      auth: e.auth,
      hostname: e.hostname || e.host || "localhost",
      port: e.port,
      pathname: e.pathname,
      search: e.search
    };
  }
  Bn.RequestError = class extends Error {
    constructor(e) {
      super(e.message), this.name = "RequestError", Object.assign(this, e);
    }
  };
  Bn.CacheError = class extends Error {
    constructor(e) {
      super(e.message), this.name = "CacheError", Object.assign(this, e);
    }
  };
  cd.exports = Bn;
});

// node_modules/.pnpm/mimic-response@3.1.0/node_modules/mimic-response/index.js
var pd = _((eP, ud) => {
  "use strict";
  c();
  var Pb = [
    "aborted",
    "complete",
    "headers",
    "httpVersion",
    "httpVersionMinor",
    "httpVersionMajor",
    "method",
    "rawHeaders",
    "rawTrailers",
    "setTimeout",
    "socket",
    "statusCode",
    "statusMessage",
    "trailers",
    "url"
  ];
  ud.exports = (e, t) => {
    if (t._readableState.autoDestroy)
      throw new Error("The second stream must have the `autoDestroy` option set to `false`");
    let n = new Set(Object.keys(e).concat(Pb)), r = {};
    for (let i of n)
      i in t || (r[i] = {
        get() {
          let s = e[i];
          return typeof s == "function" ? s.bind(e) : s;
        },
        set(s) {
          e[i] = s;
        },
        enumerable: !0,
        configurable: !1
      });
    return Object.defineProperties(t, r), e.once("aborted", () => {
      t.destroy(), t.emit("aborted");
    }), e.once("close", () => {
      e.complete && t.readable ? t.once("end", () => {
        t.emit("close");
      }) : t.emit("close");
    }), t;
  };
});

// node_modules/.pnpm/decompress-response@6.0.0/node_modules/decompress-response/index.js
var fd = _((nP, dd) => {
  "use strict";
  c();
  var { Transform: jb, PassThrough: qb } = require("stream"), ua = require("zlib"), Lb = pd();
  dd.exports = (e) => {
    let t = (e.headers["content-encoding"] || "").toLowerCase();
    if (!["gzip", "deflate", "br"].includes(t))
      return e;
    let n = t === "br";
    if (n && typeof ua.createBrotliDecompress != "function")
      return e.destroy(new Error("Brotli is not supported on Node.js < 12")), e;
    let r = !0, i = new jb({
      transform(o, l, p) {
        r = !1, p(null, o);
      },
      flush(o) {
        o();
      }
    }), s = new qb({
      autoDestroy: !1,
      destroy(o, l) {
        e.destroy(), l(o);
      }
    }), a = n ? ua.createBrotliDecompress() : ua.createUnzip();
    return a.once("error", (o) => {
      if (r && !e.readable) {
        s.end();
        return;
      }
      s.destroy(o);
    }), Lb(e, s), e.pipe(i).pipe(a).pipe(s), s;
  };
});

// node_modules/.pnpm/quick-lru@5.1.1/node_modules/quick-lru/index.js
var da = _((iP, md) => {
  "use strict";
  c();
  var pa = class {
    constructor(t = {}) {
      if (!(t.maxSize && t.maxSize > 0))
        throw new TypeError("`maxSize` must be a number greater than 0");
      this.maxSize = t.maxSize, this.onEviction = t.onEviction, this.cache = /* @__PURE__ */ new Map(), this.oldCache = /* @__PURE__ */ new Map(), this._size = 0;
    }
    _set(t, n) {
      if (this.cache.set(t, n), this._size++, this._size >= this.maxSize) {
        if (this._size = 0, typeof this.onEviction == "function")
          for (let [r, i] of this.oldCache.entries())
            this.onEviction(r, i);
        this.oldCache = this.cache, this.cache = /* @__PURE__ */ new Map();
      }
    }
    get(t) {
      if (this.cache.has(t))
        return this.cache.get(t);
      if (this.oldCache.has(t)) {
        let n = this.oldCache.get(t);
        return this.oldCache.delete(t), this._set(t, n), n;
      }
    }
    set(t, n) {
      return this.cache.has(t) ? this.cache.set(t, n) : this._set(t, n), this;
    }
    has(t) {
      return this.cache.has(t) || this.oldCache.has(t);
    }
    peek(t) {
      if (this.cache.has(t))
        return this.cache.get(t);
      if (this.oldCache.has(t))
        return this.oldCache.get(t);
    }
    delete(t) {
      let n = this.cache.delete(t);
      return n && this._size--, this.oldCache.delete(t) || n;
    }
    clear() {
      this.cache.clear(), this.oldCache.clear(), this._size = 0;
    }
    *keys() {
      for (let [t] of this)
        yield t;
    }
    *values() {
      for (let [, t] of this)
        yield t;
    }
    *[Symbol.iterator]() {
      for (let t of this.cache)
        yield t;
      for (let t of this.oldCache) {
        let [n] = t;
        this.cache.has(n) || (yield t);
      }
    }
    get size() {
      let t = 0;
      for (let n of this.oldCache.keys())
        this.cache.has(n) || t++;
      return Math.min(this._size + t, this.maxSize);
    }
  };
  md.exports = pa;
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/agent.js
var ma = _((aP, yd) => {
  "use strict";
  c();
  var Ub = require("events"), Db = require("tls"), Ib = require("http2"), Fb = da(), xe = /* @__PURE__ */ Symbol("currentStreamsCount"), hd = /* @__PURE__ */ Symbol("request"), je = /* @__PURE__ */ Symbol("cachedOriginSet"), en = /* @__PURE__ */ Symbol("gracefullyClosing"), Nb = [
    // `http2.connect()` options
    "maxDeflateDynamicTableSize",
    "maxSessionMemory",
    "maxHeaderListPairs",
    "maxOutstandingPings",
    "maxReservedRemoteStreams",
    "maxSendHeaderBlockLength",
    "paddingStrategy",
    // `tls.connect()` options
    "localAddress",
    "path",
    "rejectUnauthorized",
    "minDHSize",
    // `tls.createSecureContext()` options
    "ca",
    "cert",
    "clientCertEngine",
    "ciphers",
    "key",
    "pfx",
    "servername",
    "minVersion",
    "maxVersion",
    "secureProtocol",
    "crl",
    "honorCipherOrder",
    "ecdhCurve",
    "dhparam",
    "secureOptions",
    "sessionIdContext"
  ], Bb = (e, t, n) => {
    let r = 0, i = e.length;
    for (; r < i; ) {
      let s = r + i >>> 1;
      n(e[s], t) ? r = s + 1 : i = s;
    }
    return r;
  }, zb = (e, t) => e.remoteSettings.maxConcurrentStreams > t.remoteSettings.maxConcurrentStreams, fa = (e, t) => {
    for (let n of e)
      // The set is a proper subset when its length is less than the other set.
      n[je].length < t[je].length && // And the other set includes all elements of the subset.
      n[je].every((r) => t[je].includes(r)) && // Makes sure that the session can handle all requests from the covered session.
      n[xe] + t[xe] <= t.remoteSettings.maxConcurrentStreams && gd(n);
  }, Hb = (e, t) => {
    for (let n of e)
      t[je].length < n[je].length && t[je].every((r) => n[je].includes(r)) && t[xe] + n[xe] <= n.remoteSettings.maxConcurrentStreams && gd(t);
  }, xd = ({ agent: e, isFree: t }) => {
    let n = {};
    for (let r in e.sessions) {
      let s = e.sessions[r].filter((a) => {
        let o = a[Rt.kCurrentStreamsCount] < a.remoteSettings.maxConcurrentStreams;
        return t ? o : !o;
      });
      s.length !== 0 && (n[r] = s);
    }
    return n;
  }, gd = (e) => {
    e[en] = !0, e[xe] === 0 && e.close();
  }, Rt = class e extends Ub {
    constructor({ timeout: t = 6e4, maxSessions: n = 1 / 0, maxFreeSessions: r = 10, maxCachedTlsSessions: i = 100 } = {}) {
      super(), this.sessions = {}, this.queue = {}, this.timeout = t, this.maxSessions = n, this.maxFreeSessions = r, this._freeSessionsCount = 0, this._sessionsCount = 0, this.settings = {
        enablePush: !1
      }, this.tlsSessionCache = new Fb({ maxSize: i });
    }
    static normalizeOrigin(t, n) {
      return typeof t == "string" && (t = new URL(t)), n && t.hostname !== n && (t.hostname = n), t.origin;
    }
    normalizeOptions(t) {
      let n = "";
      if (t)
        for (let r of Nb)
          t[r] && (n += `:${t[r]}`);
      return n;
    }
    _tryToCreateNewSession(t, n) {
      if (!(t in this.queue) || !(n in this.queue[t]))
        return;
      let r = this.queue[t][n];
      this._sessionsCount < this.maxSessions && !r.completed && (r.completed = !0, r());
    }
    getSession(t, n, r) {
      return new Promise((i, s) => {
        Array.isArray(r) ? (r = [...r], i()) : r = [{ resolve: i, reject: s }];
        let a = this.normalizeOptions(n), o = e.normalizeOrigin(t, n && n.servername);
        if (o === void 0) {
          for (let { reject: u } of r)
            u(new TypeError("The `origin` argument needs to be a string or an URL object"));
          return;
        }
        if (a in this.sessions) {
          let u = this.sessions[a], d = -1, m = -1, x;
          for (let b of u) {
            let v = b.remoteSettings.maxConcurrentStreams;
            if (v < d)
              break;
            if (b[je].includes(o)) {
              let h = b[xe];
              if (h >= v || b[en] || // Unfortunately the `close` event isn't called immediately,
              // so `session.destroyed` is `true`, but `session.closed` is `false`.
              b.destroyed)
                continue;
              x || (d = v), h > m && (x = b, m = h);
            }
          }
          if (x) {
            if (r.length !== 1) {
              for (let { reject: b } of r) {
                let v = new Error(
                  `Expected the length of listeners to be 1, got ${r.length}.
Please report this to https://github.com/szmarczak/http2-wrapper/`
                );
                b(v);
              }
              return;
            }
            r[0].resolve(x);
            return;
          }
        }
        if (a in this.queue) {
          if (o in this.queue[a]) {
            this.queue[a][o].listeners.push(...r), this._tryToCreateNewSession(a, o);
            return;
          }
        } else
          this.queue[a] = {};
        let l = () => {
          a in this.queue && this.queue[a][o] === p && (delete this.queue[a][o], Object.keys(this.queue[a]).length === 0 && delete this.queue[a]);
        }, p = () => {
          let u = `${o}:${a}`, d = !1;
          try {
            let m = Ib.connect(t, {
              createConnection: this.createConnection,
              settings: this.settings,
              session: this.tlsSessionCache.get(u),
              ...n
            });
            m[xe] = 0, m[en] = !1;
            let x = () => m[xe] < m.remoteSettings.maxConcurrentStreams, b = !0;
            m.socket.once("session", (h) => {
              this.tlsSessionCache.set(u, h);
            }), m.once("error", (h) => {
              for (let { reject: w } of r)
                w(h);
              this.tlsSessionCache.delete(u);
            }), m.setTimeout(this.timeout, () => {
              m.destroy();
            }), m.once("close", () => {
              if (d) {
                b && this._freeSessionsCount--, this._sessionsCount--;
                let h = this.sessions[a];
                h.splice(h.indexOf(m), 1), h.length === 0 && delete this.sessions[a];
              } else {
                let h = new Error("Session closed without receiving a SETTINGS frame");
                h.code = "HTTP2WRAPPER_NOSETTINGS";
                for (let { reject: w } of r)
                  w(h);
                l();
              }
              this._tryToCreateNewSession(a, o);
            });
            let v = () => {
              if (!(!(a in this.queue) || !x())) {
                for (let h of m[je])
                  if (h in this.queue[a]) {
                    let { listeners: w } = this.queue[a][h];
                    for (; w.length !== 0 && x(); )
                      w.shift().resolve(m);
                    let T = this.queue[a];
                    if (T[h].listeners.length === 0 && (delete T[h], Object.keys(T).length === 0)) {
                      delete this.queue[a];
                      break;
                    }
                    if (!x())
                      break;
                  }
              }
            };
            m.on("origin", () => {
              m[je] = m.originSet, x() && (v(), fa(this.sessions[a], m));
            }), m.once("remoteSettings", () => {
              if (m.ref(), m.unref(), this._sessionsCount++, p.destroyed) {
                let h = new Error("Agent has been destroyed");
                for (let w of r)
                  w.reject(h);
                m.destroy();
                return;
              }
              m[je] = m.originSet;
              {
                let h = this.sessions;
                if (a in h) {
                  let w = h[a];
                  w.splice(Bb(w, m, zb), 0, m);
                } else
                  h[a] = [m];
              }
              this._freeSessionsCount += 1, d = !0, this.emit("session", m), v(), l(), m[xe] === 0 && this._freeSessionsCount > this.maxFreeSessions && m.close(), r.length !== 0 && (this.getSession(o, n, r), r.length = 0), m.on("remoteSettings", () => {
                v(), fa(this.sessions[a], m);
              });
            }), m[hd] = m.request, m.request = (h, w) => {
              if (m[en])
                throw new Error("The session is gracefully closing. No new streams are allowed.");
              let T = m[hd](h, w);
              return m.ref(), ++m[xe], m[xe] === m.remoteSettings.maxConcurrentStreams && this._freeSessionsCount--, T.once("close", () => {
                if (b = x(), --m[xe], !m.destroyed && !m.closed && (Hb(this.sessions[a], m), x() && !m.closed)) {
                  b || (this._freeSessionsCount++, b = !0);
                  let A = m[xe] === 0;
                  A && m.unref(), A && (this._freeSessionsCount > this.maxFreeSessions || m[en]) ? m.close() : (fa(this.sessions[a], m), v());
                }
              }), T;
            };
          } catch (m) {
            for (let x of r)
              x.reject(m);
            l();
          }
        };
        p.listeners = r, p.completed = !1, p.destroyed = !1, this.queue[a][o] = p, this._tryToCreateNewSession(a, o);
      });
    }
    request(t, n, r, i) {
      return new Promise((s, a) => {
        this.getSession(t, n, [{
          reject: a,
          resolve: (o) => {
            try {
              s(o.request(r, i));
            } catch (l) {
              a(l);
            }
          }
        }]);
      });
    }
    createConnection(t, n) {
      return e.connect(t, n);
    }
    static connect(t, n) {
      n.ALPNProtocols = ["h2"];
      let r = t.port || 443, i = t.hostname || t.host;
      return typeof n.servername > "u" && (n.servername = i), Db.connect(r, i, n);
    }
    closeFreeSessions() {
      for (let t of Object.values(this.sessions))
        for (let n of t)
          n[xe] === 0 && n.close();
    }
    destroy(t) {
      for (let n of Object.values(this.sessions))
        for (let r of n)
          r.destroy(t);
      for (let n of Object.values(this.queue))
        for (let r of Object.values(n))
          r.destroyed = !0;
      this.queue = {};
    }
    get freeSessions() {
      return xd({ agent: this, isFree: !0 });
    }
    get busySessions() {
      return xd({ agent: this, isFree: !1 });
    }
  };
  Rt.kCurrentStreamsCount = xe;
  Rt.kGracefullyClosing = en;
  yd.exports = {
    Agent: Rt,
    globalAgent: new Rt()
  };
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/incoming-message.js
var xa = _((cP, vd) => {
  "use strict";
  c();
  var { Readable: Mb } = require("stream"), ha = class extends Mb {
    constructor(t, n) {
      super({
        highWaterMark: n,
        autoDestroy: !1
      }), this.statusCode = null, this.statusMessage = "", this.httpVersion = "2.0", this.httpVersionMajor = 2, this.httpVersionMinor = 0, this.headers = {}, this.trailers = {}, this.req = null, this.aborted = !1, this.complete = !1, this.upgrade = null, this.rawHeaders = [], this.rawTrailers = [], this.socket = t, this.connection = t, this._dumped = !1;
    }
    _destroy(t) {
      this.req._request.destroy(t);
    }
    setTimeout(t, n) {
      return this.req.setTimeout(t, n), this;
    }
    _dump() {
      this._dumped || (this._dumped = !0, this.removeAllListeners("data"), this.resume());
    }
    _read() {
      this.req && this.req._request.resume();
    }
  };
  vd.exports = ha;
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/utils/url-to-options.js
var ga = _((uP, bd) => {
  "use strict";
  c();
  bd.exports = (e) => {
    let t = {
      protocol: e.protocol,
      hostname: typeof e.hostname == "string" && e.hostname.startsWith("[") ? e.hostname.slice(1, -1) : e.hostname,
      host: e.host,
      hash: e.hash,
      search: e.search,
      pathname: e.pathname,
      href: e.href,
      path: `${e.pathname || ""}${e.search || ""}`
    };
    return typeof e.port == "string" && e.port.length !== 0 && (t.port = Number(e.port)), (e.username || e.password) && (t.auth = `${e.username || ""}:${e.password || ""}`), t;
  };
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/utils/proxy-events.js
var _d = _((dP, wd) => {
  "use strict";
  c();
  wd.exports = (e, t, n) => {
    for (let r of n)
      e.on(r, (...i) => t.emit(r, ...i));
  };
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/utils/is-request-pseudo-header.js
var Sd = _((mP, Ed) => {
  "use strict";
  c();
  Ed.exports = (e) => {
    switch (e) {
      case ":method":
      case ":scheme":
      case ":authority":
      case ":path":
        return !0;
      default:
        return !1;
    }
  };
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/utils/errors.js
var Td = _((gP, Rd) => {
  "use strict";
  c();
  var tn = (e, t, n) => {
    Rd.exports[t] = class extends e {
      constructor(...i) {
        super(typeof n == "string" ? n : n(i)), this.name = `${super.name} [${t}]`, this.code = t;
      }
    };
  };
  tn(TypeError, "ERR_INVALID_ARG_TYPE", (e) => {
    let t = e[0].includes(".") ? "property" : "argument", n = e[1], r = Array.isArray(n);
    return r && (n = `${n.slice(0, -1).join(", ")} or ${n.slice(-1)}`), `The "${e[0]}" ${t} must be ${r ? "one of" : "of"} type ${n}. Received ${typeof e[2]}`;
  });
  tn(TypeError, "ERR_INVALID_PROTOCOL", (e) => `Protocol "${e[0]}" not supported. Expected "${e[1]}"`);
  tn(Error, "ERR_HTTP_HEADERS_SENT", (e) => `Cannot ${e[0]} headers after they are sent to the client`);
  tn(TypeError, "ERR_INVALID_HTTP_TOKEN", (e) => `${e[0]} must be a valid HTTP token [${e[1]}]`);
  tn(TypeError, "ERR_HTTP_INVALID_HEADER_VALUE", (e) => `Invalid value "${e[0]} for header "${e[1]}"`);
  tn(TypeError, "ERR_INVALID_CHAR", (e) => `Invalid character in ${e[0]} [${e[1]}]`);
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/client-request.js
var _a = _((vP, qd) => {
  "use strict";
  c();
  var $b = require("http2"), { Writable: Vb } = require("stream"), { Agent: kd, globalAgent: Wb } = ma(), Gb = xa(), Kb = ga(), Jb = _d(), Yb = Sd(), {
    ERR_INVALID_ARG_TYPE: ya,
    ERR_INVALID_PROTOCOL: Qb,
    ERR_HTTP_HEADERS_SENT: Cd,
    ERR_INVALID_HTTP_TOKEN: Xb,
    ERR_HTTP_INVALID_HEADER_VALUE: Zb,
    ERR_INVALID_CHAR: ew
  } = Td(), {
    HTTP2_HEADER_STATUS: Ad,
    HTTP2_HEADER_METHOD: Od,
    HTTP2_HEADER_PATH: Pd,
    HTTP2_METHOD_CONNECT: tw
  } = $b.constants, me = /* @__PURE__ */ Symbol("headers"), va = /* @__PURE__ */ Symbol("origin"), ba = /* @__PURE__ */ Symbol("session"), jd = /* @__PURE__ */ Symbol("options"), Mr = /* @__PURE__ */ Symbol("flushedHeaders"), zn = /* @__PURE__ */ Symbol("jobs"), nw = /^[\^`\-\w!#$%&*+.|~]+$/, rw = /[^\t\u0020-\u007E\u0080-\u00FF]/, wa = class extends Vb {
    constructor(t, n, r) {
      super({
        autoDestroy: !1
      });
      let i = typeof t == "string" || t instanceof URL;
      if (i && (t = Kb(t instanceof URL ? t : new URL(t))), typeof n == "function" || n === void 0 ? (r = n, n = i ? t : { ...t }) : n = { ...t, ...n }, n.h2session)
        this[ba] = n.h2session;
      else if (n.agent === !1)
        this.agent = new kd({ maxFreeSessions: 0 });
      else if (typeof n.agent > "u" || n.agent === null)
        typeof n.createConnection == "function" ? (this.agent = new kd({ maxFreeSessions: 0 }), this.agent.createConnection = n.createConnection) : this.agent = Wb;
      else if (typeof n.agent.request == "function")
        this.agent = n.agent;
      else
        throw new ya("options.agent", ["Agent-like Object", "undefined", "false"], n.agent);
      if (n.protocol && n.protocol !== "https:")
        throw new Qb(n.protocol, "https:");
      let s = n.port || n.defaultPort || this.agent && this.agent.defaultPort || 443, a = n.hostname || n.host || "localhost";
      delete n.hostname, delete n.host, delete n.port;
      let { timeout: o } = n;
      if (n.timeout = void 0, this[me] = /* @__PURE__ */ Object.create(null), this[zn] = [], this.socket = null, this.connection = null, this.method = n.method || "GET", this.path = n.path, this.res = null, this.aborted = !1, this.reusedSocket = !1, n.headers)
        for (let [l, p] of Object.entries(n.headers))
          this.setHeader(l, p);
      n.auth && !("authorization" in this[me]) && (this[me].authorization = "Basic " + Buffer.from(n.auth).toString("base64")), n.session = n.tlsSession, n.path = n.socketPath, this[jd] = n, s === 443 ? (this[va] = `https://${a}`, ":authority" in this[me] || (this[me][":authority"] = a)) : (this[va] = `https://${a}:${s}`, ":authority" in this[me] || (this[me][":authority"] = `${a}:${s}`)), o && this.setTimeout(o), r && this.once("response", r), this[Mr] = !1;
    }
    get method() {
      return this[me][Od];
    }
    set method(t) {
      t && (this[me][Od] = t.toUpperCase());
    }
    get path() {
      return this[me][Pd];
    }
    set path(t) {
      t && (this[me][Pd] = t);
    }
    get _mustNotHaveABody() {
      return this.method === "GET" || this.method === "HEAD" || this.method === "DELETE";
    }
    _write(t, n, r) {
      if (this._mustNotHaveABody) {
        r(new Error("The GET, HEAD and DELETE methods must NOT have a body"));
        return;
      }
      this.flushHeaders();
      let i = () => this._request.write(t, n, r);
      this._request ? i() : this[zn].push(i);
    }
    _final(t) {
      if (this.destroyed)
        return;
      this.flushHeaders();
      let n = () => {
        if (this._mustNotHaveABody) {
          t();
          return;
        }
        this._request.end(t);
      };
      this._request ? n() : this[zn].push(n);
    }
    abort() {
      this.res && this.res.complete || (this.aborted || process.nextTick(() => this.emit("abort")), this.aborted = !0, this.destroy());
    }
    _destroy(t, n) {
      this.res && this.res._dump(), this._request && this._request.destroy(), n(t);
    }
    async flushHeaders() {
      if (this[Mr] || this.destroyed)
        return;
      this[Mr] = !0;
      let t = this.method === tw, n = (r) => {
        if (this._request = r, this.destroyed) {
          r.destroy();
          return;
        }
        t || Jb(r, this, ["timeout", "continue", "close", "error"]);
        let i = (a) => (...o) => {
          !this.writable && !this.destroyed ? a(...o) : this.once("finish", () => {
            a(...o);
          });
        };
        r.once("response", i((a, o, l) => {
          let p = new Gb(this.socket, r.readableHighWaterMark);
          this.res = p, p.req = this, p.statusCode = a[Ad], p.headers = a, p.rawHeaders = l, p.once("end", () => {
            this.aborted ? (p.aborted = !0, p.emit("aborted")) : (p.complete = !0, p.socket = null, p.connection = null);
          }), t ? (p.upgrade = !0, this.emit("connect", p, r, Buffer.alloc(0)) ? this.emit("close") : r.destroy()) : (r.on("data", (u) => {
            !p._dumped && !p.push(u) && r.pause();
          }), r.once("end", () => {
            p.push(null);
          }), this.emit("response", p) || p._dump());
        })), r.once("headers", i(
          (a) => this.emit("information", { statusCode: a[Ad] })
        )), r.once("trailers", i((a, o, l) => {
          let { res: p } = this;
          p.trailers = a, p.rawTrailers = l;
        }));
        let { socket: s } = r.session;
        this.socket = s, this.connection = s;
        for (let a of this[zn])
          a();
        this.emit("socket", this.socket);
      };
      if (this[ba])
        try {
          n(this[ba].request(this[me]));
        } catch (r) {
          this.emit("error", r);
        }
      else {
        this.reusedSocket = !0;
        try {
          n(await this.agent.request(this[va], this[jd], this[me]));
        } catch (r) {
          this.emit("error", r);
        }
      }
    }
    getHeader(t) {
      if (typeof t != "string")
        throw new ya("name", "string", t);
      return this[me][t.toLowerCase()];
    }
    get headersSent() {
      return this[Mr];
    }
    removeHeader(t) {
      if (typeof t != "string")
        throw new ya("name", "string", t);
      if (this.headersSent)
        throw new Cd("remove");
      delete this[me][t.toLowerCase()];
    }
    setHeader(t, n) {
      if (this.headersSent)
        throw new Cd("set");
      if (typeof t != "string" || !nw.test(t) && !Yb(t))
        throw new Xb("Header name", t);
      if (typeof n > "u")
        throw new Zb(n, t);
      if (rw.test(n))
        throw new ew("header content", t);
      this[me][t.toLowerCase()] = n;
    }
    setNoDelay() {
    }
    setSocketKeepAlive() {
    }
    setTimeout(t, n) {
      let r = () => this._request.setTimeout(t, n);
      return this._request ? r() : this[zn].push(r), this;
    }
    get maxHeadersCount() {
      if (!this.destroyed && this._request)
        return this._request.session.localSettings.maxHeaderListSize;
    }
    set maxHeadersCount(t) {
    }
  };
  qd.exports = wa;
});

// node_modules/.pnpm/resolve-alpn@1.2.1/node_modules/resolve-alpn/index.js
var Ud = _((wP, Ld) => {
  "use strict";
  c();
  var iw = require("tls");
  Ld.exports = (e = {}, t = iw.connect) => new Promise((n, r) => {
    let i = !1, s, a = async () => {
      await l, s.off("timeout", o), s.off("error", r), e.resolveSocket ? (n({ alpnProtocol: s.alpnProtocol, socket: s, timeout: i }), i && (await Promise.resolve(), s.emit("timeout"))) : (s.destroy(), n({ alpnProtocol: s.alpnProtocol, timeout: i }));
    }, o = async () => {
      i = !0, a();
    }, l = (async () => {
      try {
        s = await t(e, a), s.on("error", r), s.once("timeout", o);
      } catch (p) {
        r(p);
      }
    })();
  });
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/utils/calculate-server-name.js
var Id = _((EP, Dd) => {
  "use strict";
  c();
  var sw = require("net");
  Dd.exports = (e) => {
    let t = e.host, n = e.headers && e.headers.host;
    return n && (n.startsWith("[") ? n.indexOf("]") === -1 ? t = n : t = n.slice(1, -1) : t = n.split(":", 1)[0]), sw.isIP(t) ? "" : t;
  };
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/auto.js
var Bd = _((RP, Sa) => {
  "use strict";
  c();
  var Fd = require("http"), Ea = require("https"), aw = Ud(), ow = da(), cw = _a(), lw = Id(), uw = ga(), $r = new ow({ maxSize: 100 }), Hn = /* @__PURE__ */ new Map(), Nd = (e, t, n) => {
    t._httpMessage = { shouldKeepAlive: !0 };
    let r = () => {
      e.emit("free", t, n);
    };
    t.on("free", r);
    let i = () => {
      e.removeSocket(t, n);
    };
    t.on("close", i);
    let s = () => {
      e.removeSocket(t, n), t.off("close", i), t.off("free", r), t.off("agentRemove", s);
    };
    t.on("agentRemove", s), e.emit("free", t, n);
  }, pw = async (e) => {
    let t = `${e.host}:${e.port}:${e.ALPNProtocols.sort()}`;
    if (!$r.has(t)) {
      if (Hn.has(t))
        return (await Hn.get(t)).alpnProtocol;
      let { path: n, agent: r } = e;
      e.path = e.socketPath;
      let i = aw(e);
      Hn.set(t, i);
      try {
        let { socket: s, alpnProtocol: a } = await i;
        if ($r.set(t, a), e.path = n, a === "h2")
          s.destroy();
        else {
          let { globalAgent: o } = Ea, l = Ea.Agent.prototype.createConnection;
          r ? r.createConnection === l ? Nd(r, s, e) : s.destroy() : o.createConnection === l ? Nd(o, s, e) : s.destroy();
        }
        return Hn.delete(t), a;
      } catch (s) {
        throw Hn.delete(t), s;
      }
    }
    return $r.get(t);
  };
  Sa.exports = async (e, t, n) => {
    if ((typeof e == "string" || e instanceof URL) && (e = uw(new URL(e))), typeof t == "function" && (n = t, t = void 0), t = {
      ALPNProtocols: ["h2", "http/1.1"],
      ...e,
      ...t,
      resolveSocket: !0
    }, !Array.isArray(t.ALPNProtocols) || t.ALPNProtocols.length === 0)
      throw new Error("The `ALPNProtocols` option must be an Array with at least one entry");
    t.protocol = t.protocol || "https:";
    let r = t.protocol === "https:";
    t.host = t.hostname || t.host || "localhost", t.session = t.tlsSession, t.servername = t.servername || lw(t), t.port = t.port || (r ? 443 : 80), t._defaultAgent = r ? Ea.globalAgent : Fd.globalAgent;
    let i = t.agent;
    if (i) {
      if (i.addRequest)
        throw new Error("The `options.agent` object can contain only `http`, `https` or `http2` properties");
      t.agent = i[r ? "https" : "http"];
    }
    return r && await pw(t) === "h2" ? (i && (t.agent = i.http2), new cw(t, n)) : Fd.request(t, n);
  };
  Sa.exports.protocolCache = $r;
});

// node_modules/.pnpm/http2-wrapper@1.0.3/node_modules/http2-wrapper/source/index.js
var Hd = _((kP, zd) => {
  "use strict";
  c();
  var dw = require("http2"), fw = ma(), Ra = _a(), mw = xa(), hw = Bd(), xw = (e, t, n) => new Ra(e, t, n), gw = (e, t, n) => {
    let r = new Ra(e, t, n);
    return r.end(), r;
  };
  zd.exports = {
    ...dw,
    ClientRequest: Ra,
    IncomingMessage: mw,
    ...fw,
    request: xw,
    get: gw,
    auto: hw
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/is-form-data.js
var ka = _((Ta) => {
  "use strict";
  c();
  Object.defineProperty(Ta, "__esModule", { value: !0 });
  var Md = Ze();
  Ta.default = (e) => Md.default.nodeStream(e) && Md.default.function_(e.getBoundary);
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/get-body-size.js
var Gd = _((Ca) => {
  "use strict";
  c();
  Object.defineProperty(Ca, "__esModule", { value: !0 });
  var Vd = require("fs"), Wd = require("util"), $d = Ze(), yw = ka(), vw = Wd.promisify(Vd.stat);
  Ca.default = async (e, t) => {
    if (t && "content-length" in t)
      return Number(t["content-length"]);
    if (!e)
      return 0;
    if ($d.default.string(e))
      return Buffer.byteLength(e);
    if ($d.default.buffer(e))
      return e.length;
    if (yw.default(e))
      return Wd.promisify(e.getLength.bind(e))();
    if (e instanceof Vd.ReadStream) {
      let { size: n } = await vw(e.path);
      return n === 0 ? void 0 : n;
    }
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/proxy-events.js
var Oa = _((Aa) => {
  "use strict";
  c();
  Object.defineProperty(Aa, "__esModule", { value: !0 });
  function bw(e, t, n) {
    let r = {};
    for (let i of n)
      r[i] = (...s) => {
        t.emit(i, ...s);
      }, e.on(i, r[i]);
    return () => {
      for (let i of n)
        e.off(i, r[i]);
    };
  }
  Aa.default = bw;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/unhandle.js
var Kd = _((Pa) => {
  "use strict";
  c();
  Object.defineProperty(Pa, "__esModule", { value: !0 });
  Pa.default = () => {
    let e = [];
    return {
      once(t, n, r) {
        t.once(n, r), e.push({ origin: t, event: n, fn: r });
      },
      unhandleAll() {
        for (let t of e) {
          let { origin: n, event: r, fn: i } = t;
          n.removeListener(r, i);
        }
        e.length = 0;
      }
    };
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/timed-out.js
var Yd = _((Mn) => {
  "use strict";
  c();
  Object.defineProperty(Mn, "__esModule", { value: !0 });
  Mn.TimeoutError = void 0;
  var ww = require("net"), _w = Kd(), Jd = /* @__PURE__ */ Symbol("reentry"), Ew = () => {
  }, Vr = class extends Error {
    constructor(t, n) {
      super(`Timeout awaiting '${n}' for ${t}ms`), this.event = n, this.name = "TimeoutError", this.code = "ETIMEDOUT";
    }
  };
  Mn.TimeoutError = Vr;
  Mn.default = (e, t, n) => {
    if (Jd in e)
      return Ew;
    e[Jd] = !0;
    let r = [], { once: i, unhandleAll: s } = _w.default(), a = (d, m, x) => {
      var b;
      let v = setTimeout(m, d, d, x);
      (b = v.unref) === null || b === void 0 || b.call(v);
      let h = () => {
        clearTimeout(v);
      };
      return r.push(h), h;
    }, { host: o, hostname: l } = n, p = (d, m) => {
      e.destroy(new Vr(d, m));
    }, u = () => {
      for (let d of r)
        d();
      s();
    };
    if (e.once("error", (d) => {
      if (u(), e.listenerCount("error") === 0)
        throw d;
    }), e.once("close", u), i(e, "response", (d) => {
      i(d, "end", u);
    }), typeof t.request < "u" && a(t.request, p, "request"), typeof t.socket < "u") {
      let d = () => {
        p(t.socket, "socket");
      };
      e.setTimeout(t.socket, d), r.push(() => {
        e.removeListener("timeout", d);
      });
    }
    return i(e, "socket", (d) => {
      var m;
      let { socketPath: x } = e;
      if (d.connecting) {
        let b = !!(x ?? ww.isIP((m = l ?? o) !== null && m !== void 0 ? m : "") !== 0);
        if (typeof t.lookup < "u" && !b && typeof d.address().address > "u") {
          let v = a(t.lookup, p, "lookup");
          i(d, "lookup", v);
        }
        if (typeof t.connect < "u") {
          let v = () => a(t.connect, p, "connect");
          b ? i(d, "connect", v()) : i(d, "lookup", (h) => {
            h === null && i(d, "connect", v());
          });
        }
        typeof t.secureConnect < "u" && n.protocol === "https:" && i(d, "connect", () => {
          let v = a(t.secureConnect, p, "secureConnect");
          i(d, "secureConnect", v);
        });
      }
      if (typeof t.send < "u") {
        let b = () => a(t.send, p, "send");
        d.connecting ? i(d, "connect", () => {
          i(e, "upload-complete", b());
        }) : i(e, "upload-complete", b());
      }
    }), typeof t.response < "u" && i(e, "upload-complete", () => {
      let d = a(t.response, p, "response");
      i(e, "response", d);
    }), u;
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/url-to-options.js
var Xd = _((ja) => {
  "use strict";
  c();
  Object.defineProperty(ja, "__esModule", { value: !0 });
  var Qd = Ze();
  ja.default = (e) => {
    e = e;
    let t = {
      protocol: e.protocol,
      hostname: Qd.default.string(e.hostname) && e.hostname.startsWith("[") ? e.hostname.slice(1, -1) : e.hostname,
      host: e.host,
      hash: e.hash,
      search: e.search,
      pathname: e.pathname,
      href: e.href,
      path: `${e.pathname || ""}${e.search || ""}`
    };
    return Qd.default.string(e.port) && e.port.length > 0 && (t.port = Number(e.port)), (e.username || e.password) && (t.auth = `${e.username || ""}:${e.password || ""}`), t;
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/options-to-url.js
var Zd = _((qa) => {
  "use strict";
  c();
  Object.defineProperty(qa, "__esModule", { value: !0 });
  var Sw = require("url"), Rw = [
    "protocol",
    "host",
    "hostname",
    "port",
    "pathname",
    "search"
  ];
  qa.default = (e, t) => {
    var n, r;
    if (t.path) {
      if (t.pathname)
        throw new TypeError("Parameters `path` and `pathname` are mutually exclusive.");
      if (t.search)
        throw new TypeError("Parameters `path` and `search` are mutually exclusive.");
      if (t.searchParams)
        throw new TypeError("Parameters `path` and `searchParams` are mutually exclusive.");
    }
    if (t.search && t.searchParams)
      throw new TypeError("Parameters `search` and `searchParams` are mutually exclusive.");
    if (!e) {
      if (!t.protocol)
        throw new TypeError("No URL protocol specified");
      e = `${t.protocol}//${(r = (n = t.hostname) !== null && n !== void 0 ? n : t.host) !== null && r !== void 0 ? r : ""}`;
    }
    let i = new Sw.URL(e);
    if (t.path) {
      let s = t.path.indexOf("?");
      s === -1 ? t.pathname = t.path : (t.pathname = t.path.slice(0, s), t.search = t.path.slice(s + 1)), delete t.path;
    }
    for (let s of Rw)
      t[s] && (i[s] = t[s].toString());
    return i;
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/weakable-map.js
var ef = _((Ua) => {
  "use strict";
  c();
  Object.defineProperty(Ua, "__esModule", { value: !0 });
  var La = class {
    constructor() {
      this.weakMap = /* @__PURE__ */ new WeakMap(), this.map = /* @__PURE__ */ new Map();
    }
    set(t, n) {
      typeof t == "object" ? this.weakMap.set(t, n) : this.map.set(t, n);
    }
    get(t) {
      return typeof t == "object" ? this.weakMap.get(t) : this.map.get(t);
    }
    has(t) {
      return typeof t == "object" ? this.weakMap.has(t) : this.map.has(t);
    }
  };
  Ua.default = La;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/get-buffer.js
var Ia = _((Da) => {
  "use strict";
  c();
  Object.defineProperty(Da, "__esModule", { value: !0 });
  var Tw = async (e) => {
    let t = [], n = 0;
    for await (let r of e)
      t.push(r), n += Buffer.byteLength(r);
    return Buffer.isBuffer(t[0]) ? Buffer.concat(t, n) : Buffer.from(t.join(""));
  };
  Da.default = Tw;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/dns-ip-version.js
var nf = _((Tt) => {
  "use strict";
  c();
  Object.defineProperty(Tt, "__esModule", { value: !0 });
  Tt.dnsLookupIpVersionToFamily = Tt.isDnsLookupIpVersion = void 0;
  var tf = {
    auto: 0,
    ipv4: 4,
    ipv6: 6
  };
  Tt.isDnsLookupIpVersion = (e) => e in tf;
  Tt.dnsLookupIpVersionToFamily = (e) => {
    if (Tt.isDnsLookupIpVersion(e))
      return tf[e];
    throw new Error("Invalid DNS lookup IP version");
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/utils/is-response-ok.js
var Fa = _((Wr) => {
  "use strict";
  c();
  Object.defineProperty(Wr, "__esModule", { value: !0 });
  Wr.isResponseOk = void 0;
  Wr.isResponseOk = (e) => {
    let { statusCode: t } = e, n = e.request.options.followRedirect ? 299 : 399;
    return t >= 200 && t <= n || t === 304;
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/utils/deprecation-warning.js
var sf = _((Na) => {
  "use strict";
  c();
  Object.defineProperty(Na, "__esModule", { value: !0 });
  var rf = /* @__PURE__ */ new Set();
  Na.default = (e) => {
    rf.has(e) || (rf.add(e), process.emitWarning(`Got: ${e}`, {
      type: "DeprecationWarning"
    }));
  };
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/as-promise/normalize-arguments.js
var af = _((Ba) => {
  "use strict";
  c();
  Object.defineProperty(Ba, "__esModule", { value: !0 });
  var $ = Ze(), kw = (e, t) => {
    if ($.default.null_(e.encoding))
      throw new TypeError("To get a Buffer, set `options.responseType` to `buffer` instead");
    $.assert.any([$.default.string, $.default.undefined], e.encoding), $.assert.any([$.default.boolean, $.default.undefined], e.resolveBodyOnly), $.assert.any([$.default.boolean, $.default.undefined], e.methodRewriting), $.assert.any([$.default.boolean, $.default.undefined], e.isStream), $.assert.any([$.default.string, $.default.undefined], e.responseType), e.responseType === void 0 && (e.responseType = "text");
    let { retry: n } = e;
    if (t ? e.retry = { ...t.retry } : e.retry = {
      calculateDelay: (r) => r.computedValue,
      limit: 0,
      methods: [],
      statusCodes: [],
      errorCodes: [],
      maxRetryAfter: void 0
    }, $.default.object(n) ? (e.retry = {
      ...e.retry,
      ...n
    }, e.retry.methods = [...new Set(e.retry.methods.map((r) => r.toUpperCase()))], e.retry.statusCodes = [...new Set(e.retry.statusCodes)], e.retry.errorCodes = [...new Set(e.retry.errorCodes)]) : $.default.number(n) && (e.retry.limit = n), $.default.undefined(e.retry.maxRetryAfter) && (e.retry.maxRetryAfter = Math.min(
      ...[e.timeout.request, e.timeout.connect].filter($.default.number)
    )), $.default.object(e.pagination)) {
      t && (e.pagination = {
        ...t.pagination,
        ...e.pagination
      });
      let { pagination: r } = e;
      if (!$.default.function_(r.transform))
        throw new Error("`options.pagination.transform` must be implemented");
      if (!$.default.function_(r.shouldContinue))
        throw new Error("`options.pagination.shouldContinue` must be implemented");
      if (!$.default.function_(r.filter))
        throw new TypeError("`options.pagination.filter` must be implemented");
      if (!$.default.function_(r.paginate))
        throw new Error("`options.pagination.paginate` must be implemented");
    }
    return e.responseType === "json" && e.headers.accept === void 0 && (e.headers.accept = "application/json"), e;
  };
  Ba.default = kw;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/calculate-retry-delay.js
var of = _(($n) => {
  "use strict";
  c();
  Object.defineProperty($n, "__esModule", { value: !0 });
  $n.retryAfterStatusCodes = void 0;
  $n.retryAfterStatusCodes = /* @__PURE__ */ new Set([413, 429, 503]);
  var Cw = ({ attemptCount: e, retryOptions: t, error: n, retryAfter: r }) => {
    if (e > t.limit)
      return 0;
    let i = t.methods.includes(n.options.method), s = t.errorCodes.includes(n.code), a = n.response && t.statusCodes.includes(n.response.statusCode);
    if (!i || !s && !a)
      return 0;
    if (n.response) {
      if (r)
        return t.maxRetryAfter === void 0 || r > t.maxRetryAfter ? 0 : r;
      if (n.response.statusCode === 413)
        return 0;
    }
    let o = Math.random() * 100;
    return 2 ** (e - 1) * 1e3 + o;
  };
  $n.default = Cw;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/core/index.js
var Gn = _((U) => {
  "use strict";
  c();
  Object.defineProperty(U, "__esModule", { value: !0 });
  U.UnsupportedProtocolError = U.ReadError = U.TimeoutError = U.UploadError = U.CacheError = U.HTTPError = U.MaxRedirectsError = U.RequestError = U.setNonEnumerableProperties = U.knownHookEvents = U.withoutBody = U.kIsNormalizedAlready = void 0;
  var cf = require("util"), lf = require("stream"), Aw = require("fs"), ot = require("url"), uf = require("http"), za = require("http"), Ow = require("https"), Pw = Ep(), jw = Op(), pf = ld(), qw = fd(), Lw = Hd(), Uw = zr(), E = Ze(), Dw = Gd(), df = ka(), Iw = Oa(), ff = Yd(), Fw = Xd(), mf = Zd(), Nw = ef(), Bw = Ia(), hf = nf(), zw = Fa(), ct = sf(), Hw = af(), Mw = of(), Ha, ue = /* @__PURE__ */ Symbol("request"), Jr = /* @__PURE__ */ Symbol("response"), nn = /* @__PURE__ */ Symbol("responseSize"), rn = /* @__PURE__ */ Symbol("downloadedSize"), sn = /* @__PURE__ */ Symbol("bodySize"), an = /* @__PURE__ */ Symbol("uploadedSize"), Gr = /* @__PURE__ */ Symbol("serverResponsesPiped"), xf = /* @__PURE__ */ Symbol("unproxyEvents"), gf = /* @__PURE__ */ Symbol("isFromCache"), Ma = /* @__PURE__ */ Symbol("cancelTimeouts"), yf = /* @__PURE__ */ Symbol("startedReading"), on = /* @__PURE__ */ Symbol("stopReading"), Kr = /* @__PURE__ */ Symbol("triggerRead"), lt = /* @__PURE__ */ Symbol("body"), Vn = /* @__PURE__ */ Symbol("jobs"), vf = /* @__PURE__ */ Symbol("originalResponse"), bf = /* @__PURE__ */ Symbol("retryTimeout");
  U.kIsNormalizedAlready = /* @__PURE__ */ Symbol("isNormalizedAlready");
  var $w = E.default.string(process.versions.brotli);
  U.withoutBody = /* @__PURE__ */ new Set(["GET", "HEAD"]);
  U.knownHookEvents = [
    "init",
    "beforeRequest",
    "beforeRedirect",
    "beforeError",
    "beforeRetry",
    // Promise-Only
    "afterResponse"
  ];
  function Vw(e) {
    for (let t in e) {
      let n = e[t];
      if (!E.default.string(n) && !E.default.number(n) && !E.default.boolean(n) && !E.default.null_(n) && !E.default.undefined(n))
        throw new TypeError(`The \`searchParams\` value '${String(n)}' must be a string, number, boolean or null`);
    }
  }
  function Ww(e) {
    return E.default.object(e) && !("statusCode" in e);
  }
  var $a = new Nw.default(), Gw = async (e) => new Promise((t, n) => {
    let r = (i) => {
      n(i);
    };
    e.pending || t(), e.once("error", r), e.once("ready", () => {
      e.off("error", r), t();
    });
  }), Kw = /* @__PURE__ */ new Set([300, 301, 302, 303, 304, 307, 308]), Jw = [
    "context",
    "body",
    "json",
    "form"
  ];
  U.setNonEnumerableProperties = (e, t) => {
    let n = {};
    for (let r of e)
      if (r)
        for (let i of Jw)
          i in r && (n[i] = {
            writable: !0,
            configurable: !0,
            enumerable: !1,
            // @ts-expect-error TS doesn't see the check above
            value: r[i]
          });
    Object.defineProperties(t, n);
  };
  var ee = class extends Error {
    constructor(t, n, r) {
      var i;
      if (super(t), Error.captureStackTrace(this, this.constructor), this.name = "RequestError", this.code = n.code, r instanceof ni ? (Object.defineProperty(this, "request", {
        enumerable: !1,
        value: r
      }), Object.defineProperty(this, "response", {
        enumerable: !1,
        value: r[Jr]
      }), Object.defineProperty(this, "options", {
        // This fails because of TS 3.7.2 useDefineForClassFields
        // Ref: https://github.com/microsoft/TypeScript/issues/34972
        enumerable: !1,
        value: r.options
      })) : Object.defineProperty(this, "options", {
        // This fails because of TS 3.7.2 useDefineForClassFields
        // Ref: https://github.com/microsoft/TypeScript/issues/34972
        enumerable: !1,
        value: r
      }), this.timings = (i = this.request) === null || i === void 0 ? void 0 : i.timings, E.default.string(n.stack) && E.default.string(this.stack)) {
        let s = this.stack.indexOf(this.message) + this.message.length, a = this.stack.slice(s).split(`
`).reverse(), o = n.stack.slice(n.stack.indexOf(n.message) + n.message.length).split(`
`).reverse();
        for (; o.length !== 0 && o[0] === a[0]; )
          a.shift();
        this.stack = `${this.stack.slice(0, s)}${a.reverse().join(`
`)}${o.reverse().join(`
`)}`;
      }
    }
  };
  U.RequestError = ee;
  var Yr = class extends ee {
    constructor(t) {
      super(`Redirected ${t.options.maxRedirects} times. Aborting.`, {}, t), this.name = "MaxRedirectsError";
    }
  };
  U.MaxRedirectsError = Yr;
  var Qr = class extends ee {
    constructor(t) {
      super(`Response code ${t.statusCode} (${t.statusMessage})`, {}, t.request), this.name = "HTTPError";
    }
  };
  U.HTTPError = Qr;
  var Xr = class extends ee {
    constructor(t, n) {
      super(t.message, t, n), this.name = "CacheError";
    }
  };
  U.CacheError = Xr;
  var Zr = class extends ee {
    constructor(t, n) {
      super(t.message, t, n), this.name = "UploadError";
    }
  };
  U.UploadError = Zr;
  var ei = class extends ee {
    constructor(t, n, r) {
      super(t.message, t, r), this.name = "TimeoutError", this.event = t.event, this.timings = n;
    }
  };
  U.TimeoutError = ei;
  var Wn = class extends ee {
    constructor(t, n) {
      super(t.message, t, n), this.name = "ReadError";
    }
  };
  U.ReadError = Wn;
  var ti = class extends ee {
    constructor(t) {
      super(`Unsupported protocol "${t.url.protocol}"`, {}, t), this.name = "UnsupportedProtocolError";
    }
  };
  U.UnsupportedProtocolError = ti;
  var Yw = [
    "socket",
    "connect",
    "continue",
    "information",
    "upgrade",
    "timeout"
  ], ni = class extends lf.Duplex {
    constructor(t, n = {}, r) {
      super({
        // This must be false, to enable throwing after destroy
        // It is used for retry logic in Promise API
        autoDestroy: !1,
        // It needs to be zero because we're just proxying the data to another stream
        highWaterMark: 0
      }), this[rn] = 0, this[an] = 0, this.requestInitialized = !1, this[Gr] = /* @__PURE__ */ new Set(), this.redirects = [], this[on] = !1, this[Kr] = !1, this[Vn] = [], this.retryCount = 0, this._progressCallbacks = [];
      let i = () => this._unlockWrite(), s = () => this._lockWrite();
      this.on("pipe", (p) => {
        p.prependListener("data", i), p.on("data", s), p.prependListener("end", i), p.on("end", s);
      }), this.on("unpipe", (p) => {
        p.off("data", i), p.off("data", s), p.off("end", i), p.off("end", s);
      }), this.on("pipe", (p) => {
        p instanceof za.IncomingMessage && (this.options.headers = {
          ...p.headers,
          ...this.options.headers
        });
      });
      let { json: a, body: o, form: l } = n;
      if ((a || o || l) && this._lockWrite(), U.kIsNormalizedAlready in n)
        this.options = n;
      else
        try {
          this.options = this.constructor.normalizeArguments(t, n, r);
        } catch (p) {
          E.default.nodeStream(n.body) && n.body.destroy(), this.destroy(p);
          return;
        }
      (async () => {
        var p;
        try {
          this.options.body instanceof Aw.ReadStream && await Gw(this.options.body);
          let { url: u } = this.options;
          if (!u)
            throw new TypeError("Missing `url` property");
          if (this.requestUrl = u.toString(), decodeURI(this.requestUrl), await this._finalizeBody(), await this._makeRequest(), this.destroyed) {
            (p = this[ue]) === null || p === void 0 || p.destroy();
            return;
          }
          for (let d of this[Vn])
            d();
          this[Vn].length = 0, this.requestInitialized = !0;
        } catch (u) {
          if (u instanceof ee) {
            this._beforeError(u);
            return;
          }
          this.destroyed || this.destroy(u);
        }
      })();
    }
    static normalizeArguments(t, n, r) {
      var i, s, a, o, l;
      let p = n;
      if (E.default.object(t) && !E.default.urlInstance(t))
        n = { ...r, ...t, ...n };
      else {
        if (t && n && n.url !== void 0)
          throw new TypeError("The `url` option is mutually exclusive with the `input` argument");
        n = { ...r, ...n }, t !== void 0 && (n.url = t), E.default.urlInstance(n.url) && (n.url = new ot.URL(n.url.toString()));
      }
      if (n.cache === !1 && (n.cache = void 0), n.dnsCache === !1 && (n.dnsCache = void 0), E.assert.any([E.default.string, E.default.undefined], n.method), E.assert.any([E.default.object, E.default.undefined], n.headers), E.assert.any([E.default.string, E.default.urlInstance, E.default.undefined], n.prefixUrl), E.assert.any([E.default.object, E.default.undefined], n.cookieJar), E.assert.any([E.default.object, E.default.string, E.default.undefined], n.searchParams), E.assert.any([E.default.object, E.default.string, E.default.undefined], n.cache), E.assert.any([E.default.object, E.default.number, E.default.undefined], n.timeout), E.assert.any([E.default.object, E.default.undefined], n.context), E.assert.any([E.default.object, E.default.undefined], n.hooks), E.assert.any([E.default.boolean, E.default.undefined], n.decompress), E.assert.any([E.default.boolean, E.default.undefined], n.ignoreInvalidCookies), E.assert.any([E.default.boolean, E.default.undefined], n.followRedirect), E.assert.any([E.default.number, E.default.undefined], n.maxRedirects), E.assert.any([E.default.boolean, E.default.undefined], n.throwHttpErrors), E.assert.any([E.default.boolean, E.default.undefined], n.http2), E.assert.any([E.default.boolean, E.default.undefined], n.allowGetBody), E.assert.any([E.default.string, E.default.undefined], n.localAddress), E.assert.any([hf.isDnsLookupIpVersion, E.default.undefined], n.dnsLookupIpVersion), E.assert.any([E.default.object, E.default.undefined], n.https), E.assert.any([E.default.boolean, E.default.undefined], n.rejectUnauthorized), n.https && (E.assert.any([E.default.boolean, E.default.undefined], n.https.rejectUnauthorized), E.assert.any([E.default.function_, E.default.undefined], n.https.checkServerIdentity), E.assert.any([E.default.string, E.default.object, E.default.array, E.default.undefined], n.https.certificateAuthority), E.assert.any([E.default.string, E.default.object, E.default.array, E.default.undefined], n.https.key), E.assert.any([E.default.string, E.default.object, E.default.array, E.default.undefined], n.https.certificate), E.assert.any([E.default.string, E.default.undefined], n.https.passphrase), E.assert.any([E.default.string, E.default.buffer, E.default.array, E.default.undefined], n.https.pfx)), E.assert.any([E.default.object, E.default.undefined], n.cacheOptions), E.default.string(n.method) ? n.method = n.method.toUpperCase() : n.method = "GET", n.headers === (r == null ? void 0 : r.headers) ? n.headers = { ...n.headers } : n.headers = Uw({ ...r == null ? void 0 : r.headers, ...n.headers }), "slashes" in n)
        throw new TypeError("The legacy `url.Url` has been deprecated. Use `URL` instead.");
      if ("auth" in n)
        throw new TypeError("Parameter `auth` is deprecated. Use `username` / `password` instead.");
      if ("searchParams" in n && n.searchParams && n.searchParams !== (r == null ? void 0 : r.searchParams)) {
        let x;
        if (E.default.string(n.searchParams) || n.searchParams instanceof ot.URLSearchParams)
          x = new ot.URLSearchParams(n.searchParams);
        else {
          Vw(n.searchParams), x = new ot.URLSearchParams();
          for (let b in n.searchParams) {
            let v = n.searchParams[b];
            v === null ? x.append(b, "") : v !== void 0 && x.append(b, v);
          }
        }
        (i = r == null ? void 0 : r.searchParams) === null || i === void 0 || i.forEach((b, v) => {
          x.has(v) || x.append(v, b);
        }), n.searchParams = x;
      }
      if (n.username = (s = n.username) !== null && s !== void 0 ? s : "", n.password = (a = n.password) !== null && a !== void 0 ? a : "", E.default.undefined(n.prefixUrl) ? n.prefixUrl = (o = r == null ? void 0 : r.prefixUrl) !== null && o !== void 0 ? o : "" : (n.prefixUrl = n.prefixUrl.toString(), n.prefixUrl !== "" && !n.prefixUrl.endsWith("/") && (n.prefixUrl += "/")), E.default.string(n.url)) {
        if (n.url.startsWith("/"))
          throw new Error("`input` must not start with a slash when using `prefixUrl`");
        n.url = mf.default(n.prefixUrl + n.url, n);
      } else (E.default.undefined(n.url) && n.prefixUrl !== "" || n.protocol) && (n.url = mf.default(n.prefixUrl, n));
      if (n.url) {
        "port" in n && delete n.port;
        let { prefixUrl: x } = n;
        Object.defineProperty(n, "prefixUrl", {
          set: (v) => {
            let h = n.url;
            if (!h.href.startsWith(v))
              throw new Error(`Cannot change \`prefixUrl\` from ${x} to ${v}: ${h.href}`);
            n.url = new ot.URL(v + h.href.slice(x.length)), x = v;
          },
          get: () => x
        });
        let { protocol: b } = n.url;
        if (b === "unix:" && (b = "http:", n.url = new ot.URL(`http://unix${n.url.pathname}${n.url.search}`)), n.searchParams && (n.url.search = n.searchParams.toString()), b !== "http:" && b !== "https:")
          throw new ti(n);
        n.username === "" ? n.username = n.url.username : n.url.username = n.username, n.password === "" ? n.password = n.url.password : n.url.password = n.password;
      }
      let { cookieJar: u } = n;
      if (u) {
        let { setCookie: x, getCookieString: b } = u;
        E.assert.function_(x), E.assert.function_(b), x.length === 4 && b.length === 0 && (x = cf.promisify(x.bind(n.cookieJar)), b = cf.promisify(b.bind(n.cookieJar)), n.cookieJar = {
          setCookie: x,
          getCookieString: b
        });
      }
      let { cache: d } = n;
      if (d && ($a.has(d) || $a.set(d, new pf(((x, b) => {
        let v = x[ue](x, b);
        return E.default.promise(v) && (v.once = (h, w) => {
          if (h === "error")
            v.catch(w);
          else if (h === "abort")
            (async () => {
              try {
                (await v).once("abort", w);
              } catch {
              }
            })();
          else
            throw new Error(`Unknown HTTP2 promise event: ${h}`);
          return v;
        }), v;
      }), d))), n.cacheOptions = { ...n.cacheOptions }, n.dnsCache === !0)
        Ha || (Ha = new jw.default()), n.dnsCache = Ha;
      else if (!E.default.undefined(n.dnsCache) && !n.dnsCache.lookup)
        throw new TypeError(`Parameter \`dnsCache\` must be a CacheableLookup instance or a boolean, got ${E.default(n.dnsCache)}`);
      E.default.number(n.timeout) ? n.timeout = { request: n.timeout } : r && n.timeout !== r.timeout ? n.timeout = {
        ...r.timeout,
        ...n.timeout
      } : n.timeout = { ...n.timeout }, n.context || (n.context = {});
      let m = n.hooks === (r == null ? void 0 : r.hooks);
      n.hooks = { ...n.hooks };
      for (let x of U.knownHookEvents)
        if (x in n.hooks)
          if (E.default.array(n.hooks[x]))
            n.hooks[x] = [...n.hooks[x]];
          else
            throw new TypeError(`Parameter \`${x}\` must be an Array, got ${E.default(n.hooks[x])}`);
        else
          n.hooks[x] = [];
      if (r && !m)
        for (let x of U.knownHookEvents)
          r.hooks[x].length > 0 && (n.hooks[x] = [
            ...r.hooks[x],
            ...n.hooks[x]
          ]);
      if ("family" in n && ct.default('"options.family" was never documented, please use "options.dnsLookupIpVersion"'), r != null && r.https && (n.https = { ...r.https, ...n.https }), "rejectUnauthorized" in n && ct.default('"options.rejectUnauthorized" is now deprecated, please use "options.https.rejectUnauthorized"'), "checkServerIdentity" in n && ct.default('"options.checkServerIdentity" was never documented, please use "options.https.checkServerIdentity"'), "ca" in n && ct.default('"options.ca" was never documented, please use "options.https.certificateAuthority"'), "key" in n && ct.default('"options.key" was never documented, please use "options.https.key"'), "cert" in n && ct.default('"options.cert" was never documented, please use "options.https.certificate"'), "passphrase" in n && ct.default('"options.passphrase" was never documented, please use "options.https.passphrase"'), "pfx" in n && ct.default('"options.pfx" was never documented, please use "options.https.pfx"'), "followRedirects" in n)
        throw new TypeError("The `followRedirects` option does not exist. Use `followRedirect` instead.");
      if (n.agent) {
        for (let x in n.agent)
          if (x !== "http" && x !== "https" && x !== "http2")
            throw new TypeError(`Expected the \`options.agent\` properties to be \`http\`, \`https\` or \`http2\`, got \`${x}\``);
      }
      return n.maxRedirects = (l = n.maxRedirects) !== null && l !== void 0 ? l : 0, U.setNonEnumerableProperties([r, p], n), Hw.default(n, r);
    }
    _lockWrite() {
      let t = () => {
        throw new TypeError("The payload has been already provided");
      };
      this.write = t, this.end = t;
    }
    _unlockWrite() {
      this.write = super.write, this.end = super.end;
    }
    async _finalizeBody() {
      let { options: t } = this, { headers: n } = t, r = !E.default.undefined(t.form), i = !E.default.undefined(t.json), s = !E.default.undefined(t.body), a = r || i || s, o = U.withoutBody.has(t.method) && !(t.method === "GET" && t.allowGetBody);
      if (this._cannotHaveBody = o, a) {
        if (o)
          throw new TypeError(`The \`${t.method}\` method cannot be used with a body`);
        if ([s, r, i].filter((l) => l).length > 1)
          throw new TypeError("The `body`, `json` and `form` options are mutually exclusive");
        if (s && !(t.body instanceof lf.Readable) && !E.default.string(t.body) && !E.default.buffer(t.body) && !df.default(t.body))
          throw new TypeError("The `body` option must be a stream.Readable, string or Buffer");
        if (r && !E.default.object(t.form))
          throw new TypeError("The `form` option must be an Object");
        {
          let l = !E.default.string(n["content-type"]);
          s ? (df.default(t.body) && l && (n["content-type"] = `multipart/form-data; boundary=${t.body.getBoundary()}`), this[lt] = t.body) : r ? (l && (n["content-type"] = "application/x-www-form-urlencoded"), this[lt] = new ot.URLSearchParams(t.form).toString()) : (l && (n["content-type"] = "application/json"), this[lt] = t.stringifyJson(t.json));
          let p = await Dw.default(this[lt], t.headers);
          E.default.undefined(n["content-length"]) && E.default.undefined(n["transfer-encoding"]) && !o && !E.default.undefined(p) && (n["content-length"] = String(p));
        }
      } else o ? this._lockWrite() : this._unlockWrite();
      this[sn] = Number(n["content-length"]) || void 0;
    }
    async _onResponseBase(t) {
      let { options: n } = this, { url: r } = n;
      this[vf] = t, n.decompress && (t = qw(t));
      let i = t.statusCode, s = t;
      s.statusMessage = s.statusMessage ? s.statusMessage : uf.STATUS_CODES[i], s.url = n.url.toString(), s.requestUrl = this.requestUrl, s.redirectUrls = this.redirects, s.request = this, s.isFromCache = t.fromCache || !1, s.ip = this.ip, s.retryCount = this.retryCount, this[gf] = s.isFromCache, this[nn] = Number(t.headers["content-length"]) || void 0, this[Jr] = t, t.once("end", () => {
        this[nn] = this[rn], this.emit("downloadProgress", this.downloadProgress);
      }), t.once("error", (o) => {
        t.destroy(), this._beforeError(new Wn(o, this));
      }), t.once("aborted", () => {
        this._beforeError(new Wn({
          name: "Error",
          message: "The server aborted pending request",
          code: "ECONNRESET"
        }, this));
      }), this.emit("downloadProgress", this.downloadProgress);
      let a = t.headers["set-cookie"];
      if (E.default.object(n.cookieJar) && a) {
        let o = a.map(async (l) => n.cookieJar.setCookie(l, r.toString()));
        n.ignoreInvalidCookies && (o = o.map(async (l) => l.catch(() => {
        })));
        try {
          await Promise.all(o);
        } catch (l) {
          this._beforeError(l);
          return;
        }
      }
      if (n.followRedirect && t.headers.location && Kw.has(i)) {
        if (t.resume(), this[ue] && (this[Ma](), delete this[ue], this[xf]()), (i === 303 && n.method !== "GET" && n.method !== "HEAD" || !n.methodRewriting) && (n.method = "GET", "body" in n && delete n.body, "json" in n && delete n.json, "form" in n && delete n.form, this[lt] = void 0, delete n.headers["content-length"]), this.redirects.length >= n.maxRedirects) {
          this._beforeError(new Yr(this));
          return;
        }
        try {
          let l = Buffer.from(t.headers.location, "binary").toString(), p = new ot.URL(l, r), u = p.toString();
          decodeURI(u), p.hostname !== r.hostname || p.port !== r.port ? ("host" in n.headers && delete n.headers.host, "cookie" in n.headers && delete n.headers.cookie, "authorization" in n.headers && delete n.headers.authorization, (n.username || n.password) && (n.username = "", n.password = "")) : (p.username = n.username, p.password = n.password), this.redirects.push(u), n.url = p;
          for (let d of n.hooks.beforeRedirect)
            await d(n, s);
          this.emit("redirect", s, n), await this._makeRequest();
        } catch (l) {
          this._beforeError(l);
          return;
        }
        return;
      }
      if (n.isStream && n.throwHttpErrors && !zw.isResponseOk(s)) {
        this._beforeError(new Qr(s));
        return;
      }
      t.on("readable", () => {
        this[Kr] && this._read();
      }), this.on("resume", () => {
        t.resume();
      }), this.on("pause", () => {
        t.pause();
      }), t.once("end", () => {
        this.push(null);
      }), this.emit("response", t);
      for (let o of this[Gr])
        if (!o.headersSent) {
          for (let l in t.headers) {
            let p = n.decompress ? l !== "content-encoding" : !0, u = t.headers[l];
            p && o.setHeader(l, u);
          }
          o.statusCode = i;
        }
    }
    async _onResponse(t) {
      try {
        await this._onResponseBase(t);
      } catch (n) {
        this._beforeError(n);
      }
    }
    _onRequest(t) {
      let { options: n } = this, { timeout: r, url: i } = n;
      Pw.default(t), this[Ma] = ff.default(t, r, i);
      let s = n.cache ? "cacheableResponse" : "response";
      t.once(s, (l) => {
        this._onResponse(l);
      }), t.once("error", (l) => {
        var p;
        t.destroy(), (p = t.res) === null || p === void 0 || p.removeAllListeners("end"), l = l instanceof ff.TimeoutError ? new ei(l, this.timings, this) : new ee(l.message, l, this), this._beforeError(l);
      }), this[xf] = Iw.default(t, this, Yw), this[ue] = t, this.emit("uploadProgress", this.uploadProgress);
      let a = this[lt], o = this.redirects.length === 0 ? this : t;
      E.default.nodeStream(a) ? (a.pipe(o), a.once("error", (l) => {
        this._beforeError(new Zr(l, this));
      })) : (this._unlockWrite(), E.default.undefined(a) ? (this._cannotHaveBody || this._noPipe) && (o.end(), this._lockWrite()) : (this._writeRequest(a, void 0, () => {
      }), o.end(), this._lockWrite())), this.emit("request", t);
    }
    async _createCacheableRequest(t, n) {
      return new Promise((r, i) => {
        Object.assign(n, Fw.default(t)), delete n.url;
        let s, a = $a.get(n.cache)(n, async (o) => {
          o._readableState.autoDestroy = !1, s && (await s).emit("cacheableResponse", o), r(o);
        });
        n.url = t, a.once("error", i), a.once("request", async (o) => {
          s = o, r(s);
        });
      });
    }
    async _makeRequest() {
      var t, n, r, i, s;
      let { options: a } = this, { headers: o } = a;
      for (let w in o)
        if (E.default.undefined(o[w]))
          delete o[w];
        else if (E.default.null_(o[w]))
          throw new TypeError(`Use \`undefined\` instead of \`null\` to delete the \`${w}\` header`);
      if (a.decompress && E.default.undefined(o["accept-encoding"]) && (o["accept-encoding"] = $w ? "gzip, deflate, br" : "gzip, deflate"), a.cookieJar) {
        let w = await a.cookieJar.getCookieString(a.url.toString());
        E.default.nonEmptyString(w) && (a.headers.cookie = w);
      }
      for (let w of a.hooks.beforeRequest) {
        let T = await w(a);
        if (!E.default.undefined(T)) {
          a.request = () => T;
          break;
        }
      }
      a.body && this[lt] !== a.body && (this[lt] = a.body);
      let { agent: l, request: p, timeout: u, url: d } = a;
      if (a.dnsCache && !("lookup" in a) && (a.lookup = a.dnsCache.lookup), d.hostname === "unix") {
        let w = /(?<socketPath>.+?):(?<path>.+)/.exec(`${d.pathname}${d.search}`);
        if (w != null && w.groups) {
          let { socketPath: T, path: A } = w.groups;
          Object.assign(a, {
            socketPath: T,
            path: A,
            host: ""
          });
        }
      }
      let m = d.protocol === "https:", x;
      a.http2 ? x = Lw.auto : x = m ? Ow.request : uf.request;
      let b = (t = a.request) !== null && t !== void 0 ? t : x, v = a.cache ? this._createCacheableRequest : b;
      l && !a.http2 && (a.agent = l[m ? "https" : "http"]), a[ue] = b, delete a.request, delete a.timeout;
      let h = a;
      if (h.shared = (n = a.cacheOptions) === null || n === void 0 ? void 0 : n.shared, h.cacheHeuristic = (r = a.cacheOptions) === null || r === void 0 ? void 0 : r.cacheHeuristic, h.immutableMinTimeToLive = (i = a.cacheOptions) === null || i === void 0 ? void 0 : i.immutableMinTimeToLive, h.ignoreCargoCult = (s = a.cacheOptions) === null || s === void 0 ? void 0 : s.ignoreCargoCult, a.dnsLookupIpVersion !== void 0)
        try {
          h.family = hf.dnsLookupIpVersionToFamily(a.dnsLookupIpVersion);
        } catch {
          throw new Error("Invalid `dnsLookupIpVersion` option value");
        }
      a.https && ("rejectUnauthorized" in a.https && (h.rejectUnauthorized = a.https.rejectUnauthorized), a.https.checkServerIdentity && (h.checkServerIdentity = a.https.checkServerIdentity), a.https.certificateAuthority && (h.ca = a.https.certificateAuthority), a.https.certificate && (h.cert = a.https.certificate), a.https.key && (h.key = a.https.key), a.https.passphrase && (h.passphrase = a.https.passphrase), a.https.pfx && (h.pfx = a.https.pfx));
      try {
        let w = await v(d, h);
        E.default.undefined(w) && (w = x(d, h)), a.request = p, a.timeout = u, a.agent = l, a.https && ("rejectUnauthorized" in a.https && delete h.rejectUnauthorized, a.https.checkServerIdentity && delete h.checkServerIdentity, a.https.certificateAuthority && delete h.ca, a.https.certificate && delete h.cert, a.https.key && delete h.key, a.https.passphrase && delete h.passphrase, a.https.pfx && delete h.pfx), Ww(w) ? this._onRequest(w) : this.writable ? (this.once("finish", () => {
          this._onResponse(w);
        }), this._unlockWrite(), this.end(), this._lockWrite()) : this._onResponse(w);
      } catch (w) {
        throw w instanceof pf.CacheError ? new Xr(w, this) : new ee(w.message, w, this);
      }
    }
    async _error(t) {
      try {
        for (let n of this.options.hooks.beforeError)
          t = await n(t);
      } catch (n) {
        t = new ee(n.message, n, this);
      }
      this.destroy(t);
    }
    _beforeError(t) {
      if (this[on])
        return;
      let { options: n } = this, r = this.retryCount + 1;
      this[on] = !0, t instanceof ee || (t = new ee(t.message, t, this));
      let i = t, { response: s } = i;
      (async () => {
        if (s && !s.body) {
          s.setEncoding(this._readableState.encoding);
          try {
            s.rawBody = await Bw.default(s), s.body = s.rawBody.toString();
          } catch {
          }
        }
        if (this.listenerCount("retry") !== 0) {
          let a;
          try {
            let o;
            s && "retry-after" in s.headers && (o = Number(s.headers["retry-after"]), Number.isNaN(o) ? (o = Date.parse(s.headers["retry-after"]) - Date.now(), o <= 0 && (o = 1)) : o *= 1e3), a = await n.retry.calculateDelay({
              attemptCount: r,
              retryOptions: n.retry,
              error: i,
              retryAfter: o,
              computedValue: Mw.default({
                attemptCount: r,
                retryOptions: n.retry,
                error: i,
                retryAfter: o,
                computedValue: 0
              })
            });
          } catch (o) {
            this._error(new ee(o.message, o, this));
            return;
          }
          if (a) {
            let o = async () => {
              try {
                for (let l of this.options.hooks.beforeRetry)
                  await l(this.options, i, r);
              } catch (l) {
                this._error(new ee(l.message, t, this));
                return;
              }
              this.destroyed || (this.destroy(), this.emit("retry", r, t));
            };
            this[bf] = setTimeout(o, a);
            return;
          }
        }
        this._error(i);
      })();
    }
    _read() {
      this[Kr] = !0;
      let t = this[Jr];
      if (t && !this[on]) {
        t.readableLength && (this[Kr] = !1);
        let n;
        for (; (n = t.read()) !== null; ) {
          this[rn] += n.length, this[yf] = !0;
          let r = this.downloadProgress;
          r.percent < 1 && this.emit("downloadProgress", r), this.push(n);
        }
      }
    }
    // Node.js 12 has incorrect types, so the encoding must be a string
    _write(t, n, r) {
      let i = () => {
        this._writeRequest(t, n, r);
      };
      this.requestInitialized ? i() : this[Vn].push(i);
    }
    _writeRequest(t, n, r) {
      this[ue].destroyed || (this._progressCallbacks.push(() => {
        this[an] += Buffer.byteLength(t, n);
        let i = this.uploadProgress;
        i.percent < 1 && this.emit("uploadProgress", i);
      }), this[ue].write(t, n, (i) => {
        !i && this._progressCallbacks.length > 0 && this._progressCallbacks.shift()(), r(i);
      }));
    }
    _final(t) {
      let n = () => {
        for (; this._progressCallbacks.length !== 0; )
          this._progressCallbacks.shift()();
        if (!(ue in this)) {
          t();
          return;
        }
        if (this[ue].destroyed) {
          t();
          return;
        }
        this[ue].end((r) => {
          r || (this[sn] = this[an], this.emit("uploadProgress", this.uploadProgress), this[ue].emit("upload-complete")), t(r);
        });
      };
      this.requestInitialized ? n() : this[Vn].push(n);
    }
    _destroy(t, n) {
      var r;
      this[on] = !0, clearTimeout(this[bf]), ue in this && (this[Ma](), !((r = this[Jr]) === null || r === void 0) && r.complete || this[ue].destroy()), t !== null && !E.default.undefined(t) && !(t instanceof ee) && (t = new ee(t.message, t, this)), n(t);
    }
    get _isAboutToError() {
      return this[on];
    }
    /**
    The remote IP address.
    */
    get ip() {
      var t;
      return (t = this.socket) === null || t === void 0 ? void 0 : t.remoteAddress;
    }
    /**
    Indicates whether the request has been aborted or not.
    */
    get aborted() {
      var t, n, r;
      return ((n = (t = this[ue]) === null || t === void 0 ? void 0 : t.destroyed) !== null && n !== void 0 ? n : this.destroyed) && !(!((r = this[vf]) === null || r === void 0) && r.complete);
    }
    get socket() {
      var t, n;
      return (n = (t = this[ue]) === null || t === void 0 ? void 0 : t.socket) !== null && n !== void 0 ? n : void 0;
    }
    /**
    Progress event for downloading (receiving a response).
    */
    get downloadProgress() {
      let t;
      return this[nn] ? t = this[rn] / this[nn] : this[nn] === this[rn] ? t = 1 : t = 0, {
        percent: t,
        transferred: this[rn],
        total: this[nn]
      };
    }
    /**
    Progress event for uploading (sending a request).
    */
    get uploadProgress() {
      let t;
      return this[sn] ? t = this[an] / this[sn] : this[sn] === this[an] ? t = 1 : t = 0, {
        percent: t,
        transferred: this[an],
        total: this[sn]
      };
    }
    /**
        The object contains the following properties:
    
        - `start` - Time when the request started.
        - `socket` - Time when a socket was assigned to the request.
        - `lookup` - Time when the DNS lookup finished.
        - `connect` - Time when the socket successfully connected.
        - `secureConnect` - Time when the socket securely connected.
        - `upload` - Time when the request finished uploading.
        - `response` - Time when the request fired `response` event.
        - `end` - Time when the response fired `end` event.
        - `error` - Time when the request fired `error` event.
        - `abort` - Time when the request fired `abort` event.
        - `phases`
            - `wait` - `timings.socket - timings.start`
            - `dns` - `timings.lookup - timings.socket`
            - `tcp` - `timings.connect - timings.lookup`
            - `tls` - `timings.secureConnect - timings.connect`
            - `request` - `timings.upload - (timings.secureConnect || timings.connect)`
            - `firstByte` - `timings.response - timings.upload`
            - `download` - `timings.end - timings.response`
            - `total` - `(timings.end || timings.error || timings.abort) - timings.start`
    
        If something has not been measured yet, it will be `undefined`.
    
        __Note__: The time is a `number` representing the milliseconds elapsed since the UNIX epoch.
        */
    get timings() {
      var t;
      return (t = this[ue]) === null || t === void 0 ? void 0 : t.timings;
    }
    /**
    Whether the response was retrieved from the cache.
    */
    get isFromCache() {
      return this[gf];
    }
    pipe(t, n) {
      if (this[yf])
        throw new Error("Failed to pipe. The response has been emitted already.");
      return t instanceof za.ServerResponse && this[Gr].add(t), super.pipe(t, n);
    }
    unpipe(t) {
      return t instanceof za.ServerResponse && this[Gr].delete(t), super.unpipe(t), this;
    }
  };
  U.default = ni;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/as-promise/types.js
var Kn = _((Ne) => {
  "use strict";
  c();
  var Qw = Ne && Ne.__createBinding || (Object.create ? (function(e, t, n, r) {
    r === void 0 && (r = n), Object.defineProperty(e, r, { enumerable: !0, get: function() {
      return t[n];
    } });
  }) : (function(e, t, n, r) {
    r === void 0 && (r = n), e[r] = t[n];
  })), Xw = Ne && Ne.__exportStar || function(e, t) {
    for (var n in e) n !== "default" && !Object.prototype.hasOwnProperty.call(t, n) && Qw(t, e, n);
  };
  Object.defineProperty(Ne, "__esModule", { value: !0 });
  Ne.CancelError = Ne.ParseError = void 0;
  var wf = Gn(), Va = class extends wf.RequestError {
    constructor(t, n) {
      let { options: r } = n.request;
      super(`${t.message} in "${r.url.toString()}"`, t, n.request), this.name = "ParseError";
    }
  };
  Ne.ParseError = Va;
  var Wa = class extends wf.RequestError {
    constructor(t) {
      super("Promise was canceled", {}, t), this.name = "CancelError";
    }
    get isCanceled() {
      return !0;
    }
  };
  Ne.CancelError = Wa;
  Xw(Gn(), Ne);
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/as-promise/parse-body.js
var Ef = _((Ga) => {
  "use strict";
  c();
  Object.defineProperty(Ga, "__esModule", { value: !0 });
  var _f = Kn(), Zw = (e, t, n, r) => {
    let { rawBody: i } = e;
    try {
      if (t === "text")
        return i.toString(r);
      if (t === "json")
        return i.length === 0 ? "" : n(i.toString());
      if (t === "buffer")
        return i;
      throw new _f.ParseError({
        message: `Unknown body type '${t}'`,
        name: "Error"
      }, e);
    } catch (s) {
      throw new _f.ParseError(s, e);
    }
  };
  Ga.default = Zw;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/as-promise/index.js
var Ka = _((ut) => {
  "use strict";
  c();
  var e_ = ut && ut.__createBinding || (Object.create ? (function(e, t, n, r) {
    r === void 0 && (r = n), Object.defineProperty(e, r, { enumerable: !0, get: function() {
      return t[n];
    } });
  }) : (function(e, t, n, r) {
    r === void 0 && (r = n), e[r] = t[n];
  })), t_ = ut && ut.__exportStar || function(e, t) {
    for (var n in e) n !== "default" && !Object.prototype.hasOwnProperty.call(t, n) && e_(t, e, n);
  };
  Object.defineProperty(ut, "__esModule", { value: !0 });
  var n_ = require("events"), r_ = Ze(), i_ = wp(), ri = Kn(), Sf = Ef(), Rf = Gn(), s_ = Oa(), a_ = Ia(), Tf = Fa(), o_ = [
    "request",
    "response",
    "redirect",
    "uploadProgress",
    "downloadProgress"
  ];
  function kf(e) {
    let t, n, r = new n_.EventEmitter(), i = new i_((a, o, l) => {
      let p = (u) => {
        let d = new Rf.default(void 0, e);
        d.retryCount = u, d._noPipe = !0, l(() => d.destroy()), l.shouldReject = !1, l(() => o(new ri.CancelError(d))), t = d, d.once("response", async (b) => {
          var v;
          if (b.retryCount = u, b.request.aborted)
            return;
          let h;
          try {
            h = await a_.default(d), b.rawBody = h;
          } catch {
            return;
          }
          if (d._isAboutToError)
            return;
          let w = ((v = b.headers["content-encoding"]) !== null && v !== void 0 ? v : "").toLowerCase(), T = ["gzip", "deflate", "br"].includes(w), { options: A } = d;
          if (T && !A.decompress)
            b.body = h;
          else
            try {
              b.body = Sf.default(b, A.responseType, A.parseJson, A.encoding);
            } catch (O) {
              if (b.body = h.toString(), Tf.isResponseOk(b)) {
                d._beforeError(O);
                return;
              }
            }
          try {
            for (let [O, q] of A.hooks.afterResponse.entries())
              b = await q(b, async (W) => {
                let ne = Rf.default.normalizeArguments(void 0, {
                  ...W,
                  retry: {
                    calculateDelay: () => 0
                  },
                  throwHttpErrors: !1,
                  resolveBodyOnly: !1
                }, A);
                ne.hooks.afterResponse = ne.hooks.afterResponse.slice(0, O);
                for (let Ce of ne.hooks.beforeRetry)
                  await Ce(ne);
                let re = kf(ne);
                return l(() => {
                  re.catch(() => {
                  }), re.cancel();
                }), re;
              });
          } catch (O) {
            d._beforeError(new ri.RequestError(O.message, O, d));
            return;
          }
          if (!Tf.isResponseOk(b)) {
            d._beforeError(new ri.HTTPError(b));
            return;
          }
          n = b, a(d.options.resolveBodyOnly ? b.body : b);
        });
        let m = (b) => {
          if (i.isCanceled)
            return;
          let { options: v } = d;
          if (b instanceof ri.HTTPError && !v.throwHttpErrors) {
            let { response: h } = b;
            a(d.options.resolveBodyOnly ? h.body : h);
            return;
          }
          o(b);
        };
        d.once("error", m);
        let x = d.options.body;
        d.once("retry", (b, v) => {
          var h, w;
          if (x === ((h = v.request) === null || h === void 0 ? void 0 : h.options.body) && r_.default.nodeStream((w = v.request) === null || w === void 0 ? void 0 : w.options.body)) {
            m(v);
            return;
          }
          p(b);
        }), s_.default(d, r, o_);
      };
      p(0);
    });
    i.on = (a, o) => (r.on(a, o), i);
    let s = (a) => {
      let o = (async () => {
        await i;
        let { options: l } = n.request;
        return Sf.default(n, a, l.parseJson, l.encoding);
      })();
      return Object.defineProperties(o, Object.getOwnPropertyDescriptors(i)), o;
    };
    return i.json = () => {
      let { headers: a } = t.options;
      return !t.writableFinished && a.accept === void 0 && (a.accept = "application/json"), s("json");
    }, i.buffer = () => s("buffer"), i.text = () => s("text"), i;
  }
  ut.default = kf;
  t_(Kn(), ut);
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/as-promise/create-rejection.js
var Cf = _((Ja) => {
  "use strict";
  c();
  Object.defineProperty(Ja, "__esModule", { value: !0 });
  var c_ = Kn();
  function l_(e, ...t) {
    let n = (async () => {
      if (e instanceof c_.RequestError)
        try {
          for (let i of t)
            if (i)
              for (let s of i)
                e = await s(e);
        } catch (i) {
          e = i;
        }
      throw e;
    })(), r = () => n;
    return n.json = r, n.text = r, n.buffer = r, n.on = r, n;
  }
  Ja.default = l_;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/utils/deep-freeze.js
var Pf = _((Ya) => {
  "use strict";
  c();
  Object.defineProperty(Ya, "__esModule", { value: !0 });
  var Af = Ze();
  function Of(e) {
    for (let t of Object.values(e))
      (Af.default.plainObject(t) || Af.default.array(t)) && Of(t);
    return Object.freeze(e);
  }
  Ya.default = Of;
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/types.js
var qf = _((jf) => {
  "use strict";
  c();
  Object.defineProperty(jf, "__esModule", { value: !0 });
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/create.js
var Qa = _((Le) => {
  "use strict";
  c();
  var u_ = Le && Le.__createBinding || (Object.create ? (function(e, t, n, r) {
    r === void 0 && (r = n), Object.defineProperty(e, r, { enumerable: !0, get: function() {
      return t[n];
    } });
  }) : (function(e, t, n, r) {
    r === void 0 && (r = n), e[r] = t[n];
  })), p_ = Le && Le.__exportStar || function(e, t) {
    for (var n in e) n !== "default" && !Object.prototype.hasOwnProperty.call(t, n) && u_(t, e, n);
  };
  Object.defineProperty(Le, "__esModule", { value: !0 });
  Le.defaultHandler = void 0;
  var Lf = Ze(), qe = Ka(), d_ = Cf(), si = Gn(), f_ = Pf(), m_ = {
    RequestError: qe.RequestError,
    CacheError: qe.CacheError,
    ReadError: qe.ReadError,
    HTTPError: qe.HTTPError,
    MaxRedirectsError: qe.MaxRedirectsError,
    TimeoutError: qe.TimeoutError,
    ParseError: qe.ParseError,
    CancelError: qe.CancelError,
    UnsupportedProtocolError: qe.UnsupportedProtocolError,
    UploadError: qe.UploadError
  }, h_ = async (e) => new Promise((t) => {
    setTimeout(t, e);
  }), { normalizeArguments: ii } = si.default, Uf = (...e) => {
    let t;
    for (let n of e)
      t = ii(void 0, n, t);
    return t;
  }, x_ = (e) => e.isStream ? new si.default(void 0, e) : qe.default(e), g_ = (e) => "defaults" in e && "options" in e.defaults, y_ = [
    "get",
    "post",
    "put",
    "patch",
    "head",
    "delete"
  ];
  Le.defaultHandler = (e, t) => t(e);
  var Df = (e, t) => {
    if (e)
      for (let n of e)
        n(t);
  }, If = (e) => {
    e._rawHandlers = e.handlers, e.handlers = e.handlers.map((r) => ((i, s) => {
      let a, o = r(i, (l) => (a = s(l), a));
      if (o !== a && !i.isStream && a) {
        let l = o, { then: p, catch: u, finally: d } = l;
        Object.setPrototypeOf(l, Object.getPrototypeOf(a)), Object.defineProperties(l, Object.getOwnPropertyDescriptors(a)), l.then = p, l.catch = u, l.finally = d;
      }
      return o;
    }));
    let t = ((r, i = {}, s) => {
      var a, o;
      let l = 0, p = (u) => e.handlers[l++](u, l === e.handlers.length ? x_ : p);
      if (Lf.default.plainObject(r)) {
        let u = {
          ...r,
          ...i
        };
        si.setNonEnumerableProperties([r, i], u), i = u, r = void 0;
      }
      try {
        let u;
        try {
          Df(e.options.hooks.init, i), Df((a = i.hooks) === null || a === void 0 ? void 0 : a.init, i);
        } catch (m) {
          u = m;
        }
        let d = ii(r, i, s ?? e.options);
        if (d[si.kIsNormalizedAlready] = !0, u)
          throw new qe.RequestError(u.message, u, d);
        return p(d);
      } catch (u) {
        if (i.isStream)
          throw u;
        return d_.default(u, e.options.hooks.beforeError, (o = i.hooks) === null || o === void 0 ? void 0 : o.beforeError);
      }
    });
    t.extend = (...r) => {
      let i = [e.options], s = [...e._rawHandlers], a;
      for (let o of r)
        g_(o) ? (i.push(o.defaults.options), s.push(...o.defaults._rawHandlers), a = o.defaults.mutableDefaults) : (i.push(o), "handlers" in o && s.push(...o.handlers), a = o.mutableDefaults);
      return s = s.filter((o) => o !== Le.defaultHandler), s.length === 0 && s.push(Le.defaultHandler), If({
        options: Uf(...i),
        handlers: s,
        mutableDefaults: !!a
      });
    };
    let n = (async function* (r, i) {
      let s = ii(r, i, e.options);
      s.resolveBodyOnly = !1;
      let a = s.pagination;
      if (!Lf.default.object(a))
        throw new TypeError("`options.pagination` must be implemented");
      let o = [], { countLimit: l } = a, p = 0;
      for (; p < a.requestLimit; ) {
        p !== 0 && await h_(a.backoff);
        let u = await t(void 0, void 0, s), d = await a.transform(u), m = [];
        for (let b of d)
          if (a.filter(b, o, m) && (!a.shouldContinue(b, o, m) || (yield b, a.stackAllItems && o.push(b), m.push(b), --l <= 0)))
            return;
        let x = a.paginate(u, o, m);
        if (x === !1)
          return;
        x === u.request.options ? s = u.request.options : x !== void 0 && (s = ii(void 0, x, s)), p++;
      }
    });
    t.paginate = n, t.paginate.all = (async (r, i) => {
      let s = [];
      for await (let a of n(r, i))
        s.push(a);
      return s;
    }), t.paginate.each = n, t.stream = ((r, i) => t(r, { ...i, isStream: !0 }));
    for (let r of y_)
      t[r] = ((i, s) => t(i, { ...s, method: r })), t.stream[r] = ((i, s) => t(i, { ...s, method: r, isStream: !0 }));
    return Object.assign(t, m_), Object.defineProperty(t, "defaults", {
      value: e.mutableDefaults ? e : f_.default(e),
      writable: e.mutableDefaults,
      configurable: e.mutableDefaults,
      enumerable: !0
    }), t.mergeOptions = Uf, t;
  };
  Le.default = If;
  p_(qf(), Le);
});

// node_modules/.pnpm/got@11.8.2/node_modules/got/dist/source/index.js
var Za = _((tt, ai) => {
  "use strict";
  c();
  var v_ = tt && tt.__createBinding || (Object.create ? (function(e, t, n, r) {
    r === void 0 && (r = n), Object.defineProperty(e, r, { enumerable: !0, get: function() {
      return t[n];
    } });
  }) : (function(e, t, n, r) {
    r === void 0 && (r = n), e[r] = t[n];
  })), Ff = tt && tt.__exportStar || function(e, t) {
    for (var n in e) n !== "default" && !Object.prototype.hasOwnProperty.call(t, n) && v_(t, e, n);
  };
  Object.defineProperty(tt, "__esModule", { value: !0 });
  var b_ = require("url"), Nf = Qa(), w_ = {
    options: {
      method: "GET",
      retry: {
        limit: 2,
        methods: [
          "GET",
          "PUT",
          "HEAD",
          "DELETE",
          "OPTIONS",
          "TRACE"
        ],
        statusCodes: [
          408,
          413,
          429,
          500,
          502,
          503,
          504,
          521,
          522,
          524
        ],
        errorCodes: [
          "ETIMEDOUT",
          "ECONNRESET",
          "EADDRINUSE",
          "ECONNREFUSED",
          "EPIPE",
          "ENOTFOUND",
          "ENETUNREACH",
          "EAI_AGAIN"
        ],
        maxRetryAfter: void 0,
        calculateDelay: ({ computedValue: e }) => e
      },
      timeout: {},
      headers: {
        "user-agent": "got (https://github.com/sindresorhus/got)"
      },
      hooks: {
        init: [],
        beforeRequest: [],
        beforeRedirect: [],
        beforeRetry: [],
        beforeError: [],
        afterResponse: []
      },
      cache: void 0,
      dnsCache: void 0,
      decompress: !0,
      throwHttpErrors: !0,
      followRedirect: !0,
      isStream: !1,
      responseType: "text",
      resolveBodyOnly: !1,
      maxRedirects: 10,
      prefixUrl: "",
      methodRewriting: !0,
      ignoreInvalidCookies: !1,
      context: {},
      // TODO: Set this to `true` when Got 12 gets released
      http2: !1,
      allowGetBody: !1,
      https: void 0,
      pagination: {
        transform: (e) => e.request.options.responseType === "json" ? e.body : JSON.parse(e.body),
        paginate: (e) => {
          if (!Reflect.has(e.headers, "link"))
            return !1;
          let t = e.headers.link.split(","), n;
          for (let r of t) {
            let i = r.split(";");
            if (i[1].includes("next")) {
              n = i[0].trimStart().trim(), n = n.slice(1, -1);
              break;
            }
          }
          return n ? {
            url: new b_.URL(n)
          } : !1;
        },
        filter: () => !0,
        shouldContinue: () => !0,
        countLimit: 1 / 0,
        backoff: 0,
        requestLimit: 1e4,
        stackAllItems: !0
      },
      parseJson: (e) => JSON.parse(e),
      stringifyJson: (e) => JSON.stringify(e),
      cacheOptions: {}
    },
    handlers: [Nf.defaultHandler],
    mutableDefaults: !1
  }, Xa = Nf.default(w_);
  tt.default = Xa;
  ai.exports = Xa;
  ai.exports.default = Xa;
  ai.exports.__esModule = !0;
  Ff(Qa(), tt);
  Ff(Ka(), tt);
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/types.js
var oi = _((Be) => {
  "use strict";
  c();
  Object.defineProperty(Be, "__esModule", { value: !0 });
  Be.QRCodeStatus = Be.OrderByType = Be.MediaType = void 0;
  var __;
  (function(e) {
    e[e.ALL = 0] = "ALL", e[e.IMAGE = 1] = "IMAGE", e[e.MUSIC = 2] = "MUSIC", e[e.VIDEO = 3] = "VIDEO", e[e.TXT = 4] = "TXT";
  })(__ = Be.MediaType || (Be.MediaType = {}));
  var E_;
  (function(e) {
    e[e.NAME = 1] = "NAME", e[e.SIZE = 2] = "SIZE", e[e.LAST_OP_TIME = 3] = "LAST_OP_TIME";
  })(E_ = Be.OrderByType || (Be.OrderByType = {}));
  var S_;
  (function(e) {
    e[e.SUCCESS = 0] = "SUCCESS", e[e.WAITING = -106] = "WAITING", e[e.SCANNED = -11002] = "SCANNED", e[e.EXPIRED = -11001] = "EXPIRED";
  })(S_ = Be.QRCodeStatus || (Be.QRCodeStatus = {}));
});

// node_modules/.pnpm/@netdrive-sdk+log@1.0.0/node_modules/@netdrive-sdk/log/dist/index.js
var zf = _((cn) => {
  "use strict";
  c();
  var Bf = cn && cn.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  };
  Object.defineProperty(cn, "__esModule", { value: !0 });
  cn.Logger = void 0;
  var We = Bf(require("fs")), ze = Bf(require("path")), R_ = {
    info: "[INFO]",
    warn: "[WARN]",
    error: "[ERROR]",
    debug: "[DEBUG]",
    notice: "[NOTICE]"
  }, eo = class {
    fileStream = null;
    stream;
    currentFileSize = 0;
    options;
    logDirectory;
    baseLogPath;
    logFileExt;
    baseLogName;
    constructor(t = {}, n) {
      this.options = {
        consoleOutput: !0,
        fileOutput: !1,
        filePath: ze.default.join(process.cwd(), "logs", "app.log"),
        maxFileSize: 1024 * 1024 * 10,
        // 10MB
        maxFiles: 5,
        isDebugEnabled: !1,
        ...t
      }, this.logDirectory = ze.default.dirname(this.options.filePath), this.baseLogPath = this.options.filePath, this.logFileExt = ze.default.extname(this.baseLogPath), this.baseLogName = ze.default.basename(this.baseLogPath, this.logFileExt), this.stream = n || process.stdout, this.options.fileOutput && (this.ensureLogDirectory(), this.createFileStream());
    }
    configure(t) {
      this.options = {
        ...this.options,
        ...t
      }, (t.fileOutput !== void 0 || t.filePath !== void 0) && (this.close(), this.options.fileOutput && (this.logDirectory = ze.default.dirname(this.options.filePath), this.baseLogPath = this.options.filePath, this.logFileExt = ze.default.extname(this.baseLogPath), this.baseLogName = ze.default.basename(this.baseLogPath, this.logFileExt), this.ensureLogDirectory(), this.createFileStream()));
    }
    messageTransformer = (t) => t;
    ensureLogDirectory() {
      We.default.existsSync(this.logDirectory) || We.default.mkdirSync(this.logDirectory, { recursive: !0 });
    }
    createFileStream() {
      this.fileStream = We.default.createWriteStream(this.baseLogPath, { flags: "a" }), this.currentFileSize = We.default.existsSync(this.baseLogPath) ? We.default.statSync(this.baseLogPath).size : 0;
    }
    rotateLogFile() {
      if (!this.fileStream || !this.options.fileOutput)
        return;
      this.fileStream.end();
      let t = ze.default.join(this.logDirectory, `${this.baseLogName}.${this.options.maxFiles}${this.logFileExt}`);
      We.default.existsSync(t) && We.default.unlinkSync(t);
      for (let n = this.options.maxFiles - 1; n >= 1; n--) {
        let r = ze.default.join(this.logDirectory, `${this.baseLogName}.${n}${this.logFileExt}`), i = ze.default.join(this.logDirectory, `${this.baseLogName}.${n + 1}${this.logFileExt}`);
        We.default.existsSync(r) && We.default.renameSync(r, i);
      }
      We.default.renameSync(this.baseLogPath, ze.default.join(this.logDirectory, `${this.baseLogName}.1${this.logFileExt}`)), this.createFileStream(), this.currentFileSize = 0;
    }
    writeToFile(t) {
      if (!this.fileStream || !this.options.fileOutput)
        return;
      let n = `${t}
`;
      this.currentFileSize += Buffer.byteLength(n), this.currentFileSize > this.options.maxFileSize && this.rotateLogFile(), this.fileStream.write(n);
    }
    info(t) {
      this._doLog(t, "info");
    }
    error(t) {
      this._doLog(t, "error");
    }
    warn(t) {
      this._doLog(t, "warn");
    }
    debug(t) {
      this.options.isDebugEnabled && this._doLog(t, "debug");
    }
    notice(t) {
      this._doLog(t, "notice");
    }
    getTimestamp() {
      return (/* @__PURE__ */ new Date()).toLocaleString("zh-CN", {
        year: "numeric",
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit"
      }).replace(/\//g, "-");
    }
    _doLog(t, n) {
      let r = "undefined";
      t === null ? r = "null" : t instanceof Error ? r = t.stack || t.toString() : typeof t == "string" ? r = t : r = JSON.stringify(t);
      let i = this.getTimestamp(), s = R_[n], a = `[${i}] ${s} ${this.messageTransformer(r, n)}
`;
      this.options.consoleOutput && this.stream.write(a), this.options.fileOutput && this.writeToFile(a.trim());
    }
    close() {
      this.fileStream && (this.fileStream.end(), this.fileStream = null);
    }
  };
  cn.Logger = eo;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/log.js
var ln = _((ci) => {
  "use strict";
  c();
  Object.defineProperty(ci, "__esModule", { value: !0 });
  ci.logger = void 0;
  var T_ = zf(), k_ = new T_.Logger();
  ci.logger = k_;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/util.js
var li = _((N) => {
  "use strict";
  c();
  var Hf = N && N.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  };
  Object.defineProperty(N, "__esModule", { value: !0 });
  N.asyncPool = N.calculateFileAndChunkMD5 = N.partSize = N.randomString = N.md5 = N.hexToBase64 = N.hmacSha1 = N.aesECBEncrypt = N.rsaEncrypt = N.getSignature = N.sortParameter = void 0;
  var kt = Hf(require("crypto")), C_ = Hf(require("fs")), A_ = (e) => {
    if (!e)
      return "";
    let t = Object.entries(e).map((n) => n.join("="));
    return t.sort((n, r) => n > r ? 1 : n < r ? -1 : 0), t.join("&");
  };
  N.sortParameter = A_;
  var O_ = (e) => {
    let t = (0, N.sortParameter)(e);
    return kt.default.createHash("md5").update(t).digest("hex");
  };
  N.getSignature = O_;
  var P_ = (e, t, n = "hex") => {
    let r = `-----BEGIN PUBLIC KEY-----
${e}
-----END PUBLIC KEY-----`;
    return kt.default.publicEncrypt({
      key: r,
      padding: kt.default.constants.RSA_PKCS1_PADDING
    }, Buffer.from(t)).toString(n);
  };
  N.rsaEncrypt = P_;
  var j_ = (e, t) => {
    let n = Object.entries(e).map((s) => s.join("=")).join("&"), r = kt.default.createCipheriv("aes-128-ecb", Buffer.from(t, "utf8"), null);
    r.setAutoPadding(!0);
    let i = r.update(n, "utf-8", "hex");
    return i += r.final("hex"), i;
  };
  N.aesECBEncrypt = j_;
  var q_ = (e, t, n = "hex") => {
    let r = Object.entries(e).map((s) => s.join("=")).join("&"), i = kt.default.createHmac("sha1", t);
    return i.update(r), i.digest(n);
  };
  N.hmacSha1 = q_;
  var L_ = (e) => Buffer.from(e, "hex").toString("base64");
  N.hexToBase64 = L_;
  var U_ = (e) => kt.default.createHash("md5").update(e).digest("hex");
  N.md5 = U_;
  var D_ = (e) => e.replace(/[xy]/g, (t) => {
    var n = 16 * Math.random() | 0, r = t === "x" ? n : 3 & n | 8;
    return r.toString(16);
  });
  N.randomString = D_;
  var I_ = (e) => {
    if (e > 10485760 * 2 * 999) {
      let r = e / 1999 / 10485760;
      return Math.max(Math.ceil(r), 5) * 10485760;
    }
    return e > 10485760 * 999 ? 10485760 * 2 : 10485760;
  };
  N.partSize = I_;
  var F_ = (e, t = 1024 * 1024) => new Promise((n, r) => {
    let i = C_.default.createReadStream(e, { highWaterMark: t }), s = kt.default.createHash("md5"), a = [];
    i.on("data", (o) => {
      s.update(o);
      let l = (0, N.md5)(o);
      a.push(l.toUpperCase());
    }), i.on("end", () => {
      let o = s.digest("hex");
      i.close(), n({ fileMd5: o, chunkMd5s: a });
    }), i.on("error", (o) => {
      r(o);
    });
  });
  N.calculateFileAndChunkMD5 = F_;
  var N_ = async (e, t, n) => {
    let r = [], i = [];
    for (let s of t) {
      let a = Promise.resolve().then(() => n(s, t));
      if (r.push(a), e <= t.length) {
        let o = a.then(() => i.splice(i.indexOf(o), 1));
        i.push(o), i.length >= e && await Promise.race(i);
      }
    }
    return Promise.all(r);
  };
  N.asyncPool = N_;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/const.js
var to = _((J) => {
  "use strict";
  c();
  Object.defineProperty(J, "__esModule", { value: !0 });
  J.clientSuffix = J.UserAgent = J.ReturnURL = J.ClientType = J.AppID = J.AccountType = J.UPLOAD_URL = J.API_URL = J.AUTH_URL = J.WEB_URL = void 0;
  J.WEB_URL = "https://cloud.189.cn";
  J.AUTH_URL = "https://open.e.189.cn";
  J.API_URL = "https://api.cloud.189.cn";
  J.UPLOAD_URL = "https://upload.cloud.189.cn";
  J.AccountType = "02";
  J.AppID = "8025431004";
  J.ClientType = "10020";
  J.ReturnURL = "https://m.cloud.189.cn/zhuanti/2020/loginErrorPc/index.html";
  J.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36";
  var B_ = "6.2", z_ = "TELEPC", H_ = "web_cloud.189.cn", M_ = () => ({
    clientType: z_,
    version: B_,
    channelId: H_,
    rand: Date.now()
  });
  J.clientSuffix = M_;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/signature.js
var Mf = _((Ge) => {
  "use strict";
  c();
  var $_ = Ge && Ge.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  };
  Object.defineProperty(Ge, "__esModule", { value: !0 });
  Ge.signatureUpload = Ge.signatureAppKey = Ge.signatureAccesstoken = void 0;
  var no = $_(require("url")), Ct = li(), V_ = ln(), W_ = (e, t) => {
    let n = String(Date.now()), { query: r } = no.default.parse(e.url.toString(), !0), i = (0, Ct.getSignature)(Object.assign(Object.assign({}, e.method === "GET" ? r : e.json || e.form), { Timestamp: n, AccessToken: t }));
    e.headers["Sign-Type"] = "1", e.headers.Signature = i, e.headers.Timestamp = n, e.headers.Accesstoken = t;
  };
  Ge.signatureAccesstoken = W_;
  var G_ = (e, t) => {
    let n = String(Date.now()), { query: r } = no.default.parse(e.url.toString(), !0), i = (0, Ct.getSignature)(Object.assign(Object.assign({}, e.method === "GET" ? r : e.json || e.form), { Timestamp: n, AppKey: t }));
    e.headers["Sign-Type"] = "1", e.headers.Signature = i, e.headers.Timestamp = n, e.headers.AppKey = t;
  };
  Ge.signatureAppKey = G_;
  var K_ = (e, t, n) => {
    let r = String(Date.now()), { query: i } = no.default.parse(e.url.toString(), !0), s = (0, Ct.randomString)("xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"), a = (0, Ct.randomString)("xxxxxxxxxxxx4xxxyxxxxxxxxxxxxxxx").slice(0, 16 + 16 * Math.random() | 0);
    V_.logger.debug(`upload query: ${JSON.stringify(i)}`);
    let o = (0, Ct.aesECBEncrypt)(i, a.substring(0, 16)), l = {
      SessionKey: n,
      Operate: "GET",
      RequestURI: e.url.pathname,
      Date: r,
      params: o
    }, p = (0, Ct.rsaEncrypt)(t.pubKey, a, "base64");
    e.headers["X-Request-Date"] = r, e.headers["X-Request-ID"] = s, e.headers.SessionKey = n, e.headers.EncryptionText = p, e.headers.PkId = t.pkId, e.headers.Signature = (0, Ct.hmacSha1)(l, a), e.url.search = "", e.url.hash = "", e.url.searchParams.set("params", o);
  };
  Ge.signatureUpload = K_;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/hook/logHook.js
var $f = _((ui) => {
  "use strict";
  c();
  Object.defineProperty(ui, "__esModule", { value: !0 });
  ui.logHook = void 0;
  var J_ = ln(), Y_ = (e, t) => (J_.logger.debug(`url: ${e.requestUrl}, response: ${e.body})}`), e);
  ui.logHook = Y_;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/error.js
var Vf = _((pt) => {
  "use strict";
  c();
  Object.defineProperty(pt, "__esModule", { value: !0 });
  pt.checkError = pt.AuthApiError = pt.InvalidRefreshTokenError = void 0;
  var pi = class extends Error {
  };
  pt.InvalidRefreshTokenError = pi;
  var di = class extends Error {
  };
  pt.AuthApiError = di;
  var Q_ = (e) => {
    let t;
    try {
      t = JSON.parse(e);
    } catch {
      return;
    }
    if ("result" in t && "msg" in t)
      switch (t.result) {
        case 0:
          return;
        case -117:
          throw new pi(t.msg);
        default:
          throw new di(t.msg);
      }
  };
  pt.checkError = Q_;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/hook/checkErrorHook.js
var Wf = _((fi) => {
  "use strict";
  c();
  Object.defineProperty(fi, "__esModule", { value: !0 });
  fi.checkErrorHook = void 0;
  var X_ = Vf(), Z_ = (e, t) => ((0, X_.checkError)(e.body.toString()), e);
  fi.checkErrorHook = Z_;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/hook/index.js
var ro = _((un) => {
  "use strict";
  c();
  Object.defineProperty(un, "__esModule", { value: !0 });
  un.checkErrorHook = un.logHook = void 0;
  var eE = $f();
  Object.defineProperty(un, "logHook", { enumerable: !0, get: function() {
    return eE.logHook;
  } });
  var tE = Wf();
  Object.defineProperty(un, "checkErrorHook", { enumerable: !0, get: function() {
    return tE.checkErrorHook;
  } });
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/CloudAuthClient.js
var ao = _((dt) => {
  "use strict";
  c();
  var nE = dt && dt.__classPrivateFieldGet || function(e, t, n, r) {
    if (n === "a" && !r) throw new TypeError("Private accessor was defined without a getter");
    if (typeof t == "function" ? e !== t || !r : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return n === "m" ? r : n === "a" ? r.call(e) : r ? r.value : t.get(e);
  }, rE = dt && dt.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  }, io;
  Object.defineProperty(dt, "__esModule", { value: !0 });
  dt.CloudAuthClient = void 0;
  var iE = rE(Za()), At = ln(), B = to(), Gf = oi(), Kf = li(), Jf = ro(), so = class {
    constructor() {
      io.set(this, (t, n, r, i) => {
        let s = (0, Kf.rsaEncrypt)(t.pubKey, r), a = (0, Kf.rsaEncrypt)(t.pubKey, i);
        return {
          appKey: B.AppID,
          accountType: B.AccountType,
          // mailSuffix: '@189.cn',
          validateCode: "",
          captchaToken: n.captchaToken,
          dynamicCheck: "FALSE",
          clientType: "1",
          cb_SaveName: "3",
          isOauth2: !1,
          returnUrl: B.ReturnURL,
          paramId: n.paramId,
          userName: `${t.pre}${s}`,
          password: `${t.pre}${a}`
        };
      }), this.authRequest = iE.default.extend({
        headers: {
          "User-Agent": B.UserAgent,
          Accept: "application/json;charset=UTF-8"
        },
        hooks: {
          afterResponse: [Jf.logHook, Jf.checkErrorHook]
        }
      });
    }
    /**
     * 获取加密参数
     * @returns
     */
    getEncrypt() {
      return this.authRequest.post(`${B.AUTH_URL}/api/logbox/config/encryptConf.do`).json();
    }
    async getLoginForm() {
      let t = await this.authRequest.get(`${B.WEB_URL}/api/portal/unifyLoginForPC.action`, {
        searchParams: {
          appId: B.AppID,
          clientType: B.ClientType,
          returnURL: B.ReturnURL,
          timeStamp: Date.now()
        }
      }).text();
      if (t) {
        let n = t.match("'captchaToken' value='(.+?)'")[1], r = t.match('lt = "(.+?)"')[1], i = t.match('paramId = "(.+?)"')[1], s = t.match('reqId = "(.+?)"')[1];
        return { captchaToken: n, lt: r, paramId: i, reqId: s };
      }
      return null;
    }
    async getSessionForPC(t) {
      let n = Object.assign(Object.assign({ appId: B.AppID }, (0, B.clientSuffix)()), t);
      return await this.authRequest.post(`${B.API_URL}/getSessionForPC.action`, {
        searchParams: n
      }).json();
    }
    /**
     * 用户名密码登录
     * */
    async loginByPassword(t, n) {
      At.logger.debug("loginByPassword...");
      try {
        let r = await Promise.all([
          //1.获取公钥
          this.getEncrypt(),
          //2.获取登录参数
          this.getLoginForm()
        ]), i = r[0].data, s = r[1], a = nE(this, io, "f").call(this, i, s, t, n), o = await this.authRequest.post(`${B.AUTH_URL}/api/logbox/oauth2/loginSubmit.do`, {
          headers: {
            Referer: B.AUTH_URL,
            lt: s.lt,
            REQID: s.reqId
          },
          form: a
        }).json();
        return await this.getSessionForPC({ redirectURL: o.toUrl });
      } catch (r) {
        throw At.logger.error(r), r;
      }
    }
    /**
     * token登录
     */
    async loginByAccessToken(t) {
      return At.logger.debug("loginByAccessToken..."), await this.getSessionForPC({ accessToken: t });
    }
    /**
     * sso登录
     */
    async loginBySsoCooike(t) {
      At.logger.debug("loginBySsoCooike...");
      let n = await this.authRequest.get(`${B.WEB_URL}/api/portal/unifyLoginForPC.action`, {
        searchParams: {
          appId: B.AppID,
          clientType: B.ClientType,
          returnURL: B.ReturnURL,
          timeStamp: Date.now()
        }
      }), r = await this.authRequest(n.url, {
        headers: {
          Cookie: `SSON=${t}`
        }
      });
      return await this.getSessionForPC({ redirectURL: r.url });
    }
    /**
     * 刷新token
     */
    refreshToken(t) {
      return this.authRequest.post(`${B.AUTH_URL}/api/oauth2/refreshToken.do`, {
        form: {
          clientId: B.AppID,
          refreshToken: t,
          grantType: "refresh_token",
          format: "json"
        }
      }).json();
    }
    /**
     * Get QR code data for scanning login
     * @returns QR code data including uuid for display
     */
    async getQRCode() {
      At.logger.debug("getQRCode...");
      let t = await this.getLoginForm(), n = await this.authRequest.post(`${B.AUTH_URL}/api/logbox/oauth2/getUUID.do`, {
        headers: {
          Referer: B.AUTH_URL
        },
        form: { appId: B.AppID }
      }).json();
      if (!n.uuid || !n.encryuuid)
        throw new Error("Failed to get QR code UUID");
      return {
        uuid: n.uuid,
        encryuuid: n.encryuuid,
        reqId: t.reqId,
        lt: t.lt,
        paramId: t.paramId
      };
    }
    /**
     * Check QR code scan status
     * @param qrData - QR code data from getQRCode
     * @returns status and redirectUrl on success
     */
    async checkQRCodeStatus(t) {
      let n = /* @__PURE__ */ new Date(), r = (s, a = 2) => String(s).padStart(a, "0"), i = `${n.getFullYear()}-${r(n.getMonth() + 1)}-${r(n.getDate())}${r(n.getHours())}:${r(n.getMinutes())}:${r(n.getSeconds())}.${r(n.getMilliseconds(), 3)}`;
      return this.authRequest.post(`${B.AUTH_URL}/api/logbox/oauth2/qrcodeLoginState.do`, {
        headers: {
          Referer: B.AUTH_URL,
          Reqid: t.reqId,
          lt: t.lt
        },
        form: {
          appId: B.AppID,
          clientType: B.ClientType,
          returnUrl: B.ReturnURL,
          paramId: t.paramId,
          uuid: t.uuid,
          encryuuid: t.encryuuid,
          date: i,
          timeStamp: Date.now()
        }
      }).json();
    }
    /**
     * QR code login with polling
     * @param onQRReady - callback invoked with QR code URL for display
     * @param options - polling interval and timeout
     * @returns token session
     */
    async loginByQRCode(t, n) {
      var r, i;
      At.logger.debug("loginByQRCode...");
      let s = (r = n == null ? void 0 : n.pollInterval) !== null && r !== void 0 ? r : 3e3, a = (i = n == null ? void 0 : n.timeout) !== null && i !== void 0 ? i : 12e4, o = await this.getQRCode();
      t(o.uuid);
      let l = Date.now() + a;
      for (; Date.now() < l; ) {
        let p = await this.checkQRCodeStatus(o);
        if (p.status === Gf.QRCodeStatus.SUCCESS)
          return At.logger.debug("QR code login success, getting session..."), await this.getSessionForPC({ redirectURL: p.redirectUrl });
        if (p.status === Gf.QRCodeStatus.EXPIRED)
          throw new Error("QR code expired");
        await new Promise((u) => setTimeout(u, s));
      }
      throw new Error("QR code login timeout");
    }
  };
  dt.CloudAuthClient = so;
  io = /* @__PURE__ */ new WeakMap();
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/store/store.js
var co = _((mi) => {
  "use strict";
  c();
  Object.defineProperty(mi, "__esModule", { value: !0 });
  mi.Store = void 0;
  var oo = class {
    constructor() {
    }
  };
  mi.Store = oo;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/store/memstore.js
var uo = _((hi) => {
  "use strict";
  c();
  Object.defineProperty(hi, "__esModule", { value: !0 });
  hi.MemoryStore = void 0;
  var sE = co(), lo = class extends sE.Store {
    constructor() {
      super(), this.store = {
        accessToken: "",
        refreshToken: "",
        expiresIn: 0
      };
    }
    get() {
      return this.store;
    }
    update(t) {
      var n, r;
      this.store = {
        accessToken: t.accessToken,
        refreshToken: (n = t.refreshToken) !== null && n !== void 0 ? n : this.store.refreshToken,
        expiresIn: (r = t.expiresIn) !== null && r !== void 0 ? r : this.store.expiresIn
      };
    }
  };
  hi.MemoryStore = lo;
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/store/file-token-store.js
var em = _((Ee) => {
  "use strict";
  c();
  var aE = Ee && Ee.__createBinding || (Object.create ? (function(e, t, n, r) {
    r === void 0 && (r = n);
    var i = Object.getOwnPropertyDescriptor(t, n);
    (!i || ("get" in i ? !t.__esModule : i.writable || i.configurable)) && (i = { enumerable: !0, get: function() {
      return t[n];
    } }), Object.defineProperty(e, r, i);
  }) : (function(e, t, n, r) {
    r === void 0 && (r = n), e[r] = t[n];
  })), oE = Ee && Ee.__setModuleDefault || (Object.create ? (function(e, t) {
    Object.defineProperty(e, "default", { enumerable: !0, value: t });
  }) : function(e, t) {
    e.default = t;
  }), Qf = Ee && Ee.__importStar || function(e) {
    if (e && e.__esModule) return e;
    var t = {};
    if (e != null) for (var n in e) n !== "default" && Object.prototype.hasOwnProperty.call(e, n) && aE(t, e, n);
    return oE(t, e), t;
  }, Yf = Ee && Ee.__classPrivateFieldGet || function(e, t, n, r) {
    if (n === "a" && !r) throw new TypeError("Private accessor was defined without a getter");
    if (typeof t == "function" ? e !== t || !r : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return n === "m" ? r : n === "a" ? r.call(e) : r ? r.value : t.get(e);
  }, cE = Ee && Ee.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  }, xi, Xf, Zf;
  Object.defineProperty(Ee, "__esModule", { value: !0 });
  Ee.FileTokenStore = void 0;
  var gi = Qf(require("fs")), lE = Qf(require("fs/promises")), uE = cE(require("path")), pE = uo(), po = class extends pE.MemoryStore {
    constructor(t) {
      if (super(), xi.add(this), this.filePath = t, !t)
        throw new Error("Unknown file for read/write token");
      this.ensureTokenDirectory(t);
      let n = Yf(this, xi, "m", Xf).call(this, t);
      n && super.update(n);
    }
    ensureTokenDirectory(t) {
      let n = uE.default.dirname(t);
      gi.existsSync(n) || gi.mkdirSync(n, { recursive: !0 });
    }
    update(t) {
      return super.update(t), Yf(this, xi, "m", Zf).call(this, this.filePath, this.store);
    }
  };
  Ee.FileTokenStore = po;
  xi = /* @__PURE__ */ new WeakSet(), Xf = function(t) {
    let n = null;
    if (gi.existsSync(t) && (n = gi.readFileSync(t, {
      encoding: "utf-8"
    })), n)
      try {
        return JSON.parse(n);
      } catch {
        throw new Error(`Could not parse token file ${t}. Please ensure it is not corrupted.`);
      }
    return null;
  }, Zf = function(t, n) {
    return lE.writeFile(t, JSON.stringify(n), {
      encoding: "utf-8"
    });
  };
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/store/index.js
var mo = _((nt) => {
  "use strict";
  c();
  var dE = nt && nt.__createBinding || (Object.create ? (function(e, t, n, r) {
    r === void 0 && (r = n);
    var i = Object.getOwnPropertyDescriptor(t, n);
    (!i || ("get" in i ? !t.__esModule : i.writable || i.configurable)) && (i = { enumerable: !0, get: function() {
      return t[n];
    } }), Object.defineProperty(e, r, i);
  }) : (function(e, t, n, r) {
    r === void 0 && (r = n), e[r] = t[n];
  })), fo = nt && nt.__exportStar || function(e, t) {
    for (var n in e) n !== "default" && !Object.prototype.hasOwnProperty.call(t, n) && dE(t, e, n);
  };
  Object.defineProperty(nt, "__esModule", { value: !0 });
  fo(co(), nt);
  fo(uo(), nt);
  fo(em(), nt);
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/CloudClient.js
var cm = _((ft) => {
  "use strict";
  c();
  var ke = ft && ft.__classPrivateFieldGet || function(e, t, n, r) {
    if (n === "a" && !r) throw new TypeError("Private accessor was defined without a getter");
    if (typeof t == "function" ? e !== t || !r : !t.has(e)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return n === "m" ? r : n === "a" ? r.call(e) : r ? r.value : t.get(e);
  }, bo = ft && ft.__importDefault || function(e) {
    return e && e.__esModule ? e : { default: e };
  }, Se, go, rm, im, Ot, ho, sm, am;
  Object.defineProperty(ft, "__esModule", { value: !0 });
  ft.CloudClient = void 0;
  var yo = bo(require("fs")), fE = bo(require("path")), om = bo(Za()), tm = oi(), Y = ln(), Jn = li(), F = to(), xo = Mf(), mE = ao(), hE = ro(), xE = mo(), nm = {
    clientId: "538135150693412",
    model: "KB2000",
    version: "9.0.6"
  }, vo = class {
    constructor(t) {
      Se.add(this), go.set(this, (n) => {
        if (!n.ssonCookie && !n.token && !(n.username && n.password) && !n.onQRCodeReady)
          throw Y.logger.error("valid"), new Error("Please provide username and password or token or ssonCooike or onQRCodeReady !");
      }), ke(this, go, "f").call(this, t), this.username = t.username, this.password = t.password, this.ssonCookie = t.ssonCookie, this.onQRCodeReady = t.onQRCodeReady, this.qrLoginOptions = t.qrLoginOptions, this.tokenStore = t.token || new xE.MemoryStore(), this.authClient = new mE.CloudAuthClient(), this.session = {
        accessToken: "",
        sessionKey: ""
      }, this.rsaKey = null, this.request = om.default.extend({
        retry: {
          limit: 2,
          statusCodes: [408, 413, 429],
          errorCodes: ["ETIMEDOUT", "ECONNRESET"]
        },
        headers: {
          "User-Agent": F.UserAgent,
          Referer: `${F.WEB_URL}/web/main/`,
          Accept: "application/json;charset=UTF-8"
        },
        hooks: {
          beforeRequest: [
            async (n) => {
              if (n.url.href.includes(F.API_URL)) {
                let r = await this.getAccessToken();
                (0, xo.signatureAccesstoken)(n, r);
              } else if (n.url.href.includes(F.WEB_URL)) {
                n.url.href.includes("/open") && (0, xo.signatureAppKey)(n, "600100422");
                let r = await this.getSessionKey();
                n.url.searchParams.set("sessionKey", r);
              } else if (n.url.href.includes(F.UPLOAD_URL)) {
                let r = await this.getSessionKey(), i = await this.generateRsaKey();
                (0, xo.signatureUpload)(n, i, r);
              }
            }
          ],
          afterResponse: [
            hE.logHook,
            async (n, r) => {
              if (n.statusCode === 400)
                try {
                  let { errorCode: i, errorMsg: s } = JSON.parse(n.body.toString());
                  if (i === "InvalidAccessToken")
                    return Y.logger.debug(`InvalidAccessToken retry..., errorMsg: ${s}`), Y.logger.debug("Refresh AccessToken"), this.session.accessToken = "", r({});
                  if (i === "InvalidSessionKey")
                    return Y.logger.debug(`InvalidSessionKey retry..., errorMsg: ${s}`), Y.logger.debug("Refresh InvalidSessionKey"), this.session.sessionKey = "", r({});
                } catch (i) {
                  Y.logger.error(i);
                }
              return n;
            }
          ]
        }
      });
    }
    async getSession() {
      let { accessToken: t, expiresIn: n, refreshToken: r } = await this.tokenStore.get();
      if (t && n && n > Date.now())
        try {
          return await this.authClient.loginByAccessToken(t);
        } catch (i) {
          Y.logger.error(i);
        }
      if (r)
        try {
          let i = await this.authClient.refreshToken(r);
          return await this.tokenStore.update({
            accessToken: i.accessToken,
            refreshToken: i.refreshToken,
            expiresIn: new Date(Date.now() + i.expiresIn * 1e3).getTime()
          }), await this.authClient.loginByAccessToken(i.accessToken);
        } catch (i) {
          Y.logger.error(i);
        }
      if (this.ssonCookie)
        try {
          let i = await this.authClient.loginBySsoCooike(this.ssonCookie);
          return await this.tokenStore.update({
            accessToken: i.accessToken,
            refreshToken: i.refreshToken,
            expiresIn: new Date(Date.now() + 8640 * 60 * 1e3).getTime()
          }), i;
        } catch (i) {
          Y.logger.error(i);
        }
      if (this.username && this.password)
        try {
          let i = await this.authClient.loginByPassword(this.username, this.password);
          return await this.tokenStore.update({
            accessToken: i.accessToken,
            refreshToken: i.refreshToken,
            expiresIn: new Date(Date.now() + 8640 * 60 * 1e3).getTime()
          }), i;
        } catch (i) {
          Y.logger.error(i);
        }
      if (this.onQRCodeReady)
        try {
          let i = await this.authClient.loginByQRCode(this.onQRCodeReady, this.qrLoginOptions);
          return await this.tokenStore.update({
            accessToken: i.accessToken,
            refreshToken: i.refreshToken,
            expiresIn: new Date(Date.now() + 8640 * 60 * 1e3).getTime()
          }), i;
        } catch (i) {
          Y.logger.error(i);
        }
      throw new Error("Can not get session.");
    }
    /**
     * 获取 sessionKey
     * @returns sessionKey
     */
    async getSessionKey() {
      return this.session.sessionKey ? this.session.sessionKey : (this.sessionKeyPromise || (this.sessionKeyPromise = this.getSession().then((n) => (this.session.sessionKey = n.sessionKey, n.sessionKey)).finally(() => {
        this.sessionKeyPromise = null;
      })), await this.sessionKeyPromise);
    }
    /**
     * 获取 accessToken
     * @returns accessToken
     */
    async getAccessToken() {
      return this.session.accessToken ? this.session.accessToken : (this.accessTokenPromise || (this.accessTokenPromise = ke(this, Se, "m", rm).call(this).then((n) => (this.session.accessToken = n.accessToken, n)).finally(() => {
        this.accessTokenPromise = null;
      })), (await this.accessTokenPromise).accessToken);
    }
    /**
     * 获取 RSA key
     * @returns RSAKey
     */
    async generateRsaKey() {
      return this.rsaKey && new Date(this.rsaKey.expire).getTime() > Date.now() ? this.rsaKey : (this.generateRsaKeyPromise || (this.generateRsaKeyPromise = ke(this, Se, "m", im).call(this).then((n) => (this.rsaKey = {
        expire: n.expire,
        pubKey: n.pubKey,
        pkId: n.pkId,
        ver: n.ver
      }, n)).finally(() => {
        this.generateRsaKeyPromise = null;
      })), await this.generateRsaKeyPromise);
    }
    /**
     * 获取用户网盘存储容量信息
     * @returns 账号容量结果
     */
    getUserSizeInfo() {
      return this.request.get(`${F.WEB_URL}/api/portal/getUserSizeInfo.action`).json();
    }
    /**
     * 个人签到任务
     * @returns 签到结果
     */
    userSign() {
      return this.request.get(`${F.WEB_URL}/mkt/userSign.action?rand=${(/* @__PURE__ */ new Date()).getTime()}&clientType=TELEANDROID&version=${nm.version}&model=${nm.model}`).json();
    }
    /**
     * 获取家庭信息
     * @returns 家庭列表信息
     */
    getFamilyList() {
      return this.request.get(`${F.API_URL}/open/family/manage/getFamilyList.action`).json();
    }
    /**
     * 家庭签到任务
     * @param familyId - 家庭id
     * @returns 签到结果
     * @deprecated 已无效
     */
    familyUserSign(t) {
      return this.request.get(`${F.API_URL}/open/family/manage/exeFamilyUserSign.action?familyId=${t}`).json();
    }
    /**
     * 获取文件列表
     * @param pageQuery - 查询参数
     * @returns
     */
    getListFiles(t, n) {
      let r = {
        pageNum: 1,
        pageSize: 60,
        mediaType: tm.MediaType.ALL.toString(),
        orderBy: tm.OrderByType.LAST_OP_TIME.toString(),
        descending: !0,
        folderId: "",
        iconOption: 5
      }, i = Object.assign(Object.assign({}, r), t);
      return n ? this.request.get(`${F.API_URL}/open/family/file/listFiles.action`, {
        searchParams: Object.assign(Object.assign({}, i), { familyId: n })
      }).json() : this.request.get(`${F.API_URL}/open/file/listFiles.action`, {
        searchParams: Object.assign({}, i)
      }).json();
    }
    /**
     * 创建文件夹
     * @param createFolderRequest - 创建文件夹请求
     * @returns
     */
    createFolder(t) {
      let n = ke(this, Se, "m", Ot).call(this, t) ? `${F.API_URL}/open/family/file/createFolder.action` : `${F.API_URL}/open/file/createFolder.action`;
      return this.request.post(n, {
        form: t
      }).json();
    }
    /**
     * 重命名文件夹
     * @param renameFolderRequest - 重名文件夹请求
     * @returns
     */
    renameFolder(t) {
      let n = `${F.API_URL}/open/file/renameFolder.action`, r = {
        destFolderName: t.folderName,
        folderId: t.folderId
      };
      return ke(this, Se, "m", Ot).call(this, t) && (n = `${F.API_URL}/open/family/file/renameFolder.action`, r = Object.assign(r, {
        familyId: t.familyId
      })), this.request.post(n, {
        form: r
      }).json();
    }
    /**
     * 初始化上传
     * @param initMultiUploadRequest - 初始化请求
     * @returns
     */
    async initMultiUpload(t) {
      let { parentFolderId: n, fileName: r, fileSize: i, sliceSize: s, fileMd5: a, sliceMd5: o } = t, l = Object.assign({
        parentFolderId: n,
        fileName: r,
        fileSize: i,
        sliceSize: s
      }, a && o ? { fileMd5: a, sliceMd5: o } : { lazyCheck: 1 }), p = `${F.UPLOAD_URL}/person/initMultiUpload`;
      return ke(this, Se, "m", Ot).call(this, t) && (p = `${F.UPLOAD_URL}/family/initMultiUpload`, l = Object.assign(l, {
        familyId: t.familyId
      })), await this.request.get(p, {
        searchParams: Object.assign({}, l)
      }).json();
    }
    /**
     * 提交上传
     * @param commitMultiUploadRequest - 提交请求
     * @returns
     */
    commitMultiUpload(t) {
      let n = ke(this, Se, "m", Ot).call(this, t) ? `${F.UPLOAD_URL}/family/commitMultiUploadFile` : `${F.UPLOAD_URL}/person/commitMultiUploadFile`;
      return this.request.get(n, {
        searchParams: Object.assign({}, t)
      }).json();
    }
    /**
     * 检测秒传
     * @param params - 检查参数
     * @returns
     */
    checkTransSecond(t) {
      let n = ke(this, Se, "m", Ot).call(this, t) ? `${F.UPLOAD_URL}/family/checkTransSecond` : `${F.UPLOAD_URL}/person/checkTransSecond`;
      return this.request.get(n, {
        searchParams: t
      }).json();
    }
    /**
     * 文件上传
     * @param param - 上传参数
     * @param callbacks - 上传回调
     * @returns
     */
    async upload(t, n = {}) {
      let { filePath: r, parentFolderId: i, familyId: s } = t, { size: a } = await yo.default.promises.stat(r), o = encodeURIComponent(fE.default.basename(r)), l = (0, Jn.partSize)(a), { fileMd5: p, chunkMd5s: u } = await (0, Jn.calculateFileAndChunkMD5)(r, l);
      return u.length === 1 ? (Y.logger.debug("single file upload"), ke(this, Se, "m", sm).call(this, {
        parentFolderId: i,
        filePath: r,
        fileName: o,
        fileSize: a,
        sliceSize: l,
        fileMd5: p,
        familyId: s
      }, n)) : (Y.logger.debug("multi file upload"), ke(this, Se, "m", am).call(this, {
        parentFolderId: i,
        filePath: r,
        fileName: o,
        fileSize: a,
        sliceSize: l,
        fileMd5: p,
        chunkMd5s: u,
        familyId: s
      }, n));
    }
    /**
     * 检测任务状态
     * @param type - 任务类型
     * @param taskId - 任务Id
     * @param maxAttempts - 重试次数
     * @param interval - 重试间隔
     * @returns
     */
    async checkTaskStatus(t, n, r = 120, i = 500) {
      for (let s = 0; s < r; s++) {
        try {
          let { taskStatus: a, successedFileIdList: o } = await this.request.post(`${F.API_URL}/open/batch/checkBatchTask.action`, {
            form: { type: t, taskId: n }
          }).json();
          if (a === -1)
            return Y.logger.error("创建任务异常"), {
              taskId: n,
              taskStatus: a
            };
          if (a === 2)
            return Y.logger.error("文件重名任务异常"), {
              taskId: n,
              taskStatus: a
            };
          if (a === 4)
            return { successedFileIdList: o, taskId: n, taskStatus: a };
        } catch (a) {
          Y.logger.error(`Check task status attempt ${s + 1} failed:` + a);
        }
        await new Promise((a) => setTimeout(a, i));
      }
    }
    /**
     * 创建任务
     * @param createBatchTaskRequest - 创建任务参数
     * @returns
     */
    async createBatchTask(t) {
      let n = {
        type: t.type,
        taskInfos: JSON.stringify(t.taskInfos)
      };
      t.targetFolderId && (n = Object.assign(n, {
        targetFolderId: t.targetFolderId
      })), ke(this, Se, "m", Ot).call(this, t) && (n = Object.assign(n, {
        familyId: t.familyId
      }));
      try {
        let { taskId: r } = await this.request.post(`${F.API_URL}/open/batch/createBatchTask.action`, {
          form: n
        }).json();
        return await this.checkTaskStatus(t.type, r);
      } catch (r) {
        throw Y.logger.error("Batch task creation failed:" + r), r;
      }
    }
    /**
     * 获取文件下载路径
     * @param params - 文件参数
     * @returns
     */
    getFileDownloadUrl(t) {
      let n = t.familyId ? `${F.API_URL}/open/family/file/getFileDownloadUrl.action` : `${F.API_URL}/open/file/getFileDownloadUrl.action`;
      return this.request(n, {
        searchParams: t
      }).json();
    }
  };
  ft.CloudClient = vo;
  go = /* @__PURE__ */ new WeakMap(), Se = /* @__PURE__ */ new WeakSet(), rm = function() {
    return this.request.get(`${F.WEB_URL}/api/open/oauth2/getAccessTokenBySsKey.action`).json();
  }, im = function() {
    return this.request.get(`${F.WEB_URL}/api/security/generateRsaKey.action`).json();
  }, Ot = function(t) {
    return "familyId" in t && t.familyId !== void 0;
  }, ho = async function({ partNumber: t, md5: n, buffer: r, uploadFileId: i, familyId: s }, a = {}) {
    let o = `${t}-${(0, Jn.hexToBase64)(n)}`;
    Y.logger.debug(`upload part: ${t}`);
    let l = {
      partInfo: o,
      uploadFileId: i
    }, p = s ? `${F.UPLOAD_URL}/family/getMultiUploadUrls` : `${F.UPLOAD_URL}/person/getMultiUploadUrls`, u = await this.request.get(p, {
      searchParams: l
    }).json(), { requestURL: d, requestHeader: m } = u.uploadUrls[`partNumber_${t}`], x = m.split("&").reduce((b, v) => {
      let h = v.split("=")[0], w = v.match(/=(.*)/)[1];
      return b[h] = w, b;
    }, {});
    Y.logger.debug(`Upload URL: ${d}`), Y.logger.debug(`Upload Headers: ${JSON.stringify(x)}`), await om.default.put(d, {
      headers: x,
      body: r
    }).on("uploadProgress", (b) => {
      var v;
      (v = a.onProgress) === null || v === void 0 || v.call(a, b.transferred * 100 / b.total);
    });
  }, sm = /**
   * 单个小文件上传
   */
  async function({ parentFolderId: t, filePath: n, fileName: r, fileSize: i, fileMd5: s, sliceSize: a, familyId: o }, l = {}) {
    var p, u, d;
    let m = s, x = {
      parentFolderId: t,
      fileName: r,
      fileSize: i,
      sliceSize: a,
      fileMd5: s,
      sliceMd5: m,
      familyId: o
    }, b;
    try {
      let v = await this.initMultiUpload(x), { uploadFileId: h, fileDataExists: w } = v.data;
      if (w)
        Y.logger.debug(`单文件 ${n} 秒传: ${h}`), (p = l.onProgress) === null || p === void 0 || p.call(l, 100);
      else {
        b = await yo.default.promises.open(n, "r");
        let A = Buffer.alloc(i);
        await b.read(A, 0, i), await ke(this, Se, "m", ho).call(this, {
          partNumber: 1,
          md5: s,
          buffer: A,
          uploadFileId: h,
          familyId: o
        }, {
          onProgress: l.onProgress,
          onError: l.onError
        });
      }
      let T = Object.assign(Object.assign({}, await this.commitMultiUpload({
        fileMd5: s,
        sliceMd5: m,
        uploadFileId: h,
        familyId: o
      })), { fileDataExists: w });
      return (u = l.onComplete) === null || u === void 0 || u.call(l, T), T;
    } catch (v) {
      throw (d = l.onError) === null || d === void 0 || d.call(l, v), v;
    } finally {
      b == null || b.close();
    }
  }, am = /**
   * 大文件分块上传
   */
  async function({ parentFolderId: t, filePath: n, fileName: r, fileSize: i, fileMd5: s, sliceSize: a, chunkMd5s: o, familyId: l }, p = {}) {
    var u, d, m;
    let x = (0, Jn.md5)(o.join(`
`)), b = {
      parentFolderId: t,
      fileName: r,
      fileSize: i,
      sliceSize: a,
      familyId: l
    }, v;
    try {
      let h = await this.initMultiUpload(b), { uploadFileId: w } = h.data, T = {
        fileMd5: s,
        sliceMd5: x,
        uploadFileId: w,
        familyId: l
      }, A = await this.checkTransSecond(T), { fileDataExists: O } = A.data;
      if (O)
        Y.logger.debug(`多块文件 ${n} 秒传: ${w}`), (u = p.onProgress) === null || u === void 0 || u.call(p, 100);
      else {
        v = await yo.default.promises.open(n, "r");
        let W = o.length, ne = {};
        await (0, Jn.asyncPool)(5, [...Array(W).keys()], async (re) => {
          let Ce = re + 1, H = re * a, pe = Math.min(a, i - H), Q = Buffer.alloc(pe);
          await v.read(Q, 0, pe, H), await ke(this, Se, "m", ho).call(this, {
            partNumber: Ce,
            md5: o[re],
            buffer: Q,
            uploadFileId: w,
            familyId: l
          }, {
            onProgress: (rt) => {
              if (p.onProgress) {
                ne[`partNumber_${Ce}`] = rt;
                let de = Object.values(ne).reduce((Me, Ae) => Me + Ae, 0) / W;
                p.onProgress(de);
              }
            },
            onError: p.onError
          });
        });
      }
      let q = Object.assign(Object.assign({}, await this.commitMultiUpload({
        fileMd5: s,
        sliceMd5: x,
        uploadFileId: w,
        lazyCheck: 1,
        familyId: l
      })), { fileDataExists: O });
      return (d = p.onComplete) === null || d === void 0 || d.call(p, q), q;
    } catch (h) {
      throw (m = p.onError) === null || m === void 0 || m.call(p, h), h;
    } finally {
      v == null || v.close();
    }
  };
});

// node_modules/.pnpm/cloud189-sdk@1.0.9/node_modules/cloud189-sdk/dist/index.js
var lm = _((He) => {
  "use strict";
  c();
  var gE = He && He.__createBinding || (Object.create ? (function(e, t, n, r) {
    r === void 0 && (r = n);
    var i = Object.getOwnPropertyDescriptor(t, n);
    (!i || ("get" in i ? !t.__esModule : i.writable || i.configurable)) && (i = { enumerable: !0, get: function() {
      return t[n];
    } }), Object.defineProperty(e, r, i);
  }) : (function(e, t, n, r) {
    r === void 0 && (r = n), e[r] = t[n];
  })), Yn = He && He.__exportStar || function(e, t) {
    for (var n in e) n !== "default" && !Object.prototype.hasOwnProperty.call(t, n) && gE(t, e, n);
  };
  Object.defineProperty(He, "__esModule", { value: !0 });
  Yn(cm(), He);
  Yn(ao(), He);
  Yn(oi(), He);
  Yn(mo(), He);
  Yn(ln(), He);
});

// src/index.ts
c();

// src/config.ts
c();

// node_modules/.pnpm/dotenv@17.4.2/node_modules/dotenv/config.js
c();
(function() {
  ko().config(
    Object.assign(
      {},
      Ao(),
      Po()(process.argv)
    )
  );
})();

// src/config.ts
var Zn = process.env.TG, wi = process.env.ACCOUNTS, jo = (() => {
  switch (process.env.Throw) {
    case "true":
      return !0;
    case "false":
      return !1;
    default:
      return !0;
  }
})();

// src/tg.ts
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/index.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/axios.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/utils.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/bind.js
c();
function fn(e, t) {
  return function() {
    return e.apply(t, arguments);
  };
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/utils.js
var { toString: Um } = Object.prototype, { getPrototypeOf: tr } = Object, { iterator: nr, toStringTag: Uo } = Symbol, rr = /* @__PURE__ */ ((e) => (t) => {
  let n = Um.call(t);
  return e[n] || (e[n] = n.slice(8, -1).toLowerCase());
})(/* @__PURE__ */ Object.create(null)), De = (e) => (e = e.toLowerCase(), (t) => rr(t) === e), ir = (e) => (t) => typeof t === e, { isArray: Ut } = Array, Lt = ir("undefined");
function mn(e) {
  return e !== null && !Lt(e) && e.constructor !== null && !Lt(e.constructor) && ve(e.constructor.isBuffer) && e.constructor.isBuffer(e);
}
var Do = De("ArrayBuffer");
function Dm(e) {
  let t;
  return typeof ArrayBuffer < "u" && ArrayBuffer.isView ? t = ArrayBuffer.isView(e) : t = e && e.buffer && Do(e.buffer), t;
}
var Im = ir("string"), ve = ir("function"), Io = ir("number"), hn = (e) => e !== null && typeof e == "object", Fm = (e) => e === !0 || e === !1, er = (e) => {
  if (rr(e) !== "object")
    return !1;
  let t = tr(e);
  return (t === null || t === Object.prototype || Object.getPrototypeOf(t) === null) && !(Uo in e) && !(nr in e);
}, Nm = (e) => {
  if (!hn(e) || mn(e))
    return !1;
  try {
    return Object.keys(e).length === 0 && Object.getPrototypeOf(e) === Object.prototype;
  } catch {
    return !1;
  }
}, Bm = De("Date"), zm = De("File"), Hm = (e) => !!(e && typeof e.uri < "u"), Mm = (e) => e && typeof e.getParts < "u", $m = De("Blob"), Vm = De("FileList"), Wm = (e) => hn(e) && ve(e.pipe);
function Gm() {
  return typeof globalThis < "u" ? globalThis : typeof self < "u" ? self : typeof window < "u" ? window : typeof global < "u" ? global : {};
}
var qo = Gm(), Lo = typeof qo.FormData < "u" ? qo.FormData : void 0, Km = (e) => {
  if (!e) return !1;
  if (Lo && e instanceof Lo) return !0;
  let t = tr(e);
  if (!t || t === Object.prototype || !ve(e.append)) return !1;
  let n = rr(e);
  return n === "formdata" || // detect form-data instance
  n === "object" && ve(e.toString) && e.toString() === "[object FormData]";
}, Jm = De("URLSearchParams"), [Ym, Qm, Xm, Zm] = [
  "ReadableStream",
  "Request",
  "Response",
  "Headers"
].map(De), eh = (e) => e.trim ? e.trim() : e.replace(/^[\s\uFEFF\xA0]+|[\s\uFEFF\xA0]+$/g, "");
function xn(e, t, { allOwnKeys: n = !1 } = {}) {
  if (e === null || typeof e > "u")
    return;
  let r, i;
  if (typeof e != "object" && (e = [e]), Ut(e))
    for (r = 0, i = e.length; r < i; r++)
      t.call(null, e[r], r, e);
  else {
    if (mn(e))
      return;
    let s = n ? Object.getOwnPropertyNames(e) : Object.keys(e), a = s.length, o;
    for (r = 0; r < a; r++)
      o = s[r], t.call(null, e[o], o, e);
  }
}
function Fo(e, t) {
  if (mn(e))
    return null;
  t = t.toLowerCase();
  let n = Object.keys(e), r = n.length, i;
  for (; r-- > 0; )
    if (i = n[r], t === i.toLowerCase())
      return i;
  return null;
}
var xt = typeof globalThis < "u" ? globalThis : typeof self < "u" ? self : typeof window < "u" ? window : global, No = (e) => !Lt(e) && e !== xt;
function _i(...e) {
  let { caseless: t, skipUndefined: n } = No(this) && this || {}, r = {}, i = (s, a) => {
    if (a === "__proto__" || a === "constructor" || a === "prototype")
      return;
    let o = t && Fo(r, a) || a, l = Ei(r, o) ? r[o] : void 0;
    er(l) && er(s) ? r[o] = _i(l, s) : er(s) ? r[o] = _i({}, s) : Ut(s) ? r[o] = s.slice() : (!n || !Lt(s)) && (r[o] = s);
  };
  for (let s = 0, a = e.length; s < a; s++)
    e[s] && xn(e[s], i);
  return r;
}
var th = (e, t, n, { allOwnKeys: r } = {}) => (xn(
  t,
  (i, s) => {
    n && ve(i) ? Object.defineProperty(e, s, {
      // Null-proto descriptor so a polluted Object.prototype.get cannot
      // hijack defineProperty's accessor-vs-data resolution.
      __proto__: null,
      value: fn(i, n),
      writable: !0,
      enumerable: !0,
      configurable: !0
    }) : Object.defineProperty(e, s, {
      __proto__: null,
      value: i,
      writable: !0,
      enumerable: !0,
      configurable: !0
    });
  },
  { allOwnKeys: r }
), e), nh = (e) => (e.charCodeAt(0) === 65279 && (e = e.slice(1)), e), rh = (e, t, n, r) => {
  e.prototype = Object.create(t.prototype, r), Object.defineProperty(e.prototype, "constructor", {
    __proto__: null,
    value: e,
    writable: !0,
    enumerable: !1,
    configurable: !0
  }), Object.defineProperty(e, "super", {
    __proto__: null,
    value: t.prototype
  }), n && Object.assign(e.prototype, n);
}, ih = (e, t, n, r) => {
  let i, s, a, o = {};
  if (t = t || {}, e == null) return t;
  do {
    for (i = Object.getOwnPropertyNames(e), s = i.length; s-- > 0; )
      a = i[s], (!r || r(a, e, t)) && !o[a] && (t[a] = e[a], o[a] = !0);
    e = n !== !1 && tr(e);
  } while (e && (!n || n(e, t)) && e !== Object.prototype);
  return t;
}, sh = (e, t, n) => {
  e = String(e), (n === void 0 || n > e.length) && (n = e.length), n -= t.length;
  let r = e.indexOf(t, n);
  return r !== -1 && r === n;
}, ah = (e) => {
  if (!e) return null;
  if (Ut(e)) return e;
  let t = e.length;
  if (!Io(t)) return null;
  let n = new Array(t);
  for (; t-- > 0; )
    n[t] = e[t];
  return n;
}, oh = /* @__PURE__ */ ((e) => (t) => e && t instanceof e)(typeof Uint8Array < "u" && tr(Uint8Array)), ch = (e, t) => {
  let r = (e && e[nr]).call(e), i;
  for (; (i = r.next()) && !i.done; ) {
    let s = i.value;
    t.call(e, s[0], s[1]);
  }
}, lh = (e, t) => {
  let n, r = [];
  for (; (n = e.exec(t)) !== null; )
    r.push(n);
  return r;
}, uh = De("HTMLFormElement"), ph = (e) => e.toLowerCase().replace(/[-_\s]([a-z\d])(\w*)/g, function(n, r, i) {
  return r.toUpperCase() + i;
}), Ei = (({ hasOwnProperty: e }) => (t, n) => e.call(t, n))(Object.prototype), dh = De("RegExp"), Bo = (e, t) => {
  let n = Object.getOwnPropertyDescriptors(e), r = {};
  xn(n, (i, s) => {
    let a;
    (a = t(i, s, e)) !== !1 && (r[s] = a || i);
  }), Object.defineProperties(e, r);
}, fh = (e) => {
  Bo(e, (t, n) => {
    if (ve(e) && ["arguments", "caller", "callee"].includes(n))
      return !1;
    let r = e[n];
    if (ve(r)) {
      if (t.enumerable = !1, "writable" in t) {
        t.writable = !1;
        return;
      }
      t.set || (t.set = () => {
        throw Error("Can not rewrite read-only method '" + n + "'");
      });
    }
  });
}, mh = (e, t) => {
  let n = {}, r = (i) => {
    i.forEach((s) => {
      n[s] = !0;
    });
  };
  return Ut(e) ? r(e) : r(String(e).split(t)), n;
}, hh = () => {
}, xh = (e, t) => e != null && Number.isFinite(e = +e) ? e : t;
function gh(e) {
  return !!(e && ve(e.append) && e[Uo] === "FormData" && e[nr]);
}
var yh = (e) => {
  let t = /* @__PURE__ */ new WeakSet(), n = (r) => {
    if (hn(r)) {
      if (t.has(r))
        return;
      if (mn(r))
        return r;
      if (!("toJSON" in r)) {
        t.add(r);
        let i = Ut(r) ? [] : {};
        return xn(r, (s, a) => {
          let o = n(s);
          !Lt(o) && (i[a] = o);
        }), t.delete(r), i;
      }
    }
    return r;
  };
  return n(e);
}, vh = De("AsyncFunction"), bh = (e) => e && (hn(e) || ve(e)) && ve(e.then) && ve(e.catch), zo = ((e, t) => e ? setImmediate : t ? ((n, r) => (xt.addEventListener(
  "message",
  ({ source: i, data: s }) => {
    i === xt && s === n && r.length && r.shift()();
  },
  !1
), (i) => {
  r.push(i), xt.postMessage(n, "*");
}))(`axios@${Math.random()}`, []) : (n) => setTimeout(n))(typeof setImmediate == "function", ve(xt.postMessage)), wh = typeof queueMicrotask < "u" ? queueMicrotask.bind(xt) : typeof process < "u" && process.nextTick || zo, _h = (e) => e != null && ve(e[nr]), f = {
  isArray: Ut,
  isArrayBuffer: Do,
  isBuffer: mn,
  isFormData: Km,
  isArrayBufferView: Dm,
  isString: Im,
  isNumber: Io,
  isBoolean: Fm,
  isObject: hn,
  isPlainObject: er,
  isEmptyObject: Nm,
  isReadableStream: Ym,
  isRequest: Qm,
  isResponse: Xm,
  isHeaders: Zm,
  isUndefined: Lt,
  isDate: Bm,
  isFile: zm,
  isReactNativeBlob: Hm,
  isReactNative: Mm,
  isBlob: $m,
  isRegExp: dh,
  isFunction: ve,
  isStream: Wm,
  isURLSearchParams: Jm,
  isTypedArray: oh,
  isFileList: Vm,
  forEach: xn,
  merge: _i,
  extend: th,
  trim: eh,
  stripBOM: nh,
  inherits: rh,
  toFlatObject: ih,
  kindOf: rr,
  kindOfTest: De,
  endsWith: sh,
  toArray: ah,
  forEachEntry: ch,
  matchAll: lh,
  isHTMLForm: uh,
  hasOwnProperty: Ei,
  hasOwnProp: Ei,
  // an alias to avoid ESLint no-prototype-builtins detection
  reduceDescriptors: Bo,
  freezeMethods: fh,
  toObjectSet: mh,
  toCamelCase: ph,
  noop: hh,
  toFiniteNumber: xh,
  findKey: Fo,
  global: xt,
  isContextDefined: No,
  isSpecCompliantForm: gh,
  toJSONObject: yh,
  isAsyncFn: vh,
  isThenable: bh,
  setImmediate: zo,
  asap: wh,
  isIterable: _h
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/Axios.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/buildURL.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/AxiosURLSearchParams.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/toFormData.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/AxiosError.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/AxiosHeaders.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/parseHeaders.js
c();
var Eh = f.toObjectSet([
  "age",
  "authorization",
  "content-length",
  "content-type",
  "etag",
  "expires",
  "from",
  "host",
  "if-modified-since",
  "if-unmodified-since",
  "last-modified",
  "location",
  "max-forwards",
  "proxy-authorization",
  "referer",
  "retry-after",
  "user-agent"
]), Ho = (e) => {
  let t = {}, n, r, i;
  return e && e.split(`
`).forEach(function(a) {
    i = a.indexOf(":"), n = a.substring(0, i).trim().toLowerCase(), r = a.substring(i + 1).trim(), !(!n || t[n] && Eh[n]) && (n === "set-cookie" ? t[n] ? t[n].push(r) : t[n] = [r] : t[n] = t[n] ? t[n] + ", " + r : r);
  }), t;
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/sanitizeHeaderValue.js
c();
function Sh(e) {
  let t = 0, n = e.length;
  for (; t < n; ) {
    let r = e.charCodeAt(t);
    if (r !== 9 && r !== 32)
      break;
    t += 1;
  }
  for (; n > t; ) {
    let r = e.charCodeAt(n - 1);
    if (r !== 9 && r !== 32)
      break;
    n -= 1;
  }
  return t === 0 && n === e.length ? e : e.slice(t, n);
}
var Rh = new RegExp("[\\u0000-\\u0008\\u000a-\\u001f\\u007f]+", "g"), Th = new RegExp("[^\\u0009\\u0020-\\u007e\\u0080-\\u00ff]+", "g");
function Si(e, t) {
  return f.isArray(e) ? e.map((n) => Si(n, t)) : Sh(String(e).replace(t, ""));
}
var Mo = (e) => Si(e, Rh), kh = (e) => Si(e, Th);
function Dt(e) {
  let t = /* @__PURE__ */ Object.create(null);
  return f.forEach(e.toJSON(), (n, r) => {
    t[r] = kh(n);
  }), t;
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/AxiosHeaders.js
var $o = /* @__PURE__ */ Symbol("internals");
function gn(e) {
  return e && String(e).trim().toLowerCase();
}
function sr(e) {
  return e === !1 || e == null ? e : f.isArray(e) ? e.map(sr) : Mo(String(e));
}
function Ch(e) {
  let t = /* @__PURE__ */ Object.create(null), n = /([^\s,;=]+)\s*(?:=\s*([^,;]+))?/g, r;
  for (; r = n.exec(e); )
    t[r[1]] = r[2];
  return t;
}
var Ah = (e) => /^[-_a-zA-Z0-9^`|~,!#$%&'*+.]+$/.test(e.trim());
function Ri(e, t, n, r, i) {
  if (f.isFunction(r))
    return r.call(this, t, n);
  if (i && (t = n), !!f.isString(t)) {
    if (f.isString(r))
      return t.indexOf(r) !== -1;
    if (f.isRegExp(r))
      return r.test(t);
  }
}
function Oh(e) {
  return e.trim().toLowerCase().replace(/([a-z\d])(\w*)/g, (t, n, r) => n.toUpperCase() + r);
}
function Ph(e, t) {
  let n = f.toCamelCase(" " + t);
  ["get", "set", "has"].forEach((r) => {
    Object.defineProperty(e, r + n, {
      // Null-proto descriptor so a polluted Object.prototype.get cannot turn
      // this data descriptor into an accessor descriptor on the way in.
      __proto__: null,
      value: function(i, s, a) {
        return this[r].call(this, t, i, s, a);
      },
      configurable: !0
    });
  });
}
var It = class {
  constructor(t) {
    t && this.set(t);
  }
  set(t, n, r) {
    let i = this;
    function s(o, l, p) {
      let u = gn(l);
      if (!u)
        throw new Error("header name must be a non-empty string");
      let d = f.findKey(i, u);
      (!d || i[d] === void 0 || p === !0 || p === void 0 && i[d] !== !1) && (i[d || l] = sr(o));
    }
    let a = (o, l) => f.forEach(o, (p, u) => s(p, u, l));
    if (f.isPlainObject(t) || t instanceof this.constructor)
      a(t, n);
    else if (f.isString(t) && (t = t.trim()) && !Ah(t))
      a(Ho(t), n);
    else if (f.isObject(t) && f.isIterable(t)) {
      let o = {}, l, p;
      for (let u of t) {
        if (!f.isArray(u))
          throw TypeError("Object iterator must return a key-value pair");
        o[p = u[0]] = (l = o[p]) ? f.isArray(l) ? [...l, u[1]] : [l, u[1]] : u[1];
      }
      a(o, n);
    } else
      t != null && s(n, t, r);
    return this;
  }
  get(t, n) {
    if (t = gn(t), t) {
      let r = f.findKey(this, t);
      if (r) {
        let i = this[r];
        if (!n)
          return i;
        if (n === !0)
          return Ch(i);
        if (f.isFunction(n))
          return n.call(this, i, r);
        if (f.isRegExp(n))
          return n.exec(i);
        throw new TypeError("parser must be boolean|regexp|function");
      }
    }
  }
  has(t, n) {
    if (t = gn(t), t) {
      let r = f.findKey(this, t);
      return !!(r && this[r] !== void 0 && (!n || Ri(this, this[r], r, n)));
    }
    return !1;
  }
  delete(t, n) {
    let r = this, i = !1;
    function s(a) {
      if (a = gn(a), a) {
        let o = f.findKey(r, a);
        o && (!n || Ri(r, r[o], o, n)) && (delete r[o], i = !0);
      }
    }
    return f.isArray(t) ? t.forEach(s) : s(t), i;
  }
  clear(t) {
    let n = Object.keys(this), r = n.length, i = !1;
    for (; r--; ) {
      let s = n[r];
      (!t || Ri(this, this[s], s, t, !0)) && (delete this[s], i = !0);
    }
    return i;
  }
  normalize(t) {
    let n = this, r = {};
    return f.forEach(this, (i, s) => {
      let a = f.findKey(r, s);
      if (a) {
        n[a] = sr(i), delete n[s];
        return;
      }
      let o = t ? Oh(s) : String(s).trim();
      o !== s && delete n[s], n[o] = sr(i), r[o] = !0;
    }), this;
  }
  concat(...t) {
    return this.constructor.concat(this, ...t);
  }
  toJSON(t) {
    let n = /* @__PURE__ */ Object.create(null);
    return f.forEach(this, (r, i) => {
      r != null && r !== !1 && (n[i] = t && f.isArray(r) ? r.join(", ") : r);
    }), n;
  }
  [Symbol.iterator]() {
    return Object.entries(this.toJSON())[Symbol.iterator]();
  }
  toString() {
    return Object.entries(this.toJSON()).map(([t, n]) => t + ": " + n).join(`
`);
  }
  getSetCookie() {
    return this.get("set-cookie") || [];
  }
  get [Symbol.toStringTag]() {
    return "AxiosHeaders";
  }
  static from(t) {
    return t instanceof this ? t : new this(t);
  }
  static concat(t, ...n) {
    let r = new this(t);
    return n.forEach((i) => r.set(i)), r;
  }
  static accessor(t) {
    let r = (this[$o] = this[$o] = {
      accessors: {}
    }).accessors, i = this.prototype;
    function s(a) {
      let o = gn(a);
      r[o] || (Ph(i, a), r[o] = !0);
    }
    return f.isArray(t) ? t.forEach(s) : s(t), this;
  }
};
It.accessor([
  "Content-Type",
  "Content-Length",
  "Accept",
  "Accept-Encoding",
  "User-Agent",
  "Authorization"
]);
f.reduceDescriptors(It.prototype, ({ value: e }, t) => {
  let n = t[0].toUpperCase() + t.slice(1);
  return {
    get: () => e,
    set(r) {
      this[n] = r;
    }
  };
});
f.freezeMethods(It);
var M = It;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/AxiosError.js
var jh = "[REDACTED ****]";
function qh(e) {
  if (f.hasOwnProp(e, "toJSON"))
    return !0;
  let t = Object.getPrototypeOf(e);
  for (; t && t !== Object.prototype; ) {
    if (f.hasOwnProp(t, "toJSON"))
      return !0;
    t = Object.getPrototypeOf(t);
  }
  return !1;
}
function Lh(e, t) {
  let n = new Set(t.map((s) => String(s).toLowerCase())), r = [], i = (s) => {
    if (s === null || typeof s != "object" || f.isBuffer(s)) return s;
    if (r.indexOf(s) !== -1) return;
    s instanceof M && (s = s.toJSON()), r.push(s);
    let a;
    if (f.isArray(s))
      a = [], s.forEach((o, l) => {
        let p = i(o);
        f.isUndefined(p) || (a[l] = p);
      });
    else {
      if (!f.isPlainObject(s) && qh(s))
        return r.pop(), s;
      a = /* @__PURE__ */ Object.create(null);
      for (let [o, l] of Object.entries(s)) {
        let p = n.has(o.toLowerCase()) ? jh : i(l);
        f.isUndefined(p) || (a[o] = p);
      }
    }
    return r.pop(), a;
  };
  return i(e);
}
var le = class e extends Error {
  static from(t, n, r, i, s, a) {
    let o = new e(t.message, n || t.code, r, i, s);
    return o.cause = t, o.name = t.name, t.status != null && o.status == null && (o.status = t.status), a && Object.assign(o, a), o;
  }
  /**
   * Create an Error with the specified message, config, error code, request and response.
   *
   * @param {string} message The error message.
   * @param {string} [code] The error code (for example, 'ECONNABORTED').
   * @param {Object} [config] The config.
   * @param {Object} [request] The request.
   * @param {Object} [response] The response.
   *
   * @returns {Error} The created error.
   */
  constructor(t, n, r, i, s) {
    super(t), Object.defineProperty(this, "message", {
      // Null-proto descriptor so a polluted Object.prototype.get cannot turn
      // this data descriptor into an accessor descriptor on the way in.
      __proto__: null,
      value: t,
      enumerable: !0,
      writable: !0,
      configurable: !0
    }), this.name = "AxiosError", this.isAxiosError = !0, n && (this.code = n), r && (this.config = r), i && (this.request = i), s && (this.response = s, this.status = s.status);
  }
  toJSON() {
    let t = this.config, n = t && f.hasOwnProp(t, "redact") ? t.redact : void 0, r = f.isArray(n) && n.length > 0 ? Lh(t, n) : f.toJSONObject(t);
    return {
      // Standard
      message: this.message,
      name: this.name,
      // Microsoft
      description: this.description,
      number: this.number,
      // Mozilla
      fileName: this.fileName,
      lineNumber: this.lineNumber,
      columnNumber: this.columnNumber,
      stack: this.stack,
      // Axios
      config: r,
      code: this.code,
      status: this.status
    };
  }
};
le.ERR_BAD_OPTION_VALUE = "ERR_BAD_OPTION_VALUE";
le.ERR_BAD_OPTION = "ERR_BAD_OPTION";
le.ECONNABORTED = "ECONNABORTED";
le.ETIMEDOUT = "ETIMEDOUT";
le.ECONNREFUSED = "ECONNREFUSED";
le.ERR_NETWORK = "ERR_NETWORK";
le.ERR_FR_TOO_MANY_REDIRECTS = "ERR_FR_TOO_MANY_REDIRECTS";
le.ERR_DEPRECATED = "ERR_DEPRECATED";
le.ERR_BAD_RESPONSE = "ERR_BAD_RESPONSE";
le.ERR_BAD_REQUEST = "ERR_BAD_REQUEST";
le.ERR_CANCELED = "ERR_CANCELED";
le.ERR_NOT_SUPPORT = "ERR_NOT_SUPPORT";
le.ERR_INVALID_URL = "ERR_INVALID_URL";
le.ERR_FORM_DATA_DEPTH_EXCEEDED = "ERR_FORM_DATA_DEPTH_EXCEEDED";
var S = le;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/platform/node/classes/FormData.js
c();
var Kl = he(Gl(), 1), xr = Kl.default;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/toFormData.js
function Wi(e) {
  return f.isPlainObject(e) || f.isArray(e);
}
function Jl(e) {
  return f.endsWith(e, "[]") ? e.slice(0, -2) : e;
}
function Vi(e, t, n) {
  return e ? e.concat(t).map(function(i, s) {
    return i = Jl(i), !n && s ? "[" + i + "]" : i;
  }).join(n ? "." : "") : t;
}
function vg(e) {
  return f.isArray(e) && !e.some(Wi);
}
var bg = f.toFlatObject(f, {}, null, function(t) {
  return /^is[A-Z]/.test(t);
});
function wg(e, t, n) {
  if (!f.isObject(e))
    throw new TypeError("target must be an object");
  t = t || new (xr || FormData)(), n = f.toFlatObject(
    n,
    {
      metaTokens: !0,
      dots: !1,
      indexes: !1
    },
    !1,
    function(h, w) {
      return !f.isUndefined(w[h]);
    }
  );
  let r = n.metaTokens, i = n.visitor || d, s = n.dots, a = n.indexes, o = n.Blob || typeof Blob < "u" && Blob, l = n.maxDepth === void 0 ? 100 : n.maxDepth, p = o && f.isSpecCompliantForm(t);
  if (!f.isFunction(i))
    throw new TypeError("visitor must be a function");
  function u(v) {
    if (v === null) return "";
    if (f.isDate(v))
      return v.toISOString();
    if (f.isBoolean(v))
      return v.toString();
    if (!p && f.isBlob(v))
      throw new S("Blob is not supported. Use a Buffer instead.");
    return f.isArrayBuffer(v) || f.isTypedArray(v) ? p && typeof Blob == "function" ? new Blob([v]) : Buffer.from(v) : v;
  }
  function d(v, h, w) {
    let T = v;
    if (f.isReactNative(t) && f.isReactNativeBlob(v))
      return t.append(Vi(w, h, s), u(v)), !1;
    if (v && !w && typeof v == "object") {
      if (f.endsWith(h, "{}"))
        h = r ? h : h.slice(0, -2), v = JSON.stringify(v);
      else if (f.isArray(v) && vg(v) || (f.isFileList(v) || f.endsWith(h, "[]")) && (T = f.toArray(v)))
        return h = Jl(h), T.forEach(function(O, q) {
          !(f.isUndefined(O) || O === null) && t.append(
            // eslint-disable-next-line no-nested-ternary
            a === !0 ? Vi([h], q, s) : a === null ? h : h + "[]",
            u(O)
          );
        }), !1;
    }
    return Wi(v) ? !0 : (t.append(Vi(w, h, s), u(v)), !1);
  }
  let m = [], x = Object.assign(bg, {
    defaultVisitor: d,
    convertValue: u,
    isVisitable: Wi
  });
  function b(v, h, w = 0) {
    if (!f.isUndefined(v)) {
      if (w > l)
        throw new S(
          "Object is too deeply nested (" + w + " levels). Max depth: " + l,
          S.ERR_FORM_DATA_DEPTH_EXCEEDED
        );
      if (m.indexOf(v) !== -1)
        throw Error("Circular reference detected in " + h.join("."));
      m.push(v), f.forEach(v, function(A, O) {
        (!(f.isUndefined(A) || A === null) && i.call(t, A, f.isString(O) ? O.trim() : O, h, x)) === !0 && b(A, h ? h.concat(O) : [O], w + 1);
      }), m.pop();
    }
  }
  if (!f.isObject(e))
    throw new TypeError("data must be an object");
  return b(e), t;
}
var st = wg;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/AxiosURLSearchParams.js
function Yl(e) {
  let t = {
    "!": "%21",
    "'": "%27",
    "(": "%28",
    ")": "%29",
    "~": "%7E",
    "%20": "+"
  };
  return encodeURIComponent(e).replace(/[!'()~]|%20/g, function(r) {
    return t[r];
  });
}
function Ql(e, t) {
  this._pairs = [], e && st(e, this, t);
}
var Xl = Ql.prototype;
Xl.append = function(t, n) {
  this._pairs.push([t, n]);
};
Xl.toString = function(t) {
  let n = t ? function(r) {
    return t.call(this, r, Yl);
  } : Yl;
  return this._pairs.map(function(i) {
    return n(i[0]) + "=" + n(i[1]);
  }, "").join("&");
};
var Zl = Ql;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/buildURL.js
function _g(e) {
  return encodeURIComponent(e).replace(/%3A/gi, ":").replace(/%24/g, "$").replace(/%2C/gi, ",").replace(/%20/g, "+");
}
function yt(e, t, n) {
  if (!t)
    return e;
  let r = n && n.encode || _g, i = f.isFunction(n) ? {
    serialize: n
  } : n, s = i && i.serialize, a;
  if (s ? a = s(t, i) : a = f.isURLSearchParams(t) ? t.toString() : new Zl(t, i).toString(r), a) {
    let o = e.indexOf("#");
    o !== -1 && (e = e.slice(0, o)), e += (e.indexOf("?") === -1 ? "?" : "&") + a;
  }
  return e;
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/InterceptorManager.js
c();
var Gi = class {
  constructor() {
    this.handlers = [];
  }
  /**
   * Add a new interceptor to the stack
   *
   * @param {Function} fulfilled The function to handle `then` for a `Promise`
   * @param {Function} rejected The function to handle `reject` for a `Promise`
   * @param {Object} options The options for the interceptor, synchronous and runWhen
   *
   * @return {Number} An ID used to remove interceptor later
   */
  use(t, n, r) {
    return this.handlers.push({
      fulfilled: t,
      rejected: n,
      synchronous: r ? r.synchronous : !1,
      runWhen: r ? r.runWhen : null
    }), this.handlers.length - 1;
  }
  /**
   * Remove an interceptor from the stack
   *
   * @param {Number} id The ID that was returned by `use`
   *
   * @returns {void}
   */
  eject(t) {
    this.handlers[t] && (this.handlers[t] = null);
  }
  /**
   * Clear all interceptors from the stack
   *
   * @returns {void}
   */
  clear() {
    this.handlers && (this.handlers = []);
  }
  /**
   * Iterate over all the registered interceptors
   *
   * This method is particularly useful for skipping over any
   * interceptors that may have become `null` calling `eject`.
   *
   * @param {Function} fn The function to call for each interceptor
   *
   * @returns {void}
   */
  forEach(t) {
    f.forEach(this.handlers, function(r) {
      r !== null && t(r);
    });
  }
}, Ki = Gi;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/dispatchRequest.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/transformData.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/defaults/index.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/defaults/transitional.js
c();
var at = {
  silentJSONParsing: !0,
  forcedJSONParsing: !0,
  clarifyTimeoutError: !1,
  legacyInterceptorReqResOrdering: !0
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/toURLEncodedForm.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/platform/index.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/platform/node/index.js
c();
var ru = he(require("crypto"), 1);

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/platform/node/classes/URLSearchParams.js
c();
var eu = he(require("url"), 1), tu = eu.default.URLSearchParams;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/platform/node/index.js
var Ji = "abcdefghijklmnopqrstuvwxyz", nu = "0123456789", iu = {
  DIGIT: nu,
  ALPHA: Ji,
  ALPHA_DIGIT: Ji + Ji.toUpperCase() + nu
}, Eg = (e = 16, t = iu.ALPHA_DIGIT) => {
  let n = "", { length: r } = t, i = new Uint32Array(e);
  ru.default.randomFillSync(i);
  for (let s = 0; s < e; s++)
    n += t[i[s] % r];
  return n;
}, su = {
  isNode: !0,
  classes: {
    URLSearchParams: tu,
    FormData: xr,
    Blob: typeof Blob < "u" && Blob || null
  },
  ALPHABET: iu,
  generateString: Eg,
  protocols: ["http", "https", "file", "data"]
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/platform/common/utils.js
var Xi = {};
gm(Xi, {
  hasBrowserEnv: () => Qi,
  hasStandardBrowserEnv: () => Sg,
  hasStandardBrowserWebWorkerEnv: () => Rg,
  navigator: () => Yi,
  origin: () => Tg
});
c();
var Qi = typeof window < "u" && typeof document < "u", Yi = typeof navigator == "object" && navigator || void 0, Sg = Qi && (!Yi || ["ReactNative", "NativeScript", "NS"].indexOf(Yi.product) < 0), Rg = typeof WorkerGlobalScope < "u" && // eslint-disable-next-line no-undef
self instanceof WorkerGlobalScope && typeof self.importScripts == "function", Tg = Qi && window.location.href || "http://localhost";

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/platform/index.js
var L = {
  ...Xi,
  ...su
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/toURLEncodedForm.js
function Zi(e, t) {
  return st(e, new L.classes.URLSearchParams(), {
    visitor: function(n, r, i, s) {
      return L.isNode && f.isBuffer(n) ? (this.append(r, n.toString("base64")), !1) : s.defaultVisitor.apply(this, arguments);
    },
    ...t
  });
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/formDataToJSON.js
c();
function kg(e) {
  return f.matchAll(/\w+|\[(\w*)]/g, e).map((t) => t[0] === "[]" ? "" : t[1] || t[0]);
}
function Cg(e) {
  let t = {}, n = Object.keys(e), r, i = n.length, s;
  for (r = 0; r < i; r++)
    s = n[r], t[s] = e[s];
  return t;
}
function Ag(e) {
  function t(n, r, i, s) {
    let a = n[s++];
    if (a === "__proto__") return !0;
    let o = Number.isFinite(+a), l = s >= n.length;
    return a = !a && f.isArray(i) ? i.length : a, l ? (f.hasOwnProp(i, a) ? i[a] = f.isArray(i[a]) ? i[a].concat(r) : [i[a], r] : i[a] = r, !o) : ((!f.hasOwnProp(i, a) || !f.isObject(i[a])) && (i[a] = []), t(n, r, i[a], s) && f.isArray(i[a]) && (i[a] = Cg(i[a])), !o);
  }
  if (f.isFormData(e) && f.isFunction(e.entries)) {
    let n = {};
    return f.forEachEntry(e, (r, i) => {
      t(kg(r), i, n, 0);
    }), n;
  }
  return null;
}
var gr = Ag;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/defaults/index.js
var Ht = (e, t) => e != null && f.hasOwnProp(e, t) ? e[t] : void 0;
function Og(e, t, n) {
  if (f.isString(e))
    try {
      return (t || JSON.parse)(e), f.trim(e);
    } catch (r) {
      if (r.name !== "SyntaxError")
        throw r;
    }
  return (n || JSON.stringify)(e);
}
var es = {
  transitional: at,
  adapter: ["xhr", "http", "fetch"],
  transformRequest: [
    function(t, n) {
      let r = n.getContentType() || "", i = r.indexOf("application/json") > -1, s = f.isObject(t);
      if (s && f.isHTMLForm(t) && (t = new FormData(t)), f.isFormData(t))
        return i ? JSON.stringify(gr(t)) : t;
      if (f.isArrayBuffer(t) || f.isBuffer(t) || f.isStream(t) || f.isFile(t) || f.isBlob(t) || f.isReadableStream(t))
        return t;
      if (f.isArrayBufferView(t))
        return t.buffer;
      if (f.isURLSearchParams(t))
        return n.setContentType("application/x-www-form-urlencoded;charset=utf-8", !1), t.toString();
      let o;
      if (s) {
        let l = Ht(this, "formSerializer");
        if (r.indexOf("application/x-www-form-urlencoded") > -1)
          return Zi(t, l).toString();
        if ((o = f.isFileList(t)) || r.indexOf("multipart/form-data") > -1) {
          let p = Ht(this, "env"), u = p && p.FormData;
          return st(
            o ? { "files[]": t } : t,
            u && new u(),
            l
          );
        }
      }
      return s || i ? (n.setContentType("application/json", !1), Og(t)) : t;
    }
  ],
  transformResponse: [
    function(t) {
      let n = Ht(this, "transitional") || es.transitional, r = n && n.forcedJSONParsing, i = Ht(this, "responseType"), s = i === "json";
      if (f.isResponse(t) || f.isReadableStream(t))
        return t;
      if (t && f.isString(t) && (r && !i || s)) {
        let o = !(n && n.silentJSONParsing) && s;
        try {
          return JSON.parse(t, Ht(this, "parseReviver"));
        } catch (l) {
          if (o)
            throw l.name === "SyntaxError" ? S.from(l, S.ERR_BAD_RESPONSE, this, null, Ht(this, "response")) : l;
        }
      }
      return t;
    }
  ],
  /**
   * A timeout in milliseconds to abort a request. If set to 0 (default) a
   * timeout is not created.
   */
  timeout: 0,
  xsrfCookieName: "XSRF-TOKEN",
  xsrfHeaderName: "X-XSRF-TOKEN",
  maxContentLength: -1,
  maxBodyLength: -1,
  env: {
    FormData: L.classes.FormData,
    Blob: L.classes.Blob
  },
  validateStatus: function(t) {
    return t >= 200 && t < 300;
  },
  headers: {
    common: {
      Accept: "application/json, text/plain, */*",
      "Content-Type": void 0
    }
  }
};
f.forEach(["delete", "get", "head", "post", "put", "patch", "query"], (e) => {
  es.headers[e] = {};
});
var Mt = es;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/transformData.js
function _n(e, t) {
  let n = this || Mt, r = t || n, i = M.from(r.headers), s = r.data;
  return f.forEach(e, function(o) {
    s = o.call(n, s, i.normalize(), t ? t.status : void 0);
  }), i.normalize(), s;
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/cancel/isCancel.js
c();
function En(e) {
  return !!(e && e.__CANCEL__);
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/cancel/CanceledError.js
c();
var ts = class extends S {
  /**
   * A `CanceledError` is an object that is thrown when an operation is canceled.
   *
   * @param {string=} message The message.
   * @param {Object=} config The config.
   * @param {Object=} request The request.
   *
   * @returns {CanceledError} The created error.
   */
  constructor(t, n, r) {
    super(t ?? "canceled", S.ERR_CANCELED, n, r), this.name = "CanceledError", this.__CANCEL__ = !0;
  }
}, Te = ts;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/adapters.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/http.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/settle.js
c();
function Ve(e, t, n) {
  let r = n.config.validateStatus;
  !n.status || !r || r(n.status) ? e(n) : t(new S(
    "Request failed with status code " + n.status,
    n.status >= 400 && n.status < 500 ? S.ERR_BAD_REQUEST : S.ERR_BAD_RESPONSE,
    n.config,
    n.request,
    n
  ));
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/buildFullPath.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/isAbsoluteURL.js
c();
function ns(e) {
  return typeof e != "string" ? !1 : /^([a-z][a-z\d+\-.]*:)?\/\//i.test(e);
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/combineURLs.js
c();
function rs(e, t) {
  return t ? e.replace(/\/?\/$/, "") + "/" + t.replace(/^\/+/, "") : e;
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/buildFullPath.js
function vt(e, t, n) {
  let r = !ns(t);
  return e && (r || n === !1) ? rs(e, t) : t;
}

// node_modules/.pnpm/proxy-from-env@2.1.0/node_modules/proxy-from-env/index.js
c();
var Pg = {
  ftp: 21,
  gopher: 70,
  http: 80,
  https: 443,
  ws: 80,
  wss: 443
};
function jg(e) {
  try {
    return new URL(e);
  } catch {
    return null;
  }
}
function au(e) {
  var t = (typeof e == "string" ? jg(e) : e) || {}, n = t.protocol, r = t.host, i = t.port;
  if (typeof r != "string" || !r || typeof n != "string" || (n = n.split(":", 1)[0], r = r.replace(/:\d*$/, ""), i = parseInt(i) || Pg[n] || 0, !qg(r, i)))
    return "";
  var s = is(n + "_proxy") || is("all_proxy");
  return s && s.indexOf("://") === -1 && (s = n + "://" + s), s;
}
function qg(e, t) {
  var n = is("no_proxy").toLowerCase();
  return n ? n === "*" ? !1 : n.split(/[,\s]/).every(function(r) {
    if (!r)
      return !0;
    var i = r.match(/^(.+):(\d+)$/), s = i ? i[1] : r, a = i ? parseInt(i[2]) : 0;
    return a && a !== t ? !0 : /^[.*]/.test(s) ? (s.charAt(0) === "*" && (s = s.slice(1)), !e.endsWith(s)) : e !== s;
  }) : !0;
}
function is(e) {
  return process.env[e.toLowerCase()] || process.env[e.toUpperCase()] || "";
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/http.js
var Us = he(_u(), 1), Qu = he(require("http"), 1), Xu = he(require("https"), 1), Ds = he(require("http2"), 1), Is = he(require("util"), 1), qs = require("path"), Zu = he(Au(), 1), Qe = he(require("zlib"), 1);

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/env/data.js
c();
var Je = "1.16.1";

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/fromDataURI.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/parseProtocol.js
c();
function qn(e) {
  let t = /^([-+\w]{1,25}):(?:\/\/)?/.exec(e);
  return t && t[1] || "";
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/fromDataURI.js
var qy = /^([^,;]+\/[^,;]+)?((?:;[^,;=]+=[^,;]+)*)(;base64)?,([\s\S]*)$/;
function Ts(e, t, n) {
  let r = n && n.Blob || L.classes.Blob, i = qn(e);
  if (t === void 0 && r && (t = !0), i === "data") {
    e = i.length ? e.slice(i.length + 1) : e;
    let s = qy.exec(e);
    if (!s)
      throw new S("Invalid URL", S.ERR_INVALID_URL);
    let a = s[1], o = s[2], l = s[3] ? "base64" : "utf8", p = s[4], u;
    a ? u = o ? a + o : a : o && (u = "text/plain" + o);
    let d = Buffer.from(decodeURIComponent(p), l);
    if (t) {
      if (!r)
        throw new S("Blob is not supported", S.ERR_NOT_SUPPORT);
      return new r([d], { type: u });
    }
    return d;
  }
  throw new S("Unsupported protocol " + i, S.ERR_NOT_SUPPORT);
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/http.js
var Oe = he(require("stream"), 1);

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/AxiosTransformStream.js
c();
var Ou = he(require("stream"), 1);
var ks = /* @__PURE__ */ Symbol("internals"), Cs = class extends Ou.default.Transform {
  constructor(t) {
    t = f.toFlatObject(
      t,
      {
        maxRate: 0,
        chunkSize: 64 * 1024,
        minChunkSize: 100,
        timeWindow: 500,
        ticksRate: 2,
        samplesCount: 15
      },
      null,
      (r, i) => !f.isUndefined(i[r])
    ), super({
      readableHighWaterMark: t.chunkSize
    });
    let n = this[ks] = {
      timeWindow: t.timeWindow,
      chunkSize: t.chunkSize,
      maxRate: t.maxRate,
      minChunkSize: t.minChunkSize,
      bytesSeen: 0,
      isCaptured: !1,
      notifiedBytesLoaded: 0,
      ts: Date.now(),
      bytes: 0,
      onReadCallback: null
    };
    this.on("newListener", (r) => {
      r === "progress" && (n.isCaptured || (n.isCaptured = !0));
    });
  }
  _read(t) {
    let n = this[ks];
    return n.onReadCallback && n.onReadCallback(), super._read(t);
  }
  _transform(t, n, r) {
    let i = this[ks], s = i.maxRate, a = this.readableHighWaterMark, o = i.timeWindow, l = 1e3 / o, p = s / l, u = i.minChunkSize !== !1 ? Math.max(i.minChunkSize, p * 0.01) : 0, d = (x, b) => {
      let v = Buffer.byteLength(x);
      i.bytesSeen += v, i.bytes += v, i.isCaptured && this.emit("progress", i.bytesSeen), this.push(x) ? process.nextTick(b) : i.onReadCallback = () => {
        i.onReadCallback = null, process.nextTick(b);
      };
    }, m = (x, b) => {
      let v = Buffer.byteLength(x), h = null, w = a, T, A = 0;
      if (s) {
        let O = Date.now();
        (!i.ts || (A = O - i.ts) >= o) && (i.ts = O, T = p - i.bytes, i.bytes = T < 0 ? -T : 0, A = 0), T = p - i.bytes;
      }
      if (s) {
        if (T <= 0)
          return setTimeout(() => {
            b(null, x);
          }, o - A);
        T < w && (w = T);
      }
      w && v > w && v - w > u && (h = x.subarray(w), x = x.subarray(0, w)), d(
        x,
        h ? () => {
          process.nextTick(b, null, h);
        } : b
      );
    };
    m(t, function x(b, v) {
      if (b)
        return r(b);
      v ? m(v, x) : r(null);
    });
  }
}, As = Cs;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/http.js
var ep = require("events");

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/formDataToStream.js
c();
var ju = he(require("util"), 1), qu = require("stream");

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/readBlob.js
c();
var { asyncIterator: Pu } = Symbol, Ly = async function* (e) {
  e.stream ? yield* e.stream() : e.arrayBuffer ? yield await e.arrayBuffer() : e[Pu] ? yield* e[Pu]() : yield e;
}, Er = Ly;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/formDataToStream.js
var Uy = L.ALPHABET.ALPHA_DIGIT + "-_", Ln = typeof TextEncoder == "function" ? new TextEncoder() : new ju.default.TextEncoder(), St = `\r
`, Dy = Ln.encode(St), Iy = 2, Os = class {
  constructor(t, n) {
    let { escapeName: r } = this.constructor, i = f.isString(n), s = `Content-Disposition: form-data; name="${r(t)}"${!i && n.name ? `; filename="${r(n.name)}"` : ""}${St}`;
    if (i)
      n = Ln.encode(String(n).replace(/\r?\n|\r\n?/g, St));
    else {
      let a = String(n.type || "application/octet-stream").replace(/[\r\n]/g, "");
      s += `Content-Type: ${a}${St}`;
    }
    this.headers = Ln.encode(s + St), this.contentLength = i ? n.byteLength : n.size, this.size = this.headers.byteLength + this.contentLength + Iy, this.name = t, this.value = n;
  }
  async *encode() {
    yield this.headers;
    let { value: t } = this;
    f.isTypedArray(t) ? yield t : yield* Er(t), yield Dy;
  }
  static escapeName(t) {
    return String(t).replace(
      /[\r\n"]/g,
      (n) => ({
        "\r": "%0D",
        "\n": "%0A",
        '"': "%22"
      })[n]
    );
  }
}, Fy = (e, t, n) => {
  let {
    tag: r = "form-data-boundary",
    size: i = 25,
    boundary: s = r + "-" + L.generateString(i, Uy)
  } = n || {};
  if (!f.isFormData(e))
    throw TypeError("FormData instance required");
  if (s.length < 1 || s.length > 70)
    throw Error("boundary must be 1-70 characters long");
  let a = Ln.encode("--" + s + St), o = Ln.encode("--" + s + "--" + St), l = o.byteLength, p = Array.from(e.entries()).map(([d, m]) => {
    let x = new Os(d, m);
    return l += x.size, x;
  });
  l += a.byteLength * p.length, l = f.toFiniteNumber(l);
  let u = {
    "Content-Type": `multipart/form-data; boundary=${s}`
  };
  return Number.isFinite(l) && (u["Content-Length"] = l), t && t(u), qu.Readable.from(
    (async function* () {
      for (let d of p)
        yield a, yield* d.encode();
      yield o;
    })()
  );
}, Lu = Fy;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/ZlibHeaderTransformStream.js
c();
var Uu = he(require("stream"), 1), Ps = class extends Uu.default.Transform {
  __transform(t, n, r) {
    this.push(t), r();
  }
  _transform(t, n, r) {
    if (t.length !== 0 && (this._transform = this.__transform, t[0] !== 120)) {
      let i = Buffer.alloc(2);
      i[0] = 120, i[1] = 156, this.push(i, n);
    }
    this.__transform(t, n, r);
  }
}, Du = Ps;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/callbackify.js
c();
var Ny = (e, t) => f.isAsyncFn(e) ? function(...n) {
  let r = n.pop();
  e.apply(this, n).then((i) => {
    try {
      t ? r(null, ...t(i)) : r(null, i);
    } catch (s) {
      r(s);
    }
  }, r);
} : e, Iu = Ny;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/shouldBypassProxy.js
c();
var By = /* @__PURE__ */ new Set(["localhost"]), Bu = (e) => {
  let t = e.split(".");
  return t.length !== 4 || t[0] !== "127" ? !1 : t.every((n) => /^\d+$/.test(n) && Number(n) >= 0 && Number(n) <= 255);
}, zy = (e) => {
  if (e === "::1") return !0;
  let t = e.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (t) return Bu(t[1]);
  let n = e.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);
  if (n) {
    let i = parseInt(n[1], 16);
    return i >= 32512 && i <= 32767;
  }
  let r = e.split(":");
  if (r.length === 8) {
    for (let i = 0; i < 7; i++)
      if (!/^0+$/.test(r[i])) return !1;
    return /^0*1$/.test(r[7]);
  }
  return !1;
}, Fu = (e) => e ? By.has(e) || Bu(e) ? !0 : zy(e) : !1, Hy = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21
}, My = (e) => {
  let t = e, n = 0;
  if (t.charAt(0) === "[") {
    let s = t.indexOf("]");
    if (s !== -1) {
      let a = t.slice(1, s), o = t.slice(s + 1);
      return o.charAt(0) === ":" && /^\d+$/.test(o.slice(1)) && (n = Number.parseInt(o.slice(1), 10)), [a, n];
    }
  }
  let r = t.indexOf(":"), i = t.lastIndexOf(":");
  return r !== -1 && r === i && /^\d+$/.test(t.slice(i + 1)) && (n = Number.parseInt(t.slice(i + 1), 10), t = t.slice(0, i)), [t, n];
}, $y = /^(?:::|(?:0{1,4}:){1,4}:|(?:0{1,4}:){5})ffff:(\d+\.\d+\.\d+\.\d+)$/i, Vy = /^(?:::|(?:0{1,4}:){1,4}:|(?:0{1,4}:){5})ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i, Wy = (e) => {
  if (typeof e != "string" || e.indexOf(":") === -1) return e;
  let t = e.match($y);
  if (t) return t[1];
  let n = e.match(Vy);
  if (n) {
    let r = parseInt(n[1], 16), i = parseInt(n[2], 16);
    return `${r >> 8}.${r & 255}.${i >> 8}.${i & 255}`;
  }
  return e;
}, Nu = (e) => e && (e.charAt(0) === "[" && e.charAt(e.length - 1) === "]" && (e = e.slice(1, -1)), Wy(e.replace(/\.+$/, "")));
function js(e) {
  let t;
  try {
    t = new URL(e);
  } catch {
    return !1;
  }
  let n = (process.env.no_proxy || process.env.NO_PROXY || "").toLowerCase();
  if (!n)
    return !1;
  if (n === "*")
    return !0;
  let r = Number.parseInt(t.port, 10) || Hy[t.protocol.split(":", 1)[0]] || 0, i = Nu(t.hostname.toLowerCase());
  return n.split(/[\s,]+/).some((s) => {
    if (!s)
      return !1;
    let [a, o] = My(s);
    return a = Nu(a), !a || o && o !== r ? !1 : (a.charAt(0) === "*" && (a = a.slice(1)), a.charAt(0) === "." ? i.endsWith(a) : i === a || Fu(i) && Fu(a));
  });
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/progressEventReducer.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/speedometer.js
c();
function Gy(e, t) {
  e = e || 10;
  let n = new Array(e), r = new Array(e), i = 0, s = 0, a;
  return t = t !== void 0 ? t : 1e3, function(l) {
    let p = Date.now(), u = r[s];
    a || (a = p), n[i] = l, r[i] = p;
    let d = s, m = 0;
    for (; d !== i; )
      m += n[d++], d = d % e;
    if (i = (i + 1) % e, i === s && (s = (s + 1) % e), p - a < t)
      return;
    let x = u && p - u;
    return x ? Math.round(m * 1e3 / x) : void 0;
  };
}
var zu = Gy;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/throttle.js
c();
function Ky(e, t) {
  let n = 0, r = 1e3 / t, i, s, a = (p, u = Date.now()) => {
    n = u, i = null, s && (clearTimeout(s), s = null), e(...p);
  };
  return [(...p) => {
    let u = Date.now(), d = u - n;
    d >= r ? a(p, u) : (i = p, s || (s = setTimeout(() => {
      s = null, a(i);
    }, r - d)));
  }, () => i && a(i)];
}
var Hu = Ky;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/progressEventReducer.js
var Ye = (e, t, n = 3) => {
  let r = 0, i = zu(50, 250);
  return Hu((s) => {
    if (!s || typeof s.loaded != "number")
      return;
    let a = s.loaded, o = s.lengthComputable ? s.total : void 0, l = o != null ? Math.min(a, o) : a, p = Math.max(0, l - r), u = i(p);
    r = Math.max(r, l);
    let d = {
      loaded: l,
      total: o,
      progress: o ? l / o : void 0,
      bytes: p,
      rate: u || void 0,
      estimated: u && o ? (o - l) / u : void 0,
      event: s,
      lengthComputable: o != null,
      [t ? "download" : "upload"]: !0
    };
    e(d);
  }, n);
}, Kt = (e, t) => {
  let n = e != null;
  return [
    (r) => t[0]({
      lengthComputable: n,
      total: e,
      loaded: r
    }),
    t[1]
  ];
}, Jt = (e) => (...t) => f.asap(() => e(...t));

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/estimateDataURLDecodedBytes.js
c();
function Un(e) {
  if (!e || typeof e != "string" || !e.startsWith("data:")) return 0;
  let t = e.indexOf(",");
  if (t < 0) return 0;
  let n = e.slice(5, t), r = e.slice(t + 1);
  if (/;base64/i.test(n)) {
    let a = r.length, o = r.length;
    for (let x = 0; x < o; x++)
      if (r.charCodeAt(x) === 37 && x + 2 < o) {
        let b = r.charCodeAt(x + 1), v = r.charCodeAt(x + 2);
        (b >= 48 && b <= 57 || b >= 65 && b <= 70 || b >= 97 && b <= 102) && (v >= 48 && v <= 57 || v >= 65 && v <= 70 || v >= 97 && v <= 102) && (a -= 2, x += 2);
      }
    let l = 0, p = o - 1, u = (x) => x >= 2 && r.charCodeAt(x - 2) === 37 && // '%'
    r.charCodeAt(x - 1) === 51 && // '3'
    (r.charCodeAt(x) === 68 || r.charCodeAt(x) === 100);
    p >= 0 && (r.charCodeAt(p) === 61 ? (l++, p--) : u(p) && (l++, p -= 3)), l === 1 && p >= 0 && (r.charCodeAt(p) === 61 || u(p)) && l++;
    let m = Math.floor(a / 4) * 3 - (l || 0);
    return m > 0 ? m : 0;
  }
  if (typeof Buffer < "u" && typeof Buffer.byteLength == "function")
    return Buffer.byteLength(r, "utf8");
  let s = 0;
  for (let a = 0, o = r.length; a < o; a++) {
    let l = r.charCodeAt(a);
    if (l < 128)
      s += 1;
    else if (l < 2048)
      s += 2;
    else if (l >= 55296 && l <= 56319 && a + 1 < o) {
      let p = r.charCodeAt(a + 1);
      p >= 56320 && p <= 57343 ? (s += 4, a++) : s += 3;
    } else
      s += 3;
  }
  return s;
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/http.js
var Mu = {
  flush: Qe.default.constants.Z_SYNC_FLUSH,
  finishFlush: Qe.default.constants.Z_SYNC_FLUSH
}, Jy = {
  flush: Qe.default.constants.BROTLI_OPERATION_FLUSH,
  finishFlush: Qe.default.constants.BROTLI_OPERATION_FLUSH
}, $u = f.isFunction(Qe.default.createBrotliDecompress), { http: Yy, https: Qy } = Zu.default, tp = /https:?/, Xy = ["content-type", "content-length"];
function Zy(e, t, n) {
  if (n !== "content-only") {
    e.set(t);
    return;
  }
  Object.entries(t).forEach(([r, i]) => {
    Xy.includes(r.toLowerCase()) && e.set(r, i);
  });
}
var Vu = /* @__PURE__ */ Symbol("axios.http.socketListener"), Sr = /* @__PURE__ */ Symbol("axios.http.currentReq"), np = /* @__PURE__ */ Symbol("axios.http.installedTunnel"), ev = /* @__PURE__ */ new Map(), Wu = /* @__PURE__ */ new WeakMap();
function tv(e, t) {
  let n = e.protocol + "//" + e.hostname + ":" + (e.port || "") + "#" + (e.auth || ""), r = t ? Wu.get(t) || Wu.set(t, /* @__PURE__ */ new Map()).get(t) : ev, i = r.get(n);
  if (i) return i;
  let s = t && t.options ? { ...t.options, ...e } : e;
  return i = new Us.default(s), i[np] = !0, r.set(n, i), i;
}
var Gu = L.protocols.map((e) => e + ":"), Ku = (e) => {
  if (!f.isString(e))
    return e;
  try {
    return decodeURIComponent(e);
  } catch {
    return e;
  }
}, Ju = (e, [t, n]) => (e.on("end", n).on("error", n), t), Ls = class {
  constructor() {
    this.sessions = /* @__PURE__ */ Object.create(null);
  }
  getSession(t, n) {
    n = Object.assign(
      {
        sessionTimeout: 1e3
      },
      n
    );
    let r = this.sessions[t];
    if (r) {
      let u = r.length;
      for (let d = 0; d < u; d++) {
        let [m, x] = r[d];
        if (!m.destroyed && !m.closed && Is.default.isDeepStrictEqual(x, n))
          return m;
      }
    }
    let i = Ds.default.connect(t, n), s, a = () => {
      if (s)
        return;
      s = !0;
      let u = r, d = u.length, m = d;
      for (; m--; )
        if (u[m][0] === i) {
          d === 1 ? delete this.sessions[t] : u.splice(m, 1), i.closed || i.close();
          return;
        }
    }, o = i.request, { sessionTimeout: l } = n;
    if (l != null) {
      let u, d = 0;
      i.request = function() {
        let m = o.apply(this, arguments);
        return d++, u && (clearTimeout(u), u = null), m.once("close", () => {
          --d || (u = setTimeout(() => {
            u = null, a();
          }, l));
        }), m;
      };
    }
    i.once("close", a);
    let p = [i, n];
    return r ? r.push(p) : r = this.sessions[t] = [p], i;
  }
}, nv = new Ls();
function rv(e, t, n) {
  e.beforeRedirects.proxy && e.beforeRedirects.proxy(e), e.beforeRedirects.config && e.beforeRedirects.config(e, t, n);
}
function rp(e, t, n, r, i) {
  let s = t;
  if (!s && s !== !1) {
    let a = au(n);
    a && (js(n) || (s = new URL(a)));
  }
  if (r && e.headers)
    for (let a of Object.keys(e.headers))
      a.toLowerCase() === "proxy-authorization" && delete e.headers[a];
  if (r && e.agent && e.agent[np] && (e.agent = void 0), s) {
    let a = s instanceof URL, o = (m) => a || f.hasOwnProp(s, m) ? s[m] : void 0, l = o("username"), p = o("password"), u = f.hasOwnProp(s, "auth") ? s.auth : void 0;
    if (l && (u = (l || "") + ":" + (p || "")), u) {
      let m = typeof u == "object", x = m && f.hasOwnProp(u, "username") ? u.username : void 0, b = m && f.hasOwnProp(u, "password") ? u.password : void 0;
      if (!!(x || b))
        u = (x || "") + ":" + (b || "");
      else if (m)
        throw new S("Invalid proxy authorization", S.ERR_BAD_OPTION, { proxy: s });
    }
    if (tp.test(e.protocol)) {
      if (!(i instanceof Us.default)) {
        let m = o("hostname") || o("host"), x = o("port"), b = o("protocol"), v = b ? b.includes(":") ? b : `${b}:` : "http:", h = m && m.includes(":") && !m.startsWith("[") ? `[${m}]` : m, w = new URL(
          `${v}//${h}${x ? ":" + x : ""}`
        ), T = {
          protocol: w.protocol,
          hostname: w.hostname.replace(/^\[|\]$/g, ""),
          port: w.port,
          auth: u && typeof u == "string" ? u : void 0
        };
        w.protocol === "https:" && (T.ALPNProtocols = ["http/1.1"]);
        let A = tv(T, i);
        e.agent = A, e.agents && (e.agents.https = A);
      }
    } else {
      if (u) {
        let v = Buffer.from(u, "utf8").toString("base64");
        e.headers["Proxy-Authorization"] = "Basic " + v;
      }
      let m = !1;
      for (let v of Object.keys(e.headers))
        if (v.toLowerCase() === "host") {
          m = !0;
          break;
        }
      m || (e.headers.host = e.hostname + (e.port ? ":" + e.port : ""));
      let x = o("hostname") || o("host");
      e.hostname = x, e.host = x, e.port = o("port"), e.path = n;
      let b = o("protocol");
      b && (e.protocol = b.includes(":") ? b : `${b}:`);
    }
  }
  e.beforeRedirects.proxy = function(o) {
    rp(o, t, o.href, !0, i);
  };
}
var iv = typeof process < "u" && f.kindOf(process) === "process", sv = (e) => new Promise((t, n) => {
  let r, i, s = (l, p) => {
    i || (i = !0, r && r(l, p));
  }, a = (l) => {
    s(l), t(l);
  }, o = (l) => {
    s(l, !0), n(l);
  };
  e(a, o, (l) => r = l).catch(o);
}), av = ({ address: e, family: t }) => {
  if (!f.isString(e))
    throw TypeError("address must be a string");
  return {
    address: e,
    family: t || (e.indexOf(".") < 0 ? 6 : 4)
  };
}, Yu = (e, t) => av(f.isObject(e) ? e : { address: e, family: t }), ov = {
  request(e, t) {
    let n = e.protocol + "//" + e.hostname + ":" + (e.port || (e.protocol === "https:" ? 443 : 80)), { http2Options: r, headers: i } = e, s = nv.getSession(n, r), { HTTP2_HEADER_SCHEME: a, HTTP2_HEADER_METHOD: o, HTTP2_HEADER_PATH: l, HTTP2_HEADER_STATUS: p } = Ds.default.constants, u = {
      [a]: e.protocol.replace(":", ""),
      [o]: e.method,
      [l]: e.path
    };
    f.forEach(i, (m, x) => {
      x.charAt(0) !== ":" && (u[x] = m);
    });
    let d = s.request(u);
    return d.once("response", (m) => {
      let x = d;
      m = Object.assign({}, m);
      let b = m[p];
      delete m[p], x.headers = m, x.statusCode = +b, t(x);
    }), d;
  }
}, ip = iv && function(t) {
  return sv(async function(r, i, s) {
    let a = (C) => f.hasOwnProp(t, C) ? t[C] : void 0, o = a("data"), l = a("lookup"), p = a("family"), u = a("httpVersion");
    u === void 0 && (u = 1);
    let d = a("http2Options"), m = a("responseType"), x = a("responseEncoding"), b = t.method.toUpperCase(), v, h = !1, w, T;
    if (u = +u, Number.isNaN(u))
      throw TypeError(`Invalid protocol version: '${t.httpVersion}' is not a number`);
    if (u !== 1 && u !== 2)
      throw TypeError(`Unsupported protocol version '${u}'`);
    let A = u === 2;
    if (l) {
      let C = Iu(l, (R) => f.isArray(R) ? R : [R]);
      l = (R, D, X) => {
        C(R, D, (I, ce, Re) => {
          if (I)
            return X(I);
          let z = f.isArray(ce) ? ce.map((jt) => Yu(jt)) : [Yu(ce, Re)];
          D.all ? X(I, z) : X(I, z[0].address, z[0].family);
        });
      };
    }
    let O = new ep.EventEmitter();
    function q(C) {
      try {
        O.emit(
          "abort",
          !C || C.type ? new Te(null, t, w) : C
        );
      } catch (R) {
        console.warn("emit error", R);
      }
    }
    function W() {
      T && (clearTimeout(T), T = null);
    }
    function ne() {
      let C = t.timeout ? "timeout of " + t.timeout + "ms exceeded" : "timeout exceeded", R = t.transitional || at;
      return t.timeoutErrorMessage && (C = t.timeoutErrorMessage), new S(
        C,
        R.clarifyTimeoutError ? S.ETIMEDOUT : S.ECONNABORTED,
        t,
        w
      );
    }
    O.once("abort", i);
    let re = () => {
      W(), t.cancelToken && t.cancelToken.unsubscribe(q), t.signal && t.signal.removeEventListener("abort", q), O.removeAllListeners();
    };
    (t.cancelToken || t.signal) && (t.cancelToken && t.cancelToken.subscribe(q), t.signal && (t.signal.aborted ? q() : t.signal.addEventListener("abort", q))), s((C, R) => {
      if (v = !0, W(), R) {
        h = !0, re();
        return;
      }
      let { data: D } = C;
      if (D instanceof Oe.default.Readable || D instanceof Oe.default.Duplex) {
        let X = Oe.default.finished(D, () => {
          X(), re();
        });
      } else
        re();
    });
    let Ce = vt(t.baseURL, t.url, t.allowAbsoluteUrls), H = new URL(Ce, L.hasBrowserEnv ? L.origin : void 0), pe = H.protocol || Gu[0];
    if (pe === "data:") {
      if (t.maxContentLength > -1) {
        let R = String(t.url || Ce || "");
        if (Un(R) > t.maxContentLength)
          return i(
            new S(
              "maxContentLength size of " + t.maxContentLength + " exceeded",
              S.ERR_BAD_RESPONSE,
              t
            )
          );
      }
      let C;
      if (b !== "GET")
        return Ve(r, i, {
          status: 405,
          statusText: "method not allowed",
          headers: {},
          config: t
        });
      try {
        C = Ts(t.url, m === "blob", {
          Blob: t.env && t.env.Blob
        });
      } catch (R) {
        throw S.from(R, S.ERR_BAD_REQUEST, t);
      }
      return m === "text" ? (C = C.toString(x), (!x || x === "utf8") && (C = f.stripBOM(C))) : m === "stream" && (C = Oe.default.Readable.from(C)), Ve(r, i, {
        data: C,
        status: 200,
        statusText: "OK",
        headers: new M(),
        config: t
      });
    }
    if (Gu.indexOf(pe) === -1)
      return i(
        new S("Unsupported protocol " + pe, S.ERR_BAD_REQUEST, t)
      );
    let Q = M.from(t.headers).normalize();
    Q.set("User-Agent", "axios/" + Je, !1);
    let { onUploadProgress: rt, onDownloadProgress: de } = t, Me = t.maxRate, Ae, Pt;
    if (f.isSpecCompliantForm(o)) {
      let C = Q.getContentType(/boundary=([-_\w\d]{10,70})/i);
      o = Lu(
        o,
        (R) => {
          Q.set(R);
        },
        {
          tag: `axios-${Je}-boundary`,
          boundary: C && C[1] || void 0
        }
      );
    } else if (f.isFormData(o) && f.isFunction(o.getHeaders) && o.getHeaders !== Object.prototype.getHeaders) {
      if (Zy(Q, o.getHeaders(), a("formDataHeaderPolicy")), !Q.hasContentLength())
        try {
          let C = await Is.default.promisify(o.getLength).call(o);
          Number.isFinite(C) && C >= 0 && Q.setContentLength(C);
        } catch {
        }
    } else if (f.isBlob(o) || f.isFile(o))
      o.size && Q.setContentType(o.type || "application/octet-stream"), Q.setContentLength(o.size || 0), o = Oe.default.Readable.from(Er(o));
    else if (o && !f.isStream(o)) {
      if (!Buffer.isBuffer(o))
        if (f.isArrayBuffer(o))
          o = Buffer.from(new Uint8Array(o));
        else if (f.isString(o))
          o = Buffer.from(o, "utf-8");
        else
          return i(
            new S(
              "Data after transformation must be a string, an ArrayBuffer, a Buffer, or a Stream",
              S.ERR_BAD_REQUEST,
              t
            )
          );
      if (Q.setContentLength(o.length, !1), t.maxBodyLength > -1 && o.length > t.maxBodyLength)
        return i(
          new S(
            "Request body larger than maxBodyLength limit",
            S.ERR_BAD_REQUEST,
            t
          )
        );
    }
    let Qn = f.toFiniteNumber(Q.getContentLength());
    f.isArray(Me) ? (Ae = Me[0], Pt = Me[1]) : Ae = Pt = Me, o && (rt || Ae) && (f.isStream(o) || (o = Oe.default.Readable.from(o, { objectMode: !1 })), o = Oe.default.pipeline(
      [
        o,
        new As({
          maxRate: f.toFiniteNumber(Ae)
        })
      ],
      f.noop
    ), rt && o.on(
      "progress",
      Ju(
        o,
        Kt(
          Qn,
          Ye(Jt(rt), !1, 3)
        )
      )
    ));
    let ge, fe = a("auth");
    if (fe) {
      let C = fe.username || "", R = fe.password || "";
      ge = C + ":" + R;
    }
    if (!ge && H.username) {
      let C = Ku(H.username), R = Ku(H.password);
      ge = C + ":" + R;
    }
    ge && Q.delete("authorization");
    let $e;
    try {
      $e = yt(
        H.pathname + H.search,
        t.params,
        t.paramsSerializer
      ).replace(/^\?/, "");
    } catch (C) {
      let R = new Error(C.message);
      return R.config = t, R.url = t.url, R.exists = !0, i(R);
    }
    Q.set(
      "Accept-Encoding",
      "gzip, compress, deflate" + ($u ? ", br" : ""),
      !1
    );
    let ie = Object.assign(/* @__PURE__ */ Object.create(null), {
      path: $e,
      method: b,
      headers: Dt(Q),
      agents: { http: t.httpAgent, https: t.httpsAgent },
      auth: ge,
      protocol: pe,
      family: p,
      beforeRedirect: rv,
      beforeRedirects: /* @__PURE__ */ Object.create(null),
      http2Options: d
    });
    if (!f.isUndefined(l) && (ie.lookup = l), t.socketPath) {
      if (typeof t.socketPath != "string")
        return i(
          new S("socketPath must be a string", S.ERR_BAD_OPTION_VALUE, t)
        );
      if (t.allowedSocketPaths != null) {
        let C = Array.isArray(t.allowedSocketPaths) ? t.allowedSocketPaths : [t.allowedSocketPaths], R = (0, qs.resolve)(t.socketPath);
        if (!C.some(
          (X) => typeof X == "string" && (0, qs.resolve)(X) === R
        ))
          return i(
            new S(
              `socketPath "${t.socketPath}" is not permitted by allowedSocketPaths`,
              S.ERR_BAD_OPTION_VALUE,
              t
            )
          );
      }
      ie.socketPath = t.socketPath;
    } else
      ie.hostname = H.hostname.startsWith("[") ? H.hostname.slice(1, -1) : H.hostname, ie.port = H.port, rp(
        ie,
        t.proxy,
        pe + "//" + H.hostname + (H.port ? ":" + H.port : "") + ie.path,
        !1,
        t.httpsAgent
      );
    let G, Ue = !1, ye = tp.test(ie.protocol);
    if (ie.agent == null && (ie.agent = ye ? t.httpsAgent : t.httpAgent), A)
      G = ov;
    else {
      let C = a("transport");
      if (C)
        G = C;
      else if (t.maxRedirects === 0)
        G = ye ? Xu.default : Qu.default, Ue = !0;
      else {
        t.maxRedirects && (ie.maxRedirects = t.maxRedirects);
        let R = a("beforeRedirect");
        R && (ie.beforeRedirects.config = R), G = ye ? Qy : Yy;
      }
    }
    t.maxBodyLength > -1 ? ie.maxBodyLength = t.maxBodyLength : ie.maxBodyLength = 1 / 0, ie.insecureHTTPParser = !!a("insecureHTTPParser"), w = G.request(ie, function(R) {
      if (W(), w.destroyed) return;
      let D = [R], X = f.toFiniteNumber(R.headers["content-length"]);
      if (de || Pt) {
        let z = new As({
          maxRate: f.toFiniteNumber(Pt)
        });
        de && z.on(
          "progress",
          Ju(
            z,
            Kt(
              X,
              Ye(Jt(de), !0, 3)
            )
          )
        ), D.push(z);
      }
      let I = R, ce = R.req || w;
      if (t.decompress !== !1 && R.headers["content-encoding"])
        switch ((b === "HEAD" || R.statusCode === 204) && delete R.headers["content-encoding"], (R.headers["content-encoding"] || "").toLowerCase()) {
          /*eslint default-case:0*/
          case "gzip":
          case "x-gzip":
          case "compress":
          case "x-compress":
            D.push(Qe.default.createUnzip(Mu)), delete R.headers["content-encoding"];
            break;
          case "deflate":
            D.push(new Du()), D.push(Qe.default.createUnzip(Mu)), delete R.headers["content-encoding"];
            break;
          case "br":
            $u && (D.push(Qe.default.createBrotliDecompress(Jy)), delete R.headers["content-encoding"]);
        }
      I = D.length > 1 ? Oe.default.pipeline(D, f.noop) : D[0];
      let Re = {
        status: R.statusCode,
        statusText: R.statusMessage,
        headers: new M(R.headers),
        config: t,
        request: ce
      };
      if (m === "stream") {
        if (t.maxContentLength > -1) {
          let z = t.maxContentLength, jt = I;
          async function* pn() {
            let se = 0;
            for await (let wo of jt) {
              if (se += wo.length, se > z)
                throw new S(
                  "maxContentLength size of " + z + " exceeded",
                  S.ERR_BAD_RESPONSE,
                  t,
                  ce
                );
              yield wo;
            }
          }
          I = Oe.default.Readable.from(pn(), {
            objectMode: !1
          });
        }
        Re.data = I, Ve(r, i, Re);
      } else {
        let z = [], jt = 0;
        I.on("data", function(se) {
          z.push(se), jt += se.length, t.maxContentLength > -1 && jt > t.maxContentLength && (h = !0, I.destroy(), q(
            new S(
              "maxContentLength size of " + t.maxContentLength + " exceeded",
              S.ERR_BAD_RESPONSE,
              t,
              ce
            )
          ));
        }), I.on("aborted", function() {
          if (h)
            return;
          let se = new S(
            "stream has been aborted",
            S.ERR_BAD_RESPONSE,
            t,
            ce,
            Re
          );
          I.destroy(se), i(se);
        }), I.on("error", function(se) {
          h || i(S.from(se, null, t, ce, Re));
        }), I.on("end", function() {
          try {
            let se = z.length === 1 ? z[0] : Buffer.concat(z);
            m !== "arraybuffer" && (se = se.toString(x), (!x || x === "utf8") && (se = f.stripBOM(se))), Re.data = se;
          } catch (se) {
            return i(S.from(se, null, t, Re.request, Re));
          }
          Ve(r, i, Re);
        });
      }
      O.once("abort", (z) => {
        I.destroyed || (I.emit("error", z), I.destroy());
      });
    }), O.once("abort", (C) => {
      w.close ? w.close() : w.destroy(C);
    }), w.on("error", function(R) {
      i(S.from(R, null, t, w));
    });
    let mt = /* @__PURE__ */ new Set();
    if (w.on("socket", function(R) {
      R.setKeepAlive(!0, 1e3 * 60), R[Vu] || (R.on("error", function(X) {
        let I = R[Sr];
        I && !I.destroyed && I.destroy(X);
      }), R[Vu] = !0), R[Sr] = w, mt.add(R);
    }), w.once("close", function() {
      W();
      for (let R of mt)
        R[Sr] === w && (R[Sr] = null);
      mt.clear();
    }), t.timeout) {
      let C = parseInt(t.timeout, 10);
      if (Number.isNaN(C)) {
        q(
          new S(
            "error trying to parse `config.timeout` to int",
            S.ERR_BAD_OPTION_VALUE,
            t,
            w
          )
        );
        return;
      }
      let R = function() {
        v || q(ne());
      };
      Ue && C > 0 && (T = setTimeout(R, C)), w.setTimeout(C, R);
    } else
      w.setTimeout(0);
    if (f.isStream(o)) {
      let C = !1, R = !1;
      o.on("end", () => {
        C = !0;
      }), o.once("error", (X) => {
        R = !0, w.destroy(X);
      }), o.on("close", () => {
        !C && !R && q(new Te("Request stream has been aborted", t, w));
      });
      let D = o;
      if (t.maxBodyLength > -1 && t.maxRedirects === 0) {
        let X = t.maxBodyLength, I = 0;
        D = Oe.default.pipeline(
          [
            o,
            new Oe.default.Transform({
              transform(ce, Re, z) {
                if (I += ce.length, I > X)
                  return z(
                    new S(
                      "Request body larger than maxBodyLength limit",
                      S.ERR_BAD_REQUEST,
                      t,
                      w
                    )
                  );
                z(null, ce);
              }
            })
          ],
          f.noop
        ), D.on("error", (ce) => {
          w.destroyed || w.destroy(ce);
        });
      }
      D.pipe(w);
    } else
      o && w.write(o), w.end();
  });
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/xhr.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/resolveConfig.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/isURLSameOrigin.js
c();
var sp = L.hasStandardBrowserEnv ? /* @__PURE__ */ ((e, t) => (n) => (n = new URL(n, L.origin), e.protocol === n.protocol && e.host === n.host && (t || e.port === n.port)))(
  new URL(L.origin),
  L.navigator && /(msie|trident)/i.test(L.navigator.userAgent)
) : () => !0;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/cookies.js
c();
var ap = L.hasStandardBrowserEnv ? (
  // Standard browser envs support document.cookie
  {
    write(e, t, n, r, i, s, a) {
      if (typeof document > "u") return;
      let o = [`${e}=${encodeURIComponent(t)}`];
      f.isNumber(n) && o.push(`expires=${new Date(n).toUTCString()}`), f.isString(r) && o.push(`path=${r}`), f.isString(i) && o.push(`domain=${i}`), s === !0 && o.push("secure"), f.isString(a) && o.push(`SameSite=${a}`), document.cookie = o.join("; ");
    },
    read(e) {
      if (typeof document > "u") return null;
      let t = document.cookie.split(";");
      for (let n = 0; n < t.length; n++) {
        let r = t[n].replace(/^\s+/, ""), i = r.indexOf("=");
        if (i !== -1 && r.slice(0, i) === e)
          return decodeURIComponent(r.slice(i + 1));
      }
      return null;
    },
    remove(e) {
      this.write(e, "", Date.now() - 864e5, "/");
    }
  }
) : (
  // Non-standard browser env (web workers, react-native) lack needed support.
  {
    write() {
    },
    read() {
      return null;
    },
    remove() {
    }
  }
);

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/mergeConfig.js
c();
var op = (e) => e instanceof M ? { ...e } : e;
function Fe(e, t) {
  t = t || {};
  let n = /* @__PURE__ */ Object.create(null);
  Object.defineProperty(n, "hasOwnProperty", {
    // Null-proto descriptor so a polluted Object.prototype.get cannot turn
    // this data descriptor into an accessor descriptor on the way in.
    __proto__: null,
    value: Object.prototype.hasOwnProperty,
    enumerable: !1,
    writable: !0,
    configurable: !0
  });
  function r(p, u, d, m) {
    return f.isPlainObject(p) && f.isPlainObject(u) ? f.merge.call({ caseless: m }, p, u) : f.isPlainObject(u) ? f.merge({}, u) : f.isArray(u) ? u.slice() : u;
  }
  function i(p, u, d, m) {
    if (f.isUndefined(u)) {
      if (!f.isUndefined(p))
        return r(void 0, p, d, m);
    } else return r(p, u, d, m);
  }
  function s(p, u) {
    if (!f.isUndefined(u))
      return r(void 0, u);
  }
  function a(p, u) {
    if (f.isUndefined(u)) {
      if (!f.isUndefined(p))
        return r(void 0, p);
    } else return r(void 0, u);
  }
  function o(p, u, d) {
    if (f.hasOwnProp(t, d))
      return r(p, u);
    if (f.hasOwnProp(e, d))
      return r(void 0, p);
  }
  let l = {
    url: s,
    method: s,
    data: s,
    baseURL: a,
    transformRequest: a,
    transformResponse: a,
    paramsSerializer: a,
    timeout: a,
    timeoutMessage: a,
    withCredentials: a,
    withXSRFToken: a,
    adapter: a,
    responseType: a,
    xsrfCookieName: a,
    xsrfHeaderName: a,
    onUploadProgress: a,
    onDownloadProgress: a,
    decompress: a,
    maxContentLength: a,
    maxBodyLength: a,
    beforeRedirect: a,
    transport: a,
    httpAgent: a,
    httpsAgent: a,
    cancelToken: a,
    socketPath: a,
    allowedSocketPaths: a,
    responseEncoding: a,
    validateStatus: o,
    headers: (p, u, d) => i(op(p), op(u), d, !0)
  };
  return f.forEach(Object.keys({ ...e, ...t }), function(u) {
    if (u === "__proto__" || u === "constructor" || u === "prototype") return;
    let d = f.hasOwnProp(l, u) ? l[u] : i, m = f.hasOwnProp(e, u) ? e[u] : void 0, x = f.hasOwnProp(t, u) ? t[u] : void 0, b = d(m, x, u);
    f.isUndefined(b) && d !== o || (n[u] = b);
  }), n;
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/resolveConfig.js
var cv = ["content-type", "content-length"];
function lv(e, t, n) {
  if (n !== "content-only") {
    e.set(t);
    return;
  }
  Object.entries(t).forEach(([r, i]) => {
    cv.includes(r.toLowerCase()) && e.set(r, i);
  });
}
var uv = (e) => encodeURIComponent(e).replace(
  /%([0-9A-F]{2})/gi,
  (t, n) => String.fromCharCode(parseInt(n, 16))
), Rr = (e) => {
  let t = Fe({}, e), n = (m) => f.hasOwnProp(t, m) ? t[m] : void 0, r = n("data"), i = n("withXSRFToken"), s = n("xsrfHeaderName"), a = n("xsrfCookieName"), o = n("headers"), l = n("auth"), p = n("baseURL"), u = n("allowAbsoluteUrls"), d = n("url");
  if (t.headers = o = M.from(o), t.url = yt(
    vt(p, d, u),
    e.params,
    e.paramsSerializer
  ), l && o.set(
    "Authorization",
    "Basic " + btoa((l.username || "") + ":" + (l.password ? uv(l.password) : ""))
  ), f.isFormData(r) && (L.hasStandardBrowserEnv || L.hasStandardBrowserWebWorkerEnv ? o.setContentType(void 0) : f.isFunction(r.getHeaders) && lv(o, r.getHeaders(), n("formDataHeaderPolicy"))), L.hasStandardBrowserEnv && (f.isFunction(i) && (i = i(t)), i === !0 || i == null && sp(t.url))) {
    let x = s && a && ap.read(a);
    x && o.set(s, x);
  }
  return t;
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/xhr.js
var pv = typeof XMLHttpRequest < "u", cp = pv && function(e) {
  return new Promise(function(n, r) {
    let i = Rr(e), s = i.data, a = M.from(i.headers).normalize(), { responseType: o, onUploadProgress: l, onDownloadProgress: p } = i, u, d, m, x, b;
    function v() {
      x && x(), b && b(), i.cancelToken && i.cancelToken.unsubscribe(u), i.signal && i.signal.removeEventListener("abort", u);
    }
    let h = new XMLHttpRequest();
    h.open(i.method.toUpperCase(), i.url, !0), h.timeout = i.timeout;
    function w() {
      if (!h)
        return;
      let A = M.from(
        "getAllResponseHeaders" in h && h.getAllResponseHeaders()
      ), q = {
        data: !o || o === "text" || o === "json" ? h.responseText : h.response,
        status: h.status,
        statusText: h.statusText,
        headers: A,
        config: e,
        request: h
      };
      Ve(
        function(ne) {
          n(ne), v();
        },
        function(ne) {
          r(ne), v();
        },
        q
      ), h = null;
    }
    "onloadend" in h ? h.onloadend = w : h.onreadystatechange = function() {
      !h || h.readyState !== 4 || h.status === 0 && !(h.responseURL && h.responseURL.startsWith("file:")) || setTimeout(w);
    }, h.onabort = function() {
      h && (r(new S("Request aborted", S.ECONNABORTED, e, h)), v(), h = null);
    }, h.onerror = function(O) {
      let q = O && O.message ? O.message : "Network Error", W = new S(q, S.ERR_NETWORK, e, h);
      W.event = O || null, r(W), v(), h = null;
    }, h.ontimeout = function() {
      let O = i.timeout ? "timeout of " + i.timeout + "ms exceeded" : "timeout exceeded", q = i.transitional || at;
      i.timeoutErrorMessage && (O = i.timeoutErrorMessage), r(
        new S(
          O,
          q.clarifyTimeoutError ? S.ETIMEDOUT : S.ECONNABORTED,
          e,
          h
        )
      ), v(), h = null;
    }, s === void 0 && a.setContentType(null), "setRequestHeader" in h && f.forEach(Dt(a), function(O, q) {
      h.setRequestHeader(q, O);
    }), f.isUndefined(i.withCredentials) || (h.withCredentials = !!i.withCredentials), o && o !== "json" && (h.responseType = i.responseType), p && ([m, b] = Ye(p, !0), h.addEventListener("progress", m)), l && h.upload && ([d, x] = Ye(l), h.upload.addEventListener("progress", d), h.upload.addEventListener("loadend", x)), (i.cancelToken || i.signal) && (u = (A) => {
      h && (r(!A || A.type ? new Te(null, e, h) : A), h.abort(), v(), h = null);
    }, i.cancelToken && i.cancelToken.subscribe(u), i.signal && (i.signal.aborted ? u() : i.signal.addEventListener("abort", u)));
    let T = qn(i.url);
    if (T && !L.protocols.includes(T)) {
      r(
        new S(
          "Unsupported protocol " + T + ":",
          S.ERR_BAD_REQUEST,
          e
        )
      );
      return;
    }
    h.send(s || null);
  });
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/fetch.js
c();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/composeSignals.js
c();
var dv = (e, t) => {
  if (e = e ? e.filter(Boolean) : [], !t && !e.length)
    return;
  let n = new AbortController(), r = !1, i = function(l) {
    if (!r) {
      r = !0, a();
      let p = l instanceof Error ? l : this.reason;
      n.abort(
        p instanceof S ? p : new Te(p instanceof Error ? p.message : p)
      );
    }
  }, s = t && setTimeout(() => {
    s = null, i(new S(`timeout of ${t}ms exceeded`, S.ETIMEDOUT));
  }, t), a = () => {
    e && (s && clearTimeout(s), s = null, e.forEach((l) => {
      l.unsubscribe ? l.unsubscribe(i) : l.removeEventListener("abort", i);
    }), e = null);
  };
  e.forEach((l) => l.addEventListener("abort", i));
  let { signal: o } = n;
  return o.unsubscribe = () => f.asap(a), o;
}, lp = dv;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/trackStream.js
c();
var fv = function* (e, t) {
  let n = e.byteLength;
  if (!t || n < t) {
    yield e;
    return;
  }
  let r = 0, i;
  for (; r < n; )
    i = r + t, yield e.slice(r, i), r = i;
}, mv = async function* (e, t) {
  for await (let n of hv(e))
    yield* fv(n, t);
}, hv = async function* (e) {
  if (e[Symbol.asyncIterator]) {
    yield* e;
    return;
  }
  let t = e.getReader();
  try {
    for (; ; ) {
      let { done: n, value: r } = await t.read();
      if (n)
        break;
      yield r;
    }
  } finally {
    await t.cancel();
  }
}, Fs = (e, t, n, r) => {
  let i = mv(e, t), s = 0, a, o = (l) => {
    a || (a = !0, r && r(l));
  };
  return new ReadableStream(
    {
      async pull(l) {
        try {
          let { done: p, value: u } = await i.next();
          if (p) {
            o(), l.close();
            return;
          }
          let d = u.byteLength;
          if (n) {
            let m = s += d;
            n(m);
          }
          l.enqueue(new Uint8Array(u));
        } catch (p) {
          throw o(p), p;
        }
      },
      cancel(l) {
        return o(l), i.return();
      }
    },
    {
      highWaterMark: 2
    }
  );
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/fetch.js
var up = 64 * 1024, { isFunction: Tr } = f, pp = (e, ...t) => {
  try {
    return !!e(...t);
  } catch {
    return !1;
  }
}, xv = (e) => {
  let t = f.global !== void 0 && f.global !== null ? f.global : globalThis, { ReadableStream: n, TextEncoder: r } = t;
  e = f.merge.call(
    {
      skipUndefined: !0
    },
    {
      Request: t.Request,
      Response: t.Response
    },
    e
  );
  let { fetch: i, Request: s, Response: a } = e, o = i ? Tr(i) : typeof fetch == "function", l = Tr(s), p = Tr(a);
  if (!o)
    return !1;
  let u = o && Tr(n), d = o && (typeof r == "function" ? /* @__PURE__ */ ((w) => (T) => w.encode(T))(new r()) : async (w) => new Uint8Array(await new s(w).arrayBuffer())), m = l && u && pp(() => {
    let w = !1, T = new s(L.origin, {
      body: new n(),
      method: "POST",
      get duplex() {
        return w = !0, "half";
      }
    }), A = T.headers.has("Content-Type");
    return T.body != null && T.body.cancel(), w && !A;
  }), x = p && u && pp(() => f.isReadableStream(new a("").body)), b = {
    stream: x && ((w) => w.body)
  };
  o && ["text", "arrayBuffer", "blob", "formData", "stream"].forEach((w) => {
    !b[w] && (b[w] = (T, A) => {
      let O = T && T[w];
      if (O)
        return O.call(T);
      throw new S(
        `Response type '${w}' is not supported`,
        S.ERR_NOT_SUPPORT,
        A
      );
    });
  });
  let v = async (w) => {
    if (w == null)
      return 0;
    if (f.isBlob(w))
      return w.size;
    if (f.isSpecCompliantForm(w))
      return (await new s(L.origin, {
        method: "POST",
        body: w
      }).arrayBuffer()).byteLength;
    if (f.isArrayBufferView(w) || f.isArrayBuffer(w))
      return w.byteLength;
    if (f.isURLSearchParams(w) && (w = w + ""), f.isString(w))
      return (await d(w)).byteLength;
  }, h = async (w, T) => {
    let A = f.toFiniteNumber(w.getContentLength());
    return A ?? v(T);
  };
  return async (w) => {
    let {
      url: T,
      method: A,
      data: O,
      signal: q,
      cancelToken: W,
      timeout: ne,
      onDownloadProgress: re,
      onUploadProgress: Ce,
      responseType: H,
      headers: pe,
      withCredentials: Q = "same-origin",
      fetchOptions: rt,
      maxContentLength: de,
      maxBodyLength: Me
    } = Rr(w), Ae = f.isNumber(de) && de > -1, Pt = f.isNumber(Me) && Me > -1, Qn = i || fetch;
    H = H ? (H + "").toLowerCase() : "text";
    let ge = lp(
      [q, W && W.toAbortSignal()],
      ne
    ), fe = null, $e = ge && ge.unsubscribe && (() => {
      ge.unsubscribe();
    }), ie;
    try {
      if (Ae && typeof T == "string" && T.startsWith("data:") && Un(T) > de)
        throw new S(
          "maxContentLength size of " + de + " exceeded",
          S.ERR_BAD_RESPONSE,
          w,
          fe
        );
      if (Pt && A !== "get" && A !== "head") {
        let R = await h(pe, O);
        if (typeof R == "number" && isFinite(R) && R > Me)
          throw new S(
            "Request body larger than maxBodyLength limit",
            S.ERR_BAD_REQUEST,
            w,
            fe
          );
      }
      if (Ce && m && A !== "get" && A !== "head" && (ie = await h(pe, O)) !== 0) {
        let R = new s(T, {
          method: "POST",
          body: O,
          duplex: "half"
        }), D;
        if (f.isFormData(O) && (D = R.headers.get("content-type")) && pe.setContentType(D), R.body) {
          let [X, I] = Kt(
            ie,
            Ye(Jt(Ce))
          );
          O = Fs(R.body, up, X, I);
        }
      }
      f.isString(Q) || (Q = Q ? "include" : "omit");
      let G = l && "credentials" in s.prototype;
      if (f.isFormData(O)) {
        let R = pe.getContentType();
        R && /^multipart\/form-data/i.test(R) && !/boundary=/i.test(R) && pe.delete("content-type");
      }
      pe.set("User-Agent", "axios/" + Je, !1);
      let Ue = {
        ...rt,
        signal: ge,
        method: A.toUpperCase(),
        headers: Dt(pe.normalize()),
        body: O,
        duplex: "half",
        credentials: G ? Q : void 0
      };
      fe = l && new s(T, Ue);
      let ye = await (l ? Qn(fe, rt) : Qn(T, Ue));
      if (Ae) {
        let R = f.toFiniteNumber(ye.headers.get("content-length"));
        if (R != null && R > de)
          throw new S(
            "maxContentLength size of " + de + " exceeded",
            S.ERR_BAD_RESPONSE,
            w,
            fe
          );
      }
      let mt = x && (H === "stream" || H === "response");
      if (x && ye.body && (re || Ae || mt && $e)) {
        let R = {};
        ["status", "statusText", "headers"].forEach((z) => {
          R[z] = ye[z];
        });
        let D = f.toFiniteNumber(ye.headers.get("content-length")), [X, I] = re && Kt(
          D,
          Ye(Jt(re), !0)
        ) || [], ce = 0, Re = (z) => {
          if (Ae && (ce = z, ce > de))
            throw new S(
              "maxContentLength size of " + de + " exceeded",
              S.ERR_BAD_RESPONSE,
              w,
              fe
            );
          X && X(z);
        };
        ye = new a(
          Fs(ye.body, up, Re, () => {
            I && I(), $e && $e();
          }),
          R
        );
      }
      H = H || "text";
      let C = await b[f.findKey(b, H) || "text"](
        ye,
        w
      );
      if (Ae && !x && !mt) {
        let R;
        if (C != null && (typeof C.byteLength == "number" ? R = C.byteLength : typeof C.size == "number" ? R = C.size : typeof C == "string" && (R = typeof r == "function" ? new r().encode(C).byteLength : C.length)), typeof R == "number" && R > de)
          throw new S(
            "maxContentLength size of " + de + " exceeded",
            S.ERR_BAD_RESPONSE,
            w,
            fe
          );
      }
      return !mt && $e && $e(), await new Promise((R, D) => {
        Ve(R, D, {
          data: C,
          headers: M.from(ye.headers),
          status: ye.status,
          statusText: ye.statusText,
          config: w,
          request: fe
        });
      });
    } catch (G) {
      if ($e && $e(), ge && ge.aborted && ge.reason instanceof S) {
        let Ue = ge.reason;
        throw Ue.config = w, fe && (Ue.request = fe), G !== Ue && (Ue.cause = G), Ue;
      }
      throw G && G.name === "TypeError" && /Load failed|fetch/i.test(G.message) ? Object.assign(
        new S(
          "Network Error",
          S.ERR_NETWORK,
          w,
          fe,
          G && G.response
        ),
        {
          cause: G.cause || G
        }
      ) : S.from(G, G && G.code, w, fe, G && G.response);
    }
  };
}, gv = /* @__PURE__ */ new Map(), Ns = (e) => {
  let t = e && e.env || {}, { fetch: n, Request: r, Response: i } = t, s = [r, i, n], a = s.length, o = a, l, p, u = gv;
  for (; o--; )
    l = s[o], p = u.get(l), p === void 0 && u.set(l, p = o ? /* @__PURE__ */ new Map() : xv(t)), u = p;
  return p;
}, NC = Ns();

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/adapters/adapters.js
var Bs = {
  http: ip,
  xhr: cp,
  fetch: {
    get: Ns
  }
};
f.forEach(Bs, (e, t) => {
  if (e) {
    try {
      Object.defineProperty(e, "name", { __proto__: null, value: t });
    } catch {
    }
    Object.defineProperty(e, "adapterName", { __proto__: null, value: t });
  }
});
var dp = (e) => `- ${e}`, vv = (e) => f.isFunction(e) || e === null || e === !1;
function bv(e, t) {
  e = f.isArray(e) ? e : [e];
  let { length: n } = e, r, i, s = {};
  for (let a = 0; a < n; a++) {
    r = e[a];
    let o;
    if (i = r, !vv(r) && (i = Bs[(o = String(r)).toLowerCase()], i === void 0))
      throw new S(`Unknown adapter '${o}'`);
    if (i && (f.isFunction(i) || (i = i.get(t))))
      break;
    s[o || "#" + a] = i;
  }
  if (!i) {
    let a = Object.entries(s).map(
      ([l, p]) => `adapter ${l} ` + (p === !1 ? "is not supported by the environment" : "is not available in the build")
    ), o = n ? a.length > 1 ? `since :
` + a.map(dp).join(`
`) : " " + dp(a[0]) : "as no adapter specified";
    throw new S(
      "There is no suitable adapter to dispatch the request " + o,
      "ERR_NOT_SUPPORT"
    );
  }
  return i;
}
var kr = {
  /**
   * Resolve an adapter from a list of adapter names or functions.
   * @type {Function}
   */
  getAdapter: bv,
  /**
   * Exposes all known adapters
   * @type {Object<string, Function|Object>}
   */
  adapters: Bs
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/dispatchRequest.js
function zs(e) {
  if (e.cancelToken && e.cancelToken.throwIfRequested(), e.signal && e.signal.aborted)
    throw new Te(null, e);
}
function Cr(e) {
  return zs(e), e.headers = M.from(e.headers), e.data = _n.call(e, e.transformRequest), ["post", "put", "patch"].indexOf(e.method) !== -1 && e.headers.setContentType("application/x-www-form-urlencoded", !1), kr.getAdapter(e.adapter || Mt.adapter, e)(e).then(
    function(r) {
      zs(e), e.response = r;
      try {
        r.data = _n.call(e, e.transformResponse, r);
      } finally {
        delete e.response;
      }
      return r.headers = M.from(r.headers), r;
    },
    function(r) {
      if (!En(r) && (zs(e), r && r.response)) {
        e.response = r.response;
        try {
          r.response.data = _n.call(
            e,
            e.transformResponse,
            r.response
          );
        } finally {
          delete e.response;
        }
        r.response.headers = M.from(r.response.headers);
      }
      return Promise.reject(r);
    }
  );
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/validator.js
c();
var Ar = {};
["object", "boolean", "number", "function", "string", "symbol"].forEach((e, t) => {
  Ar[e] = function(r) {
    return typeof r === e || "a" + (t < 1 ? "n " : " ") + e;
  };
});
var fp = {};
Ar.transitional = function(t, n, r) {
  function i(s, a) {
    return "[Axios v" + Je + "] Transitional option '" + s + "'" + a + (r ? ". " + r : "");
  }
  return (s, a, o) => {
    if (t === !1)
      throw new S(
        i(a, " has been removed" + (n ? " in " + n : "")),
        S.ERR_DEPRECATED
      );
    return n && !fp[a] && (fp[a] = !0, console.warn(
      i(
        a,
        " has been deprecated since v" + n + " and will be removed in the near future"
      )
    )), t ? t(s, a, o) : !0;
  };
};
Ar.spelling = function(t) {
  return (n, r) => (console.warn(`${r} is likely a misspelling of ${t}`), !0);
};
function wv(e, t, n) {
  if (typeof e != "object")
    throw new S("options must be an object", S.ERR_BAD_OPTION_VALUE);
  let r = Object.keys(e), i = r.length;
  for (; i-- > 0; ) {
    let s = r[i], a = Object.prototype.hasOwnProperty.call(t, s) ? t[s] : void 0;
    if (a) {
      let o = e[s], l = o === void 0 || a(o, s, e);
      if (l !== !0)
        throw new S(
          "option " + s + " must be " + l,
          S.ERR_BAD_OPTION_VALUE
        );
      continue;
    }
    if (n !== !0)
      throw new S("Unknown option " + s, S.ERR_BAD_OPTION);
  }
}
var Dn = {
  assertOptions: wv,
  validators: Ar
};

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/core/Axios.js
var Pe = Dn.validators, Yt = class {
  constructor(t) {
    this.defaults = t || {}, this.interceptors = {
      request: new Ki(),
      response: new Ki()
    };
  }
  /**
   * Dispatch a request
   *
   * @param {String|Object} configOrUrl The config specific for this request (merged with this.defaults)
   * @param {?Object} config
   *
   * @returns {Promise} The Promise to be fulfilled
   */
  async request(t, n) {
    try {
      return await this._request(t, n);
    } catch (r) {
      if (r instanceof Error) {
        let i = {};
        Error.captureStackTrace ? Error.captureStackTrace(i) : i = new Error();
        let s = (() => {
          if (!i.stack)
            return "";
          let a = i.stack.indexOf(`
`);
          return a === -1 ? "" : i.stack.slice(a + 1);
        })();
        try {
          if (!r.stack)
            r.stack = s;
          else if (s) {
            let a = s.indexOf(`
`), o = a === -1 ? -1 : s.indexOf(`
`, a + 1), l = o === -1 ? "" : s.slice(o + 1);
            String(r.stack).endsWith(l) || (r.stack += `
` + s);
          }
        } catch {
        }
      }
      throw r;
    }
  }
  _request(t, n) {
    typeof t == "string" ? (n = n || {}, n.url = t) : n = t || {}, n = Fe(this.defaults, n);
    let { transitional: r, paramsSerializer: i, headers: s } = n;
    r !== void 0 && Dn.assertOptions(
      r,
      {
        silentJSONParsing: Pe.transitional(Pe.boolean),
        forcedJSONParsing: Pe.transitional(Pe.boolean),
        clarifyTimeoutError: Pe.transitional(Pe.boolean),
        legacyInterceptorReqResOrdering: Pe.transitional(Pe.boolean)
      },
      !1
    ), i != null && (f.isFunction(i) ? n.paramsSerializer = {
      serialize: i
    } : Dn.assertOptions(
      i,
      {
        encode: Pe.function,
        serialize: Pe.function
      },
      !0
    )), n.allowAbsoluteUrls !== void 0 || (this.defaults.allowAbsoluteUrls !== void 0 ? n.allowAbsoluteUrls = this.defaults.allowAbsoluteUrls : n.allowAbsoluteUrls = !0), Dn.assertOptions(
      n,
      {
        baseUrl: Pe.spelling("baseURL"),
        withXsrfToken: Pe.spelling("withXSRFToken")
      },
      !0
    ), n.method = (n.method || this.defaults.method || "get").toLowerCase();
    let a = s && f.merge(s.common, s[n.method]);
    s && f.forEach(["delete", "get", "head", "post", "put", "patch", "query", "common"], (b) => {
      delete s[b];
    }), n.headers = M.concat(a, s);
    let o = [], l = !0;
    this.interceptors.request.forEach(function(v) {
      if (typeof v.runWhen == "function" && v.runWhen(n) === !1)
        return;
      l = l && v.synchronous;
      let h = n.transitional || at;
      h && h.legacyInterceptorReqResOrdering ? o.unshift(v.fulfilled, v.rejected) : o.push(v.fulfilled, v.rejected);
    });
    let p = [];
    this.interceptors.response.forEach(function(v) {
      p.push(v.fulfilled, v.rejected);
    });
    let u, d = 0, m;
    if (!l) {
      let b = [Cr.bind(this), void 0];
      for (b.unshift(...o), b.push(...p), m = b.length, u = Promise.resolve(n); d < m; )
        u = u.then(b[d++], b[d++]);
      return u;
    }
    m = o.length;
    let x = n;
    for (; d < m; ) {
      let b = o[d++], v = o[d++];
      try {
        x = b(x);
      } catch (h) {
        v.call(this, h);
        break;
      }
    }
    try {
      u = Cr.call(this, x);
    } catch (b) {
      return Promise.reject(b);
    }
    for (d = 0, m = p.length; d < m; )
      u = u.then(p[d++], p[d++]);
    return u;
  }
  getUri(t) {
    t = Fe(this.defaults, t);
    let n = vt(t.baseURL, t.url, t.allowAbsoluteUrls);
    return yt(n, t.params, t.paramsSerializer);
  }
};
f.forEach(["delete", "get", "head", "options"], function(t) {
  Yt.prototype[t] = function(n, r) {
    return this.request(
      Fe(r || {}, {
        method: t,
        url: n,
        data: (r || {}).data
      })
    );
  };
});
f.forEach(["post", "put", "patch", "query"], function(t) {
  function n(r) {
    return function(s, a, o) {
      return this.request(
        Fe(o || {}, {
          method: t,
          headers: r ? {
            "Content-Type": "multipart/form-data"
          } : {},
          url: s,
          data: a
        })
      );
    };
  }
  Yt.prototype[t] = n(), t !== "query" && (Yt.prototype[t + "Form"] = n(!0));
});
var In = Yt;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/cancel/CancelToken.js
c();
var Hs = class e {
  constructor(t) {
    if (typeof t != "function")
      throw new TypeError("executor must be a function.");
    let n;
    this.promise = new Promise(function(s) {
      n = s;
    });
    let r = this;
    this.promise.then((i) => {
      if (!r._listeners) return;
      let s = r._listeners.length;
      for (; s-- > 0; )
        r._listeners[s](i);
      r._listeners = null;
    }), this.promise.then = (i) => {
      let s, a = new Promise((o) => {
        r.subscribe(o), s = o;
      }).then(i);
      return a.cancel = function() {
        r.unsubscribe(s);
      }, a;
    }, t(function(s, a, o) {
      r.reason || (r.reason = new Te(s, a, o), n(r.reason));
    });
  }
  /**
   * Throws a `CanceledError` if cancellation has been requested.
   */
  throwIfRequested() {
    if (this.reason)
      throw this.reason;
  }
  /**
   * Subscribe to the cancel signal
   */
  subscribe(t) {
    if (this.reason) {
      t(this.reason);
      return;
    }
    this._listeners ? this._listeners.push(t) : this._listeners = [t];
  }
  /**
   * Unsubscribe from the cancel signal
   */
  unsubscribe(t) {
    if (!this._listeners)
      return;
    let n = this._listeners.indexOf(t);
    n !== -1 && this._listeners.splice(n, 1);
  }
  toAbortSignal() {
    let t = new AbortController(), n = (r) => {
      t.abort(r);
    };
    return this.subscribe(n), t.signal.unsubscribe = () => this.unsubscribe(n), t.signal;
  }
  /**
   * Returns an object that contains a new `CancelToken` and a function that, when called,
   * cancels the `CancelToken`.
   */
  static source() {
    let t;
    return {
      token: new e(function(i) {
        t = i;
      }),
      cancel: t
    };
  }
}, mp = Hs;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/spread.js
c();
function Ms(e) {
  return function(n) {
    return e.apply(null, n);
  };
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/isAxiosError.js
c();
function $s(e) {
  return f.isObject(e) && e.isAxiosError === !0;
}

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/helpers/HttpStatusCode.js
c();
var Vs = {
  Continue: 100,
  SwitchingProtocols: 101,
  Processing: 102,
  EarlyHints: 103,
  Ok: 200,
  Created: 201,
  Accepted: 202,
  NonAuthoritativeInformation: 203,
  NoContent: 204,
  ResetContent: 205,
  PartialContent: 206,
  MultiStatus: 207,
  AlreadyReported: 208,
  ImUsed: 226,
  MultipleChoices: 300,
  MovedPermanently: 301,
  Found: 302,
  SeeOther: 303,
  NotModified: 304,
  UseProxy: 305,
  Unused: 306,
  TemporaryRedirect: 307,
  PermanentRedirect: 308,
  BadRequest: 400,
  Unauthorized: 401,
  PaymentRequired: 402,
  Forbidden: 403,
  NotFound: 404,
  MethodNotAllowed: 405,
  NotAcceptable: 406,
  ProxyAuthenticationRequired: 407,
  RequestTimeout: 408,
  Conflict: 409,
  Gone: 410,
  LengthRequired: 411,
  PreconditionFailed: 412,
  PayloadTooLarge: 413,
  UriTooLong: 414,
  UnsupportedMediaType: 415,
  RangeNotSatisfiable: 416,
  ExpectationFailed: 417,
  ImATeapot: 418,
  MisdirectedRequest: 421,
  UnprocessableEntity: 422,
  Locked: 423,
  FailedDependency: 424,
  TooEarly: 425,
  UpgradeRequired: 426,
  PreconditionRequired: 428,
  TooManyRequests: 429,
  RequestHeaderFieldsTooLarge: 431,
  UnavailableForLegalReasons: 451,
  InternalServerError: 500,
  NotImplemented: 501,
  BadGateway: 502,
  ServiceUnavailable: 503,
  GatewayTimeout: 504,
  HttpVersionNotSupported: 505,
  VariantAlsoNegotiates: 506,
  InsufficientStorage: 507,
  LoopDetected: 508,
  NotExtended: 510,
  NetworkAuthenticationRequired: 511,
  WebServerIsDown: 521,
  ConnectionTimedOut: 522,
  OriginIsUnreachable: 523,
  TimeoutOccurred: 524,
  SslHandshakeFailed: 525,
  InvalidSslCertificate: 526
};
Object.entries(Vs).forEach(([e, t]) => {
  Vs[t] = e;
});
var hp = Vs;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/lib/axios.js
function xp(e) {
  let t = new In(e), n = fn(In.prototype.request, t);
  return f.extend(n, In.prototype, t, { allOwnKeys: !0 }), f.extend(n, t, null, { allOwnKeys: !0 }), n.create = function(i) {
    return xp(Fe(e, i));
  }, n;
}
var Z = xp(Mt);
Z.Axios = In;
Z.CanceledError = Te;
Z.CancelToken = mp;
Z.isCancel = En;
Z.VERSION = Je;
Z.toFormData = st;
Z.AxiosError = S;
Z.Cancel = Z.CanceledError;
Z.all = function(t) {
  return Promise.all(t);
};
Z.spread = Ms;
Z.isAxiosError = $s;
Z.mergeConfig = Fe;
Z.AxiosHeaders = M;
Z.formToJSON = (e) => gr(f.isHTMLForm(e) ? new FormData(e) : e);
Z.getAdapter = kr.getAdapter;
Z.HttpStatusCode = hp;
Z.default = Z;
var Or = Z;

// node_modules/.pnpm/axios@1.16.1/node_modules/axios/index.js
var {
  Axios: WA,
  AxiosError: GA,
  CanceledError: KA,
  isCancel: JA,
  CancelToken: YA,
  VERSION: QA,
  all: XA,
  Cancel: ZA,
  isAxiosError: eO,
  spread: tO,
  toFormData: nO,
  AxiosHeaders: rO,
  HttpStatusCode: iO,
  formToJSON: sO,
  getAdapter: aO,
  mergeConfig: oO,
  create: cO
} = Or;

// src/tg.ts
var Pr = class {
  token;
  chat_id;
  max_try = 3;
  timeout = 5e3;
  base_url;
  constructor(t, n, r = 3, i = 5e3) {
    this.token = t, this.chat_id = n, this.max_try = r, this.timeout = i, this.base_url = `https://api.telegram.org/bot${this.token}/`;
  }
  async post(t, n) {
    let r = this.base_url + t, i = Or.create({
      baseURL: r,
      timeout: this.timeout
    });
    for (let s = 0; s < this.max_try; s++)
      try {
        return { ok: !0, result: (await i.post("", n)).data };
      } catch (a) {
        if (s === this.max_try)
          return console.log(`Telegram API 请求失败,${a}`), { ok: !1, error: a };
        console.log(`${a}
Telegram API 请求失败，正在第 ${s + 1} 次重试...`), await new Promise((o) => setTimeout(o, 1e3));
      }
    return { ok: !1, error: "Telegram API 请求失败" };
  }
  async text(t, n) {
    let r = {
      chat_id: this.chat_id,
      text: t
    };
    return n && (r.parse_mode = n), this.post("sendMessage", r);
  }
  async md(t) {
    return this.text(t, "Markdown");
  }
};

// src/ecloud.ts
c();
var um = he(lm(), 1), yi = class {
  username;
  password;
  client;
  constructor(t, n) {
    this.username = t, this.password = n, this.client = new um.CloudClient({ username: t, password: n });
  }
  async userSign() {
    return await this.client.userSign();
  }
  async info() {
    return await this.client.getUserSizeInfo();
  }
};

// src/index.ts
async function yE(e, t) {
  var i;
  let n = "", r = !1;
  try {
    let [s, a] = e;
    if (!s || !a) throw new Error("Missing Account Or Password");
    if (!new RegExp(/^(?:(?:\+|00)86)?1\d{10}$/).test(s)) throw new Error("Invalid Account");
    let o = new yi(s, a), l = await o.userSign(), p = await o.info(), u = {
      index: t + 1,
      isSign: l.isSign,
      bonus: l.netdiskBonus,
      id: (i = p.account.split("@")[0]) == null ? void 0 : i.replace(/\*/g, "\\*"),
      total: p.cloudCapacityInfo.totalSize
    };
    n = `🙍🏻‍♂️ 第${u.index}个账号 ${u.id}
${u.isSign ? "✅" : "☑️"} 已签到，获得 ${u.bonus}M 空间
🍺 总共 ${vE(u.total)} 容量`;
  } catch (s) {
    n = `❌ 第${t + 1}个账号 出错
⁉️ ${s}`, r = !0;
  } finally {
    return console.log(n), [n, r];
  }
}
function vE(e) {
  return e > 1024 * 1024 * 1024 * 1024 ? (e / (1024 * 1024 * 1024 * 1024)).toFixed(2) + "TB" : e > 1024 * 1024 * 1024 ? (e / (1024 * 1024 * 1024)).toFixed(2) + "GB" : e > 1024 * 1024 ? (e / 1024 * 1024).toFixed(2) + "MB" : e + "KB";
}
async function bE(e) {
  let t = 0, n = [], r = !1, i = e.replace("；", ";").replace("&&", `
`).split(`
`).map((s) => s.split(";"));
  if (t = i.length, t == 0)
    return {
      len: t,
      msg: n,
      err: r
    };
  for (let s = 0; s < t; s++) {
    let a = await yE(i[s], s);
    n.push(a[0]), a[1] && (r = !0);
  }
  return {
    len: t,
    msg: n,
    err: r
  };
}
function wE(e, t) {
  let n = (/* @__PURE__ */ new Date()).toLocaleString("zh-CN", { hour12: !1, timeZone: "Asia/Shanghai" });
  return `
#ecloud *天翼云盘自动签到*

${e.join(`
`)}

📅 *时间*：${n}
`;
}
async function _E(e, t) {
  if (Zn) {
    let n = wE(e, t);
    console.log(n);
    let r = {};
    if (Zn)
      try {
        let i = Zn.replace("；", ";").split(";").filter(Boolean);
        if (i.length != 2 || !i[0] || !i[1]) throw new Error("Invalid TG config");
        await new Pr(i[0], i[1]).md(n).then((a) => {
          a.error && (r.tg = a.error);
        });
      } catch (i) {
        r.tg = i;
      }
    return r;
  }
  return {};
}
async function EE() {
  let e = {};
  if (!wi) throw new Error("No accounts provided");
  let t = await bE(wi).then((n) => (n.err && (e.main = !0), n));
  if (await _E(t.msg, t.len).then((n) => Object.assign(e, n)), Object.keys(e).length && (console.log(Object.entries(e).join(`
`)), jo))
    throw new Error("Some Error Occured");
}
(async () => await EE())();
/*! Bundled license information:

mime-db/index.js:
  (*!
   * mime-db
   * Copyright(c) 2014 Jonathan Ong
   * Copyright(c) 2015-2022 Douglas Christopher Wilson
   * MIT Licensed
   *)

mime-types/index.js:
  (*!
   * mime-types
   * Copyright(c) 2014 Jonathan Ong
   * Copyright(c) 2015 Douglas Christopher Wilson
   * MIT Licensed
   *)
*/
