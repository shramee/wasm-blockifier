var Xs = Object.defineProperty;
var Js = (e, a, t) => a in e ? Xs(e, a, { enumerable: !0, configurable: !0, writable: !0, value: t }) : e[a] = t;
var ct = (e, a, t) => (Js(e, typeof a != "symbol" ? a + "" : a, t), t);
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const jf = BigInt(0), ln = BigInt(1), Qs = BigInt(2), un = (e) => e instanceof Uint8Array, eo = Array.from({ length: 256 }, (e, a) => a.toString(16).padStart(2, "0"));
function Je(e) {
  if (!un(e))
    throw new Error("Uint8Array expected");
  let a = "";
  for (let t = 0; t < e.length; t++)
    a += eo[e[t]];
  return a;
}
function qf(e) {
  const a = e.toString(16);
  return a.length & 1 ? `0${a}` : a;
}
function hn(e) {
  if (typeof e != "string")
    throw new Error("hex string expected, got " + typeof e);
  return BigInt(e === "" ? "0" : `0x${e}`);
}
function He(e) {
  if (typeof e != "string")
    throw new Error("hex string expected, got " + typeof e);
  if (e.length % 2)
    throw new Error("hex string is invalid: unpadded " + e.length);
  const a = new Uint8Array(e.length / 2);
  for (let t = 0; t < a.length; t++) {
    const n = t * 2, c = e.slice(n, n + 2), r = Number.parseInt(c, 16);
    if (Number.isNaN(r) || r < 0)
      throw new Error("invalid byte sequence");
    a[t] = r;
  }
  return a;
}
function ie(e) {
  return hn(Je(e));
}
function Sc(e) {
  if (!un(e))
    throw new Error("Uint8Array expected");
  return hn(Je(Uint8Array.from(e).reverse()));
}
const $t = (e, a) => He(e.toString(16).padStart(a * 2, "0")), Kf = (e, a) => $t(e, a).reverse(), kc = (e) => He(qf(e));
function be(e, a, t) {
  let n;
  if (typeof a == "string")
    try {
      n = He(a);
    } catch (r) {
      throw new Error(`${e} must be valid hex string, got "${a}". Cause: ${r}`);
    }
  else if (un(a))
    n = Uint8Array.from(a);
  else
    throw new Error(`${e} must be hex string or Uint8Array`);
  const c = n.length;
  if (typeof t == "number" && c !== t)
    throw new Error(`${e} expected ${t} bytes, got ${c}`);
  return n;
}
function zt(...e) {
  const a = new Uint8Array(e.reduce((n, c) => n + c.length, 0));
  let t = 0;
  return e.forEach((n) => {
    if (!un(n))
      throw new Error("Uint8Array expected");
    a.set(n, t), t += n.length;
  }), a;
}
function to(e, a) {
  if (e.length !== a.length)
    return !1;
  for (let t = 0; t < e.length; t++)
    if (e[t] !== a[t])
      return !1;
  return !0;
}
function ao(e) {
  if (typeof e != "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof e}`);
  return new TextEncoder().encode(e);
}
function no(e) {
  let a;
  for (a = 0; e > jf; e >>= ln, a += 1)
    ;
  return a;
}
const co = (e, a) => e >> BigInt(a) & ln, ro = (e, a, t) => e | (t ? ln : jf) << BigInt(a), pn = (e) => (Qs << BigInt(e - 1)) - ln, Nn = (e) => new Uint8Array(e), Dr = (e) => Uint8Array.from(e);
function Gf(e, a, t) {
  if (typeof e != "number" || e < 2)
    throw new Error("hashLen must be a number");
  if (typeof a != "number" || a < 2)
    throw new Error("qByteLen must be a number");
  if (typeof t != "function")
    throw new Error("hmacFn must be a function");
  let n = Nn(e), c = Nn(e), r = 0;
  const f = () => {
    n.fill(1), c.fill(0), r = 0;
  }, d = (...b) => t(c, n, ...b), o = (b = Nn()) => {
    c = d(Dr([0]), b), n = d(), b.length !== 0 && (c = d(Dr([1]), b), n = d());
  }, i = () => {
    if (r++ >= 1e3)
      throw new Error("drbg: tried 1000 values");
    let b = 0;
    const u = [];
    for (; b < a; ) {
      n = d();
      const l = n.slice();
      u.push(l), b += n.length;
    }
    return zt(...u);
  };
  return (b, u) => {
    f(), o(b);
    let l;
    for (; !(l = u(i())); )
      o();
    return f(), l;
  };
}
const fo = {
  bigint: (e) => typeof e == "bigint",
  function: (e) => typeof e == "function",
  boolean: (e) => typeof e == "boolean",
  string: (e) => typeof e == "string",
  isSafeInteger: (e) => Number.isSafeInteger(e),
  array: (e) => Array.isArray(e),
  field: (e, a) => a.Fp.isValid(e),
  hash: (e) => typeof e == "function" && Number.isSafeInteger(e.outputLen)
};
function xa(e, a, t = {}) {
  const n = (c, r, f) => {
    const d = fo[r];
    if (typeof d != "function")
      throw new Error(`Invalid validator "${r}", expected function`);
    const o = e[c];
    if (!(f && o === void 0) && !d(o, e))
      throw new Error(`Invalid param ${String(c)}=${o} (${typeof o}), expected ${r}`);
  };
  for (const [c, r] of Object.entries(a))
    n(c, r, !1);
  for (const [c, r] of Object.entries(t))
    n(c, r, !0);
  return e;
}
const io = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  bitGet: co,
  bitLen: no,
  bitMask: pn,
  bitSet: ro,
  bytesToHex: Je,
  bytesToNumberBE: ie,
  bytesToNumberLE: Sc,
  concatBytes: zt,
  createHmacDrbg: Gf,
  ensureBytes: be,
  equalBytes: to,
  hexToBytes: He,
  hexToNumber: hn,
  numberToBytesBE: $t,
  numberToBytesLE: Kf,
  numberToHexUnpadded: qf,
  numberToVarBytesBE: kc,
  utf8ToBytes: ao,
  validateObject: xa
}, Symbol.toStringTag, { value: "Module" }));
function Lr(e) {
  if (!Number.isSafeInteger(e) || e < 0)
    throw new Error(`Wrong positive integer: ${e}`);
}
function Yf(e, ...a) {
  if (!(e instanceof Uint8Array))
    throw new Error("Expected Uint8Array");
  if (a.length > 0 && !a.includes(e.length))
    throw new Error(`Expected Uint8Array of length ${a}, not of length=${e.length}`);
}
function Ja(e, a = !0) {
  if (e.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (a && e.finished)
    throw new Error("Hash#digest() has already been called");
}
function Wf(e, a) {
  Yf(e);
  const t = a.outputLen;
  if (e.length < t)
    throw new Error(`digestInto() expects output buffer of length at least ${t}`);
}
const $a = /* @__PURE__ */ BigInt(2 ** 32 - 1), $r = /* @__PURE__ */ BigInt(32);
function so(e, a = !1) {
  return a ? { h: Number(e & $a), l: Number(e >> $r & $a) } : { h: Number(e >> $r & $a) | 0, l: Number(e & $a) | 0 };
}
function oo(e, a = !1) {
  let t = new Uint32Array(e.length), n = new Uint32Array(e.length);
  for (let c = 0; c < e.length; c++) {
    const { h: r, l: f } = so(e[c], a);
    [t[c], n[c]] = [r, f];
  }
  return [t, n];
}
const bo = (e, a, t) => e << t | a >>> 32 - t, lo = (e, a, t) => a << t | e >>> 32 - t, uo = (e, a, t) => a << t - 32 | e >>> 64 - t, ho = (e, a, t) => e << t - 32 | a >>> 64 - t;
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const po = (e) => e instanceof Uint8Array, _o = (e) => new Uint32Array(e.buffer, e.byteOffset, Math.floor(e.byteLength / 4)), On = (e) => new DataView(e.buffer, e.byteOffset, e.byteLength), ve = (e, a) => e << 32 - a | e >>> a, go = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
if (!go)
  throw new Error("Non little-endian hardware is not supported");
function Xf(e) {
  if (typeof e != "string")
    throw new Error(`utf8ToBytes expected string, got ${typeof e}`);
  return new Uint8Array(new TextEncoder().encode(e));
}
function Tc(e) {
  if (typeof e == "string" && (e = Xf(e)), !po(e))
    throw new Error(`expected Uint8Array, got ${typeof e}`);
  return e;
}
let Jf = class {
  // Safe version that clones internal state
  clone() {
    return this._cloneInto();
  }
};
function Qf(e) {
  const a = (n) => e().update(Tc(n)).digest(), t = e();
  return a.outputLen = t.outputLen, a.blockLen = t.blockLen, a.create = () => e(), a;
}
const [ed, td, ad] = [[], [], []], yo = /* @__PURE__ */ BigInt(0), ta = /* @__PURE__ */ BigInt(1), wo = /* @__PURE__ */ BigInt(2), mo = /* @__PURE__ */ BigInt(7), Eo = /* @__PURE__ */ BigInt(256), vo = /* @__PURE__ */ BigInt(113);
for (let e = 0, a = ta, t = 1, n = 0; e < 24; e++) {
  [t, n] = [n, (2 * t + 3 * n) % 5], ed.push(2 * (5 * n + t)), td.push((e + 1) * (e + 2) / 2 % 64);
  let c = yo;
  for (let r = 0; r < 7; r++)
    a = (a << ta ^ (a >> mo) * vo) % Eo, a & wo && (c ^= ta << (ta << /* @__PURE__ */ BigInt(r)) - ta);
  ad.push(c);
}
const [xo, Ao] = /* @__PURE__ */ oo(ad, !0), Pr = (e, a, t) => t > 32 ? uo(e, a, t) : bo(e, a, t), Hr = (e, a, t) => t > 32 ? ho(e, a, t) : lo(e, a, t);
function So(e, a = 24) {
  const t = new Uint32Array(10);
  for (let n = 24 - a; n < 24; n++) {
    for (let f = 0; f < 10; f++)
      t[f] = e[f] ^ e[f + 10] ^ e[f + 20] ^ e[f + 30] ^ e[f + 40];
    for (let f = 0; f < 10; f += 2) {
      const d = (f + 8) % 10, o = (f + 2) % 10, i = t[o], s = t[o + 1], b = Pr(i, s, 1) ^ t[d], u = Hr(i, s, 1) ^ t[d + 1];
      for (let l = 0; l < 50; l += 10)
        e[f + l] ^= b, e[f + l + 1] ^= u;
    }
    let c = e[2], r = e[3];
    for (let f = 0; f < 24; f++) {
      const d = td[f], o = Pr(c, r, d), i = Hr(c, r, d), s = ed[f];
      c = e[s], r = e[s + 1], e[s] = o, e[s + 1] = i;
    }
    for (let f = 0; f < 50; f += 10) {
      for (let d = 0; d < 10; d++)
        t[d] = e[f + d];
      for (let d = 0; d < 10; d++)
        e[f + d] ^= ~t[(d + 2) % 10] & t[(d + 4) % 10];
    }
    e[0] ^= xo[n], e[1] ^= Ao[n];
  }
  t.fill(0);
}
class Cc extends Jf {
  // NOTE: we accept arguments in bytes instead of bits here.
  constructor(a, t, n, c = !1, r = 24) {
    if (super(), this.blockLen = a, this.suffix = t, this.outputLen = n, this.enableXOF = c, this.rounds = r, this.pos = 0, this.posOut = 0, this.finished = !1, this.destroyed = !1, Lr(n), 0 >= this.blockLen || this.blockLen >= 200)
      throw new Error("Sha3 supports only keccak-f1600 function");
    this.state = new Uint8Array(200), this.state32 = _o(this.state);
  }
  keccak() {
    So(this.state32, this.rounds), this.posOut = 0, this.pos = 0;
  }
  update(a) {
    Ja(this);
    const { blockLen: t, state: n } = this;
    a = Tc(a);
    const c = a.length;
    for (let r = 0; r < c; ) {
      const f = Math.min(t - this.pos, c - r);
      for (let d = 0; d < f; d++)
        n[this.pos++] ^= a[r++];
      this.pos === t && this.keccak();
    }
    return this;
  }
  finish() {
    if (this.finished)
      return;
    this.finished = !0;
    const { state: a, suffix: t, pos: n, blockLen: c } = this;
    a[n] ^= t, t & 128 && n === c - 1 && this.keccak(), a[c - 1] ^= 128, this.keccak();
  }
  writeInto(a) {
    Ja(this, !1), Yf(a), this.finish();
    const t = this.state, { blockLen: n } = this;
    for (let c = 0, r = a.length; c < r; ) {
      this.posOut >= n && this.keccak();
      const f = Math.min(n - this.posOut, r - c);
      a.set(t.subarray(this.posOut, this.posOut + f), c), this.posOut += f, c += f;
    }
    return a;
  }
  xofInto(a) {
    if (!this.enableXOF)
      throw new Error("XOF is not possible for this instance");
    return this.writeInto(a);
  }
  xof(a) {
    return Lr(a), this.xofInto(new Uint8Array(a));
  }
  digestInto(a) {
    if (Wf(a, this), this.finished)
      throw new Error("digest() was already called");
    return this.writeInto(a), this.destroy(), a;
  }
  digest() {
    return this.digestInto(new Uint8Array(this.outputLen));
  }
  destroy() {
    this.destroyed = !0, this.state.fill(0);
  }
  _cloneInto(a) {
    const { blockLen: t, suffix: n, outputLen: c, rounds: r, enableXOF: f } = this;
    return a || (a = new Cc(t, n, c, f, r)), a.state32.set(this.state32), a.pos = this.pos, a.posOut = this.posOut, a.finished = this.finished, a.rounds = r, a.suffix = n, a.outputLen = c, a.enableXOF = f, a.destroyed = this.destroyed, a;
  }
}
const ko = (e, a, t) => Qf(() => new Cc(a, e, t)), To = /* @__PURE__ */ ko(1, 136, 256 / 8);
function Co(e, a, t, n) {
  if (typeof e.setBigUint64 == "function")
    return e.setBigUint64(a, t, n);
  const c = BigInt(32), r = BigInt(4294967295), f = Number(t >> c & r), d = Number(t & r), o = n ? 4 : 0, i = n ? 0 : 4;
  e.setUint32(a + o, f, n), e.setUint32(a + i, d, n);
}
class Io extends Jf {
  constructor(a, t, n, c) {
    super(), this.blockLen = a, this.outputLen = t, this.padOffset = n, this.isLE = c, this.finished = !1, this.length = 0, this.pos = 0, this.destroyed = !1, this.buffer = new Uint8Array(a), this.view = On(this.buffer);
  }
  update(a) {
    Ja(this);
    const { view: t, buffer: n, blockLen: c } = this;
    a = Tc(a);
    const r = a.length;
    for (let f = 0; f < r; ) {
      const d = Math.min(c - this.pos, r - f);
      if (d === c) {
        const o = On(a);
        for (; c <= r - f; f += c)
          this.process(o, f);
        continue;
      }
      n.set(a.subarray(f, f + d), this.pos), this.pos += d, f += d, this.pos === c && (this.process(t, 0), this.pos = 0);
    }
    return this.length += a.length, this.roundClean(), this;
  }
  digestInto(a) {
    Ja(this), Wf(a, this), this.finished = !0;
    const { buffer: t, view: n, blockLen: c, isLE: r } = this;
    let { pos: f } = this;
    t[f++] = 128, this.buffer.subarray(f).fill(0), this.padOffset > c - f && (this.process(n, 0), f = 0);
    for (let b = f; b < c; b++)
      t[b] = 0;
    Co(n, c - 8, BigInt(this.length * 8), r), this.process(n, 0);
    const d = On(a), o = this.outputLen;
    if (o % 4)
      throw new Error("_sha2: outputLen should be aligned to 32bit");
    const i = o / 4, s = this.get();
    if (i > s.length)
      throw new Error("_sha2: outputLen bigger than state");
    for (let b = 0; b < i; b++)
      d.setUint32(4 * b, s[b], r);
  }
  digest() {
    const { buffer: a, outputLen: t } = this;
    this.digestInto(a);
    const n = a.slice(0, t);
    return this.destroy(), n;
  }
  _cloneInto(a) {
    a || (a = new this.constructor()), a.set(...this.get());
    const { blockLen: t, buffer: n, length: c, finished: r, destroyed: f, pos: d } = this;
    return a.length = c, a.pos = d, a.finished = r, a.destroyed = f, c % t && a.buffer.set(n), a;
  }
}
const No = (e, a, t) => e & a ^ ~e & t, Oo = (e, a, t) => e & a ^ e & t ^ a & t, Bo = /* @__PURE__ */ new Uint32Array([
  1116352408,
  1899447441,
  3049323471,
  3921009573,
  961987163,
  1508970993,
  2453635748,
  2870763221,
  3624381080,
  310598401,
  607225278,
  1426881987,
  1925078388,
  2162078206,
  2614888103,
  3248222580,
  3835390401,
  4022224774,
  264347078,
  604807628,
  770255983,
  1249150122,
  1555081692,
  1996064986,
  2554220882,
  2821834349,
  2952996808,
  3210313671,
  3336571891,
  3584528711,
  113926993,
  338241895,
  666307205,
  773529912,
  1294757372,
  1396182291,
  1695183700,
  1986661051,
  2177026350,
  2456956037,
  2730485921,
  2820302411,
  3259730800,
  3345764771,
  3516065817,
  3600352804,
  4094571909,
  275423344,
  430227734,
  506948616,
  659060556,
  883997877,
  958139571,
  1322822218,
  1537002063,
  1747873779,
  1955562222,
  2024104815,
  2227730452,
  2361852424,
  2428436474,
  2756734187,
  3204031479,
  3329325298
]), Ve = /* @__PURE__ */ new Uint32Array([
  1779033703,
  3144134277,
  1013904242,
  2773480762,
  1359893119,
  2600822924,
  528734635,
  1541459225
]), je = /* @__PURE__ */ new Uint32Array(64);
class Ro extends Io {
  constructor() {
    super(64, 32, 8, !1), this.A = Ve[0] | 0, this.B = Ve[1] | 0, this.C = Ve[2] | 0, this.D = Ve[3] | 0, this.E = Ve[4] | 0, this.F = Ve[5] | 0, this.G = Ve[6] | 0, this.H = Ve[7] | 0;
  }
  get() {
    const { A: a, B: t, C: n, D: c, E: r, F: f, G: d, H: o } = this;
    return [a, t, n, c, r, f, d, o];
  }
  // prettier-ignore
  set(a, t, n, c, r, f, d, o) {
    this.A = a | 0, this.B = t | 0, this.C = n | 0, this.D = c | 0, this.E = r | 0, this.F = f | 0, this.G = d | 0, this.H = o | 0;
  }
  process(a, t) {
    for (let b = 0; b < 16; b++, t += 4)
      je[b] = a.getUint32(t, !1);
    for (let b = 16; b < 64; b++) {
      const u = je[b - 15], l = je[b - 2], _ = ve(u, 7) ^ ve(u, 18) ^ u >>> 3, h = ve(l, 17) ^ ve(l, 19) ^ l >>> 10;
      je[b] = h + je[b - 7] + _ + je[b - 16] | 0;
    }
    let { A: n, B: c, C: r, D: f, E: d, F: o, G: i, H: s } = this;
    for (let b = 0; b < 64; b++) {
      const u = ve(d, 6) ^ ve(d, 11) ^ ve(d, 25), l = s + u + No(d, o, i) + Bo[b] + je[b] | 0, h = (ve(n, 2) ^ ve(n, 13) ^ ve(n, 22)) + Oo(n, c, r) | 0;
      s = i, i = o, o = d, d = f + l | 0, f = r, r = c, c = n, n = l + h | 0;
    }
    n = n + this.A | 0, c = c + this.B | 0, r = r + this.C | 0, f = f + this.D | 0, d = d + this.E | 0, o = o + this.F | 0, i = i + this.G | 0, s = s + this.H | 0, this.set(n, c, r, f, d, o, i, s);
  }
  roundClean() {
    je.fill(0);
  }
  destroy() {
    this.set(0, 0, 0, 0, 0, 0, 0, 0), this.buffer.fill(0);
  }
}
const Ic = /* @__PURE__ */ Qf(() => new Ro());
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const J = BigInt(0), M = BigInt(1), rt = BigInt(2), Do = BigInt(3), ac = BigInt(4), Ur = BigInt(5), Fr = BigInt(8);
BigInt(9);
BigInt(16);
function ae(e, a) {
  const t = e % a;
  return t >= J ? t : a + t;
}
function Lo(e, a, t) {
  if (t <= J || a < J)
    throw new Error("Expected power/modulo > 0");
  if (t === M)
    return J;
  let n = M;
  for (; a > J; )
    a & M && (n = n * e % t), e = e * e % t, a >>= M;
  return n;
}
function nc(e, a) {
  if (e === J || a <= J)
    throw new Error(`invert: expected positive integers, got n=${e} mod=${a}`);
  let t = ae(e, a), n = a, c = J, r = M;
  for (; t !== J; ) {
    const d = n / t, o = n % t, i = c - r * d;
    n = t, t = o, c = r, r = i;
  }
  if (n !== M)
    throw new Error("invert: does not exist");
  return ae(c, a);
}
function $o(e) {
  const a = (e - M) / rt;
  let t, n, c;
  for (t = e - M, n = 0; t % rt === J; t /= rt, n++)
    ;
  for (c = rt; c < e && Lo(c, a, e) !== e - M; c++)
    ;
  if (n === 1) {
    const f = (e + M) / ac;
    return function(o, i) {
      const s = o.pow(i, f);
      if (!o.eql(o.sqr(s), i))
        throw new Error("Cannot find square root");
      return s;
    };
  }
  const r = (t + M) / rt;
  return function(d, o) {
    if (d.pow(o, a) === d.neg(d.ONE))
      throw new Error("Cannot find square root");
    let i = n, s = d.pow(d.mul(d.ONE, c), t), b = d.pow(o, r), u = d.pow(o, t);
    for (; !d.eql(u, d.ONE); ) {
      if (d.eql(u, d.ZERO))
        return d.ZERO;
      let l = 1;
      for (let h = d.sqr(u); l < i && !d.eql(h, d.ONE); l++)
        h = d.sqr(h);
      const _ = d.pow(s, M << BigInt(i - l - 1));
      s = d.sqr(_), b = d.mul(b, _), u = d.mul(u, s), i = l;
    }
    return b;
  };
}
function Po(e) {
  if (e % ac === Do) {
    const a = (e + M) / ac;
    return function(n, c) {
      const r = n.pow(c, a);
      if (!n.eql(n.sqr(r), c))
        throw new Error("Cannot find square root");
      return r;
    };
  }
  if (e % Fr === Ur) {
    const a = (e - Ur) / Fr;
    return function(n, c) {
      const r = n.mul(c, rt), f = n.pow(r, a), d = n.mul(c, f), o = n.mul(n.mul(d, rt), f), i = n.mul(d, n.sub(o, n.ONE));
      if (!n.eql(n.sqr(i), c))
        throw new Error("Cannot find square root");
      return i;
    };
  }
  return $o(e);
}
const Ho = [
  "create",
  "isValid",
  "is0",
  "neg",
  "inv",
  "sqrt",
  "sqr",
  "eql",
  "add",
  "sub",
  "mul",
  "pow",
  "div",
  "addN",
  "subN",
  "mulN",
  "sqrN"
];
function _n(e) {
  const a = {
    ORDER: "bigint",
    MASK: "bigint",
    BYTES: "isSafeInteger",
    BITS: "isSafeInteger"
  }, t = Ho.reduce((n, c) => (n[c] = "function", n), a);
  return xa(e, t);
}
function nd(e, a, t) {
  if (t < J)
    throw new Error("Expected power > 0");
  if (t === J)
    return e.ONE;
  if (t === M)
    return a;
  let n = e.ONE, c = a;
  for (; t > J; )
    t & M && (n = e.mul(n, c)), c = e.sqr(c), t >>= M;
  return n;
}
function Uo(e, a) {
  const t = new Array(a.length), n = a.reduce((r, f, d) => e.is0(f) ? r : (t[d] = r, e.mul(r, f)), e.ONE), c = e.inv(n);
  return a.reduceRight((r, f, d) => e.is0(f) ? r : (t[d] = e.mul(r, t[d]), e.mul(r, f)), c), t;
}
function Nc(e, a) {
  const t = a !== void 0 ? a : e.toString(2).length, n = Math.ceil(t / 8);
  return { nBitLength: t, nByteLength: n };
}
function Oc(e, a, t = !1, n = {}) {
  if (e <= J)
    throw new Error(`Expected Fp ORDER > 0, got ${e}`);
  const { nBitLength: c, nByteLength: r } = Nc(e, a);
  if (r > 2048)
    throw new Error("Field lengths over 2048 bytes are not supported");
  const f = Po(e), d = Object.freeze({
    ORDER: e,
    BITS: c,
    BYTES: r,
    MASK: pn(c),
    ZERO: J,
    ONE: M,
    create: (o) => ae(o, e),
    isValid: (o) => {
      if (typeof o != "bigint")
        throw new Error(`Invalid field element: expected bigint, got ${typeof o}`);
      return J <= o && o < e;
    },
    is0: (o) => o === J,
    isOdd: (o) => (o & M) === M,
    neg: (o) => ae(-o, e),
    eql: (o, i) => o === i,
    sqr: (o) => ae(o * o, e),
    add: (o, i) => ae(o + i, e),
    sub: (o, i) => ae(o - i, e),
    mul: (o, i) => ae(o * i, e),
    pow: (o, i) => nd(d, o, i),
    div: (o, i) => ae(o * nc(i, e), e),
    // Same as above, but doesn't normalize
    sqrN: (o) => o * o,
    addN: (o, i) => o + i,
    subN: (o, i) => o - i,
    mulN: (o, i) => o * i,
    inv: (o) => nc(o, e),
    sqrt: n.sqrt || ((o) => f(d, o)),
    invertBatch: (o) => Uo(d, o),
    // TODO: do we really need constant cmov?
    // We don't have const-time bigints anyway, so probably will be not very useful
    cmov: (o, i, s) => s ? i : o,
    toBytes: (o) => t ? Kf(o, r) : $t(o, r),
    fromBytes: (o) => {
      if (o.length !== r)
        throw new Error(`Fp.fromBytes: expected ${r}, got ${o.length}`);
      return t ? Sc(o) : ie(o);
    }
  });
  return Object.freeze(d);
}
function Fo(e, a, t = !1) {
  e = be("privateHash", e);
  const n = e.length, c = Nc(a).nByteLength + 8;
  if (c < 24 || n < c || n > 1024)
    throw new Error(`hashToPrivateScalar: expected ${c}-1024 bytes of input, got ${n}`);
  const r = t ? Sc(e) : ie(e);
  return ae(r, a - M) + M;
}
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function cd(e) {
  const { Fp: a } = e;
  _n(a);
  for (const o of ["t", "roundsFull", "roundsPartial"])
    if (typeof e[o] != "number" || !Number.isSafeInteger(e[o]))
      throw new Error(`Poseidon: invalid param ${o}=${e[o]} (${typeof e[o]})`);
  if (e.reversePartialPowIdx !== void 0 && typeof e.reversePartialPowIdx != "boolean")
    throw new Error(`Poseidon: invalid param reversePartialPowIdx=${e.reversePartialPowIdx}`);
  let t = e.sboxPower;
  if (t === void 0 && (t = 5), typeof t != "number" || !Number.isSafeInteger(t))
    throw new Error(`Poseidon wrong sboxPower=${t}`);
  const n = BigInt(t);
  let c = (o) => nd(a, o, n);
  if (t === 3 ? c = (o) => a.mul(a.sqrN(o), o) : t === 5 && (c = (o) => a.mul(a.sqrN(a.sqrN(o)), o)), e.roundsFull % 2 !== 0)
    throw new Error(`Poseidon roundsFull is not even: ${e.roundsFull}`);
  const r = e.roundsFull + e.roundsPartial;
  if (!Array.isArray(e.roundConstants) || e.roundConstants.length !== r)
    throw new Error("Poseidon: wrong round constants");
  const f = e.roundConstants.map((o) => {
    if (!Array.isArray(o) || o.length !== e.t)
      throw new Error(`Poseidon wrong round constants: ${o}`);
    return o.map((i) => {
      if (typeof i != "bigint" || !a.isValid(i))
        throw new Error(`Poseidon wrong round constant=${i}`);
      return a.create(i);
    });
  });
  if (!Array.isArray(e.mds) || e.mds.length !== e.t)
    throw new Error("Poseidon: wrong MDS matrix");
  const d = e.mds.map((o) => {
    if (!Array.isArray(o) || o.length !== e.t)
      throw new Error(`Poseidon MDS matrix row: ${o}`);
    return o.map((i) => {
      if (typeof i != "bigint")
        throw new Error(`Poseidon MDS matrix value=${i}`);
      return a.create(i);
    });
  });
  return Object.freeze({ ...e, rounds: r, sboxFn: c, roundConstants: f, mds: d });
}
function zo(e, a) {
  if (typeof a != "number")
    throw new Error("poseidonSplitConstants: wrong t");
  if (!Array.isArray(e) || e.length % a)
    throw new Error("poseidonSplitConstants: wrong rc");
  const t = [];
  let n = [];
  for (let c = 0; c < e.length; c++)
    n.push(e[c]), n.length === a && (t.push(n), n = []);
  return t;
}
function rd(e) {
  const { t: a, Fp: t, rounds: n, sboxFn: c, reversePartialPowIdx: r } = cd(e), f = Math.floor(e.roundsFull / 2), d = r ? a - 1 : 0, o = (s, b, u) => (s = s.map((l, _) => t.add(l, e.roundConstants[u][_])), b ? s = s.map((l) => c(l)) : s[d] = c(s[d]), s = e.mds.map((l) => l.reduce((_, h, p) => t.add(_, t.mulN(h, s[p])), t.ZERO)), s), i = function(b) {
    if (!Array.isArray(b) || b.length !== a)
      throw new Error(`Poseidon: wrong values (expected array of bigints with length ${a})`);
    b = b.map((l) => {
      if (typeof l != "bigint")
        throw new Error(`Poseidon: wrong value=${l} (${typeof l})`);
      return t.create(l);
    });
    let u = 0;
    for (let l = 0; l < f; l++)
      b = o(b, !0, u++);
    for (let l = 0; l < e.roundsPartial; l++)
      b = o(b, !1, u++);
    for (let l = 0; l < f; l++)
      b = o(b, !0, u++);
    if (u !== n)
      throw new Error(`Poseidon: wrong number of rounds: last round=${u}, total=${n}`);
    return b;
  };
  return i.roundConstants = e.roundConstants, i;
}
const Mo = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  poseidon: rd,
  splitConstants: zo,
  validateOpts: cd
}, Symbol.toStringTag, { value: "Module" }));
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const Zo = BigInt(0), Bn = BigInt(1);
function Vo(e, a) {
  const t = (c, r) => {
    const f = r.negate();
    return c ? f : r;
  }, n = (c) => {
    const r = Math.ceil(a / c) + 1, f = 2 ** (c - 1);
    return { windows: r, windowSize: f };
  };
  return {
    constTimeNegate: t,
    // non-const time multiplication ladder
    unsafeLadder(c, r) {
      let f = e.ZERO, d = c;
      for (; r > Zo; )
        r & Bn && (f = f.add(d)), d = d.double(), r >>= Bn;
      return f;
    },
    /**
     * Creates a wNAF precomputation window. Used for caching.
     * Default window size is set by `utils.precompute()` and is equal to 8.
     * Number of precomputed points depends on the curve size:
     * 2^(𝑊−1) * (Math.ceil(𝑛 / 𝑊) + 1), where:
     * - 𝑊 is the window size
     * - 𝑛 is the bitlength of the curve order.
     * For a 256-bit curve and window size 8, the number of precomputed points is 128 * 33 = 4224.
     * @returns precomputed point tables flattened to a single array
     */
    precomputeWindow(c, r) {
      const { windows: f, windowSize: d } = n(r), o = [];
      let i = c, s = i;
      for (let b = 0; b < f; b++) {
        s = i, o.push(s);
        for (let u = 1; u < d; u++)
          s = s.add(i), o.push(s);
        i = s.double();
      }
      return o;
    },
    /**
     * Implements ec multiplication using precomputed tables and w-ary non-adjacent form.
     * @param W window size
     * @param precomputes precomputed tables
     * @param n scalar (we don't check here, but should be less than curve order)
     * @returns real and fake (for const-time) points
     */
    wNAF(c, r, f) {
      const { windows: d, windowSize: o } = n(c);
      let i = e.ZERO, s = e.BASE;
      const b = BigInt(2 ** c - 1), u = 2 ** c, l = BigInt(c);
      for (let _ = 0; _ < d; _++) {
        const h = _ * o;
        let p = Number(f & b);
        f >>= l, p > o && (p -= u, f += Bn);
        const g = h, E = h + Math.abs(p) - 1, v = _ % 2 !== 0, y = p < 0;
        p === 0 ? s = s.add(t(v, r[g])) : i = i.add(t(y, r[E]));
      }
      return { p: i, f: s };
    },
    wNAFCached(c, r, f, d) {
      const o = c._WINDOW_SIZE || 1;
      let i = r.get(c);
      return i || (i = this.precomputeWindow(c, o), o !== 1 && r.set(c, d(i))), this.wNAF(o, i, f);
    }
  };
}
function fd(e) {
  return _n(e.Fp), xa(e, {
    n: "bigint",
    h: "bigint",
    Gx: "field",
    Gy: "field"
  }, {
    nBitLength: "isSafeInteger",
    nByteLength: "isSafeInteger"
  }), Object.freeze({
    ...Nc(e.n, e.nBitLength),
    ...e,
    p: e.Fp.ORDER
  });
}
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function jo(e) {
  const a = fd(e);
  xa(a, {
    a: "field",
    b: "field"
  }, {
    allowedPrivateKeyLengths: "array",
    wrapPrivateKey: "boolean",
    isTorsionFree: "function",
    clearCofactor: "function",
    allowInfinityPoint: "boolean",
    fromBytes: "function",
    toBytes: "function"
  });
  const { endo: t, Fp: n, a: c } = a;
  if (t) {
    if (!n.eql(c, n.ZERO))
      throw new Error("Endomorphism can only be defined for Koblitz curves that have a=0");
    if (typeof t != "object" || typeof t.beta != "bigint" || typeof t.splitScalar != "function")
      throw new Error("Expected endomorphism with beta: bigint and splitScalar: function");
  }
  return Object.freeze({ ...a });
}
const { bytesToNumberBE: qo, hexToBytes: Ko } = io, Ke = {
  // asn.1 DER encoding utils
  Err: class extends Error {
    constructor(a = "") {
      super(a);
    }
  },
  _parseInt(e) {
    const { Err: a } = Ke;
    if (e.length < 2 || e[0] !== 2)
      throw new a("Invalid signature integer tag");
    const t = e[1], n = e.subarray(2, t + 2);
    if (!t || n.length !== t)
      throw new a("Invalid signature integer: wrong length");
    if (n[0] & 128)
      throw new a("Invalid signature integer: negative");
    if (n[0] === 0 && !(n[1] & 128))
      throw new a("Invalid signature integer: unnecessary leading zero");
    return { d: qo(n), l: e.subarray(t + 2) };
  },
  toSig(e) {
    const { Err: a } = Ke, t = typeof e == "string" ? Ko(e) : e;
    if (!(t instanceof Uint8Array))
      throw new Error("ui8a expected");
    let n = t.length;
    if (n < 2 || t[0] != 48)
      throw new a("Invalid signature tag");
    if (t[1] !== n - 2)
      throw new a("Invalid signature: incorrect length");
    const { d: c, l: r } = Ke._parseInt(t.subarray(2)), { d: f, l: d } = Ke._parseInt(r);
    if (d.length)
      throw new a("Invalid signature: left bytes after parsing");
    return { r: c, s: f };
  },
  hexFromSig(e) {
    const a = (i) => Number.parseInt(i[0], 16) & 8 ? "00" + i : i, t = (i) => {
      const s = i.toString(16);
      return s.length & 1 ? `0${s}` : s;
    }, n = a(t(e.s)), c = a(t(e.r)), r = n.length / 2, f = c.length / 2, d = t(r), o = t(f);
    return `30${t(f + r + 4)}02${o}${c}02${d}${n}`;
  }
}, me = BigInt(0), Z = BigInt(1), Be = BigInt(2), Qa = BigInt(3), zr = BigInt(4);
function dd(e) {
  const a = jo(e), { Fp: t } = a, n = a.toBytes || ((_, h, p) => {
    const g = h.toAffine();
    return zt(Uint8Array.from([4]), t.toBytes(g.x), t.toBytes(g.y));
  }), c = a.fromBytes || ((_) => {
    const h = _.subarray(1), p = t.fromBytes(h.subarray(0, t.BYTES)), g = t.fromBytes(h.subarray(t.BYTES, 2 * t.BYTES));
    return { x: p, y: g };
  });
  function r(_) {
    const { a: h, b: p } = a, g = t.sqr(_), E = t.mul(g, _);
    return t.add(t.add(E, t.mul(_, h)), p);
  }
  if (!t.eql(t.sqr(a.Gy), r(a.Gx)))
    throw new Error("bad generator point: equation left != right");
  function f(_) {
    return typeof _ == "bigint" && me < _ && _ < a.n;
  }
  function d(_) {
    if (!f(_))
      throw new Error("Expected valid bigint: 0 < bigint < curve.n");
  }
  function o(_) {
    const { allowedPrivateKeyLengths: h, nByteLength: p, wrapPrivateKey: g, n: E } = a;
    if (h && typeof _ != "bigint") {
      if (_ instanceof Uint8Array && (_ = Je(_)), typeof _ != "string" || !h.includes(_.length))
        throw new Error("Invalid key");
      _ = _.padStart(p * 2, "0");
    }
    let v;
    try {
      v = typeof _ == "bigint" ? _ : ie(be("private key", _, p));
    } catch {
      throw new Error(`private key must be ${p} bytes, hex or bigint, not ${typeof _}`);
    }
    return g && (v = ae(v, E)), d(v), v;
  }
  const i = /* @__PURE__ */ new Map();
  function s(_) {
    if (!(_ instanceof b))
      throw new Error("ProjectivePoint expected");
  }
  class b {
    constructor(h, p, g) {
      if (this.px = h, this.py = p, this.pz = g, h == null || !t.isValid(h))
        throw new Error("x required");
      if (p == null || !t.isValid(p))
        throw new Error("y required");
      if (g == null || !t.isValid(g))
        throw new Error("z required");
    }
    // Does not validate if the point is on-curve.
    // Use fromHex instead, or call assertValidity() later.
    static fromAffine(h) {
      const { x: p, y: g } = h || {};
      if (!h || !t.isValid(p) || !t.isValid(g))
        throw new Error("invalid affine point");
      if (h instanceof b)
        throw new Error("projective point not allowed");
      const E = (v) => t.eql(v, t.ZERO);
      return E(p) && E(g) ? b.ZERO : new b(p, g, t.ONE);
    }
    get x() {
      return this.toAffine().x;
    }
    get y() {
      return this.toAffine().y;
    }
    /**
     * Takes a bunch of Projective Points but executes only one
     * inversion on all of them. Inversion is very slow operation,
     * so this improves performance massively.
     * Optimization: converts a list of projective points to a list of identical points with Z=1.
     */
    static normalizeZ(h) {
      const p = t.invertBatch(h.map((g) => g.pz));
      return h.map((g, E) => g.toAffine(p[E])).map(b.fromAffine);
    }
    /**
     * Converts hash string or Uint8Array to Point.
     * @param hex short/long ECDSA hex
     */
    static fromHex(h) {
      const p = b.fromAffine(c(be("pointHex", h)));
      return p.assertValidity(), p;
    }
    // Multiplies generator point by privateKey.
    static fromPrivateKey(h) {
      return b.BASE.multiply(o(h));
    }
    // "Private method", don't use it directly
    _setWindowSize(h) {
      this._WINDOW_SIZE = h, i.delete(this);
    }
    // A point on curve is valid if it conforms to equation.
    assertValidity() {
      if (this.is0()) {
        if (a.allowInfinityPoint)
          return;
        throw new Error("bad point: ZERO");
      }
      const { x: h, y: p } = this.toAffine();
      if (!t.isValid(h) || !t.isValid(p))
        throw new Error("bad point: x or y not FE");
      const g = t.sqr(p), E = r(h);
      if (!t.eql(g, E))
        throw new Error("bad point: equation left != right");
      if (!this.isTorsionFree())
        throw new Error("bad point: not in prime-order subgroup");
    }
    hasEvenY() {
      const { y: h } = this.toAffine();
      if (t.isOdd)
        return !t.isOdd(h);
      throw new Error("Field doesn't support isOdd");
    }
    /**
     * Compare one point to another.
     */
    equals(h) {
      s(h);
      const { px: p, py: g, pz: E } = this, { px: v, py: y, pz: S } = h, A = t.eql(t.mul(p, S), t.mul(v, E)), m = t.eql(t.mul(g, S), t.mul(y, E));
      return A && m;
    }
    /**
     * Flips point to one corresponding to (x, -y) in Affine coordinates.
     */
    negate() {
      return new b(this.px, t.neg(this.py), this.pz);
    }
    // Renes-Costello-Batina exception-free doubling formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 3
    // Cost: 8M + 3S + 3*a + 2*b3 + 15add.
    double() {
      const { a: h, b: p } = a, g = t.mul(p, Qa), { px: E, py: v, pz: y } = this;
      let S = t.ZERO, A = t.ZERO, m = t.ZERO, C = t.mul(E, E), O = t.mul(v, v), T = t.mul(y, y), k = t.mul(E, v);
      return k = t.add(k, k), m = t.mul(E, y), m = t.add(m, m), S = t.mul(h, m), A = t.mul(g, T), A = t.add(S, A), S = t.sub(O, A), A = t.add(O, A), A = t.mul(S, A), S = t.mul(k, S), m = t.mul(g, m), T = t.mul(h, T), k = t.sub(C, T), k = t.mul(h, k), k = t.add(k, m), m = t.add(C, C), C = t.add(m, C), C = t.add(C, T), C = t.mul(C, k), A = t.add(A, C), T = t.mul(v, y), T = t.add(T, T), C = t.mul(T, k), S = t.sub(S, C), m = t.mul(T, O), m = t.add(m, m), m = t.add(m, m), new b(S, A, m);
    }
    // Renes-Costello-Batina exception-free addition formula.
    // There is 30% faster Jacobian formula, but it is not complete.
    // https://eprint.iacr.org/2015/1060, algorithm 1
    // Cost: 12M + 0S + 3*a + 3*b3 + 23add.
    add(h) {
      s(h);
      const { px: p, py: g, pz: E } = this, { px: v, py: y, pz: S } = h;
      let A = t.ZERO, m = t.ZERO, C = t.ZERO;
      const O = a.a, T = t.mul(a.b, Qa);
      let k = t.mul(p, v), z = t.mul(g, y), U = t.mul(E, S), N = t.add(p, g), w = t.add(v, y);
      N = t.mul(N, w), w = t.add(k, z), N = t.sub(N, w), w = t.add(p, E);
      let x = t.add(v, S);
      return w = t.mul(w, x), x = t.add(k, U), w = t.sub(w, x), x = t.add(g, E), A = t.add(y, S), x = t.mul(x, A), A = t.add(z, U), x = t.sub(x, A), C = t.mul(O, w), A = t.mul(T, U), C = t.add(A, C), A = t.sub(z, C), C = t.add(z, C), m = t.mul(A, C), z = t.add(k, k), z = t.add(z, k), U = t.mul(O, U), w = t.mul(T, w), z = t.add(z, U), U = t.sub(k, U), U = t.mul(O, U), w = t.add(w, U), k = t.mul(z, w), m = t.add(m, k), k = t.mul(x, w), A = t.mul(N, A), A = t.sub(A, k), k = t.mul(N, z), C = t.mul(x, C), C = t.add(C, k), new b(A, m, C);
    }
    subtract(h) {
      return this.add(h.negate());
    }
    is0() {
      return this.equals(b.ZERO);
    }
    wNAF(h) {
      return l.wNAFCached(this, i, h, (p) => {
        const g = t.invertBatch(p.map((E) => E.pz));
        return p.map((E, v) => E.toAffine(g[v])).map(b.fromAffine);
      });
    }
    /**
     * Non-constant-time multiplication. Uses double-and-add algorithm.
     * It's faster, but should only be used when you don't care about
     * an exposed private key e.g. sig verification, which works over *public* keys.
     */
    multiplyUnsafe(h) {
      const p = b.ZERO;
      if (h === me)
        return p;
      if (d(h), h === Z)
        return this;
      const { endo: g } = a;
      if (!g)
        return l.unsafeLadder(this, h);
      let { k1neg: E, k1: v, k2neg: y, k2: S } = g.splitScalar(h), A = p, m = p, C = this;
      for (; v > me || S > me; )
        v & Z && (A = A.add(C)), S & Z && (m = m.add(C)), C = C.double(), v >>= Z, S >>= Z;
      return E && (A = A.negate()), y && (m = m.negate()), m = new b(t.mul(m.px, g.beta), m.py, m.pz), A.add(m);
    }
    /**
     * Constant time multiplication.
     * Uses wNAF method. Windowed method may be 10% faster,
     * but takes 2x longer to generate and consumes 2x memory.
     * Uses precomputes when available.
     * Uses endomorphism for Koblitz curves.
     * @param scalar by which the point would be multiplied
     * @returns New point
     */
    multiply(h) {
      d(h);
      let p = h, g, E;
      const { endo: v } = a;
      if (v) {
        const { k1neg: y, k1: S, k2neg: A, k2: m } = v.splitScalar(p);
        let { p: C, f: O } = this.wNAF(S), { p: T, f: k } = this.wNAF(m);
        C = l.constTimeNegate(y, C), T = l.constTimeNegate(A, T), T = new b(t.mul(T.px, v.beta), T.py, T.pz), g = C.add(T), E = O.add(k);
      } else {
        const { p: y, f: S } = this.wNAF(p);
        g = y, E = S;
      }
      return b.normalizeZ([g, E])[0];
    }
    /**
     * Efficiently calculate `aP + bQ`. Unsafe, can expose private key, if used incorrectly.
     * Not using Strauss-Shamir trick: precomputation tables are faster.
     * The trick could be useful if both P and Q are not G (not in our case).
     * @returns non-zero affine point
     */
    multiplyAndAddUnsafe(h, p, g) {
      const E = b.BASE, v = (S, A) => A === me || A === Z || !S.equals(E) ? S.multiplyUnsafe(A) : S.multiply(A), y = v(this, p).add(v(h, g));
      return y.is0() ? void 0 : y;
    }
    // Converts Projective point to affine (x, y) coordinates.
    // Can accept precomputed Z^-1 - for example, from invertBatch.
    // (x, y, z) ∋ (x=x/z, y=y/z)
    toAffine(h) {
      const { px: p, py: g, pz: E } = this, v = this.is0();
      h == null && (h = v ? t.ONE : t.inv(E));
      const y = t.mul(p, h), S = t.mul(g, h), A = t.mul(E, h);
      if (v)
        return { x: t.ZERO, y: t.ZERO };
      if (!t.eql(A, t.ONE))
        throw new Error("invZ was invalid");
      return { x: y, y: S };
    }
    isTorsionFree() {
      const { h, isTorsionFree: p } = a;
      if (h === Z)
        return !0;
      if (p)
        return p(b, this);
      throw new Error("isTorsionFree() has not been declared for the elliptic curve");
    }
    clearCofactor() {
      const { h, clearCofactor: p } = a;
      return h === Z ? this : p ? p(b, this) : this.multiplyUnsafe(a.h);
    }
    toRawBytes(h = !0) {
      return this.assertValidity(), n(b, this, h);
    }
    toHex(h = !0) {
      return Je(this.toRawBytes(h));
    }
  }
  b.BASE = new b(a.Gx, a.Gy, t.ONE), b.ZERO = new b(t.ZERO, t.ONE, t.ZERO);
  const u = a.nBitLength, l = Vo(b, a.endo ? Math.ceil(u / 2) : u);
  return {
    CURVE: a,
    ProjectivePoint: b,
    normPrivateKeyToScalar: o,
    weierstrassEquation: r,
    isWithinCurveOrder: f
  };
}
function Go(e) {
  const a = fd(e);
  return xa(a, {
    hash: "hash",
    hmac: "function",
    randomBytes: "function"
  }, {
    bits2int: "function",
    bits2int_modN: "function",
    lowS: "boolean"
  }), Object.freeze({ lowS: !0, ...a });
}
function id(e) {
  const a = Go(e), { Fp: t, n } = a, c = t.BYTES + 1, r = 2 * t.BYTES + 1;
  function f(w) {
    return me < w && w < t.ORDER;
  }
  function d(w) {
    return ae(w, n);
  }
  function o(w) {
    return nc(w, n);
  }
  const { ProjectivePoint: i, normPrivateKeyToScalar: s, weierstrassEquation: b, isWithinCurveOrder: u } = dd({
    ...a,
    toBytes(w, x, R) {
      const L = x.toAffine(), P = t.toBytes(L.x), Y = zt;
      return R ? Y(Uint8Array.from([x.hasEvenY() ? 2 : 3]), P) : Y(Uint8Array.from([4]), P, t.toBytes(L.y));
    },
    fromBytes(w) {
      const x = w.length, R = w[0], L = w.subarray(1);
      if (x === c && (R === 2 || R === 3)) {
        const P = ie(L);
        if (!f(P))
          throw new Error("Point is not on curve");
        const Y = b(P);
        let he = t.sqrt(Y);
        const se = (he & Z) === Z;
        return (R & 1) === 1 !== se && (he = t.neg(he)), { x: P, y: he };
      } else if (x === r && R === 4) {
        const P = t.fromBytes(L.subarray(0, t.BYTES)), Y = t.fromBytes(L.subarray(t.BYTES, 2 * t.BYTES));
        return { x: P, y: Y };
      } else
        throw new Error(`Point of length ${x} was invalid. Expected ${c} compressed bytes or ${r} uncompressed bytes`);
    }
  }), l = (w) => Je($t(w, a.nByteLength));
  function _(w) {
    const x = n >> Z;
    return w > x;
  }
  function h(w) {
    return _(w) ? d(-w) : w;
  }
  const p = (w, x, R) => ie(w.slice(x, R));
  class g {
    constructor(x, R, L) {
      this.r = x, this.s = R, this.recovery = L, this.assertValidity();
    }
    // pair (bytes of r, bytes of s)
    static fromCompact(x) {
      const R = a.nByteLength;
      return x = be("compactSignature", x, R * 2), new g(p(x, 0, R), p(x, R, 2 * R));
    }
    // DER encoded ECDSA signature
    // https://bitcoin.stackexchange.com/questions/57644/what-are-the-parts-of-a-bitcoin-transaction-input-script
    static fromDER(x) {
      const { r: R, s: L } = Ke.toSig(be("DER", x));
      return new g(R, L);
    }
    assertValidity() {
      if (!u(this.r))
        throw new Error("r must be 0 < r < CURVE.n");
      if (!u(this.s))
        throw new Error("s must be 0 < s < CURVE.n");
    }
    addRecoveryBit(x) {
      return new g(this.r, this.s, x);
    }
    recoverPublicKey(x) {
      const { r: R, s: L, recovery: P } = this, Y = m(be("msgHash", x));
      if (P == null || ![0, 1, 2, 3].includes(P))
        throw new Error("recovery id invalid");
      const he = P === 2 || P === 3 ? R + a.n : R;
      if (he >= t.ORDER)
        throw new Error("recovery id 2 or 3 invalid");
      const se = P & 1 ? "03" : "02", ze = i.fromHex(se + l(he)), Me = o(he), xt = d(-Y * Me), ea = d(L * Me), Ze = i.BASE.multiplyAndAddUnsafe(ze, xt, ea);
      if (!Ze)
        throw new Error("point at infinify");
      return Ze.assertValidity(), Ze;
    }
    // Signatures should be low-s, to prevent malleability.
    hasHighS() {
      return _(this.s);
    }
    normalizeS() {
      return this.hasHighS() ? new g(this.r, d(-this.s), this.recovery) : this;
    }
    // DER-encoded
    toDERRawBytes() {
      return He(this.toDERHex());
    }
    toDERHex() {
      return Ke.hexFromSig({ r: this.r, s: this.s });
    }
    // padded bytes of r, then padded bytes of s
    toCompactRawBytes() {
      return He(this.toCompactHex());
    }
    toCompactHex() {
      return l(this.r) + l(this.s);
    }
  }
  const E = {
    isValidPrivateKey(w) {
      try {
        return s(w), !0;
      } catch {
        return !1;
      }
    },
    normPrivateKeyToScalar: s,
    /**
     * Produces cryptographically secure private key from random of size (nBitLength+64)
     * as per FIPS 186 B.4.1 with modulo bias being neglible.
     */
    randomPrivateKey: () => {
      const w = a.randomBytes(t.BYTES + 8), x = Fo(w, n);
      return $t(x, a.nByteLength);
    },
    /**
     * Creates precompute table for an arbitrary EC point. Makes point "cached".
     * Allows to massively speed-up `point.multiply(scalar)`.
     * @returns cached point
     * @example
     * const fast = utils.precompute(8, ProjectivePoint.fromHex(someonesPubKey));
     * fast.multiply(privKey); // much faster ECDH now
     */
    precompute(w = 8, x = i.BASE) {
      return x._setWindowSize(w), x.multiply(BigInt(3)), x;
    }
  };
  function v(w, x = !0) {
    return i.fromPrivateKey(w).toRawBytes(x);
  }
  function y(w) {
    const x = w instanceof Uint8Array, R = typeof w == "string", L = (x || R) && w.length;
    return x ? L === c || L === r : R ? L === 2 * c || L === 2 * r : w instanceof i;
  }
  function S(w, x, R = !0) {
    if (y(w))
      throw new Error("first arg must be private key");
    if (!y(x))
      throw new Error("second arg must be public key");
    return i.fromHex(x).multiply(s(w)).toRawBytes(R);
  }
  const A = a.bits2int || function(w) {
    const x = ie(w), R = w.length * 8 - a.nBitLength;
    return R > 0 ? x >> BigInt(R) : x;
  }, m = a.bits2int_modN || function(w) {
    return d(A(w));
  }, C = pn(a.nBitLength);
  function O(w) {
    if (typeof w != "bigint")
      throw new Error("bigint expected");
    if (!(me <= w && w < C))
      throw new Error(`bigint expected < 2^${a.nBitLength}`);
    return $t(w, a.nByteLength);
  }
  function T(w, x, R = k) {
    if (["recovered", "canonical"].some((nt) => nt in R))
      throw new Error("sign() legacy options not supported");
    const { hash: L, randomBytes: P } = a;
    let { lowS: Y, prehash: he, extraEntropy: se } = R;
    Y == null && (Y = !0), w = be("msgHash", w), he && (w = be("prehashed msgHash", L(w)));
    const ze = m(w), Me = s(x), xt = [O(Me), O(ze)];
    if (se != null) {
      const nt = se === !0 ? P(t.BYTES) : se;
      xt.push(be("extraEntropy", nt, t.BYTES));
    }
    const ea = zt(...xt), Ze = ze;
    function In(nt) {
      const At = A(nt);
      if (!u(At))
        return;
      const Or = o(At), St = i.BASE.multiply(At).toAffine(), we = d(St.x);
      if (we === me)
        return;
      const kt = d(Or * d(Ze + we * Me));
      if (kt === me)
        return;
      let Br = (St.x === we ? 0 : 2) | Number(St.y & Z), Rr = kt;
      return Y && _(kt) && (Rr = h(kt), Br ^= 1), new g(we, Rr, Br);
    }
    return { seed: ea, k2sig: In };
  }
  const k = { lowS: a.lowS, prehash: !1 }, z = { lowS: a.lowS, prehash: !1 };
  function U(w, x, R = k) {
    const { seed: L, k2sig: P } = T(w, x, R);
    return Gf(a.hash.outputLen, a.nByteLength, a.hmac)(L, P);
  }
  i.BASE._setWindowSize(8);
  function N(w, x, R, L = z) {
    var St;
    const P = w;
    if (x = be("msgHash", x), R = be("publicKey", R), "strict" in L)
      throw new Error("options.strict was renamed to lowS");
    const { lowS: Y, prehash: he } = L;
    let se, ze;
    try {
      if (typeof P == "string" || P instanceof Uint8Array)
        try {
          se = g.fromDER(P);
        } catch (we) {
          if (!(we instanceof Ke.Err))
            throw we;
          se = g.fromCompact(P);
        }
      else if (typeof P == "object" && typeof P.r == "bigint" && typeof P.s == "bigint") {
        const { r: we, s: kt } = P;
        se = new g(we, kt);
      } else
        throw new Error("PARSE");
      ze = i.fromHex(R);
    } catch (we) {
      if (we.message === "PARSE")
        throw new Error("signature must be Signature instance, Uint8Array or hex string");
      return !1;
    }
    if (Y && se.hasHighS())
      return !1;
    he && (x = a.hash(x));
    const { r: Me, s: xt } = se, ea = m(x), Ze = o(xt), In = d(ea * Ze), nt = d(Me * Ze), At = (St = i.BASE.multiplyAndAddUnsafe(ze, In, nt)) == null ? void 0 : St.toAffine();
    return At ? d(At.x) === Me : !1;
  }
  return {
    CURVE: a,
    getPublicKey: v,
    getSharedSecret: S,
    sign: U,
    verify: N,
    ProjectivePoint: i,
    Signature: g,
    utils: E
  };
}
function sd(e, a) {
  const t = e.ORDER;
  let n = me;
  for (let u = t - Z; u % Be === me; u /= Be)
    n += Z;
  const c = n, r = (t - Z) / Be ** c, f = (r - Z) / Be, d = Be ** c - Z, o = Be ** (c - Z), i = e.pow(a, r), s = e.pow(a, (r + Z) / Be);
  let b = (u, l) => {
    let _ = i, h = e.pow(l, d), p = e.sqr(h);
    p = e.mul(p, l);
    let g = e.mul(u, p);
    g = e.pow(g, f), g = e.mul(g, h), h = e.mul(g, l), p = e.mul(g, u);
    let E = e.mul(p, h);
    g = e.pow(E, o);
    let v = e.eql(g, e.ONE);
    h = e.mul(p, s), g = e.mul(E, _), p = e.cmov(h, p, v), E = e.cmov(g, E, v);
    for (let y = c; y > Z; y--) {
      let S = Be ** (y - Be), A = e.pow(E, S);
      const m = e.eql(A, e.ONE);
      h = e.mul(p, _), _ = e.mul(_, _), A = e.mul(E, _), p = e.cmov(h, p, m), E = e.cmov(A, E, m);
    }
    return { isValid: v, value: p };
  };
  if (e.ORDER % zr === Qa) {
    const u = (e.ORDER - Qa) / zr, l = e.sqrt(e.neg(a));
    b = (_, h) => {
      let p = e.sqr(h);
      const g = e.mul(_, h);
      p = e.mul(p, g);
      let E = e.pow(p, u);
      E = e.mul(E, g);
      const v = e.mul(E, l), y = e.mul(e.sqr(E), h), S = e.eql(y, _);
      let A = e.cmov(v, E, S);
      return { isValid: S, value: A };
    };
  }
  return b;
}
function Yo(e, a) {
  if (_n(e), !e.isValid(a.A) || !e.isValid(a.B) || !e.isValid(a.Z))
    throw new Error("mapToCurveSimpleSWU: invalid opts");
  const t = sd(e, a.Z);
  if (!e.isOdd)
    throw new Error("Fp.isOdd is not implemented!");
  return (n) => {
    let c, r, f, d, o, i, s, b;
    c = e.sqr(n), c = e.mul(c, a.Z), r = e.sqr(c), r = e.add(r, c), f = e.add(r, e.ONE), f = e.mul(f, a.B), d = e.cmov(a.Z, e.neg(r), !e.eql(r, e.ZERO)), d = e.mul(d, a.A), r = e.sqr(f), i = e.sqr(d), o = e.mul(i, a.A), r = e.add(r, o), r = e.mul(r, f), i = e.mul(i, d), o = e.mul(i, a.B), r = e.add(r, o), s = e.mul(c, f);
    const { isValid: u, value: l } = t(r, i);
    b = e.mul(c, n), b = e.mul(b, l), s = e.cmov(s, f, u), b = e.cmov(b, l, u);
    const _ = e.isOdd(n) === e.isOdd(b);
    return b = e.cmov(e.neg(b), b, _), s = e.div(s, d), { x: s, y: b };
  };
}
const Wo = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  DER: Ke,
  SWUFpSqrtRatio: sd,
  mapToCurveSimpleSWU: Yo,
  weierstrass: id,
  weierstrassPoints: dd
}, Symbol.toStringTag, { value: "Module" }));
function cc(e) {
  if (!Number.isSafeInteger(e) || e < 0)
    throw new Error(`Wrong positive integer: ${e}`);
}
function Xo(e) {
  if (typeof e != "boolean")
    throw new Error(`Expected boolean, not ${e}`);
}
function od(e, ...a) {
  if (!(e instanceof Uint8Array))
    throw new TypeError("Expected Uint8Array");
  if (a.length > 0 && !a.includes(e.length))
    throw new TypeError(`Expected Uint8Array of length ${a}, not of length=${e.length}`);
}
function Jo(e) {
  if (typeof e != "function" || typeof e.create != "function")
    throw new Error("Hash should be wrapped by utils.wrapConstructor");
  cc(e.outputLen), cc(e.blockLen);
}
function Qo(e, a = !0) {
  if (e.destroyed)
    throw new Error("Hash instance has been destroyed");
  if (a && e.finished)
    throw new Error("Hash#digest() has already been called");
}
function e0(e, a) {
  od(e);
  const t = a.outputLen;
  if (e.length < t)
    throw new Error(`digestInto() expects output buffer of length at least ${t}`);
}
const Pa = {
  number: cc,
  bool: Xo,
  bytes: od,
  hash: Jo,
  exists: Qo,
  output: e0
}, Rn = typeof globalThis == "object" && "crypto" in globalThis ? globalThis.crypto : void 0;
/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
const t0 = new Uint8Array(new Uint32Array([287454020]).buffer)[0] === 68;
if (!t0)
  throw new Error("Non little-endian hardware is not supported");
Array.from({ length: 256 }, (e, a) => a.toString(16).padStart(2, "0"));
function a0(e) {
  if (typeof e != "string")
    throw new TypeError(`utf8ToBytes expected string, got ${typeof e}`);
  return new TextEncoder().encode(e);
}
function n0(e) {
  if (typeof e == "string" && (e = a0(e)), !(e instanceof Uint8Array))
    throw new TypeError(`Expected input type is Uint8Array (got ${typeof e})`);
  return e;
}
function c0(...e) {
  if (!e.every((n) => n instanceof Uint8Array))
    throw new Error("Uint8Array list expected");
  if (e.length === 1)
    return e[0];
  const a = e.reduce((n, c) => n + c.length, 0), t = new Uint8Array(a);
  for (let n = 0, c = 0; n < e.length; n++) {
    const r = e[n];
    t.set(r, c), c += r.length;
  }
  return t;
}
class r0 {
  // Safe version that clones internal state
  clone() {
    return this._cloneInto();
  }
}
function f0(e = 32) {
  if (Rn && typeof Rn.getRandomValues == "function")
    return Rn.getRandomValues(new Uint8Array(e));
  throw new Error("crypto.getRandomValues must be defined");
}
class bd extends r0 {
  constructor(a, t) {
    super(), this.finished = !1, this.destroyed = !1, Pa.hash(a);
    const n = n0(t);
    if (this.iHash = a.create(), typeof this.iHash.update != "function")
      throw new TypeError("Expected instance of class which extends utils.Hash");
    this.blockLen = this.iHash.blockLen, this.outputLen = this.iHash.outputLen;
    const c = this.blockLen, r = new Uint8Array(c);
    r.set(n.length > c ? a.create().update(n).digest() : n);
    for (let f = 0; f < r.length; f++)
      r[f] ^= 54;
    this.iHash.update(r), this.oHash = a.create();
    for (let f = 0; f < r.length; f++)
      r[f] ^= 106;
    this.oHash.update(r), r.fill(0);
  }
  update(a) {
    return Pa.exists(this), this.iHash.update(a), this;
  }
  digestInto(a) {
    Pa.exists(this), Pa.bytes(a, this.outputLen), this.finished = !0, this.iHash.digestInto(a), this.oHash.update(a), this.oHash.digestInto(a), this.destroy();
  }
  digest() {
    const a = new Uint8Array(this.oHash.outputLen);
    return this.digestInto(a), a;
  }
  _cloneInto(a) {
    a || (a = Object.create(Object.getPrototypeOf(this), {}));
    const { oHash: t, iHash: n, finished: c, destroyed: r, blockLen: f, outputLen: d } = this;
    return a = a, a.finished = c, a.destroyed = r, a.blockLen = f, a.outputLen = d, a.oHash = t._cloneInto(a.oHash), a.iHash = n._cloneInto(a.iHash), a;
  }
  destroy() {
    this.destroyed = !0, this.oHash.destroy(), this.iHash.destroy();
  }
}
const ld = (e, a, t) => new bd(e, a).update(t).digest();
ld.create = (e, a) => new bd(e, a);
/*! noble-curves - MIT License (c) 2022 Paul Miller (paulmillr.com) */
function d0(e) {
  return {
    hash: e,
    hmac: (a, ...t) => ld(e, a, c0(...t)),
    randomBytes: f0
  };
}
const en = BigInt("3618502788666131213697322783095070105526743751716087489154079457884512865583"), ud = 252;
function Mr(e) {
  for (; e[0] === 0; )
    e = e.subarray(1);
  const a = e.length * 8 - ud, t = ie(e);
  return a > 0 ? t >> BigInt(a) : t;
}
function hd(e) {
  return typeof e == "string" && (e = Dc(e), e.length & 1 && (e = "0" + e)), He(e);
}
const Et = id({
  a: BigInt(1),
  b: BigInt("3141592653589793238462643383279502884197169399375105820974944592307816406665"),
  Fp: Oc(BigInt("0x800000000000011000000000000000000000000000000000000000000000001")),
  n: en,
  nBitLength: ud,
  Gx: BigInt("874739451078007766457464989774322083649278607533249481151382481072868806602"),
  Gy: BigInt("152666792071518830868575557812948353041420400780739481342941381225525861407"),
  h: BigInt(1),
  lowS: !1,
  ...d0(Ic),
  bits2int: Mr,
  bits2int_modN: (e) => {
    const a = ie(e).toString(16);
    return a.length === 63 && (e = hd(a + "0")), ae(Mr(e), en);
  }
}), i0 = Et;
function ut(e) {
  return be("", typeof e == "string" ? hd(e) : e);
}
function Bc(e) {
  return Je(ut(e)).padStart(64, "0");
}
function pd(e, a = !1) {
  return Et.getPublicKey(Bc(e), a);
}
function s0(e, a) {
  return Et.getSharedSecret(Bc(e), a);
}
function ca(e, a, t) {
  return Et.sign(ut(e), Bc(a), t);
}
function o0(e, a, t) {
  const n = e instanceof _d ? e : ut(e);
  return Et.verify(n, ut(a), ut(t));
}
const { CURVE: b0, ProjectivePoint: It, Signature: _d, utils: Rc } = Et;
function gd(e) {
  return `0x${Je(e.subarray(1)).replace(/^0+/gm, "")}`;
}
function Dc(e) {
  return e.replace(/^0x/i, "");
}
function l0(e) {
  return `0x${e.toString(16)}`;
}
function yd(e) {
  const a = ut(e), t = 2n ** 256n, n = t - ae(t, en);
  for (let c = 0; ; c++) {
    const r = rc(zt(a, kc(BigInt(c))));
    if (r < n)
      return ae(r, en).toString(16);
    if (c === 1e5)
      throw new Error("grindKey is broken: tried 100k vals");
  }
}
function Lc(e) {
  return gd(pd(e, !0));
}
function u0(e) {
  if (e = Dc(e), e.length !== 130)
    throw new Error("Wrong ethereum signature");
  return yd(e.substring(0, 64));
}
const h0 = 2n ** 31n - 1n, Ha = (e) => Number(e & h0);
function p0(e, a, t, n) {
  const c = Ha(rc(e)), r = Ha(rc(a)), f = hn(Dc(t));
  return `m/2645'/${c}'/${r}'/${Ha(f)}'/${Ha(f >> 31n)}'/${n}`;
}
const la = [
  new It(2089986280348253421170679821480865132823066470938446095505822317253594081284n, 1713931329540660377023406109199410414810705867260802078187082345529207694986n, 1n),
  new It(996781205833008774514500082376783249102396023663454813447423147977397232763n, 1668503676786377725805489344771023921079126552019160156920634619255970485781n, 1n),
  new It(2251563274489750535117886426533222435294046428347329203627021249169616184184n, 1798716007562728905295480679789526322175868328062420237419143593021674992973n, 1n),
  new It(2138414695194151160943305727036575959195309218611738193261179310511854807447n, 113410276730064486255102093846540133784865286929052426931474106396135072156n, 1n),
  new It(2379962749567351885752724891227938183011949129833673362440656643086021394946n, 776496453633298175483985398648758586525933812536653089401905292063708816422n, 1n)
];
function wd(e, a) {
  const t = [];
  let n = e;
  for (let c = 0; c < 248; c++)
    t.push(n), n = n.double();
  n = a;
  for (let c = 0; c < 4; c++)
    t.push(n), n = n.double();
  return t;
}
const _0 = wd(la[1], la[2]), g0 = wd(la[3], la[4]);
function md(e) {
  let a;
  if (typeof e == "bigint")
    a = e;
  else if (typeof e == "number") {
    if (!Number.isSafeInteger(e))
      throw new Error(`Invalid pedersenArg: ${e}`);
    a = BigInt(e);
  } else
    a = ie(ut(e));
  if (!(0n <= a && a < Et.CURVE.Fp.ORDER))
    throw new Error(`PedersenArg should be 0 <= value < CURVE.P: ${a}`);
  return a;
}
function Zr(e, a, t) {
  let n = md(a);
  for (let c = 0; c < 252; c++) {
    const r = t[c];
    if (r.equals(e))
      throw new Error("Same point");
    (n & 1n) !== 0n && (e = e.add(r)), n >>= 1n;
  }
  return e;
}
function Kt(e, a) {
  let t = la[0];
  return t = Zr(t, e, _0), t = Zr(t, a, g0), gd(t.toRawBytes(!0));
}
function y0(e, a = Kt) {
  if (!Array.isArray(e) || e.length < 1)
    throw new Error("data should be array of at least 1 element");
  return e.length === 1 ? l0(md(e[0])) : Array.from(e).reverse().reduce((t, n) => a(n, t));
}
const w0 = (e, a = Kt) => [0, ...e, e.length].reduce((t, n) => a(t, n)), m0 = pn(250), Aa = (e) => ie(To(e)) & m0, rc = (e) => ie(Ic(e)), E0 = Oc(BigInt("14474011154664525231415395255581126252639794253786371766033694892385558855681")), Ed = Oc(BigInt("3618502788666131213697322783095070105623107215331596699973092056135872020481"));
function fc(e, a, t) {
  const n = e.fromBytes(Ic(Xf(`${a}${t}`)));
  return e.create(n);
}
function vd(e, a, t, n = 0) {
  const c = [], r = [];
  for (let f = 0; f < t; f++)
    c.push(fc(e, `${a}x`, n * t + f)), r.push(fc(e, `${a}y`, n * t + f));
  if ((/* @__PURE__ */ new Set([...c, ...r])).size !== 2 * t)
    throw new Error("X and Y values are not distinct");
  return c.map((f) => r.map((d) => e.inv(e.sub(f, d))));
}
const v0 = [
  [3, 1, 1],
  [1, -1, 1],
  [1, 1, -2]
].map((e) => e.map(BigInt));
function $c(e, a) {
  if (_n(e.Fp), !Number.isSafeInteger(e.rate) || !Number.isSafeInteger(e.capacity))
    throw new Error(`Wrong poseidon opts: ${e}`);
  const t = e.rate + e.capacity, n = e.roundsFull + e.roundsPartial, c = [];
  for (let f = 0; f < n; f++) {
    const d = [];
    for (let o = 0; o < t; o++)
      d.push(fc(e.Fp, "Hades", t * f + o));
    c.push(d);
  }
  const r = rd({
    ...e,
    t,
    sboxPower: 3,
    reversePartialPowIdx: !0,
    mds: a,
    roundConstants: c
  });
  return r.m = t, r.rate = e.rate, r.capacity = e.capacity, r;
}
function x0(e, a = 0) {
  const t = e.rate + e.capacity;
  if (!Number.isSafeInteger(a))
    throw new Error(`Wrong mdsAttempt=${a}`);
  return $c(e, vd(e.Fp, "HadesMDS", t, a));
}
const Sa = $c({ Fp: Ed, rate: 2, capacity: 1, roundsFull: 8, roundsPartial: 83 }, v0);
function xd(e, a, t = Sa) {
  return t([e, a, 2n])[0];
}
function A0(e, a, t = Sa) {
  return kc(xd(ie(e), ie(a), t));
}
function S0(e, a = Sa) {
  return a([e, 0n, 1n])[0];
}
function Qe(e, a = Sa) {
  const { m: t, rate: n } = a;
  if (!Array.isArray(e))
    throw new Error("bigint array expected in values");
  const c = Array.from(e);
  for (c.push(1n); c.length % n !== 0; )
    c.push(0n);
  let r = new Array(t).fill(0n);
  for (let f = 0; f < c.length; f += n) {
    for (let d = 0; d < n; d++)
      r[d] += c[f + d];
    r = a(r);
  }
  return r[0];
}
const k0 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  CURVE: b0,
  Fp251: Ed,
  Fp253: E0,
  ProjectivePoint: It,
  Signature: _d,
  _poseidonMDS: vd,
  _starkCurve: i0,
  computeHashOnElements: w0,
  ethSigToPrivate: u0,
  getAccountPath: p0,
  getPublicKey: pd,
  getSharedSecret: s0,
  getStarkKey: Lc,
  grindKey: yd,
  hashChain: y0,
  keccak: Aa,
  pedersen: Kt,
  poseidonBasic: $c,
  poseidonCreate: x0,
  poseidonHash: xd,
  poseidonHashFunc: A0,
  poseidonHashMany: Qe,
  poseidonHashSingle: S0,
  poseidonSmall: Sa,
  sign: ca,
  utils: Rc,
  verify: o0
}, Symbol.toStringTag, { value: "Module" }));
function ka(e) {
  return T0.test(e);
}
var T0 = /^-?[0-9]+$/;
function Ad(e) {
  return C0.test(e);
}
var C0 = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?$/;
function I0(e, a) {
  var t = parseFloat(e), n = String(t), c = Vr(e), r = Vr(n);
  if (c === r)
    return !0;
  if ((a == null ? void 0 : a.approx) === !0) {
    var f = 14;
    if (!ka(e) && r.length >= f && c.startsWith(r.substring(0, f)))
      return !0;
  }
  return !1;
}
var ra = /* @__PURE__ */ function(e) {
  return e.underflow = "underflow", e.overflow = "overflow", e.truncate_integer = "truncate_integer", e.truncate_float = "truncate_float", e;
}({});
function N0(e) {
  if (!I0(e, {
    approx: !1
  })) {
    if (ka(e))
      return ra.truncate_integer;
    var a = parseFloat(e);
    return isFinite(a) ? a === 0 ? ra.underflow : ra.truncate_float : ra.overflow;
  }
}
function Vr(e) {
  return e.replace(O0, "").replace(R0, "").replace(D0, "").replace(B0, "");
}
var O0 = /[eE][+-]?\d+$/, B0 = /^-?(0*)?/, R0 = /\./, D0 = /0+$/;
function Mt(e) {
  "@babel/helpers - typeof";
  return Mt = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(a) {
    return typeof a;
  } : function(a) {
    return a && typeof Symbol == "function" && a.constructor === Symbol && a !== Symbol.prototype ? "symbol" : typeof a;
  }, Mt(e);
}
function L0(e, a) {
  if (!(e instanceof a))
    throw new TypeError("Cannot call a class as a function");
}
function jr(e, a) {
  for (var t = 0; t < a.length; t++) {
    var n = a[t];
    n.enumerable = n.enumerable || !1, n.configurable = !0, "value" in n && (n.writable = !0), Object.defineProperty(e, Sd(n.key), n);
  }
}
function $0(e, a, t) {
  return a && jr(e.prototype, a), t && jr(e, t), Object.defineProperty(e, "prototype", { writable: !1 }), e;
}
function P0(e, a, t) {
  return a = Sd(a), a in e ? Object.defineProperty(e, a, { value: t, enumerable: !0, configurable: !0, writable: !0 }) : e[a] = t, e;
}
function Sd(e) {
  var a = H0(e, "string");
  return Mt(a) === "symbol" ? a : String(a);
}
function H0(e, a) {
  if (Mt(e) !== "object" || e === null)
    return e;
  var t = e[Symbol.toPrimitive];
  if (t !== void 0) {
    var n = t.call(e, a || "default");
    if (Mt(n) !== "object")
      return n;
    throw new TypeError("@@toPrimitive must return a primitive value.");
  }
  return (a === "string" ? String : Number)(e);
}
var U0 = /* @__PURE__ */ function() {
  function e(a) {
    if (L0(this, e), P0(this, "isLosslessNumber", !0), !Ad(a))
      throw new Error('Invalid number (value: "' + a + '")');
    this.value = a;
  }
  return $0(e, [{
    key: "valueOf",
    value: function() {
      var t = N0(this.value);
      if (t === void 0 || t === ra.truncate_float)
        return parseFloat(this.value);
      if (ka(this.value))
        return BigInt(this.value);
      throw new Error("Cannot safely convert to number: " + "the value '".concat(this.value, "' would ").concat(t, " and become ").concat(parseFloat(this.value)));
    }
    /**
     * Get the value of the LosslessNumber as string.
     */
  }, {
    key: "toString",
    value: function() {
      return this.value;
    }
    // Note: we do NOT implement a .toJSON() method, and you should not implement
    // or use that, it cannot safely turn the numeric value in the string into
    // stringified JSON since it has to be parsed into a number first.
  }]), e;
}();
function F0(e) {
  return e && Mt(e) === "object" && e.isLosslessNumber === !0 || !1;
}
function z0(e) {
  return new U0(e);
}
function M0(e) {
  return ka(e) ? BigInt(e) : parseFloat(e);
}
function dc(e) {
  "@babel/helpers - typeof";
  return dc = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(a) {
    return typeof a;
  } : function(a) {
    return a && typeof Symbol == "function" && a.constructor === Symbol && a !== Symbol.prototype ? "symbol" : typeof a;
  }, dc(e);
}
function Z0(e, a) {
  return Pc({
    "": e
  }, "", e, a);
}
function Pc(e, a, t, n) {
  return Array.isArray(t) ? n.call(e, a, j0(t, n)) : t && dc(t) === "object" && !F0(t) ? n.call(e, a, V0(t, n)) : n.call(e, a, t);
}
function V0(e, a) {
  return Object.keys(e).forEach(function(t) {
    var n = Pc(e, t, e[t], a);
    n !== void 0 ? e[t] = n : delete e[t];
  }), e;
}
function j0(e, a) {
  for (var t = 0; t < e.length; t++)
    e[t] = Pc(e, t + "", e[t], a);
  return e;
}
function ic(e) {
  "@babel/helpers - typeof";
  return ic = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(a) {
    return typeof a;
  } : function(a) {
    return a && typeof Symbol == "function" && a.constructor === Symbol && a !== Symbol.prototype ? "symbol" : typeof a;
  }, ic(e);
}
function Dn(e) {
  return Y0(e) || G0(e) || K0(e) || q0();
}
function q0() {
  throw new TypeError(`Invalid attempt to spread non-iterable instance.
In order to be iterable, non-array objects must have a [Symbol.iterator]() method.`);
}
function K0(e, a) {
  if (e) {
    if (typeof e == "string")
      return sc(e, a);
    var t = Object.prototype.toString.call(e).slice(8, -1);
    if (t === "Object" && e.constructor && (t = e.constructor.name), t === "Map" || t === "Set")
      return Array.from(e);
    if (t === "Arguments" || /^(?:Ui|I)nt(?:8|16|32)(?:Clamped)?Array$/.test(t))
      return sc(e, a);
  }
}
function G0(e) {
  if (typeof Symbol < "u" && e[Symbol.iterator] != null || e["@@iterator"] != null)
    return Array.from(e);
}
function Y0(e) {
  if (Array.isArray(e))
    return sc(e);
}
function sc(e, a) {
  (a == null || a > e.length) && (a = e.length);
  for (var t = 0, n = new Array(a); t < a; t++)
    n[t] = e[t];
  return n;
}
function kd(e, a) {
  var t = arguments.length > 2 && arguments[2] !== void 0 ? arguments[2] : z0, n = 0, c = d();
  return _(c), p(), a ? Z0(c, a) : c;
  function r() {
    if (e.charCodeAt(n) === t1) {
      n++, i();
      for (var N = {}, w = !0; n < e.length && e.charCodeAt(n) !== Kr; ) {
        w ? w = !1 : (u(), i());
        var x = n, R = s();
        R === void 0 && v(), i(), l();
        var L = d();
        L === void 0 && O(), Object.prototype.hasOwnProperty.call(N, R) && !oc(L, N[R]) && y(R, x + 1), N[R] = L;
      }
      return e.charCodeAt(n) !== Kr && S(), n++, N;
    }
  }
  function f() {
    if (e.charCodeAt(n) === a1) {
      n++, i();
      for (var N = [], w = !0; n < e.length && e.charCodeAt(n) !== Gr; ) {
        w ? w = !1 : u();
        var x = d();
        h(x), N.push(x);
      }
      return e.charCodeAt(n) !== Gr && A(), n++, N;
    }
  }
  function d() {
    var N, w, x, R, L, P;
    i();
    var Y = (N = (w = (x = (R = (L = (P = s()) !== null && P !== void 0 ? P : b()) !== null && L !== void 0 ? L : r()) !== null && R !== void 0 ? R : f()) !== null && x !== void 0 ? x : o("true", !0)) !== null && w !== void 0 ? w : o("false", !1)) !== null && N !== void 0 ? N : o("null", null);
    return i(), Y;
  }
  function o(N, w) {
    if (e.slice(n, n + N.length) === N)
      return n += N.length, w;
  }
  function i() {
    for (; W0(e.charCodeAt(n)); )
      n++;
  }
  function s() {
    if (e.charCodeAt(n) === Ln) {
      n++;
      for (var N = ""; n < e.length && e.charCodeAt(n) !== Ln; ) {
        if (e.charCodeAt(n) === e1) {
          var w = e[n + 1], x = Q0[w];
          x !== void 0 ? (N += x, n++) : w === "u" ? Ua(e.charCodeAt(n + 2)) && Ua(e.charCodeAt(n + 3)) && Ua(e.charCodeAt(n + 4)) && Ua(e.charCodeAt(n + 5)) ? (N += String.fromCharCode(parseInt(e.slice(n + 2, n + 6), 16)), n += 5) : T(n) : C(n);
        } else
          J0(e.charCodeAt(n)) ? N += e[n] : m(e[n]);
        n++;
      }
      return E(), n++, N;
    }
  }
  function b() {
    var N = n;
    if (e.charCodeAt(n) === Yr && (n++, g(N)), e.charCodeAt(n) === Hc)
      n++;
    else if (X0(e.charCodeAt(n)))
      for (n++; Fa(e.charCodeAt(n)); )
        n++;
    if (e.charCodeAt(n) === o1)
      for (n++, g(N); Fa(e.charCodeAt(n)); )
        n++;
    if (e.charCodeAt(n) === p1 || e.charCodeAt(n) === h1)
      for (n++, (e.charCodeAt(n) === Yr || e.charCodeAt(n) === d1) && n++, g(N); Fa(e.charCodeAt(n)); )
        n++;
    if (n > N)
      return t(e.slice(N, n));
  }
  function u() {
    if (e.charCodeAt(n) !== s1)
      throw new SyntaxError("Comma ',' expected after value ".concat(U()));
    n++;
  }
  function l() {
    if (e.charCodeAt(n) !== b1)
      throw new SyntaxError("Colon ':' expected after property name ".concat(U()));
    n++;
  }
  function _(N) {
    if (N === void 0)
      throw new SyntaxError("JSON value expected ".concat(U()));
  }
  function h(N) {
    if (N === void 0)
      throw new SyntaxError("Array item expected ".concat(U()));
  }
  function p() {
    if (n < e.length)
      throw new SyntaxError("Expected end of input ".concat(U()));
  }
  function g(N) {
    if (!Fa(e.charCodeAt(n))) {
      var w = e.slice(N, n);
      throw new SyntaxError("Invalid number '".concat(w, "', expecting a digit ").concat(U()));
    }
  }
  function E() {
    if (e.charCodeAt(n) !== Ln)
      throw new SyntaxError(`End of string '"' expected `.concat(U()));
  }
  function v() {
    throw new SyntaxError("Quoted object key expected ".concat(U()));
  }
  function y(N, w) {
    throw new SyntaxError("Duplicate key '".concat(N, "' encountered at position ").concat(w));
  }
  function S() {
    throw new SyntaxError("Quoted object key or end of object '}' expected ".concat(U()));
  }
  function A() {
    throw new SyntaxError("Array item or end of array ']' expected ".concat(U()));
  }
  function m(N) {
    throw new SyntaxError("Invalid character '".concat(N, "' ").concat(k()));
  }
  function C(N) {
    var w = e.slice(N, N + 2);
    throw new SyntaxError("Invalid escape character '".concat(w, "' ").concat(k()));
  }
  function O() {
    throw new SyntaxError("Object value expected after ':' ".concat(k()));
  }
  function T(N) {
    for (var w = N + 2; /\w/.test(e[w]); )
      w++;
    var x = e.slice(N, w);
    throw new SyntaxError("Invalid unicode character '".concat(x, "' ").concat(k()));
  }
  function k() {
    return "at position ".concat(n);
  }
  function z() {
    return n < e.length ? "but got '".concat(e[n], "'") : "but reached end of input";
  }
  function U() {
    return z() + " " + k();
  }
}
function W0(e) {
  return e === n1 || e === c1 || e === r1 || e === f1;
}
function Ua(e) {
  return e >= Hc && e <= Uc || e >= l1 && e <= _1 || e >= u1 && e <= g1;
}
function Fa(e) {
  return e >= Hc && e <= Uc;
}
function X0(e) {
  return e >= i1 && e <= Uc;
}
function J0(e) {
  return e >= 32 && e <= 1114111;
}
function oc(e, a) {
  if (e === a)
    return !0;
  if (Array.isArray(e) && Array.isArray(a))
    return e.length === a.length && e.every(function(n, c) {
      return oc(n, a[c]);
    });
  if (qr(e) && qr(a)) {
    var t = Dn(new Set([].concat(Dn(Object.keys(e)), Dn(Object.keys(a)))));
    return t.every(function(n) {
      return oc(e[n], a[n]);
    });
  }
  return !1;
}
function qr(e) {
  return ic(e) === "object" && e !== null;
}
var Q0 = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: `
`,
  r: "\r",
  t: "	"
  // note that \u is handled separately in parseString()
}, e1 = 92, t1 = 123, Kr = 125, a1 = 91, Gr = 93, n1 = 32, c1 = 10, r1 = 9, f1 = 13, Ln = 34, d1 = 43, Yr = 45, Hc = 48, i1 = 49, Uc = 57, s1 = 44, o1 = 46, b1 = 58, l1 = 65, u1 = 97, h1 = 69, p1 = 101, _1 = 70, g1 = 102;
function tn(e) {
  "@babel/helpers - typeof";
  return tn = typeof Symbol == "function" && typeof Symbol.iterator == "symbol" ? function(a) {
    return typeof a;
  } : function(a) {
    return a && typeof Symbol == "function" && a.constructor === Symbol && a !== Symbol.prototype ? "symbol" : typeof a;
  }, tn(e);
}
function Td(e, a, t, n) {
  var c = y1(t), r = typeof a == "function" ? a.call({
    "": e
  }, "", e) : e;
  return f(r, "");
  function f(s, b) {
    if (Array.isArray(n)) {
      var u = n.find(function(_) {
        return _.test(s);
      });
      if (u) {
        var l = u.stringify(s);
        if (typeof l != "string" || !Ad(l))
          throw new Error("Invalid JSON number: output of a number stringifier must be a string containing a JSON number " + "(output: ".concat(l, ")"));
        return l;
      }
    }
    if (typeof s == "boolean" || typeof s == "number" || typeof s == "string" || s === null || s instanceof Date || s instanceof Boolean || s instanceof Number || s instanceof String)
      return JSON.stringify(s);
    if (s && s.isLosslessNumber || typeof s == "bigint")
      return s.toString();
    if (Array.isArray(s))
      return d(s, b);
    if (s && tn(s) === "object")
      return o(s, b);
  }
  function d(s, b) {
    if (s.length === 0)
      return "[]";
    for (var u = c ? b + c : void 0, l = c ? `[
` : "[", _ = 0; _ < s.length; _++) {
      var h = typeof a == "function" ? a.call(s, String(_), s[_]) : s[_];
      c && (l += u), typeof h < "u" && typeof h != "function" ? l += f(h, u) : l += "null", _ < s.length - 1 && (l += c ? `,
` : ",");
    }
    return l += c ? `
` + b + "]" : "]", l;
  }
  function o(s, b) {
    if (typeof s.toJSON == "function")
      return Td(s.toJSON(), a, t, void 0);
    var u = Array.isArray(a) ? a.map(String) : Object.keys(s);
    if (u.length === 0)
      return "{}";
    var l = c ? b + c : void 0, _ = !0, h = c ? `{
` : "{";
    return u.forEach(function(p) {
      var g = typeof a == "function" ? a.call(s, p, s[p]) : s[p];
      if (i(p, g)) {
        _ ? _ = !1 : h += c ? `,
` : ",";
        var E = JSON.stringify(p);
        h += c ? l + E + ": " : E + ":", h += f(g, l);
      }
    }), h += c ? `
` + b + "}" : "}", h;
  }
  function i(s, b) {
    return typeof b < "u" && typeof b != "function" && tn(b) !== "symbol";
  }
}
function y1(e) {
  if (typeof e == "number")
    return " ".repeat(e);
  if (typeof e == "string" && e !== "")
    return e;
}
/*! pako 2.1.0 https://github.com/nodeca/pako @license (MIT AND Zlib) */
const w1 = 4, Wr = 0, Xr = 1, m1 = 2;
function Gt(e) {
  let a = e.length;
  for (; --a >= 0; )
    e[a] = 0;
}
const E1 = 0, Cd = 1, v1 = 2, x1 = 3, A1 = 258, Fc = 29, Ta = 256, ua = Ta + 1 + Fc, Pt = 30, zc = 19, Id = 2 * ua + 1, it = 15, $n = 16, S1 = 7, Mc = 256, Nd = 16, Od = 17, Bd = 18, bc = (
  /* extra bits for each length code */
  new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0])
), Ka = (
  /* extra bits for each distance code */
  new Uint8Array([0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13])
), k1 = (
  /* extra bits for each bit length code */
  new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 3, 7])
), Rd = new Uint8Array([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]), T1 = 512, De = new Array((ua + 2) * 2);
Gt(De);
const ia = new Array(Pt * 2);
Gt(ia);
const ha = new Array(T1);
Gt(ha);
const pa = new Array(A1 - x1 + 1);
Gt(pa);
const Zc = new Array(Fc);
Gt(Zc);
const an = new Array(Pt);
Gt(an);
function Pn(e, a, t, n, c) {
  this.static_tree = e, this.extra_bits = a, this.extra_base = t, this.elems = n, this.max_length = c, this.has_stree = e && e.length;
}
let Dd, Ld, $d;
function Hn(e, a) {
  this.dyn_tree = e, this.max_code = 0, this.stat_desc = a;
}
const Pd = (e) => e < 256 ? ha[e] : ha[256 + (e >>> 7)], _a = (e, a) => {
  e.pending_buf[e.pending++] = a & 255, e.pending_buf[e.pending++] = a >>> 8 & 255;
}, de = (e, a, t) => {
  e.bi_valid > $n - t ? (e.bi_buf |= a << e.bi_valid & 65535, _a(e, e.bi_buf), e.bi_buf = a >> $n - e.bi_valid, e.bi_valid += t - $n) : (e.bi_buf |= a << e.bi_valid & 65535, e.bi_valid += t);
}, Se = (e, a, t) => {
  de(
    e,
    t[a * 2],
    t[a * 2 + 1]
    /*.Len*/
  );
}, Hd = (e, a) => {
  let t = 0;
  do
    t |= e & 1, e >>>= 1, t <<= 1;
  while (--a > 0);
  return t >>> 1;
}, C1 = (e) => {
  e.bi_valid === 16 ? (_a(e, e.bi_buf), e.bi_buf = 0, e.bi_valid = 0) : e.bi_valid >= 8 && (e.pending_buf[e.pending++] = e.bi_buf & 255, e.bi_buf >>= 8, e.bi_valid -= 8);
}, I1 = (e, a) => {
  const t = a.dyn_tree, n = a.max_code, c = a.stat_desc.static_tree, r = a.stat_desc.has_stree, f = a.stat_desc.extra_bits, d = a.stat_desc.extra_base, o = a.stat_desc.max_length;
  let i, s, b, u, l, _, h = 0;
  for (u = 0; u <= it; u++)
    e.bl_count[u] = 0;
  for (t[e.heap[e.heap_max] * 2 + 1] = 0, i = e.heap_max + 1; i < Id; i++)
    s = e.heap[i], u = t[t[s * 2 + 1] * 2 + 1] + 1, u > o && (u = o, h++), t[s * 2 + 1] = u, !(s > n) && (e.bl_count[u]++, l = 0, s >= d && (l = f[s - d]), _ = t[s * 2], e.opt_len += _ * (u + l), r && (e.static_len += _ * (c[s * 2 + 1] + l)));
  if (h !== 0) {
    do {
      for (u = o - 1; e.bl_count[u] === 0; )
        u--;
      e.bl_count[u]--, e.bl_count[u + 1] += 2, e.bl_count[o]--, h -= 2;
    } while (h > 0);
    for (u = o; u !== 0; u--)
      for (s = e.bl_count[u]; s !== 0; )
        b = e.heap[--i], !(b > n) && (t[b * 2 + 1] !== u && (e.opt_len += (u - t[b * 2 + 1]) * t[b * 2], t[b * 2 + 1] = u), s--);
  }
}, Ud = (e, a, t) => {
  const n = new Array(it + 1);
  let c = 0, r, f;
  for (r = 1; r <= it; r++)
    c = c + t[r - 1] << 1, n[r] = c;
  for (f = 0; f <= a; f++) {
    let d = e[f * 2 + 1];
    d !== 0 && (e[f * 2] = Hd(n[d]++, d));
  }
}, N1 = () => {
  let e, a, t, n, c;
  const r = new Array(it + 1);
  for (t = 0, n = 0; n < Fc - 1; n++)
    for (Zc[n] = t, e = 0; e < 1 << bc[n]; e++)
      pa[t++] = n;
  for (pa[t - 1] = n, c = 0, n = 0; n < 16; n++)
    for (an[n] = c, e = 0; e < 1 << Ka[n]; e++)
      ha[c++] = n;
  for (c >>= 7; n < Pt; n++)
    for (an[n] = c << 7, e = 0; e < 1 << Ka[n] - 7; e++)
      ha[256 + c++] = n;
  for (a = 0; a <= it; a++)
    r[a] = 0;
  for (e = 0; e <= 143; )
    De[e * 2 + 1] = 8, e++, r[8]++;
  for (; e <= 255; )
    De[e * 2 + 1] = 9, e++, r[9]++;
  for (; e <= 279; )
    De[e * 2 + 1] = 7, e++, r[7]++;
  for (; e <= 287; )
    De[e * 2 + 1] = 8, e++, r[8]++;
  for (Ud(De, ua + 1, r), e = 0; e < Pt; e++)
    ia[e * 2 + 1] = 5, ia[e * 2] = Hd(e, 5);
  Dd = new Pn(De, bc, Ta + 1, ua, it), Ld = new Pn(ia, Ka, 0, Pt, it), $d = new Pn(new Array(0), k1, 0, zc, S1);
}, Fd = (e) => {
  let a;
  for (a = 0; a < ua; a++)
    e.dyn_ltree[a * 2] = 0;
  for (a = 0; a < Pt; a++)
    e.dyn_dtree[a * 2] = 0;
  for (a = 0; a < zc; a++)
    e.bl_tree[a * 2] = 0;
  e.dyn_ltree[Mc * 2] = 1, e.opt_len = e.static_len = 0, e.sym_next = e.matches = 0;
}, zd = (e) => {
  e.bi_valid > 8 ? _a(e, e.bi_buf) : e.bi_valid > 0 && (e.pending_buf[e.pending++] = e.bi_buf), e.bi_buf = 0, e.bi_valid = 0;
}, Jr = (e, a, t, n) => {
  const c = a * 2, r = t * 2;
  return e[c] < e[r] || e[c] === e[r] && n[a] <= n[t];
}, Un = (e, a, t) => {
  const n = e.heap[t];
  let c = t << 1;
  for (; c <= e.heap_len && (c < e.heap_len && Jr(a, e.heap[c + 1], e.heap[c], e.depth) && c++, !Jr(a, n, e.heap[c], e.depth)); )
    e.heap[t] = e.heap[c], t = c, c <<= 1;
  e.heap[t] = n;
}, Qr = (e, a, t) => {
  let n, c, r = 0, f, d;
  if (e.sym_next !== 0)
    do
      n = e.pending_buf[e.sym_buf + r++] & 255, n += (e.pending_buf[e.sym_buf + r++] & 255) << 8, c = e.pending_buf[e.sym_buf + r++], n === 0 ? Se(e, c, a) : (f = pa[c], Se(e, f + Ta + 1, a), d = bc[f], d !== 0 && (c -= Zc[f], de(e, c, d)), n--, f = Pd(n), Se(e, f, t), d = Ka[f], d !== 0 && (n -= an[f], de(e, n, d)));
    while (r < e.sym_next);
  Se(e, Mc, a);
}, lc = (e, a) => {
  const t = a.dyn_tree, n = a.stat_desc.static_tree, c = a.stat_desc.has_stree, r = a.stat_desc.elems;
  let f, d, o = -1, i;
  for (e.heap_len = 0, e.heap_max = Id, f = 0; f < r; f++)
    t[f * 2] !== 0 ? (e.heap[++e.heap_len] = o = f, e.depth[f] = 0) : t[f * 2 + 1] = 0;
  for (; e.heap_len < 2; )
    i = e.heap[++e.heap_len] = o < 2 ? ++o : 0, t[i * 2] = 1, e.depth[i] = 0, e.opt_len--, c && (e.static_len -= n[i * 2 + 1]);
  for (a.max_code = o, f = e.heap_len >> 1; f >= 1; f--)
    Un(e, t, f);
  i = r;
  do
    f = e.heap[
      1
      /*SMALLEST*/
    ], e.heap[
      1
      /*SMALLEST*/
    ] = e.heap[e.heap_len--], Un(
      e,
      t,
      1
      /*SMALLEST*/
    ), d = e.heap[
      1
      /*SMALLEST*/
    ], e.heap[--e.heap_max] = f, e.heap[--e.heap_max] = d, t[i * 2] = t[f * 2] + t[d * 2], e.depth[i] = (e.depth[f] >= e.depth[d] ? e.depth[f] : e.depth[d]) + 1, t[f * 2 + 1] = t[d * 2 + 1] = i, e.heap[
      1
      /*SMALLEST*/
    ] = i++, Un(
      e,
      t,
      1
      /*SMALLEST*/
    );
  while (e.heap_len >= 2);
  e.heap[--e.heap_max] = e.heap[
    1
    /*SMALLEST*/
  ], I1(e, a), Ud(t, o, e.bl_count);
}, ef = (e, a, t) => {
  let n, c = -1, r, f = a[0 * 2 + 1], d = 0, o = 7, i = 4;
  for (f === 0 && (o = 138, i = 3), a[(t + 1) * 2 + 1] = 65535, n = 0; n <= t; n++)
    r = f, f = a[(n + 1) * 2 + 1], !(++d < o && r === f) && (d < i ? e.bl_tree[r * 2] += d : r !== 0 ? (r !== c && e.bl_tree[r * 2]++, e.bl_tree[Nd * 2]++) : d <= 10 ? e.bl_tree[Od * 2]++ : e.bl_tree[Bd * 2]++, d = 0, c = r, f === 0 ? (o = 138, i = 3) : r === f ? (o = 6, i = 3) : (o = 7, i = 4));
}, tf = (e, a, t) => {
  let n, c = -1, r, f = a[0 * 2 + 1], d = 0, o = 7, i = 4;
  for (f === 0 && (o = 138, i = 3), n = 0; n <= t; n++)
    if (r = f, f = a[(n + 1) * 2 + 1], !(++d < o && r === f)) {
      if (d < i)
        do
          Se(e, r, e.bl_tree);
        while (--d !== 0);
      else
        r !== 0 ? (r !== c && (Se(e, r, e.bl_tree), d--), Se(e, Nd, e.bl_tree), de(e, d - 3, 2)) : d <= 10 ? (Se(e, Od, e.bl_tree), de(e, d - 3, 3)) : (Se(e, Bd, e.bl_tree), de(e, d - 11, 7));
      d = 0, c = r, f === 0 ? (o = 138, i = 3) : r === f ? (o = 6, i = 3) : (o = 7, i = 4);
    }
}, O1 = (e) => {
  let a;
  for (ef(e, e.dyn_ltree, e.l_desc.max_code), ef(e, e.dyn_dtree, e.d_desc.max_code), lc(e, e.bl_desc), a = zc - 1; a >= 3 && e.bl_tree[Rd[a] * 2 + 1] === 0; a--)
    ;
  return e.opt_len += 3 * (a + 1) + 5 + 5 + 4, a;
}, B1 = (e, a, t, n) => {
  let c;
  for (de(e, a - 257, 5), de(e, t - 1, 5), de(e, n - 4, 4), c = 0; c < n; c++)
    de(e, e.bl_tree[Rd[c] * 2 + 1], 3);
  tf(e, e.dyn_ltree, a - 1), tf(e, e.dyn_dtree, t - 1);
}, R1 = (e) => {
  let a = 4093624447, t;
  for (t = 0; t <= 31; t++, a >>>= 1)
    if (a & 1 && e.dyn_ltree[t * 2] !== 0)
      return Wr;
  if (e.dyn_ltree[9 * 2] !== 0 || e.dyn_ltree[10 * 2] !== 0 || e.dyn_ltree[13 * 2] !== 0)
    return Xr;
  for (t = 32; t < Ta; t++)
    if (e.dyn_ltree[t * 2] !== 0)
      return Xr;
  return Wr;
};
let af = !1;
const D1 = (e) => {
  af || (N1(), af = !0), e.l_desc = new Hn(e.dyn_ltree, Dd), e.d_desc = new Hn(e.dyn_dtree, Ld), e.bl_desc = new Hn(e.bl_tree, $d), e.bi_buf = 0, e.bi_valid = 0, Fd(e);
}, Md = (e, a, t, n) => {
  de(e, (E1 << 1) + (n ? 1 : 0), 3), zd(e), _a(e, t), _a(e, ~t), t && e.pending_buf.set(e.window.subarray(a, a + t), e.pending), e.pending += t;
}, L1 = (e) => {
  de(e, Cd << 1, 3), Se(e, Mc, De), C1(e);
}, $1 = (e, a, t, n) => {
  let c, r, f = 0;
  e.level > 0 ? (e.strm.data_type === m1 && (e.strm.data_type = R1(e)), lc(e, e.l_desc), lc(e, e.d_desc), f = O1(e), c = e.opt_len + 3 + 7 >>> 3, r = e.static_len + 3 + 7 >>> 3, r <= c && (c = r)) : c = r = t + 5, t + 4 <= c && a !== -1 ? Md(e, a, t, n) : e.strategy === w1 || r === c ? (de(e, (Cd << 1) + (n ? 1 : 0), 3), Qr(e, De, ia)) : (de(e, (v1 << 1) + (n ? 1 : 0), 3), B1(e, e.l_desc.max_code + 1, e.d_desc.max_code + 1, f + 1), Qr(e, e.dyn_ltree, e.dyn_dtree)), Fd(e), n && zd(e);
}, P1 = (e, a, t) => (e.pending_buf[e.sym_buf + e.sym_next++] = a, e.pending_buf[e.sym_buf + e.sym_next++] = a >> 8, e.pending_buf[e.sym_buf + e.sym_next++] = t, a === 0 ? e.dyn_ltree[t * 2]++ : (e.matches++, a--, e.dyn_ltree[(pa[t] + Ta + 1) * 2]++, e.dyn_dtree[Pd(a) * 2]++), e.sym_next === e.sym_end);
var H1 = D1, U1 = Md, F1 = $1, z1 = P1, M1 = L1, Z1 = {
  _tr_init: H1,
  _tr_stored_block: U1,
  _tr_flush_block: F1,
  _tr_tally: z1,
  _tr_align: M1
};
const V1 = (e, a, t, n) => {
  let c = e & 65535 | 0, r = e >>> 16 & 65535 | 0, f = 0;
  for (; t !== 0; ) {
    f = t > 2e3 ? 2e3 : t, t -= f;
    do
      c = c + a[n++] | 0, r = r + c | 0;
    while (--f);
    c %= 65521, r %= 65521;
  }
  return c | r << 16 | 0;
};
var ga = V1;
const j1 = () => {
  let e, a = [];
  for (var t = 0; t < 256; t++) {
    e = t;
    for (var n = 0; n < 8; n++)
      e = e & 1 ? 3988292384 ^ e >>> 1 : e >>> 1;
    a[t] = e;
  }
  return a;
}, q1 = new Uint32Array(j1()), K1 = (e, a, t, n) => {
  const c = q1, r = n + t;
  e ^= -1;
  for (let f = n; f < r; f++)
    e = e >>> 8 ^ c[(e ^ a[f]) & 255];
  return e ^ -1;
};
var K = K1, ht = {
  2: "need dictionary",
  /* Z_NEED_DICT       2  */
  1: "stream end",
  /* Z_STREAM_END      1  */
  0: "",
  /* Z_OK              0  */
  "-1": "file error",
  /* Z_ERRNO         (-1) */
  "-2": "stream error",
  /* Z_STREAM_ERROR  (-2) */
  "-3": "data error",
  /* Z_DATA_ERROR    (-3) */
  "-4": "insufficient memory",
  /* Z_MEM_ERROR     (-4) */
  "-5": "buffer error",
  /* Z_BUF_ERROR     (-5) */
  "-6": "incompatible version"
  /* Z_VERSION_ERROR (-6) */
}, Yt = {
  /* Allowed flush values; see deflate() and inflate() below for details */
  Z_NO_FLUSH: 0,
  Z_PARTIAL_FLUSH: 1,
  Z_SYNC_FLUSH: 2,
  Z_FULL_FLUSH: 3,
  Z_FINISH: 4,
  Z_BLOCK: 5,
  Z_TREES: 6,
  /* Return codes for the compression/decompression functions. Negative values
  * are errors, positive values are used for special but normal events.
  */
  Z_OK: 0,
  Z_STREAM_END: 1,
  Z_NEED_DICT: 2,
  Z_ERRNO: -1,
  Z_STREAM_ERROR: -2,
  Z_DATA_ERROR: -3,
  Z_MEM_ERROR: -4,
  Z_BUF_ERROR: -5,
  //Z_VERSION_ERROR: -6,
  /* compression levels */
  Z_NO_COMPRESSION: 0,
  Z_BEST_SPEED: 1,
  Z_BEST_COMPRESSION: 9,
  Z_DEFAULT_COMPRESSION: -1,
  Z_FILTERED: 1,
  Z_HUFFMAN_ONLY: 2,
  Z_RLE: 3,
  Z_FIXED: 4,
  Z_DEFAULT_STRATEGY: 0,
  /* Possible values of the data_type field (though see inflate()) */
  Z_BINARY: 0,
  Z_TEXT: 1,
  //Z_ASCII:                1, // = Z_TEXT (deprecated)
  Z_UNKNOWN: 2,
  /* The deflate compression method */
  Z_DEFLATED: 8
  //Z_NULL:                 null // Use -1 or null inline, depending on var type
};
const { _tr_init: G1, _tr_stored_block: uc, _tr_flush_block: Y1, _tr_tally: Ye, _tr_align: W1 } = Z1, {
  Z_NO_FLUSH: We,
  Z_PARTIAL_FLUSH: X1,
  Z_FULL_FLUSH: J1,
  Z_FINISH: pe,
  Z_BLOCK: nf,
  Z_OK: W,
  Z_STREAM_END: cf,
  Z_STREAM_ERROR: Te,
  Z_DATA_ERROR: Q1,
  Z_BUF_ERROR: Fn,
  Z_DEFAULT_COMPRESSION: eb,
  Z_FILTERED: tb,
  Z_HUFFMAN_ONLY: za,
  Z_RLE: ab,
  Z_FIXED: nb,
  Z_DEFAULT_STRATEGY: cb,
  Z_UNKNOWN: rb,
  Z_DEFLATED: gn
} = Yt, fb = 9, db = 15, ib = 8, sb = 29, ob = 256, hc = ob + 1 + sb, bb = 30, lb = 19, ub = 2 * hc + 1, hb = 15, D = 3, Ge = 258, Ce = Ge + D + 1, pb = 32, Zt = 42, Vc = 57, pc = 69, _c = 73, gc = 91, yc = 103, st = 113, fa = 666, ce = 1, Wt = 2, pt = 3, Xt = 4, _b = 3, ot = (e, a) => (e.msg = ht[a], a), rf = (e) => e * 2 - (e > 4 ? 9 : 0), qe = (e) => {
  let a = e.length;
  for (; --a >= 0; )
    e[a] = 0;
}, gb = (e) => {
  let a, t, n, c = e.w_size;
  a = e.hash_size, n = a;
  do
    t = e.head[--n], e.head[n] = t >= c ? t - c : 0;
  while (--a);
  a = c, n = a;
  do
    t = e.prev[--n], e.prev[n] = t >= c ? t - c : 0;
  while (--a);
};
let yb = (e, a, t) => (a << e.hash_shift ^ t) & e.hash_mask, Xe = yb;
const oe = (e) => {
  const a = e.state;
  let t = a.pending;
  t > e.avail_out && (t = e.avail_out), t !== 0 && (e.output.set(a.pending_buf.subarray(a.pending_out, a.pending_out + t), e.next_out), e.next_out += t, a.pending_out += t, e.total_out += t, e.avail_out -= t, a.pending -= t, a.pending === 0 && (a.pending_out = 0));
}, ue = (e, a) => {
  Y1(e, e.block_start >= 0 ? e.block_start : -1, e.strstart - e.block_start, a), e.block_start = e.strstart, oe(e.strm);
}, H = (e, a) => {
  e.pending_buf[e.pending++] = a;
}, aa = (e, a) => {
  e.pending_buf[e.pending++] = a >>> 8 & 255, e.pending_buf[e.pending++] = a & 255;
}, wc = (e, a, t, n) => {
  let c = e.avail_in;
  return c > n && (c = n), c === 0 ? 0 : (e.avail_in -= c, a.set(e.input.subarray(e.next_in, e.next_in + c), t), e.state.wrap === 1 ? e.adler = ga(e.adler, a, c, t) : e.state.wrap === 2 && (e.adler = K(e.adler, a, c, t)), e.next_in += c, e.total_in += c, c);
}, Zd = (e, a) => {
  let t = e.max_chain_length, n = e.strstart, c, r, f = e.prev_length, d = e.nice_match;
  const o = e.strstart > e.w_size - Ce ? e.strstart - (e.w_size - Ce) : 0, i = e.window, s = e.w_mask, b = e.prev, u = e.strstart + Ge;
  let l = i[n + f - 1], _ = i[n + f];
  e.prev_length >= e.good_match && (t >>= 2), d > e.lookahead && (d = e.lookahead);
  do
    if (c = a, !(i[c + f] !== _ || i[c + f - 1] !== l || i[c] !== i[n] || i[++c] !== i[n + 1])) {
      n += 2, c++;
      do
        ;
      while (i[++n] === i[++c] && i[++n] === i[++c] && i[++n] === i[++c] && i[++n] === i[++c] && i[++n] === i[++c] && i[++n] === i[++c] && i[++n] === i[++c] && i[++n] === i[++c] && n < u);
      if (r = Ge - (u - n), n = u - Ge, r > f) {
        if (e.match_start = a, f = r, r >= d)
          break;
        l = i[n + f - 1], _ = i[n + f];
      }
    }
  while ((a = b[a & s]) > o && --t !== 0);
  return f <= e.lookahead ? f : e.lookahead;
}, Vt = (e) => {
  const a = e.w_size;
  let t, n, c;
  do {
    if (n = e.window_size - e.lookahead - e.strstart, e.strstart >= a + (a - Ce) && (e.window.set(e.window.subarray(a, a + a - n), 0), e.match_start -= a, e.strstart -= a, e.block_start -= a, e.insert > e.strstart && (e.insert = e.strstart), gb(e), n += a), e.strm.avail_in === 0)
      break;
    if (t = wc(e.strm, e.window, e.strstart + e.lookahead, n), e.lookahead += t, e.lookahead + e.insert >= D)
      for (c = e.strstart - e.insert, e.ins_h = e.window[c], e.ins_h = Xe(e, e.ins_h, e.window[c + 1]); e.insert && (e.ins_h = Xe(e, e.ins_h, e.window[c + D - 1]), e.prev[c & e.w_mask] = e.head[e.ins_h], e.head[e.ins_h] = c, c++, e.insert--, !(e.lookahead + e.insert < D)); )
        ;
  } while (e.lookahead < Ce && e.strm.avail_in !== 0);
}, Vd = (e, a) => {
  let t = e.pending_buf_size - 5 > e.w_size ? e.w_size : e.pending_buf_size - 5, n, c, r, f = 0, d = e.strm.avail_in;
  do {
    if (n = 65535, r = e.bi_valid + 42 >> 3, e.strm.avail_out < r || (r = e.strm.avail_out - r, c = e.strstart - e.block_start, n > c + e.strm.avail_in && (n = c + e.strm.avail_in), n > r && (n = r), n < t && (n === 0 && a !== pe || a === We || n !== c + e.strm.avail_in)))
      break;
    f = a === pe && n === c + e.strm.avail_in ? 1 : 0, uc(e, 0, 0, f), e.pending_buf[e.pending - 4] = n, e.pending_buf[e.pending - 3] = n >> 8, e.pending_buf[e.pending - 2] = ~n, e.pending_buf[e.pending - 1] = ~n >> 8, oe(e.strm), c && (c > n && (c = n), e.strm.output.set(e.window.subarray(e.block_start, e.block_start + c), e.strm.next_out), e.strm.next_out += c, e.strm.avail_out -= c, e.strm.total_out += c, e.block_start += c, n -= c), n && (wc(e.strm, e.strm.output, e.strm.next_out, n), e.strm.next_out += n, e.strm.avail_out -= n, e.strm.total_out += n);
  } while (f === 0);
  return d -= e.strm.avail_in, d && (d >= e.w_size ? (e.matches = 2, e.window.set(e.strm.input.subarray(e.strm.next_in - e.w_size, e.strm.next_in), 0), e.strstart = e.w_size, e.insert = e.strstart) : (e.window_size - e.strstart <= d && (e.strstart -= e.w_size, e.window.set(e.window.subarray(e.w_size, e.w_size + e.strstart), 0), e.matches < 2 && e.matches++, e.insert > e.strstart && (e.insert = e.strstart)), e.window.set(e.strm.input.subarray(e.strm.next_in - d, e.strm.next_in), e.strstart), e.strstart += d, e.insert += d > e.w_size - e.insert ? e.w_size - e.insert : d), e.block_start = e.strstart), e.high_water < e.strstart && (e.high_water = e.strstart), f ? Xt : a !== We && a !== pe && e.strm.avail_in === 0 && e.strstart === e.block_start ? Wt : (r = e.window_size - e.strstart, e.strm.avail_in > r && e.block_start >= e.w_size && (e.block_start -= e.w_size, e.strstart -= e.w_size, e.window.set(e.window.subarray(e.w_size, e.w_size + e.strstart), 0), e.matches < 2 && e.matches++, r += e.w_size, e.insert > e.strstart && (e.insert = e.strstart)), r > e.strm.avail_in && (r = e.strm.avail_in), r && (wc(e.strm, e.window, e.strstart, r), e.strstart += r, e.insert += r > e.w_size - e.insert ? e.w_size - e.insert : r), e.high_water < e.strstart && (e.high_water = e.strstart), r = e.bi_valid + 42 >> 3, r = e.pending_buf_size - r > 65535 ? 65535 : e.pending_buf_size - r, t = r > e.w_size ? e.w_size : r, c = e.strstart - e.block_start, (c >= t || (c || a === pe) && a !== We && e.strm.avail_in === 0 && c <= r) && (n = c > r ? r : c, f = a === pe && e.strm.avail_in === 0 && n === c ? 1 : 0, uc(e, e.block_start, n, f), e.block_start += n, oe(e.strm)), f ? pt : ce);
}, zn = (e, a) => {
  let t, n;
  for (; ; ) {
    if (e.lookahead < Ce) {
      if (Vt(e), e.lookahead < Ce && a === We)
        return ce;
      if (e.lookahead === 0)
        break;
    }
    if (t = 0, e.lookahead >= D && (e.ins_h = Xe(e, e.ins_h, e.window[e.strstart + D - 1]), t = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h], e.head[e.ins_h] = e.strstart), t !== 0 && e.strstart - t <= e.w_size - Ce && (e.match_length = Zd(e, t)), e.match_length >= D)
      if (n = Ye(e, e.strstart - e.match_start, e.match_length - D), e.lookahead -= e.match_length, e.match_length <= e.max_lazy_match && e.lookahead >= D) {
        e.match_length--;
        do
          e.strstart++, e.ins_h = Xe(e, e.ins_h, e.window[e.strstart + D - 1]), t = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h], e.head[e.ins_h] = e.strstart;
        while (--e.match_length !== 0);
        e.strstart++;
      } else
        e.strstart += e.match_length, e.match_length = 0, e.ins_h = e.window[e.strstart], e.ins_h = Xe(e, e.ins_h, e.window[e.strstart + 1]);
    else
      n = Ye(e, 0, e.window[e.strstart]), e.lookahead--, e.strstart++;
    if (n && (ue(e, !1), e.strm.avail_out === 0))
      return ce;
  }
  return e.insert = e.strstart < D - 1 ? e.strstart : D - 1, a === pe ? (ue(e, !0), e.strm.avail_out === 0 ? pt : Xt) : e.sym_next && (ue(e, !1), e.strm.avail_out === 0) ? ce : Wt;
}, Tt = (e, a) => {
  let t, n, c;
  for (; ; ) {
    if (e.lookahead < Ce) {
      if (Vt(e), e.lookahead < Ce && a === We)
        return ce;
      if (e.lookahead === 0)
        break;
    }
    if (t = 0, e.lookahead >= D && (e.ins_h = Xe(e, e.ins_h, e.window[e.strstart + D - 1]), t = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h], e.head[e.ins_h] = e.strstart), e.prev_length = e.match_length, e.prev_match = e.match_start, e.match_length = D - 1, t !== 0 && e.prev_length < e.max_lazy_match && e.strstart - t <= e.w_size - Ce && (e.match_length = Zd(e, t), e.match_length <= 5 && (e.strategy === tb || e.match_length === D && e.strstart - e.match_start > 4096) && (e.match_length = D - 1)), e.prev_length >= D && e.match_length <= e.prev_length) {
      c = e.strstart + e.lookahead - D, n = Ye(e, e.strstart - 1 - e.prev_match, e.prev_length - D), e.lookahead -= e.prev_length - 1, e.prev_length -= 2;
      do
        ++e.strstart <= c && (e.ins_h = Xe(e, e.ins_h, e.window[e.strstart + D - 1]), t = e.prev[e.strstart & e.w_mask] = e.head[e.ins_h], e.head[e.ins_h] = e.strstart);
      while (--e.prev_length !== 0);
      if (e.match_available = 0, e.match_length = D - 1, e.strstart++, n && (ue(e, !1), e.strm.avail_out === 0))
        return ce;
    } else if (e.match_available) {
      if (n = Ye(e, 0, e.window[e.strstart - 1]), n && ue(e, !1), e.strstart++, e.lookahead--, e.strm.avail_out === 0)
        return ce;
    } else
      e.match_available = 1, e.strstart++, e.lookahead--;
  }
  return e.match_available && (n = Ye(e, 0, e.window[e.strstart - 1]), e.match_available = 0), e.insert = e.strstart < D - 1 ? e.strstart : D - 1, a === pe ? (ue(e, !0), e.strm.avail_out === 0 ? pt : Xt) : e.sym_next && (ue(e, !1), e.strm.avail_out === 0) ? ce : Wt;
}, wb = (e, a) => {
  let t, n, c, r;
  const f = e.window;
  for (; ; ) {
    if (e.lookahead <= Ge) {
      if (Vt(e), e.lookahead <= Ge && a === We)
        return ce;
      if (e.lookahead === 0)
        break;
    }
    if (e.match_length = 0, e.lookahead >= D && e.strstart > 0 && (c = e.strstart - 1, n = f[c], n === f[++c] && n === f[++c] && n === f[++c])) {
      r = e.strstart + Ge;
      do
        ;
      while (n === f[++c] && n === f[++c] && n === f[++c] && n === f[++c] && n === f[++c] && n === f[++c] && n === f[++c] && n === f[++c] && c < r);
      e.match_length = Ge - (r - c), e.match_length > e.lookahead && (e.match_length = e.lookahead);
    }
    if (e.match_length >= D ? (t = Ye(e, 1, e.match_length - D), e.lookahead -= e.match_length, e.strstart += e.match_length, e.match_length = 0) : (t = Ye(e, 0, e.window[e.strstart]), e.lookahead--, e.strstart++), t && (ue(e, !1), e.strm.avail_out === 0))
      return ce;
  }
  return e.insert = 0, a === pe ? (ue(e, !0), e.strm.avail_out === 0 ? pt : Xt) : e.sym_next && (ue(e, !1), e.strm.avail_out === 0) ? ce : Wt;
}, mb = (e, a) => {
  let t;
  for (; ; ) {
    if (e.lookahead === 0 && (Vt(e), e.lookahead === 0)) {
      if (a === We)
        return ce;
      break;
    }
    if (e.match_length = 0, t = Ye(e, 0, e.window[e.strstart]), e.lookahead--, e.strstart++, t && (ue(e, !1), e.strm.avail_out === 0))
      return ce;
  }
  return e.insert = 0, a === pe ? (ue(e, !0), e.strm.avail_out === 0 ? pt : Xt) : e.sym_next && (ue(e, !1), e.strm.avail_out === 0) ? ce : Wt;
};
function xe(e, a, t, n, c) {
  this.good_length = e, this.max_lazy = a, this.nice_length = t, this.max_chain = n, this.func = c;
}
const da = [
  /*      good lazy nice chain */
  new xe(0, 0, 0, 0, Vd),
  /* 0 store only */
  new xe(4, 4, 8, 4, zn),
  /* 1 max speed, no lazy matches */
  new xe(4, 5, 16, 8, zn),
  /* 2 */
  new xe(4, 6, 32, 32, zn),
  /* 3 */
  new xe(4, 4, 16, 16, Tt),
  /* 4 lazy matches */
  new xe(8, 16, 32, 32, Tt),
  /* 5 */
  new xe(8, 16, 128, 128, Tt),
  /* 6 */
  new xe(8, 32, 128, 256, Tt),
  /* 7 */
  new xe(32, 128, 258, 1024, Tt),
  /* 8 */
  new xe(32, 258, 258, 4096, Tt)
  /* 9 max compression */
], Eb = (e) => {
  e.window_size = 2 * e.w_size, qe(e.head), e.max_lazy_match = da[e.level].max_lazy, e.good_match = da[e.level].good_length, e.nice_match = da[e.level].nice_length, e.max_chain_length = da[e.level].max_chain, e.strstart = 0, e.block_start = 0, e.lookahead = 0, e.insert = 0, e.match_length = e.prev_length = D - 1, e.match_available = 0, e.ins_h = 0;
};
function vb() {
  this.strm = null, this.status = 0, this.pending_buf = null, this.pending_buf_size = 0, this.pending_out = 0, this.pending = 0, this.wrap = 0, this.gzhead = null, this.gzindex = 0, this.method = gn, this.last_flush = -1, this.w_size = 0, this.w_bits = 0, this.w_mask = 0, this.window = null, this.window_size = 0, this.prev = null, this.head = null, this.ins_h = 0, this.hash_size = 0, this.hash_bits = 0, this.hash_mask = 0, this.hash_shift = 0, this.block_start = 0, this.match_length = 0, this.prev_match = 0, this.match_available = 0, this.strstart = 0, this.match_start = 0, this.lookahead = 0, this.prev_length = 0, this.max_chain_length = 0, this.max_lazy_match = 0, this.level = 0, this.strategy = 0, this.good_match = 0, this.nice_match = 0, this.dyn_ltree = new Uint16Array(ub * 2), this.dyn_dtree = new Uint16Array((2 * bb + 1) * 2), this.bl_tree = new Uint16Array((2 * lb + 1) * 2), qe(this.dyn_ltree), qe(this.dyn_dtree), qe(this.bl_tree), this.l_desc = null, this.d_desc = null, this.bl_desc = null, this.bl_count = new Uint16Array(hb + 1), this.heap = new Uint16Array(2 * hc + 1), qe(this.heap), this.heap_len = 0, this.heap_max = 0, this.depth = new Uint16Array(2 * hc + 1), qe(this.depth), this.sym_buf = 0, this.lit_bufsize = 0, this.sym_next = 0, this.sym_end = 0, this.opt_len = 0, this.static_len = 0, this.matches = 0, this.insert = 0, this.bi_buf = 0, this.bi_valid = 0;
}
const Ca = (e) => {
  if (!e)
    return 1;
  const a = e.state;
  return !a || a.strm !== e || a.status !== Zt && //#ifdef GZIP
  a.status !== Vc && //#endif
  a.status !== pc && a.status !== _c && a.status !== gc && a.status !== yc && a.status !== st && a.status !== fa ? 1 : 0;
}, jd = (e) => {
  if (Ca(e))
    return ot(e, Te);
  e.total_in = e.total_out = 0, e.data_type = rb;
  const a = e.state;
  return a.pending = 0, a.pending_out = 0, a.wrap < 0 && (a.wrap = -a.wrap), a.status = //#ifdef GZIP
  a.wrap === 2 ? Vc : (
    //#endif
    a.wrap ? Zt : st
  ), e.adler = a.wrap === 2 ? 0 : 1, a.last_flush = -2, G1(a), W;
}, qd = (e) => {
  const a = jd(e);
  return a === W && Eb(e.state), a;
}, xb = (e, a) => Ca(e) || e.state.wrap !== 2 ? Te : (e.state.gzhead = a, W), Kd = (e, a, t, n, c, r) => {
  if (!e)
    return Te;
  let f = 1;
  if (a === eb && (a = 6), n < 0 ? (f = 0, n = -n) : n > 15 && (f = 2, n -= 16), c < 1 || c > fb || t !== gn || n < 8 || n > 15 || a < 0 || a > 9 || r < 0 || r > nb || n === 8 && f !== 1)
    return ot(e, Te);
  n === 8 && (n = 9);
  const d = new vb();
  return e.state = d, d.strm = e, d.status = Zt, d.wrap = f, d.gzhead = null, d.w_bits = n, d.w_size = 1 << d.w_bits, d.w_mask = d.w_size - 1, d.hash_bits = c + 7, d.hash_size = 1 << d.hash_bits, d.hash_mask = d.hash_size - 1, d.hash_shift = ~~((d.hash_bits + D - 1) / D), d.window = new Uint8Array(d.w_size * 2), d.head = new Uint16Array(d.hash_size), d.prev = new Uint16Array(d.w_size), d.lit_bufsize = 1 << c + 6, d.pending_buf_size = d.lit_bufsize * 4, d.pending_buf = new Uint8Array(d.pending_buf_size), d.sym_buf = d.lit_bufsize, d.sym_end = (d.lit_bufsize - 1) * 3, d.level = a, d.strategy = r, d.method = t, qd(e);
}, Ab = (e, a) => Kd(e, a, gn, db, ib, cb), Sb = (e, a) => {
  if (Ca(e) || a > nf || a < 0)
    return e ? ot(e, Te) : Te;
  const t = e.state;
  if (!e.output || e.avail_in !== 0 && !e.input || t.status === fa && a !== pe)
    return ot(e, e.avail_out === 0 ? Fn : Te);
  const n = t.last_flush;
  if (t.last_flush = a, t.pending !== 0) {
    if (oe(e), e.avail_out === 0)
      return t.last_flush = -1, W;
  } else if (e.avail_in === 0 && rf(a) <= rf(n) && a !== pe)
    return ot(e, Fn);
  if (t.status === fa && e.avail_in !== 0)
    return ot(e, Fn);
  if (t.status === Zt && t.wrap === 0 && (t.status = st), t.status === Zt) {
    let c = gn + (t.w_bits - 8 << 4) << 8, r = -1;
    if (t.strategy >= za || t.level < 2 ? r = 0 : t.level < 6 ? r = 1 : t.level === 6 ? r = 2 : r = 3, c |= r << 6, t.strstart !== 0 && (c |= pb), c += 31 - c % 31, aa(t, c), t.strstart !== 0 && (aa(t, e.adler >>> 16), aa(t, e.adler & 65535)), e.adler = 1, t.status = st, oe(e), t.pending !== 0)
      return t.last_flush = -1, W;
  }
  if (t.status === Vc) {
    if (e.adler = 0, H(t, 31), H(t, 139), H(t, 8), t.gzhead)
      H(
        t,
        (t.gzhead.text ? 1 : 0) + (t.gzhead.hcrc ? 2 : 0) + (t.gzhead.extra ? 4 : 0) + (t.gzhead.name ? 8 : 0) + (t.gzhead.comment ? 16 : 0)
      ), H(t, t.gzhead.time & 255), H(t, t.gzhead.time >> 8 & 255), H(t, t.gzhead.time >> 16 & 255), H(t, t.gzhead.time >> 24 & 255), H(t, t.level === 9 ? 2 : t.strategy >= za || t.level < 2 ? 4 : 0), H(t, t.gzhead.os & 255), t.gzhead.extra && t.gzhead.extra.length && (H(t, t.gzhead.extra.length & 255), H(t, t.gzhead.extra.length >> 8 & 255)), t.gzhead.hcrc && (e.adler = K(e.adler, t.pending_buf, t.pending, 0)), t.gzindex = 0, t.status = pc;
    else if (H(t, 0), H(t, 0), H(t, 0), H(t, 0), H(t, 0), H(t, t.level === 9 ? 2 : t.strategy >= za || t.level < 2 ? 4 : 0), H(t, _b), t.status = st, oe(e), t.pending !== 0)
      return t.last_flush = -1, W;
  }
  if (t.status === pc) {
    if (t.gzhead.extra) {
      let c = t.pending, r = (t.gzhead.extra.length & 65535) - t.gzindex;
      for (; t.pending + r > t.pending_buf_size; ) {
        let d = t.pending_buf_size - t.pending;
        if (t.pending_buf.set(t.gzhead.extra.subarray(t.gzindex, t.gzindex + d), t.pending), t.pending = t.pending_buf_size, t.gzhead.hcrc && t.pending > c && (e.adler = K(e.adler, t.pending_buf, t.pending - c, c)), t.gzindex += d, oe(e), t.pending !== 0)
          return t.last_flush = -1, W;
        c = 0, r -= d;
      }
      let f = new Uint8Array(t.gzhead.extra);
      t.pending_buf.set(f.subarray(t.gzindex, t.gzindex + r), t.pending), t.pending += r, t.gzhead.hcrc && t.pending > c && (e.adler = K(e.adler, t.pending_buf, t.pending - c, c)), t.gzindex = 0;
    }
    t.status = _c;
  }
  if (t.status === _c) {
    if (t.gzhead.name) {
      let c = t.pending, r;
      do {
        if (t.pending === t.pending_buf_size) {
          if (t.gzhead.hcrc && t.pending > c && (e.adler = K(e.adler, t.pending_buf, t.pending - c, c)), oe(e), t.pending !== 0)
            return t.last_flush = -1, W;
          c = 0;
        }
        t.gzindex < t.gzhead.name.length ? r = t.gzhead.name.charCodeAt(t.gzindex++) & 255 : r = 0, H(t, r);
      } while (r !== 0);
      t.gzhead.hcrc && t.pending > c && (e.adler = K(e.adler, t.pending_buf, t.pending - c, c)), t.gzindex = 0;
    }
    t.status = gc;
  }
  if (t.status === gc) {
    if (t.gzhead.comment) {
      let c = t.pending, r;
      do {
        if (t.pending === t.pending_buf_size) {
          if (t.gzhead.hcrc && t.pending > c && (e.adler = K(e.adler, t.pending_buf, t.pending - c, c)), oe(e), t.pending !== 0)
            return t.last_flush = -1, W;
          c = 0;
        }
        t.gzindex < t.gzhead.comment.length ? r = t.gzhead.comment.charCodeAt(t.gzindex++) & 255 : r = 0, H(t, r);
      } while (r !== 0);
      t.gzhead.hcrc && t.pending > c && (e.adler = K(e.adler, t.pending_buf, t.pending - c, c));
    }
    t.status = yc;
  }
  if (t.status === yc) {
    if (t.gzhead.hcrc) {
      if (t.pending + 2 > t.pending_buf_size && (oe(e), t.pending !== 0))
        return t.last_flush = -1, W;
      H(t, e.adler & 255), H(t, e.adler >> 8 & 255), e.adler = 0;
    }
    if (t.status = st, oe(e), t.pending !== 0)
      return t.last_flush = -1, W;
  }
  if (e.avail_in !== 0 || t.lookahead !== 0 || a !== We && t.status !== fa) {
    let c = t.level === 0 ? Vd(t, a) : t.strategy === za ? mb(t, a) : t.strategy === ab ? wb(t, a) : da[t.level].func(t, a);
    if ((c === pt || c === Xt) && (t.status = fa), c === ce || c === pt)
      return e.avail_out === 0 && (t.last_flush = -1), W;
    if (c === Wt && (a === X1 ? W1(t) : a !== nf && (uc(t, 0, 0, !1), a === J1 && (qe(t.head), t.lookahead === 0 && (t.strstart = 0, t.block_start = 0, t.insert = 0))), oe(e), e.avail_out === 0))
      return t.last_flush = -1, W;
  }
  return a !== pe ? W : t.wrap <= 0 ? cf : (t.wrap === 2 ? (H(t, e.adler & 255), H(t, e.adler >> 8 & 255), H(t, e.adler >> 16 & 255), H(t, e.adler >> 24 & 255), H(t, e.total_in & 255), H(t, e.total_in >> 8 & 255), H(t, e.total_in >> 16 & 255), H(t, e.total_in >> 24 & 255)) : (aa(t, e.adler >>> 16), aa(t, e.adler & 65535)), oe(e), t.wrap > 0 && (t.wrap = -t.wrap), t.pending !== 0 ? W : cf);
}, kb = (e) => {
  if (Ca(e))
    return Te;
  const a = e.state.status;
  return e.state = null, a === st ? ot(e, Q1) : W;
}, Tb = (e, a) => {
  let t = a.length;
  if (Ca(e))
    return Te;
  const n = e.state, c = n.wrap;
  if (c === 2 || c === 1 && n.status !== Zt || n.lookahead)
    return Te;
  if (c === 1 && (e.adler = ga(e.adler, a, t, 0)), n.wrap = 0, t >= n.w_size) {
    c === 0 && (qe(n.head), n.strstart = 0, n.block_start = 0, n.insert = 0);
    let o = new Uint8Array(n.w_size);
    o.set(a.subarray(t - n.w_size, t), 0), a = o, t = n.w_size;
  }
  const r = e.avail_in, f = e.next_in, d = e.input;
  for (e.avail_in = t, e.next_in = 0, e.input = a, Vt(n); n.lookahead >= D; ) {
    let o = n.strstart, i = n.lookahead - (D - 1);
    do
      n.ins_h = Xe(n, n.ins_h, n.window[o + D - 1]), n.prev[o & n.w_mask] = n.head[n.ins_h], n.head[n.ins_h] = o, o++;
    while (--i);
    n.strstart = o, n.lookahead = D - 1, Vt(n);
  }
  return n.strstart += n.lookahead, n.block_start = n.strstart, n.insert = n.lookahead, n.lookahead = 0, n.match_length = n.prev_length = D - 1, n.match_available = 0, e.next_in = f, e.input = d, e.avail_in = r, n.wrap = c, W;
};
var Cb = Ab, Ib = Kd, Nb = qd, Ob = jd, Bb = xb, Rb = Sb, Db = kb, Lb = Tb, $b = "pako deflate (from Nodeca project)", sa = {
  deflateInit: Cb,
  deflateInit2: Ib,
  deflateReset: Nb,
  deflateResetKeep: Ob,
  deflateSetHeader: Bb,
  deflate: Rb,
  deflateEnd: Db,
  deflateSetDictionary: Lb,
  deflateInfo: $b
};
const Pb = (e, a) => Object.prototype.hasOwnProperty.call(e, a);
var Hb = function(e) {
  const a = Array.prototype.slice.call(arguments, 1);
  for (; a.length; ) {
    const t = a.shift();
    if (t) {
      if (typeof t != "object")
        throw new TypeError(t + "must be non-object");
      for (const n in t)
        Pb(t, n) && (e[n] = t[n]);
    }
  }
  return e;
}, Ub = (e) => {
  let a = 0;
  for (let n = 0, c = e.length; n < c; n++)
    a += e[n].length;
  const t = new Uint8Array(a);
  for (let n = 0, c = 0, r = e.length; n < r; n++) {
    let f = e[n];
    t.set(f, c), c += f.length;
  }
  return t;
}, yn = {
  assign: Hb,
  flattenChunks: Ub
};
let Gd = !0;
try {
  String.fromCharCode.apply(null, new Uint8Array(1));
} catch {
  Gd = !1;
}
const ya = new Uint8Array(256);
for (let e = 0; e < 256; e++)
  ya[e] = e >= 252 ? 6 : e >= 248 ? 5 : e >= 240 ? 4 : e >= 224 ? 3 : e >= 192 ? 2 : 1;
ya[254] = ya[254] = 1;
var Fb = (e) => {
  if (typeof TextEncoder == "function" && TextEncoder.prototype.encode)
    return new TextEncoder().encode(e);
  let a, t, n, c, r, f = e.length, d = 0;
  for (c = 0; c < f; c++)
    t = e.charCodeAt(c), (t & 64512) === 55296 && c + 1 < f && (n = e.charCodeAt(c + 1), (n & 64512) === 56320 && (t = 65536 + (t - 55296 << 10) + (n - 56320), c++)), d += t < 128 ? 1 : t < 2048 ? 2 : t < 65536 ? 3 : 4;
  for (a = new Uint8Array(d), r = 0, c = 0; r < d; c++)
    t = e.charCodeAt(c), (t & 64512) === 55296 && c + 1 < f && (n = e.charCodeAt(c + 1), (n & 64512) === 56320 && (t = 65536 + (t - 55296 << 10) + (n - 56320), c++)), t < 128 ? a[r++] = t : t < 2048 ? (a[r++] = 192 | t >>> 6, a[r++] = 128 | t & 63) : t < 65536 ? (a[r++] = 224 | t >>> 12, a[r++] = 128 | t >>> 6 & 63, a[r++] = 128 | t & 63) : (a[r++] = 240 | t >>> 18, a[r++] = 128 | t >>> 12 & 63, a[r++] = 128 | t >>> 6 & 63, a[r++] = 128 | t & 63);
  return a;
};
const zb = (e, a) => {
  if (a < 65534 && e.subarray && Gd)
    return String.fromCharCode.apply(null, e.length === a ? e : e.subarray(0, a));
  let t = "";
  for (let n = 0; n < a; n++)
    t += String.fromCharCode(e[n]);
  return t;
};
var Mb = (e, a) => {
  const t = a || e.length;
  if (typeof TextDecoder == "function" && TextDecoder.prototype.decode)
    return new TextDecoder().decode(e.subarray(0, a));
  let n, c;
  const r = new Array(t * 2);
  for (c = 0, n = 0; n < t; ) {
    let f = e[n++];
    if (f < 128) {
      r[c++] = f;
      continue;
    }
    let d = ya[f];
    if (d > 4) {
      r[c++] = 65533, n += d - 1;
      continue;
    }
    for (f &= d === 2 ? 31 : d === 3 ? 15 : 7; d > 1 && n < t; )
      f = f << 6 | e[n++] & 63, d--;
    if (d > 1) {
      r[c++] = 65533;
      continue;
    }
    f < 65536 ? r[c++] = f : (f -= 65536, r[c++] = 55296 | f >> 10 & 1023, r[c++] = 56320 | f & 1023);
  }
  return zb(r, c);
}, Zb = (e, a) => {
  a = a || e.length, a > e.length && (a = e.length);
  let t = a - 1;
  for (; t >= 0 && (e[t] & 192) === 128; )
    t--;
  return t < 0 || t === 0 ? a : t + ya[e[t]] > a ? t : a;
}, wa = {
  string2buf: Fb,
  buf2string: Mb,
  utf8border: Zb
};
function Vb() {
  this.input = null, this.next_in = 0, this.avail_in = 0, this.total_in = 0, this.output = null, this.next_out = 0, this.avail_out = 0, this.total_out = 0, this.msg = "", this.state = null, this.data_type = 2, this.adler = 0;
}
var Yd = Vb;
const Wd = Object.prototype.toString, {
  Z_NO_FLUSH: jb,
  Z_SYNC_FLUSH: qb,
  Z_FULL_FLUSH: Kb,
  Z_FINISH: Gb,
  Z_OK: nn,
  Z_STREAM_END: Yb,
  Z_DEFAULT_COMPRESSION: Wb,
  Z_DEFAULT_STRATEGY: Xb,
  Z_DEFLATED: Jb
} = Yt;
function Ia(e) {
  this.options = yn.assign({
    level: Wb,
    method: Jb,
    chunkSize: 16384,
    windowBits: 15,
    memLevel: 8,
    strategy: Xb
  }, e || {});
  let a = this.options;
  a.raw && a.windowBits > 0 ? a.windowBits = -a.windowBits : a.gzip && a.windowBits > 0 && a.windowBits < 16 && (a.windowBits += 16), this.err = 0, this.msg = "", this.ended = !1, this.chunks = [], this.strm = new Yd(), this.strm.avail_out = 0;
  let t = sa.deflateInit2(
    this.strm,
    a.level,
    a.method,
    a.windowBits,
    a.memLevel,
    a.strategy
  );
  if (t !== nn)
    throw new Error(ht[t]);
  if (a.header && sa.deflateSetHeader(this.strm, a.header), a.dictionary) {
    let n;
    if (typeof a.dictionary == "string" ? n = wa.string2buf(a.dictionary) : Wd.call(a.dictionary) === "[object ArrayBuffer]" ? n = new Uint8Array(a.dictionary) : n = a.dictionary, t = sa.deflateSetDictionary(this.strm, n), t !== nn)
      throw new Error(ht[t]);
    this._dict_set = !0;
  }
}
Ia.prototype.push = function(e, a) {
  const t = this.strm, n = this.options.chunkSize;
  let c, r;
  if (this.ended)
    return !1;
  for (a === ~~a ? r = a : r = a === !0 ? Gb : jb, typeof e == "string" ? t.input = wa.string2buf(e) : Wd.call(e) === "[object ArrayBuffer]" ? t.input = new Uint8Array(e) : t.input = e, t.next_in = 0, t.avail_in = t.input.length; ; ) {
    if (t.avail_out === 0 && (t.output = new Uint8Array(n), t.next_out = 0, t.avail_out = n), (r === qb || r === Kb) && t.avail_out <= 6) {
      this.onData(t.output.subarray(0, t.next_out)), t.avail_out = 0;
      continue;
    }
    if (c = sa.deflate(t, r), c === Yb)
      return t.next_out > 0 && this.onData(t.output.subarray(0, t.next_out)), c = sa.deflateEnd(this.strm), this.onEnd(c), this.ended = !0, c === nn;
    if (t.avail_out === 0) {
      this.onData(t.output);
      continue;
    }
    if (r > 0 && t.next_out > 0) {
      this.onData(t.output.subarray(0, t.next_out)), t.avail_out = 0;
      continue;
    }
    if (t.avail_in === 0)
      break;
  }
  return !0;
};
Ia.prototype.onData = function(e) {
  this.chunks.push(e);
};
Ia.prototype.onEnd = function(e) {
  e === nn && (this.result = yn.flattenChunks(this.chunks)), this.chunks = [], this.err = e, this.msg = this.strm.msg;
};
function jc(e, a) {
  const t = new Ia(a);
  if (t.push(e, !0), t.err)
    throw t.msg || ht[t.err];
  return t.result;
}
function Qb(e, a) {
  return a = a || {}, a.raw = !0, jc(e, a);
}
function e2(e, a) {
  return a = a || {}, a.gzip = !0, jc(e, a);
}
var t2 = Ia, a2 = jc, n2 = Qb, c2 = e2, r2 = Yt, f2 = {
  Deflate: t2,
  deflate: a2,
  deflateRaw: n2,
  gzip: c2,
  constants: r2
};
const Ma = 16209, d2 = 16191;
var i2 = function(a, t) {
  let n, c, r, f, d, o, i, s, b, u, l, _, h, p, g, E, v, y, S, A, m, C, O, T;
  const k = a.state;
  n = a.next_in, O = a.input, c = n + (a.avail_in - 5), r = a.next_out, T = a.output, f = r - (t - a.avail_out), d = r + (a.avail_out - 257), o = k.dmax, i = k.wsize, s = k.whave, b = k.wnext, u = k.window, l = k.hold, _ = k.bits, h = k.lencode, p = k.distcode, g = (1 << k.lenbits) - 1, E = (1 << k.distbits) - 1;
  e:
    do {
      _ < 15 && (l += O[n++] << _, _ += 8, l += O[n++] << _, _ += 8), v = h[l & g];
      t:
        for (; ; ) {
          if (y = v >>> 24, l >>>= y, _ -= y, y = v >>> 16 & 255, y === 0)
            T[r++] = v & 65535;
          else if (y & 16) {
            S = v & 65535, y &= 15, y && (_ < y && (l += O[n++] << _, _ += 8), S += l & (1 << y) - 1, l >>>= y, _ -= y), _ < 15 && (l += O[n++] << _, _ += 8, l += O[n++] << _, _ += 8), v = p[l & E];
            a:
              for (; ; ) {
                if (y = v >>> 24, l >>>= y, _ -= y, y = v >>> 16 & 255, y & 16) {
                  if (A = v & 65535, y &= 15, _ < y && (l += O[n++] << _, _ += 8, _ < y && (l += O[n++] << _, _ += 8)), A += l & (1 << y) - 1, A > o) {
                    a.msg = "invalid distance too far back", k.mode = Ma;
                    break e;
                  }
                  if (l >>>= y, _ -= y, y = r - f, A > y) {
                    if (y = A - y, y > s && k.sane) {
                      a.msg = "invalid distance too far back", k.mode = Ma;
                      break e;
                    }
                    if (m = 0, C = u, b === 0) {
                      if (m += i - y, y < S) {
                        S -= y;
                        do
                          T[r++] = u[m++];
                        while (--y);
                        m = r - A, C = T;
                      }
                    } else if (b < y) {
                      if (m += i + b - y, y -= b, y < S) {
                        S -= y;
                        do
                          T[r++] = u[m++];
                        while (--y);
                        if (m = 0, b < S) {
                          y = b, S -= y;
                          do
                            T[r++] = u[m++];
                          while (--y);
                          m = r - A, C = T;
                        }
                      }
                    } else if (m += b - y, y < S) {
                      S -= y;
                      do
                        T[r++] = u[m++];
                      while (--y);
                      m = r - A, C = T;
                    }
                    for (; S > 2; )
                      T[r++] = C[m++], T[r++] = C[m++], T[r++] = C[m++], S -= 3;
                    S && (T[r++] = C[m++], S > 1 && (T[r++] = C[m++]));
                  } else {
                    m = r - A;
                    do
                      T[r++] = T[m++], T[r++] = T[m++], T[r++] = T[m++], S -= 3;
                    while (S > 2);
                    S && (T[r++] = T[m++], S > 1 && (T[r++] = T[m++]));
                  }
                } else if (y & 64) {
                  a.msg = "invalid distance code", k.mode = Ma;
                  break e;
                } else {
                  v = p[(v & 65535) + (l & (1 << y) - 1)];
                  continue a;
                }
                break;
              }
          } else if (y & 64)
            if (y & 32) {
              k.mode = d2;
              break e;
            } else {
              a.msg = "invalid literal/length code", k.mode = Ma;
              break e;
            }
          else {
            v = h[(v & 65535) + (l & (1 << y) - 1)];
            continue t;
          }
          break;
        }
    } while (n < c && r < d);
  S = _ >> 3, n -= S, _ -= S << 3, l &= (1 << _) - 1, a.next_in = n, a.next_out = r, a.avail_in = n < c ? 5 + (c - n) : 5 - (n - c), a.avail_out = r < d ? 257 + (d - r) : 257 - (r - d), k.hold = l, k.bits = _;
};
const Ct = 15, ff = 852, df = 592, sf = 0, Mn = 1, of = 2, s2 = new Uint16Array([
  /* Length codes 257..285 base */
  3,
  4,
  5,
  6,
  7,
  8,
  9,
  10,
  11,
  13,
  15,
  17,
  19,
  23,
  27,
  31,
  35,
  43,
  51,
  59,
  67,
  83,
  99,
  115,
  131,
  163,
  195,
  227,
  258,
  0,
  0
]), o2 = new Uint8Array([
  /* Length codes 257..285 extra */
  16,
  16,
  16,
  16,
  16,
  16,
  16,
  16,
  17,
  17,
  17,
  17,
  18,
  18,
  18,
  18,
  19,
  19,
  19,
  19,
  20,
  20,
  20,
  20,
  21,
  21,
  21,
  21,
  16,
  72,
  78
]), b2 = new Uint16Array([
  /* Distance codes 0..29 base */
  1,
  2,
  3,
  4,
  5,
  7,
  9,
  13,
  17,
  25,
  33,
  49,
  65,
  97,
  129,
  193,
  257,
  385,
  513,
  769,
  1025,
  1537,
  2049,
  3073,
  4097,
  6145,
  8193,
  12289,
  16385,
  24577,
  0,
  0
]), l2 = new Uint8Array([
  /* Distance codes 0..29 extra */
  16,
  16,
  16,
  16,
  17,
  17,
  18,
  18,
  19,
  19,
  20,
  20,
  21,
  21,
  22,
  22,
  23,
  23,
  24,
  24,
  25,
  25,
  26,
  26,
  27,
  27,
  28,
  28,
  29,
  29,
  64,
  64
]), u2 = (e, a, t, n, c, r, f, d) => {
  const o = d.bits;
  let i = 0, s = 0, b = 0, u = 0, l = 0, _ = 0, h = 0, p = 0, g = 0, E = 0, v, y, S, A, m, C = null, O;
  const T = new Uint16Array(Ct + 1), k = new Uint16Array(Ct + 1);
  let z = null, U, N, w;
  for (i = 0; i <= Ct; i++)
    T[i] = 0;
  for (s = 0; s < n; s++)
    T[a[t + s]]++;
  for (l = o, u = Ct; u >= 1 && T[u] === 0; u--)
    ;
  if (l > u && (l = u), u === 0)
    return c[r++] = 1 << 24 | 64 << 16 | 0, c[r++] = 1 << 24 | 64 << 16 | 0, d.bits = 1, 0;
  for (b = 1; b < u && T[b] === 0; b++)
    ;
  for (l < b && (l = b), p = 1, i = 1; i <= Ct; i++)
    if (p <<= 1, p -= T[i], p < 0)
      return -1;
  if (p > 0 && (e === sf || u !== 1))
    return -1;
  for (k[1] = 0, i = 1; i < Ct; i++)
    k[i + 1] = k[i] + T[i];
  for (s = 0; s < n; s++)
    a[t + s] !== 0 && (f[k[a[t + s]]++] = s);
  if (e === sf ? (C = z = f, O = 20) : e === Mn ? (C = s2, z = o2, O = 257) : (C = b2, z = l2, O = 0), E = 0, s = 0, i = b, m = r, _ = l, h = 0, S = -1, g = 1 << l, A = g - 1, e === Mn && g > ff || e === of && g > df)
    return 1;
  for (; ; ) {
    U = i - h, f[s] + 1 < O ? (N = 0, w = f[s]) : f[s] >= O ? (N = z[f[s] - O], w = C[f[s] - O]) : (N = 32 + 64, w = 0), v = 1 << i - h, y = 1 << _, b = y;
    do
      y -= v, c[m + (E >> h) + y] = U << 24 | N << 16 | w | 0;
    while (y !== 0);
    for (v = 1 << i - 1; E & v; )
      v >>= 1;
    if (v !== 0 ? (E &= v - 1, E += v) : E = 0, s++, --T[i] === 0) {
      if (i === u)
        break;
      i = a[t + f[s]];
    }
    if (i > l && (E & A) !== S) {
      for (h === 0 && (h = l), m += b, _ = i - h, p = 1 << _; _ + h < u && (p -= T[_ + h], !(p <= 0)); )
        _++, p <<= 1;
      if (g += 1 << _, e === Mn && g > ff || e === of && g > df)
        return 1;
      S = E & A, c[S] = l << 24 | _ << 16 | m - r | 0;
    }
  }
  return E !== 0 && (c[m + E] = i - h << 24 | 64 << 16 | 0), d.bits = l, 0;
};
var oa = u2;
const h2 = 0, Xd = 1, Jd = 2, {
  Z_FINISH: bf,
  Z_BLOCK: p2,
  Z_TREES: Za,
  Z_OK: _t,
  Z_STREAM_END: _2,
  Z_NEED_DICT: g2,
  Z_STREAM_ERROR: ye,
  Z_DATA_ERROR: Qd,
  Z_MEM_ERROR: ei,
  Z_BUF_ERROR: y2,
  Z_DEFLATED: lf
} = Yt, wn = 16180, uf = 16181, hf = 16182, pf = 16183, _f = 16184, gf = 16185, yf = 16186, wf = 16187, mf = 16188, Ef = 16189, cn = 16190, Re = 16191, Zn = 16192, vf = 16193, Vn = 16194, xf = 16195, Af = 16196, Sf = 16197, kf = 16198, Va = 16199, ja = 16200, Tf = 16201, Cf = 16202, If = 16203, Nf = 16204, Of = 16205, jn = 16206, Bf = 16207, Rf = 16208, F = 16209, ti = 16210, ai = 16211, w2 = 852, m2 = 592, E2 = 15, v2 = E2, Df = (e) => (e >>> 24 & 255) + (e >>> 8 & 65280) + ((e & 65280) << 8) + ((e & 255) << 24);
function x2() {
  this.strm = null, this.mode = 0, this.last = !1, this.wrap = 0, this.havedict = !1, this.flags = 0, this.dmax = 0, this.check = 0, this.total = 0, this.head = null, this.wbits = 0, this.wsize = 0, this.whave = 0, this.wnext = 0, this.window = null, this.hold = 0, this.bits = 0, this.length = 0, this.offset = 0, this.extra = 0, this.lencode = null, this.distcode = null, this.lenbits = 0, this.distbits = 0, this.ncode = 0, this.nlen = 0, this.ndist = 0, this.have = 0, this.next = null, this.lens = new Uint16Array(320), this.work = new Uint16Array(288), this.lendyn = null, this.distdyn = null, this.sane = 0, this.back = 0, this.was = 0;
}
const vt = (e) => {
  if (!e)
    return 1;
  const a = e.state;
  return !a || a.strm !== e || a.mode < wn || a.mode > ai ? 1 : 0;
}, ni = (e) => {
  if (vt(e))
    return ye;
  const a = e.state;
  return e.total_in = e.total_out = a.total = 0, e.msg = "", a.wrap && (e.adler = a.wrap & 1), a.mode = wn, a.last = 0, a.havedict = 0, a.flags = -1, a.dmax = 32768, a.head = null, a.hold = 0, a.bits = 0, a.lencode = a.lendyn = new Int32Array(w2), a.distcode = a.distdyn = new Int32Array(m2), a.sane = 1, a.back = -1, _t;
}, ci = (e) => {
  if (vt(e))
    return ye;
  const a = e.state;
  return a.wsize = 0, a.whave = 0, a.wnext = 0, ni(e);
}, ri = (e, a) => {
  let t;
  if (vt(e))
    return ye;
  const n = e.state;
  return a < 0 ? (t = 0, a = -a) : (t = (a >> 4) + 5, a < 48 && (a &= 15)), a && (a < 8 || a > 15) ? ye : (n.window !== null && n.wbits !== a && (n.window = null), n.wrap = t, n.wbits = a, ci(e));
}, fi = (e, a) => {
  if (!e)
    return ye;
  const t = new x2();
  e.state = t, t.strm = e, t.window = null, t.mode = wn;
  const n = ri(e, a);
  return n !== _t && (e.state = null), n;
}, A2 = (e) => fi(e, v2);
let Lf = !0, qn, Kn;
const S2 = (e) => {
  if (Lf) {
    qn = new Int32Array(512), Kn = new Int32Array(32);
    let a = 0;
    for (; a < 144; )
      e.lens[a++] = 8;
    for (; a < 256; )
      e.lens[a++] = 9;
    for (; a < 280; )
      e.lens[a++] = 7;
    for (; a < 288; )
      e.lens[a++] = 8;
    for (oa(Xd, e.lens, 0, 288, qn, 0, e.work, { bits: 9 }), a = 0; a < 32; )
      e.lens[a++] = 5;
    oa(Jd, e.lens, 0, 32, Kn, 0, e.work, { bits: 5 }), Lf = !1;
  }
  e.lencode = qn, e.lenbits = 9, e.distcode = Kn, e.distbits = 5;
}, di = (e, a, t, n) => {
  let c;
  const r = e.state;
  return r.window === null && (r.wsize = 1 << r.wbits, r.wnext = 0, r.whave = 0, r.window = new Uint8Array(r.wsize)), n >= r.wsize ? (r.window.set(a.subarray(t - r.wsize, t), 0), r.wnext = 0, r.whave = r.wsize) : (c = r.wsize - r.wnext, c > n && (c = n), r.window.set(a.subarray(t - n, t - n + c), r.wnext), n -= c, n ? (r.window.set(a.subarray(t - n, t), 0), r.wnext = n, r.whave = r.wsize) : (r.wnext += c, r.wnext === r.wsize && (r.wnext = 0), r.whave < r.wsize && (r.whave += c))), 0;
}, k2 = (e, a) => {
  let t, n, c, r, f, d, o, i, s, b, u, l, _, h, p = 0, g, E, v, y, S, A, m, C;
  const O = new Uint8Array(4);
  let T, k;
  const z = (
    /* permutation of code lengths */
    new Uint8Array([16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15])
  );
  if (vt(e) || !e.output || !e.input && e.avail_in !== 0)
    return ye;
  t = e.state, t.mode === Re && (t.mode = Zn), f = e.next_out, c = e.output, o = e.avail_out, r = e.next_in, n = e.input, d = e.avail_in, i = t.hold, s = t.bits, b = d, u = o, C = _t;
  e:
    for (; ; )
      switch (t.mode) {
        case wn:
          if (t.wrap === 0) {
            t.mode = Zn;
            break;
          }
          for (; s < 16; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          if (t.wrap & 2 && i === 35615) {
            t.wbits === 0 && (t.wbits = 15), t.check = 0, O[0] = i & 255, O[1] = i >>> 8 & 255, t.check = K(t.check, O, 2, 0), i = 0, s = 0, t.mode = uf;
            break;
          }
          if (t.head && (t.head.done = !1), !(t.wrap & 1) || /* check if zlib header allowed */
          (((i & 255) << 8) + (i >> 8)) % 31) {
            e.msg = "incorrect header check", t.mode = F;
            break;
          }
          if ((i & 15) !== lf) {
            e.msg = "unknown compression method", t.mode = F;
            break;
          }
          if (i >>>= 4, s -= 4, m = (i & 15) + 8, t.wbits === 0 && (t.wbits = m), m > 15 || m > t.wbits) {
            e.msg = "invalid window size", t.mode = F;
            break;
          }
          t.dmax = 1 << t.wbits, t.flags = 0, e.adler = t.check = 1, t.mode = i & 512 ? Ef : Re, i = 0, s = 0;
          break;
        case uf:
          for (; s < 16; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          if (t.flags = i, (t.flags & 255) !== lf) {
            e.msg = "unknown compression method", t.mode = F;
            break;
          }
          if (t.flags & 57344) {
            e.msg = "unknown header flags set", t.mode = F;
            break;
          }
          t.head && (t.head.text = i >> 8 & 1), t.flags & 512 && t.wrap & 4 && (O[0] = i & 255, O[1] = i >>> 8 & 255, t.check = K(t.check, O, 2, 0)), i = 0, s = 0, t.mode = hf;
        case hf:
          for (; s < 32; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          t.head && (t.head.time = i), t.flags & 512 && t.wrap & 4 && (O[0] = i & 255, O[1] = i >>> 8 & 255, O[2] = i >>> 16 & 255, O[3] = i >>> 24 & 255, t.check = K(t.check, O, 4, 0)), i = 0, s = 0, t.mode = pf;
        case pf:
          for (; s < 16; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          t.head && (t.head.xflags = i & 255, t.head.os = i >> 8), t.flags & 512 && t.wrap & 4 && (O[0] = i & 255, O[1] = i >>> 8 & 255, t.check = K(t.check, O, 2, 0)), i = 0, s = 0, t.mode = _f;
        case _f:
          if (t.flags & 1024) {
            for (; s < 16; ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            t.length = i, t.head && (t.head.extra_len = i), t.flags & 512 && t.wrap & 4 && (O[0] = i & 255, O[1] = i >>> 8 & 255, t.check = K(t.check, O, 2, 0)), i = 0, s = 0;
          } else
            t.head && (t.head.extra = null);
          t.mode = gf;
        case gf:
          if (t.flags & 1024 && (l = t.length, l > d && (l = d), l && (t.head && (m = t.head.extra_len - t.length, t.head.extra || (t.head.extra = new Uint8Array(t.head.extra_len)), t.head.extra.set(
            n.subarray(
              r,
              // extra field is limited to 65536 bytes
              // - no need for additional size check
              r + l
            ),
            /*len + copy > state.head.extra_max - len ? state.head.extra_max : copy,*/
            m
          )), t.flags & 512 && t.wrap & 4 && (t.check = K(t.check, n, l, r)), d -= l, r += l, t.length -= l), t.length))
            break e;
          t.length = 0, t.mode = yf;
        case yf:
          if (t.flags & 2048) {
            if (d === 0)
              break e;
            l = 0;
            do
              m = n[r + l++], t.head && m && t.length < 65536 && (t.head.name += String.fromCharCode(m));
            while (m && l < d);
            if (t.flags & 512 && t.wrap & 4 && (t.check = K(t.check, n, l, r)), d -= l, r += l, m)
              break e;
          } else
            t.head && (t.head.name = null);
          t.length = 0, t.mode = wf;
        case wf:
          if (t.flags & 4096) {
            if (d === 0)
              break e;
            l = 0;
            do
              m = n[r + l++], t.head && m && t.length < 65536 && (t.head.comment += String.fromCharCode(m));
            while (m && l < d);
            if (t.flags & 512 && t.wrap & 4 && (t.check = K(t.check, n, l, r)), d -= l, r += l, m)
              break e;
          } else
            t.head && (t.head.comment = null);
          t.mode = mf;
        case mf:
          if (t.flags & 512) {
            for (; s < 16; ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            if (t.wrap & 4 && i !== (t.check & 65535)) {
              e.msg = "header crc mismatch", t.mode = F;
              break;
            }
            i = 0, s = 0;
          }
          t.head && (t.head.hcrc = t.flags >> 9 & 1, t.head.done = !0), e.adler = t.check = 0, t.mode = Re;
          break;
        case Ef:
          for (; s < 32; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          e.adler = t.check = Df(i), i = 0, s = 0, t.mode = cn;
        case cn:
          if (t.havedict === 0)
            return e.next_out = f, e.avail_out = o, e.next_in = r, e.avail_in = d, t.hold = i, t.bits = s, g2;
          e.adler = t.check = 1, t.mode = Re;
        case Re:
          if (a === p2 || a === Za)
            break e;
        case Zn:
          if (t.last) {
            i >>>= s & 7, s -= s & 7, t.mode = jn;
            break;
          }
          for (; s < 3; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          switch (t.last = i & 1, i >>>= 1, s -= 1, i & 3) {
            case 0:
              t.mode = vf;
              break;
            case 1:
              if (S2(t), t.mode = Va, a === Za) {
                i >>>= 2, s -= 2;
                break e;
              }
              break;
            case 2:
              t.mode = Af;
              break;
            case 3:
              e.msg = "invalid block type", t.mode = F;
          }
          i >>>= 2, s -= 2;
          break;
        case vf:
          for (i >>>= s & 7, s -= s & 7; s < 32; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          if ((i & 65535) !== (i >>> 16 ^ 65535)) {
            e.msg = "invalid stored block lengths", t.mode = F;
            break;
          }
          if (t.length = i & 65535, i = 0, s = 0, t.mode = Vn, a === Za)
            break e;
        case Vn:
          t.mode = xf;
        case xf:
          if (l = t.length, l) {
            if (l > d && (l = d), l > o && (l = o), l === 0)
              break e;
            c.set(n.subarray(r, r + l), f), d -= l, r += l, o -= l, f += l, t.length -= l;
            break;
          }
          t.mode = Re;
          break;
        case Af:
          for (; s < 14; ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          if (t.nlen = (i & 31) + 257, i >>>= 5, s -= 5, t.ndist = (i & 31) + 1, i >>>= 5, s -= 5, t.ncode = (i & 15) + 4, i >>>= 4, s -= 4, t.nlen > 286 || t.ndist > 30) {
            e.msg = "too many length or distance symbols", t.mode = F;
            break;
          }
          t.have = 0, t.mode = Sf;
        case Sf:
          for (; t.have < t.ncode; ) {
            for (; s < 3; ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            t.lens[z[t.have++]] = i & 7, i >>>= 3, s -= 3;
          }
          for (; t.have < 19; )
            t.lens[z[t.have++]] = 0;
          if (t.lencode = t.lendyn, t.lenbits = 7, T = { bits: t.lenbits }, C = oa(h2, t.lens, 0, 19, t.lencode, 0, t.work, T), t.lenbits = T.bits, C) {
            e.msg = "invalid code lengths set", t.mode = F;
            break;
          }
          t.have = 0, t.mode = kf;
        case kf:
          for (; t.have < t.nlen + t.ndist; ) {
            for (; p = t.lencode[i & (1 << t.lenbits) - 1], g = p >>> 24, E = p >>> 16 & 255, v = p & 65535, !(g <= s); ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            if (v < 16)
              i >>>= g, s -= g, t.lens[t.have++] = v;
            else {
              if (v === 16) {
                for (k = g + 2; s < k; ) {
                  if (d === 0)
                    break e;
                  d--, i += n[r++] << s, s += 8;
                }
                if (i >>>= g, s -= g, t.have === 0) {
                  e.msg = "invalid bit length repeat", t.mode = F;
                  break;
                }
                m = t.lens[t.have - 1], l = 3 + (i & 3), i >>>= 2, s -= 2;
              } else if (v === 17) {
                for (k = g + 3; s < k; ) {
                  if (d === 0)
                    break e;
                  d--, i += n[r++] << s, s += 8;
                }
                i >>>= g, s -= g, m = 0, l = 3 + (i & 7), i >>>= 3, s -= 3;
              } else {
                for (k = g + 7; s < k; ) {
                  if (d === 0)
                    break e;
                  d--, i += n[r++] << s, s += 8;
                }
                i >>>= g, s -= g, m = 0, l = 11 + (i & 127), i >>>= 7, s -= 7;
              }
              if (t.have + l > t.nlen + t.ndist) {
                e.msg = "invalid bit length repeat", t.mode = F;
                break;
              }
              for (; l--; )
                t.lens[t.have++] = m;
            }
          }
          if (t.mode === F)
            break;
          if (t.lens[256] === 0) {
            e.msg = "invalid code -- missing end-of-block", t.mode = F;
            break;
          }
          if (t.lenbits = 9, T = { bits: t.lenbits }, C = oa(Xd, t.lens, 0, t.nlen, t.lencode, 0, t.work, T), t.lenbits = T.bits, C) {
            e.msg = "invalid literal/lengths set", t.mode = F;
            break;
          }
          if (t.distbits = 6, t.distcode = t.distdyn, T = { bits: t.distbits }, C = oa(Jd, t.lens, t.nlen, t.ndist, t.distcode, 0, t.work, T), t.distbits = T.bits, C) {
            e.msg = "invalid distances set", t.mode = F;
            break;
          }
          if (t.mode = Va, a === Za)
            break e;
        case Va:
          t.mode = ja;
        case ja:
          if (d >= 6 && o >= 258) {
            e.next_out = f, e.avail_out = o, e.next_in = r, e.avail_in = d, t.hold = i, t.bits = s, i2(e, u), f = e.next_out, c = e.output, o = e.avail_out, r = e.next_in, n = e.input, d = e.avail_in, i = t.hold, s = t.bits, t.mode === Re && (t.back = -1);
            break;
          }
          for (t.back = 0; p = t.lencode[i & (1 << t.lenbits) - 1], g = p >>> 24, E = p >>> 16 & 255, v = p & 65535, !(g <= s); ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          if (E && !(E & 240)) {
            for (y = g, S = E, A = v; p = t.lencode[A + ((i & (1 << y + S) - 1) >> y)], g = p >>> 24, E = p >>> 16 & 255, v = p & 65535, !(y + g <= s); ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            i >>>= y, s -= y, t.back += y;
          }
          if (i >>>= g, s -= g, t.back += g, t.length = v, E === 0) {
            t.mode = Of;
            break;
          }
          if (E & 32) {
            t.back = -1, t.mode = Re;
            break;
          }
          if (E & 64) {
            e.msg = "invalid literal/length code", t.mode = F;
            break;
          }
          t.extra = E & 15, t.mode = Tf;
        case Tf:
          if (t.extra) {
            for (k = t.extra; s < k; ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            t.length += i & (1 << t.extra) - 1, i >>>= t.extra, s -= t.extra, t.back += t.extra;
          }
          t.was = t.length, t.mode = Cf;
        case Cf:
          for (; p = t.distcode[i & (1 << t.distbits) - 1], g = p >>> 24, E = p >>> 16 & 255, v = p & 65535, !(g <= s); ) {
            if (d === 0)
              break e;
            d--, i += n[r++] << s, s += 8;
          }
          if (!(E & 240)) {
            for (y = g, S = E, A = v; p = t.distcode[A + ((i & (1 << y + S) - 1) >> y)], g = p >>> 24, E = p >>> 16 & 255, v = p & 65535, !(y + g <= s); ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            i >>>= y, s -= y, t.back += y;
          }
          if (i >>>= g, s -= g, t.back += g, E & 64) {
            e.msg = "invalid distance code", t.mode = F;
            break;
          }
          t.offset = v, t.extra = E & 15, t.mode = If;
        case If:
          if (t.extra) {
            for (k = t.extra; s < k; ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            t.offset += i & (1 << t.extra) - 1, i >>>= t.extra, s -= t.extra, t.back += t.extra;
          }
          if (t.offset > t.dmax) {
            e.msg = "invalid distance too far back", t.mode = F;
            break;
          }
          t.mode = Nf;
        case Nf:
          if (o === 0)
            break e;
          if (l = u - o, t.offset > l) {
            if (l = t.offset - l, l > t.whave && t.sane) {
              e.msg = "invalid distance too far back", t.mode = F;
              break;
            }
            l > t.wnext ? (l -= t.wnext, _ = t.wsize - l) : _ = t.wnext - l, l > t.length && (l = t.length), h = t.window;
          } else
            h = c, _ = f - t.offset, l = t.length;
          l > o && (l = o), o -= l, t.length -= l;
          do
            c[f++] = h[_++];
          while (--l);
          t.length === 0 && (t.mode = ja);
          break;
        case Of:
          if (o === 0)
            break e;
          c[f++] = t.length, o--, t.mode = ja;
          break;
        case jn:
          if (t.wrap) {
            for (; s < 32; ) {
              if (d === 0)
                break e;
              d--, i |= n[r++] << s, s += 8;
            }
            if (u -= o, e.total_out += u, t.total += u, t.wrap & 4 && u && (e.adler = t.check = /*UPDATE_CHECK(state.check, put - _out, _out);*/
            t.flags ? K(t.check, c, u, f - u) : ga(t.check, c, u, f - u)), u = o, t.wrap & 4 && (t.flags ? i : Df(i)) !== t.check) {
              e.msg = "incorrect data check", t.mode = F;
              break;
            }
            i = 0, s = 0;
          }
          t.mode = Bf;
        case Bf:
          if (t.wrap && t.flags) {
            for (; s < 32; ) {
              if (d === 0)
                break e;
              d--, i += n[r++] << s, s += 8;
            }
            if (t.wrap & 4 && i !== (t.total & 4294967295)) {
              e.msg = "incorrect length check", t.mode = F;
              break;
            }
            i = 0, s = 0;
          }
          t.mode = Rf;
        case Rf:
          C = _2;
          break e;
        case F:
          C = Qd;
          break e;
        case ti:
          return ei;
        case ai:
        default:
          return ye;
      }
  return e.next_out = f, e.avail_out = o, e.next_in = r, e.avail_in = d, t.hold = i, t.bits = s, (t.wsize || u !== e.avail_out && t.mode < F && (t.mode < jn || a !== bf)) && di(e, e.output, e.next_out, u - e.avail_out), b -= e.avail_in, u -= e.avail_out, e.total_in += b, e.total_out += u, t.total += u, t.wrap & 4 && u && (e.adler = t.check = /*UPDATE_CHECK(state.check, strm.next_out - _out, _out);*/
  t.flags ? K(t.check, c, u, e.next_out - u) : ga(t.check, c, u, e.next_out - u)), e.data_type = t.bits + (t.last ? 64 : 0) + (t.mode === Re ? 128 : 0) + (t.mode === Va || t.mode === Vn ? 256 : 0), (b === 0 && u === 0 || a === bf) && C === _t && (C = y2), C;
}, T2 = (e) => {
  if (vt(e))
    return ye;
  let a = e.state;
  return a.window && (a.window = null), e.state = null, _t;
}, C2 = (e, a) => {
  if (vt(e))
    return ye;
  const t = e.state;
  return t.wrap & 2 ? (t.head = a, a.done = !1, _t) : ye;
}, I2 = (e, a) => {
  const t = a.length;
  let n, c, r;
  return vt(e) || (n = e.state, n.wrap !== 0 && n.mode !== cn) ? ye : n.mode === cn && (c = 1, c = ga(c, a, t, 0), c !== n.check) ? Qd : (r = di(e, a, t, t), r ? (n.mode = ti, ei) : (n.havedict = 1, _t));
};
var N2 = ci, O2 = ri, B2 = ni, R2 = A2, D2 = fi, L2 = k2, $2 = T2, P2 = C2, H2 = I2, U2 = "pako inflate (from Nodeca project)", Le = {
  inflateReset: N2,
  inflateReset2: O2,
  inflateResetKeep: B2,
  inflateInit: R2,
  inflateInit2: D2,
  inflate: L2,
  inflateEnd: $2,
  inflateGetHeader: P2,
  inflateSetDictionary: H2,
  inflateInfo: U2
};
function F2() {
  this.text = 0, this.time = 0, this.xflags = 0, this.os = 0, this.extra = null, this.extra_len = 0, this.name = "", this.comment = "", this.hcrc = 0, this.done = !1;
}
var z2 = F2;
const ii = Object.prototype.toString, {
  Z_NO_FLUSH: M2,
  Z_FINISH: Z2,
  Z_OK: ma,
  Z_STREAM_END: Gn,
  Z_NEED_DICT: Yn,
  Z_STREAM_ERROR: V2,
  Z_DATA_ERROR: $f,
  Z_MEM_ERROR: j2
} = Yt;
function Na(e) {
  this.options = yn.assign({
    chunkSize: 1024 * 64,
    windowBits: 15,
    to: ""
  }, e || {});
  const a = this.options;
  a.raw && a.windowBits >= 0 && a.windowBits < 16 && (a.windowBits = -a.windowBits, a.windowBits === 0 && (a.windowBits = -15)), a.windowBits >= 0 && a.windowBits < 16 && !(e && e.windowBits) && (a.windowBits += 32), a.windowBits > 15 && a.windowBits < 48 && (a.windowBits & 15 || (a.windowBits |= 15)), this.err = 0, this.msg = "", this.ended = !1, this.chunks = [], this.strm = new Yd(), this.strm.avail_out = 0;
  let t = Le.inflateInit2(
    this.strm,
    a.windowBits
  );
  if (t !== ma)
    throw new Error(ht[t]);
  if (this.header = new z2(), Le.inflateGetHeader(this.strm, this.header), a.dictionary && (typeof a.dictionary == "string" ? a.dictionary = wa.string2buf(a.dictionary) : ii.call(a.dictionary) === "[object ArrayBuffer]" && (a.dictionary = new Uint8Array(a.dictionary)), a.raw && (t = Le.inflateSetDictionary(this.strm, a.dictionary), t !== ma)))
    throw new Error(ht[t]);
}
Na.prototype.push = function(e, a) {
  const t = this.strm, n = this.options.chunkSize, c = this.options.dictionary;
  let r, f, d;
  if (this.ended)
    return !1;
  for (a === ~~a ? f = a : f = a === !0 ? Z2 : M2, ii.call(e) === "[object ArrayBuffer]" ? t.input = new Uint8Array(e) : t.input = e, t.next_in = 0, t.avail_in = t.input.length; ; ) {
    for (t.avail_out === 0 && (t.output = new Uint8Array(n), t.next_out = 0, t.avail_out = n), r = Le.inflate(t, f), r === Yn && c && (r = Le.inflateSetDictionary(t, c), r === ma ? r = Le.inflate(t, f) : r === $f && (r = Yn)); t.avail_in > 0 && r === Gn && t.state.wrap > 0 && e[t.next_in] !== 0; )
      Le.inflateReset(t), r = Le.inflate(t, f);
    switch (r) {
      case V2:
      case $f:
      case Yn:
      case j2:
        return this.onEnd(r), this.ended = !0, !1;
    }
    if (d = t.avail_out, t.next_out && (t.avail_out === 0 || r === Gn))
      if (this.options.to === "string") {
        let o = wa.utf8border(t.output, t.next_out), i = t.next_out - o, s = wa.buf2string(t.output, o);
        t.next_out = i, t.avail_out = n - i, i && t.output.set(t.output.subarray(o, o + i), 0), this.onData(s);
      } else
        this.onData(t.output.length === t.next_out ? t.output : t.output.subarray(0, t.next_out));
    if (!(r === ma && d === 0)) {
      if (r === Gn)
        return r = Le.inflateEnd(this.strm), this.onEnd(r), this.ended = !0, !0;
      if (t.avail_in === 0)
        break;
    }
  }
  return !0;
};
Na.prototype.onData = function(e) {
  this.chunks.push(e);
};
Na.prototype.onEnd = function(e) {
  e === ma && (this.options.to === "string" ? this.result = this.chunks.join("") : this.result = yn.flattenChunks(this.chunks)), this.chunks = [], this.err = e, this.msg = this.strm.msg;
};
function qc(e, a) {
  const t = new Na(a);
  if (t.push(e), t.err)
    throw t.msg || ht[t.err];
  return t.result;
}
function q2(e, a) {
  return a = a || {}, a.raw = !0, qc(e, a);
}
var K2 = Na, G2 = qc, Y2 = q2, W2 = qc, X2 = Yt, J2 = {
  Inflate: K2,
  inflate: G2,
  inflateRaw: Y2,
  ungzip: W2,
  constants: X2
};
const { Deflate: R3, deflate: D3, deflateRaw: L3, gzip: Q2 } = f2, { Inflate: $3, inflate: P3, inflateRaw: H3, ungzip: e6 } = J2;
var t6 = Q2, a6 = e6, bt = typeof globalThis < "u" ? globalThis : typeof window < "u" ? window : typeof global < "u" ? global : typeof self < "u" ? self : {};
function si(e) {
  return e && e.__esModule && Object.prototype.hasOwnProperty.call(e, "default") ? e.default : e;
}
function n6(e) {
  if (e.__esModule)
    return e;
  var a = e.default;
  if (typeof a == "function") {
    var t = function n() {
      return this instanceof n ? Reflect.construct(a, arguments, this.constructor) : a.apply(this, arguments);
    };
    t.prototype = a.prototype;
  } else
    t = {};
  return Object.defineProperty(t, "__esModule", { value: !0 }), Object.keys(e).forEach(function(n) {
    var c = Object.getOwnPropertyDescriptor(e, n);
    Object.defineProperty(t, n, c.get ? c : {
      enumerable: !0,
      get: function() {
        return e[n];
      }
    });
  }), t;
}
var X = typeof globalThis < "u" && globalThis || typeof self < "u" && self || // eslint-disable-next-line no-undef
typeof global < "u" && global || {}, te = {
  searchParams: "URLSearchParams" in X,
  iterable: "Symbol" in X && "iterator" in Symbol,
  blob: "FileReader" in X && "Blob" in X && function() {
    try {
      return new Blob(), !0;
    } catch {
      return !1;
    }
  }(),
  formData: "FormData" in X,
  arrayBuffer: "ArrayBuffer" in X
};
function c6(e) {
  return e && DataView.prototype.isPrototypeOf(e);
}
if (te.arrayBuffer)
  var r6 = [
    "[object Int8Array]",
    "[object Uint8Array]",
    "[object Uint8ClampedArray]",
    "[object Int16Array]",
    "[object Uint16Array]",
    "[object Int32Array]",
    "[object Uint32Array]",
    "[object Float32Array]",
    "[object Float64Array]"
  ], f6 = ArrayBuffer.isView || function(e) {
    return e && r6.indexOf(Object.prototype.toString.call(e)) > -1;
  };
function Jt(e) {
  if (typeof e != "string" && (e = String(e)), /[^a-z0-9\-#$%&'*+.^_`|~!]/i.test(e) || e === "")
    throw new TypeError('Invalid character in header field name: "' + e + '"');
  return e.toLowerCase();
}
function Kc(e) {
  return typeof e != "string" && (e = String(e)), e;
}
function Gc(e) {
  var a = {
    next: function() {
      var t = e.shift();
      return { done: t === void 0, value: t };
    }
  };
  return te.iterable && (a[Symbol.iterator] = function() {
    return a;
  }), a;
}
function q(e) {
  this.map = {}, e instanceof q ? e.forEach(function(a, t) {
    this.append(t, a);
  }, this) : Array.isArray(e) ? e.forEach(function(a) {
    if (a.length != 2)
      throw new TypeError("Headers constructor: expected name/value pair to be length 2, found" + a.length);
    this.append(a[0], a[1]);
  }, this) : e && Object.getOwnPropertyNames(e).forEach(function(a) {
    this.append(a, e[a]);
  }, this);
}
q.prototype.append = function(e, a) {
  e = Jt(e), a = Kc(a);
  var t = this.map[e];
  this.map[e] = t ? t + ", " + a : a;
};
q.prototype.delete = function(e) {
  delete this.map[Jt(e)];
};
q.prototype.get = function(e) {
  return e = Jt(e), this.has(e) ? this.map[e] : null;
};
q.prototype.has = function(e) {
  return this.map.hasOwnProperty(Jt(e));
};
q.prototype.set = function(e, a) {
  this.map[Jt(e)] = Kc(a);
};
q.prototype.forEach = function(e, a) {
  for (var t in this.map)
    this.map.hasOwnProperty(t) && e.call(a, this.map[t], t, this);
};
q.prototype.keys = function() {
  var e = [];
  return this.forEach(function(a, t) {
    e.push(t);
  }), Gc(e);
};
q.prototype.values = function() {
  var e = [];
  return this.forEach(function(a) {
    e.push(a);
  }), Gc(e);
};
q.prototype.entries = function() {
  var e = [];
  return this.forEach(function(a, t) {
    e.push([t, a]);
  }), Gc(e);
};
te.iterable && (q.prototype[Symbol.iterator] = q.prototype.entries);
function Wn(e) {
  if (!e._noBody) {
    if (e.bodyUsed)
      return Promise.reject(new TypeError("Already read"));
    e.bodyUsed = !0;
  }
}
function oi(e) {
  return new Promise(function(a, t) {
    e.onload = function() {
      a(e.result);
    }, e.onerror = function() {
      t(e.error);
    };
  });
}
function d6(e) {
  var a = new FileReader(), t = oi(a);
  return a.readAsArrayBuffer(e), t;
}
function i6(e) {
  var a = new FileReader(), t = oi(a), n = /charset=([A-Za-z0-9_-]+)/.exec(e.type), c = n ? n[1] : "utf-8";
  return a.readAsText(e, c), t;
}
function s6(e) {
  for (var a = new Uint8Array(e), t = new Array(a.length), n = 0; n < a.length; n++)
    t[n] = String.fromCharCode(a[n]);
  return t.join("");
}
function Pf(e) {
  if (e.slice)
    return e.slice(0);
  var a = new Uint8Array(e.byteLength);
  return a.set(new Uint8Array(e)), a.buffer;
}
function bi() {
  return this.bodyUsed = !1, this._initBody = function(e) {
    this.bodyUsed = this.bodyUsed, this._bodyInit = e, e ? typeof e == "string" ? this._bodyText = e : te.blob && Blob.prototype.isPrototypeOf(e) ? this._bodyBlob = e : te.formData && FormData.prototype.isPrototypeOf(e) ? this._bodyFormData = e : te.searchParams && URLSearchParams.prototype.isPrototypeOf(e) ? this._bodyText = e.toString() : te.arrayBuffer && te.blob && c6(e) ? (this._bodyArrayBuffer = Pf(e.buffer), this._bodyInit = new Blob([this._bodyArrayBuffer])) : te.arrayBuffer && (ArrayBuffer.prototype.isPrototypeOf(e) || f6(e)) ? this._bodyArrayBuffer = Pf(e) : this._bodyText = e = Object.prototype.toString.call(e) : (this._noBody = !0, this._bodyText = ""), this.headers.get("content-type") || (typeof e == "string" ? this.headers.set("content-type", "text/plain;charset=UTF-8") : this._bodyBlob && this._bodyBlob.type ? this.headers.set("content-type", this._bodyBlob.type) : te.searchParams && URLSearchParams.prototype.isPrototypeOf(e) && this.headers.set("content-type", "application/x-www-form-urlencoded;charset=UTF-8"));
  }, te.blob && (this.blob = function() {
    var e = Wn(this);
    if (e)
      return e;
    if (this._bodyBlob)
      return Promise.resolve(this._bodyBlob);
    if (this._bodyArrayBuffer)
      return Promise.resolve(new Blob([this._bodyArrayBuffer]));
    if (this._bodyFormData)
      throw new Error("could not read FormData body as blob");
    return Promise.resolve(new Blob([this._bodyText]));
  }), this.arrayBuffer = function() {
    if (this._bodyArrayBuffer) {
      var e = Wn(this);
      return e || (ArrayBuffer.isView(this._bodyArrayBuffer) ? Promise.resolve(
        this._bodyArrayBuffer.buffer.slice(
          this._bodyArrayBuffer.byteOffset,
          this._bodyArrayBuffer.byteOffset + this._bodyArrayBuffer.byteLength
        )
      ) : Promise.resolve(this._bodyArrayBuffer));
    } else {
      if (te.blob)
        return this.blob().then(d6);
      throw new Error("could not read as ArrayBuffer");
    }
  }, this.text = function() {
    var e = Wn(this);
    if (e)
      return e;
    if (this._bodyBlob)
      return i6(this._bodyBlob);
    if (this._bodyArrayBuffer)
      return Promise.resolve(s6(this._bodyArrayBuffer));
    if (this._bodyFormData)
      throw new Error("could not read FormData body as text");
    return Promise.resolve(this._bodyText);
  }, te.formData && (this.formData = function() {
    return this.text().then(l6);
  }), this.json = function() {
    return this.text().then(JSON.parse);
  }, this;
}
var o6 = ["CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT", "TRACE"];
function b6(e) {
  var a = e.toUpperCase();
  return o6.indexOf(a) > -1 ? a : e;
}
function gt(e, a) {
  if (!(this instanceof gt))
    throw new TypeError('Please use the "new" operator, this DOM object constructor cannot be called as a function.');
  a = a || {};
  var t = a.body;
  if (e instanceof gt) {
    if (e.bodyUsed)
      throw new TypeError("Already read");
    this.url = e.url, this.credentials = e.credentials, a.headers || (this.headers = new q(e.headers)), this.method = e.method, this.mode = e.mode, this.signal = e.signal, !t && e._bodyInit != null && (t = e._bodyInit, e.bodyUsed = !0);
  } else
    this.url = String(e);
  if (this.credentials = a.credentials || this.credentials || "same-origin", (a.headers || !this.headers) && (this.headers = new q(a.headers)), this.method = b6(a.method || this.method || "GET"), this.mode = a.mode || this.mode || null, this.signal = a.signal || this.signal || function() {
    if ("AbortController" in X) {
      var r = new AbortController();
      return r.signal;
    }
  }(), this.referrer = null, (this.method === "GET" || this.method === "HEAD") && t)
    throw new TypeError("Body not allowed for GET or HEAD requests");
  if (this._initBody(t), (this.method === "GET" || this.method === "HEAD") && (a.cache === "no-store" || a.cache === "no-cache")) {
    var n = /([?&])_=[^&]*/;
    if (n.test(this.url))
      this.url = this.url.replace(n, "$1_=" + (/* @__PURE__ */ new Date()).getTime());
    else {
      var c = /\?/;
      this.url += (c.test(this.url) ? "&" : "?") + "_=" + (/* @__PURE__ */ new Date()).getTime();
    }
  }
}
gt.prototype.clone = function() {
  return new gt(this, { body: this._bodyInit });
};
function l6(e) {
  var a = new FormData();
  return e.trim().split("&").forEach(function(t) {
    if (t) {
      var n = t.split("="), c = n.shift().replace(/\+/g, " "), r = n.join("=").replace(/\+/g, " ");
      a.append(decodeURIComponent(c), decodeURIComponent(r));
    }
  }), a;
}
function u6(e) {
  var a = new q(), t = e.replace(/\r?\n[\t ]+/g, " ");
  return t.split("\r").map(function(n) {
    return n.indexOf(`
`) === 0 ? n.substr(1, n.length) : n;
  }).forEach(function(n) {
    var c = n.split(":"), r = c.shift().trim();
    if (r) {
      var f = c.join(":").trim();
      try {
        a.append(r, f);
      } catch (d) {
        console.warn("Response " + d.message);
      }
    }
  }), a;
}
bi.call(gt.prototype);
function Ne(e, a) {
  if (!(this instanceof Ne))
    throw new TypeError('Please use the "new" operator, this DOM object constructor cannot be called as a function.');
  if (a || (a = {}), this.type = "default", this.status = a.status === void 0 ? 200 : a.status, this.status < 200 || this.status > 599)
    throw new RangeError("Failed to construct 'Response': The status provided (0) is outside the range [200, 599].");
  this.ok = this.status >= 200 && this.status < 300, this.statusText = a.statusText === void 0 ? "" : "" + a.statusText, this.headers = new q(a.headers), this.url = a.url || "", this._initBody(e);
}
bi.call(Ne.prototype);
Ne.prototype.clone = function() {
  return new Ne(this._bodyInit, {
    status: this.status,
    statusText: this.statusText,
    headers: new q(this.headers),
    url: this.url
  });
};
Ne.error = function() {
  var e = new Ne(null, { status: 200, statusText: "" });
  return e.status = 0, e.type = "error", e;
};
var h6 = [301, 302, 303, 307, 308];
Ne.redirect = function(e, a) {
  if (h6.indexOf(a) === -1)
    throw new RangeError("Invalid status code");
  return new Ne(null, { status: a, headers: { location: e } });
};
var ft = X.DOMException;
try {
  new ft();
} catch {
  ft = function(a, t) {
    this.message = a, this.name = t;
    var n = Error(a);
    this.stack = n.stack;
  }, ft.prototype = Object.create(Error.prototype), ft.prototype.constructor = ft;
}
function li(e, a) {
  return new Promise(function(t, n) {
    var c = new gt(e, a);
    if (c.signal && c.signal.aborted)
      return n(new ft("Aborted", "AbortError"));
    var r = new XMLHttpRequest();
    function f() {
      r.abort();
    }
    r.onload = function() {
      var i = {
        statusText: r.statusText,
        headers: u6(r.getAllResponseHeaders() || "")
      };
      c.url.startsWith("file://") && (r.status < 200 || r.status > 599) ? i.status = 200 : i.status = r.status, i.url = "responseURL" in r ? r.responseURL : i.headers.get("X-Request-URL");
      var s = "response" in r ? r.response : r.responseText;
      setTimeout(function() {
        t(new Ne(s, i));
      }, 0);
    }, r.onerror = function() {
      setTimeout(function() {
        n(new TypeError("Network request failed"));
      }, 0);
    }, r.ontimeout = function() {
      setTimeout(function() {
        n(new TypeError("Network request failed"));
      }, 0);
    }, r.onabort = function() {
      setTimeout(function() {
        n(new ft("Aborted", "AbortError"));
      }, 0);
    };
    function d(i) {
      try {
        return i === "" && X.location.href ? X.location.href : i;
      } catch {
        return i;
      }
    }
    if (r.open(c.method, d(c.url), !0), c.credentials === "include" ? r.withCredentials = !0 : c.credentials === "omit" && (r.withCredentials = !1), "responseType" in r && (te.blob ? r.responseType = "blob" : te.arrayBuffer && (r.responseType = "arraybuffer")), a && typeof a.headers == "object" && !(a.headers instanceof q || X.Headers && a.headers instanceof X.Headers)) {
      var o = [];
      Object.getOwnPropertyNames(a.headers).forEach(function(i) {
        o.push(Jt(i)), r.setRequestHeader(i, Kc(a.headers[i]));
      }), c.headers.forEach(function(i, s) {
        o.indexOf(s) === -1 && r.setRequestHeader(s, i);
      });
    } else
      c.headers.forEach(function(i, s) {
        r.setRequestHeader(s, i);
      });
    c.signal && (c.signal.addEventListener("abort", f), r.onreadystatechange = function() {
      r.readyState === 4 && c.signal.removeEventListener("abort", f);
    }), r.send(typeof c._bodyInit > "u" ? null : c._bodyInit);
  });
}
li.polyfill = !0;
X.fetch || (X.fetch = li, X.Headers = q, X.Request = gt, X.Response = Ne);
var p6 = self.fetch.bind(self);
const _6 = /* @__PURE__ */ si(p6);
var ui = { exports: {} };
(function(e) {
  (function(a, t, n) {
    e.exports ? e.exports = n() : t[a] = n();
  })("urljoin", bt, function() {
    function a(t) {
      var n = [];
      if (t.length === 0)
        return "";
      if (typeof t[0] != "string")
        throw new TypeError("Url must be a string. Received " + t[0]);
      if (t[0].match(/^[^/:]+:\/*$/) && t.length > 1) {
        var c = t.shift();
        t[0] = c + t[0];
      }
      t[0].match(/^file:\/\/\//) ? t[0] = t[0].replace(/^([^/:]+):\/*/, "$1:///") : t[0] = t[0].replace(/^([^/:]+):\/*/, "$1://");
      for (var r = 0; r < t.length; r++) {
        var f = t[r];
        if (typeof f != "string")
          throw new TypeError("Url must be a string. Received " + f);
        f !== "" && (r > 0 && (f = f.replace(/^[\/]+/, "")), r < t.length - 1 ? f = f.replace(/[\/]+$/, "") : f = f.replace(/[\/]+$/, "/"), n.push(f));
      }
      var d = n.join("/");
      d = d.replace(/\/(\?|&|#[^!])/g, "$1");
      var o = d.split("?");
      return d = o.shift() + (o.length > 0 ? "?" : "") + o.join("&"), d;
    }
    return function() {
      var t;
      return typeof arguments[0] == "object" ? t = arguments[0] : t = [].slice.call(arguments), a(t);
    };
  });
})(ui);
var g6 = ui.exports;
const hi = /* @__PURE__ */ si(g6);
var y6 = Object.defineProperty, Q = (e, a) => {
  for (var t in a)
    y6(e, t, { get: a[t], enumerable: !0 });
}, pi = {};
Q(pi, {
  ALPHA: () => S6,
  API_VERSION: () => ki,
  BETA: () => k6,
  BaseUrl: () => Ti,
  CONSTANT_POINTS: () => C6,
  EC_ORDER: () => A6,
  FIELD_GEN: () => v6,
  FIELD_PRIME: () => E6,
  FIELD_SIZE: () => x6,
  IS_BROWSER: () => mn,
  MASK_250: () => Ai,
  MASK_251: () => Si,
  MAX_ECDSA_VAL: () => T6,
  NetworkName: () => Ci,
  StarknetChainId: () => Ii,
  TransactionHashPrefix: () => Ni,
  UDC: () => dt,
  ZERO: () => re
});
var _i = {};
Q(_i, {
  IS_BROWSER: () => mn,
  addHexPrefix: () => ee,
  arrayBufferToString: () => Wc,
  atobUniversal: () => yi,
  btoaUniversal: () => wi,
  buf2hex: () => mi,
  calcByteLength: () => vi,
  padLeft: () => Ei,
  removeHexPrefix: () => Ue,
  sanitizeBytes: () => xi,
  sanitizeHex: () => m6,
  stringToArrayBuffer: () => gi,
  utf8ToArray: () => En
});
var mn = typeof window < "u", Yc = "0";
function Wc(e) {
  return new Uint8Array(e).reduce((a, t) => a + String.fromCharCode(t), "");
}
function gi(e) {
  return Uint8Array.from(e, (a) => a.charCodeAt(0));
}
function yi(e) {
  return mn ? gi(atob(e)) : Buffer.from(e, "base64");
}
function wi(e) {
  return mn ? btoa(Wc(e)) : Buffer.from(e).toString("base64");
}
function mi(e) {
  return [...e].map((a) => a.toString(16).padStart(2, "0")).join("");
}
function Ue(e) {
  return e.replace(/^0x/i, "");
}
function ee(e) {
  return `0x${Ue(e)}`;
}
function w6(e, a, t, n = Yc) {
  const c = a - e.length;
  let r = e;
  if (c > 0) {
    const f = n.repeat(c);
    r = t ? f + e : e + f;
  }
  return r;
}
function Ei(e, a, t = Yc) {
  return w6(e, a, !0, t);
}
function vi(e, a = 8) {
  const t = e % a;
  return t ? (e - t) / a * a + a : e;
}
function xi(e, a = 8, t = Yc) {
  return Ei(e, vi(e.length, a), t);
}
function m6(e) {
  return e = Ue(e), e = xi(e, 2), e && (e = ee(e)), e;
}
function En(e) {
  return new TextEncoder().encode(e);
}
var re = 0n, Ai = 2n ** 250n - 1n, Si = 2n ** 251n, ki = re, Ti = /* @__PURE__ */ ((e) => (e.SN_MAIN = "https://alpha-mainnet.starknet.io", e.SN_GOERLI = "https://alpha4.starknet.io", e.SN_GOERLI2 = "https://alpha4-2.starknet.io", e))(Ti || {}), Ci = /* @__PURE__ */ ((e) => (e.SN_MAIN = "SN_MAIN", e.SN_GOERLI = "SN_GOERLI", e.SN_GOERLI2 = "SN_GOERLI2", e))(Ci || {}), Ii = /* @__PURE__ */ ((e) => (e.SN_MAIN = "0x534e5f4d41494e", e.SN_GOERLI = "0x534e5f474f45524c49", e.SN_GOERLI2 = "0x534e5f474f45524c4932", e))(Ii || {}), Ni = /* @__PURE__ */ ((e) => (e.DECLARE = "0x6465636c617265", e.DEPLOY = "0x6465706c6f79", e.DEPLOY_ACCOUNT = "0x6465706c6f795f6163636f756e74", e.INVOKE = "0x696e766f6b65", e.L1_HANDLER = "0x6c315f68616e646c6572", e))(Ni || {}), dt = {
  ADDRESS: "0x041a78e741e5af2fec34b695679bc6891742439f7afb8484ecd7766661ad02bf",
  ENTRYPOINT: "deployContract"
}, E6 = "800000000000011000000000000000000000000000000000000000000000001", v6 = "3", x6 = 251, A6 = "800000000000010FFFFFFFFFFFFFFFFB781126DCAE7B2321E66A241ADC64D2F", S6 = "1", k6 = "6F21413EFBE40DE150E596D72F7A8C5609AD26C15C915C1F4CDFCB99CEE9E89", T6 = "800000000000000000000000000000000000000000000000000000000000000", C6 = [
  [
    "49ee3eba8c1600700ee1b87eb599f16716b0b1022947733551fde4050ca6804",
    "3ca0cfe4b3bc6ddf346d49d06ea0ed34e621062c0e056c1d0405d266e10268a"
  ],
  [
    "1ef15c18599971b7beced415a40f0c7deacfd9b0d1819e03d723d8bc943cfca",
    "5668060aa49730b7be4801df46ec62de53ecd11abe43a32873000c36e8dc1f"
  ],
  [
    "234287dcbaffe7f969c748655fca9e58fa8120b6d56eb0c1080d17957ebe47b",
    "3b056f100f96fb21e889527d41f4e39940135dd7a6c94cc6ed0268ee89e5615"
  ],
  [
    "3909690e1123c80678a7ba0fde0e8447f6f02b3f6b960034d1e93524f8b476",
    "7122e9063d239d89d4e336753845b76f2b33ca0d7f0c1acd4b9fe974994cc19"
  ],
  [
    "40fd002e38ea01a01b2702eb7c643e9decc2894cbf31765922e281939ab542c",
    "109f720a79e2a41471f054ca885efd90c8cfbbec37991d1b6343991e0a3e740"
  ],
  [
    "2f52066635c139fc2f64eb0bd5e3fd7a705f576854ec4f00aa60361fddb981b",
    "6d78a24d8a5f97fc600318ce16b3c840315979c3273078ec1a285f217ee6a26"
  ],
  [
    "6a0767a1fd60d5b9027a35af1b68e57a1c366ebcde2006cdd07af27043ef674",
    "606b72c0ca0498b8c1817ed7922d550894c324f5efdfc85a19a1ae382411ca2"
  ],
  [
    "7fa463ee2a2d6a585d5c3358918270f6c28c66df1f86803374d1edf3819cc62",
    "a996edf01598832e644e1cae9a37288865ad80e2787f9bf958aceccc99afae"
  ],
  [
    "3d4da70d1540da597dbae1651d28487604a4e66a4a1823b97e8e9639393dbec",
    "45cdef70c35d3b6f0a2273a9886ccb6306d813e8204bdfd30b4efee63c8a3f9"
  ],
  [
    "1e448fdbcd9896c6fbf5f36cb7e7fcb77a751ff2d942593cae023363cc7750e",
    "30c81da0f3a8cb64468eaa491c7ae7b4842b62cb4148820da211afc4caffb3a"
  ],
  [
    "6531acf1a7cb90a4eb27de0b7f915e387a3b0fd063ba6e1289b91f48411be26",
    "31330f5daa091889981a3ea782ae997f5f171336ed0487a03f051551a2cafa2"
  ],
  [
    "54be016394d5662d67d7e82f5e889ed2f97ccf95d911f57dd2362c4040ed4f4",
    "c6cb184053f054d6a59c1bf0986d17090d25089b3fdcdaf185edc87ef113e5"
  ],
  [
    "35b9ecd0499ca1d5d42dcbb0c6b4042b3733c64b607ca711e706e786ef2afc6",
    "5624b476a5b21c3a544f0712d4817b06ad380a5a6529d323bf64da8ef862d8d"
  ],
  [
    "4ce0378e3ee8f77ed58f2ddbd8bb7676c8a38bfb1d3694c275254bd8ca38e23",
    "5a16fcbff0769c9cf2b02c31621878ec819fff4b8231bff82c6183db2746820"
  ],
  [
    "648d5c6f98680a1b926bfeb01c00224c56fdcf751b251c4449c8a94f425cfcf",
    "72c05ac793cd1620a833fbe2214d36900ebe446e095c62fcb740937f98cca8c"
  ],
  [
    "bd09be3e4e1af8a14189977e334f097c18e4a8bf42577ef5aafa0f807bd89b",
    "6e0e72ed7eb65c86cee29c411fb4761122558ee81013344ba8509c49de9f9b6"
  ],
  [
    "35ea4e339b44ae7724419bdfbe07022253137a4afb7cbaffad341ea61249357",
    "3665d676a026a174f367bb4417780e53a7803cb02d0db32eb4545c267c42f14"
  ],
  [
    "36457bc744f42e697b825c2d1afd8f4029d696a4514710f81da52d88e178643",
    "7c93715896735492a68c7969a024b3a8fd538bffc1521538107de1a5f13ce9c"
  ],
  [
    "5b3a08ebcf9c109cc9082f70d9df2b9c11b5428ee23917b4e790c4c10f6e661",
    "9d7b42ab0c20f5510df7ea5e196eec99342739077e9a168198c89da859753"
  ],
  [
    "21883ef8580fc06e59481955d52ece3aca6e82c8c9fc58e216dcf46f96990c6",
    "51a6423543e6e8a43e71da34cd90f5b520b8d33b67c4bf857573ab9e301aa4c"
  ],
  [
    "19e86b77f9b581e81092b305c852faf53940a8f15f0a6990c414f04c0fa7ef9",
    "515630e35d4398c9c79fc4ee08e1023fa47d8e03c6e7819c6d2ccef45398fa"
  ],
  [
    "888ab8eb4c31bb2ac5b54aa320dbe1a69c96b864e8a5f54d89c1d1a6b86c24",
    "730e148467f6a55ce22c5296f5380df88f38de76ef0b2de844cd3094aaaf3ea"
  ],
  [
    "75e79ff13a894e7120dac17b7429c0c32ce7828f726c9973728c0977a5f5977",
    "4960526e59c1c736561a201bc56f7d762641b39f609d273cc996f5d9197cfb8"
  ],
  [
    "640fe009249115d7254f72ecafb3006139e4bed7e9041af51458c737282d1d5",
    "3cc6c978a575246e2ce4f7ef1fcc7f63085db9ff98a1b1f3fe374087c0332c"
  ],
  [
    "6d6fd09ccab7c26de9b3906191235deb5c34685580c488275356a05e209ca96",
    "7157f81a34213dd8f91dea4f6df1bcfabc4ee091a3049eeeb3b7923d39b8645"
  ],
  [
    "5531ca1d00f151d71da820918f74caf2985b24dca20e124721fff507b5a5876",
    "518529643d3f25e47f72c322223ba60a63d6bfe78cf3f612215d9c19bf29200"
  ],
  [
    "6192d454e4f8fe212bdfccd5b15dd5056d7622ffe456c6c67e5a7265aea49c4",
    "2377a45dc630017ae863cb968ddb38333a70c7946d8684e6d7a6213f634b7bc"
  ],
  [
    "542fb44b4ef3640a64fdb22a2560fb26668065c069cf31d1df424819a39ff18",
    "5dbae9b0948e0361aea443503840341c322aa1a1366ce5390e71bf161f78f8c"
  ],
  [
    "299ff3e3412a7eb4cb4a3051b07b1be2e7b1c4b789f39ffb52cba3d048b71de",
    "1951d3175c02761b291d86b6c0a08387ad5e2a2130ccc33c852530572cb3958"
  ],
  [
    "628ce3f5367dadc1411133e55eb25e2e3c2880d6e28754a5cb1c5d109627e73",
    "ae3e9b7d50964e28bd15380400b7659b87affdef5d2586cbefcd9be7d67c0d"
  ],
  [
    "6ea54aff064895eccf9db2283225d62044ae67621192b3346338948382f5933",
    "6431507e51aadacfaf39f102a8ff387756e9b5e1bc8323d44acae55130d93db"
  ],
  [
    "28097d50d175a6235320fe8cfe138dd9e46895d189582e472c38ad7a67d923a",
    "7f9eab4133d7d09a7ff63368d6135c26262b62336eca1b5ca33f2096ce388ba"
  ],
  [
    "619fd09cdd6ff4323973f256c2cbdcb224f7f25b8aef623af2d4a0105e62e02",
    "2c95f0ae11d47eeae1bc7f1350f75f9185c5bc840382ceb38a797cae9c40308"
  ],
  [
    "641c18982ced304512a3f2395942a38add0d6a7156229c2a7c8b8dfbe9beb96",
    "6f6288c9c659b6af5ac975f4180deffe53d516399b2cc62f31732e9d4ba9837"
  ],
  [
    "58ab546e51fe49fc5a382e4064a2bd6cfc268904412f86c26de14f28a71d0f2",
    "124b7217943e7e328408e8afdfa7da00dcbc94a2bb85fd8e01fb162d2c2c0a9"
  ],
  [
    "a82c2fdedbb26c3c762a12f7e86b0e01e65320e0a25a8399d665f6e266bf74",
    "1a1de28e253f3e10f44d0111e8074f882d7f42e5900780ccbdc31da372d3fd8"
  ],
  [
    "744c725a7455a992e3cf5bd007bc234dd4668dba285f553f38350ad94c1615b",
    "7f721a87f48798bdc4a9c0eb88559e2ad7a74112fd901e70ea159e67a9c33f"
  ],
  [
    "434df142ddaa60f7881b6348d91687de40457de7ccfb07f0304b9e820705d0c",
    "7fae425e3b53f97dd1f5b20e49ed9fe24ff1efc341ba5e017ac89cf8df0cc39"
  ],
  [
    "7a1e2b809dff46277021cbc376f79c37e1b683bbd6bca5317014f0dc0e1ae73",
    "56790278a231912c334eff05281e08af1558e85516b4411ef64647c13bea431"
  ],
  [
    "4931b7990348d41cf8907be79f45bb7991fd18f8a57868351c92fa7a34cbcd7",
    "ca35091815cdf0837d396e25aad6052ad32d497a33b123256cffdc008bc50e"
  ],
  [
    "250b815d352fd89f8210b624b147ea7d0a4f47bcac49f3ac9b777840da93ebe",
    "1173f10e9691948b7da7632f328520455aadcba46e017f891e0a1d7da2bef04"
  ],
  [
    "2223b85032fa67292f6e1f822628e6756e5c3cc08fc252ab88d63d624e4dfb2",
    "55619ba96a7dcec77832fcb22cd5c21c7dcebc0280d730cba0002b67e0a8c63"
  ],
  [
    "249b131e04de73af9820d3e22492d9ec51bdc0c4c4f34d95352fa44dd61f245",
    "7576d3b5d136368ff01170a77d8286d0d1c7c40688862fb40813b4af3c6065e"
  ],
  [
    "6777915d9b4769027eb7e04733f8a2d669c84fe06080f55e8a55674dfbf9efb",
    "640d0ff384c9635e1af364760f104e058e3c86209fa9d2320aeac887b2e02d8"
  ],
  [
    "2abe3f237681052f002414399111cf07f8421535af41251edc427a36b5b19c9",
    "636ce4deaf468a503ab20ccb2f7e5bdc98551656ebf53e9c7786b11dd9090be"
  ],
  [
    "4d5cc5414758ea1be55be779bd7da296c7e11f1564d9e8797ceea347c16f8ea",
    "1a680c4c410cf5ddc74e95ff2897c193edaaecce5b2cde4e96bbae5c0054eff"
  ],
  [
    "46c375c684b30adf4d51de81e92afee52b1a3847e177403372c82109373edca",
    "1eaadc5783c90a0261306423d52009e991126b3f620e9cb6cffca41ca096f4f"
  ],
  [
    "2ddfb71f51205888118cbabba8fd07d460a810289bfdeeb7118707e310cb152",
    "1fd905d07b3933be886f2518246bdafa6f33259a174668808223cd7c28183c7"
  ],
  [
    "386f3879960713d41fdb3b1e41bbebf26b1c0e27a9a75bb1adcc1a0d3e8547b",
    "2b21498c0f34ec6f17c720334dc0f36021c2f87afbbbc8847d0bd536eb265e5"
  ],
  [
    "407eae62c6c4de3b942195afec3f45efec71ddb5e6edee3d427631bcdbf9b90",
    "436e7f2d78268ef62c4172d2ff1469028bad1f1d0f97ab007064418e61caa8f"
  ],
  [
    "1b881175e21201d17e095e9b3966b354f47de8c1acee5177f5909e0fd72328f",
    "69954b1a9b8bfccf8ec384d32924518a935758f3d3662ef754bcc88f1f6f3ec"
  ],
  [
    "7d545a82bff003b8115be32a0c437f7c0a98f776bcf7fddb0392822844f3c5e",
    "34b6e53a9565a7daa010711f5bf72254a4e61da3e6a562210a9abc9e8b66d69"
  ],
  [
    "299b9fcd4fadfc4b6141457a3036aaa68501c23df579de26df69d4def89b913",
    "b95bf2c2bb303c38bb396382edc798ca6a4847e573ce19b7b08533d1912675"
  ],
  [
    "551f5a4dae4a341a3e20336a7d2f365ddd45849351ec6dd4fcbedfe4806d5d5",
    "5865c977a0ecf13ce85ae14c5c316872080bd36f0f614f56b6dfc7ece83792e"
  ],
  [
    "7a1d69c08e68c80ad8b310736e6247a53bcba0183b9b8798833bc696a0fb6e2",
    "3ce803a20ebb3b120d5eaf0ad64bed0522fad1a0f2ce39a5c5cbae98c4438f6"
  ],
  [
    "28acacc0bc41d84e83663f02b36981a2c8272ecd72d3901164be2affb09c504",
    "7a5aee0b160eaff5b5968ab1a0304ce58c3d5ae0148d9191c39e87668229e5b"
  ],
  [
    "1f78cfdbcc767b68e69a224a077468cdfcb0afd6952b85bccbdb96d1fb8500b",
    "4772ba173c6b583284eb001cfc2a124104833f464ff9df096443e10ef3e9dd4"
  ],
  [
    "2774108962ca9897e7f22c064d2ccedac4fef5fc9569331c27cdc336c95774b",
    "9e13d79b68e8dc8091c019618f5b07283a710ddf1733dc674a99fc32c12911"
  ],
  [
    "770d116415cd2c4ace0d8b721dd77e4a2ef766591f9ec9fa0b61304548994ed",
    "42165d93c82f687635aa2b68492b3adffd516beb4baa94520efa11467a209fd"
  ],
  [
    "5e6e4ece6621e2275415e1fda1e7c4f496de498b77c0b913073c6a6099394b9",
    "3d92ce044fc77fa227adc31f6fc17ef8b4ec1c5aafc44630c0d9195075bf56d"
  ],
  [
    "6e69c717b5d98807ff1e404a5187a9ceaf0110b83aa15a84f930928b1171825",
    "1ee7cfc3a9744d7fa380ba28604af9df33ac077724374c04588bd71fa16b177"
  ],
  [
    "404318f2d2ceb44f549c80f9d7de9879d8f7da4b81e7350c00e974ebf2daef1",
    "3934831b5af70d17a3f1da9d2931bd757e6acf2893236264fc7e0d92ff1a1cb"
  ],
  [
    "20dcb6f394fea6d549b2e75748f61b7ec03b6e52319cb14163373a9c22bb9dc",
    "106a8c96cfb95a331618b7416d1498554730499e194a58fbf63019890480fc7"
  ],
  [
    "119000f277ccee013e6bb121194ec1ab5460fb6a96eb702a14079865f4170aa",
    "1737a32f5415e8720a5606ec1dd4756f02e7c6817e3723b453d091f2d192773"
  ],
  [
    "45d0fb5cd95db76d05dec3faa12e467a308eabaad363a062353db3cd2d9b749",
    "ae08691b5b0cdd19ec499132421638f470f493320e4003d123ab1da761b965"
  ],
  [
    "1257b3e65cdfb6367c6d0942327e799bc66eb221e70c6573a9862889eb51c38",
    "593309fd45755dd2cc4afd2b9316bc4638b0c5ddb3009694fcb7b250d0c8a2f"
  ],
  [
    "186dcf9950f72e868014a8accf14aa36e82a7a2a29f86ba37f6632da4189db3",
    "55684c9f7a043fc523ed78f756f834b4db823d5e4161bd79602c17d55a5cd8c"
  ],
  [
    "58791d5569f282f5c3b01ecdc9388df7ba3ca223a2dc1eed5edaf2a1d302fb9",
    "6298d7dd51561a045bb4089deda9f40b2865589ed433e56d54554f8b45e79f0"
  ],
  [
    "13fd87144aa5aa4b24d5a7bf907d8280d15937fed262d41084898cb688fc28b",
    "3fa54367770cc4479a857411ddcabe86627b405ce1cd14ad3b2863bde13abe4"
  ],
  [
    "48118139445415f0c1879224e2dee744ed35280ff00537260402a1741ec3676",
    "4dfa39dadaabecfc54ecb7a25319444f8e952782d863790e42a9887064fc0c1"
  ],
  [
    "4ad031bb9eda84f2fe5d354c7948d41558ca657a04508654721810ee72ef158",
    "620ebd5d0086b92c6009a42777b946a351c2c7ba852b57d3c9905fc337459ef"
  ],
  [
    "4a34abb016ad8cb4575ea5bd28385d2348e5bcc0cbba90059f90f9c71f86e8b",
    "4f781829ad83f9ed1e1b6de0e5f4ac60dfdfe7f23cb4411e815817e705e52c8"
  ],
  [
    "7fc632d7512aab5356b7915dca854c8b12b369ab54f524fbce352f00eb9b9f9",
    "2ce80b944fc9158005f630b34385d50c3ad84450a9e1e529925b3211dd2a1de"
  ],
  [
    "65ed10347503cbc0216ca03f7536cca16b6abd18d332a9258685907f2e5c23f",
    "3be1a18c6bfa6f2f4898ebefad5a8e844c74626d5baa04a820d407fe28bbca6"
  ],
  [
    "1a8abba1be2e276cdd1f28c912280833a5ede1ec121738fcca47dc070dcc71d",
    "21b724378bc029a5199799df005922590d4e59cae52976f8e437bf6693eec4a"
  ],
  [
    "3a99c22dafcfe9004ebb674805736a26aeed7ed5d465ae37226dcbe270a972b",
    "5bf67552af08e1e6e2a24bf562c23225e89869cab9bef8becb3669175a3c94f"
  ],
  [
    "4a6a5e4b3501f2b7bbdd8da73ea81ffca347170bdfb6776a037cdd74c560fb4",
    "5af167ebb259c2da88740ec559ee04052bb66480b836cadd0e2590c32d7111b"
  ],
  [
    "6890d95308525f0bac9dc25cc1189eb92d29d4b3fe61bc8aee1c716ac17b1e8",
    "e6f23f78e882026b53ea4fac6950e56e3da461e52339eb43d2fdb2dade7ca9"
  ],
  [
    "748f4cf4f027efdeaed7c7f91ef3730ff2f2bb0bfc2db8f27aadde947f7d4d5",
    "3a1cbc550699411052c76293b8c41a3a8a1ecf12cbbc029a1b2b6ea986fca93"
  ],
  [
    "7321f3f581690922cd0dec40c9c352aae412ec2ccdf718f137f7786ab452cd3",
    "5be5130c9277cdb76d7409452438ec15d246b211dd1e276ee58e82a81c98fd4"
  ],
  [
    "6c4d6cb7e7ae70955224b8a912ff57ca218635a2436b36cee25dce8a5cdf51f",
    "32f8c03c6db3246946e432e4148e69f5628b200c6d7d72449df6eeac0998039"
  ],
  [
    "1dad5f2e795ea6fa5177f110989516eacf8fb37bd6a091c7c93f1d73a2fe309",
    "56b2298c538180e99dea3e171dbb5c6fba0bd0a9ed40537277c0c2373a8e2c4"
  ],
  [
    "1610605baacc9bc62c4cc923dc943347cfece7ae241e746fbe6c2c878221dbd",
    "431a82d657e0d109d00dea88cf3fa9b999845221b7b5590a20c40fc71368c1c"
  ],
  [
    "6a4f5c787fb09a5be2b04d2eafa1e6f3d3c863ee22960eb0b64f6eaf6659162",
    "14dbc3eaea6146ee7eaace5a91ed9430dad3a47e9ca2f68b455171f8fe6a7b3"
  ],
  [
    "738415b73e55412b0e582e45ff0d7bf4b1bf2922db581783fdcc75559f40e",
    "33825aeb3fd8459999eb418d15102ba5864b069c6ea517f0c6e9eab8d9aca47"
  ],
  [
    "2603e72ce53985c70782774057a17944f7b4ce224a809be4e2b5af3606aa1d8",
    "92822921809c42318f42dac4d773325f41c43069e990adac7818a45e2554dc"
  ],
  [
    "181cd967ab4615357cc96c82eae9152ce7598c1a1dfdd91a458bddb016ae9fe",
    "5d562fdaeb0e12647e230e50eaf216bed52fa73c6b7378821a3bfc4cd66d4ff"
  ],
  [
    "1121726069b9ef5954ba6490100b226e0be53fef3e071b7c58a1286174b789a",
    "4b25594cf4e9eb2d14b3f52f2661a9992234fc222c0a0d44517cb77deb9c16f"
  ],
  [
    "e543663969b915337f105f80995a77b356f1a51d8b4a4fb12d44364130e873",
    "34b2e3c009fdab4cb7349a580df2e64c0098a123280078e5da6623a9ec6b44f"
  ],
  [
    "4e2f8909bb62de5ef65600e61bbf969293815296b6e23702875e049b3ce5c45",
    "3cb81f2c21f22a7add26fa38a9ce5d9cce1bb251bd2698f90c34ff0a84f7af"
  ],
  [
    "37b546e403a1ba970c17b67c2f1361ab9c803f8d2b5cd93803014faa08861ed",
    "37079184ea46272f5809b523d060686633f7995167897a153be1772fd6566f6"
  ],
  [
    "27bddca77f7bd7f66b3693567a4238f2e6751d95b0bcb409f6b24d08f84798c",
    "6417a85cbfd6fc02df560d3963a241a986baacdfa423f65d7227ce49a96c57d"
  ],
  [
    "2de71a39aa043057d1bc66e45f804542acddf18f7a6d88c0d7fb0ca240debdf",
    "306c1ce39ab46300f7cca0f3a2fbfa77296a27e24bc66b0b8044968ec0ee413"
  ],
  [
    "307c877154364c0c03534e7327d5a88e1380ceef6481567ade37a14ee7c1a72",
    "3404bc7dbfb33b95d922d0693aaf9358f77888d7d95e773c38d83dbe2e5f995"
  ],
  [
    "79f09ff7c60850e5f5ea020722659a1ed27db4c95dca131f99552f785c8afbc",
    "40429528c099349b426ddbf129497176951a64a53db5f9d8bd2be0252cb22b2"
  ],
  [
    "4027dc6b56d446e5972f35464eeac85c5254ef377c902d9fe37aea841bb5292",
    "7c3ea37689ef679fa2f5c7e031a78e23d484a8317990fd34d44d95cc1db3717"
  ],
  [
    "645dbf78a3c228c4b7151450b5e65edb58e71f37e1e4bc5f471e0f1abd6d9c2",
    "15cfe7850f327b256e23b00627451560c5c6ab60db78d45b7ab286afb6f13ab"
  ],
  [
    "1503ca373757677ad1d911a2b599d01c46eb879d1ce21ae171c7e439846a85f",
    "583eb269b7030da6a0c324026919de3f9489d2ff6ae0e6320c36f05469ad66c"
  ],
  [
    "66e1819ba3ec4ad4ae9f7d7588d23baa004e29d3aad2393d52af204a81626ca",
    "505249980cbe6273b82ad5038fe04a981896f4117345ac1abcc67e2525c0ee4"
  ],
  [
    "5ec20dbb290254545f9292c0a8e4fbbfb80ad9aab0a0e0e9e9923f784d70ed1",
    "bdb1ca3a859227cf5d00eaae1f22584e826ed83b7ccdb65483ed5213dc4323"
  ],
  [
    "a5c1a5011f4b81c5c01ef0b07c0fbf0a166de77280f0ae241f2db6cba15194",
    "4444521fb9b33d7dfeb1247d0ee1a2b854ad166cb663d9dd2e686909362a689"
  ],
  [
    "1f35335de40e00c62642dac2fda8b30f071986ce4f11db849df11bc45ad4e0c",
    "7801a2c761b90fd4477ba0be9a775003d5dfcd959b1ed198b4681f15e7acbf"
  ],
  [
    "48db4798cf6821c1ffb8178b1d3bb6020e04186c96aaf4670972d367f4ed5f",
    "781019494df95b888f1578f1b4a3f8e125ea60eca47ef9207a10630671217a3"
  ],
  [
    "17f653d904210148a8e74d8e719a3061683c164aa6d79c902a19f185ab437bd",
    "6780e97985932c3860d810af1e065d454b1cb4be0e7ffe2d8cea7d52526e223"
  ],
  [
    "5c4d0c7432f9b0070436240f9855adae1467cdc9826952ae01b68cd52a3ad89",
    "1c5747f968ed91261b7ae9bf1023c999da9816e37de602d6a1a50d397752bff"
  ],
  [
    "6fedd7639fdaa2f7bad4ca0b391710f6f8a7e890250ae8ae4252bb8b39a1e58",
    "436a215f655a3fd3778b2335ffdc9aca6b98474e43d764c1f8362830b084f0e"
  ],
  [
    "7fbd45a889c5e9d127bb4f8474d6be7cb9796bbfff923b75e42a1ad4cae37d6",
    "484bd12622a6ba81cd53049c550d9ed682a8e765b656b1cbff9bbea637bd1f4"
  ],
  [
    "17d984d47937263f7966a3e7b1eea04071e678494bd749c9e02b48b3234f06d",
    "7b341ff08722c4e161005d0037204a7a2001fdda7af2cc1a0b04a027f115a0f"
  ],
  [
    "7f1822045db45ea07e1519c3ee1f7705915f35fe4dd8db1e8921b5d1c740edf",
    "33d41e06b93320ad1b3d9580380ec797a05dac3f1cc8008899110ebefde2f78"
  ],
  [
    "7b19453ecb74b7d0e2a66b9890ff73bfbbcd61a266abd6d82dbe665bf32f34d",
    "6dba2355420dac582b1f349609ea1c89b89bba2d1a68a0642f1dd12d86e73cb"
  ],
  [
    "273e82a15f395ddf2489a95685bec8bac62c4b459d1b28987d3cb27e4bc9128",
    "653375b48a4cf5d5b101c9ef533039bedce5dbeef3f59e8f168bdc99b06ca5f"
  ],
  [
    "3006c9e7fc6a553d8eb4e8a47ce9f10d1a39576ac255ae9e0a4ce3869e76212",
    "65fe9e2ef2aae608be309332d464f57e28f1df5de1a6a519751b056971f932e"
  ],
  [
    "5e8f384c8a4607fbe9789fcc52d54249d304d698562597d114c1d81452d3dee",
    "3c8bc78066b5d947dc1e405e326ee55ea606c7988f666748d259850fa259a22"
  ],
  [
    "7841b2102e9aa103fb53a642b3e167b21113ea44751ab38e0b5ef8312654db9",
    "71bf5c8308fcf9c4a7847494cd9bdd946fddf7d3a37e8bb0b201ff2343deb8e"
  ],
  [
    "40f68027420c11e3ade9aae041978dc18081c4f94943463aac92d887f922a62",
    "499c6062594a6c7e21a3cb91ea451813393bff365a27a08f1a515439b83cf42"
  ],
  [
    "6ce77a50d038b222634e87948df0590b79d66087b01e42b9b6d8fa30ebb1465",
    "35f5c46bb1be8555a93f155a174d54ec048c2ac8676e7c743054ddc52709d37"
  ],
  [
    "604f8b9f2dacb13d569262864063c2d4bb2b2cd716db6eeb2b1eeabc57746f6",
    "68c6799e24f3b44eec3049973445174727a66970f1614a782efa2b91ab1e457"
  ],
  [
    "73d620f3bfe77f672943d448d7dc05327adf64b8e7af50039c469d7f7c994c4",
    "4859deb36eaf0c802f0d1514602368143a33ec6ce8fd55248b59025debc6afb"
  ],
  [
    "3fd2bcd1c89d706a3647fbd354097f09c76636e93ae504973f944d8fc3bcc1",
    "677ef842cf5eb2444941f527abec567725e469469192354ad509a26ebb3d0e0"
  ],
  [
    "39222ea924ac17b533c72ffb2c47ffdc11d6a7f7c70fbde3a10fb0b8f35eb2f",
    "20dc4bd1089019bc1d7379b4feb3eae6eb5af59e9f253845da9fd633057e952"
  ],
  [
    "326f58994e1347f62e4102183215b5db956378d2f61f14aba4dec94577f53c",
    "7a03284c296003bbe05178a1d82efdb7b8125511d63e20e50aed789c2e52e1"
  ],
  [
    "53aa8939c74d4ee58f03bc88bace5a45c7bfcf27466201da05dc6723a5f5632",
    "2e32535ca7732904a048183247b04b426ecf9b39fc393a9cebe92fb1dc7a7f1"
  ],
  [
    "6cee1a03145e93b3e826e6067005f09c06099c98198c91c222407ba5c8c132e",
    "beaecad1274e7c6e5476a100c271aa1a6f86ee5a9fa5c2f26124d5886fa63"
  ],
  [
    "3ec659b8175e1be1bd5a252108714776b813e330393f587814f5f1f32a73332",
    "529a5cf9f8c237ae69a94217d173c8d19c156952041f5c980da557990863fa7"
  ],
  [
    "3d66ec5963d0c534d4139c8cef2e1ac48b3e7965fafabf58be26f903318af4e",
    "3d3f2de7a95f59b683725ee6283cbaf31f97c4b600df9a4621413223a468740"
  ],
  [
    "7fb38ace8e0932fac2ea0d3eb676db8d684db1817e2e4d59da7996ce398b4a",
    "68f92bd5768cdd4710249f9d49ef1d5654e497b9a4ba10bd2971366d83fb400"
  ],
  [
    "1c4a49314d6b4969cdd142c76ceb7682bfb868ace7f7568b0fc8635bda5a9fb",
    "5fc0519f1f4cc10b5771312458748c036313b87707ed0540026ac64a5955aa9"
  ],
  [
    "3073c95d08d3b97caea5f0be16b2789bee766f76b7e5499f8ce8f96abb0f344",
    "52a8974b4eb9a1f6a0ae2c83cb4715bf18d73f057255fcb3f63b74f7e78f590"
  ],
  [
    "44485b16d597a5de3604df6f7ed7e00b8aeef9e7e8dea8688255153b8bb16aa",
    "6cccb0ba170123266f24b5d93a744397dc2c44820edc4f8f5b9a0f5c9b3b940"
  ],
  [
    "7618f77b7b32d512688dd62e0b48231d9574c6361e8be353a7dc04f7c3a115e",
    "78ffcd16d80636381ca231aae70d99c9e20298b4f5388fd823ea9fa2b8ddfd9"
  ],
  [
    "7dc82fee1ef95cf5b3720fcc07f63246654bfe39762627839da40e51c75654d",
    "4c0ccdd70955da74558de20c88352df8a02aa97e4d5971c500e884740a8cb62"
  ],
  [
    "7fa5d460dc10cbb418b444d9bde97e92c70a99a222b99f244dccee7e62cc04c",
    "636163901baa5b7576c38c43407af578b8c4607e01e86011ae2dde587a89f84"
  ],
  [
    "758930d46006623a756c89bd0cc378f6a3c1f43c9a0edbb42274c35e75c16d2",
    "1d74dd9f81c2fec811b8cbd6168a745b0a111932b2a345265ef2853b50b6245"
  ],
  [
    "7332ee0626b044d664ef228f8cb84df7c643e52f6a2591ae1c9007ad61ec16e",
    "229bd8e630572cbdee54283234cf3e9f060e6382f99943bf234119d47b54470"
  ],
  [
    "78a16ef803aa20a075bb2f66c61bb2dae5698bebb94a0995fa74c3d53de1614",
    "246d588b68edb6fed96c128349908c42dcd64c46341b205e79f4aed9b5d3675"
  ],
  [
    "6e1933939bd03b67bba753cc0cbe7d2f25bad68c993887ef8c9e2fcd59b0647",
    "599413f7c204a11a5ce315eab11299ab7326603412bb00bc1c59ff75a37d6b4"
  ],
  [
    "4a79957a5a1888ad063b51c69565a2b48e8eb917183e220a1c8d3374526d30e",
    "1f092de0e069bba7fc5386e2e9a114c1618f88c4b95e220cd35ffe96f99fcad"
  ],
  [
    "3148aa3df9ece39aca84f59489f2710522216f14be6055ee0027529d1d55e2d",
    "617e9a52a92975db0ba1977f71116f7058a0d31b869ac7f3ee2fd80b0c5100c"
  ],
  [
    "5c1188e72384160ae39d07328346cda4f6c12d227448e6236f04dc971625287",
    "1643006eb3a3bc6aafd5f685cf054f2a572e6ca58c0118bcec0b833741f116d"
  ],
  [
    "3f72efc93c9b71adc4c51d8fc69d3940b20d08733af2b7d05140fdb1d1c1004",
    "7399259987c8f4ebfab46e522380707e58427d3962ee0c2a91760813f76d232"
  ],
  [
    "3129b34c03c51aa8f611e91d5cfcc9bd3ef108ee66e6d3ee35a0e0e50055bb",
    "563b18b5650085efb4cf179a029e6afff27b1d3091cd28eaa68d24fa1f801c6"
  ],
  [
    "16eac0f9fb4c67cf89a7fa4ee615bbe731d8edcb709a1b9b50c7d873a530f52",
    "7ff8288b6e199ca8f316192881424a37fb080c29daa76b1f0edaccaf580a80e"
  ],
  [
    "75f6b6028c43ce832f65d7e8e620d43b16cba215b4b94df5b60fc24e9655ee4",
    "35e9ccfaed2293a8b94b28de03bcb13eb64a26c831e26cc61a39b97969a2ff0"
  ],
  [
    "3c6152fe093bd6316897917ec56a218640ec1b2148f21db9b14fc7a5ff362e8",
    "6eef2df27ae7d63a28856b07b73e7aad7ca94f317201a1e675ffc6f9a1710dd"
  ],
  [
    "54e01b5fe4fd96052aad55b3f26b1d254dfc7e2525fffb9ae0a77eb8cc5579",
    "7c3d39232ab333675b219abc766ed9b4782c840e6b046614dedb8a619696eb0"
  ],
  [
    "d1e63f8ea8a76429cf254a6d3b668761f0dc572d4bfac4fd56d9eaf58fb6c0",
    "2bd0a84d3908a63085824c9329a0983913006ba155b56a58eb3f9becab29c45"
  ],
  [
    "2d6122f2a702edd4da7385b1580796a71d13bd72be94cfb3fec01149c006c2d",
    "70eb282fae992efa6f5915e578b640653549f23385ef3a29ab29b1b9b8ad63b"
  ],
  [
    "752fec14beaadb5ddbba6b3a17fcb86579fa588ef407fad0ea07dbb22a640d3",
    "3feb6728eca21a1e84e8f9f23010387a53a96a1cb62d86fb37996150a1299ef"
  ],
  [
    "63f94a92f27acde8f5ed949b459506f51d70c85bcc61a34d647264ecc53c65e",
    "37e5dce0646ee66f4fdb93b82d54d83a054948fa7d7fa74ab6b36246fc7383e"
  ],
  [
    "d6aa909287a2f05b9528690c741702c4c5f4d486c19a46c38215f52ef79c7b",
    "5ebe1128dd81093df4aca0df365d58adab848d1be1a94b95eeb649afd66a018"
  ],
  [
    "12866812b3053e2f7a9572bdaf5ef2b48c6fb62a0eed9ff0356df50e7d05557",
    "6785f7eb2cd1c120e4c7167b46861d10117040a2e9f2ca86a71e9d67df90613"
  ],
  [
    "46a730d05330b1b13673cb8a1b8f45460035e4a9f1a1751cfba099c4355c1c",
    "76fb0ec6cd16a8141cdcd875c8b2de9fce42d296072643d148ac7e7fa7472df"
  ],
  [
    "4bd4380a22900bd34835e0a908eacf4b6edb61eda0cf483f9212453b37e7516",
    "5e9551cd20d8d7ddbf4366880b7d5267385afa1966ff30da4baaf273b009d29"
  ],
  [
    "71f1994ad40baa2922424ae222663a64f93d8b67929e9a10f9e4c1ab19f3833",
    "85320fe68ec0d37cc19fdfd03589d66906ffa4046c80e1b094a85f27676346"
  ],
  [
    "5a63b1bf5232f28f808765c6be7ce1f81c52145b39f01c879fae0f4303bee61",
    "3bc5d6df68bb6d0577bf9ae2ae59ec0e9b2dc7dd56ea179fb38a41e853db950"
  ],
  [
    "161ded55ff1087032381e6c1449704f63ad2d88df82dfc44a71890fa09b3941",
    "78a52e0013842037274ea75daaf8eb4afc04ccc4b07bfaf3f5ee47d165e01b"
  ],
  [
    "1bfce5229c5fbff5c0f452a22317fcfcd9262f23df41840f84fe7d44cfba1a1",
    "66b387872c00e63c73006a955d42cf49c46c5708fc9d1579b9ae38341b24a3d"
  ],
  [
    "56d47dadc9cbd1dcb2ee3efcd5d4af5e6aea71df10815c68b54a14e81d11b44",
    "47e966ba54df48e9b612a903685e0060a67e4725402e8cb4cf654e54e813a3e"
  ],
  [
    "4b1c44438afd4ddf20a2cf612df2ee494ce84c7274c5529e857693e73018491",
    "430403bd31d8f0677e06abff7159384560f27b9622943fea1a3192f14bf40d4"
  ],
  [
    "7f7281728fc2214aa1dbf13176a4624b53814734abd570eb6ef7c7e32379606",
    "312da47be347fb3fa2c9089b38df372560dcace2effeeacab4d96ab11567295"
  ],
  [
    "16a28884a1be8183e0d3fc0db84a9afbf47126fd3be548c2a584aaafbfa7dfe",
    "7c3f57b3b895564ba562c1cd80b71fda6d2e611665c6ab87744f5390858fe24"
  ],
  [
    "323339f37b327a731232a9580e79952063c7c232bd1380146d8a83c285f4b8b",
    "4f16be1d983c7232f92cce6b9690695978d42cecc8eeb8c206e125d1098a265"
  ],
  [
    "624d26cbaa197e104eb83cebf2adeed09a5cdad359993fe5e3529d4d0def21d",
    "261b7da3cfb55c788977e0d8d640e3e93ae5a325d962ce85c816d7d32cfc430"
  ],
  [
    "f24ecb7ee83a3e28dab54a330dc93d0429a7aea36412e922dce8fbff40d60d",
    "b043e36a258d1df1d21b0cc7be9c4dcae1bd4ed326c110e668ac23d86805a6"
  ],
  [
    "686cea46b710bde1231483bfdbc700cfa3da6ecd5841c0e0c782f9ea24328ec",
    "7eb7407aa58edd6911c7c7e8d1e03bb52ead4a2415a0c33325872ff3a521dd6"
  ],
  [
    "3866ee1186264549df3dfcdf8705c0380c9372eef6d4081c2454d3aded1720e",
    "634c6d3e8eb8af652a4be73e3b613452c2213104ca875b66b4b15ee5b1716af"
  ],
  [
    "484c687cd2969a1d20a58cdfb9a60f280a473284503b1ecff5de514aaf8206b",
    "34d44d26b7427e51a646d1b924084762f5b461685450f21d6a472de565bebd8"
  ],
  [
    "203561333771fa0fe22c4033349f7b877d15b0542a5598e81e067968768247a",
    "2b6a533aff6e2163a36a2a89cb7415848bef48db40f952ffd380f47676707c2"
  ],
  [
    "2ffa6cca6233695760251206fc5e34c8d3692498589478cdd3d5b09f0b7c05d",
    "6c57d605478fa9626c4ed769554d075daa53e1a1d0bd4d94174d3bfeeb11ad6"
  ],
  [
    "5dccf0fa46a5571f204d0b033b45f299cbb3d9f80fded57253ea4f1c64faaef",
    "30a38e131ee8756ee5ea2a3e16618a5dbc28b5b9311308bf037ecc2039dfc7d"
  ],
  [
    "57b0a2eaebeafd950221facdd24790d7d1ab8883e5c5d55635f0d14a1ee4741",
    "7b41cc478fa6be38417271db8ed12efc0da6982552c1496025d2df0576bf4ad"
  ],
  [
    "611b5725101f611c387ccaa13889ecf3bb5595071a179ce350029bfca4ad7f1",
    "3129755977abc8995fec7eec1123a1561e429fde37ff36af002d3211831ecf4"
  ],
  [
    "1c06bbd0c52fdab9fcaf680c7a93fb821e538a2ed79f00f3c34d5afb9ea6b31",
    "3873d3bdfe0be0157bbc141198dc95497823cc222986d24c594b87bd48dc527"
  ],
  [
    "275cdbabc989c615130d36dabfa55ca9d539ed5f67c187444b0a9a12e5b7234",
    "2b7f723e68e579e551115d56f0ae71a3b787b843cc04a35b9f11084b006521"
  ],
  [
    "6cc702eb20f8b5940c7da71f8b1801f55c8c2d8e2e4a3c6c983f00bc1ffdd95",
    "5d15b3727bc66f3aba6d589acdd139fae115232eb845abe61fbdfc51341352e"
  ],
  [
    "44defb418700cee8c9bd696b872adb005490512d8bba081f8f99a9f15cc981c",
    "3b2072cdb1d919b2b65b5cb3557f0a3381d7ca293c267ca4a38f83e77bcc96e"
  ],
  [
    "fd83ce77b1578b3a9b8c3cbeaddb1504d2fd4a19c901c21ac65961224e4966",
    "110cbe64fc10c6b9c66f15ca406a35f50b723b35d83c5eb9797a57f8395f4f9"
  ],
  [
    "9dc6ff90e341875e113bbfb507724dc7095a280d2f32cb6ba61a1e0c2d2aef",
    "4aeb622896c852c2747454e8f172c9482955a42ecbe522d6ce07ecde79d0a51"
  ],
  [
    "71c58b0e47b9dd9107ebd8a8c8fa9f0534e78231bac612c1ddc7a94edf33eb7",
    "7f90edaf4792bf8334adbaa0f4ee7c654312725af188682d75f34874c4eccb9"
  ],
  [
    "1f6de1f14988778ceb2dfe844f92394f1f1e72fd1581ceb3bf336c95ce50345",
    "4f6007ed4e022d2ee9fe4ca8207c5f6c766c4f3b85260e941fb24ad0dcbf0bc"
  ],
  [
    "3ddc3ac25ede4a67a97547ed27dc920239b585fb3624177e2e8d59eba678115",
    "a9afd8f8bb759cbd1dff2addc63f47da4ba1291ea34229c09c0637dc5c8d24"
  ],
  [
    "c56b0269d8431556e471cab9d70edda3a37b391696f107b2dc370631de51d",
    "729c52f6b134f733eb750c14bd9f95c077f0f6f6ff4005701e5bedc6544599d"
  ],
  [
    "44d32ce19ac6807cb22e4f25fe1486a36a13926f147fbfa054b63ff0446177d",
    "212a21e8c124c9cd37c80d2dd66913ceaa6b6f666522f115c39382b2d5925e8"
  ],
  [
    "35dfc16f3ae6ccc06a267bf6d931601e52f3e45359ffc513570b65b96adc4f",
    "74311d10f4bece01b5ae65a6affe5c931463aa1b73a3320eeb41bbb7bb1ff62"
  ],
  [
    "e0acd9d2d907031b319b80121dc90699d003d220ea785d50e5033cdb3b1a03",
    "3911ba78d6e507485d6374b0f7d2e6198f6462a7d6d3cf046404a07af690357"
  ],
  [
    "3c57918ca254c0cb7dac251ef4e10c7d82327969552eae15d26c4c52660922a",
    "5fd5f5ff3f14e671548074114c72c48409df8a2e71fc8aa3c8acb506e2a88df"
  ],
  [
    "222ad8b61e219ba2b581f606b7c996516850a46a3db72fe1f72b5a9be6c324c",
    "72015a5e2db648112abd284fd867b59fc5606645177d26cf6e9a655c9912d42"
  ],
  [
    "3c86d5d774bc614469768ad38f7be9a53e9a233942c5c553b82e49aae684764",
    "480febea8229e130dedffff89c11f3c43e11724e6bd89d5566d78752859d41c"
  ],
  [
    "adb73bb8352d0c10175df371f7868ef2c9e0c79ac788430c480c0f7d85c187",
    "60b564785248111502e6f39c4994d6293fac22bc25f4d764b2fb1957d3c9bd8"
  ],
  [
    "3836ab8b46cf4f453a22532c886940b982029b29c42adca90ded5bf77e6bcb9",
    "7b15e91d6355f147b171a90b064a9d8b2d7bf3699bbf4987664c61c950d8996"
  ],
  [
    "12ed96af1a97c45ec31f1531e96f6fb28a03ba52ab8484545fbe0dddc97bb32",
    "6d1f522b6c6cad0940cff8e23decc72bb8d4164696af031415508b025aa8be1"
  ],
  [
    "27382994ae5878223ef802e9b4882f481a1b4008f1eec8484483471f7aa742b",
    "c31750d242b3975b0026a0e86ccdd17d0f680a8c6f53f197fc25eb1f777917"
  ],
  [
    "431677eba3715455bc235557518a74f3b111a88844ef13e159ad44bc16de3e6",
    "30000e1eb6a17d9df776981e65c6e500fded1ac12003adc9446b269812c9197"
  ],
  [
    "4b563e6f42589671579eabfa2cda5502b361c46a5ac8d45c8ed44741a925b33",
    "627bdb41678443fdd1aa607709e9699b652308615f4bea760a3b79ee0d9ab5c"
  ],
  [
    "2932fd3f81fc973ca9def6b7f1bb50f980fe589187cfe9e9f52ba4d356cf2c8",
    "1e6bfd00fa976c4770263a227048214c38850fe0f059e7b3d2c7871ef07d68f"
  ],
  [
    "e44e4f3d96d9dec775b996be57e57fdc28e7c68023109b221c414a244a0dbc",
    "58b1e52fa274812e5184e00e9ad812bec2463140adfb4bea3b2d665867dcc9"
  ],
  [
    "7fcb89be1f4bec745887bb891e53fefd665c53d00a9e74de16b8a7e1f7adfb5",
    "74af0b06633f779897e199609c71cc5649bbb65bc2c0abd4c678f0480c198d1"
  ],
  [
    "62a381ffb904ea3ff4d451d4c8459457cdbc3dc2fd2da646a95d8c1e90c0b7b",
    "1ba058658e09db9e319fa73de8ab4a992b71e4efc22c273725bdcab84e2a315"
  ],
  [
    "1b0fbb7a84c67e668450a54449c7a46261a2d355589f8b84ebfbaf9a77ee938",
    "44f8fffa33dd33a6146c35d196595e22cc4a215f61ee9197cd751400970a1b"
  ],
  [
    "78fe920bd96a356d4d95ee34adafe8fecf071d3107c36f047b4024ddc4b3eea",
    "6162f29607fdbec10181fbac6e57d5cb41b922c5791fb24bd28bcdd75d16c41"
  ],
  [
    "5629b849e026e65d119ac11821d7ab7efd9c52226f75c7427505d6818bb0c8d",
    "1539c0f90970ee8b490e45bbe5568170e5708521a0e59f976be680595906feb"
  ],
  [
    "62bc853f349bac8c6e5921d27ba85dbd9ba20a375d70a7bc008928f3e123b04",
    "6acfeb1de05ba43c3ef1a9110a983a320e77b3ca294abbc04aeca19b194f26f"
  ],
  [
    "4cf4bed663464418285cbae359b5d84ec76b5997d24f3640984c7663421190f",
    "941f818e3e3e8fb1568da85217d17f9250ebc948379014d900a7b1a848494"
  ],
  [
    "52ff3d9ffe9a302f6dfaaf74bab57c08027d5cb699a69b30830540c0a2d47a1",
    "987dd8876873778d933fbfed37aab2f7d6f669c37024f926b1edcb2ca55782"
  ],
  [
    "1109ee32f0bc53de6bfa457060b366e909d7c18061ec9845f46ac715496897f",
    "38f36f172bdfd454b9285f86e6bdece8fdffc95182c7d801b03c671cc55139b"
  ],
  [
    "4b4482f1d84efe23dadf3bb10df3dcaa251312dcdd604f616f1eb540e1f3232",
    "7c9c149dcae9135f940fb54482f9c3cd8193721643a6e23157b8020410d439c"
  ],
  [
    "69cb459b9e415b7581ca163611c470d875971d5d7949de732d1f0f200544a73",
    "a7136fa9dd00c0469863b7def3f83a5611ed628810d7e807e7a873da5a9897"
  ],
  [
    "b66a4e32ac9a4baa8f64780acd94ed3628b2b0ea874ba4dece629af65f9e62",
    "24328ba9996a24389658e3467b8b90dc3927ef8419fe28b3f55b1c1aaa51915"
  ],
  [
    "5ecc3080062dd451236de0e4eb91c5c75100733364bc5469f5fa76f79021ecb",
    "6da4abb9031a27b5be94529324fad8026e7d871570780081b0f424d4fe543c9"
  ],
  [
    "1e3146f00880bb22486d5bc73e54367d54251f4002bcf342d0393b05a4b9ce0",
    "23b6fb8e945d3205f633ba724202db5a99305f807137edf942cd60eef867699"
  ],
  [
    "2e1da8013285598b899f026c6974185db12c97b4c63509769d3d4ad1d18a4e5",
    "1e7e7b668674d1593c39d58bc7bccbf568208732b3519bc2cdf93db34366862"
  ],
  [
    "d26c3f389d81709506f184b53871497c8d36c5c9eee8e3737358204c1acba3",
    "34649c3d39f3b825947fedbca215ae30c5a5995e93b1c8efca4944cf85a082a"
  ],
  [
    "91300478a83595d548f32f259033291fc7d083953b0b8bde88c7559660c563",
    "e5d2bff57fc6551e9b80c06ac7314a71907cdcc66ce82f2cce721a670df10a"
  ],
  [
    "1f7abcb9d462c63ffe92aa56619ae8590089cca4d93ee3e5f34a63882452cc7",
    "7e9f85c7b7ca6e9a4f3a026d1048adbeef69ea9d876c6f647c257b879a81bdd"
  ],
  [
    "4d2caa1323012e4c83b0ad387308b8aef5637bc35ddd882e7f5e41cf2ca410f",
    "47150e808c81a540b6f8864e9d6636589cacaa516f82caaa96506edfbd6f0e"
  ],
  [
    "3c10a6083c38351deb3e6d1b386827d0acf48979b66b95249eb8700ec26b069",
    "47e34bfe561d903cffdd1d849b85aa3cbd31cb4a9bbd8cc2e5fd2f95016cabc"
  ],
  [
    "758bd54868eec045d0b4d3d2bc415d24bce13fee47cefdfda46425c109b657",
    "3392a7c66ea3bd7b044680bbe9f78ae86752097404c067e9d2572f55330df83"
  ],
  [
    "19e718e0ca1d2d6fadbc6006ee7dda7a385430e29f5e239cdd4bb7c3fdcb2f8",
    "5c68249b7fe03ea2e13481a63b6cd4bf74ce42009a89fee0b3f8f968b3ec709"
  ],
  [
    "28077f57ea62401806367e6d54fe45d02de5b072db787ffdcc3854e12a3e855",
    "14f3762689072f5fb41d03e94b01808c739f6d42b7b785b0e464100b150efd2"
  ],
  [
    "3b8a8cefd017363ce867265af3293cec081fa589fe561830f0078778cbd338f",
    "69ccf2383cb7b4f9c806d72535812483e7c5e9a1a5928529d64ca7e085e758d"
  ],
  [
    "77878f388d22161a2953e5aca6bac1ea480e102f329574b4b201640d44a296b",
    "7eb35706a90a03aff7c2fecca72659136547cee98038746db5aba16fd7178df"
  ],
  [
    "97332e6da70961f2ef31b7b628f1018d21db8db015922a301fca7d6fc6a8e6",
    "2e37b06f639fc7a82601b744570a2619e543cbfaf60e474107fcaf4686d3223"
  ],
  [
    "a81518d452d3aac48bf0386c3ff170ef4e684a4def242c964e129c64f4d647",
    "37506e44c85908ec7b7adda9547fbdcc2e3605151fefa77fbf127ce3bc938f2"
  ],
  [
    "e80336b2220b1d666074f6b0dac85353d0e4c2e8bd0f37055a2236a6a9fadc",
    "1cae76d73eda7a5964c5d9d3ad6748aff51f5543c56441d2fdb7b444a39846a"
  ],
  [
    "2c01fd8430ecb44e066f352c4f697fc9fda177dbe162f82862d7b9ea8c918de",
    "6e1dfa99640fdf5b30603d34c7c97c1aa6e6b7f3a2c52a21fc64b0fcac7d591"
  ],
  [
    "744e37b511cd0ddcfe15f3581947014c159de81ed055d15a13c7a2d1fa39f0f",
    "685caa8ff6979a6c63640ac638a3f9c75737f2031bd55322a47384357af164d"
  ],
  [
    "40e627ff84e1a7a9068b4368770f5956128a4d9e9e33e9cf5e24d9a242149fd",
    "2465bd6cb20bbdf810e2bc5c3c458cecf4f3aa163a7ac99c2579e5f33417f2e"
  ],
  [
    "5f635af7f554a17bceb6ccb6e637abf89ab6dadd399189b0a0390e87b1896bc",
    "2aa6238a69f89665646c0e3ca2ba5f709cc6e14351cf71e1b00ec45201417a2"
  ],
  [
    "5edad3063c9fa8305978d7e6a4e037c9fa519b8023c7608dfc3b66e5c1e8985",
    "49f405d07d7d01919da51159ecdad1031a5ac208c026fdfc14d38f633d92183"
  ],
  [
    "2fdf2e8a45858c12926a1f25a62255fb2d02d0149a15ef669f859806683e649",
    "61cfb686bb31e2524470d4ad2ae09e3cc91b16305a21d748098feb1d8ce3b3d"
  ],
  [
    "ecdbd7c37f1dffa3943977278da3bb429afdf948b4ea6cdebace3d3be82381",
    "190b67fb34f7f3ad6afd3d6b6427aa327547d8ac0fb4deeb0feeba1f63d6c60"
  ],
  [
    "233021b483f578dfa5222f8cccba5766ceee0ac65f6d4a3b1673b302a21fb3c",
    "7d4b6d44d175d4b593f06f5a6dcba2cdbc4eaa2097abaf613123546866cf4ef"
  ],
  [
    "42db4e953c2a7a743de9fe20c5798f2247f51db4eabc6f40e86c13909a310ce",
    "12c1a0764a0b9f3666e431923ce15e7fcd0ded5ab153f0b48d362cca1604e65"
  ],
  [
    "30d539e2b545fb957e40e2255f6463b52d227c9808472cee6a3d521aa283a44",
    "5f9eccf747fe6313570f99e845db32b40070acee9ce9e34da7f3c29ca53a07a"
  ],
  [
    "4bd64e5ade3e2733580a6116b4af328751198e7128f9acfe3a3496b545efb5a",
    "4d584768900dabfc0dbaa086632b8051bb3905ef79b84d96c01514441d0cc93"
  ],
  [
    "62d6e771f02e591557197d13c3e77dfa2d1794ac1808407bd8227c4be31b466",
    "5c6f5607c1808e899ba36a425911fa8566b7ea9cc80de8a80538c0fceb837c0"
  ],
  [
    "5ce406218cb2852b1d2fe1836b19462f664631785216e87ffbce26030e2101f",
    "5225f107743c255ab50e7be4a090fe39478d1ef4ff558468559d8cfa87bb94"
  ],
  [
    "670286486e8dda3dc66b0ed3149be7697d3e06c8279844079daa7e42d5af728",
    "26becabe7430380c56e320f5ae3329569cae7b0af06fd5327ee23979d200eb0"
  ],
  [
    "3ef448df33a4394c43e93e5850cd0c5a6dcb18ae1cd865d00fe8ede9336a9f5",
    "56711f6ab7e0e4f7365ac34e284ac2879f40208c46f6febcc1dcf7146ecf015"
  ],
  [
    "4b63fc130288e92f2d6ba238caa7a6364804e29829ac037c57df32fbf762bc3",
    "1eb8c80af55278b4113286c038fff2bfad2da62763bb03426506b869139da0e"
  ],
  [
    "4e7e998557b29a95f805a6e2e26efc1e970108272d4755738c04f28572295c0",
    "97cfcc2f447bde61bde71049d8200a74a3028b21703bc139143d81a3623f09"
  ],
  [
    "574b67898f02964c408f68e9470e7b615be037e40b824e6617f89cb56c21219",
    "49392d5f8e6740a1b0b7444f56d7a17363f8656c6e4c628678c86223f2e46c8"
  ],
  [
    "7e8cb50ea5d5c1b09e219e7305bcb601d99b6d7185b1c388aa8e36fe1e56554",
    "47fefa308645455c12ccb5817da338f0c4f423b341aff4a9d158891a4fd69ba"
  ],
  [
    "67266dea9e71b4ed2bf24a597a823dd048cf31e725db511edceac72998c9ef6",
    "39babd65850befde1f7c28e41dbdbb4caf82bbcf3bcb5b33161f1c2960b2d8"
  ],
  [
    "63e99c2cb9c74eb9227d48065e27abb8f606df8fc83b2c44e4ea38b046bad2b",
    "60494a53dd13ecf34e08079d343c88fb655d6d810785af81f08d5aa9bcdcf9"
  ],
  [
    "3cf0600b0f5a2a4eb78c487cd385350e8c7848e3f6983231881d7f1bbe28543",
    "56dee4288528de609976ef6b903b652127c37b0590e91a2fdbebc3f11df2628"
  ],
  [
    "758f09245fa4b8b23d290ee2b3bfcede199b4fdb11f3cf2502a8ceedd61b129",
    "622d9baadfde781e985d9722e0a04715666769a4cc7a9bea0b96d6386be1746"
  ],
  [
    "38e1a45b81492aa95d7abea2b08b8c14dc0b8a41108b036871fb737910ae18c",
    "145c611262656385e5ed6243568cd3f9f59dbfed7a01ba11e22bb8bb272e08e"
  ],
  [
    "206e54ca53a2f155bd4fc45bf2edb77798ae6623defd4cf22f2dd4a7d119dad",
    "6c94e7f0825ad81680e4cdbcaaaf4df806d57a0d1fb2331926c3fe2b79d22e8"
  ],
  [
    "56e98d2862893caebf66180e84badf19ffc8b53041eaaa313ae7286a8fac3d",
    "526306f9c01afd6e0c1198ea5de17630f5a39c4ecd02d8e6f0d613c355995c6"
  ],
  [
    "4fa56f376c83db33f9dab2656558f3399099ec1de5e3018b7a6932dba8aa378",
    "3fa0984c931c9e38113e0c0e47e4401562761f92a7a23b45168f4e80ff5b54d"
  ],
  [
    "450cfaadfecdb8a2fbd4b95c44cb1db723ee5ac9677c9c188b3d7c8eff4ca58",
    "1a552bdfc0c81be734f1f6ca9a6dd3ab4daa61c11fb53ebb7046eee25d617c7"
  ],
  [
    "6fe20e5c8a8004e33eafc84d16ef770f2f0b7bace19adaaa150f987d295a34d",
    "28a35040a2ebe9a14a162d3208d5eabc6e2f3a8310f926bd80be65aa71775e2"
  ],
  [
    "1bd65f45a35bf62ae8f9ffcbd7de2976b90518b6820c219f039c50043bb1edf",
    "fb5f0f8659f9b6ed7cb0ddd7999506d0c20b26bbe69d1915a31842cfac41eb"
  ],
  [
    "4ba4cc166be8dec764910f75b45f74b40c690c74709e90f3aa372f0bd2d6997",
    "40301cf5c1751f4b971e46c4ede85fcac5c59a5ce5ae7c48151f27b24b219c"
  ],
  [
    "21cfbc678f5a279ebb6ed124273c8df37eaf12a2d04180403ae6b5ec0b1e1ef",
    "4478ed6a346d899ad7b0b10350270aad39ddd5b68529297e4c91a54357f0a7f"
  ],
  [
    "350bfefbe3d864eaadac9cc1195c14159bb736be743aed7380d2384cadd2046",
    "5e2a4b3ad0e1d7b9b8ef72b10d68a80e5ee691d7db591fcfbaad6240d41da8b"
  ],
  [
    "529acd569127f73c8d34345f87e96cebfb48ee12a00a3861cda209337ed94e6",
    "3120671a89b705e5bfd99b0e7fd2118b4914a3ac309b3d74527cacb5ad7491"
  ],
  [
    "55d3d7956a97d10e65a4d8ffeba40deaf0db0b57f8e022cdb3df6df613f5c6d",
    "159e59a6f92f48fcf85aa96c1a03749a4c4e2cf9e2bc94dd36796daebd9b8b9"
  ],
  [
    "405f019ee8f2e972a005c549b0884b5051f63d1e78480b73208dc07d8c65a1f",
    "4301a3d0c285ad309ff24a12c100ead7f48ba1368143712f32ac141ab4d9e8d"
  ],
  [
    "376d59b298d982f02dccad0edd5bbd4e5e8fad7898750675ed0856850a7babe",
    "5233b12bbc50564eb61cc098a17d3d97f06ec7a230380e4c5d3b725cc318eba"
  ],
  [
    "2f55624af6109ef04b2ed035a44a904ace8627f55889f011f768aabf4de9a38",
    "7f64209ce7dfb63337ccf3d8c14f4093295f86996cabfee23b1655549aca089"
  ],
  [
    "3b8965e942bed2714bc2e685fb103496e1e3595ac6a343d6df45fb5ef6979ed",
    "5b7cac7a165cb69ae103dd9052fb39c00ed0aad47989005aee53972d82d45b5"
  ],
  [
    "7abfe3accdec1eae1a50049efdd9a8eb7c2921a08e8bf1fe606e9d5a4039ec4",
    "3af178e7e831f8148244d2d2b284a32991852db6212ad0a9d77540ef648a5fe"
  ],
  [
    "4983196df6ad7d6f0a8d76f86af3863ad8611374a03fc0fd00793181dbde9d",
    "204c1f91b70f975a21d24a8face664e496f00f602daaafa69a3b56098a4cf89"
  ],
  [
    "79e2b91c1531a3b16dbd53e72d94e16bf265cbec261658151acfaea3718ea72",
    "3d9bdb47e8b148c1c5e9e694ffbc2cf71aac74ae1a85e8d8c3f77e580f962eb"
  ],
  [
    "297efceec61b3be17565843cae465c52524b4ecd9331a4170f54f7de8c4556c",
    "6ccef1733624cc8b973ac63dd54e7a53604929affe81c3439525ae5ed6af993"
  ],
  [
    "44f04b1966264a23ccdc870c8563ad2efcd4c8087b5469b90e792287a5581c7",
    "1c417f0e9829fa3d3cbb7c3cf4dc7aac04c5bf66ff3f86b833a42c533aed1fc"
  ],
  [
    "6ff83f5d8b51db3be0bda80eed2e2adb7037f2f58f705e88f0f98197431ac26",
    "64f59b8428894c2b7afd740866065ded42e716c7d48accd3f117f22768ed9fd"
  ],
  [
    "14aa8187c9559f77cd1cf96b2dfc949182529936f2b0b4050ea56e134073b24",
    "5f36508c68b1dc586f3fd3f4e2bd29c6d8258491b8a6aa19ede811ce0d3d0a1"
  ],
  [
    "95e8882a68c5000d1c2be7c0b43e7f2a6f8de906485241f0285a5c73a27a83",
    "1e4cb67207ab73bc1e5d19fa2146fde6d03021393b77a55df4ddda1fd28f5b1"
  ],
  [
    "2ae0704dacb3da47d564514b4c3543505b403ba09a248c6e74593cba1867ff5",
    "5a4b5818088dc9ef4066b90a8893ae80fc89584f987ec1928ef9d72cea2bd67"
  ],
  [
    "61a10898a76fb99989e51c0e823cb60b95ec7ccccb917c42b2b28014f5fd94d",
    "23d8ec1de45366d3b86c64c2da05a2ce3d171adf52ca5522e652ffd0eeee795"
  ],
  [
    "79884133c879cf07734976fd64de220c5a972e04c2a3afb74c362d6c3beecbf",
    "2aaa0e6d4891b792b5643fdf09873343cd0e3fbba3cbd0601b481a4083f32b6"
  ],
  [
    "45f73d2fa82be6c5ccd0f62d2237efe8727c479967d27cce28e42b9a44bad5b",
    "2fa4932215f72d56d8be5205c5851c9b3e5f2a14468e4a7acace5437c6b27dd"
  ],
  [
    "37f53f771850f52f9c8f87b53c6bf0c93c2bed76f5fd1d5697356d0b2325007",
    "50f1a052b79b446fbc7b93ffa1a4515f6c3be3a76a2b0bc5eb8ff327549960c"
  ],
  [
    "71bd6d23e0d2f312d47582efa609101f15b9ccc571fca8ac4fe3457c67fbc9b",
    "3b3fdf86bd4c7fc26d60540a6439b4d179dcbf7b91efb0ddc60dfbff9a148c6"
  ],
  [
    "78219ba049438385b829c13a4993874a4a326c4143de0dd581c7b9956f99b06",
    "5505f1268dcdd4ee01b77abac3bfdcbf3f0513ab097c69ff777b4a631aaf256"
  ],
  [
    "b81e924a86536dcf68bc5a2ca2065a61103ba6c9eb0ae4cf8cce9dbe286f15",
    "653a6dfb51acfe8a844fb8362795e5549d424aed88d3a090366a44f840b5b83"
  ],
  [
    "441c0d7b7aa705046dc0e07ba5f33a7d9df23f694a05192ff8c2d7be2aa3fdc",
    "4c06568c0902bb99d428bfa0a946ed0f0ca0a51fbf07cad88e06e9c78e38a59"
  ],
  [
    "2569c8c78b6d6b92533f29f767c95720d377fa63ad5a3b9827ee0a74b0488aa",
    "4b59c81d3cfe08834f946d9d57614f5366e0bcd9349475aaaebe01341196fe0"
  ],
  [
    "3f2fa285a0471647b214eac652bbad9d58a9f2dd2e812aff0210d0d8a6eb32f",
    "4cdb18e1c2848c2b52c1a6557165bd1a8f55c2f7562f5cc0b326f73c25b696c"
  ],
  [
    "5bb5141ab4fcc5290ae9151b8045a2cd8391547ce7b3b33cbbb10f8fb538092",
    "5a36bfd52acc6a83a9913b937ec086cc27fed030b5fa70dbc5d3c12c9515f56"
  ],
  [
    "3f3fed272edf91aa7f8ca5d70005d390fbc67830ffc69c5fa3ae17582d2771",
    "459057e0883c44d8776fa217405f443e5954f08c4a5db68e437becaa664a999"
  ],
  [
    "5237ca6656237a717a739a4509f70db1b9dedbb6cd232f60c9bd8c4563a6b1f",
    "56c7799dd02896dbe7d69dd8bb9718270549592099569d107b7b49c34bf5a49"
  ],
  [
    "1cf6b8499ac881e0b2fc7def9bc1a28937033b2fc52de99e75909a620c7a281",
    "5769cf4f735366fa386b6858043dc99a100f86fbc77b16d57d77766197ba27a"
  ],
  [
    "1b74b8a6b86dbf9638cdb0601e1a332b8d880753423d38c3394902c57f15e40",
    "6bb2dc10d2ecbb913219d0ebdc8d3337d644ed8b6c4e70637ef4c7e50887488"
  ],
  [
    "61e4da415661bba52a4737e2bcde1a837787c4796b2e1854778534f1582c29b",
    "27c43e632cb7652e8508c9c38e3b4ad0d3dd6ba748d42dc84ec2685e64b9aad"
  ],
  [
    "7c460a204d23f20ce86596dae6ac9b36734e4a9f7c5b43262c97a36c6a41c6e",
    "481a11f9300ab4c4bf6924c5ca884728cc361247377065920966785d043fbbf"
  ],
  [
    "124ff5e55e4effa40daa5b9618d75c49c8b6fad95cbe8c0bfdd83cb9bed8316",
    "33a2ea15d0f71f58a00de71acd7f22ccf9002115e49dd1f7631faa0d32f9987"
  ],
  [
    "61c9f8fc86715e95ff43583a865c5a6515f93381839d557ef884a68637eaf4c",
    "5877daaa42bbab9083b571e12648a9d62ced4470d71653092b6546f4a5acceb"
  ],
  [
    "70a6b9a9e5d1fcc07dd9ebef6d8f5fcf04c6cb34932d0fe2335330ac6dc8d3d",
    "3f0cbd332ac56922e886656bee74f6e9bb4bb88f7af7bba9098678af1f38fc"
  ],
  [
    "41db8a0f1ea78443a39e08a54323743c8897eed1ddc28f41aec6f2655040d9f",
    "7d4bf32f8f4719c2e4af8b7889f3b65cfdd033dc2f971798a12170f2b26efce"
  ],
  [
    "62f035e01acdfe841104942d6c8c07f0fbd618cb85998ea24bcc24cfac1f8",
    "1caa886104b7d753fda93645a746989794cd825c62473b526ea34b3d51b5771"
  ],
  [
    "441c6f016d270e86c19843727b83b864cec060cafc813b23d7e41e5abb1a60a",
    "29fece4e40400f3acae0586f4fc8ed535e805e472123ec38d662d8a0b01c086"
  ],
  [
    "2c791ba0fb0b66177815c98191fa6188dba9c795e34a7c3c8a19086215e3cee",
    "11123151389d4b330db6a665a560407e7cd8c3807c749e2b0cffd9c3074ba77"
  ],
  [
    "5292da4ca71ae75ed0554c267747e39c7a129b3b863e1af3ebb3e368439c4ea",
    "63af6a5016deea8cc674c44f16c63c1db31f09af4fb4d2ea7917c28116661fc"
  ],
  [
    "3367388d5d1b7758dc3d92e244f227bb8a54e3d9909e7b7dd62ab5965e3efc7",
    "7ffb4833071e4b03ea755ccb9938487a478248fe9b1158a08f1ac298801c092"
  ],
  [
    "95c863314b7f18090f8eee602403be823a367a1b416d54c32e5f914e67d922",
    "159c2824f899171deee23e0ed520d4825bd667983df0a8d45d3a1f7156d91f9"
  ],
  [
    "621c6e08b3c57404644ad49ac7629832c141273fa1f323781b3395393fe985c",
    "65d1eb0140652958c4371ebec791e03317d6b2e689d90e304666f1b610783dd"
  ],
  [
    "54313129bf13993952cd2b31ed06013aba85e74c1b8a00e062031f32188a84e",
    "680129efc9eb8ec07fc180e8f6877e5f0f9f44e3000a2c586ed4ce49d12a313"
  ],
  [
    "21ea57a1c8286bb45872e78617853c47b89091670ba51c124afa3362e7260d",
    "7087e5c1536df233ec9bfe2f983e8d7622892b9bf64c450c9823898e2cc2fc8"
  ],
  [
    "3793b05b99e7a57d88db4ed0dbc3b771285abcd9052da50f88595354409f3f3",
    "12164105041c056f127e737c7cd63981e05f246bd2b6b65d1f427019c7c3801"
  ],
  [
    "befd345cef5fcae22ac37dacd6b9128cc58cbba3e3fd774e11b421c2ba392",
    "6209d25f24f88f7876ca604db23d05f78e6b3b67fb033f2f1bee221f352b8c8"
  ],
  [
    "15fa536045fda4c65ff74f10b4e669ce88b9996c6772288289d3ad725987fa6",
    "30e0c2124a35e265e931ccc66ce5ac3697d982814beb407144ff6762cb691df"
  ],
  [
    "38b795bd77ac573576dc204857a488cac2cce19809882631ca2069598c577c8",
    "786ba555d55ebef688b068bb9186a34a08cb00bdfef51619bbf911890ae9a13"
  ],
  [
    "6c66853592196c3eb8d9526dc155205e2c64097adf8684bb0e15eb460ce1c72",
    "1bb4ebf654f4250c8dd1061a4e1b464b31a8a9999ac9960446ef8108a66871a"
  ],
  [
    "5b08dfbc87ad9c00b88e78816973ad2f9c10c70f2156908892cc7b7a2a1fd30",
    "1151f407a77e2556073173d8f5c9ff561d8a23742121ca15f7d0ac391af50ea"
  ],
  [
    "309190eba106aa6ead54b5ca5817969aa68b4b4c627700799a49fc6bdd32ba1",
    "505b6a2bc7b0d78ca6ce2abe7dfb7312369918a4599cccf8a615f6701cfd851"
  ],
  [
    "89cc205966af08acc8910d563af7443d5dfbb5d88dae79c013c678c65dcecc",
    "1f8cf955694b246a423ac725791231257b88936e00347ecaa1e17045c0ab540"
  ],
  [
    "480086b61a80c36cf1e1a350baf554e58ee8d9333186b70c9c512fb9e9d5a84",
    "511edfe58f8d36a6170df743731da1ff525cfd5108be20e30ac4183d1281570"
  ],
  [
    "3caf14fb1d2e90a13ad4eb091250fe37133aabf6029633e905e5a93ead41dbb",
    "49122aff6059dfda19e4b973aba5ebe3804c91728936c6381c1ed1ea9380920"
  ],
  [
    "66d1b8fb2cabc46cd79741ce1cb7326077ad8ea3227a6427244bdd3806bdadd",
    "4a52eb74f4d5371ba3265dffd61c844f9e68d4ff0b44dc4936182f9280bb66b"
  ],
  [
    "373330c5afd53c31257fcc9050fef873e15ea9f81d9810f30744309b04e02b3",
    "5889806607b3dc97a9c5b0c8a2f16d1792099a22866b879ca480cb89a11ef5c"
  ],
  [
    "26840d0ec69a22c6818ff64b8b14633b531508c866e21d1dc9239778ae9e8c7",
    "157971f9a6e3a24d3b307be0e7c8cd352e2eb5cad33cf276270c0f309ee63fc"
  ],
  [
    "ebb84848f1c38c19a754d1b5d9460e39624dadbb30800987c9419c0f933b9f",
    "517b297cf32f4064e6d6c8e761ba8db89809604a701c7b3aa1a9c6beb370ea7"
  ],
  [
    "25780380bc0795ed0dca727c55240f1d63593e552d224adb40df2d3721c0f66",
    "10215fb5a893e0275e9f1f66b217dde35addee91ed0e8f7d79531a2ff57b8c8"
  ],
  [
    "243e1581cd1abfbf18c31c19a4c3d1cedfe69a40bb57b607c9af2717eefc742",
    "1296c27929f14535718c3a4ebe045f00afdc60afc74c7d398d8ce1b6609dc0f"
  ],
  [
    "48babb8649e054bc8e0b902c89e6940c265f48464520649502ef1064eb94562",
    "3235be7852b0526d1a16f6969ec0e5b0e09cedaadc65863dea4e47f4f398264"
  ],
  [
    "592db7c27e63489ef4bcef2eafce89f40067cd9a1ba48bc3dc76b5fc62ad9ca",
    "48b7711b570cd9ac65910e75e752f4b751fdbfb4091a28f59b8c046d3d9f8bc"
  ],
  [
    "31d133456222586ae42a9ec7ce8539ee04afbe0b2ed00a2564dab0798d9b55d",
    "a77c52fa1fd718db5c83e7fda6d7d4d9aafef9ad95cad621470f2b753729e5"
  ],
  [
    "4651668379883521e7983aafcb93811b4a72ef2975b3277773746708ef3e3fc",
    "512507f3f544d80ba5d47f73b571881e8d70d7b1d305b9704bdad036b7abc47"
  ],
  [
    "26069e359b2e847affaef604f772f36224608b7642245d0e643889ed231bddc",
    "75ae1ec379f074ebc91270077c74b4d34347ce183b676b4dbe100bfff143b9e"
  ],
  [
    "3196d01d1fa11dc3803b4813c4bbc6326869f61410f2bd14bc0f570d875aebe",
    "20313217cac79875bd2a503db1e86d1e5559911667a02524759344468d9561d"
  ],
  [
    "483256607f75f06fb126addc60cadddd602154cc4782bcc08351a48745d0b97",
    "2950a7e500ebbe9775f08be37cc2e62ccf9030de18948d1bab07a4a9173f75d"
  ],
  [
    "65f07b6050a2fc6eebe2c29ffa62f764060f7f9d3c82d2cb5e4e368aaa442c9",
    "562c9654b646cb84a213b41de203c871b3eae0a05c9c105a66a53c319c06373"
  ],
  [
    "284870f6181c43f3b01d94baa9c5b6ada0deb861145523ad9169580eb7bed35",
    "5e03e6c40c1cfa3cafb01fd0622349871832a9d35499d06408a83edc1b76d02"
  ],
  [
    "32229810a52137f0e6c3d37595c46f6132822d4b05f42674b48d7a7ac3ad85",
    "7babde959a0cf2c53ee59fc52c77c3adf899453f077f441965629f9aead30cd"
  ],
  [
    "1ea8b98a6b85e74e0a2fbc18b206e290f3ed94ce99ca665e8e2351dfade990a",
    "478e93c4724115fb1648c8d5347422adbc1a0bbf962b2312e14aec80e1be742"
  ],
  [
    "270cbaa08c79140c85b864475a0bf569cc03ac785e57f543dc444f37ce746cf",
    "3a9b8d894016680ae9d1bf3deb931d8987d4d8d8bfed45b81ccc595ec79046b"
  ],
  [
    "6943922708b8ae5b40dd7031ef2e487abc4ac39a3591368285e83d6c9c51f4d",
    "5f157c37d09634e8cbfbef90ea50af59815d011e419a691c67ca3402b5efc33"
  ],
  [
    "48ac6a80979fab4912cf0cb557d917a0bd68825d8658ec100496eaae6ff62e1",
    "2b6931350ab183402e39476340eb1177b7006f7a552915581e29a79bd7203a0"
  ],
  [
    "e3adf9517d92ef22d1e2a787740a292ba32d5ca69faa9e8675f63ed816dce5",
    "36bccf69bb12dadd610145a3399213248d193660d8dc90a2e206f23bf2c7997"
  ],
  [
    "5e6c8ae5afb2fa470f767581f3d578cf6a49547e4b78665edfd45776948bef8",
    "6cbfc11953dd7e195d2ce74e52a60df524767b44c4608bdd755be4bc85eb74c"
  ],
  [
    "15a576a1242d39300f0db3ad770983825988da0457718ecd596c63a0a0eb4a6",
    "69a42e5f6f5a63349b57683a4609bba90f556a1680fa1ec3b02ee7d3211f903"
  ],
  [
    "274cd14e4fbf2ed07402e8ad8075b320c5f76b7ea45ea36af523e95ed63ab50",
    "6ca640f9557c5f2d8b27f6ce95b108880ff4e4816b26b70b6506114389ce656"
  ],
  [
    "4d8284e132e2fe81c5f71be1e3c79ab51b229e2c56c323e207cda179999d123",
    "116cfc00e9fbee1cf16af6282123cdf20eed13021c2037ef4c86f94eb6e6cba"
  ],
  [
    "4056194fb5643e97991942ef5b63cadd89080bf57a01489c4398aca03f0980a",
    "2e2cddb434fa6f6da7859c3d518f0ced8795eea043a6c9613fb3e020103339f"
  ],
  [
    "5d119d5c5ce532afc0875e0ee9b026d878c8773d34237f90a0d0670da6f01b3",
    "4a79fc025ce076b6a4742fbcc8cad313d0a8220c58024a41a5a674c0947e64b"
  ],
  [
    "11800ce4061d99b9d53fd4138802335258f7798c5a935c9979f5a949ce1d483",
    "36745a4741a5c7290eaa8f2a3f9ec955ccb7ca323272e5d35d35c2a724ffac8"
  ],
  [
    "4302525bceb97fa642fd5560a4a39fba3d2c06f68e6aff3332ff1854439ebb3",
    "e31edfd081ce82f8177b2d7d96e69851d09e908c2517114ffb37ee12c0ac64"
  ],
  [
    "2f5fcbb96f0a66fd3bdfbcc78bda361cb812570f50e7c476533d56eee01c0e3",
    "527428a34855b5695c479d8fb7e831a299f7897f36682a74169cc60d160df2d"
  ],
  [
    "52167df045ad0dc999b98de3d035aced9da4434211149b8cf4bf20e774580cf",
    "19051d2a1ad3fab190c5dfaf45188b49b4e90cca22aae54f0a785562d3d3f41"
  ],
  [
    "541b5332491dbdb2b6f6bccceb7634970c046963891fae936dd950f4432b961",
    "78fa54da996a51e3a9c06091d58c2405a806649da2bb1f323807c4eec50eda2"
  ],
  [
    "5f11e973da659b7738f87ca5bd4f3bd02207dd3c8d978f0d3e83fe81030febd",
    "137aba7027069f62d25caed416e13537687bb1428e71e5f0a0c52d52f2e65bc"
  ],
  [
    "15ec941ee6c2110b819b5541be52981c09d83484c9dc735c43f39f5778718b4",
    "4561826142dc5b56acfcf605a78a4090472bb61235bcd605a765e05d0a7e549"
  ],
  [
    "68ba398736d659522f484406110b43c68158bf4992094acf797a38979c587a4",
    "7c1d9e1702e28afddf22fed7a7a79df4315c174d0c6c4f4c75bc77d9b56777f"
  ],
  [
    "67889cea31c81a429fbae643a4fce0ecd690a5c32b99397e39ed6d7a08702df",
    "7ea277c80b671146c9e455b98f42f45b941ac95ca2d15c8fa9ea82ee9b45e01"
  ],
  [
    "596f2c68390ac26505d3c2eca5c77d46f8f3acbed192a2649d8c525a58d2334",
    "49f3bd8c62c610d5c19c52d970bde24b270c4ff7ae900453b909e72483974a0"
  ],
  [
    "567779fb8b0afe592cea284629e3621ccfae3c4d7d3dc559c9fed750591a395",
    "6010bdc33f1cdb374facefff537e7910b72a1120502f312a7ce41df0d552ddd"
  ],
  [
    "cebed0233e810aa6a29a8b0829d28f1c92f303d14dd73d6b12da98117dfc7",
    "4bdd51e1192a00df23aa8d0673e4915877ca41ddb8c9eaf21d39dd167fde7b7"
  ],
  [
    "4c7085f066adeb6781596771972b188177e63f2e2b3788d03e033cdd5af1f06",
    "2929ee89f525862b0cedb3ab9b5166e1680cb77fb4668f10a6a3d76b5434566"
  ],
  [
    "760e341bd836899c226176f47685f69438270c150c6fe7744cd723cd1e72359",
    "1bf09f2f1aac1a10ce8bdf20d5d178db747f01a4aa0aa8a5e4bfeef562cd94e"
  ],
  [
    "6016b94c00b54920027ef64902c61478244b1936337d2ad41d9a8d43dd6a4b2",
    "3bf3dd9bce7f6d6f120de87fcbce6219340b59c2c1d75ee0d45105d33aab1cd"
  ],
  [
    "4929e44ff692eb944d1045bee96e750219cda3bda0500029f0df49a1db30b5b",
    "2e138dcbd092242699004b4ce98764ffe4e892841f56830af298581cd1e523f"
  ],
  [
    "5972d0e526311bacb70a04e88969b6c63c7399b578f0dc28bbd00d65ef01da7",
    "76b22bca9ac12d26530e7b0757e646beb3bbc5680d0f3f82fb8ee57ed4b5e39"
  ],
  [
    "2ca0a42a26e26934ca2d48db960b4719113d87c5e57fb437d557c5eb4e03ac7",
    "62778c02561d4ec5d83a132afd7763a8349207c6b5d01fba70b56ba660cba2e"
  ],
  [
    "5137ee53f076e21a2c23da09f63c0d275408c31e4634a6b6373be5cf13e6c00",
    "14fb446c077beb78e04de3282a63bfde12f9af85caaca4ddfab506cee31c0c1"
  ],
  [
    "7d944853d1627b63f560aeda33acf640d35a4ee4d23a744957a2dae9d5b7c6c",
    "bcb411a210710acbcb9ea12680d89e3e4e652228b6786d3886e95f4d9e6970"
  ],
  [
    "37d412c2ffb173a728477446b60b2b702d07a5243cb5fc8963e623a5ee75843",
    "672c79968908f92cd0cb0b4c65ba86e8f359b015623a89441e1bf859bba84cb"
  ],
  [
    "5b37f472aa80398bff12cc74c8ee784c4fc89757292580d3a498bff17e9f114",
    "7d79da1aab9cfef58a5f3d1c9ec466956a45f8d2af0c1da6dd4c93f720fae6e"
  ],
  [
    "25c09b3f1188c562571536202eb0f5fc4b9a7590417b8ea58b4343685d88a63",
    "3d5b817c73b37e9a1d24ca923351359b42ced2f3cafbcac8c2d6322dc767bb"
  ],
  [
    "32e60904e73f9756f71e0a918d302aeca17cad4acacc81bab15702ab5ff78f0",
    "bcf4c0204f8275072f98a65b09ac58b87cdc9c70c4edfe99fe18870a3a5459"
  ],
  [
    "49c35575996c1517d2daed90d2fe4a58e674d6b4aaa7288d0642c8bf59e562f",
    "57eeee00adea4ca80eeabab57852cbf03f1a57e21872cd44221e0550b9193b8"
  ],
  [
    "10e1776b4c2a867bf1b028c6edec224cc6616c747e272f49e69b67b02a893dd",
    "8d45d62ec8e627b56950f2f7622a0438647f9e9f28e723e4a37cebc039a1b0"
  ],
  [
    "79a93a75ecbe943acc964fd39ecfc971dc6555b2bc335e7b53f52f4eb16cd36",
    "146132a68ce2ca8b48363612226771ac547eb3cf52b6eb7981718faac08aa3c"
  ],
  [
    "6b22d32e0590e169504e7f19864fd646d0994e7ed3e578a5b88f6e095913439",
    "68c3b22d859fb85e5c8fa0a8aea932285945b230957e603394333e9ad5acd82"
  ],
  [
    "71ce5ec8286eb8c93b8481c6d19cf0a288ef4da4397e9c80f65023e516bc097",
    "54470babc742780cd8a05499026e738ccbf81d4170d1731734de68a8e5b402c"
  ],
  [
    "27beb13a43bc6a1f6ce046da438b0beac5899ff4d57962dcfb6476b563f74b",
    "14074e9e93ee45394dfbe833998b9d1691961f8ba3166224b36404448c61bb3"
  ],
  [
    "6b1de6c8f161aa6509a1dcacf2c0aa1bcf6ee9d9b40e032a9d72f77a6fa298c",
    "5e9312eb5b59d6cbadd7d3dcbc39f1b5bd9a8346fdcfdf1107bada6f9cc048"
  ],
  [
    "32670fc3fa43bf39974ba72ea51f0d045d92d084a81fe5282dfc8309aa900b9",
    "518fee521bf1af62356aac3b7e53fdbf57121e030c6e9572b3de69912ca4eb4"
  ],
  [
    "4b9ca363eabed9c66091a347375f7065cd28f49f914447de7cc1461f1375f1e",
    "3a1a3a2e5e7e72476befe2571ece708052d740d02cbe6fed58740968ae609c4"
  ],
  [
    "4cc6da42863a3deca62fa218b7a3b50e034eb4bafd393eccba3f4cbe192ef10",
    "20bfa683c884f203713953b26d2821287ecd305fa2cb70570474533fc07f918"
  ],
  [
    "87705353c44a5ccec8de65cf5433be6b3d9bd21eea49b60e6c907cf1a67a6a",
    "112804b13eee56e3b01aff75fa08fa8374c44fc461aed8a30ad54acd09c24eb"
  ],
  [
    "6cf6eeeb9d339c0a05f72fd5af73fc7588e6d957100ee8999109437bc126cae",
    "54fa257cea22032eac272fcd034dadf2e00d602ef9e519cf7072023c130aad1"
  ],
  [
    "19b32925048c5519d929650c833661b452ef7be7963fab0b6b328ab7dd7a28a",
    "1bd0c14a10bf9b88ea61011c0b2e64d07da151c6203800d5a5d12063838a510"
  ],
  [
    "12a5fc5559428bc3b4eff97b21b63668b866e0722807f1db1f19696bacd9b0d",
    "4c2eb07f0c24047a3d73b560144f3fd32c99d6dbd9fc7cd2fd2a72a6e4b24c7"
  ],
  [
    "13662b7a7d390aa76eb86a7c3bff6d9913eb28db6bd1a7c42de5cdad2e35ce2",
    "40626aded7f56f82cc431ae30527b096f57fbfbc04d3e12a5abae3edf301cf1"
  ],
  [
    "255825bd49b8a2cce114360bd9c8fe8c641af64c8e7710107213cfcb006f43d",
    "3619cce4482335232f9e76a1460be9d296f2d468d26e4f95a78c71524fe59cc"
  ],
  [
    "7f83009eeed4f12f54d341bbf06066480cfcdf51dda103ac54d4bcecf6b3b31",
    "4269519d28faafd7fd68bebfd8404d71ba05d62c4bb6d65d24aa6802fb84ab6"
  ],
  [
    "2f325650eb316646b4eec903fe44828fcb11054f1bd42ca3a77f7e734110b35",
    "44f976082271016f9048e22c507d97d628722bb431f8d5cc1890524e6c386bf"
  ],
  [
    "750b166bb6edc0ee80fae39c7c106879036738df2d79fb2294e1c21e9a24d6b",
    "54f8aa297a1afafe2a17a3254f45861167414327e918d17003c6aad01d0b24c"
  ],
  [
    "3aedb10db9cf3285cdeee375879396fac1fb50dd259e1716f8c01e66f67ca72",
    "7feb9400f621f58c21601f23b7ec7c94a9b6b193c1cd74a8a60846aedadd359"
  ],
  [
    "4ab7151702de76faa493e7a0b1ac20ee4d10c33b83fec9477547cb1236973eb",
    "63f1f122e3ef3acc46b0915ac69c3f5772879799cad889a817f55f5853d1235"
  ],
  [
    "1675ead0d20e5bc3a7a7331999a87ac4c916ae29669e54197bb02aa6364520f",
    "4d1122da90d49e491922d9b533a6a668e2f65a2737ebb391ebb29fb7c1f8a9d"
  ],
  [
    "2f7148111ef53c613157aeec12e16a20f13481da4390b6ce18a85d1d8547087",
    "2eeda779ab395597651d2a0b833ccf53b10280750139916ae2baf4ec57c633d"
  ],
  [
    "4439c7810e7b2ba772b701ec3acdca0b80c9df23047710b87f7dc3f13b337d3",
    "5029cfe704c602a8a4662af0a5860ec03fb88f046d0e3400f2ce7638014c621"
  ],
  [
    "2248eec40b5732a6a488b681f093643af7937071bc73118acae295a32b51b05",
    "1577e4aec30a97b648de4d0b19cf8891151b4eb11f8de9c6d7312f091552e19"
  ],
  [
    "4738424e558d4e0d87a3124ca02ea24f0adc6b7a9768b0d3945ed2a6104857c",
    "33576f92aca3f0c8ae689c3c274c2de6b918940d86a6852e02fc99e35d1614"
  ],
  [
    "7829edd8b866ebf7baaf604ed13d19a9797578f44bbc51b1cd67ca53803e96b",
    "5559040a6083f2af1f9133ccaf5bc2ce06e56ddfc7dd410e9635c0116b62722"
  ],
  [
    "7f927b881f2cdc05e1a69e40bb714af47b630d1425f08ab5d574ee698f33d51",
    "26a465288e96572de303203bd38f4a03031e8158da0591cb037c0a5111d1056"
  ],
  [
    "36a65598552f8753580d1655417d645a140966e10a1e1663015f9fdfae44881",
    "33d5bbfaebf59eae72b89b1aea12ab2ba3c9617f8c3baed1ec16bdf668381b5"
  ],
  [
    "403becfa545c826782026ff409cc16c9d4fe428f1b5b6e630c92439d2fa5fd",
    "47bd6f2bf5d74f710ecb479c79b01fb774fbdad590e683a415cdedf33f71dc5"
  ],
  [
    "3a747826d241b877d3d56b16e0b810cf088eda4fd6048da174c9991a942a5eb",
    "2c7ba19b0a3486a2cdb84d4a388d34beb077a0e467ba44590166f93f6a09d2e"
  ],
  [
    "3d60cd375842714b37bda89dd1f13a7e0f3ff133b522209617d031bce05a537",
    "f77f216451ab01ad5226844d2162a7f32744688bcb4325445539e2ce5cec4"
  ],
  [
    "235bf66f67c9100e7f0e22bb299cdfaa603644b240e0770aec7e7fd163e2a65",
    "37110b3fa83ece3990afca2bea8d5ebb3c7aace60a0147f8e6ab733e2f2b4d5"
  ],
  [
    "3b796d4eb69a55471fa86108f787b3604874e92b6887a7667a6c2bfbbd9a42b",
    "4912d6dc0419732ef82cb3278415851d4e2d7ca89e0f4d7128cc9de51b810fe"
  ],
  [
    "48d53516dd51e49faa7ab46c8c10db1befd10f23c6a9d9bc3640a2f0da44518",
    "73a2fb3d064adadf21aa1362c04affc660598f38a9e069b3afb74d0a99ae9ee"
  ],
  [
    "48c32cff161ed145da0d5b73084897647abb777adf65738559ceab6939cf3e0",
    "3d99308978e828f857c382df32b472bda81e8ec8e30c8844077ba6d6d2ba903"
  ],
  [
    "2947ff091a8ec9684affbc9a62e09e598841c4a6dc638088492aa47dea57097",
    "19a2cc97975e547f97a4d02e42f89e6ced6f5a953cfccdec347867d26926541"
  ],
  [
    "1960d85f30475615f82484eba0bdafb7ea7cac3809f0518a757d66f02b01676",
    "36c8f77baabf0cc8805d993bbe62041fcf4e3239cf9d53278a4fbd91e75eeb7"
  ],
  [
    "2765f28074d21d5a055340b6d40092d2bbef807e02009fabfa08ec0b9bdf38b",
    "7fb189e0553d5df52b6843661814824b3f3cbebbd54988f042fb256c6bf30b"
  ],
  [
    "348836cb2aaa00212f4b1a4e2d7fc5417f246bf2fe5c9a16ebabda449e2e08a",
    "3f7276fd7d69e0d55ce5ee1d2d830534a27227fe0b6d8a36c93f9a78b872969"
  ],
  [
    "7afb9d34b6a42ea8c6d870e4b8191c274201dc1f93a1a2219a2392b7e345a31",
    "42bbc20dc7115e0758b364a110227b16b64ec58fc535ce5ff1a9ad8b8a09fdd"
  ],
  [
    "2cae0c2afee1767fd4c66f52e1f176d217e92e89cc19eb36d5a6c1715f641a",
    "5335efe2d9bc3667d25ea88bf76438a4d6ab9ba5c512f9da7d0529b79b62d83"
  ],
  [
    "1cc5fde334707723c3a06f00c106db88664284a2df47bb6b144d9f960aea3e2",
    "dbbf610d100316938bcd8bcd078513512ecb50d4579690dbefaa419c05980d"
  ],
  [
    "54e90cb8f3a2998d2675c5780679e06c0556b1e618f8fdf07f9a4b2466fbf1e",
    "16248676b6f06ec5e34994bc3115f85c8147b54f34d8500928f2fdc051e2089"
  ],
  [
    "525c70a2ba0dbdd68d75640f47f13d0d415ea595f7030f533f4625c2a46523b",
    "58292c8675e5e1a438f49e0c05648d9a7aa997f2f1fd77d5de1944afe5d7eea"
  ],
  [
    "54726d78d099007393348787a03107ab492e59690a46c87fb02ec554f2353bd",
    "53b54b77184ba75a3391e0ebfa6d6974db028f3f8e34bbd5460759a5848dd76"
  ],
  [
    "4ac81a66903537769d3aac6c483ccc08535cb767b6b5e1ec8017a7393ab70ae",
    "2cb22b77a8a05d26f11a4dec80eff292633aa05553a889c5ab16b6ac6e2ab17"
  ],
  [
    "21d0175349e21114988a2930b9a607d43245783cb4a0c984ce27f4c4206708",
    "59f1f49342cc5496213d3329bf4ca7fb0044337449c579bf53147a1dac9e67c"
  ],
  [
    "167f821b381f4c8adcc39789475fb55ba639e5124fe75f26dd61be396dd5e66",
    "22002c87d4cafb47ac9d27286d5cf5ff7a6715d69814118269b0729be9e4b3a"
  ],
  [
    "31010666c6db83a9f9e4db4c48173afd405783ac53852a6e38a8ff925528843",
    "1f466dc9b5d9094107c741dbf380f9fd98d8549cd50f67169901516f8cce74c"
  ],
  [
    "1ad3875769a5053388a86edc85dd80fdffbbda6a456aea497ff81a0f1f6707b",
    "2de7cdec5e2bad56a71bd2f33a4ae4c874e1ad4210a6ac32b443cfa34e85b1b"
  ],
  [
    "c489650fb7f459ce09cd05a456fc5a46b849b38a671298ed645bcdaab168b0",
    "45610d092b8af1c43ceed474cd17f7bbee65120aa6fa4d37f949e7e41f25327"
  ],
  [
    "394256a5ef4d7af5459587a0bd2edb8acaf5ecfef2563c9a04daf34a4abe4c6",
    "1ebee390dae1403c0c53994e1d064fa64e20fcb45392e209b2b99486a559ffd"
  ],
  [
    "410a1511fead6151e9bedb089b9832d0fe01fab76d3f8459929f767525aeb27",
    "361f0a5ffe09fcc3ad4eff3f5e89508ac247af80267100b69de3c59df561cfa"
  ],
  [
    "38cd437c9f659e110a869605c182ee9fdc26de36baf559d9229e258267bb734",
    "624b1128ea7739bf1cbd0e423af92a4884323c868d2ba0ee9d362946edee2d1"
  ],
  [
    "78b126e50b7042d2a019f95cb87a3213c664ca1bafe345999b1e9e2dac1e608",
    "19e398196b22f4488cbe854c614ad8c353839abc5ab3a4f3f5c03c16ba8a198"
  ],
  [
    "6d3a5ce91132f385a91823c5c8046c4b638f5fe63357424410d901457cdb867",
    "7b80bae16d2d487e122495174f7a70992bc5dafbed72bf84127ead7c57302bb"
  ],
  [
    "32d053a904dc4d88fbe7d0b96e0cbeca22a00aa5c79c753d52b0b60abf31602",
    "3af6a02e5cae6d6490354ae51185149e3fdb6d0d9caab90e95ff58aa0c40377"
  ],
  [
    "49b1fbff5bdb0aa6938b066dde0ed772c0d81f9eff52e7fe038b0ccbd78adb5",
    "1c6e57834eb14d507eed8b36c81ddf92fa91c242467061927a742fafa82b43d"
  ],
  [
    "2f28b8994ca6f234d9293d26196b43b9d1d5306844348c4a638102c05de85f5",
    "759cfb172eab065d477248b3569f4ff5791055f01e95fe71b94b8e615d73c96"
  ],
  [
    "3c2ee954ff534f856f59188fa0f29ed8a022aee0cac52d634f6dc58cd514d70",
    "22bd162e74925f0a876bd8a206b8767dfdd7c898576a73a490f138d9a7f99c6"
  ],
  [
    "5763a7cab001e1aaeabf9ab5b9b2fffe6cc2b299ab04ec4933da74d960e1ab",
    "715ee4f8ee93ab5a1dba00f0a6abc4eec47d49b61254cc27fc36a031e32f0f8"
  ],
  [
    "19976ad8d7b7f47c785408243a227401996b36e47c7a78a7bc7d4256233ba9a",
    "896b713c5d7777b0703821a73c1d9a4c3755501042120534ff13990975e1f5"
  ],
  [
    "61674b992c29827186cab5ff454758dbbed8e89bc23d0bd33193afccc3a04bc",
    "38e1020744c13903809ea30a0662fdb5226ae760cdcf10800faabec452e00f8"
  ],
  [
    "2ea2d48bcb83c0c9cda4efe11f07165cfcbc9ccd26526e5fb12556316d4b1df",
    "1d2d68b74ad384c5c4a9c85453104216357bfcdf635680b40215f0f800974cb"
  ],
  [
    "7881212050264c40c336ed3a15dd2cd868ec9a558f5b728869eab66e8b8ed54",
    "21aaefcc8ad8a161b8971d6880321781dbd939570c540da4c330922b8c81e9b"
  ],
  [
    "b6be88ce0461d20f59c5199573cda0170b61decf6e8e69a6d32f1695adc4ed",
    "5536e4808370716f2bb3423a9a49a38ddbfe91faf3b7a35eb53d3519238b6cf"
  ],
  [
    "e5972af1655eb6dde2e8c77cc58044299922441b5ee41ceaf5cafedc765bcc",
    "550282f37a4783dd60801c237045992d6fbe82a5902e7d837ea25f6f98c7b3a"
  ],
  [
    "7efc1aad1f580d8f50274f1c114c40056be19a8c96fa8c4cb5bf85e1e7f3e4",
    "2689f1c3898b114d668be6413643ee9f879913d40c262541fd0316264c60a4f"
  ],
  [
    "7939db98037f59b0113e9d60051f75ac9c3cfd1a3eb535c73e2d945068c6c5c",
    "410914ca8bbf3c65cdf3e9772ca790c19131c50068d34b7346c10260a578a8e"
  ],
  [
    "225b77ad00a2b83d26690190b74867326eca4f55bfbc3a13be036225ca3b1b5",
    "411faafef89042ce6beb64309fdaff70fa53e9d32d79a21e7f82f80e79ff05e"
  ],
  [
    "1501e64c99c8b6658b0479f2c05c9142d246eaabfccf2fcec8dc4399539d8e1",
    "3bab1e3339e42c9ee66c65b0b20236fdd9362d3ce786ad3a9779ab578af50a8"
  ],
  [
    "59b907b941f24fb8ea2458153e55f07534b388e835af7b69f3c9f54392a335",
    "1d5438c4f2f68a417f3d56f916d899a6ffe910f5f2989ca31687f1b10f60db8"
  ],
  [
    "2887d08a26f484546f360e33abbf7a998b7170a5b30070938b84f072c676bf3",
    "62a78e8d00e5d3a59e2fc424ffa08961567ba1ef24c8531cd7bceee6074a535"
  ],
  [
    "6e3cc8076b3d45377929033af35aab0c6d19ae4fd47c0daf844079ca04c46eb",
    "7b90f338e4d848aa8f19d0b5c3bca916a2a9024acbf14bddb278bca2aa39e5f"
  ],
  [
    "34844dacdd3ec54a3af328bb9d67715ab33425e194ac9977ca02ef22e8f7a88",
    "3c1affc6372f32a1634748124f9e1a03c4f0c993971da0dc28888b0801279d"
  ],
  [
    "436b192e03a49796cf9bc5e93c88268b71c9c24f9c3a85322bba634ebea309d",
    "67a8091ef69d62abcb28ce5df4dc7d53f8dc2b9690344f75ecd03a6d9386044"
  ],
  [
    "592d25b68baff87a6d7fd41ff0dadbddc1bd1316683de3b2d677501c0eb14e4",
    "27ad1e1099683f54589010faeefb19e38569ace43653be8787a42b0591e7bc5"
  ],
  [
    "89a5111ae911512ba62e87b97f643c0219702f235c70f62c6678a129302009",
    "557fa3d98e9ce7b83b47545013a4498f3de43787fb66b1a54521222242f7c1b"
  ],
  [
    "1c9b5e53377e72da5066cb08566bbf9ec31ec1877f455d932cd9b1aa375d34e",
    "72f79555a8bc207863f32d482fca54692825449fd8963fcea3de3a8183a739a"
  ],
  [
    "574a6e05eb14591729515be239ea8c1fa9e12d4049d42876f76c8ff37bca03",
    "5f99b3af43ca68c1c73e8190d5f73c8de162ba643d7d5f0cd73cfa8135db6d3"
  ],
  [
    "513fc5c2e16505b2b25a2f284e167d5401194bcac0dc3ecf8b7c9acb560daa1",
    "687ee7a1a8954d08d3856e1a16ded808e419e789736d3f55f79f7693bad69f5"
  ],
  [
    "53d48bd1205274b1c2b0a0ceb3d21c5fcd7c8892a784931603240b288a598b9",
    "35387abd7ea59c9b956de44d36533cad1f6668c438d666651695ff3862159be"
  ],
  [
    "213eb1ea99e08825110dd61094eb6e8145119dc1c507636f068730b1e086d44",
    "744f6853f4f02f4f042468d0739e0c9f64df720b87ed77d1979547084ef7a89"
  ],
  [
    "735ef017d091ca23264ad0aa7bb9b2be3309b4539605e79ed4a652ccb2fbe3c",
    "7f0ccc7a5747c4e921fff97d431169f690763427e2cfd1ad74d7a0308d7faa9"
  ],
  [
    "3f36babc5a30070b610ed97db44997e6d9115c9c0579ad8f75d295a17130001",
    "79047908a2474e32d5c712a07bf5c4ad522590bb5d6cefda410d30528e12ca8"
  ],
  [
    "51c04907ae88a5926b242fb2862cb1f2c651a94e6caad5bff8601c079fded74",
    "10a585a269f460aed43f54c7de13cdf623fc8de5957526997278be939ef32ad"
  ],
  [
    "c1e1bd626a735aa2c065831317217ecce68e377eb1f67e54ce2e97bc2ef2dc",
    "53c5af23a9b482f420be6dfd37b6886154cfd130794098e1f51c1885ac2556a"
  ],
  [
    "5aff3b30775ae4758e604a4a6262803a545f5ef4e7855fa245ac6a6431a9ece",
    "39a4799e5519047f29333bee9c86c99bfa8056d4aa381c396c4a44331fe795f"
  ],
  [
    "3d753e9723701a8e9d99b91bb93dee2eda7ffa5072fb2cd5c5fd99aebcdb299",
    "15798bf5c17d6d5880fed1553af32dd8d8baf2888c715a886575448a24c7975"
  ],
  [
    "6593e5078466b07a4222d2e544da826d2c583c9cc5f2eaea148b129b00d4aa0",
    "11b352b08a0a61d3cd67d1dc08069dec3bde907b3da0f56de5011b956bf8744"
  ],
  [
    "7a6eb353c5be9ff03fe4a06c01fb71aad2b38144179a291ebcbb2c2417cca65",
    "3de3ecb12f2fa699b46a9d399abf77ca17bebc3e491bfb2542dd0fba991e2bb"
  ],
  [
    "2c7ead583d6c32162091034a9eddfa775b4e84b8bdbea939edb2a80dcf64f6",
    "461790ce40d9c276d962b2a1e9a74d66e9d7335962e234e8a2fc6963d31722d"
  ],
  [
    "34285af023d9b4c2c2b88e8704bf2c05a9b553b00b2e70ff05f8c2970cb134f",
    "33fe678e7671760a83836107428dbade68c3593fbe568f3f8f1b2c568099c44"
  ],
  [
    "6222f720a24466263db6a11842f117fc4bb78da6705f140e48869db3e087441",
    "6eff5b9bf3aeedc962bc5a24b66e7bdad2153450ed53a058bf2c8dbf2907693"
  ],
  [
    "17c6ec5ea206eb97cbf53851e37ce391080e0d2bf1e5395610f79ab0503f7ce",
    "3adb71ca3523d88ceb1e365f12dfb24895453c14daf0046b2626cddadfdf5f7"
  ],
  [
    "70859f9771a713e54974ce11cdaf44b0dcc3e9befa0c0834908d877eeaafd27",
    "d18f794bf0cc0623b711e7450030424e52326c45ba9b03341883ae4828a5f8"
  ],
  [
    "2a820cfd0fd4ab0871e7b303cd545a3086caf8fa818c087a4017197da74efbf",
    "5f992683ff37f6c041b84bfc01503d333ac9763505cc8f69473da01812969d1"
  ],
  [
    "5b0526de2c07fe7cd73e3884f642d57a0ac5e13c68590ed03a14e530616e8c1",
    "eec69d0cbd92c9fca31ec967dba848bec368e792d6678797946a5e34fe3487"
  ],
  [
    "6cf6b3efee707210cb3a72f1e885c3d0953aefb43e5e148c740aa1641725c61",
    "911cb630b898e2c1a9115f9e45bafe3b819edfb1eab6e15612d14289939984"
  ],
  [
    "74e913de55f1e46143cb2ecfc580f8d3d3908f200281322b84e21c989cda293",
    "761d2736c9ac7670ba905bc2629c6c0dbe988820a4454ff415ba68710f7df92"
  ],
  [
    "44084305e0c911a40b7cbefe5f13cffe9a99375d1a584c4a2200958050af7a9",
    "249c83877371564708ea525b64b1e7e12785460d83364446531c9adcacba5f0"
  ],
  [
    "2bf71ad4d1bee1a67fb300477029f54bdb0e09f78bf2ac2e8afc7465a7adbcc",
    "6244dd6cad282539049be57487bfd9900bb0d5da805d02b535096368fcb4cd5"
  ],
  [
    "3a62d8f763b62def36e4089458046a49c5ecb91b861549530773e0548ff2bb",
    "6a10a03ba61e6ac657270465c09aa9526cf1ebe96bdecdf0e7000476a47b9eb"
  ],
  [
    "284eed3a17c51e0677d4fe897f056abe9def8af07a4630e6ca5723e2aa6677",
    "516a06ac1d5626ed03d2eee9de6f60f0311eca703a99b0fb31b9c66b01c27c7"
  ],
  [
    "2a2c63b16cccd685f731d06fe93ce2cffb358d34d03dda9a7368185c1eb0c32",
    "7180baca0ba81284809f92eca1654cd76b925a9242e5d5e0f18d0a55d13c6ec"
  ],
  [
    "5f9466017ec09769611389ea5370ad68dda936d3f5816c9e928ff9574abf9a7",
    "6619b5b145bb5f4f29deb7a4cd68ef4da3995312fa6537f0d01684da4267ece"
  ],
  [
    "74f229babe01b4962b3307589c1a13019134b1db6822698388bebb55d21c30f",
    "156ae857ab3279f754facba0db36398dffec8c31e5e160473198f2f891b7531"
  ],
  [
    "334b9fe3a5fd99bc966ddd1309698fd32afd1f235062f2c275b6616a185de45",
    "221a60053583cc0607f6f2e6966b62fc9dac00538bb7eb1148e007a92116d2"
  ],
  [
    "7ad710ba002a67c731efbaba2149d16fec5d2f7aa3d126fd9886172e9f4ea30",
    "3a10f8e902a7a13aec94d66415347e1314f9bac83a7db176096b809b25ffb86"
  ],
  [
    "4306dd0a184a3283c3097ff8f7434cec80912e9dc04b7df21ba73fda9f8e6d8",
    "6d42bd3d1a8dbddafd09e872e2aa3891ae79ec939dc1b382196bc21c4ab749"
  ],
  [
    "1c3f2124e1135c32a426d1d14e471edd9e0f2c7bd703ee123cbbd608e8c4be7",
    "3cc607a3c3f1ab68dd5fa56c65996002721b8ad8ad4b0dd9e5b1467d316583"
  ],
  [
    "294af33272ffcee0b56a436de1b73759cbddebef4c07888b42c2f92b0b68e1",
    "d837164311d5dca8d37b99ef9eb22708643c83d1cbdfe852f63ea07b06fbad"
  ],
  [
    "753bdb5439a19bbffdfa02b1dc24e8368f22d0a8276b109c11e6feb26f56f39",
    "6ed396231af93647633eab467f1a034f38e76823eb85baf97cae56e2dcd9f75"
  ],
  [
    "5674f0cb892b733fc0b50e121d8679afed0a925c32594cc65ffe83bebe7748e",
    "7fbf0325dd38dd94905adab2c52758552292a6a103d9edfcb11938828e828c8"
  ],
  [
    "4a8f053573a0a74251059d0229d89b6660407ba0b491779fd10f87a5117c81f",
    "21b70112485398bf67ec9d733df24a1df30dea718a93b786f41ed04e3ae3c5e"
  ],
  [
    "726c01ec4a08df8fc8de173311f50d4f3b97c5a9cf68c1536146f827db95ae8",
    "15013cafadefa7f1c4e4dfdd70bd4d3979dd18bd7f0332572ce2a3fd8773d12"
  ],
  [
    "38ac0fbfa98937257460db7e6645d7e5112b6fce7234813fc8a704e8ade8da2",
    "73c0109f86048aad08c443f781ae60ad13b99f7b9cfdf3128fe6d6eeb799a7b"
  ],
  [
    "6f6d3a38621582ace092eb50ecfe9eff265df141ebdcab8653299116fcea291",
    "4a1bf3f39bc919c8f1b720a0b1ce952cad17f2ba98308ee6b76dd9b6f3d7b75"
  ],
  [
    "6a307fc28e1df8d9ad01766419e097797d65cb674436fa1c8f012d3de2c2a1f",
    "26911a635ba824db004875d79dd84834a97ac12643e42829015bf88c1fd6f05"
  ],
  [
    "2a74860e3336d6db916555894cc8028f41508812925db1925457afe40257155",
    "5f8da573f4c39816ce2dba8a20224223a7cfec53117ec78973930c0e9b60244"
  ],
  [
    "4d2b49e1ed0799f719b8269f092cb489a466a645bc0ccabafdc678864c176d7",
    "5410083df7d256f18cbf5697ae5e52c31e075d8a3b27e21d6f5177ca882f6c1"
  ],
  [
    "110ecb9fbf6c333d168cee473cc5ad98809b6cb9eb5d1f6cd28ab5fab504fd3",
    "7e3c54d7533d9f8c3310f219dab0cc3ea4d39b418a748eeffd6bae2b8637a43"
  ],
  [
    "5be4d711b80da70e6d3ac493250bbfd16f20b25f31919b3a91cf14ffbac1096",
    "7f55a0919f082e8885f1515e83c5b39b6022404503507498e1b4422d79c43e2"
  ],
  [
    "2605125b95ca4ba93a21cbbba5762898a7cf9e988f07ab9e64cb3868e3b139d",
    "62f0ccf55b9fc0eaf9736fc8ee484e2acdbe259813af9803cf815829a5e9d3b"
  ],
  [
    "1092bbbf206f2a3068167c3dd99a72de31e206f6c504c071c8214d105ff814d",
    "309f489f68a62089f53b96df5d4fbc3ecc5a1a42eb7ece0e49bad17ad490ff4"
  ],
  [
    "2abdee9409d9c92559ca3f4e6bddd649c31aa09b90bfcb4a612af491241e18d",
    "3ffa8eac180a29de3f8a69efca84bac046f921f5725e96a6ff0530be1436aaf"
  ],
  [
    "376313f27d00bb1aae7ec991745efe6ee28c6b50de0c6cd9845cc4bb4f83543",
    "6a8e0a9389ba528b156fa94ac090a895d7b795818d4941c29415d9e2984c547"
  ],
  [
    "a80380c71bd466a696b3f0fbf02817c9459d9798f4f3899cf32edf647fe066",
    "6a09805e814e7cdfc76eba4b79f1df5ae559e0f0aba9f728d3cba4ea5c57471"
  ],
  [
    "223694b921d247d989a79b9b2b2f07496036c40cb043eab074a9d6a2cd2ffed",
    "c247217f1b1df35e30d9e15fdaadf42d6fb0edd3a5a7e265d4cdc426c120aa"
  ],
  [
    "102333620df278c6714bbc880fc087db58c1b9b4d77ed4d61b32a74bfc7c3e2",
    "6a77d37727ccf71c2caeb151faf4404d4b94e9047f9f0a7c3966367f3b53c65"
  ],
  [
    "891626f466536929ee7eadcd18b41925706dedab7528ed5f0f7abf039eb9d2",
    "5f73d11c141c933a35b2d0d06e5cbae614a20d17dc3b439f8bcdc3413c5ea37"
  ],
  [
    "215c23fd3f073f870e5e80303967391bf173f8adcdbeec72d131c557babc203",
    "10634332e9d9439a321597dc5b0fac9ff478834c3d6e281735f21a4a5e13266"
  ],
  [
    "21ea0bdc1332bc36e6aeb43be9071651c27e4ea2eadec636c8d818d4af72a36",
    "3a523d9643dccc6bb9c7c58413312caa3e60ba9c7c7f0177e0f3f469a3241e3"
  ],
  [
    "60deaed1bffb6190beed40caaf2bfab5e43d3707aff7ad3f278d571aa247eae",
    "e41f71ff254c1418e6a66992af307789fe04d6606fb2670900bb1a089fd879"
  ],
  [
    "1e1fac4a1646253fb1332fadc21fbdd3e3a24a840d129400f520ae4116a4cf5",
    "69c406f9f46576afad68808de0ab7e8922b6226af748e721d9097e21f1800f3"
  ],
  [
    "5db0ddcdf79ffe74d6454c12d2bc60b06776db03c75dc413f5be42ea9a91b5e",
    "134c3d6c699841f17306835bb193785228ffe7ab212a01a861c56b086a18cec"
  ],
  [
    "626814e320fb5bea505b248fd1c1389ad586c1cfe04923fe2f83173e915f4f8",
    "7ae407a926e887206a8b85cf485f1f327c9bb8ccbb6897024e2d122877d8ee0"
  ],
  [
    "23186237dc7d3b570cea645282ad4c359731bbfa54e7f036426bf6493812cd",
    "7d1fbab7e61a22d3b00993290d9f4cd5d820061573e787f66c2cff9a18e1eaf"
  ],
  [
    "54302dcb0e6cc1c6e44cca8f61a63bb2ca65048d53fb325d36ff12c49a58202",
    "1b77b3e37d13504b348046268d8ae25ce98ad783c25561a879dcc77e99c2426"
  ],
  [
    "13961b56b9fc0e412e468c385c22bd0680a25624ec211ffbb6bc877b2a6926c",
    "62f7f7792c77cd981fad13cb6863fe099c4d971c1374109185eae99943f16e9"
  ],
  [
    "47abd7308c70659af3f00fafe6837298af3cb530b6c2ba710ffd07a6bc1ae98",
    "75d0c8a7377aa9f0663d0c124a5659750847afabc29e39893fd27534a4a03cb"
  ],
  [
    "2c6276b764fb398fa555857dbe0ce0ec18fab7a233bf23851295739801f0585",
    "5d8f4897ce44007ec5bfcb9aeb78b8f6e1d40a514f72d213c9300d2770d2b8c"
  ]
], Oi = {};
Q(Oi, {
  EntryPointType: () => Jc,
  RPC: () => Ae,
  SIMULATION_FLAG: () => Xc,
  TransactionStatus: () => Qc,
  TransactionType: () => er
});
var Xc = /* @__PURE__ */ ((e) => (e[e.SKIP_VALIDATE = 0] = "SKIP_VALIDATE", e[e.SKIP_EXECUTE = 1] = "SKIP_EXECUTE", e))(Xc || {}), Jc = /* @__PURE__ */ ((e) => (e.EXTERNAL = "EXTERNAL", e.L1_HANDLER = "L1_HANDLER", e.CONSTRUCTOR = "CONSTRUCTOR", e))(Jc || {}), Qc = /* @__PURE__ */ ((e) => (e.NOT_RECEIVED = "NOT_RECEIVED", e.RECEIVED = "RECEIVED", e.PENDING = "PENDING", e.ACCEPTED_ON_L2 = "ACCEPTED_ON_L2", e.ACCEPTED_ON_L1 = "ACCEPTED_ON_L1", e.REJECTED = "REJECTED", e))(Qc || {}), er = /* @__PURE__ */ ((e) => (e.INVOKE = "INVOKE_FUNCTION", e.DECLARE = "DECLARE", e.DEPLOY = "DEPLOY", e.DEPLOY_ACCOUNT = "DEPLOY_ACCOUNT", e))(er || {}), Ae;
((e) => {
  ((a) => {
    a.DECLARE = "DECLARE", a.DEPLOY = "DEPLOY", a.DEPLOY_ACCOUNT = "DEPLOY_ACCOUNT", a.INVOKE = "INVOKE", a.L1_HANDLER = "L1_HANDLER";
  })(e.TransactionType || (e.TransactionType = {}));
})(Ae || (Ae = {}));
function V(e, a) {
  if (!e)
    throw new Error(a || "Assertion failure");
}
var tr = {};
Q(tr, {
  assertInRange: () => Di,
  bigNumberishArrayToDecimalStringArray: () => Li,
  bigNumberishArrayToHexadecimalStringArray: () => $i,
  cleanHex: () => mc,
  getDecimalString: () => Pi,
  getHexString: () => nr,
  getHexStringArray: () => Hi,
  hexToBytes: () => Ui,
  hexToDecimalString: () => Ri,
  isBigInt: () => vn,
  isHex: () => Oe,
  isStringWholeNumber: () => Qt,
  toBigInt: () => B,
  toCairoBool: () => Ec,
  toHex: () => I,
  toHexString: () => ar,
  toStorageKey: () => Bi
});
function Oe(e) {
  return /^0x[0-9a-f]*$/i.test(e);
}
function B(e) {
  return BigInt(e);
}
function vn(e) {
  return typeof e == "bigint";
}
function I(e) {
  return ee(B(e).toString(16));
}
function Bi(e) {
  return ee(B(e).toString(16).padStart(64, "0"));
}
function Ri(e) {
  return BigInt(ee(e)).toString(10);
}
var mc = (e) => e.toLowerCase().replace(/^(0x)0+/, "$1");
function Di(e, a, t, n = "") {
  const c = n === "" ? "invalid length" : `invalid ${n} length`, r = BigInt(e), f = BigInt(a), d = BigInt(t);
  V(
    r >= f && r <= d,
    `Message not signable, ${c}.`
  );
}
function Li(e) {
  return e.map((a) => B(a).toString(10));
}
function $i(e) {
  return e.map((a) => I(a));
}
var Qt = (e) => /^\d+$/.test(e), ar = (e) => I(e);
function Pi(e) {
  if (Oe(e))
    return Ri(e);
  if (Qt(e))
    return e;
  throw new Error(`${e} need to be hex-string or whole-number-string`);
}
function nr(e) {
  if (Oe(e))
    return e;
  if (Qt(e))
    return ar(e);
  throw new Error(`${e} need to be hex-string or whole-number-string`);
}
function Hi(e) {
  return e.map((a) => nr(a));
}
var Ec = (e) => (+e).toString();
function Ui(e) {
  if (!Oe(e))
    throw new Error(`${e} need to be a hex-string`);
  let a = Ue(e);
  return a.length % 2 !== 0 && (a = `0${a}`), He(a);
}
var Fi = {};
Q(Fi, {
  getSelector: () => fr,
  getSelectorFromName: () => Ee,
  keccakBn: () => cr,
  starknetKeccak: () => rr
});
function cr(e) {
  const a = Ue(I(BigInt(e))), t = a.length % 2 === 0 ? a : `0${a}`;
  return ee(Aa(Ui(ee(t))).toString(16));
}
function I6(e) {
  return ee(Aa(En(e)).toString(16));
}
function rr(e) {
  return BigInt(I6(e)) & Ai;
}
function Ee(e) {
  return I(rr(e));
}
function fr(e) {
  return Oe(e) ? e : Qt(e) ? ar(e) : Ee(e);
}
var zi = {};
Q(zi, {
  decodeShortString: () => or,
  encodeShortString: () => at,
  isASCII: () => dr,
  isDecimalString: () => Zi,
  isLongText: () => ir,
  isShortString: () => Oa,
  isShortText: () => N6,
  isText: () => Ba,
  splitLongString: () => sr
});
var Mi = 31;
function dr(e) {
  return /^[\x00-\x7F]*$/.test(e);
}
function Oa(e) {
  return e.length <= Mi;
}
function Zi(e) {
  return /^[0-9]*$/i.test(e);
}
function Ba(e) {
  return typeof e == "string" && !Oe(e) && !Qt(e);
}
var N6 = (e) => Ba(e) && Oa(e), ir = (e) => Ba(e) && !Oa(e);
function sr(e) {
  const a = RegExp(`[^]{1,${Mi}}`, "g");
  return e.match(a) || [];
}
function at(e) {
  if (!dr(e))
    throw new Error(`${e} is not an ASCII string`);
  if (!Oa(e))
    throw new Error(`${e} is too long`);
  return ee(e.replace(/./g, (a) => a.charCodeAt(0).toString(16)));
}
function or(e) {
  if (!dr(e))
    throw new Error(`${e} is not an ASCII string`);
  if (Oe(e))
    return Ue(e).replace(/.{2}/g, (a) => String.fromCharCode(parseInt(a, 16)));
  if (Zi(e))
    return or("0X".concat(BigInt(e).toString(16)));
  throw new Error(`${e} is not Hex or decimal`);
}
var br = {};
Q(br, {
  Uint: () => pr,
  felt: () => _e,
  getArrayType: () => Ra,
  isCairo1Abi: () => B6,
  isCairo1Type: () => et,
  isLen: () => yt,
  isTypeArray: () => Pe,
  isTypeBool: () => xn,
  isTypeContractAddress: () => Ki,
  isTypeFelt: () => rn,
  isTypeNamedTuple: () => qi,
  isTypeStruct: () => jt,
  isTypeTuple: () => Ie,
  isTypeUint: () => _r,
  isTypeUint256: () => wt,
  tuple: () => R6,
  uint256: () => gr
});
var Vi = {};
Q(Vi, {
  UINT_128_MAX: () => ur,
  UINT_256_MAX: () => ji,
  bnToUint256: () => O6,
  isUint256: () => hr,
  uint256ToBN: () => lr
});
function lr(e) {
  return (B(e.high) << 128n) + B(e.low);
}
var ur = (1n << 128n) - 1n, ji = (1n << 256n) - 1n;
function hr(e) {
  return B(e) <= ji;
}
function O6(e) {
  const a = B(e);
  if (!hr(a))
    throw new Error("Number is too large");
  return {
    low: ee((a & ur).toString(16)),
    high: ee((a >> 128n).toString(16))
  };
}
var pr = /* @__PURE__ */ ((e) => (e.u8 = "core::integer::u8", e.u16 = "core::integer::u16", e.u32 = "core::integer::u32", e.u64 = "core::integer::u64", e.u128 = "core::integer::u128", e.u256 = "core::integer::u256", e))(pr || {}), yt = (e) => /_len$/.test(e), rn = (e) => e === "felt" || e === "core::felt252", Pe = (e) => /\*/.test(e) || e.startsWith("core::array::Array::"), Ie = (e) => /^\(.*\)$/i.test(e), qi = (e) => /\(.*\)/i.test(e) && e.includes(":"), jt = (e, a) => e in a, _r = (e) => Object.values(pr).includes(e), wt = (e) => e === "core::integer::u256", xn = (e) => e === "core::bool", Ki = (e) => e === "core::starknet::contract_address::ContractAddress", et = (e) => e.includes("core::"), Ra = (e) => et(e) ? e.substring(e.indexOf("<") + 1, e.lastIndexOf(">")) : e.replace("*", "");
function B6(e) {
  const a = e.find((t) => t.type === "function");
  if (!a)
    throw new Error("Error in ABI. No function in ABI.");
  if (a.inputs.length)
    return et(a.inputs[0].type);
  if (a.outputs.length)
    return et(a.outputs[0].type);
  throw new Error(`Error in ABI. No input/output in function ${a.name}`);
}
var gr = (e) => {
  const a = BigInt(e);
  if (!hr(a))
    throw new Error("Number is too large");
  return {
    // eslint-disable-next-line no-bitwise
    low: (a & ur).toString(10),
    // eslint-disable-next-line no-bitwise
    high: (a >> 128n).toString(10)
  };
}, R6 = (...e) => ({ ...e });
function _e(e) {
  if (vn(e) || typeof e == "number" && Number.isInteger(e))
    return e.toString();
  if (Ba(e)) {
    if (!Oa(e))
      throw new Error(
        `${e} is a long string > 31 chars, felt can store short strings, split it to array of short strings`
      );
    const a = at(e);
    return BigInt(a).toString();
  }
  if (typeof e == "string" && Oe(e))
    return BigInt(e).toString();
  if (typeof e == "string" && Qt(e))
    return e;
  if (typeof e == "boolean")
    return `${+e}`;
  throw new Error(`${e} can't be computed by felt()`);
}
var Xn = {
  isBN: (e, a, t) => {
    if (!vn(e[t]))
      throw new Error(
        `Data and formatter mismatch on ${t}:${a[t]}, expected response data ${t}:${e[t]} to be BN instead it is ${typeof e[t]}`
      );
  },
  unknown: (e, a, t) => {
    throw new Error(`Unhandled formatter type on ${t}:${a[t]} for data ${t}:${e[t]}`);
  }
};
function Ga(e, a, t) {
  return Object.entries(e).reduce((n, [c, r]) => {
    const f = t ?? a[c];
    if (!(c in a) && !t)
      return n[c] = r, n;
    if (f === "string") {
      if (Array.isArray(e[c])) {
        const d = Ga(
          e[c],
          e[c].map((o) => f)
        );
        return n[c] = Object.values(d).join(""), n;
      }
      return Xn.isBN(e, a, c), n[c] = or(r), n;
    }
    if (f === "number")
      return Xn.isBN(e, a, c), n[c] = Number(r), n;
    if (typeof f == "function")
      return n[c] = f(r), n;
    if (Array.isArray(f)) {
      const d = Ga(e[c], f, f[0]);
      return n[c] = Object.values(d), n;
    }
    return typeof f == "object" ? (n[c] = Ga(e[c], f), n) : (Xn.unknown(e, a, c), n);
  }, {});
}
function D6(e) {
  const a = e.substring(0, e.indexOf(":")), t = e.substring(a.length + 1);
  return { name: a, type: t };
}
function Gi(e) {
  if (!e.includes("("))
    return { subTuple: [], result: e };
  const a = [];
  let t = "", n = 0;
  for (; n < e.length; ) {
    if (e[n] === "(") {
      let c = 1;
      const r = n;
      for (n++; c; )
        e[n] === ")" && c--, e[n] === "(" && c++, n++;
      a.push(e.substring(r, n)), t += " ", n--;
    } else
      t += e[n];
    n++;
  }
  return {
    subTuple: a,
    result: t
  };
}
function L6(e) {
  const a = e.replace(/\s/g, "").slice(1, -1), { subTuple: t, result: n } = Gi(a);
  let c = n.split(",").map((r) => t.length ? r.replace(" ", t.shift()) : r);
  return qi(e) && (c = c.reduce((r, f) => r.concat(D6(f)), [])), c;
}
function $6(e) {
  const a = e.replace(/\s/g, "").slice(1, -1), { subTuple: t, result: n } = Gi(a);
  return n.split(",").map((r) => t.length ? r.replace(" ", t.shift()) : r);
}
function yr(e) {
  return et(e) ? $6(e) : L6(e);
}
function Jn(e) {
  return Error(
    `Your object includes the property : ${e}, containing an Uint256 object without the 'low' and 'high' keys.`
  );
}
function P6(e, a, t) {
  const n = (f, d) => d.reduce((i, s) => {
    const b = (u) => Object.defineProperty(i, s.name, {
      enumerable: !0,
      value: u ?? f[s.name]
    });
    if (f[s.name] === "undefined" && (et(s.type) || !yt(s.name)))
      throw Error(`Your object needs a property with key : ${s.name} .`);
    switch (!0) {
      case jt(s.type, t):
        b(
          n(
            f[s.name],
            t[s.type].members
          )
        );
        break;
      case wt(s.type): {
        const u = f[s.name];
        if (typeof u != "object") {
          b();
          break;
        }
        if (!("low" in u && "high" in u))
          throw Jn(s.name);
        b({ low: u.low, high: u.high });
        break;
      }
      case Ie(s.type):
        b(r(f[s.name], s));
        break;
      case Pe(s.type):
        b(c(f[s.name], s));
        break;
      case (!et(s.type) && yt(s.name)):
        break;
      default:
        b();
    }
    return i;
  }, {});
  function c(f, d) {
    const o = Ra(d.type);
    if (typeof f == "string")
      return f;
    switch (!0) {
      case o in t:
        return f.map((i) => n(i, t[o].members));
      case o === "core::integer::u256":
        return f.map((i) => {
          if (typeof i != "object")
            return i;
          if (!("low" in i && "high" in i))
            throw Jn(d.name);
          return { low: i.low, high: i.high };
        });
      case Ie(o):
        return f.map((i) => r(i, { name: "0", type: o }));
      case Pe(o):
        return f.map((i) => c(i, { name: "0", type: o }));
      default:
        return f;
    }
  }
  function r(f, d) {
    return yr(d.type).reduce((s, b, u) => {
      const l = Object.keys(f), _ = (p) => Object.defineProperty(s, u.toString(), {
        enumerable: !0,
        value: p ?? f[l[u]]
      }), h = b != null && b.type ? b.type : b;
      switch (!0) {
        case jt(h, t):
          _(
            n(
              f[l[u]],
              t[h].members
            )
          );
          break;
        case wt(h): {
          const p = f[l[u]];
          if (typeof p != "object") {
            _();
            break;
          }
          if (!("low" in p && "high" in p))
            throw Jn(d.name);
          _({ low: p.low, high: p.high });
          break;
        }
        case Ie(h):
          _(
            r(f[l[u]], {
              name: "0",
              type: h
            })
          );
          break;
        case Pe(h):
          _(
            c(f[l[u]], {
              name: "0",
              type: h
            })
          );
          break;
        default:
          _();
      }
      return s;
    }, {});
  }
  return n(e, a);
}
function Yi(e, a) {
  switch (!0) {
    case wt(e):
      const t = gr(a);
      return [_e(t.low), _e(t.high)];
    default:
      return _e(a);
  }
}
function H6(e, a) {
  const t = yr(a), n = Object.values(e);
  if (n.length !== t.length)
    throw Error(
      `ParseTuple: provided and expected abi tuple size do not match.
      provided: ${n} 
      expected: ${t}`
    );
  return t.map((c, r) => ({
    element: n[r],
    type: c.type ?? c
  }));
}
function ba(e, a, t) {
  if (e === void 0)
    throw Error(`Missing parameter for type ${a}`);
  if (Array.isArray(e)) {
    const n = [];
    n.push(_e(e.length));
    const c = Ra(a);
    return e.reduce((r, f) => r.concat(ba(f, c, t)), n);
  }
  if (t[a] && t[a].members.length) {
    const { members: n } = t[a], c = e;
    return n.reduce((r, f) => r.concat(ba(c[f.name], f.type, t)), []);
  }
  if (Ie(a))
    return H6(e, a).reduce((c, r) => {
      const f = ba(r.element, r.type, t);
      return c.concat(f);
    }, []);
  if (wt(a)) {
    if (typeof e == "object") {
      const { low: c, high: r } = e;
      return [_e(c), _e(r)];
    }
    const n = gr(e);
    return [_e(n.low), _e(n.high)];
  }
  if (typeof e == "object")
    throw Error(`Parameter ${e} do not align with abi parameter ${a}`);
  return Yi(a, e);
}
function U6(e, a, t) {
  const { name: n, type: c } = a;
  let { value: r } = e.next();
  switch (!0) {
    case Pe(c):
      if (!Array.isArray(r) && !Ba(r))
        throw Error(`ABI expected parameter ${n} to be array or long string, got ${r}`);
      return typeof r == "string" && (r = sr(r)), ba(r, a.type, t);
    case (jt(c, t) || Ie(c) || wt(c)):
      return ba(r, c, t);
    default:
      return Yi(c, r);
  }
}
function Wi(e, a) {
  let t;
  switch (!0) {
    case xn(e):
      return t = a.next().value, !!BigInt(t);
    case wt(e):
      const n = a.next().value, c = a.next().value;
      return lr({ low: n, high: c });
    default:
      return t = a.next().value, BigInt(t);
  }
}
function Ht(e, a, t) {
  if (a.type in t && t[a.type])
    return t[a.type].members.reduce((n, c) => (n[c.name] = Ht(e, c, t), n), {});
  if (Ie(a.type))
    return yr(a.type).reduce((c, r, f) => {
      const d = r != null && r.name ? r.name : f, o = r != null && r.type ? r.type : r, i = { name: d, type: o };
      return c[d] = Ht(e, i, t), c;
    }, {});
  if (Pe(a.type)) {
    const n = [], c = { name: "", type: Ra(a.type) }, r = BigInt(e.next().value);
    for (; n.length < r; )
      n.push(Ht(e, c, t));
    return n;
  }
  return Wi(a.type, e);
}
function F6(e, a, t, n) {
  const { name: c, type: r } = a;
  let f;
  switch (!0) {
    case yt(c):
      return f = e.next().value, BigInt(f);
    case (r in t || Ie(r)):
      return Ht(e, a, t);
    case Pe(r):
      if (et(r))
        return Ht(e, a, t);
      const d = [];
      if (n && n[`${c}_len`]) {
        const o = n[`${c}_len`];
        for (; d.length < o; )
          d.push(
            Ht(
              e,
              { name: c, type: a.type.replace("*", "") },
              t
            )
          );
      }
      return d;
    default:
      return Wi(r, e);
  }
}
var Xi = (e, a) => {
  V(
    typeof e == "string" || typeof e == "number" || typeof e == "bigint",
    `Validate: arg ${a.name} should be a felt typed as (String, Number or BigInt)`
  );
}, Ji = (e, a) => {
  typeof e == "number" && V(
    e <= Number.MAX_SAFE_INTEGER,
    "Validation: Parameter is to large to be typed as Number use (BigInt or String)"
  ), V(
    typeof e == "string" || typeof e == "number" || typeof e == "bigint" || typeof e == "object" && "low" in e && "high" in e,
    `Validate: arg ${a.name} of cairo ZORG type ${a.type} should be type (String, Number or BigInt)`
  );
  const t = typeof e == "object" ? lr(e) : B(e);
  switch (a.type) {
    case "core::integer::u8":
      V(
        t >= 0n && t <= 255n,
        `Validate: arg ${a.name} cairo typed ${a.type} should be in range [0 - 255]`
      );
      break;
    case "core::integer::u16":
      V(
        t >= 0n && t <= 65535n,
        `Validate: arg ${a.name} cairo typed ${a.type} should be in range [0, 65535]`
      );
      break;
    case "core::integer::u32":
      V(
        t >= 0n && t <= 4294967295n,
        `Validate: arg ${a.name} cairo typed ${a.type} should be in range [0, 4294967295]`
      );
      break;
    case "core::integer::u64":
      V(
        t >= 0n && t <= 2n ** 64n - 1n,
        `Validate: arg ${a.name} cairo typed ${a.type} should be in range [0, 2^64-1]`
      );
      break;
    case "core::integer::u128":
      V(
        t >= 0n && t <= 2n ** 128n - 1n,
        `Validate: arg ${a.name} cairo typed ${a.type} should be in range [0, 2^128-1]`
      );
      break;
    case "core::integer::u256":
      V(
        t >= 0n && t <= 2n ** 256n - 1n,
        `Validate: arg ${a.name} is ${a.type} 0 - 2^256-1`
      );
      break;
  }
}, Qi = (e, a) => {
  V(
    typeof e == "boolean",
    `Validate: arg ${a.name} of cairo type ${a.type} should be type (Boolean)`
  );
}, es = (e, a, t) => {
  V(
    typeof e == "object" && !Array.isArray(e),
    `Validate: arg ${a.name} is cairo type struct (${a.type}), and should be defined as js object (not array)`
  ), t[a.type].members.forEach(({ name: n }) => {
    V(
      Object.keys(e).includes(n),
      `Validate: arg ${a.name} should have a property ${n}`
    );
  });
}, ts = (e, a) => {
  V(
    typeof e == "object" && !Array.isArray(e),
    `Validate: arg ${a.name} should be a tuple (defined as object)`
  );
}, as = (e, a, t) => {
  const n = Ra(a.type);
  if (!(rn(n) && ir(e)))
    switch (V(Array.isArray(e), `Validate: arg ${a.name} should be an Array`), !0) {
      case rn(n):
        e.forEach((c) => Xi(c, a));
        break;
      case Ie(n):
        e.forEach((c) => ts(c, { name: a.name, type: n }));
        break;
      case jt(n, t):
        e.forEach(
          (c) => es(c, { name: a.name, type: n }, t)
        );
        break;
      case _r(n):
        e.forEach((c) => Ji(c, a));
        break;
      case xn(n):
        e.forEach((c) => Qi(c, a));
        break;
      case Pe(n):
        e.forEach(
          (c) => as(c, { name: "", type: n }, t)
        );
        break;
      default:
        throw new Error(
          `Validate Unhandled: argument ${a.name}, type ${a.type}, value ${e}`
        );
    }
};
function Hf(e, a, t) {
  e.inputs.reduce((n, c) => {
    const r = a[n];
    switch (!0) {
      case yt(c.name):
        return n;
      case rn(c.type):
        Xi(r, c);
        break;
      case _r(c.type):
        Ji(r, c);
        break;
      case xn(c.type):
        Qi(r, c);
        break;
      case Ki(c.type):
        break;
      case jt(c.type, t):
        es(r, c, t);
        break;
      case Ie(c.type):
        ts(r, c);
        break;
      case Pe(c.type):
        as(r, c, t);
        break;
      default:
        throw new Error(
          `Validate Unhandled: argument ${c.name}, type ${c.type}, value ${r}`
        );
    }
    return n + 1;
  }, 0);
}
var $ = class {
  constructor(e) {
    this.abi = e, this.structs = $.getAbiStruct(e);
  }
  /**
   * Validate arguments passed to the method as corresponding to the ones in the abi
   * @param type string - type of the method
   * @param method string - name of the method
   * @param args ArgsOrCalldata - arguments that are passed to the method
   */
  validate(e, a, t = []) {
    if (e !== "DEPLOY") {
      const r = this.abi.filter((f) => {
        if (f.type !== "function")
          return !1;
        const d = f.stateMutability === "view" || f.state_mutability === "view";
        return e === "INVOKE" ? !d : d;
      }).map((f) => f.name);
      V(
        r.includes(a),
        `${e === "INVOKE" ? "invocable" : "viewable"} method not found in abi`
      );
    }
    const n = this.abi.find(
      (r) => e === "DEPLOY" ? r.name === a && r.type === a : r.name === a && r.type === "function"
    ), c = $.abiInputsLength(n.inputs);
    if (t.length !== c)
      throw Error(
        `Invalid number of arguments, expected ${c} arguments, but got ${t.length}`
      );
    Hf(n, t, this.structs);
  }
  /**
   * Compile contract callData with abi
   * Parse the calldata by using input fields from the abi for that method
   * @param method string - method name
   * @param args RawArgs - arguments passed to the method. Can be an array of arguments (in the order of abi definition), or an object constructed in conformity with abi (in this case, the parameter can be in a wrong order).
   * @return Calldata - parsed arguments in format that contract is expecting
   * @example
   * ```typescript
   * const calldata = myCallData.compile("constructor",["0x34a",[1,3n]]);
   * ```
   * ```typescript
   * const calldata2 = myCallData.compile("constructor",{list:[1,3n],balance:"0x34"}); // wrong order is valid
   * ```
   */
  compile(e, a) {
    const t = this.abi.find((r) => r.name === e);
    let n;
    if (Array.isArray(a))
      n = a;
    else {
      const r = P6(a, t.inputs, this.structs);
      n = Object.values(r), Hf(t, n, this.structs);
    }
    const c = n[Symbol.iterator]();
    return t.inputs.reduce(
      (r, f) => yt(f.name) ? r : r.concat(U6(c, f, this.structs)),
      []
    );
  }
  /**
   * Compile contract callData without abi
   * @param rawArgs RawArgs representing cairo method arguments or string array of compiled data
   * @returns Calldata
   */
  static compile(e) {
    const a = (n) => {
      const c = (r, f = "") => {
        const d = Array.isArray(r) ? [r.length.toString(), ...r] : r;
        return Object.entries(d).flatMap(([o, i]) => {
          let s = i;
          ir(s) && (s = sr(s)), o === "entrypoint" && (s = Ee(s));
          const b = Array.isArray(d) && o === "0" ? "$$len" : o;
          return vn(s) ? [[`${f}${b}`, _e(s)]] : Object(s) === s ? c(s, `${f}${b}.`) : [[`${f}${b}`, _e(s)]];
        });
      };
      return Object.fromEntries(c(n));
    };
    let t;
    if (Array.isArray(e)) {
      const n = { ...e }, c = a(n);
      t = Object.values(c);
    } else {
      const n = a(e);
      t = Object.values(n);
    }
    return Object.defineProperty(t, "__compiled__", {
      enumerable: !1,
      writable: !1,
      value: !0
    }), t;
  }
  /**
   * Parse elements of the response array and structuring them into response object
   * @param method string - method name
   * @param response string[] - response from the method
   * @return Result - parsed response corresponding to the abi
   */
  parse(e, a) {
    const { outputs: t } = this.abi.find((r) => r.name === e), n = a.flat()[Symbol.iterator](), c = t.flat().reduce((r, f, d) => {
      const o = f.name ?? d;
      return r[o] = F6(n, f, this.structs, r), r[o] && r[`${o}_len`] && delete r[`${o}_len`], r;
    }, {});
    return Object.keys(c).length === 1 && 0 in c ? c[0] : c;
  }
  /**
   * Format cairo method response data to native js values based on provided format schema
   * @param method string - cairo method name
   * @param response string[] - cairo method response
   * @param format object - formatter object schema
   * @returns Result - parsed and formatted response object
   */
  format(e, a, t) {
    const n = this.parse(e, a);
    return Ga(n, t);
  }
  /**
   * Helper to calculate inputs from abi
   * @param inputs AbiEntry
   * @returns number
   */
  static abiInputsLength(e) {
    return e.reduce((a, t) => yt(t.name) ? a : a + 1, 0);
  }
  /**
   * Helper to extract structs from abi
   * @param abi Abi
   * @returns AbiStructs - structs from abi
   */
  static getAbiStruct(e) {
    return e.filter((a) => a.type === "struct").reduce(
      (a, t) => ({
        ...a,
        [t.name]: t
      }),
      {}
    );
  }
  /**
   * Helper: Compile HexCalldata | RawCalldata | RawArgs
   * @param rawCalldata HexCalldata | RawCalldata | RawArgs
   * @returns Calldata
   */
  static toCalldata(e = []) {
    return $.compile(e);
  }
  /**
   * Helper: Convert raw to HexCalldata
   * @param raw HexCalldata | RawCalldata | RawArgs
   * @returns HexCalldata
   */
  static toHex(e = []) {
    return $.compile(e).map((t) => I(t));
  }
}, ns = {};
Q(ns, {
  calculateContractAddressFromHash: () => Ya,
  calculateDeclareTransactionHash: () => ds,
  calculateDeployAccountTransactionHash: () => is,
  calculateDeployTransactionHash: () => Z6,
  calculateTransactionHash: () => ss,
  calculateTransactionHashCommon: () => Da,
  computeCompiledClassHash: () => ls,
  computeContractClassHash: () => hs,
  computeHashOnElements: () => ne,
  computeLegacyContractClassHash: () => bs,
  computeSierraContractClassHash: () => us,
  default: () => os,
  feeTransactionVersion: () => Rt,
  feeTransactionVersion_2: () => fn,
  formatSpaces: () => Ea,
  getSelector: () => fr,
  getSelectorFromName: () => Ee,
  getVersionsByType: () => wr,
  keccakBn: () => cr,
  poseidon: () => Mo,
  starknetKeccak: () => rr,
  transactionVersion: () => $e,
  transactionVersion_2: () => mt
});
var cs = {};
Q(cs, {
  starkCurve: () => k0,
  weierstrass: () => Wo
});
var rs = {};
Q(rs, {
  parse: () => tt,
  parseAlwaysAsBig: () => fs,
  stringify: () => Fe,
  stringifyAlwaysAsBig: () => M6
});
var z6 = (e) => {
  if (!ka(e))
    return parseFloat(e);
  const a = parseInt(e, 10);
  return Number.isSafeInteger(a) ? a : BigInt(e);
}, tt = (e) => kd(String(e), null, z6), fs = (e) => kd(String(e), null, M0), Fe = (...e) => Td(...e), M6 = Fe, $e = 1n, mt = 2n, Rt = 2n ** 128n + $e, fn = 2n ** 128n + mt;
function wr(e) {
  return e === "fee" ? { v1: Rt, v2: fn } : { v1: $e, v2: mt };
}
function ne(e) {
  return [...e, e.length].reduce((a, t) => Kt(B(a), B(t)), 0).toString();
}
function Da(e, a, t, n, c, r, f, d = []) {
  const o = ne(c), i = [
    e,
    a,
    t,
    n,
    o,
    r,
    f,
    ...d
  ];
  return ne(i);
}
function Z6(e, a, t, n) {
  return Da(
    "0x6465706c6f79",
    t,
    e,
    Ee("constructor"),
    a,
    0,
    n
  );
}
function ds(e, a, t, n, c, r, f) {
  return Da(
    "0x6465636c617265",
    t,
    a,
    0,
    [e],
    n,
    c,
    [r, ...f ? [f] : []]
  );
}
function is(e, a, t, n, c, r, f, d) {
  const o = [a, n, ...t];
  return Da(
    "0x6465706c6f795f6163636f756e74",
    c,
    e,
    0,
    o,
    r,
    f,
    [d]
  );
}
function ss(e, a, t, n, c, r) {
  return Da(
    "0x696e766f6b65",
    a,
    e,
    0,
    t,
    n,
    c,
    [r]
  );
}
function Ya(e, a, t, n) {
  const c = $.compile(t), r = ne(c), f = _e("0x535441524b4e45545f434f4e54524143545f41444452455353");
  return ne([
    f,
    n,
    e,
    a,
    r
  ]);
}
function V6(e, a) {
  return e === "attributes" || e === "accessible_scopes" ? Array.isArray(a) && a.length === 0 ? void 0 : a : e === "debug_info" ? null : a === null ? void 0 : a;
}
function Ea(e) {
  let a = !1;
  const t = [];
  for (const n of e)
    n === '"' && !(t.length > 0 && t.slice(-1)[0] === "\\") && (a = !a), a ? t.push(n) : t.push(n === ":" ? ": " : n === "," ? ", " : n);
  return t.join("");
}
function os(e) {
  const { abi: a, program: t } = e, c = Ea(Fe({ abi: a, program: t }, V6));
  return ee(Aa(En(c)).toString(16));
}
function bs(e) {
  const a = typeof e == "string" ? tt(e) : e, t = I(ki), n = ne(
    a.entry_points_by_type.EXTERNAL.flatMap((i) => [i.selector, i.offset])
  ), c = ne(
    a.entry_points_by_type.L1_HANDLER.flatMap((i) => [i.selector, i.offset])
  ), r = ne(
    a.entry_points_by_type.CONSTRUCTOR.flatMap((i) => [i.selector, i.offset])
  ), f = ne(
    a.program.builtins.map((i) => at(i))
  ), d = os(a), o = ne(a.program.data);
  return ne([
    t,
    n,
    c,
    r,
    f,
    d,
    o
  ]);
}
function j6(e) {
  return Qe(
    e.flatMap((a) => BigInt(at(a)))
  );
}
function Qn(e) {
  const a = e.flatMap((t) => [BigInt(t.selector), BigInt(t.offset), j6(t.builtins)]);
  return Qe(a);
}
function ls(e) {
  const t = BigInt(at("COMPILED_CLASS_V1")), n = Qn(e.entry_points_by_type.EXTERNAL), c = Qn(e.entry_points_by_type.L1_HANDLER), r = Qn(e.entry_points_by_type.CONSTRUCTOR), f = Qe(e.bytecode.map((d) => BigInt(d)));
  return I(
    Qe([
      t,
      n,
      c,
      r,
      f
    ])
  );
}
function ec(e) {
  const a = e.flatMap((t) => [BigInt(t.selector), BigInt(t.function_idx)]);
  return Qe(a);
}
function q6(e) {
  const a = Ea(Fe(e.abi, null));
  return BigInt(ee(Aa(En(a)).toString(16)));
}
function us(e) {
  const t = BigInt(at("CONTRACT_CLASS_V0.1.0")), n = ec(e.entry_points_by_type.EXTERNAL), c = ec(e.entry_points_by_type.L1_HANDLER), r = ec(e.entry_points_by_type.CONSTRUCTOR), f = q6(e), d = Qe(e.sierra_program.map((o) => BigInt(o)));
  return I(
    Qe([
      t,
      n,
      c,
      r,
      f,
      d
    ])
  );
}
function hs(e) {
  const a = typeof e == "string" ? tt(e) : e;
  return "sierra_program" in a ? us(a) : bs(a);
}
var ps = {};
Q(ps, {
  compressProgram: () => mr,
  decompressProgram: () => dn,
  estimatedFeeToMaxFee: () => lt,
  formatSignature: () => An,
  makeAddress: () => K6,
  randomAddress: () => Er,
  signatureToDecimalArray: () => Nt,
  signatureToHexArray: () => Ot
});
function mr(e) {
  const a = typeof e == "string" ? e : Fe(e), t = t6(a);
  return wi(t);
}
function dn(e) {
  if (Array.isArray(e))
    return e;
  const a = Wc(a6(yi(e)));
  return tt(a);
}
function Er() {
  const e = Rc.randomPrivateKey();
  return Lc(e);
}
function K6(e) {
  return ee(e).toLowerCase();
}
function An(e) {
  if (!e)
    throw Error("formatSignature: provided signature is undefined");
  if (Array.isArray(e))
    return e.map((a) => I(a));
  try {
    const { r: a, s: t } = e;
    return [I(a), I(t)];
  } catch {
    throw new Error("Signature need to be weierstrass.SignatureType or an array for custom");
  }
}
function Nt(e) {
  return Li(An(e));
}
function Ot(e) {
  return $i(An(e));
}
function lt(e, a = 0.5) {
  const t = Math.round((1 + a) * 100);
  return B(e) * B(t) / 100n;
}
function ge(e) {
  return "sierra_program" in (typeof e == "string" ? tt(e) : e);
}
function Wa(e) {
  const a = { ...e };
  if (ge(e.contract) && (!e.compiledClassHash && e.casm && (a.compiledClassHash = ls(e.casm)), !a.compiledClassHash))
    throw new Error(
      "Extract compiledClassHash failed, provide (CairoAssembly).casm file or compiledClassHash"
    );
  if (a.classHash = e.classHash ?? hs(e.contract), !a.classHash)
    throw new Error("Extract classHash failed, provide (CompiledContract).json file or classHash");
  return a;
}
function G6(e) {
  if (ge(e))
    throw Error("ContractClassResponse need to be LegacyContractClass (cairo0 response class)");
  const a = e;
  return { ...a, program: dn(a.program) };
}
var _s = typeof window < "u" && window.fetch || // use buildin fetch in browser if available
typeof global < "u" && global.fetch || // use buildin fetch in node, react-native and service worker if available
_6, gs = {};
Q(gs, {
  createSierraContractClass: () => ys,
  parseContract: () => vr,
  wait: () => sn
});
function sn(e) {
  return new Promise((a) => {
    setTimeout(a, e);
  });
}
function ys(e) {
  const a = { ...e };
  return delete a.sierra_program_debug_info, a.abi = Ea(Fe(e.abi)), a.sierra_program = Ea(Fe(e.sierra_program)), a.sierra_program = mr(a.sierra_program), a;
}
function vr(e) {
  const a = typeof e == "string" ? tt(e) : e;
  return ge(e) ? ys(a) : {
    ...a,
    ..."program" in a && { program: mr(a.program) }
  };
}
var Y6 = class {
  parseGetBlockResponse(e) {
    return {
      timestamp: e.timestamp,
      block_hash: e.block_hash,
      block_number: e.block_number,
      new_root: e.new_root,
      parent_hash: e.parent_hash,
      status: e.status,
      transactions: e.transactions
    };
  }
  parseGetTransactionResponse(e) {
    return {
      calldata: e.calldata || [],
      contract_address: e.contract_address,
      sender_address: e.contract_address,
      max_fee: e.max_fee,
      nonce: e.nonce,
      signature: e.signature || [],
      transaction_hash: e.transaction_hash,
      version: e.version
    };
  }
  parseFeeEstimateResponse(e) {
    return {
      overall_fee: B(e[0].overall_fee),
      gas_consumed: B(e[0].gas_consumed),
      gas_price: B(e[0].gas_price)
    };
  }
  parseFeeEstimateBulkResponse(e) {
    return e.map((a) => ({
      overall_fee: B(a.overall_fee),
      gas_consumed: B(a.gas_consumed),
      gas_price: B(a.gas_price)
    }));
  }
  parseCallContractResponse(e) {
    return {
      result: e
    };
  }
  parseSimulateTransactionResponse(e) {
    return e.map((a) => ({
      ...a,
      suggestedMaxFee: lt(BigInt(a.fee_estimation.overall_fee))
    }));
  }
  parseContractClassResponse(e) {
    return {
      ...e,
      abi: typeof e.abi == "string" ? JSON.parse(e.abi) : e.abi
    };
  }
};
function ws(e, a = e.constructor) {
  const { captureStackTrace: t } = Error;
  t && t(e, a);
}
function ms(e, a) {
  const { setPrototypeOf: t } = Object;
  t ? t(e, a) : e.__proto__ = a;
}
var Es = class extends Error {
  constructor(e) {
    super(e), Object.defineProperty(this, "name", {
      value: new.target.name,
      enumerable: !1,
      configurable: !0
    }), ms(this, new.target.prototype), ws(this);
  }
}, qt = class extends Es {
}, vs = class extends qt {
  constructor(e, a) {
    super(e), this.errorCode = a;
  }
}, xs = class extends qt {
  constructor(e, a) {
    super(e), this.errorCode = a;
  }
}, As = {};
Q(As, {
  StarknetIdContract: () => Ts,
  getStarknetIdContract: () => xr,
  useDecoded: () => Ss,
  useEncoded: () => ks
});
var ke = "abcdefghijklmnopqrstuvwxyz0123456789-", Dt = BigInt(ke.length + 1), G = "这来", Uf = BigInt(ke.length), vc = BigInt(G.length), Ff = BigInt(G.length + 1);
function xc(e) {
  let a = 0;
  for (; e.endsWith(G[G.length - 1]); )
    e = e.substring(0, e.length - 1), a += 1;
  return [e, a];
}
function Ss(e) {
  let a = "";
  return e.forEach((t) => {
    for (; t !== re; ) {
      const r = t % Dt;
      if (t /= Dt, r === BigInt(ke.length)) {
        const f = t / Ff;
        if (f === re) {
          const d = t % Ff;
          t = f, d === re ? a += ke[0] : a += G[Number(d) - 1];
        } else {
          const d = t % vc;
          a += G[Number(d)], t /= vc;
        }
      } else
        a += ke[Number(r)];
    }
    const [n, c] = xc(a);
    c && (a = n + (c % 2 === 0 ? G[G.length - 1].repeat(c / 2 - 1) + G[0] + ke[1] : G[G.length - 1].repeat((c - 1) / 2 + 1))), a += ".";
  }), a && a.concat("stark");
}
function ks(e) {
  let a = BigInt(0), t = BigInt(1);
  if (e.endsWith(G[0] + ke[1])) {
    const [n, c] = xc(e.substring(0, e.length - 2));
    e = n + G[G.length - 1].repeat(2 * (c + 1));
  } else {
    const [n, c] = xc(e);
    c && (e = n + G[G.length - 1].repeat(1 + 2 * (c - 1)));
  }
  for (let n = 0; n < e.length; n += 1) {
    const c = e[n], r = ke.indexOf(c), f = BigInt(ke.indexOf(c));
    if (r !== -1)
      n === e.length - 1 && e[n] === ke[0] ? (a += t * Uf, t *= Dt, t *= Dt) : (a += t * f, t *= Dt);
    else if (G.indexOf(c) !== -1) {
      a += t * Uf, t *= Dt;
      const d = (n === e.length - 1 ? 1 : 0) + G.indexOf(c);
      a += t * BigInt(d), t *= vc;
    }
  }
  return a;
}
var Ts = /* @__PURE__ */ ((e) => (e.MAINNET = "0x6ac597f8116f886fa1c97a23fa4e08299975ecaf6b598873ca6792b9bbfb678", e.TESTNET = "0x3bab268e932d2cecd1946f100ae67ce3dff9fd234119ea2f6da57d16d29fce", e))(Ts || {});
function xr(e) {
  switch (e) {
    case "0x534e5f4d41494e":
      return "0x6ac597f8116f886fa1c97a23fa4e08299975ecaf6b598873ca6792b9bbfb678";
    case "0x534e5f474f45524c49":
      return "0x3bab268e932d2cecd1946f100ae67ce3dff9fd234119ea2f6da57d16d29fce";
    default:
      throw new Error("Starknet.id is not yet deployed on this network");
  }
}
async function Ar(e, a, t) {
  const n = await e.getChainId(), c = t ?? xr(n);
  try {
    const f = (await e.callContract({
      contractAddress: c,
      entrypoint: "address_to_domain",
      calldata: $.compile({
        address: a
      })
    })).result.map((o) => BigInt(o)).slice(1), d = Ss(f);
    if (!d)
      throw Error("Starkname not found");
    return d;
  } catch (r) {
    throw r instanceof Error && r.message === "Starkname not found" ? r : Error("Could not get stark name");
  }
}
async function Sr(e, a, t) {
  const n = await e.getChainId(), c = t ?? xr(n);
  try {
    return (await e.callContract({
      contractAddress: c,
      entrypoint: "domain_to_address",
      calldata: $.compile({
        domain: [ks(a.replace(".stark", "")).toString(10)]
      })
    })).result[0];
  } catch {
    throw Error("Could not get address from stark name");
  }
}
var W6 = ["latest", "pending"], j = class {
  constructor(e) {
    this.hash = null, this.number = null, this.tag = null, this.valueOf = () => this.number, this.toString = () => this.hash, this.setIdentifier(e);
  }
  setIdentifier(e) {
    typeof e == "string" && Oe(e) ? this.hash = e : typeof e == "bigint" ? this.hash = I(e) : typeof e == "number" ? this.number = e : typeof e == "string" && W6.includes(e) ? this.tag = e : this.tag = "pending";
  }
  // TODO: fix any
  get queryIdentifier() {
    return this.number !== null ? `blockNumber=${this.number}` : this.hash !== null ? `blockHash=${this.hash}` : `blockNumber=${this.tag}`;
  }
  // TODO: fix any
  get identifier() {
    return this.number !== null ? { block_number: this.number } : this.hash !== null ? { block_hash: this.hash } : this.tag;
  }
  set identifier(e) {
    this.setIdentifier(e);
  }
  get sequencerIdentifier() {
    return this.hash !== null ? { blockHash: this.hash } : { blockNumber: this.number ?? this.tag };
  }
}, tc = {
  headers: { "Content-Type": "application/json" },
  blockIdentifier: "latest",
  retries: 200
}, on = class {
  constructor(e) {
    this.responseParser = new Y6();
    const { nodeUrl: a, retries: t, headers: n, blockIdentifier: c, chainId: r } = e;
    this.nodeUrl = a, this.retries = t || tc.retries, this.headers = { ...tc.headers, ...n }, this.blockIdentifier = c || tc.blockIdentifier, this.chainId = r, this.getChainId();
  }
  fetch(e, a) {
    const t = Fe({ method: e, jsonrpc: "2.0", params: a, id: 0 });
    return _s(this.nodeUrl, {
      method: "POST",
      body: t,
      headers: this.headers
    });
  }
  errorHandler(e) {
    if (e) {
      const { code: a, message: t } = e;
      throw new qt(`${a}: ${t}`);
    }
  }
  async fetchEndpoint(e, a) {
    var t;
    try {
      const n = await this.fetch(e, a), { error: c, result: r } = await n.json();
      return this.errorHandler(c), r;
    } catch (n) {
      throw this.errorHandler((t = n == null ? void 0 : n.response) == null ? void 0 : t.data), n;
    }
  }
  // Methods from Interface
  async getChainId() {
    return this.chainId ?? (this.chainId = await this.fetchEndpoint("starknet_chainId")), this.chainId;
  }
  async getBlock(e = this.blockIdentifier) {
    return this.getBlockWithTxHashes(e).then(
      this.responseParser.parseGetBlockResponse
    );
  }
  async getBlockHashAndNumber() {
    return this.fetchEndpoint("starknet_blockHashAndNumber");
  }
  async getBlockWithTxHashes(e = this.blockIdentifier) {
    const a = new j(e).identifier;
    return this.fetchEndpoint("starknet_getBlockWithTxHashes", { block_id: a });
  }
  async getBlockWithTxs(e = this.blockIdentifier) {
    const a = new j(e).identifier;
    return this.fetchEndpoint("starknet_getBlockWithTxs", { block_id: a });
  }
  async getClassHashAt(e, a = this.blockIdentifier) {
    const t = new j(a).identifier;
    return this.fetchEndpoint("starknet_getClassHashAt", {
      block_id: t,
      contract_address: e
    });
  }
  async getNonceForAddress(e, a = this.blockIdentifier) {
    const t = new j(a).identifier;
    return this.fetchEndpoint("starknet_getNonce", {
      contract_address: e,
      block_id: t
    });
  }
  async getPendingTransactions() {
    return this.fetchEndpoint("starknet_pendingTransactions");
  }
  async getProtocolVersion() {
    throw new Error("Pathfinder does not implement this rpc 0.1.0 method");
  }
  async getStateUpdate(e = this.blockIdentifier) {
    const a = new j(e).identifier;
    return this.fetchEndpoint("starknet_getStateUpdate", { block_id: a });
  }
  async getStorageAt(e, a, t = this.blockIdentifier) {
    const n = Bi(a), c = new j(t).identifier;
    return this.fetchEndpoint("starknet_getStorageAt", {
      contract_address: e,
      key: n,
      block_id: c
    });
  }
  // Methods from Interface
  async getTransaction(e) {
    return this.getTransactionByHash(e).then(this.responseParser.parseGetTransactionResponse);
  }
  async getTransactionByHash(e) {
    return this.fetchEndpoint("starknet_getTransactionByHash", { transaction_hash: e });
  }
  async getTransactionByBlockIdAndIndex(e, a) {
    const t = new j(e).identifier;
    return this.fetchEndpoint("starknet_getTransactionByBlockIdAndIndex", { block_id: t, index: a });
  }
  async getTransactionReceipt(e) {
    return this.fetchEndpoint("starknet_getTransactionReceipt", { transaction_hash: e });
  }
  async getClassByHash(e) {
    return this.getClass(e);
  }
  async getClass(e, a = this.blockIdentifier) {
    const t = new j(a).identifier;
    return this.fetchEndpoint("starknet_getClass", {
      class_hash: e,
      block_id: t
    }).then(this.responseParser.parseContractClassResponse);
  }
  async getClassAt(e, a = this.blockIdentifier) {
    const t = new j(a).identifier;
    return this.fetchEndpoint("starknet_getClassAt", {
      block_id: t,
      contract_address: e
    }).then(this.responseParser.parseContractClassResponse);
  }
  async getCode(e, a) {
    throw new Error("RPC does not implement getCode function");
  }
  async getEstimateFee(e, a, t = this.blockIdentifier) {
    return this.getInvokeEstimateFee(e, a, t);
  }
  async getInvokeEstimateFee(e, a, t = this.blockIdentifier) {
    const n = new j(t).identifier, c = this.buildTransaction(
      {
        type: "INVOKE_FUNCTION",
        ...e,
        ...a
      },
      "fee"
    );
    return this.fetchEndpoint("starknet_estimateFee", {
      request: [c],
      block_id: n
    }).then(this.responseParser.parseFeeEstimateResponse);
  }
  async getDeclareEstimateFee(e, a, t = this.blockIdentifier) {
    const n = new j(t).identifier, c = this.buildTransaction(
      {
        type: "DECLARE",
        ...e,
        ...a
      },
      "fee"
    );
    return this.fetchEndpoint("starknet_estimateFee", {
      request: [c],
      block_id: n
    }).then(this.responseParser.parseFeeEstimateResponse);
  }
  async getDeployAccountEstimateFee(e, a, t = this.blockIdentifier) {
    const n = new j(t).identifier, c = this.buildTransaction(
      {
        type: "DEPLOY_ACCOUNT",
        ...e,
        ...a
      },
      "fee"
    );
    return this.fetchEndpoint("starknet_estimateFee", {
      request: [c],
      block_id: n
    }).then(this.responseParser.parseFeeEstimateResponse);
  }
  async getEstimateFeeBulk(e, { blockIdentifier: a = this.blockIdentifier, skipValidate: t = !1 }) {
    t && console.warn("getEstimateFeeBulk RPC does not support skipValidate");
    const n = new j(a).identifier;
    return this.fetchEndpoint("starknet_estimateFee", {
      request: e.map((c) => this.buildTransaction(c, "fee")),
      block_id: n
    }).then(this.responseParser.parseFeeEstimateBulkResponse);
  }
  async declareContract({ contract: e, signature: a, senderAddress: t, compiledClassHash: n }, c) {
    return ge(e) ? this.fetchEndpoint("starknet_addDeclareTransaction", {
      declare_transaction: {
        type: Ae.TransactionType.DECLARE,
        contract_class: {
          sierra_program: dn(e.sierra_program),
          contract_class_version: e.contract_class_version,
          entry_points_by_type: e.entry_points_by_type,
          abi: e.abi
        },
        compiled_class_hash: n || "",
        version: I(mt),
        max_fee: I(c.maxFee || 0),
        signature: Ot(a),
        sender_address: t,
        nonce: I(c.nonce)
      }
    }) : this.fetchEndpoint("starknet_addDeclareTransaction", {
      declare_transaction: {
        type: Ae.TransactionType.DECLARE,
        contract_class: {
          program: e.program,
          entry_points_by_type: e.entry_points_by_type,
          abi: e.abi
        },
        version: I($e),
        max_fee: I(c.maxFee || 0),
        signature: Ot(a),
        sender_address: t,
        nonce: I(c.nonce)
      }
    });
  }
  async deployAccountContract({ classHash: e, constructorCalldata: a, addressSalt: t, signature: n }, c) {
    return this.fetchEndpoint("starknet_addDeployAccountTransaction", {
      deploy_account_transaction: {
        constructor_calldata: $.toHex(a || []),
        class_hash: I(e),
        contract_address_salt: I(t || 0),
        type: Ae.TransactionType.DEPLOY_ACCOUNT,
        max_fee: I(c.maxFee || 0),
        version: I(c.version || 0),
        signature: Ot(n),
        nonce: I(c.nonce)
      }
    });
  }
  async invokeFunction(e, a) {
    return this.fetchEndpoint("starknet_addInvokeTransaction", {
      invoke_transaction: {
        sender_address: e.contractAddress,
        calldata: $.toHex(e.calldata),
        type: Ae.TransactionType.INVOKE,
        max_fee: I(a.maxFee || 0),
        version: "0x1",
        signature: Ot(e.signature),
        nonce: I(a.nonce)
      }
    });
  }
  // Methods from Interface
  async callContract(e, a = this.blockIdentifier) {
    const t = new j(a).identifier, n = await this.fetchEndpoint("starknet_call", {
      request: {
        contract_address: e.contractAddress,
        entry_point_selector: Ee(e.entrypoint),
        calldata: $.toHex(e.calldata)
      },
      block_id: t
    });
    return this.responseParser.parseCallContractResponse(n);
  }
  async traceTransaction(e) {
    return this.fetchEndpoint("starknet_traceTransaction", { transaction_hash: e });
  }
  async traceBlockTransactions(e) {
    return this.fetchEndpoint("starknet_traceBlockTransactions", { block_hash: e });
  }
  async waitForTransaction(e, a) {
    const t = [
      "REJECTED",
      "NOT_RECEIVED"
      /* NOT_RECEIVED */
    ];
    let { retries: n } = this, c = !1, r = {};
    const f = (a == null ? void 0 : a.retryInterval) ?? 8e3, d = (a == null ? void 0 : a.successStates) ?? [
      "ACCEPTED_ON_L1",
      "ACCEPTED_ON_L2",
      "PENDING"
      /* PENDING */
    ];
    for (; !c; ) {
      await sn(f);
      try {
        if (r = await this.getTransactionReceipt(e), !("status" in r))
          throw new Error("pending transaction");
        if (r.status && d.includes(r.status))
          c = !0;
        else if (r.status && t.includes(r.status)) {
          const o = r.status, i = new Error(o);
          throw i.response = r, i;
        }
      } catch (o) {
        if (o instanceof Error && t.includes(o.message))
          throw o;
        if (n === 0)
          throw new Error(`waitForTransaction timed-out with retries ${this.retries}`);
      }
      n -= 1;
    }
    return await sn(f), r;
  }
  /**
   * Gets the transaction count from a block.
   *
   *
   * @param blockIdentifier
   * @returns Number of transactions
   */
  async getTransactionCount(e = this.blockIdentifier) {
    const a = new j(e).identifier;
    return this.fetchEndpoint("starknet_getBlockTransactionCount", { block_id: a });
  }
  /**
   * Gets the latest block number
   *
   *
   * @returns Number of the latest block
   */
  async getBlockNumber() {
    return this.fetchEndpoint("starknet_blockNumber");
  }
  /**
   * Gets syncing status of the node
   *
   *
   * @returns Object with the stats data
   */
  async getSyncingStats() {
    return this.fetchEndpoint("starknet_syncing");
  }
  /**
   * Gets all the events filtered
   *
   *
   * @returns events and the pagination of the events
   */
  async getEvents(e) {
    return this.fetchEndpoint("starknet_getEvents", { filter: e });
  }
  async getSimulateTransaction(e, {
    blockIdentifier: a = this.blockIdentifier,
    skipValidate: t = !1,
    skipExecute: n = !1
  }) {
    const c = new j(a).identifier, r = [];
    return t && r.push(
      0
      /* SKIP_VALIDATE */
    ), n && r.push(
      1
      /* SKIP_EXECUTE */
    ), this.fetchEndpoint("starknet_simulateTransaction", {
      block_id: c,
      transactions: e.map((f) => this.buildTransaction(f)),
      // TODO: Pathfinder 0.5.6 bug, should be transaction
      simulation_flags: r
    }).then(this.responseParser.parseSimulateTransactionResponse);
  }
  async getStarkName(e, a) {
    return Ar(this, e, a);
  }
  async getAddressFromStarkName(e, a) {
    return Sr(this, e, a);
  }
  buildTransaction(e, a) {
    const t = wr(a), n = {
      signature: Ot(e.signature),
      nonce: I(e.nonce),
      max_fee: I(e.maxFee || 0)
    };
    if (e.type === "INVOKE_FUNCTION")
      return {
        type: Ae.TransactionType.INVOKE,
        // Diff between sequencer and rpc invoke type
        sender_address: e.contractAddress,
        calldata: $.toHex(e.calldata),
        version: I(e.version || t.v1),
        ...n
      };
    if (e.type === Ae.TransactionType.DECLARE) {
      if (!ge(e.contract)) {
        const r = e.contract;
        return {
          type: e.type,
          contract_class: r,
          sender_address: e.senderAddress,
          version: I(e.version || t.v1),
          ...n
        };
      }
      const c = e.contract;
      return {
        // compiled_class_hash
        type: e.type,
        contract_class: {
          ...c,
          sierra_program: dn(c.sierra_program)
        },
        compiled_class_hash: e.compiledClassHash || "",
        sender_address: e.senderAddress,
        version: I(e.version || t.v2),
        ...n
      };
    }
    if (e.type === "DEPLOY_ACCOUNT")
      return {
        type: e.type,
        constructor_calldata: $.toHex(e.constructorCalldata || []),
        class_hash: I(e.classHash),
        contract_address_salt: I(e.addressSalt || 0),
        version: I(e.version || t.v1),
        ...n
      };
    throw Error("RPC buildTransaction received unknown TransactionType");
  }
}, X6 = class {
}, J6 = class extends X6 {
  parseGetBlockResponse(e) {
    return {
      ...e,
      new_root: e.state_root,
      parent_hash: e.parent_block_hash,
      transactions: Object.values(e.transactions).map((a) => "transaction_hash" in a && a.transaction_hash).filter(Boolean)
    };
  }
  parseGetTransactionResponse(e) {
    return {
      ...e,
      calldata: "calldata" in e.transaction ? e.transaction.calldata : [],
      contract_class: "contract_class" in e.transaction ? e.transaction.contract_class : void 0,
      entry_point_selector: "entry_point_selector" in e.transaction ? e.transaction.entry_point_selector : void 0,
      max_fee: "max_fee" in e.transaction ? e.transaction.max_fee : void 0,
      nonce: e.transaction.nonce,
      sender_address: "sender_address" in e.transaction ? e.transaction.sender_address : void 0,
      signature: "signature" in e.transaction ? e.transaction.signature : void 0,
      transaction_hash: "transaction_hash" in e.transaction ? e.transaction.transaction_hash : void 0,
      version: "version" in e.transaction ? e.transaction.version : void 0
    };
  }
  parseGetTransactionReceiptResponse(e) {
    return {
      transaction_hash: e.transaction_hash,
      status: e.status,
      messages_sent: e.l2_to_l1_messages,
      // TODO: parse
      events: e.events,
      ..."block_hash" in e && { block_hash: e.block_hash },
      ..."block_number" in e && { block_number: e.block_number },
      ..."actual_fee" in e && { actual_fee: e.actual_fee },
      ..."transaction_index" in e && { transaction_index: e.transaction_index },
      ..."execution_resources" in e && { execution_resources: e.execution_resources },
      ..."l1_to_l2_consumed_message" in e && {
        // eslint-disable-next-line @typescript-eslint/dot-notation
        l1_to_l2_consumed_message: e.l1_to_l2_consumed_message
      },
      ..."transaction_failure_reason" in e && {
        transaction_failure_reason: e.transaction_failure_reason
      }
    };
  }
  parseFeeEstimateResponse(e) {
    if ("overall_fee" in e) {
      let a = {};
      try {
        a = {
          gas_consumed: B(e.gas_usage),
          gas_price: B(e.gas_price)
        };
      } catch {
      }
      return {
        overall_fee: B(e.overall_fee),
        ...a
      };
    }
    return {
      overall_fee: B(e.amount)
    };
  }
  parseFeeEstimateBulkResponse(e) {
    return [].concat(e).map((a) => {
      if ("overall_fee" in a) {
        let t = {};
        try {
          t = {
            gas_consumed: B(a.gas_usage),
            gas_price: B(a.gas_price)
          };
        } catch {
        }
        return {
          overall_fee: B(a.overall_fee),
          ...t
        };
      }
      return {
        overall_fee: B(a.amount)
      };
    });
  }
  parseSimulateTransactionResponse(e) {
    const a = "overall_fee" in e.fee_estimation ? e.fee_estimation.overall_fee : e.fee_estimation.amount;
    return [
      {
        transaction_trace: e.trace,
        fee_estimation: e.fee_estimation,
        suggestedMaxFee: lt(BigInt(a))
      }
    ];
  }
  parseCallContractResponse(e) {
    return {
      result: e.result
    };
  }
  parseInvokeFunctionResponse(e) {
    return {
      transaction_hash: e.transaction_hash
    };
  }
  parseDeployContractResponse(e) {
    return {
      transaction_hash: e.transaction_hash,
      contract_address: e.address
    };
  }
  parseDeclareContractResponse(e) {
    return {
      transaction_hash: e.transaction_hash,
      class_hash: e.class_hash
    };
  }
  parseGetStateUpdateResponse(e) {
    const a = Object.entries(e.state_diff.nonces).map(([n, c]) => ({
      contract_address: n,
      nonce: c
    })), t = Object.entries(e.state_diff.storage_diffs).map(
      ([n, c]) => ({ address: n, storage_entries: c })
    );
    return {
      ...e,
      state_diff: {
        ...e.state_diff,
        storage_diffs: t,
        nonces: a
      }
    };
  }
  parseContractClassResponse(e) {
    const a = ge(e) ? e : vr(e);
    return {
      ...a,
      abi: typeof a.abi == "string" ? JSON.parse(a.abi) : a.abi
    };
  }
}, Q6 = /^(?:\w+:)?\/\/(\S+)$/, e3 = /^localhost[:?\d]*(?:[^:?\d]\S*)?$/, t3 = /^[^\s.]+\.\S{2,}$/;
function Cs(e) {
  if (!e || typeof e != "string")
    return !1;
  const a = e.match(Q6);
  if (!a)
    return !1;
  const t = a[1];
  return t ? !!(e3.test(t) || t3.test(t)) : !1;
}
function Bt(e, a, t) {
  return Cs(t) ? t : hi(e, t ?? a);
}
function a3(e) {
  return e === void 0 || Object.keys(e).length === 0 || Object.keys(e).length === 1 && Object.entries(e).every(([a, t]) => a === "blockIdentifier" && t === null);
}
var zf = {
  network: "SN_GOERLI2",
  blockIdentifier: "pending"
}, Ut = class {
  constructor(e = zf) {
    this.responseParser = new J6(), "network" in e ? (this.baseUrl = Ut.getNetworkFromName(e.network), this.feederGatewayUrl = Bt(this.baseUrl, "feeder_gateway"), this.gatewayUrl = Bt(this.baseUrl, "gateway")) : (this.baseUrl = e.baseUrl, this.feederGatewayUrl = Bt(
      this.baseUrl,
      "feeder_gateway",
      e.feederGatewayUrl
    ), this.gatewayUrl = Bt(this.baseUrl, "gateway", e.gatewayUrl)), this.chainId = (e == null ? void 0 : e.chainId) ?? Ut.getChainIdFromBaseUrl(this.baseUrl), this.headers = e.headers, this.blockIdentifier = (e == null ? void 0 : e.blockIdentifier) || zf.blockIdentifier;
  }
  static getNetworkFromName(e) {
    switch (e) {
      case "SN_MAIN":
        return "https://alpha-mainnet.starknet.io";
      case "SN_GOERLI":
        return "https://alpha4.starknet.io";
      case "SN_GOERLI2":
        return "https://alpha4-2.starknet.io";
      default:
        throw new Error("Could not detect base url from NetworkName");
    }
  }
  static getChainIdFromBaseUrl(e) {
    try {
      const a = new URL(e);
      return a.host.includes("mainnet.starknet.io") ? "0x534e5f4d41494e" : a.host.includes("alpha4-2.starknet.io") ? "0x534e5f474f45524c4932" : "0x534e5f474f45524c49";
    } catch {
      return console.error(`Could not parse baseUrl: ${e}`), "0x534e5f474f45524c49";
    }
  }
  getFetchUrl(e) {
    return ["add_transaction"].includes(e) ? this.gatewayUrl : this.feederGatewayUrl;
  }
  getFetchMethod(e) {
    return [
      "add_transaction",
      "call_contract",
      "estimate_fee",
      "estimate_message_fee",
      "estimate_fee_bulk",
      "simulate_transaction"
    ].includes(e) ? "POST" : "GET";
  }
  getQueryString(e) {
    return a3(e) ? "" : `?${Object.entries(e).map(([t, n]) => t === "blockIdentifier" ? `${new j(n).queryIdentifier}` : `${t}=${n}`).join("&")}`;
  }
  getHeaders(e) {
    return e === "POST" ? {
      "Content-Type": "application/json",
      ...this.headers
    } : this.headers;
  }
  // typesafe fetch
  async fetchEndpoint(e, ...[a, t]) {
    const n = this.getFetchUrl(e), c = this.getFetchMethod(e), r = this.getQueryString(a), f = hi(n, e, r);
    return this.fetch(f, {
      method: c,
      body: t
    });
  }
  async fetch(e, a) {
    const t = Bt(this.baseUrl, "", e), n = (a == null ? void 0 : a.method) ?? "GET", c = this.getHeaders(n), r = Fe(a == null ? void 0 : a.body);
    try {
      const f = await _s(t, {
        method: n,
        body: r,
        headers: c
      }), d = await f.text();
      if (!f.ok) {
        let i;
        try {
          i = tt(d);
        } catch {
          throw new xs(f.statusText, f.status);
        }
        throw new vs(i.message, i.code);
      }
      return (a != null && a.parseAlwaysAsBigInt ? fs : tt)(d);
    } catch (f) {
      throw f instanceof Error && !(f instanceof qt) ? Error(`Could not ${n} from endpoint \`${t}\`: ${f.message}`) : f;
    }
  }
  async getChainId() {
    return Promise.resolve(this.chainId);
  }
  async callContract({ contractAddress: e, entrypoint: a, calldata: t = [] }, n = this.blockIdentifier) {
    return this.fetchEndpoint(
      "call_contract",
      { blockIdentifier: n },
      {
        // TODO - determine best choice once both are fully supported in devnet
        // signature: [],
        // sender_address: contractAddress,
        contract_address: e,
        entry_point_selector: Ee(a),
        calldata: $.compile(t)
      }
    ).then(this.responseParser.parseCallContractResponse);
  }
  async getBlock(e = this.blockIdentifier) {
    return this.fetchEndpoint("get_block", { blockIdentifier: e }).then(
      this.responseParser.parseGetBlockResponse
    );
  }
  async getNonceForAddress(e, a = this.blockIdentifier) {
    return this.fetchEndpoint("get_nonce", { contractAddress: e, blockIdentifier: a });
  }
  async getStorageAt(e, a, t = this.blockIdentifier) {
    const n = B(a).toString(10);
    return this.fetchEndpoint("get_storage_at", {
      blockIdentifier: t,
      contractAddress: e,
      key: n
    });
  }
  async getTransaction(e) {
    const a = I(e);
    return this.fetchEndpoint("get_transaction", { transactionHash: a }).then((t) => {
      if (Object.values(t).length === 1)
        throw new qt(t.status);
      return this.responseParser.parseGetTransactionResponse(t);
    });
  }
  async getTransactionReceipt(e) {
    const a = I(e);
    return this.fetchEndpoint("get_transaction_receipt", { transactionHash: a }).then(
      this.responseParser.parseGetTransactionReceiptResponse
    );
  }
  async getClassAt(e, a = this.blockIdentifier) {
    return this.fetchEndpoint("get_full_contract", { blockIdentifier: a, contractAddress: e }).then(
      this.responseParser.parseContractClassResponse
    );
  }
  async getClassHashAt(e, a = this.blockIdentifier) {
    return this.fetchEndpoint("get_class_hash_at", { blockIdentifier: a, contractAddress: e });
  }
  async getClassByHash(e, a = this.blockIdentifier) {
    return this.fetchEndpoint("get_class_by_hash", { classHash: e, blockIdentifier: a }).then(
      this.responseParser.parseContractClassResponse
    );
  }
  async getCompiledClassByClassHash(e, a = this.blockIdentifier) {
    return this.fetchEndpoint("get_compiled_class_by_class_hash", { classHash: e, blockIdentifier: a });
  }
  async invokeFunction(e, a) {
    return this.fetchEndpoint("add_transaction", void 0, {
      type: "INVOKE_FUNCTION",
      sender_address: e.contractAddress,
      calldata: $.compile(e.calldata ?? []),
      signature: Nt(e.signature),
      nonce: I(a.nonce),
      max_fee: I(a.maxFee || 0),
      version: "0x1"
    }).then(this.responseParser.parseInvokeFunctionResponse);
  }
  async deployAccountContract({ classHash: e, constructorCalldata: a, addressSalt: t, signature: n }, c) {
    return this.fetchEndpoint("add_transaction", void 0, {
      type: "DEPLOY_ACCOUNT",
      contract_address_salt: t ?? Er(),
      constructor_calldata: $.compile(a ?? []),
      class_hash: I(e),
      max_fee: I(c.maxFee || 0),
      version: I(c.version || 0),
      nonce: I(c.nonce),
      signature: Nt(n)
    }).then(this.responseParser.parseDeployContractResponse);
  }
  async declareContract({ senderAddress: e, contract: a, signature: t, compiledClassHash: n }, c) {
    return ge(a) ? this.fetchEndpoint("add_transaction", void 0, {
      type: "DECLARE",
      sender_address: e,
      compiled_class_hash: n,
      contract_class: a,
      nonce: I(c.nonce),
      signature: Nt(t),
      max_fee: I(c.maxFee || 0),
      version: I(mt)
    }).then(this.responseParser.parseDeclareContractResponse) : this.fetchEndpoint("add_transaction", void 0, {
      type: "DECLARE",
      contract_class: a,
      nonce: I(c.nonce),
      signature: Nt(t),
      sender_address: e,
      max_fee: I(c.maxFee || 0),
      version: I($e)
    }).then(this.responseParser.parseDeclareContractResponse);
  }
  async getEstimateFee(e, a, t = this.blockIdentifier, n = !1) {
    return this.getInvokeEstimateFee(e, a, t, n);
  }
  async getInvokeEstimateFee(e, a, t = this.blockIdentifier, n = !1) {
    const c = this.buildTransaction(
      {
        type: "INVOKE_FUNCTION",
        ...e,
        ...a
      },
      "fee"
    );
    return this.fetchEndpoint("estimate_fee", { blockIdentifier: t, skipValidate: n }, c).then(
      this.responseParser.parseFeeEstimateResponse
    );
  }
  async getDeclareEstimateFee(e, a, t = this.blockIdentifier, n = !1) {
    const c = this.buildTransaction(
      {
        type: "DECLARE",
        ...e,
        ...a
      },
      "fee"
    );
    return this.fetchEndpoint("estimate_fee", { blockIdentifier: t, skipValidate: n }, c).then(
      this.responseParser.parseFeeEstimateResponse
    );
  }
  async getDeployAccountEstimateFee(e, a, t = this.blockIdentifier, n = !1) {
    const c = this.buildTransaction(
      {
        type: "DEPLOY_ACCOUNT",
        ...e,
        ...a
      },
      "fee"
    );
    return this.fetchEndpoint("estimate_fee", { blockIdentifier: t, skipValidate: n }, c).then(
      this.responseParser.parseFeeEstimateResponse
    );
  }
  async getEstimateFeeBulk(e, { blockIdentifier: a = this.blockIdentifier, skipValidate: t = !1 }) {
    const n = e.map((c) => this.buildTransaction(c, "fee"));
    return this.fetchEndpoint(
      "estimate_fee_bulk",
      { blockIdentifier: a, skipValidate: t },
      n
    ).then(this.responseParser.parseFeeEstimateBulkResponse);
  }
  async getCode(e, a = this.blockIdentifier) {
    return this.fetchEndpoint("get_code", { contractAddress: e, blockIdentifier: a });
  }
  async waitForTransaction(e, a) {
    const t = [
      "REJECTED",
      "NOT_RECEIVED"
      /* NOT_RECEIVED */
    ];
    let n = !1, c;
    const r = (a == null ? void 0 : a.retryInterval) ?? 8e3, f = (a == null ? void 0 : a.successStates) ?? [
      "ACCEPTED_ON_L1",
      "ACCEPTED_ON_L2",
      "PENDING"
      /* PENDING */
    ];
    for (; !n; )
      if (await sn(r), c = await this.getTransactionStatus(e), f.includes(c.tx_status))
        n = !0;
      else if (t.includes(c.tx_status)) {
        const o = c.tx_failure_reason ? `${c.tx_status}: ${c.tx_failure_reason.code}
${c.tx_failure_reason.error_message}` : c.tx_status, i = new Error(o);
        throw i.response = c, i;
      }
    return await this.getTransactionReceipt(e);
  }
  /**
   * Gets the status of a transaction.
   * @param txHash BigNumberish
   * @returns GetTransactionStatusResponse - the transaction status object
   */
  async getTransactionStatus(e) {
    const a = I(e);
    return this.fetchEndpoint("get_transaction_status", { transactionHash: a });
  }
  /**
   * Gets the smart contract address on the goerli testnet.
   * @returns GetContractAddressesResponse - starknet smart contract addresses
   */
  async getContractAddresses() {
    return this.fetchEndpoint("get_contract_addresses");
  }
  /**
   * Gets the transaction trace from a tx id.
   * @param txHash BigNumberish
   * @returns TransactionTraceResponse - the transaction trace
   */
  async getTransactionTrace(e) {
    const a = I(e);
    return this.fetchEndpoint("get_transaction_trace", { transactionHash: a });
  }
  async estimateMessageFee({ from_address: e, to_address: a, entry_point_selector: t, payload: n }, c = this.blockIdentifier) {
    const r = {
      from_address: Pi(e),
      to_address: nr(a),
      entry_point_selector: fr(t),
      payload: Hi(n)
    };
    return this.fetchEndpoint("estimate_message_fee", { blockIdentifier: c }, r);
  }
  /**
   * Simulate transaction using Sequencer provider
   * WARNING!: Sequencer will process only first element from invocations array
   *
   * @param invocations Array of invocations, but only first invocation will be processed
   * @param blockIdentifier block identifier, default 'latest'
   * @param skipValidate Skip Account __validate__ method
   * @returns
   */
  async getSimulateTransaction(e, {
    blockIdentifier: a = this.blockIdentifier,
    skipValidate: t = !1,
    skipExecute: n = !1
  }) {
    e.length > 1 && console.warn("Sequencer simulate process only first element from invocations list"), n && console.warn("Sequencer can't skip account __execute__");
    const c = this.buildTransaction(e[0]);
    return this.fetchEndpoint(
      "simulate_transaction",
      {
        blockIdentifier: a,
        skipValidate: t ?? !1
      },
      c
    ).then(this.responseParser.parseSimulateTransactionResponse);
  }
  async getStateUpdate(e = this.blockIdentifier) {
    const a = new j(e).sequencerIdentifier;
    return this.fetchEndpoint("get_state_update", { ...a }).then(
      this.responseParser.parseGetStateUpdateResponse
    );
  }
  // consider adding an optional trace retrieval parameter to the getBlock method
  async getBlockTraces(e = this.blockIdentifier) {
    const a = new j(e).sequencerIdentifier;
    return this.fetchEndpoint("get_block_traces", { ...a });
  }
  async getStarkName(e, a) {
    return Ar(this, e, a);
  }
  async getAddressFromStarkName(e, a) {
    return Sr(this, e, a);
  }
  /**
   * Build Single AccountTransaction from Single AccountInvocation
   * @param invocation AccountInvocationItem
   * @param versionType 'fee' | 'transaction' - used to determine default versions
   * @returns AccountTransactionItem
   */
  buildTransaction(e, a) {
    const t = wr(a), n = {
      signature: Nt(e.signature),
      nonce: I(e.nonce)
    };
    if (e.type === "INVOKE_FUNCTION")
      return {
        type: e.type,
        sender_address: e.contractAddress,
        calldata: $.compile(e.calldata ?? []),
        version: I(e.version || t.v1),
        ...n
      };
    if (e.type === "DECLARE")
      return ge(e.contract) ? {
        type: e.type,
        contract_class: e.contract,
        compiled_class_hash: e.compiledClassHash,
        sender_address: e.senderAddress,
        version: I(e.version || t.v2),
        // fee on getDeclareEstimateFee use t.v. instead of feet.v.
        ...n
      } : {
        type: e.type,
        contract_class: e.contract,
        sender_address: e.senderAddress,
        version: I(e.version || t.v1),
        // fee from getDeclareEstimateFee use t.v. instead of feet.v.
        ...n
      };
    if (e.type === "DEPLOY_ACCOUNT")
      return {
        type: e.type,
        constructor_calldata: $.compile(e.constructorCalldata || []),
        class_hash: I(e.classHash),
        contract_address_salt: I(e.addressSalt || 0),
        version: I(e.version || t.v1),
        ...n
      };
    throw Error("Sequencer buildTransaction received unknown TransactionType");
  }
}, Sn = class {
  constructor(a) {
    a instanceof Sn ? this.provider = a.provider : a instanceof on || a instanceof Ut ? this.provider = a : a && "rpc" in a ? this.provider = new on(a.rpc) : a && "sequencer" in a ? this.provider = new Ut(a.sequencer) : this.provider = new Ut();
  }
  async getChainId() {
    return this.provider.getChainId();
  }
  async getBlock(a) {
    return this.provider.getBlock(a);
  }
  async getClassAt(a, t) {
    return this.provider.getClassAt(a, t);
  }
  async getClassHashAt(a, t) {
    return this.provider.getClassHashAt(a, t);
  }
  getClassByHash(a) {
    return this.provider.getClassByHash(a);
  }
  async getEstimateFee(a, t, n) {
    return this.provider.getEstimateFee(a, t, n);
  }
  async getInvokeEstimateFee(a, t, n, c) {
    return this.provider.getInvokeEstimateFee(
      a,
      t,
      n,
      c
    );
  }
  async getEstimateFeeBulk(a, t) {
    return this.provider.getEstimateFeeBulk(a, t);
  }
  async getNonceForAddress(a, t) {
    return this.provider.getNonceForAddress(a, t);
  }
  async getStorageAt(a, t, n) {
    return this.provider.getStorageAt(a, t, n);
  }
  async getTransaction(a) {
    return this.provider.getTransaction(a);
  }
  async getTransactionReceipt(a) {
    return this.provider.getTransactionReceipt(a);
  }
  async callContract(a, t) {
    return this.provider.callContract(a, t);
  }
  async invokeFunction(a, t) {
    return this.provider.invokeFunction(a, t);
  }
  async deployAccountContract(a, t) {
    return this.provider.deployAccountContract(a, t);
  }
  async declareContract(a, t) {
    return this.provider.declareContract(a, t);
  }
  async getDeclareEstimateFee(a, t, n, c) {
    return this.provider.getDeclareEstimateFee(a, t, n, c);
  }
  getDeployAccountEstimateFee(a, t, n, c) {
    return this.provider.getDeployAccountEstimateFee(
      a,
      t,
      n,
      c
    );
  }
  async getCode(a, t) {
    return this.provider.getCode(a, t);
  }
  async waitForTransaction(a, t) {
    return this.provider.waitForTransaction(a, t);
  }
  async getSimulateTransaction(a, t) {
    return this.provider.getSimulateTransaction(a, t);
  }
  async getStateUpdate(a) {
    return this.provider.getStateUpdate(a);
  }
  async getStarkName(a, t) {
    return Ar(this, a, t);
  }
  async getAddressFromStarkName(a, t) {
    return Sr(this, a, t);
  }
}, n3 = class {
}, Is = {};
Q(Is, {
  fromCallsToExecuteCalldata: () => kr,
  fromCallsToExecuteCalldataWithNonce: () => c3,
  fromCallsToExecuteCalldata_cairo1: () => Os,
  getExecuteCalldata: () => bn,
  transformCallsToMulticallArrays: () => Ns,
  transformCallsToMulticallArrays_cairo1: () => r3
});
var Ns = (e) => {
  const a = [], t = [];
  return e.forEach((n) => {
    const c = $.compile(n.calldata || []);
    a.push({
      to: B(n.contractAddress).toString(10),
      selector: B(Ee(n.entrypoint)).toString(10),
      data_offset: t.length.toString(),
      data_len: c.length.toString()
    }), t.push(...c);
  }), {
    callArray: a,
    calldata: $.compile({ calldata: t })
  };
}, kr = (e) => {
  const { callArray: a, calldata: t } = Ns(e);
  return [...$.compile({ callArray: a }), ...t];
}, c3 = (e, a) => [...kr(e), B(a).toString()], r3 = (e) => e.map((t) => ({
  to: B(t.contractAddress).toString(10),
  selector: B(Ee(t.entrypoint)).toString(10),
  calldata: $.compile(t.calldata || [])
})), Os = (e) => {
  const a = e.map((t) => ({
    contractAddress: t.contractAddress,
    entrypoint: t.entrypoint,
    calldata: t.calldata
  }));
  return $.compile({ orderCalls: a });
}, bn = (e, a = "0") => a === "1" ? Os(e) : kr(e), Bs = {};
Q(Bs, {
  encodeData: () => Us,
  encodeType: () => Ps,
  encodeValue: () => Cr,
  getDependencies: () => Tr,
  getMessageHash: () => Ir,
  getStructHash: () => va,
  getTypeHash: () => Hs,
  isMerkleTreeType: () => $s,
  prepareSelector: () => Ls
});
var Rs = {};
Q(Rs, {
  MerkleTree: () => Ft,
  proofMerklePath: () => Ds
});
var Ft = class {
  constructor(e) {
    this.branches = [], this.leaves = e, this.root = this.build(e);
  }
  build(e) {
    if (e.length === 1)
      return e[0];
    e.length !== this.leaves.length && this.branches.push(e);
    const a = [];
    for (let t = 0; t < e.length; t += 2)
      t + 1 === e.length ? a.push(Ft.hash(e[t], "0x0")) : a.push(Ft.hash(e[t], e[t + 1]));
    return this.build(a);
  }
  static hash(e, a) {
    const [t, n] = [B(e), B(a)].sort((c, r) => c >= r ? 1 : -1);
    return Kt(t, n);
  }
  getProof(e, a = this.leaves, t = []) {
    const n = a.indexOf(e);
    if (n === -1)
      throw new Error("leaf not found");
    if (a.length === 1)
      return t;
    const c = n % 2 === 0, r = (c ? a[n + 1] : a[n - 1]) ?? "0x0", f = [...t, r], d = this.leaves.length === a.length ? -1 : this.branches.findIndex((i) => i.length === a.length), o = this.branches[d + 1] ?? [this.root];
    return this.getProof(
      Ft.hash(c ? e : r, c ? r : e),
      o,
      f
    );
  }
};
function Ds(e, a, t) {
  if (t.length === 0)
    return e === a;
  const [n, ...c] = t;
  return Ds(e, Ft.hash(a, n), c);
}
function f3(e) {
  try {
    return I(e);
  } catch {
    if (typeof e == "string")
      return I(at(e));
    throw new Error(`Invalid BigNumberish: ${e}`);
  }
}
var d3 = (e) => {
  const a = e;
  return !!(a.types && a.primaryType && a.message);
};
function Ls(e) {
  return Oe(e) ? e : Ee(e);
}
function $s(e) {
  return e.type === "merkletree";
}
var Tr = (e, a, t = []) => (a[a.length - 1] === "*" && (a = a.slice(0, -1)), t.includes(a) || !e[a] ? t : [
  a,
  ...e[a].reduce(
    (n, c) => [
      ...n,
      ...Tr(e, c.type, n).filter(
        (r) => !n.includes(r)
      )
    ],
    []
  )
]);
function i3(e, a) {
  if (a.parent && a.key) {
    const n = e[a.parent].find((r) => r.name === a.key);
    if (!$s(n))
      throw new Error(`${a.key} is not a merkle tree`);
    if (n.contains.endsWith("*"))
      throw new Error(`Merkle tree contain property must not be an array but was given ${a.key}`);
    return n.contains;
  }
  return "raw";
}
var Ps = (e, a) => {
  const [t, ...n] = Tr(e, a);
  return (t ? [t, ...n.sort()] : []).map((r) => `${r}(${e[r].map((f) => `${f.name}:${f.type}`)})`).join("");
}, Hs = (e, a) => Ee(Ps(e, a)), Cr = (e, a, t, n = {}) => {
  if (e[a])
    return [a, va(e, a, t)];
  if (Object.keys(e).map((c) => `${c}*`).includes(a)) {
    const c = t.map((r) => va(e, a.slice(0, -1), r));
    return [a, ne(c)];
  }
  if (a === "merkletree") {
    const c = i3(e, n), r = t.map((d) => Cr(e, c, d)[1]), { root: f } = new Ft(r);
    return ["felt", f];
  }
  return a === "felt*" ? ["felt*", ne(t)] : a === "selector" ? ["felt", Ls(t)] : [a, f3(t)];
}, Us = (e, a, t) => {
  const [n, c] = e[a].reduce(
    ([r, f], d) => {
      if (t[d.name] === void 0 || t[d.name] === null)
        throw new Error(`Cannot encode data: missing data for '${d.name}'`);
      const o = t[d.name], [i, s] = Cr(e, d.type, o, {
        parent: a,
        key: d.name
      });
      return [
        [...r, i],
        [...f, s]
      ];
    },
    [["felt"], [Hs(e, a)]]
  );
  return [n, c];
}, va = (e, a, t) => ne(Us(e, a, t)[1]), Ir = (e, a) => {
  if (!d3(e))
    throw new Error("Typed data does not match JSON schema");
  const t = [
    at("StarkNet Message"),
    va(e.types, "StarkNetDomain", e.domain),
    a,
    va(e.types, e.primaryType, e.message)
  ];
  return ne(t);
}, Fs = class {
  constructor(e = Rc.randomPrivateKey()) {
    this.pk = e instanceof Uint8Array ? mi(e) : I(e);
  }
  async getPubKey() {
    return Lc(this.pk);
  }
  async signMessage(e, a) {
    const t = Ir(e, a);
    return ca(t, this.pk);
  }
  async signTransaction(e, a, t) {
    if (t && t.length !== e.length)
      throw new Error("ABI must be provided for each transaction or no transaction");
    const n = bn(e, a.cairoVersion), c = ss(
      a.walletAddress,
      a.version,
      n,
      a.maxFee,
      a.chainId,
      a.nonce
    );
    return ca(c, this.pk);
  }
  async signDeployAccountTransaction({
    classHash: e,
    contractAddress: a,
    constructorCalldata: t,
    addressSalt: n,
    maxFee: c,
    version: r,
    chainId: f,
    nonce: d
  }) {
    const o = is(
      a,
      e,
      $.compile(t),
      n,
      r,
      c,
      f,
      d
    );
    return ca(o, this.pk);
  }
  async signDeclareTransaction({
    classHash: e,
    senderAddress: a,
    chainId: t,
    maxFee: n,
    version: c,
    nonce: r,
    compiledClassHash: f
  }) {
    const d = ds(
      e,
      a,
      c,
      n,
      t,
      r,
      f
    );
    return ca(d, this.pk);
  }
};
function zs(e) {
  if (!e.events)
    throw new Error("UDC emited event is empty");
  const a = e.events.find(
    (t) => mc(t.from_address) === mc(dt.ADDRESS)
  ) || {
    data: []
  };
  return {
    transaction_hash: e.transaction_hash,
    contract_address: a.data[0],
    address: a.data[0],
    deployer: a.data[1],
    unique: a.data[2],
    classHash: a.data[3],
    calldata_len: a.data[4],
    calldata: a.data.slice(5, 5 + parseInt(a.data[4], 16)),
    salt: a.data[a.data.length - 1]
  };
}
var Ms = class extends Sn {
  constructor(e, a, t, n = "0") {
    super(e), this.deploySelf = this.deployAccount, this.address = a.toLowerCase(), this.signer = typeof t == "string" || t instanceof Uint8Array ? new Fs(t) : t, this.cairoVersion = n;
  }
  async getNonce(e) {
    return super.getNonceForAddress(this.address, e);
  }
  async getNonceSafe(e) {
    try {
      return B(e ?? await this.getNonce());
    } catch {
      return 0n;
    }
  }
  async estimateFee(e, a) {
    return this.estimateInvokeFee(e, a);
  }
  async estimateInvokeFee(e, { nonce: a, blockIdentifier: t, skipValidate: n } = {}) {
    const c = Array.isArray(e) ? e : [e], r = B(a ?? await this.getNonce()), f = B(Rt), d = await this.getChainId(), o = {
      walletAddress: this.address,
      nonce: r,
      maxFee: re,
      version: f,
      chainId: d,
      cairoVersion: this.cairoVersion
    }, i = await this.buildInvocation(c, o), s = await super.getInvokeEstimateFee(
      { ...i },
      { version: f, nonce: r },
      t,
      n
    ), b = lt(s.overall_fee);
    return {
      ...s,
      suggestedMaxFee: b
    };
  }
  async estimateDeclareFee({ contract: e, classHash: a, casm: t, compiledClassHash: n }, { blockIdentifier: c, nonce: r, skipValidate: f } = {}) {
    const d = B(r ?? await this.getNonce()), o = ge(e) ? fn : Rt, i = await this.getChainId(), s = await this.buildDeclarePayload(
      { classHash: a, contract: e, casm: t, compiledClassHash: n },
      {
        nonce: d,
        chainId: i,
        version: o,
        walletAddress: this.address,
        maxFee: re,
        cairoVersion: this.cairoVersion
      }
    ), b = await super.getDeclareEstimateFee(
      s,
      { version: o, nonce: d },
      c,
      f
    ), u = lt(b.overall_fee);
    return {
      ...b,
      suggestedMaxFee: u
    };
  }
  async estimateAccountDeployFee({
    classHash: e,
    addressSalt: a = 0,
    constructorCalldata: t = [],
    contractAddress: n
  }, { blockIdentifier: c, skipValidate: r } = {}) {
    const f = B(Rt), d = re, o = await this.getChainId(), i = await this.buildAccountDeployPayload(
      { classHash: e, addressSalt: a, constructorCalldata: t, contractAddress: n },
      {
        nonce: d,
        chainId: o,
        version: f,
        walletAddress: this.address,
        maxFee: re,
        cairoVersion: this.cairoVersion
      }
    ), s = await super.getDeployAccountEstimateFee(
      { ...i },
      { version: f, nonce: d },
      c,
      r
    ), b = lt(s.overall_fee);
    return {
      ...s,
      suggestedMaxFee: b
    };
  }
  async estimateDeployFee(e, a) {
    const t = this.buildUDCContractPayload(e);
    return this.estimateInvokeFee(t, a);
  }
  async estimateFeeBulk(e, { nonce: a, blockIdentifier: t, skipValidate: n } = {}) {
    const c = await this.accountInvocationsFactory(e, {
      versions: [Rt, fn],
      nonce: a,
      blockIdentifier: t
    }), r = await super.getEstimateFeeBulk(c, {
      blockIdentifier: t,
      skipValidate: n
    });
    return [].concat(r).map((f) => {
      const d = lt(f.overall_fee);
      return {
        ...f,
        suggestedMaxFee: d
      };
    });
  }
  async buildInvocation(e, a) {
    const t = bn(e, this.cairoVersion), n = await this.signer.signTransaction(e, a);
    return {
      contractAddress: this.address,
      calldata: t,
      signature: n
    };
  }
  async execute(e, a = void 0, t = {}) {
    const n = Array.isArray(e) ? e : [e], c = B(t.nonce ?? await this.getNonce()), r = t.maxFee ?? await this.getSuggestedMaxFee(
      { type: "INVOKE_FUNCTION", payload: e },
      t
    ), f = B($e), d = await this.getChainId(), o = {
      walletAddress: this.address,
      nonce: c,
      maxFee: r,
      version: f,
      chainId: d,
      cairoVersion: this.cairoVersion
    }, i = await this.signer.signTransaction(n, o, a), s = bn(n, this.cairoVersion);
    return this.invokeFunction(
      { contractAddress: this.address, calldata: s, signature: i },
      {
        nonce: c,
        maxFee: r,
        version: f
      }
    );
  }
  /**
   * First check if contract is already declared, if not declare it
   * If contract already declared returned transaction_hash is ''.
   * Method will pass even if contract is already declared
   * @param payload DeclareContractPayload
   * @param transactionsDetail (optional) InvocationsDetails = \{\}
   * @returns DeclareContractResponse
   */
  async declareIfNot(e, a = {}) {
    const t = Wa(e);
    try {
      await this.getClassByHash(t.classHash);
    } catch {
      return this.declare(e, a);
    }
    return {
      transaction_hash: "",
      class_hash: t.classHash
    };
  }
  async declare(e, a = {}) {
    const t = Wa(e), n = {};
    n.nonce = B(a.nonce ?? await this.getNonce()), n.maxFee = a.maxFee ?? await this.getSuggestedMaxFee(
      {
        type: "DECLARE",
        payload: t
      },
      a
    ), n.version = ge(e.contract) ? mt : $e, n.chainId = await this.getChainId();
    const c = await this.buildDeclarePayload(t, {
      ...n,
      walletAddress: this.address,
      cairoVersion: this.cairoVersion
    });
    return this.declareContract(c, n);
  }
  async deploy(e, a) {
    const t = [].concat(e).map((f) => {
      const {
        classHash: d,
        salt: o,
        unique: i = !0,
        constructorCalldata: s = []
      } = f, b = $.compile(s), u = o ?? Er();
      return {
        call: {
          contractAddress: dt.ADDRESS,
          entrypoint: dt.ENTRYPOINT,
          calldata: [
            d,
            u,
            Ec(i),
            b.length,
            ...b
          ]
        },
        address: Ya(
          i ? Kt(this.address, u) : u,
          d,
          b,
          i ? dt.ADDRESS : 0
        )
      };
    }), n = t.map((f) => f.call), c = t.map((f) => f.address);
    return {
      ...await this.execute(n, void 0, a),
      contract_address: c
    };
  }
  async deployContract(e, a) {
    const t = await this.deploy(e, a), n = await this.waitForTransaction(t.transaction_hash, {
      successStates: [
        "ACCEPTED_ON_L2"
        /* ACCEPTED_ON_L2 */
      ]
    });
    return zs(n);
  }
  async declareAndDeploy(e, a) {
    const { constructorCalldata: t, salt: n, unique: c } = e;
    let r = await this.declareIfNot(e, a);
    if (r.transaction_hash !== "") {
      const d = await this.waitForTransaction(r.transaction_hash, {
        successStates: [
          "ACCEPTED_ON_L2"
          /* ACCEPTED_ON_L2 */
        ]
      });
      r = { ...r, ...d };
    }
    const f = await this.deployContract(
      { classHash: r.class_hash, salt: n, unique: c, constructorCalldata: t },
      a
    );
    return { declare: { ...r }, deploy: f };
  }
  async deployAccount({
    classHash: e,
    constructorCalldata: a = [],
    addressSalt: t = 0,
    contractAddress: n
  }, c = {}) {
    const r = B($e), f = re, d = await this.getChainId(), o = $.compile(a), i = n ?? Ya(t, e, o, 0), s = c.maxFee ?? await this.getSuggestedMaxFee(
      {
        type: "DEPLOY_ACCOUNT",
        payload: {
          classHash: e,
          constructorCalldata: o,
          addressSalt: t,
          contractAddress: i
        }
      },
      c
    ), b = await this.signer.signDeployAccountTransaction({
      classHash: e,
      constructorCalldata: o,
      contractAddress: i,
      addressSalt: t,
      chainId: d,
      maxFee: s,
      version: r,
      nonce: f
    });
    return this.deployAccountContract(
      { classHash: e, addressSalt: t, constructorCalldata: a, signature: b },
      {
        nonce: f,
        maxFee: s,
        version: r
      }
    );
  }
  async signMessage(e) {
    return this.signer.signMessage(e, this.address);
  }
  async hashMessage(e) {
    return Ir(e, this.address);
  }
  async verifyMessageHash(e, a) {
    try {
      return await this.callContract({
        contractAddress: this.address,
        entrypoint: "isValidSignature",
        calldata: $.compile({
          hash: B(e).toString(),
          signature: An(a)
        })
      }), !0;
    } catch {
      return !1;
    }
  }
  async verifyMessage(e, a) {
    const t = await this.hashMessage(e);
    return this.verifyMessageHash(t, a);
  }
  async getSuggestedMaxFee({ type: e, payload: a }, t) {
    let n;
    switch (e) {
      case "INVOKE_FUNCTION":
        n = await this.estimateInvokeFee(a, t);
        break;
      case "DECLARE":
        n = await this.estimateDeclareFee(a, t);
        break;
      case "DEPLOY_ACCOUNT":
        n = await this.estimateAccountDeployFee(a, t);
        break;
      case "DEPLOY":
        n = await this.estimateDeployFee(a, t);
        break;
      default:
        n = { suggestedMaxFee: re, overall_fee: re };
        break;
    }
    return n.suggestedMaxFee;
  }
  /**
   * will be renamed to buildDeclareContractTransaction
   */
  async buildDeclarePayload(e, { nonce: a, chainId: t, version: n, walletAddress: c, maxFee: r }) {
    const { classHash: f, contract: d, compiledClassHash: o } = Wa(e), i = vr(d), s = await this.signer.signDeclareTransaction({
      classHash: f,
      compiledClassHash: o,
      senderAddress: c,
      chainId: t,
      maxFee: r,
      version: n,
      nonce: a
    });
    return {
      senderAddress: c,
      signature: s,
      contract: i,
      compiledClassHash: o
    };
  }
  async buildAccountDeployPayload({
    classHash: e,
    addressSalt: a = 0,
    constructorCalldata: t = [],
    contractAddress: n
  }, { nonce: c, chainId: r, version: f, maxFee: d }) {
    const o = $.compile(t), i = n ?? Ya(a, e, o, 0), s = await this.signer.signDeployAccountTransaction({
      classHash: e,
      contractAddress: i,
      chainId: r,
      maxFee: d,
      version: f,
      nonce: c,
      addressSalt: a,
      constructorCalldata: o
    });
    return {
      classHash: e,
      addressSalt: a,
      constructorCalldata: o,
      signature: s
    };
  }
  buildUDCContractPayload(e) {
    return [].concat(e).map((t) => {
      const {
        classHash: n,
        salt: c = "0",
        unique: r = !0,
        constructorCalldata: f = []
      } = t, d = $.compile(f);
      return {
        contractAddress: dt.ADDRESS,
        entrypoint: dt.ENTRYPOINT,
        calldata: [
          n,
          c,
          Ec(r),
          d.length,
          ...d
        ]
      };
    });
  }
  async simulateTransaction(e, { nonce: a, blockIdentifier: t, skipValidate: n, skipExecute: c } = {}) {
    const r = await this.accountInvocationsFactory(e, {
      versions: [$e, mt],
      nonce: a,
      blockIdentifier: t
    });
    return super.getSimulateTransaction(r, {
      blockIdentifier: t,
      skipValidate: n,
      skipExecute: c
    });
  }
  async accountInvocationsFactory(e, { versions: a, nonce: t, blockIdentifier: n }) {
    const c = a[0], r = await this.getNonceSafe(t), f = await this.getChainId();
    return Promise.all(
      [].concat(e).map(async (d, o) => {
        const i = {
          walletAddress: this.address,
          nonce: B(Number(r) + o),
          maxFee: re,
          version: c,
          chainId: f,
          cairoVersion: this.cairoVersion
        }, s = "payload" in d ? d.payload : d, b = {
          type: d.type,
          version: c,
          nonce: B(Number(r) + o),
          blockIdentifier: n
        };
        if (d.type === "INVOKE_FUNCTION") {
          const u = await this.buildInvocation(
            [].concat(s),
            i
          );
          return {
            ...b,
            ...u
          };
        }
        if (d.type === "DECLARE") {
          i.version = ge(s.contract) ? B(a[1]) : B(a[0]);
          const u = await this.buildDeclarePayload(s, i);
          return {
            ...b,
            ...u,
            version: i.version
          };
        }
        if (d.type === "DEPLOY_ACCOUNT") {
          const u = await this.buildAccountDeployPayload(s, i);
          return {
            ...b,
            ...u
          };
        }
        if (d.type === "DEPLOY") {
          const u = this.buildUDCContractPayload(s), l = await this.buildInvocation(u, i);
          return {
            ...b,
            ...l,
            type: "INVOKE_FUNCTION"
            /* INVOKE */
          };
        }
        throw Error(`accountInvocationsFactory: unsupported transaction type: ${d}`);
      })
    );
  }
  async getStarkName(e = this.address, a) {
    return super.getStarkName(e, a);
  }
}, Zs = class {
}, Vs = new Sn(), s3 = class extends Zs {
}, kn = (e) => {
  const a = [
    "blockIdentifier",
    "parseRequest",
    "parseResponse",
    "formatResponse",
    "maxFee",
    "nonce",
    "signature",
    "addressSalt"
  ], t = e[e.length - 1];
  return typeof t == "object" && a.some((n) => n in t) ? { args: e, options: e.pop() } : { args: e };
};
function js(e, a) {
  return async function(...t) {
    const n = kn(t);
    return e.call(a.name, n.args, {
      parseRequest: !0,
      parseResponse: !0,
      ...n.options
    });
  };
}
function o3(e, a) {
  return async function(...t) {
    const n = kn(t);
    return e.invoke(a.name, n.args, {
      parseRequest: !0,
      ...n.options
    });
  };
}
function Mf(e, a) {
  return a.stateMutability === "view" || a.state_mutability === "view" ? js(e, a) : o3(e, a);
}
function b3(e, a) {
  return function(...t) {
    return e.populate(a.name, t);
  };
}
function l3(e, a) {
  return function(...t) {
    return e.estimate(a.name, t);
  };
}
function Lt(e, a) {
  return Array.isArray(e) && "__compiled__" in e ? e : Array.isArray(e) && Array.isArray(e[0]) && "__compiled__" in e[0] ? e[0] : a();
}
var Ac = class {
  /**
   * Contract class to handle contract methods
   *
   * @param abi - Abi of the contract object
   * @param address (optional) - address to connect to
   * @param providerOrAccount (optional) - Provider or Account to attach to
   */
  constructor(e, a, t = Vs) {
    this.address = a && a.toLowerCase(), this.providerOrAccount = t, this.callData = new $(e), this.structs = $.getAbiStruct(e), this.abi = e;
    const n = { enumerable: !0, value: {}, writable: !1 };
    Object.defineProperties(this, {
      functions: { enumerable: !0, value: {}, writable: !1 },
      callStatic: { enumerable: !0, value: {}, writable: !1 },
      populateTransaction: { enumerable: !0, value: {}, writable: !1 },
      estimateFee: { enumerable: !0, value: {}, writable: !1 }
    }), this.abi.forEach((c) => {
      if (c.type !== "function")
        return;
      const r = c.name;
      this[r] || Object.defineProperty(this, r, {
        ...n,
        value: Mf(this, c)
      }), this.functions[r] || Object.defineProperty(this.functions, r, {
        ...n,
        value: Mf(this, c)
      }), this.callStatic[r] || Object.defineProperty(this.callStatic, r, {
        ...n,
        value: js(this, c)
      }), this.populateTransaction[r] || Object.defineProperty(this.populateTransaction, r, {
        ...n,
        value: b3(this, c)
      }), this.estimateFee[r] || Object.defineProperty(this.estimateFee, r, {
        ...n,
        value: l3(this, c)
      });
    });
  }
  attach(e) {
    this.address = e;
  }
  connect(e) {
    this.providerOrAccount = e;
  }
  async deployed() {
    return this.deployTransactionHash && (await this.providerOrAccount.waitForTransaction(this.deployTransactionHash), this.deployTransactionHash = void 0), this;
  }
  async call(e, a = [], {
    parseRequest: t = !0,
    parseResponse: n = !0,
    formatResponse: c = void 0,
    blockIdentifier: r = void 0
  } = {}) {
    V(this.address !== null, "contract is not connected to an address");
    const f = Lt(a, () => t ? (this.callData.validate("CALL", e, a), this.callData.compile(e, a)) : (console.warn("Call skipped parsing but provided rawArgs, possible malfunction request"), a));
    return this.providerOrAccount.callContract(
      {
        contractAddress: this.address,
        calldata: f,
        entrypoint: e
      },
      r
    ).then((d) => n ? c ? this.callData.format(e, d.result, c) : this.callData.parse(e, d.result) : d.result);
  }
  invoke(e, a = [], { parseRequest: t = !0, maxFee: n, nonce: c, signature: r } = {}) {
    V(this.address !== null, "contract is not connected to an address");
    const f = Lt(a, () => t ? (this.callData.validate("INVOKE", e, a), this.callData.compile(e, a)) : (console.warn("Invoke skipped parsing but provided rawArgs, possible malfunction request"), a)), d = {
      contractAddress: this.address,
      calldata: f,
      entrypoint: e
    };
    if ("execute" in this.providerOrAccount)
      return this.providerOrAccount.execute(d, void 0, {
        maxFee: n,
        nonce: c
      });
    if (!c)
      throw new Error("Nonce is required when invoking a function without an account");
    return console.warn(`Invoking ${e} without an account. This will not work on a public node.`), this.providerOrAccount.invokeFunction(
      {
        ...d,
        signature: r
      },
      {
        nonce: c
      }
    );
  }
  async estimate(e, a = []) {
    V(this.address !== null, "contract is not connected to an address"), Lt(a, () => !1) || this.callData.validate("INVOKE", e, a);
    const t = this.populate(e, a);
    if ("estimateInvokeFee" in this.providerOrAccount)
      return this.providerOrAccount.estimateInvokeFee(t);
    throw Error("Contract must be connected to the account contract to estimate");
  }
  populate(e, a = []) {
    const t = Lt(a, () => this.callData.compile(e, a));
    return {
      contractAddress: this.address,
      entrypoint: e,
      calldata: t
    };
  }
  isCairo1() {
    return br.isCairo1Abi(this.abi);
  }
}, u3 = class {
}, h3 = class {
  constructor(e, a, t, n = e.abi) {
    this.abi = n, this.compiledContract = e, this.account = t, this.classHash = a, this.CallData = new $(n);
  }
  /**
   * Deploys contract and returns new instance of the Contract
   *
   * @param args - Array of the constructor arguments for deployment
   * @param options (optional) Object - parseRequest, parseResponse, addressSalt
   * @returns deployed Contract
   */
  async deploy(...e) {
    const { args: a, options: t = { parseRequest: !0 } } = kn(e), n = Lt(a, () => t.parseRequest ? (this.CallData.validate("DEPLOY", "constructor", a), this.CallData.compile("constructor", a)) : (console.warn("Call skipped parsing but provided rawArgs, possible malfunction request"), a)), {
      deploy: { contract_address: c, transaction_hash: r }
    } = await this.account.declareAndDeploy({
      contract: this.compiledContract,
      constructorCalldata: n,
      salt: t.addressSalt
    });
    V(!!c, "Deployment of the contract failed");
    const f = new Ac(
      this.compiledContract.abi,
      c,
      this.account
    );
    return f.deployTransactionHash = r, f;
  }
  /**
   * Attaches to new Account
   *
   * @param account - new Provider or Account to attach to
   * @returns ContractFactory
   */
  connect(e) {
    return this.account = e, this;
  }
  /**
   * Attaches current abi and account to the new address
   *
   * @param address - Contract address
   * @returns Contract
   */
  attach(e) {
    return new Ac(this.abi, e, this.account);
  }
  // ethers.js' getDeployTransaction cant be supported as it requires the account or signer to return a signed transaction which is not possible with the current implementation
};
function qs(e) {
  return ee(Ue(I(e)).padStart(64, "0"));
}
function Ks(e) {
  Di(e, re, Si, "Starknet Address");
  const a = qs(e);
  if (!a.match(/^(0x)?[0-9a-fA-F]{64}$/))
    throw new Error("Invalid Address Format");
  return a;
}
function Gs(e) {
  const a = Ue(Ks(e)).toLowerCase().split(""), t = Ue(cr(e)), n = He(t.padStart(64, "0"));
  for (let c = 0; c < a.length; c += 2)
    n[c >> 1] >> 4 >= 8 && (a[c] = a[c].toUpperCase()), (n[c >> 1] & 15) >= 8 && (a[c + 1] = a[c + 1].toUpperCase());
  return ee(a.join(""));
}
function p3(e) {
  return Gs(e) === e;
}
var _3 = tr;
const g3 = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  Account: Ms,
  AccountInterface: s3,
  CallData: $,
  Contract: Ac,
  ContractFactory: h3,
  ContractInterface: u3,
  CustomError: Es,
  EntryPointType: Jc,
  GatewayError: vs,
  HttpError: xs,
  LibraryError: qt,
  Provider: Sn,
  ProviderInterface: Zs,
  get RPC() {
    return Ae;
  },
  RpcProvider: on,
  SIMULATION_FLAG: Xc,
  SequencerProvider: Ut,
  Signer: Fs,
  SignerInterface: n3,
  TransactionStatus: Qc,
  TransactionType: er,
  addAddressPadding: qs,
  buildUrl: Bt,
  cairo: br,
  constants: pi,
  contractClassResponseToLegacyCompiledContract: G6,
  defaultProvider: Vs,
  ec: cs,
  encode: _i,
  extractContractHashes: Wa,
  fixProto: ms,
  fixStack: ws,
  getCalldata: Lt,
  getChecksumAddress: Gs,
  hash: ns,
  isSierra: ge,
  isUrl: Cs,
  json: rs,
  merkle: Rs,
  num: tr,
  number: _3,
  parseUDCEvent: zs,
  provider: gs,
  selector: Fi,
  shortString: zi,
  splitArgsAndOptions: kn,
  stark: ps,
  starknetId: As,
  transaction: Is,
  typedData: Bs,
  types: Oi,
  uint256: Vi,
  validateAndParseAddress: Ks,
  validateChecksumAddress: p3
}, Symbol.toStringTag, { value: "Module" }));
var Xa = {}, Ys = {}, Tn = {};
const y3 = /* @__PURE__ */ n6(g3);
var Cn = {};
Object.defineProperty(Cn, "__esModule", { value: !0 });
Cn.Provider = void 0;
class w3 {
  /**
   * Constructor: Initializes the Provider with a given world address.
   *
   * @param {string} worldAddress - The address of the world.
   */
  constructor(a) {
    // Store the address of the world.
    ct(this, "worldAddress");
    this.worldAddress = a;
  }
  /**
   * Retrieves the stored world address.
   *
   * @returns {string} - The address of the world.
   */
  getWorldAddress() {
    return this.worldAddress;
  }
}
Cn.Provider = w3;
var La = {};
Object.defineProperty(La, "__esModule", { value: !0 });
La.WorldEntryPoints = void 0;
var Zf;
(function(e) {
  e.get = "entity", e.set = "set_entity", e.entities = "entities", e.execute = "execute", e.register_system = "register_system", e.register_component = "register_component", e.component = "component", e.system = "system";
})(Zf || (La.WorldEntryPoints = Zf = {}));
var le = {};
Object.defineProperty(le, "__esModule", { value: !0 });
le.getAllSystemNamesAsFelt = le.getAllSystemNames = le.getAllComponentNamesAsFelt = le.getAllComponentNames = le.strTofelt252Felt = void 0;
function Nr(e) {
  const t = new TextEncoder().encode(e);
  return BigInt(t.reduce((n, c) => (n += c.toString(16), n), "0x")).toString();
}
le.strTofelt252Felt = Nr;
function m3(e) {
  return e.components.map((a) => a.name);
}
le.getAllComponentNames = m3;
function E3(e) {
  return e.components.map((a) => Nr(a.name));
}
le.getAllComponentNamesAsFelt = E3;
function v3(e) {
  return e.systems.map((a) => a.name);
}
le.getAllSystemNames = v3;
function x3(e) {
  return e.systems.map((a) => Nr(a.name));
}
le.getAllSystemNamesAsFelt = x3;
var fe = {};
Object.defineProperty(fe, "__esModule", { value: !0 });
fe.ACCOUNT_CLASS_HASH = fe.DOJO_STARTER_WORLD = fe.LOCAL_TORII = fe.LOCAL_KATANA = fe.KATANA_ACCOUNT_1_PRIVATEKEY = fe.KATANA_ACCOUNT_1_ADDRESS = void 0;
fe.KATANA_ACCOUNT_1_ADDRESS = "0x3ee9e18edc71a6df30ac3aca2e0b02a198fbce19b7480a63a0d71cbd76652e0";
fe.KATANA_ACCOUNT_1_PRIVATEKEY = "0x300001800000000300000180000000000030000000000003006001800006600";
fe.LOCAL_KATANA = "http://127.0.0.1:5050";
fe.LOCAL_TORII = "http://localhost:8080";
fe.DOJO_STARTER_WORLD = "0x26065106fa319c3981618e7567480a50132f23932226a51c219ffb8e47daa84";
fe.ACCOUNT_CLASS_HASH = "0x04d07e40e93398ed3c76981e72dd1fd22557a78ce36c0515f679e27f0bb5bc5f";
const A3 = [
  {
    type: "function",
    name: "component",
    inputs: [
      {
        name: "name",
        type: "core::felt252"
      }
    ],
    outputs: [
      {
        type: "core::starknet::class_hash::ClassHash"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "register_component",
    inputs: [
      {
        name: "class_hash",
        type: "core::starknet::class_hash::ClassHash"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "system",
    inputs: [
      {
        name: "name",
        type: "core::felt252"
      }
    ],
    outputs: [
      {
        type: "core::starknet::class_hash::ClassHash"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "register_system",
    inputs: [
      {
        name: "class_hash",
        type: "core::starknet::class_hash::ClassHash"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "uuid",
    inputs: [],
    outputs: [
      {
        type: "core::integer::u32"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "emit",
    inputs: [
      {
        name: "keys",
        type: "core::array::Span::<core::felt252>"
      },
      {
        name: "values",
        type: "core::array::Span::<core::felt252>"
      }
    ],
    outputs: [],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "execute",
    inputs: [
      {
        name: "system",
        type: "core::felt252"
      },
      {
        name: "calldata",
        type: "core::array::Array::<core::felt252>"
      }
    ],
    outputs: [
      {
        type: "core::array::Array::<core::felt252>"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "entity",
    inputs: [
      {
        name: "component",
        type: "core::felt252"
      },
      {
        name: "query",
        type: "dojo::database::query::Query"
      },
      {
        name: "offset",
        type: "core::integer::u8"
      },
      {
        name: "length",
        type: "core::integer::u32"
      }
    ],
    outputs: [
      {
        type: "core::array::Span::<core::felt252>"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "set_entity",
    inputs: [
      {
        name: "component",
        type: "core::felt252"
      },
      {
        name: "query",
        type: "dojo::database::query::Query"
      },
      {
        name: "offset",
        type: "core::integer::u8"
      },
      {
        name: "value",
        type: "core::array::Span::<core::felt252>"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "entities",
    inputs: [
      {
        name: "component",
        type: "core::felt252"
      },
      {
        name: "partition",
        type: "core::felt252"
      },
      {
        name: "length",
        type: "core::integer::u32"
      }
    ],
    outputs: [
      {
        type: "(core::array::Span::<core::felt252>, core::array::Span::<core::array::Span::<core::felt252>>)"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "set_executor",
    inputs: [
      {
        name: "contract_address",
        type: "core::starknet::contract_address::ContractAddress"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "executor",
    inputs: [],
    outputs: [
      {
        type: "core::starknet::contract_address::ContractAddress"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "delete_entity",
    inputs: [
      {
        name: "component",
        type: "core::felt252"
      },
      {
        name: "query",
        type: "dojo::database::query::Query"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "origin",
    inputs: [],
    outputs: [
      {
        type: "core::starknet::contract_address::ContractAddress"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "is_owner",
    inputs: [
      {
        name: "account",
        type: "core::starknet::contract_address::ContractAddress"
      },
      {
        name: "target",
        type: "core::felt252"
      }
    ],
    outputs: [
      {
        type: "core::bool"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "grant_owner",
    inputs: [
      {
        name: "account",
        type: "core::starknet::contract_address::ContractAddress"
      },
      {
        name: "target",
        type: "core::felt252"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "revoke_owner",
    inputs: [
      {
        name: "account",
        type: "core::starknet::contract_address::ContractAddress"
      },
      {
        name: "target",
        type: "core::felt252"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "is_writer",
    inputs: [
      {
        name: "component",
        type: "core::felt252"
      },
      {
        name: "system",
        type: "core::felt252"
      }
    ],
    outputs: [
      {
        type: "core::bool"
      }
    ],
    state_mutability: "view"
  },
  {
    type: "function",
    name: "grant_writer",
    inputs: [
      {
        name: "component",
        type: "core::felt252"
      },
      {
        name: "system",
        type: "core::felt252"
      }
    ],
    outputs: [],
    state_mutability: "external"
  },
  {
    type: "function",
    name: "revoke_writer",
    inputs: [
      {
        name: "component",
        type: "core::felt252"
      },
      {
        name: "system",
        type: "core::felt252"
      }
    ],
    outputs: [],
    state_mutability: "external"
  }
];
var S3 = bt && bt.__importDefault || function(e) {
  return e && e.__esModule ? e : { default: e };
};
Object.defineProperty(Tn, "__esModule", { value: !0 });
Tn.RPCProvider = void 0;
const Vf = y3, k3 = Cn, qa = La, na = le, T3 = fe, C3 = S3(A3);
class I3 extends k3.Provider {
  /**
   * Constructor: Initializes the RPCProvider with the given world address and URL.
   *
   * @param {string} world_address - Address of the world.
   * @param {string} [url=LOCAL_KATANA] - RPC URL (defaults to LOCAL_KATANA).
   */
  constructor(t, n = T3.LOCAL_KATANA) {
    super(t);
    ct(this, "provider");
    ct(this, "contract");
    this.provider = new Vf.RpcProvider({
      nodeUrl: n
    }), this.contract = new Vf.Contract(C3.default, this.getWorldAddress(), this.provider);
  }
  /**
   * Retrieves a single entity's details.
   *
   * @param {string} component - The component to query.
   * @param {Query} query - The query details.
   * @param {number} [offset=0] - Starting offset (defaults to 0).
   * @param {number} [length=0] - Length to retrieve (defaults to 0).
   * @returns {Promise<Array<bigint>>} - A promise that resolves to an array of bigints representing the entity's details.
   */
  async entity(t, n, c = 0, r = 0) {
    const f = {
      entrypoint: qa.WorldEntryPoints.get,
      contractAddress: this.getWorldAddress(),
      calldata: [
        (0, na.strTofelt252Felt)(t),
        n.address_domain,
        n.keys.length,
        ...n.keys,
        c,
        r
      ]
    };
    try {
      return (await this.provider.callContract(f)).result;
    } catch (d) {
      throw d;
    }
  }
  /**
   * Retrieves multiple entities' details.
   *
   * @param {string} component - The component to query.
   * @param {number} length - Number of entities to retrieve.
   * @returns {Promise<Array<bigint>>} - A promise that resolves to an array of bigints representing the entities' details.
   */
  async entities(t, n) {
    const c = {
      entrypoint: qa.WorldEntryPoints.entities,
      contractAddress: this.getWorldAddress(),
      calldata: [(0, na.strTofelt252Felt)(t), n]
    };
    try {
      return (await this.provider.callContract(c)).result;
    } catch (r) {
      throw r;
    }
  }
  /**
   * Retrieves a component's details.
   *
   * @param {string} name - Name of the component.
   * @returns {Promise<bigint>} - A promise that resolves to a bigint representing the component's details.
   */
  async component(t) {
    const n = {
      entrypoint: qa.WorldEntryPoints.component,
      contractAddress: this.getWorldAddress(),
      calldata: [(0, na.strTofelt252Felt)(t)]
    };
    try {
      return (await this.provider.callContract(n)).result;
    } catch (c) {
      throw c;
    }
  }
  /**
   * Executes a function with the given parameters.
   *
   * @param {Account} account - The account to use.
   * @param {string} system - The system name to execute.
   * @param {num.BigNumberish[]} call_data - The call data for the function.
   * @returns {Promise<InvokeFunctionResponse>} - A promise that resolves to the response of the function execution.
   */
  async execute(t, n, c) {
    try {
      const r = await (t == null ? void 0 : t.getNonce());
      return await (t == null ? void 0 : t.execute({
        contractAddress: this.getWorldAddress() || "",
        entrypoint: qa.WorldEntryPoints.execute,
        calldata: [(0, na.strTofelt252Felt)(n), c.length, ...c]
      }, void 0, {
        nonce: r,
        maxFee: 0
        // TODO: Update this value as needed.
      }));
    } catch (r) {
      throw r;
    }
  }
  /**
   * Calls a function with the given parameters.
   *
   * @param {string} selector - The selector of the function.
   * @param {num.BigNumberish[]} call_data - The call data for the function.
   * @returns {Promise<CallContractResponse>} - A promise that resolves to the response of the function call.
   * @throws {Error} - Throws an error if the call fails.
   *
   * @example
   * const response = await provider.call("position", [1, 2, 3]);
   * console.log(response.result);
   * // => 6
   *
   */
  async call(t, n) {
    try {
      return await this.contract.call("execute", [(0, na.strTofelt252Felt)(t), n]);
    } catch (c) {
      throw c;
    }
  }
}
Tn.RPCProvider = I3;
(function(e) {
  Object.defineProperty(e, "__esModule", { value: !0 }), e.RPCProvider = void 0;
  var a = Tn;
  Object.defineProperty(e, "RPCProvider", { enumerable: !0, get: function() {
    return a.RPCProvider;
  } });
})(Ys);
(function(e) {
  var a = bt && bt.__createBinding || (Object.create ? function(c, r, f, d) {
    d === void 0 && (d = f);
    var o = Object.getOwnPropertyDescriptor(r, f);
    (!o || ("get" in o ? !r.__esModule : o.writable || o.configurable)) && (o = { enumerable: !0, get: function() {
      return r[f];
    } }), Object.defineProperty(c, d, o);
  } : function(c, r, f, d) {
    d === void 0 && (d = f), c[d] = r[f];
  }), t = bt && bt.__exportStar || function(c, r) {
    for (var f in c)
      f !== "default" && !Object.prototype.hasOwnProperty.call(r, f) && a(r, c, f);
  };
  Object.defineProperty(e, "__esModule", { value: !0 }), e.RPCProvider = void 0;
  var n = Ys;
  Object.defineProperty(e, "RPCProvider", { enumerable: !0, get: function() {
    return n.RPCProvider;
  } }), t(le, e), t(La, e);
})(Xa);
class Ws {
  constructor(a, t, n) {
    ct(this, "account");
    ct(this, "provider");
    ct(this, "world");
    this.world = t, this.account = a, this.provider = new Xa.RPCProvider(t, n);
  }
  static fromCredentials(a) {
    const t = new on({ nodeUrl: a.nodeUrl || "http://localhost:5050" }), n = new Ms(t, a.accountAddress, a.accountPrivateKey);
    return new Ws(n, a.worldAddress, a.nodeUrl || "http://localhost:5050");
  }
  execute(a, t = []) {
    return this.provider.execute(this.account, a, t);
  }
  call(a, t = []) {
    return t = [Xa.strTofelt252Felt(a), t.length, ...t], this.account.callContract({
      contractAddress: this.world,
      calldata: t,
      entrypoint: "execute"
    });
  }
  async entity(a, t, n = 0, c = 1) {
    const r = typeof t != "object" ? [t] : t, f = [Xa.strTofelt252Felt(a), r.length, ...r, n.toString(), c.toString()];
    let { result: d } = await this.account.callContract({
      contractAddress: this.world,
      calldata: f,
      entrypoint: "entity"
    });
    return d;
  }
}
export {
  Ws as default
};
