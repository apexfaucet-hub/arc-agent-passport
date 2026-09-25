'use strict';
// SAFE FETCH FOR URLS A STRANGER WROTE (2026-09-25)
//
// The Arc agent watchtower (core/arc/agent-watch.js) calls every endpoint that every agent in Arc's ERC-8004
// registry publishes. Those URLs are text somebody else wrote (CLAUDE.md §4b): one agent already lists
// http://localhost:8787 as an endpoint, and a hostile one could list 127.0.0.1:3000, where our own internal
// routes live, or a name that resolves to it. So nothing here trusts the string:
//   - the checks are lib/web-read.js's, which an independent audit has already broken once and we fixed
//     (every resolved address is checked, IPv6 by its 16 bytes, only global unicast allowed);
//   - the connection is PINNED to the address that passed the check, so DNS cannot answer differently twice;
//   - this machine's own public addresses are refused too: a request to our own IP comes back in over the
//     loopback interface, where the firewall's Cloudflare-only rule does not apply;
//   - every redirect hop is re-checked; POST never follows a redirect;
//   - size and time are capped, and the reply is data: it is returned as text, never run or rendered.
// It never throws. Every failure comes back as { ok: false, error, code } so a caller can record it.
const net = require('net');
const os = require('os');
const zlib = require('zlib');
const { isBlockedIp, assertPublic } = require('./address-guard.js');

const UA = process.env.FETCH_UA || 'arc-agent-passport/1.0 (+https://github.com/apexfaucet-hub/arc-agent-passport)';

function canonIp(ip) {
  const s = String(ip || '').replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIPv6(s)) { try { return new URL('http://[' + s + ']/').hostname.replace(/^\[|\]$/g, ''); } catch (e) { return s.toLowerCase(); } }
  return s;
}
let _own = null;
function ownAddresses() {
  if (_own) return _own;
  const s = new Set();
  try {
    for (const list of Object.values(os.networkInterfaces())) for (const a of (list || [])) if (!a.internal) s.add(canonIp(a.address));
  } catch (e) { /* no interfaces readable: the private-range check still applies */ }
  _own = s;
  return s;
}

// A few named failures a report can explain in plain words.
function codeOf(e) {
  const m = String((e && (e.code || e.message)) || '');
  if (/timeout|ETIMEDOUT|aborted/i.test(m)) return 'timeout';
  if (/ENOTFOUND|EAI_AGAIN|does not resolve/i.test(m)) return 'dns';
  if (/ECONNREFUSED/i.test(m)) return 'refused';
  if (/ECONNRESET|socket hang up|EPIPE/i.test(m)) return 'reset';
  if (/CERT|certificate|SSL|TLS|self.signed|UNABLE_TO_VERIFY/i.test(m)) return 'tls';
  if (/private|loopback|our own/i.test(m)) return 'private';
  if (/only http/i.test(m)) return 'scheme';
  if (/not a URL/i.test(m)) return 'url';
  return 'error';
}

async function approve(urlStr, opts) {
  const u = await assertPublic(urlStr);          // throws on scheme, DNS failure, or any private address
  const own = ownAddresses();
  for (const a of (u.__approvedAddrs || [])) {
    if (own.has(canonIp(a))) throw new Error('that address is our own server and will not be fetched');
  }
  return u;
}

// The test suite runs a local server; production never passes _testPins. A pin maps "host:port" to 127.0.0.1
// and applies ONLY to exactly that host:port, so the escape hatch cannot widen into "loopback allowed".
async function approveOrPin(urlStr, opts) {
  const pins = opts && opts._testPins;
  if (pins) {
    let u; try { u = new URL(urlStr); } catch (e) { throw new Error('that is not a URL'); }
    const k = u.hostname + ':' + (u.port || (u.protocol === 'https:' ? 443 : 80));
    if (pins[k]) { u.__approvedAddrs = [pins[k]]; return u; }
  }
  return approve(urlStr, opts);
}

function once(u, o, deadline) {
  return new Promise((resolve) => {
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? require('https') : require('http');
    const approved = u.__approvedAddrs || [];
    if (!approved.length) return resolve({ error: new Error('no validated address to connect to') });
    const body = o.body == null ? null : Buffer.from(typeof o.body === 'string' ? o.body : JSON.stringify(o.body));
    const headers = Object.assign({ 'User-Agent': UA, Accept: '*/*', 'Accept-Encoding': 'gzip, deflate, br', Host: u.host }, o.headers || {});
    if (body) headers['Content-Length'] = String(body.length);
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; clearTimeout(timer); resolve(v); } };
    const started = Date.now();
    const req = mod.request({
      protocol: u.protocol, hostname: u.hostname, port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search, method: o.method || 'GET', headers,
      lookup: (hostname, lo, cb) => {
        const done = typeof lo === 'function' ? lo : cb;
        if (typeof lo !== 'function' && lo && lo.all) return done(null, approved.map((a) => ({ address: a, family: net.isIPv6(a) ? 6 : 4 })));
        return done(null, approved[0], net.isIPv6(approved[0]) ? 6 : 4);
      },
      servername: isHttps && !net.isIP(u.hostname) ? u.hostname : undefined,
    }, (res) => {
      const ttfb = Date.now() - started;
      let stream = res;
      const enc = String(res.headers['content-encoding'] || '').toLowerCase();
      try {
        if (enc === 'gzip' || enc === 'x-gzip') stream = res.pipe(zlib.createGunzip());
        else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
        else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());
      } catch (e) { stream = res; }
      const chunks = []; let total = 0; let truncated = false;
      const stopAt = o.stopOn instanceof RegExp ? o.stopOn : null;
      const end = () => finish({ status: res.statusCode, headers: res.headers, buf: Buffer.concat(chunks), truncated, ttfb, ms: Date.now() - started });
      stream.on('data', (d) => {
        if (truncated) return;
        total += d.length;
        if (total > o.maxBytes) { chunks.push(d.slice(0, Math.max(0, d.length - (total - o.maxBytes)))); truncated = true; try { req.destroy(); } catch (e) {} return end(); }
        chunks.push(d);
        // Streaming replies (an old MCP server's event stream) never end on their own: stop once we have seen enough.
        if (stopAt && stopAt.test(Buffer.concat(chunks).toString('utf8'))) { try { req.destroy(); } catch (e) {} return end(); }
      });
      stream.on('end', end);
      stream.on('error', (e) => (chunks.length ? end() : finish({ error: e, status: res.statusCode, headers: res.headers, ms: Date.now() - started })));
    });
    const timer = setTimeout(() => { try { req.destroy(new Error('timeout')); } catch (e) {} finish({ error: new Error('timeout'), ms: Date.now() - started }); },
      Math.max(1, deadline - Date.now()));
    req.on('error', (e) => finish({ error: e, ms: Date.now() - started }));
    if (body) req.write(body);
    req.end();
  });
}

// safeFetch(url, { method, headers, body, timeoutMs, maxBytes, maxRedirects, stopOn })
//   -> { ok, status, headers, text, bytes, truncated, finalUrl, hops, ms, ttfbMs, error, code }
async function safeFetch(url, opts) {
  const o = Object.assign({ method: 'GET', timeoutMs: 10000, maxBytes: 262144, maxRedirects: 3 }, opts || {});
  const started = Date.now();
  const deadline = started + o.timeoutMs;
  const hops = [];
  let u;
  try { u = await approveOrPin(String(url || '').trim(), o); }
  catch (e) { return { ok: false, error: String(e.message || e).slice(0, 160), code: codeOf(e), hops, ms: Date.now() - started, finalUrl: String(url || '') }; }
  for (let i = 0; ; i++) {
    const r = await once(u, o, deadline);
    if (r.error) return { ok: false, status: r.status || null, error: String(r.error.message || r.error).slice(0, 160), code: codeOf(r.error), hops, ms: Date.now() - started, finalUrl: u.toString() };
    hops.push({ url: u.toString(), status: r.status });
    const loc = r.headers && r.headers.location;
    if (r.status >= 300 && r.status < 400 && loc && String(o.method).toUpperCase() === 'GET') {
      if (i >= o.maxRedirects) return { ok: false, status: r.status, error: 'too many redirects', code: 'redirects', hops, ms: Date.now() - started, finalUrl: u.toString() };
      let next;
      try { next = await approveOrPin(new URL(loc, u).toString(), o); }
      catch (e) { return { ok: false, status: r.status, error: 'redirect refused: ' + String(e.message || e).slice(0, 120), code: codeOf(e), hops, ms: Date.now() - started, finalUrl: u.toString() }; }
      u = next;
      continue;
    }
    const text = r.buf ? r.buf.toString('utf8') : '';
    // buf: the raw body, for callers that need binary (a picture); text is its utf8 reading.
    return { ok: r.status >= 200 && r.status < 300, status: r.status, headers: r.headers || {}, text, buf: r.buf || null, bytes: r.buf ? r.buf.length : 0,
      truncated: !!r.truncated, finalUrl: u.toString(), hops, ms: Date.now() - started, ttfbMs: r.ttfb == null ? null : r.ttfb };
  }
}

// Just the address check, for callers that only need to know whether a URL may be contacted at all.
async function checkUrl(url) {
  try { const u = await approve(String(url || '').trim()); return { ok: true, addrs: u.__approvedAddrs }; }
  catch (e) { return { ok: false, error: String(e.message || e).slice(0, 160), code: codeOf(e) }; }
}

module.exports = { safeFetch, checkUrl, isBlockedIp, ownAddresses, UA };
