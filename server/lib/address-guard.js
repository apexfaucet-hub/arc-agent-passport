'use strict';
// Address checks for URLs a stranger wrote: only public addresses are ever contacted (every resolved address is checked,
// IPv6 by its 16 bytes, and only global unicast 2000::/3 is allowed). Extracted from the live service's web reader.
const dnsp = require('dns').promises;
const net = require('net');

function isBlockedIp(ip) {
  if (!ip) return true;
  if (net.isIPv4(ip)) {
    const p = ip.split('.').map(Number);
    if (p[0] === 127) return true;                        // loopback
    if (p[0] === 10) return true;                         // private
    if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
    if (p[0] === 192 && p[1] === 168) return true;
    if (p[0] === 169 && p[1] === 254) return true;        // link-local, incl. cloud metadata 169.254.169.254
    if (p[0] === 0) return true;
    if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true;  // carrier NAT
    if (p[0] >= 224) return true;                         // multicast and reserved
    return false;
  }
  // IPv6. The earlier version matched STRINGS, and an independent audit broke it in one line on 2026-09-17:
  // "::ffff:7f00:1" is the hex spelling of the IPv4-mapped ::ffff:127.0.0.1. It does not start with a blocked
  // prefix, and slicing off "::ffff:" leaves "7f00:1" which is not a v4 literal, so it was ALLOWED and reached
  // 127.0.0.1:3000 and several other loopback-only daemons. Verified live before this fix.
  //
  // String prefixes cannot be made safe here: the same address has many spellings, and 64:ff9b::/96 (NAT64) and
  // ::ffff:a9fe:a9fe (cloud metadata) are more of the same. So the address is expanded to its 16 bytes and we
  // ALLOW ONLY global unicast (2000::/3). Everything else - loopback, unspecified, link-local, unique-local,
  // multicast, mapped, NAT64 and anything unrecognised - is refused. An allowlist cannot be walked around by
  // finding one more notation.
  const bytes = ipv6Bytes(String(ip));
  if (!bytes) return true;                                  // unparseable is refused, never allowed
  // Any embedded IPv4 (::ffff:a.b.c.d in any spelling, and NAT64 64:ff9b::/96) is judged as that IPv4.
  const isMapped = bytes.slice(0, 10).every((b) => b === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  const isNat64 = bytes[0] === 0x00 && bytes[1] === 0x64 && bytes[2] === 0xff && bytes[3] === 0x9b;
  if (isMapped || isNat64) return isBlockedIp(bytes.slice(12).join('.'));
  return (bytes[0] & 0xe0) !== 0x20;                        // not 2000::/3 -> not global unicast -> blocked
}

// Expand any IPv6 spelling to 16 bytes. Returns null if it is not a valid address, and null is treated as
// blocked by the caller: we refuse what we cannot understand rather than letting it through.
function ipv6Bytes(str) {
  let s = String(str || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (s.includes('%')) s = s.split('%')[0];                 // strip zone id
  if (!s || !net.isIPv6(s)) return null;
  let tail4 = null;
  const lastColon = s.lastIndexOf(':');
  const lastPart = s.slice(lastColon + 1);
  if (lastPart.includes('.')) {                             // trailing dotted-quad form
    if (!net.isIPv4(lastPart)) return null;
    tail4 = lastPart.split('.').map(Number);
    s = s.slice(0, lastColon + 1) + '0:0';
  }
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':').filter((x) => x !== '') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':').filter((x) => x !== '') : [];
  const groups = halves.length === 2
    ? head.concat(new Array(8 - head.length - tail.length).fill('0'), tail)
    : head;
  if (groups.length !== 8) return null;
  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
    const v = parseInt(g, 16);
    out.push((v >> 8) & 0xff, v & 0xff);
  }
  if (tail4) { out[12] = tail4[0]; out[13] = tail4[1]; out[14] = tail4[2]; out[15] = tail4[3]; }
  return out;
}

// Resolve ONCE, check, and hand back the exact addresses that were approved, so the connection can be pinned to
// them. Without pinning, assertPublic() and fetch() each do their own lookup, and a hostile domain with a short
// TTL can answer with a public address for the check and 127.0.0.1 for the fetch - classic DNS rebinding.
// Raised by an independent audit on 2026-09-17 as structural rather than reproduced; the shape is the known
// vulnerable one, so it is closed rather than argued with.
async function assertPublic(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch (e) { throw new Error('that is not a URL'); }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('only http and https are fetched');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  let addrs = [];
  if (net.isIP(host)) addrs = [host];
  else {
    try { addrs = (await dnsp.lookup(host, { all: true })).map((a) => a.address); }
    catch (e) { throw new Error('that hostname does not resolve'); }
  }
  if (!addrs.length) throw new Error('that hostname does not resolve');
  for (const a of addrs) {
    if (isBlockedIp(a)) throw new Error('that address is on a private or loopback network and will not be fetched');
  }
  u.__approvedAddrs = addrs;
  return u;
}


module.exports = { isBlockedIp, assertPublic };
