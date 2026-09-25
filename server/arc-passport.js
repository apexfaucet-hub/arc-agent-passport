// Arc Agent Passport - open source copy of the server module running at https://apexfaucet.xyz/arc/passport/ (MIT).
// Mount it on an Express app: require('./arc-passport.js')(app, express, { gate }) - see README.md.
'use strict';
// ARC AGENT PASSPORT (2026-09-25). An ERC-8004 identity on Arc for any agent, in one minute.
//
// Why: an agent on Arc needs an identity that its owner holds, a registration file that parses, and endpoints that
// answer. This does all three without ever holding anyone's key:
//   FREE (self-mint): we write a correct registration file and host it; the owner's own wallet sends register(uri), so
//     the identity is theirs from the first block and agentWallet is their address. Gas is ~0.002 USDC, which one
//     claim at our Arc faucet covers.
//   PAID (done for you, an agent paying for itself): POST /api/x402/arc-passport, priced in lib/prices.js. The identity is
//     minted by our passport wallet and handed to the address that PAID - proven by its signature, never typed - with
//     transferFrom (safeTransferFrom would revert on a contract wallet without an ERC-721 receiver).
// Every passport agent is then checked every hour by the watchtower, gets its weekly uptime written on chain once it
// has endpoints that answer, and a tower in Arc City. An agent with no endpoint that answers is written active:false,
// honestly: 51 agents on Arc point their registration at one JPEG, and we do not add to that.
//
//   GET  /arc/passport/a/<slug>.json      the registration file (the agentURI), CORS open
//   GET  /arc/passport/a/<slug>.svg       the default passport image
//   POST /api/arc/passport/draft           {name, description, image?, services?} -> file + unsigned register() tx
//   POST /api/arc/passport/confirm         {slug, tx} -> reads the receipt, fills registrations[], returns the links
//   POST /api/arc/passport/edit            owner-signed change to a hosted file (EIP-191, checked against ownerOf)
//   GET  /api/arc/passport/:ref            one passport by agentId or slug
//   GET  /api/arc/passports                the recent ones (the count people see on the page)
//   POST /api/x402/arc-passport            PAID: minted and handed to the payer
//   GET  /arc/passport/:agentId            the share page; /arc/passport/:agentId/card.jpg is its link picture
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const sqlite3 = require('sqlite3');
const { safeFetch } = require('./lib/safe-fetch.js');
// Price of the paid (done-for-you) mint and a label for it; the live service reads its whole price list from one file.
const PASSPORT_USD = Number(process.env.PASSPORT_PRICE_USD || 0.99);
const usdLabel = (v) => { let s = Number(v).toFixed(3).replace(/0+$/, '').replace(/\.$/, ''); if (/\.\d$/.test(s)) s += '0'; return '$' + s; };

const SITE = process.env.SITE || 'https://apexfaucet.xyz';
const REG = '0x8004A169FB4a3325136EB29fA0ceB6D2e539a432';
const REGISTRY_ID = 'eip155:5042:' + REG;
const RPCS = ['https://arc.drpc.org', 'https://rpc.beamrpc.com', 'https://rpc.arc-scan.org', 'https://rpc.mainnet.arc.io'];
const DATA = process.env.PASSPORT_DATA_DIR || path.join(__dirname, '..', 'data');
const KEY_FILE = process.env.PASSPORT_KEY_FILE || path.join(DATA, 'arc-passport-key.json');   // only the PAID path needs a key
const CARD_DIR = path.join(DATA, 'passport-cards');
const LOCK = path.join(DATA, 'arc-passport.mint.lock');
const DRAFTS_PER_IP_PER_DAY = 10;

fs.mkdirSync(DATA, { recursive: true });
const db = new sqlite3.Database(path.join(DATA, 'arc-passport.db'));
db.serialize(() => {
  db.run('PRAGMA journal_mode=WAL');
  db.run(`CREATE TABLE IF NOT EXISTS passports (
    slug TEXT PRIMARY KEY, created_at INTEGER, ip TEXT, name TEXT, description TEXT, image TEXT, services TEXT,
    active INTEGER, probe TEXT, status TEXT, agent_id INTEGER, owner TEXT, mint_tx TEXT, transfer_tx TEXT,
    mode TEXT, paid_tx TEXT, payer TEXT, updated_at INTEGER)`);
  db.run('CREATE UNIQUE INDEX IF NOT EXISTS pp_agent ON passports(agent_id) WHERE agent_id IS NOT NULL');
});
const q = (sql, args) => new Promise((res, rej) => db.all(sql, args || [], (e, r) => (e ? rej(e) : res(r))));
const q1 = (sql, args) => q(sql, args).then((r) => r[0] || null);
const run = (sql, args) => new Promise((res, rej) => db.run(sql, args || [], function (e) { return e ? rej(e) : res(this); }));

let viem = null;
function V() {
  if (!viem) {
    const v = require('viem');
    const arc = v.defineChain({ id: 5042, name: 'Arc', nativeCurrency: { name: 'USDC', symbol: 'USDC', decimals: 18 }, rpcUrls: { default: { http: [RPCS[3]] } } });
    const pub = v.createPublicClient({ chain: arc, transport: v.fallback(RPCS.map((u) => v.http(u, { timeout: 20000, retryCount: 1 })), { rank: false }) });
    const abi = v.parseAbi(['function register(string agentURI) returns (uint256)', 'event Registered(uint256 indexed agentId, string agentURI, address indexed owner)',
      'function ownerOf(uint256 tokenId) view returns (address)', 'function transferFrom(address from, address to, uint256 tokenId)', 'function tokenURI(uint256 tokenId) view returns (string)']);
    viem = { v, arc, pub, abi };
  }
  return viem;
}
// The event's topic is hashed from its signature, never typed in.
function registeredTopic() { const { v } = V(); return v.keccak256(v.toBytes('Registered(uint256,string,address)')); }

// ── Input ──────────────────────────────────────────────────────────────────────────────────────────────────────
const clean = (s, max) => String(s == null ? '' : s).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/[<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, max);
// Words a hosted file on our domain must never carry. Short on purpose: anything else is handled when reported.
const DENY = /\b(seed ?phrase|private ?key|wallet ?drainer|send (me )?your (keys|funds)|nigg\w*|fagg\w*|kike|retard\w*|hitler)\b/i;
const SERVICE_NAMES = { web: 'web', a2a: 'A2A', mcp: 'MCP', oasf: 'OASF', ens: 'ENS', did: 'DID', email: 'email', x402: 'x402' };
const VERSIONS = { A2A: '0.3.0', MCP: '2025-06-18' };
const isHttps = (u) => { try { const x = new URL(u); return x.protocol === 'https:' && !!x.hostname && u.length <= 300; } catch (e) { return false; } };

function validate(body) {
  const b = body || {};
  const name = clean(b.name, 48), description = clean(b.description, 400);
  if (name.length < 2) return { error: 'name must be 2 to 48 characters' };
  if (description.length < 10) return { error: 'description must be 10 to 400 characters: say what the agent does' };
  if (DENY.test(name) || DENY.test(description)) return { error: 'that text cannot be hosted here' };
  let image = clean(b.image, 300);
  if (image && !isHttps(image)) return { error: 'image: an https:// link to a picture, or leave it empty for the passport picture' };
  const out = [];
  for (const s of (Array.isArray(b.services) ? b.services : []).slice(0, 6)) {
    const key = String((s && s.name) || '').toLowerCase().trim();
    const nm = SERVICE_NAMES[key];
    const ep = clean(s && s.endpoint, 300);
    if (!nm || !ep) continue;
    if (['web', 'A2A', 'MCP', 'OASF', 'x402'].includes(nm) && !isHttps(ep)) return { error: nm + ' endpoint must be an https:// URL' };
    if (nm === 'ENS' && !/^[a-z0-9-]+(\.[a-z0-9-]+)*\.eth$/i.test(ep)) return { error: 'ENS: a name ending in .eth' };
    if (nm === 'DID' && !/^did:[a-z0-9]+:[\w.:%-]{1,200}$/i.test(ep)) return { error: 'DID: did:method:identifier' };
    if (nm === 'email' && !/^[^\s@]{1,64}@[^\s@]{1,190}\.[a-z]{2,}$/i.test(ep)) return { error: 'email: a valid address' };
    const row = { name: nm, endpoint: ep };
    if (VERSIONS[nm]) row.version = VERSIONS[nm];
    out.push(row);
  }
  return { name, description, image, services: out };
}

// Does at least one of its endpoints answer? Any HTTP status below 500 counts: an MCP endpoint answers a GET with 405
// and is still there. safeFetch refuses private addresses and our own hosts, so this is not a door into our network.
async function probe(services) {
  const res = [];
  for (const s of services) {
    if (!['web', 'A2A', 'MCP', 'OASF', 'x402'].includes(s.name)) { res.push({ name: s.name, endpoint: s.endpoint, checked: false }); continue; }
    const r = await safeFetch(s.endpoint, { method: 'GET', timeoutMs: 8000, maxBytes: 65536, headers: { accept: 'application/json, text/html;q=0.9, */*;q=0.5' } });
    const answered = !!(r && r.status && r.status < 500);
    res.push({ name: s.name, endpoint: s.endpoint, checked: true, answered, status: r && r.status || null, why: answered ? null : (r && (r.error || r.code)) || 'no answer' });
  }
  return res;
}

function fileFor(row) {
  const services = JSON.parse(row.services || '[]');
  return {
    type: 'https://eips.ethereum.org/EIPS/eip-8004#registration-v1',
    name: row.name,
    description: row.description,
    image: row.image || (SITE + '/arc/passport/a/' + row.slug + '.svg'),
    services,
    x402Support: services.some((s) => s.name === 'x402'),
    active: !!row.active,
    registrations: row.agent_id != null ? [{ agentId: Number(row.agent_id), agentRegistry: REGISTRY_ID }] : [],
    supportedTrust: ['reputation'],
  };
}
const uriFor = (slug) => SITE + '/arc/passport/a/' + slug + '.json';

function linksFor(row) {
  const id = row.agent_id;
  return {
    passport: SITE + '/arc/passport/' + id,
    card: SITE + '/arc/passport/' + id + '/card.jpg',
    registrationFile: uriFor(row.slug),
    watchtower: SITE + '/arc/agents/' + id,
    badge: SITE + '/arc/agents/' + id + '/badge.svg',
    arcCity: SITE + '/arc/city/?agent=' + id,
    scan8004: 'https://8004scan.io/agents/arc/' + id,
    explorerTx: row.mint_tx ? 'https://explorer.arc.io/tx/' + row.mint_tx : null,
    faucet: SITE + '/arc/faucet/',
  };
}

function publicRow(row) {
  if (!row) return null;
  const out = { slug: row.slug, status: row.status, name: row.name, description: row.description, active: !!row.active,
    services: JSON.parse(row.services || '[]'), agentURI: uriFor(row.slug), mode: row.mode,
    createdAt: new Date(row.created_at).toISOString() };
  if (row.agent_id != null) Object.assign(out, { agentId: Number(row.agent_id), owner: row.owner, mintTx: row.mint_tx, transferTx: row.transfer_tx || null, links: linksFor(row) });
  return out;
}

// ── Draft ──────────────────────────────────────────────────────────────────────────────────────────────────────
async function draft(body, ip, mode) {
  const v = validate(body);
  if (v.error) return { ok: false, error: v.error };
  const day = Date.now() - 86400e3;
  if (ip && mode !== 'paid') {
    const n = await q1('SELECT COUNT(*) AS n FROM passports WHERE ip = ? AND created_at > ?', [ip, day]);
    if (n && n.n >= DRAFTS_PER_IP_PER_DAY) return { ok: false, error: 'ten passports a day from one address is the limit; come back tomorrow' };
  }
  const pr = await probe(v.services);
  const active = pr.some((p) => p.answered) ? 1 : 0;
  const slug = crypto.randomBytes(6).toString('hex');
  const now = Date.now();
  await run('INSERT INTO passports (slug, created_at, ip, name, description, image, services, active, probe, status, mode, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
    [slug, now, ip || null, v.name, v.description, v.image || null, JSON.stringify(v.services), active, JSON.stringify(pr), 'draft', mode || 'self', now]);
  const { v: vi, abi } = V();
  const data = vi.encodeFunctionData({ abi, functionName: 'register', args: [uriFor(slug)] });
  return {
    ok: true, slug, agentURI: uriFor(slug), active: !!active, probe: pr,
    file: fileFor({ slug, name: v.name, description: v.description, image: v.image, services: JSON.stringify(v.services), active }),
    register: { chainId: 5042, chainIdHex: '0x13b2', to: REG, data, value: '0x0',
      note: 'Send this from the wallet that should own the agent: it calls register(agentURI) on Arc\'s ERC-8004 identity registry and costs about 0.002 USDC of gas. No USDC on Arc yet? One claim at ' + SITE + '/arc/faucet/ covers it.' },
    next: 'POST ' + SITE + '/api/arc/passport/confirm {"slug":"' + slug + '","tx":"0x…"} once the transaction is in a block. Send register() within 24 hours: an unregistered draft expires then.',
    warning: active ? null : 'None of the endpoints answered, so the file says active:false. It becomes true when you edit it after your agent is up.',
  };
}

// ── Confirm: read the receipt, never believe the caller ────────────────────────────────────────────────────────
async function receiptOf(hash) {
  const { pub } = V();
  for (let i = 0; i < 8; i++) {
    try { const rc = await pub.getTransactionReceipt({ hash }); if (rc) return rc; } catch (e) { /* not yet, or one RPC lagging */ }
    await new Promise((r) => setTimeout(r, 1500));
  }
  return null;
}
function registeredIn(rc) {
  const { v, abi } = V();
  const topic = registeredTopic();
  for (const l of rc.logs || []) {
    if (String(l.address).toLowerCase() !== REG.toLowerCase() || l.topics[0] !== topic) continue;
    try { const ev = v.decodeEventLog({ abi, data: l.data, topics: l.topics }); if (ev.eventName === 'Registered') return { agentId: ev.args.agentId, uri: ev.args.agentURI, owner: ev.args.owner }; }
    catch (e) { /* not ours */ }
  }
  return null;
}
async function confirm(slug, tx) {
  slug = String(slug || '').toLowerCase(); tx = String(tx || '').trim();
  if (!/^[0-9a-f]{12}$/.test(slug)) return { ok: false, error: 'slug must be the 12-character id the draft returned' };
  if (!/^0x[0-9a-fA-F]{64}$/.test(tx)) return { ok: false, error: 'tx must be the 0x transaction hash of your register() call' };
  const row = await q1('SELECT * FROM passports WHERE slug = ?', [slug]);
  if (!row) return { ok: false, error: 'no such passport draft' };
  if (row.status === 'minted') return { ok: true, already: true, passport: publicRow(row) };
  const rc = await receiptOf(tx);
  if (!rc) return { ok: false, retry: true, error: 'the transaction is not in a block yet; send the same request again in a few seconds' };
  if (rc.status !== 'success') return { ok: false, error: 'that transaction reverted on chain' };
  const ev = registeredIn(rc);
  if (!ev) return { ok: false, error: 'that transaction did not register an agent on Arc\'s identity registry' };
  if (ev.uri !== uriFor(slug)) return { ok: false, error: 'that registration points at a different file (' + String(ev.uri).slice(0, 120) + ')' };
  await run('UPDATE passports SET status = ?, agent_id = ?, owner = ?, mint_tx = ?, updated_at = ? WHERE slug = ?',
    ['minted', Number(ev.agentId), String(ev.owner), tx, Date.now(), slug]);
  return { ok: true, passport: publicRow(await q1('SELECT * FROM passports WHERE slug = ?', [slug])) };
}

// A registration made with our file but never confirmed still gets its registrations[] filled: the watchtower's registry
// scan (core/arc/agents-scan.js) already read every agent and its URI, so the file can find its own agentId there.
function reconcileFromScan(row) {
  try {
    if (!process.env.WATCH_FILE) return row;   // optional: a registry scan (agent id + uri per agent) to adopt unconfirmed drafts
    const d = JSON.parse(fs.readFileSync(process.env.WATCH_FILE, 'utf8'));
    const a = (d.agents || []).find((x) => x.uri === uriFor(row.slug));
    if (a && a.id != null) {
      run('UPDATE passports SET status = ?, agent_id = ?, owner = ?, updated_at = ? WHERE slug = ? AND status = ?',
        ['minted', Number(a.id), a.owner || null, Date.now(), row.slug, 'draft']).catch(() => {});
      return Object.assign({}, row, { status: 'minted', agent_id: Number(a.id), owner: a.owner || null });
    }
  } catch (e) { /* the scan file is optional here */ }
  return row;
}

// ── Paid mint: our passport wallet mints, then hands the identity to the payer ───────────────────────────────────
function withLock(fn) {
  // The app is a cluster: two workers minting at once would race for the same nonce. A lock FILE, not a variable.
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const tryIt = () => {
      let fd = null;
      try { fd = fs.openSync(LOCK, 'wx'); }
      catch (e) {
        try { if (Date.now() - fs.statSync(LOCK).mtimeMs > 180e3) fs.unlinkSync(LOCK); } catch (_) {}   // a crashed holder
        if (Date.now() - t0 > 90e3) return reject(new Error('the minting wallet is busy; try again in a minute'));
        return setTimeout(tryIt, 700);
      }
      Promise.resolve().then(fn).then((v) => { try { fs.closeSync(fd); fs.unlinkSync(LOCK); } catch (_) {} resolve(v); },
        (e) => { try { fs.closeSync(fd); fs.unlinkSync(LOCK); } catch (_) {} reject(e); });
    };
    tryIt();
  });
}
async function mintFor(slug, payer) {
  const { v, arc, pub, abi } = V();
  const { privateKeyToAccount } = require('viem/accounts');
  const acct = privateKeyToAccount(JSON.parse(fs.readFileSync(KEY_FILE, 'utf8')).privateKey);
  const wal = v.createWalletClient({ chain: arc, transport: v.http(RPCS[3], { timeout: 20000 }), account: acct });
  return withLock(async () => {
    const reg = await wal.writeContract({ address: REG, abi, functionName: 'register', args: [uriFor(slug)] });
    const rc = await receiptOf(reg) || await receiptOf(reg);
    if (!rc || rc.status !== 'success') throw Object.assign(new Error('register did not confirm'), { tx: reg });
    const ev = registeredIn(rc);
    if (!ev || ev.uri !== uriFor(slug) || String(ev.owner).toLowerCase() !== acct.address.toLowerCase()) throw Object.assign(new Error('register event not found'), { tx: reg });
    const agentId = ev.agentId;
    await run('UPDATE passports SET status = ?, agent_id = ?, owner = ?, mint_tx = ?, updated_at = ? WHERE slug = ?', ['minting', Number(agentId), acct.address, reg, Date.now(), slug]);
    // Hand it over. Only the id this very transaction created, and only while we still own it.
    const holder = await pub.readContract({ address: REG, abi, functionName: 'ownerOf', args: [agentId] });
    if (String(holder).toLowerCase() !== acct.address.toLowerCase()) throw Object.assign(new Error('the new identity is not ours to hand over'), { tx: reg });
    const xfer = await wal.writeContract({ address: REG, abi, functionName: 'transferFrom', args: [acct.address, payer, agentId] });
    const rc2 = await receiptOf(xfer) || await receiptOf(xfer);
    if (!rc2 || rc2.status !== 'success') throw Object.assign(new Error('the hand-over did not confirm'), { tx: xfer, agentId: Number(agentId) });
    const owner = await pub.readContract({ address: REG, abi, functionName: 'ownerOf', args: [agentId] });
    await run('UPDATE passports SET status = ?, owner = ?, transfer_tx = ?, updated_at = ? WHERE slug = ?', ['minted', String(owner), xfer, Date.now(), slug]);
    return { agentId: Number(agentId), registerTx: reg, transferTx: xfer, owner: String(owner) };
  });
}

// ── Owner-signed edit ──────────────────────────────────────────────────────────────────────────────────────────
function editMessage(slug, agentId, sha, issuedAt) {
  return 'APEX Arc Agent Passport: update the registration file\nagent: ' + agentId + '\nfile: ' + uriFor(slug) + '\nsha256: ' + sha + '\nissued: ' + issuedAt;
}
async function edit(body) {
  const slug = String((body && body.slug) || '').toLowerCase();
  const row = await q1('SELECT * FROM passports WHERE slug = ?', [slug]);
  if (!row || row.agent_id == null) return { ok: false, error: 'no minted passport with that slug' };
  const vd = validate(body.file || {});
  if (vd.error) return { ok: false, error: vd.error };
  const issuedAt = String(body.issuedAt || '');
  const t = Date.parse(issuedAt);
  if (!t || Math.abs(Date.now() - t) > 10 * 60e3) return { ok: false, error: 'issuedAt must be within 10 minutes of now (ISO time)' };
  const sha = crypto.createHash('sha256').update(JSON.stringify({ name: vd.name, description: vd.description, image: vd.image || '', services: vd.services })).digest('hex');
  const msg = editMessage(slug, row.agent_id, sha, issuedAt);
  if (!body.signature) return { ok: false, needSignature: true, message: msg, sha256: sha, note: 'Sign this exact message (personal_sign) with the wallet that owns agent ' + row.agent_id + ', then send it back with the same file and issuedAt.' };
  const { v, pub, abi } = V();
  const owner = await pub.readContract({ address: REG, abi, functionName: 'ownerOf', args: [BigInt(row.agent_id)] });
  const good = await v.verifyMessage({ address: owner, message: msg, signature: body.signature }).catch(() => false);
  if (!good) return { ok: false, error: 'the signature is not from the wallet that owns agent ' + row.agent_id + ' (' + owner + ')' };
  const pr = await probe(vd.services);
  await run('UPDATE passports SET name = ?, description = ?, image = ?, services = ?, active = ?, probe = ?, owner = ?, updated_at = ? WHERE slug = ?',
    [vd.name, vd.description, vd.image || null, JSON.stringify(vd.services), pr.some((p) => p.answered) ? 1 : 0, JSON.stringify(pr), String(owner), Date.now(), slug]);
  try { fs.unlinkSync(path.join(CARD_DIR, row.agent_id + '.jpg')); } catch (e) {}
  return { ok: true, passport: publicRow(await q1('SELECT * FROM passports WHERE slug = ?', [slug])), probe: pr };
}

// ── Pictures ───────────────────────────────────────────────────────────────────────────────────────────────────
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
function avatarSvg(row) {
  const h = crypto.createHash('sha256').update(row.slug + row.name).digest();
  const hue = h[0] * 360 / 256, hue2 = (hue + 40 + h[1] % 80) % 360;
  const initials = esc(String(row.name).split(/\s+/).map((w) => w[0]).join('').slice(0, 2).toUpperCase());
  let rings = '';
  for (let i = 0; i < 5; i++) rings += '<circle cx="256" cy="256" r="' + (70 + i * 34) + '" fill="none" stroke="hsl(' + ((hue + i * 18) % 360) + ',70%,' + (60 - i * 6) + '%)" stroke-opacity="' + (0.9 - i * 0.15).toFixed(2) + '" stroke-width="' + (6 - i) + '"/>';
  return '<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512"><defs><radialGradient id="g" cx="50%" cy="40%" r="70%">'
    + '<stop offset="0" stop-color="hsl(' + hue2 + ',55%,22%)"/><stop offset="1" stop-color="#0B0A10"/></radialGradient></defs>'
    + '<rect width="512" height="512" rx="64" fill="url(#g)"/>' + rings
    + '<text x="256" y="292" text-anchor="middle" font-family="DejaVu Sans,Arial,sans-serif" font-size="112" font-weight="800" fill="#FFFFFF">' + initials + '</text>'
    + '<text x="256" y="470" text-anchor="middle" font-family="DejaVu Sans,Arial,sans-serif" font-size="22" letter-spacing="4" fill="#E2B94A">ARC AGENT PASSPORT</text></svg>';
}
let _cardBusy = Promise.resolve();
function renderCard(row) {
  // One render at a time: puppeteer is heavy and a cluster of workers each launching it would starve the site.
  const job = _cardBusy.then(async () => {
    fs.mkdirSync(CARD_DIR, { recursive: true });
    const out = path.join(CARD_DIR, row.agent_id + '.jpg');
    // Kinds, not a repeated list ("web · web"): a web entry shows its host, the rest their protocol name.
    const services = [...new Set(JSON.parse(row.services || '[]').map((s) => { if (s.name !== 'web') return s.name; try { return new URL(s.endpoint).host; } catch (e) { return 'web'; } }))];
    // The description is cut at a word with an ellipsis, never mid-sentence by the box edge.
    const dsc = row.description.length > 150 ? row.description.slice(0, 150).replace(/\s+\S*$/, '') + '…' : row.description;
    const when = new Date(row.created_at).toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
    const svg = avatarSvg(row).replace('<svg ', '<svg style="width:250px;height:250px" ');
    // A stranger's picture is fetched by safeFetch (no private addresses, none of our hosts, size-capped) and embedded as a
    // data: URI; the headless browser itself is never pointed at a URL someone typed.
    let img = svg;
    if (row.image) {
      try {
        const r = await safeFetch(row.image, { timeoutMs: 8000, maxBytes: 600000 });
        const ct = String((r && r.headers && r.headers['content-type']) || '').split(';')[0].trim();
        if (r && r.ok && !r.truncated && r.buf && /^image\/(png|jpe?g|gif|webp)$/.test(ct)) img = '<img src="data:' + ct + ';base64,' + r.buf.toString('base64') + '" style="width:250px;height:250px;border-radius:32px;object-fit:cover">';
      } catch (e) { /* the passport picture stands in */ }
    }
    const html = '<html><body style="margin:0;width:1200px;height:630px;background:#0B0A10;font-family:\'DejaVu Sans\',sans-serif;color:#fff;position:relative;overflow:hidden">'
      + '<div style="position:absolute;inset:0;background:radial-gradient(900px 520px at 88% 0%,#27204a 0%,#0B0A10 62%)"></div>'
      + '<div style="position:absolute;left:64px;top:56px;color:#E2B94A;font-weight:800;letter-spacing:.24em;font-size:20px">ARC AGENT PASSPORT</div>'
      + '<div style="position:absolute;left:64px;top:118px;width:760px">'
      + '<div style="font-size:64px;font-weight:900;line-height:1.05;word-break:break-word">' + esc(row.name) + '</div>'
      + '<div style="margin-top:18px;font-size:26px;color:#D8D2C4;line-height:1.35;max-height:108px;overflow:hidden">' + esc(dsc) + '</div>'
      + '<div style="margin-top:30px;font-size:30px;font-weight:800">Agent #' + Number(row.agent_id).toLocaleString('en-US') + ' <span style="color:#8E879C;font-weight:600">on Arc\'s ERC-8004 registry</span></div>'
      + '<div style="margin-top:12px;font-size:22px;color:#D8D2C4">' + (services.length ? esc(services.join(' · ')) : 'identity only, endpoints to come') + ' &nbsp;·&nbsp; since ' + esc(when) + '</div>'
      + '</div>'
      + '<div style="position:absolute;right:72px;top:150px">' + img + '</div>'
      + '<div style="position:absolute;left:64px;bottom:42px;font-size:22px;color:#8E879C">Owned by ' + esc(String(row.owner || '').slice(0, 6) + '…' + String(row.owner || '').slice(-4)) + ' &nbsp;·&nbsp; apexfaucet.xyz/arc/passport</div>'
      + '</body></html>';
    const puppeteer = require('puppeteer');
    const b = await puppeteer.launch({ args: ['--no-sandbox'] });
    try {
      const p = await b.newPage(); await p.setViewport({ width: 1200, height: 630 });
      await p.setRequestInterception(true);
      p.on('request', (rq) => (/^data:/.test(rq.url()) || rq.url() === 'about:blank' ? rq.continue() : rq.abort()));
      await p.setContent(html, { waitUntil: 'load', timeout: 15000 }).catch(() => {});
      const tmp = out + '.tmp.jpg';
      await p.screenshot({ path: tmp, type: 'jpeg', quality: 86 });
      if (fs.statSync(tmp).size > 900 * 1024) { fs.unlinkSync(tmp); throw new Error('card too big'); }
      fs.renameSync(tmp, out);
    } finally { await b.close(); }
    return out;
  });
  _cardBusy = job.catch(() => {});
  return job;
}

// ── Share page ─────────────────────────────────────────────────────────────────────────────────────────────────
function sharePage(row) {
  const id = Number(row.agent_id), L = linksFor(row);
  const services = JSON.parse(row.services || '[]');
  const title = esc(row.name) + ' · Arc Agent Passport #' + id;
  const desc = esc(row.name + ' is agent #' + id + ' on Arc\'s ERC-8004 registry. ' + row.description).slice(0, 280);
  const svc = services.length ? services.map((s) => '<li><b>' + esc(s.name) + '</b> <code>' + esc(s.endpoint) + '</code></li>').join('') : '<li>No endpoints yet. The owner can add them.</li>';
  return '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>' + title + '</title><meta name="description" content="' + desc + '">'
    + '<meta property="og:type" content="website"><meta property="og:site_name" content="APEX Faucet"><meta property="og:url" content="' + L.passport + '">'
    + '<meta property="og:title" content="' + title + '"><meta property="og:description" content="' + desc + '">'
    + '<meta property="og:image" content="' + L.card + '"><meta property="og:image:width" content="1200"><meta property="og:image:height" content="630">'
    + '<meta name="twitter:card" content="summary_large_image"><meta name="twitter:title" content="' + title + '"><meta name="twitter:description" content="' + desc + '"><meta name="twitter:image" content="' + L.card + '">'
    + '<link rel="icon" href="/favicon-192.png"><link rel="stylesheet" href="/apex-v3.css">'
    + '<style>:root{--pp-bg:#FBF8F6;--pp-card:#FFFFFF;--pp-ink:#1B1F24;--pp-soft:#4A5058;--pp-line:#E6E1D8;--pp-gold:#9A6B00}'
    + '@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--pp-bg:#0B0A10;--pp-card:#16141D;--pp-ink:#F3F0EA;--pp-soft:#C9C3B8;--pp-line:#2A2633;--pp-gold:#E2B94A}}'
    + ':root[data-theme="dark"]{--pp-bg:#0B0A10;--pp-card:#16141D;--pp-ink:#F3F0EA;--pp-soft:#C9C3B8;--pp-line:#2A2633;--pp-gold:#E2B94A}'
    + 'body{background:var(--pp-bg);color:var(--pp-ink);margin:0;font:16px/1.55 Inter,-apple-system,sans-serif}main{max-width:760px;margin:0 auto;padding:28px 16px 60px}'
    + 'html body:not(#a):not(#b):not(#c):not(#d):not(#e) .pp-k{color:var(--pp-gold)!important}html body:not(#a):not(#b):not(#c):not(#d):not(#e) .pp-s{color:var(--pp-soft)!important}'
    + '.pp-card{background:var(--pp-card);border:1px solid var(--pp-line);border-radius:16px;padding:18px;margin:14px 0}.pp-card img{width:100%;height:auto!important;border-radius:12px;display:block}'
    + '.pp-act{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0 4px}'
    + 'html body:not(#a):not(#b):not(#c):not(#d):not(#e) a.pp-btn{display:inline-block;padding:11px 16px;border-radius:12px;background:#7C5B0F!important;color:#FFFFFF!important;-webkit-text-fill-color:#FFFFFF!important;font-weight:700;text-decoration:none}'
    + 'html body:not(#a):not(#b):not(#c):not(#d):not(#e) a.pp-btn2{display:inline-block;padding:10px 15px;border-radius:12px;border:1px solid var(--pp-line);background:var(--pp-card)!important;color:var(--pp-ink)!important;-webkit-text-fill-color:var(--pp-ink)!important;font-weight:700;text-decoration:none}code{word-break:break-all;font-size:13px}'
    + 'ul{padding-left:20px}a{color:inherit}.pp-links a{display:inline-block;margin:4px 12px 4px 0}</style></head><body><main>'
    + '<div class="pp-k" style="font-weight:800;letter-spacing:.18em;font-size:13px">ARC AGENT PASSPORT</div>'
    + '<h1 style="margin:6px 0 4px;font-size:34px;line-height:1.1">' + esc(row.name) + '</h1>'
    + '<div class="pp-s">Agent #' + id + ' on Arc\'s ERC-8004 registry · owned by <code>' + esc(row.owner || '') + '</code></div>'
    + '<div class="pp-act"><a class="pp-btn" href="/arc/passport/">Get a passport for your agent</a><a class="pp-btn2" target="_blank" rel="noopener" href="https://x.com/intent/post?text='
    + encodeURIComponent(row.name + ' has its passport on Arc: agent #' + id + ' on the ERC-8004 registry.') + '&url=' + encodeURIComponent(L.passport) + '">Share on X</a></div>'
    + '<div class="pp-card"><img src="' + L.card + '" alt="' + title + '" width="1200" height="630"></div>'
    + '<div class="pp-card"><p style="margin-top:0">' + esc(row.description) + '</p><ul>' + svc + '</ul>'
    + (row.active ? '' : '<p class="pp-s">No endpoint answered when this file was written, so it says active: false. That is the honest state until the agent is up.</p>') + '</div>'
    + '<div class="pp-card pp-links"><a href="' + L.watchtower + '">Hourly check-up</a><a href="' + L.arcCity + '">Its tower in Arc City</a><a href="' + L.registrationFile + '">Registration file</a>'
    + '<a href="' + L.scan8004 + '">8004scan</a>' + (L.explorerTx ? '<a href="' + L.explorerTx + '">Registration transaction</a>' : '') + '</div>'
    + '<div class="pp-card"><b>Give your agent a passport too.</b> Free if your wallet sends the one transaction, or ' + esc(usdLabel(PASSPORT_USD)) + ' for an agent that pays with its own wallet over x402. <a href="/arc/passport/">Get one &rarr;</a></div>'
    + '</main><script src="/nav-v2.js" defer></script></body></html>';
}

// ── Routes ─────────────────────────────────────────────────────────────────────────────────────────────────────
module.exports = function (app, express, opts) {
  const json = express.json({ limit: '16kb' });
  const ipOf = (req) => String(req.headers['cf-connecting-ip'] || req.headers['x-real-ip'] || req.ip || '').slice(0, 64);

  app.get('/arc/passport/a/:file', async (req, res) => {
    const m = /^([0-9a-f]{12})\.(json|svg)$/.exec(String(req.params.file || ''));
    if (!m) return res.status(404).json({ error: 'not found' });
    let row = await q1('SELECT * FROM passports WHERE slug = ?', [m[1]]).catch(() => null);
    if (!row) return res.status(404).json({ error: 'not found' });
    res.set('Access-Control-Allow-Origin', '*');
    if (m[2] === 'svg') { res.set('Content-Type', 'image/svg+xml'); res.set('Cache-Control', 'public, max-age=86400'); return res.send(avatarSvg(row)); }
    if (row.status === 'draft' && Date.now() - row.created_at > 60e3) row = reconcileFromScan(row);
    // A draft nobody registered is not hosted forever: 24 hours to send register(), then it is gone (stranger text on our
    // domain has a shelf life, CLAUDE.md 4b). A minted file is served for good.
    if (row.status === 'draft' && Date.now() - row.created_at > 24 * 3600e3) return res.status(404).json({ error: 'this draft was never registered and expired after 24 hours; make a new one' });
    res.set('Cache-Control', 'public, max-age=60');
    res.json(fileFor(row));
  });

  app.post('/api/arc/passport/draft', json, async (req, res) => {
    try { const r = await draft(req.body, ipOf(req), 'self'); res.status(r.ok ? 200 : 400).json(r); }
    catch (e) { console.error('[passport] draft: ' + e.message); res.status(500).json({ ok: false, error: 'could not create the draft just now' }); }
  });
  app.post('/api/arc/passport/confirm', json, async (req, res) => {
    try { const r = await confirm(req.body && req.body.slug, req.body && req.body.tx); res.status(r.ok ? 200 : (r.retry ? 202 : 400)).json(r); }
    catch (e) { console.error('[passport] confirm: ' + e.message); res.status(500).json({ ok: false, retry: true, error: 'could not read the chain just now; send the same request again' }); }
  });
  app.post('/api/arc/passport/edit', json, async (req, res) => {
    try { const r = await edit(req.body); res.status(r.ok || r.needSignature ? 200 : 400).json(r); }
    catch (e) { console.error('[passport] edit: ' + e.message); res.status(500).json({ ok: false, error: 'could not update just now' }); }
  });
  app.get('/api/arc/passports', async (req, res) => {
    const rows = await q('SELECT * FROM passports WHERE status = ? ORDER BY updated_at DESC LIMIT 24', ['minted']).catch(() => []);
    const n = await q1('SELECT COUNT(*) AS n FROM passports WHERE status = ?', ['minted']).catch(() => ({ n: null }));
    res.set('Cache-Control', 'public, max-age=30');
    res.json({ ok: true, minted: n ? n.n : null, recent: rows.map((r) => ({ agentId: Number(r.agent_id), name: r.name, active: !!r.active, page: SITE + '/arc/passport/' + r.agent_id })),
      priceUsd: PASSPORT_USD, free: 'self-mint: your own wallet sends register(), about 0.002 USDC of gas' });
  });
  app.get('/api/arc/passport/:ref', async (req, res) => {
    const ref = String(req.params.ref || '').toLowerCase();
    let row = /^\d{1,9}$/.test(ref) ? await q1('SELECT * FROM passports WHERE agent_id = ?', [Number(ref)]).catch(() => null)
      : /^[0-9a-f]{12}$/.test(ref) ? await q1('SELECT * FROM passports WHERE slug = ?', [ref]).catch(() => null) : null;
    if (row && row.status === 'draft') row = reconcileFromScan(row);
    if (!row) return res.status(404).json({ ok: false, error: 'no such passport: not found by that agent id or slug' });
    res.json({ ok: true, passport: publicRow(row) });
  });

  // PAID: an agent pays for its own identity. Input is checked BEFORE the gate, so nobody pays for a request we refuse.
  const passportUsd = PASSPORT_USD;
  let _gas = { at: 0, ok: true };
  const precheck = async (req, res, next) => {
    if (req.method !== 'POST') return next();
    const v = validate(req.body);
    if (v.error) return res.status(400).json({ ok: false, error: v.error, charged: false });
    // Never take a payment we cannot deliver: register + transfer cost about 0.006 USDC of gas from the minting wallet.
    try {
      if (Date.now() - _gas.at > 60e3) {
        const addr = JSON.parse(fs.readFileSync(KEY_FILE, 'utf8')).address;
        const bal = await V().pub.getBalance({ address: addr });
        _gas = { at: Date.now(), ok: Number(bal) / 1e18 >= 0.02, usdc: Number(bal) / 1e18 };
        if (!_gas.ok) console.error('[passport] MINTING WALLET LOW: ' + _gas.usdc + ' USDC; paid passports refused until it is topped up');
      }
    } catch (e) { _gas = { at: Date.now(), ok: false }; console.error('[passport] could not read the minting wallet balance: ' + e.message); }
    if (!_gas.ok) return res.status(503).json({ ok: false, charged: false, error: 'paid passports are paused for a moment (the minting wallet is being topped up). Nothing was charged. The free path works now: POST ' + SITE + '/api/arc/passport/draft' });
    next();
  };
  // The paid path needs an x402 gate (the live service uses its own; any x402 middleware that sets req.x402.payer to the
  // paying EVM address works). Without one, the free self-mint path is the whole product and the paid route says so.
  const gate = !(opts && opts.gate) ? (req, res) => res.status(501).json({ ok: false, error: 'paid minting is not configured on this server; use POST /api/arc/passport/draft (free)' }) : opts.gate({ usdPrice: passportUsd, rails: ['arc', 'base'],
    desc: 'An ERC-8004 identity on Arc for the agent that pays: we host a correct registration file, mint the identity and hand it to the paying wallet. POST JSON {name, description, image?, services?[{name, endpoint}]}.' });
  const paying = (req) => !!(req.headers['payment-signature'] || req.headers['x-payment'] || req.headers['x-payment-arc'] || req.headers['x-payment-base']
    || req.headers['x-payment-sol'] || (req.query && (req.query._x402 || req.query._x402_arc || req.query._x402_base || req.query._x402_sol)));
  app.all('/api/x402/arc-passport', json, (req, res, next) => {
    if (req.method !== 'POST' && req.method !== 'GET') return res.status(405).json({ error: 'POST the agent as JSON' });
    // A GET only shows the price. A GET carrying a payment is refused before the gate, so it can never be charged.
    if (req.method === 'GET' && paying(req)) return res.status(400).json({ ok: false, error: 'send the payment with a POST that carries the agent as JSON', charged: false });
    next();
  }, precheck, (req, res, next) => gate(req, res, next), async (req, res) => {
    const payer = String((req.x402 && req.x402.payer) || '');
    const where = String((req.x402 && req.x402.network) || '');
    const owed = (why, extra) => {
      try { fs.appendFileSync(path.join(DATA, 'x402-undelivered.jsonl'), JSON.stringify(Object.assign({ at: new Date().toISOString(), why, route: '/api/x402/arc-passport', payer, network: where, paidTx: req.x402 && req.x402.sig, usd: passportUsd }, extra || {})) + '\n'); } catch (e) {}
      console.error('[passport] PAID BUT NOT DELIVERED: ' + why + ' payer ' + payer);
    };
    if (!/^0x[0-9a-fA-F]{40}$/.test(payer)) { owed('payer is not an EVM address'); return res.status(500).json({ ok: false, error: 'the payment did not come from an EVM wallet, so the identity has nowhere to go. This is recorded and refunded: quote your transaction at ' + SITE + '/safetynet/' }); }
    let d;
    try { d = await draft(req.body, ipOf(req), 'paid'); } catch (e) { d = { ok: false, error: e.message }; }
    if (!d.ok) { owed('draft failed: ' + d.error); return res.status(500).json({ ok: false, error: d.error, refund: 'recorded as owed; quote your transaction at ' + SITE + '/safetynet/' }); }
    await run('UPDATE passports SET paid_tx = ?, payer = ? WHERE slug = ?', [req.x402.sig || null, payer, d.slug]).catch(() => {});
    try {
      const m = await mintFor(d.slug, payer);
      const row = await q1('SELECT * FROM passports WHERE slug = ?', [d.slug]);
      res.json({ ok: true, agentId: m.agentId, owner: m.owner, registerTx: m.registerTx, transferTx: m.transferTx, passport: publicRow(row),
        note: 'Your wallet owns agent #' + m.agentId + '. agentWallet is cleared on any ERC-721 transfer (ERC-8004), so set it from your own wallet with setAgentWallet if you want payments pointed elsewhere.' });
    } catch (e) {
      owed('mint failed: ' + e.message, { tx: e.tx || null, agentId: e.agentId || null, slug: d.slug });
      res.status(500).json({ ok: false, error: 'the identity could not be minted just now (' + e.message + '). You paid, so this is recorded as owed and finished by hand, or refunded: quote your transaction at ' + SITE + '/safetynet/', slug: d.slug });
    }
  });

  app.get('/arc/passport/:id/card.jpg', async (req, res) => {
    if (!/^\d{1,9}$/.test(String(req.params.id))) return res.status(404).end();
    const row = await q1('SELECT * FROM passports WHERE agent_id = ? AND status = ?', [Number(req.params.id), 'minted']).catch(() => null);
    if (!row) return res.status(404).end();
    const f = path.join(CARD_DIR, row.agent_id + '.jpg');
    try {
      let fresh = false; try { fresh = fs.statSync(f).mtimeMs >= row.updated_at; } catch (e) {}
      if (!fresh) await renderCard(row);
      res.set('Content-Type', 'image/jpeg'); res.set('Cache-Control', 'public, max-age=3600');
      return res.send(fs.readFileSync(f));
    } catch (e) { console.error('[passport] card: ' + e.message); return res.redirect(302, '/og/arc-agents.jpg'); }
  });
  app.get('/arc/passport/:id', async (req, res, next) => {
    if (!/^\d{1,9}$/.test(String(req.params.id))) return next();
    const row = await q1('SELECT * FROM passports WHERE agent_id = ? AND status = ?', [Number(req.params.id), 'minted']).catch(() => null);
    if (!row) return res.status(404).send('<!doctype html><meta charset="utf-8"><title>No passport</title><p style="font-family:sans-serif;padding:24px">No passport has agent id ' + esc(req.params.id) + '. <a href="/arc/passport/">Get one</a>.</p>');
    res.set('Cache-Control', 'public, max-age=120');
    res.send(sharePage(row));
  });
};
module.exports.draft = draft;
module.exports.confirm = confirm;
module.exports.edit = edit;
module.exports.publicRow = publicRow;
module.exports.lookup = async (ref) => {
  const r = String(ref || '').toLowerCase();
  let row = /^\d{1,9}$/.test(r) ? await q1('SELECT * FROM passports WHERE agent_id = ?', [Number(r)]) : /^[0-9a-f]{12}$/.test(r) ? await q1('SELECT * FROM passports WHERE slug = ?', [r]) : null;
  if (row && row.status === 'draft') row = reconcileFromScan(row);
  return row ? publicRow(row) : null;
};
module.exports.stats = async () => {
  const n = await q1('SELECT COUNT(*) AS n FROM passports WHERE status = ?', ['minted']);
  return { minted: n ? n.n : 0 };
};
