#!/usr/bin/env node
/**
 * verify-proof.mjs — check, from nothing but the public API and a Solana RPC, that a HIM round was provable (docs/PROOF_SEAL.md).
 *
 *   node verify-proof.mjs <roundId>                       one round: its result leaf, each question leaf and, when players took
 *                                                                 the Human Round (the Human Round), each human-check leaf
 *   node verify-proof.mjs --epoch <n>                     one epoch: recompute both roots from the published leaves
 *   node verify-proof.mjs --keyrace <season> --wallet <W> [--inputs keyrace-s0-in.json]
 *                                                                 the Key Race seals and a wallet's own leaves
 *   options: --api <url>   the escrow API (default $HIM_ESCROW_API_URL or https://api.him.finance/escrow)
 *            --rpc <url>   the Solana RPC (default: the public endpoint of the cluster the API reports)
 *            --open <keypair.json>   a player's wallet key: signs HIM:PROOF_OPEN so the API hands over the answer keys + salts of
 *                                    THAT round (the player was shown them anyway); only then can the question leaves be recomputed
 *            --human-trace <file.json>   a player's saved Human Round trace ([{t,x,y,k}]): its hash must equal the sealed "th" of one human-check leaf
 *            --json     machine-readable result
 *
 * What it proves (and does not): see the threat model in docs/PROOF_SEAL.md. In short: the answer key of every sealed question and the
 * result of the round were fixed in a Merkle root signed by HIM's seal key and written to Solana (SPL Memo) at a time the cluster
 * stamped; the question seals are older than the round's first question. It does NOT prove the server never looked at answers early.
 *
 * Exit codes: 0 every check passed; 1 a check FAILED; 2 the round is not sealed yet; 3 verified, but some question was not sealed.
 * Dependencies: none beyond node (crypto, fetch). Signing with --open uses node's own ed25519.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import { pathToFileURL } from 'node:url';

export const MEMO_PROGRAMS = new Set(['MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', 'Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo']);

// ── the Merkle tree: byte for byte proof_merkle.go ────────────────────────────────────────────

export const sha = (...parts) => {
  const h = crypto.createHash('sha256');
  for (const p of parts) h.update(p);
  return h.digest();
};
export const leafNode = (preimage) => sha(Buffer.from([0]), Buffer.from(preimage, 'utf8'));
export const parent = (l, r) => sha(Buffer.from([1]), l, r);
export const qLeaf = (opening) => leafNode('HIM1|ql|' + opening).toString('hex');
export const rLeaf = (record) => leafNode('HIM1|rl|' + record).toString('hex');
export const hlLeaf = (record) => leafNode('HIM1|hl|' + record).toString('hex');
export const krLeaf = (label, body) => leafNode(label + body).toString('hex');

/** The path from a leaf up: [{right, h}], right = the sibling sits on the right of the running hash. */
export function verifyPath(leafHex, path, rootHex) {
  let cur = Buffer.from(leafHex, 'hex');
  if (cur.length !== 32) return false;
  for (const s of path ?? []) {
    const sib = Buffer.from(s.h, 'hex');
    if (sib.length !== 32) return false;
    cur = s.right ? parent(cur, sib) : parent(sib, cur);
  }
  return cur.toString('hex') === rootHex;
}

/** The root over leaf nodes in order (odd node promoted, never duplicated). */
export function rootOf(nodes) {
  if (!nodes.length) return null;
  let level = nodes.map((n) => (typeof n === 'string' ? Buffer.from(n, 'hex') : n));
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i + 1 < level.length; i += 2) next.push(parent(level[i], level[i + 1]));
    if (level.length % 2 === 1) next.push(level[level.length - 1]);
    level = next;
  }
  return level[0].toString('hex');
}

/**
 * The canonical form of a Human Round trace (human_round_score.go humanCanonical): "t,x,y,k" per event, t in tenths of a ms, x and y in hundredths of a
 * field unit, all rounded half up, joined by ";". Its sha256 is the sealed "th".
 */
export function humanCanonical(events) {
  const kind = { d: 'd', down: 'd', m: 'm', move: 'm', u: 'u', up: 'u' };
  return events.map((e) => `${Math.floor(e.t * 10 + 0.5)},${Math.floor(e.x * 100 + 0.5)},${Math.floor(e.y * 100 + 0.5)},${kind[e.k ?? e.kind]}`).join(';');
}
export const humanTraceHash = (events) => sha(Buffer.from(humanCanonical(events), 'utf8')).toString('hex');

// ── Solana ─────────────────────────────────────────────────────────────────────────────────────

const PUBLIC_RPC = { devnet: 'https://api.devnet.solana.com', 'mainnet-beta': process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com' };

async function rpcCall(url, method, params, fetchFn = fetch) {
  const r = await fetchFn(url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json();
  if (j.error) throw new Error(`${method}: ${j.error.message}`);
  return j.result;
}

/**
 * Fetch a memo transaction and check it: succeeded, signed by the seal key, carries exactly the expected memo text.
 * Returns {ok, reason?, blockTime?}. blockTime is the cluster's own stamp (seconds).
 */
export async function checkMemo({ rpc, sig, text, signer, fetchFn = fetch }) {
  if (!sig) return { ok: false, reason: 'no transaction signature yet' };
  let tx;
  for (let i = 0; i < 4; i++) { // a fresh transaction may need a moment to be queryable
    tx = await rpcCall(rpc, 'getTransaction', [sig, { encoding: 'jsonParsed', commitment: 'confirmed', maxSupportedTransactionVersion: 0 }], fetchFn);
    if (tx) break;
    await new Promise((r) => setTimeout(r, 1500));
  }
  if (!tx) return { ok: false, reason: 'transaction not found on this cluster' };
  if (tx.meta?.err) return { ok: false, reason: 'the transaction failed on chain' };
  const keys = tx.transaction.message.accountKeys.map((k) => (typeof k === 'string' ? k : k.pubkey));
  const signerKeys = tx.transaction.message.accountKeys.filter((k) => k.signer).map((k) => k.pubkey);
  if (signer && !(signerKeys.includes(signer) && keys[0] === signer)) return { ok: false, reason: `not signed by the seal key ${signer}` };
  const memos = [];
  for (const ix of tx.transaction.message.instructions) {
    const prog = ix.programId ?? keys[ix.programIdIndex];
    if (MEMO_PROGRAMS.has(String(prog)) && typeof ix.parsed === 'string') memos.push(ix.parsed);
  }
  if (!memos.includes(text)) return { ok: false, reason: `the transaction's memos are ${JSON.stringify(memos)}, not ${JSON.stringify(text)}` };
  return { ok: true, blockTime: tx.blockTime ?? null };
}

// ── the API ────────────────────────────────────────────────────────────────────────────────────

async function call(api, body, fetchFn = fetch) {
  const r = await fetchFn(api, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || j.error) throw new Error(`${body.action}: ${j.error ?? 'HTTP ' + r.status}`);
  return j;
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(buf) {
  let n = BigInt('0x' + buf.toString('hex'));
  let s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of buf) { if (b === 0) s = '1' + s; else break; }
  return s;
}

/** A PROOF_OPEN request signed with a local wallet key (a player of the round). */
export function signedOpen(keypairFile, roundId, now = Date.now()) {
  const kp = Buffer.from(JSON.parse(fs.readFileSync(keypairFile, 'utf8')));
  if (kp.length !== 64) throw new Error('--open wants a 64-byte Solana keypair file');
  const wallet = b58(kp.subarray(32));
  const key = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), kp.subarray(0, 32)]), format: 'der', type: 'pkcs8' });
  const message = `HIM:PROOF_OPEN:${roundId}:${wallet}:${crypto.randomBytes(8).toString('hex')}:${now + 60_000}`;
  const signature = crypto.sign(null, Buffer.from(message), key).toString('hex');
  return { action: 'PROOF_OPEN', gameId: roundId, walletAddress: wallet, message, signature };
}

// ── verifying one round ────────────────────────────────────────────────────────────────────────

/**
 * Verify a PROOF_ROUND response. Pure Merkle / structure checks run always; the chain checks run when `rpc` is given.
 * Returns {checks:[{name, ok, detail}], status:'pass'|'fail'|'pending'|'partial'}.
 */
export async function verifyRound(resp, { rpc, openings = [], humanTrace = null, fetchFn = fetch } = {}) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });
  const res = resp.result;
  let rec = null;
  try { rec = JSON.parse(res.record); } catch { /* reported below */ }
  add('result record parses', !!rec);
  add('result leaf = sha256(0x00 | "HIM1|rl|" | record)', rLeaf(res.record) === res.leaf);
  if (rec) add('record names this round', rec.r === resp.roundId, rec.r);
  let pending = false;
  if (!res.root) {
    pending = true;
    add('result sealed', false, `not sealed yet (the epoch closes ${new Date(res.sealsAfterMs).toISOString()})`);
  } else {
    add('result Merkle path reaches the epoch root', verifyPath(res.leaf, res.path, res.root));
    const text = `HIM1|r|${res.epoch}|${res.root}`;
    add('memo text is HIM1|r|<epoch>|<root>', res.memo?.text === text, res.memo?.text);
    if (rpc) {
      if (!res.memo?.sig) { pending = true; add('result memo on chain', false, 'seal found, memo not confirmed yet'); } else {
        const m = await checkMemo({ rpc, sig: res.memo.sig, text, signer: resp.signer, fetchFn });
        add('result memo is on chain, signed by the seal key', m.ok, m.reason ?? res.memo.sig);
        if (m.ok && rec && m.blockTime) add('result sealed AFTER the round settled', m.blockTime * 1000 >= rec.t1 - 2000, new Date(m.blockTime * 1000).toISOString());
      }
    }
  }
  let unsealed = 0;
  let late = 0;
  const opens = new Map(openings.map((o) => [o.leaf, o.opening]));
  for (const q of resp.questions ?? []) {
    if (!q.sealed) { unsealed++; add(`question ${q.id}: sealed`, true, 'NOT sealed (it was drawn before its seal could be used)'); continue; }
    add(`question ${q.id}: Merkle path reaches its epoch root`, verifyPath(q.leaf, q.path, q.root));
    const text = `HIM1|q|${q.epoch}|${q.root}`;
    add(`question ${q.id}: memo text`, q.memo?.text === text);
    const op = q.opening ?? opens.get(q.leaf);
    if (op) {
      add(`question ${q.id}: opening hashes to the sealed leaf`, qLeaf(op) === q.leaf);
      try { const o = JSON.parse(op); add(`question ${q.id}: opening names the question`, o.id === q.id && Array.isArray(o.o) && o.o.length === 4 && !!o.s); } catch { add(`question ${q.id}: opening parses`, false); }
    }
    if (rpc) {
      const m = await checkMemo({ rpc, sig: q.memo?.sig, text, signer: resp.signer, fetchFn });
      add(`question ${q.id}: memo on chain, signed by the seal key`, m.ok, m.reason ?? '');
      if (m.ok && rec && m.blockTime) {
        const before = m.blockTime * 1000 < rec.t0;
        const when = `${new Date(m.blockTime * 1000).toISOString()} vs round start ${new Date(rec.t0).toISOString()}`;
        if (before) add(`question ${q.id}: sealed BEFORE the round's first question`, true, when);
        else if (q.sealedBefore === true) add(`question ${q.id}: the API says sealed before, the chain says otherwise`, false, when); // a lie: fail
        else { late++; add(`question ${q.id}: sealed, but only AFTER the round began (drawn before its seal could be used)`, true, when); }
      }
    }
  }
  // the Human Round (the Human Round): one leaf per player who took the check, in the SAME result tree and sealed by the same memo kind
  const humans = resp.human ?? [];
  const sealedThs = [];
  for (const h of humans) {
    let hr = null;
    try { hr = JSON.parse(h.record); } catch { /* reported below */ }
    const tag = `human check ${String(h.key ?? '').split('|h|')[1]?.slice(0, 8) ?? '?'}`;
    add(`${tag}: record parses`, !!hr && hr.v === 1);
    add(`${tag}: leaf = sha256(0x00 | "HIM1|hl|" | record)`, hlLeaf(h.record) === h.leaf);
    if (hr) {
      add(`${tag}: record names this round and its sort key`, hr.r === resp.roundId && h.key === `${hr.r}|h|${hr.pid}`, h.key);
      sealedThs.push(hr.th);
    }
    if (!h.root) {
      pending = true;
      add(`${tag}: sealed`, false, `not sealed yet (the epoch closes ${new Date(h.sealsAfterMs).toISOString()})`);
      continue;
    }
    add(`${tag}: Merkle path reaches the epoch root`, verifyPath(h.leaf, h.path, h.root));
    const text = `HIM1|r|${h.epoch}|${h.root}`;
    add(`${tag}: memo text is HIM1|r|<epoch>|<root>`, h.memo?.text === text, h.memo?.text);
    if (rpc) {
      if (!h.memo?.sig) { pending = true; add(`${tag}: memo on chain`, false, 'seal found, memo not confirmed yet'); } else {
        const m = await checkMemo({ rpc, sig: h.memo.sig, text, signer: resp.signer, fetchFn });
        add(`${tag}: memo is on chain, signed by the seal key`, m.ok, m.reason ?? h.memo.sig);
        if (m.ok && hr && m.blockTime) add(`${tag}: sealed AFTER the check was recorded`, m.blockTime * 1000 >= hr.t - 2000, new Date(m.blockTime * 1000).toISOString());
      }
    }
  }
  if (humanTrace) add('human trace: hashes to the sealed th of a human-check leaf', sealedThs.includes(humanTraceHash(humanTrace)), humanTraceHash(humanTrace).slice(0, 16));
  const failed = checks.some((c) => !c.ok && !(pending && /sealed|memo/.test(c.name)));
  let status = failed ? 'fail' : pending ? 'pending' : unsealed || late ? 'partial' : 'pass';
  if (status === 'pass' && !rpc) status = 'pass-offchain';
  return { checks, status, unsealed, late };
}

// ── verifying an epoch ─────────────────────────────────────────────────────────────────────────

export async function verifyEpoch(api, epoch, { rpc, fetchFn = fetch } = {}) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });
  const page = async (offset) => call(api, { action: 'PROOF_EPOCH', epoch, offset, limit: 500 }, fetchFn);
  let first = await page(0);
  const rpcUrl = rpc ?? PUBLIC_RPC[first.cluster];
  for (const side of ['q', 'r']) {
    const s = first[side];
    if (!s.sealed) { add(`${side}-seal exists for epoch ${epoch}`, true, 'none (nothing was sealed on this side)'); continue; }
    const leaves = [];
    let cur = first;
    for (let off = 0; ; off += 500) {
      if (off) cur = await page(off);
      const chunk = cur[side].leaves ?? [];
      leaves.push(...chunk);
      if (chunk.length < 500) break;
    }
    add(`${side}: ${leaves.length} leaves published = n ${s.n}`, leaves.length === s.n);
    if (side === 'q') {
      const withOpenings = leaves.filter((l) => l.opening);
      if (withOpenings.length === leaves.length && leaves.length) add('q: every opening hashes to its leaf', leaves.every((l) => qLeaf(l.opening) === l.l));
    }
    add(`${side}: root recomputed from the leaves = published root`, rootOf(leaves.map((l) => l.l)) === s.root);
    const text = `HIM1|${side}|${epoch}|${s.root}`;
    add(`${side}: memo text`, s.memo?.text === text);
    if (rpcUrl) {
      const m = await checkMemo({ rpc: rpcUrl, sig: s.memo?.sig, text, signer: first.signer, fetchFn });
      add(`${side}: memo on chain, signed by the seal key`, m.ok, m.reason ?? '');
    }
  }
  return { checks, status: checks.every((c) => c.ok) ? 'pass' : 'fail' };
}

// ── verifying the Key Race ─────────────────────────────────────────────────────────────────────

export async function verifyKeyRace(resp, { rpc, inputsFile, fetchFn = fetch } = {}) {
  const checks = [];
  const add = (name, ok, detail = '') => checks.push({ name, ok, detail });
  const all = [...resp.boards, ...resp.in, ...resp.out];
  add(`${all.length} Key Race seals listed for season ${resp.season}`, all.length > 0);
  for (const s of all) {
    const text = `HIM1|k|${resp.season}|${s.kind}|${s.root}`;
    add(`${s.kind}: memo text`, s.memo?.text === text, s.memo?.text);
    if (rpc) {
      const m = await checkMemo({ rpc, sig: s.memo?.sig, text, signer: resp.signer, fetchFn });
      add(`${s.kind}: memo on chain, signed by the seal key`, m.ok, m.reason ?? '');
    }
  }
  for (const l of resp.wallet?.leaves ?? []) {
    add(`${l.kind}: your leaf = sha256(0x00 | label | body)`, krLeaf(l.label, l.body) === l.leaf);
    add(`${l.kind}: your leaf's Merkle path reaches the sealed root`, verifyPath(l.leaf, l.path, l.root) && all.some((s) => s.kind === l.kind && s.root === l.root));
  }
  if (inputsFile) {
    const f = JSON.parse(fs.readFileSync(inputsFile, 'utf8'));
    const root = rootOf(f.bodies.map((b) => krLeaf(f.label, b)));
    const seal = resp.in.find((s) => s.kind === f.kind);
    add(`inputs file: ${f.bodies.length} records hash to ${root?.slice(0, 16)}…`, !!seal && seal.root === root, seal ? '' : 'no such inputs seal');
    const out = resp.out.find((s) => s.kind === f.kind.replace(/^in/, 'out'));
    if (out) add('re-run the allocation with: him-api-local keyrace-verify --inputs <file> --outputs <file>', true, `must print root ${out.root}`);
  }
  return { checks, status: checks.every((c) => c.ok) ? 'pass' : 'fail' };
}

// ── main ───────────────────────────────────────────────────────────────────────────────────────

function args(argv) {
  const o = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') o.json = true;
    else if (a.startsWith('--')) o[a.slice(2)] = argv[++i];
    else o._.push(a);
  }
  return o;
}

function print(title, v, json) {
  if (json) { console.log(JSON.stringify({ title, ...v }, null, 2)); return; }
  console.log(title);
  for (const c of v.checks) console.log(`  ${c.ok ? 'PASS' : 'FAIL'}  ${c.name}${c.detail ? '  (' + c.detail + ')' : ''}`);
  const word = { pass: 'PASS - verified against the chain', 'pass-offchain': 'PASS (Merkle only; pass --rpc to check the chain)', fail: 'FAIL', pending: 'PENDING - not sealed yet', partial: 'PARTIAL - verified, but some question was not sealed' }[v.status];
  console.log(`RESULT: ${word}`);
}

const EXIT = { pass: 0, 'pass-offchain': 0, fail: 1, pending: 2, partial: 3 };

async function main() {
  const o = args(process.argv.slice(2));
  const api = o.api ?? process.env.HIM_ESCROW_API_URL ?? 'https://api.him.finance/escrow';
  if (o.epoch !== undefined) {
    const head = await call(api, { action: 'PROOF_EPOCH', epoch: Number(o.epoch), limit: 1 });
    const v = await verifyEpoch(api, Number(o.epoch), { rpc: o.rpc ?? PUBLIC_RPC[head.cluster] });
    print(`epoch ${o.epoch} (${head.cluster})`, v, o.json);
    process.exit(EXIT[v.status]);
  }
  if (o.keyrace !== undefined) {
    const resp = await call(api, { action: 'PROOF_KEYRACE', season: o.keyrace, walletAddress: o.wallet });
    const v = await verifyKeyRace(resp, { rpc: o.rpc ?? PUBLIC_RPC[resp.cluster], inputsFile: o.inputs });
    print(`Key Race ${o.keyrace} (${resp.cluster})`, v, o.json);
    process.exit(EXIT[v.status]);
  }
  const roundId = o._[0];
  if (!roundId) { console.error('usage: node verify-proof.mjs <roundId> | --epoch <n> | --keyrace <season> --wallet <W>   [--api url] [--rpc url] [--open keypair.json] [--json]'); process.exit(64); }
  const resp = await call(api, { action: 'PROOF_ROUND', roundId });
  let openings = [];
  if (o.open) {
    const r = await call(api, signedOpen(o.open, roundId));
    openings = r.openings ?? [];
  }
  const humanTrace = o['human-trace'] ? JSON.parse(fs.readFileSync(o['human-trace'], 'utf8')) : null;
  const v = await verifyRound(resp, { rpc: o.rpc ?? PUBLIC_RPC[resp.cluster], openings, humanTrace });
  print(`round ${roundId} (${resp.kind}, ${resp.cluster})`, v, o.json);
  process.exit(EXIT[v.status]);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((e) => { console.error('verify-proof:', e.message); process.exit(1); });
}
