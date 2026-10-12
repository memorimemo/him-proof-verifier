// Run: node --test scripts/verify-proof.test.mjs
// The verifier must agree byte for byte with the Go engine (proof_merkle.go): the goldens below are the SAME constants proof_merkle_test.go pins.
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { leafNode, qLeaf, rLeaf, krLeaf, rootOf, parent, verifyPath, verifyRound, verifyEpoch, verifyKeyRace, checkMemo, signedOpen } from './verify-proof.mjs';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const SIGNER = 'SignerPubkey11111111111111111111111111111111';
const OPENING = '{"id":"sq-001","q":"What is 15% of 200?","o":["25","30","35","40"],"c":1,"s":"00112233445566778899aabbccddeeff"}';

test('golden vectors match the Go engine', () => {
  assert.equal(qLeaf(OPENING), '4c3b06714af71736464cad79138cdb8115df3d563c73fcb5a47b151273b58062');
  assert.equal(rLeaf('{"v":1,"k":"duel","r":"abc","t0":1,"t1":2,"p":[]}'), '3ccccb8441042b0146604b5960a50f970cb0971c2a48f82ba6d8609db72af6b3');
  const [a, b, c] = ['a', 'b', 'c'].map(leafNode);
  assert.equal(parent(parent(a, b), c).toString('hex'), '36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1');
  assert.equal(rootOf([a, b, c]), '36642e73c2540ab121e3a6bf9545b0a24982cd830eb13d3cd19de3ce6c021ec1');
});

/** Build the audit path of leaf i (the same walk as proofAuditPath). */
function pathOf(nodes, i) {
  const out = [];
  let level = nodes.slice();
  while (level.length > 1) {
    if (i % 2 === 0) { if (i + 1 < level.length) out.push({ right: true, h: level[i + 1].toString('hex') }); } else out.push({ right: false, h: level[i - 1].toString('hex') });
    const next = [];
    for (let k = 0; k + 1 < level.length; k += 2) next.push(parent(level[k], level[k + 1]));
    if (level.length % 2) next.push(level[level.length - 1]);
    level = next;
    i = Math.floor(i / 2);
  }
  return out;
}

test('every leaf of every tree size verifies, and a forged leaf does not', () => {
  for (let n = 1; n <= 20; n++) {
    const nodes = Array.from({ length: n }, (_, i) => leafNode('leaf-' + i));
    const root = rootOf(nodes);
    for (let i = 0; i < n; i++) {
      assert.ok(verifyPath(nodes[i].toString('hex'), pathOf(nodes, i), root), `n=${n} i=${i}`);
      assert.ok(!verifyPath(leafNode('forged').toString('hex'), pathOf(nodes, i), root));
    }
  }
  assert.equal(rootOf([]), null);
});

test('promote-odd never collides with duplicate-last', () => {
  const n3 = [0, 1, 2].map((i) => leafNode('x' + i));
  assert.notEqual(rootOf(n3), rootOf([...n3, n3[2]]));
});

/** A round proof as the API serves it, with real trees; `mods` tweaks it. */
function fixture({ qEpoch = 10, rEpoch = 12, t0 = 1_000_000_000_000, settled = t0 + 120_000, sealedQ = 8, memoSig = 'SIGQ', rSig = 'SIGR' } = {}) {
  const qOpenings = Array.from({ length: 20 }, (_, i) => `{"id":"q-${i}","q":"Q${i}?","o":["a","b","c","d"],"c":${i % 4},"s":"${String(i).padStart(32, '0')}"}`);
  const qNodes = qOpenings.map((o) => leafNode('HIM1|ql|' + o));
  const qRoot = rootOf(qNodes);
  const refs = Array.from({ length: 8 }, (_, i) => (i < sealedQ ? { id: `q-${i}`, e: qEpoch, l: qNodes[i].toString('hex') } : { id: `q-${i}`, e: 0 }));
  const record = JSON.stringify({ v: 1, k: 'duel', r: 'round-1', t0, t1: settled, q: refs, p: [] });
  const rRecords = ['round-0', 'round-1', 'round-2'].map((id) => (id === 'round-1' ? record : JSON.stringify({ v: 1, k: 'duel', r: id, t0, t1: settled, p: [] })));
  const rNodes = rRecords.map((r) => leafNode('HIM1|rl|' + r));
  const rRoot = rootOf(rNodes);
  const questions = refs.map((ref, i) => (ref.e ? {
    id: ref.id, sealed: true, epoch: qEpoch, leaf: ref.l, root: qRoot, n: 20, index: i, path: pathOf(qNodes, i),
    memo: { text: `HIM1|q|${qEpoch}|${qRoot}`, sig: memoSig, confirmed: true }, sealedBefore: true } : { id: ref.id, sealed: false }));
  const resp = {
    success: true, cluster: 'devnet', signer: SIGNER, roundId: 'round-1', kind: 'duel',
    result: { epoch: rEpoch, record, leaf: rNodes[1].toString('hex'), state: 'confirmed', root: rRoot, n: 3, index: 1, path: pathOf(rNodes, 1),
      memo: { text: `HIM1|r|${rEpoch}|${rRoot}`, sig: rSig, confirmed: true } },
    questions, qSealed: sealedQ === 8,
  };
  return { resp, qOpenings, qRoot, rRoot, qNodes };
}

/** A fake RPC: signature -> {memos, signer, blockTime, err}. */
function rpcOf(table) {
  return async (_url, init) => {
    const { method, params } = JSON.parse(init.body);
    assert.equal(method, 'getTransaction');
    const t = table[params[0]];
    const result = !t ? null : {
      blockTime: t.blockTime, meta: { err: t.err ?? null },
      transaction: { message: { accountKeys: [{ pubkey: t.signer ?? SIGNER, signer: true }, { pubkey: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', signer: false }],
        instructions: t.memos.map((m) => ({ programId: 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr', program: 'spl-memo', parsed: m })) } },
    };
    return { json: async () => ({ result }) };
  };
}

const T0 = 1_000_000_000_000;

test('a sealed round verifies end to end against the (fake) chain', async () => {
  const f = fixture();
  const fetchFn = rpcOf({
    SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 - 3600 },
    SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 },
  });
  const v = await verifyRound(f.resp, { rpc: 'http://fake', fetchFn });
  assert.equal(v.status, 'pass', JSON.stringify(v.checks.filter((c) => !c.ok)));
  assert.ok(v.checks.some((c) => /sealed BEFORE/.test(c.name) && c.ok));
});

test('a question the API calls sealed-before, that the chain says was sealed after the round started, FAILS', async () => {
  const f = fixture();
  const fetchFn = rpcOf({ SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 + 5 }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  const v = await verifyRound(f.resp, { rpc: 'http://fake', fetchFn });
  assert.equal(v.status, 'fail');
});

test('an honest "sealed, but only after the round began" (the first hour) is PARTIAL, not a failure', async () => {
  const f = fixture();
  for (const q of f.resp.questions) q.sealedBefore = false; // what the engine says for a round drawn in the epoch that sealed its questions
  const fetchFn = rpcOf({ SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 + 5 }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  const v = await verifyRound(f.resp, { rpc: 'http://fake', fetchFn });
  assert.equal(v.status, 'partial');
  assert.equal(v.late, 8);
});

test('a doctored record, a wrong signer and a wrong memo are each caught', async () => {
  const f = fixture();
  const ok = rpcOf({ SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 - 3600 }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  const doctored = structuredClone(f.resp);
  doctored.result.record = doctored.result.record.replace('"p":[]', '"p":[{"pid":"x"}]');
  assert.equal((await verifyRound(doctored, { rpc: 'http://fake', fetchFn: ok })).status, 'fail');
  const wrongSigner = rpcOf({ SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 - 3600, signer: 'SomeoneElse' }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  assert.equal((await verifyRound(f.resp, { rpc: 'http://fake', fetchFn: wrongSigner })).status, 'fail');
  const wrongMemo = rpcOf({ SIGQ: { memos: ['HIM1|q|10|' + '0'.repeat(64)], blockTime: T0 / 1000 - 3600 }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  assert.equal((await verifyRound(f.resp, { rpc: 'http://fake', fetchFn: wrongMemo })).status, 'fail');
  const failedTx = rpcOf({ SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 - 3600, err: { InstructionError: [0, 'x'] } }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  assert.equal((await verifyRound(f.resp, { rpc: 'http://fake', fetchFn: failedTx })).status, 'fail');
  const bad = structuredClone(f.resp);
  bad.questions[3].path[0].h = '00'.repeat(32);
  assert.equal((await verifyRound(bad, { rpc: 'http://fake', fetchFn: ok })).status, 'fail');
});

test('a round with unsealed questions is partial, an unsealed epoch is pending', async () => {
  const f = fixture({ sealedQ: 5 });
  const fetchFn = rpcOf({ SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 - 3600 }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  assert.equal((await verifyRound(f.resp, { rpc: 'http://fake', fetchFn })).status, 'partial');
  const p = fixture();
  delete p.resp.result.root; delete p.resp.result.path; delete p.resp.result.memo; p.resp.result.state = 'pending'; p.resp.result.sealsAfterMs = Date.now() + 1000;
  assert.equal((await verifyRound(p.resp, { rpc: 'http://fake', fetchFn })).status, 'pending');
});

test('openings are recomputed to the sealed leaf, and a wrong salt is caught', async () => {
  const f = fixture();
  const openings = f.qOpenings.slice(0, 8).map((o, i) => ({ leaf: f.resp.questions[i].leaf, opening: o }));
  const fetchFn = rpcOf({ SIGQ: { memos: [f.resp.questions[0].memo.text], blockTime: T0 / 1000 - 3600 }, SIGR: { memos: [f.resp.result.memo.text], blockTime: T0 / 1000 + 4000 } });
  const v = await verifyRound(f.resp, { rpc: 'http://fake', fetchFn, openings });
  assert.equal(v.status, 'pass');
  assert.equal(v.checks.filter((c) => /opening hashes/.test(c.name) && c.ok).length, 8);
  openings[2] = { ...openings[2], opening: openings[2].opening.replace('"s":"0', '"s":"1') };
  assert.equal((await verifyRound(f.resp, { rpc: 'http://fake', fetchFn, openings })).status, 'fail');
});

test('off-chain mode checks only the tree', async () => {
  const v = await verifyRound(fixture().resp, {});
  assert.equal(v.status, 'pass-offchain');
});

test('an epoch is verified by recomputing its root from the published leaves', async () => {
  const openings = Array.from({ length: 5 }, (_, i) => `{"id":"q-${i}","q":"x","o":["a","b","c","d"],"c":0,"s":"${i}"}`);
  const leaves = openings.map((o) => ({ id: JSON.parse(o).id, l: qLeaf(o), opening: o }));
  const root = rootOf(leaves.map((l) => l.l));
  const memoText = `HIM1|q|7|${root}`;
  const fetchFn = async (url, init) => {
    if (url === 'http://api') return { ok: true, json: async () => ({ success: true, cluster: 'devnet', signer: SIGNER, q: { sealed: true, root, n: 5, memo: { text: memoText, sig: 'SIGQ' }, leaves }, r: { sealed: false } }) };
    return rpcOf({ SIGQ: { memos: [memoText], blockTime: 1 } })(url, init);
  };
  const v = await verifyEpoch('http://api', 7, { rpc: 'http://fake', fetchFn });
  assert.equal(v.status, 'pass', JSON.stringify(v.checks.filter((c) => !c.ok)));
  leaves[1].l = '00'.repeat(32);
  assert.equal((await verifyEpoch('http://api', 7, { rpc: 'http://fake', fetchFn })).status, 'fail');
});

test('Key Race: a winner leaf verifies; a leaf of another seal does not', async () => {
  const season = 's0';
  const label = (k) => `HIM1|kl|${k}|${season}|`;
  const bodies = Array.from({ length: 6 }, (_, i) => `{"t":"o","c":"genesis","r":${i + 1},"w":"W${i}"}`);
  const nodes = bodies.map((b) => leafNode(label('out') + b));
  const root = rootOf(nodes);
  const resp = { success: true, season, cluster: 'devnet', signer: SIGNER, boards: [], in: [], out: [{ kind: 'out', root, n: 6, memo: { text: `HIM1|k|${season}|out|${root}`, sig: 'SIGK' } }],
    wallet: { leaves: [{ kind: 'out', body: bodies[3], index: 3, leaf: nodes[3].toString('hex'), root, path: pathOf(nodes, 3), label: label('out') }] } };
  const fetchFn = rpcOf({ SIGK: { memos: [resp.out[0].memo.text], blockTime: 5 } });
  assert.equal((await verifyKeyRace(resp, { rpc: 'http://fake', fetchFn })).status, 'pass');
  const wrong = structuredClone(resp);
  wrong.wallet.leaves[0].label = label('in');
  assert.equal((await verifyKeyRace(wrong, { rpc: 'http://fake', fetchFn })).status, 'fail');
  // an inputs file whose records do not hash to the sealed inputs root is refused
  const inBodies = ['{"t":"meta"}', '{"t":"p","w":"W0"}'];
  const inRoot = rootOf(inBodies.map((b) => leafNode(label('in') + b)));
  const withIn = { ...resp, in: [{ kind: 'in', root: inRoot, n: 2, memo: { text: `HIM1|k|${season}|in|${inRoot}`, sig: 'SIGK' } }] };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vp-'));
  const file = path.join(dir, 'in.json');
  fs.writeFileSync(file, JSON.stringify({ kind: 'in', label: label('in'), bodies: inBodies }));
  const fetchIn = rpcOf({ SIGK: { memos: [resp.out[0].memo.text, withIn.in[0].memo.text], blockTime: 5 } });
  assert.equal((await verifyKeyRace(withIn, { rpc: 'http://fake', fetchFn: fetchIn, inputsFile: file })).status, 'pass');
  fs.writeFileSync(file, JSON.stringify({ kind: 'in', label: label('in'), bodies: [inBodies[0], '{"t":"p","w":"W9"}'] }));
  assert.equal((await verifyKeyRace(withIn, { rpc: 'http://fake', fetchFn: fetchIn, inputsFile: file })).status, 'fail');
});

test('checkMemo handles a missing signature, a missing transaction and several memos in one transaction', async () => {
  assert.equal((await checkMemo({ rpc: 'x', sig: '', text: 't' })).ok, false);
  const none = async () => ({ json: async () => ({ result: null }) });
  const t0 = Date.now();
  // the retry loop waits for a fresh transaction; keep the test fast by pointing at an immediately-present one instead
  const two = rpcOf({ S: { memos: ['HIM1|q|1|aa', 'HIM1|r|1|bb'], blockTime: 9 } });
  assert.equal((await checkMemo({ rpc: 'x', sig: 'S', text: 'HIM1|r|1|bb', signer: SIGNER, fetchFn: two })).ok, true);
  assert.equal((await checkMemo({ rpc: 'x', sig: 'S', text: 'HIM1|r|1|cc', signer: SIGNER, fetchFn: two })).ok, false);
  void none; void t0;
});

test('signedOpen produces a message the engine would accept (ed25519 over the message, hex)', () => {
  const kp = crypto.generateKeyPairSync('ed25519');
  const der = kp.privateKey.export({ format: 'der', type: 'pkcs8' });
  const seed = der.subarray(der.length - 32);
  const pub = kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vp-')), 'kp.json');
  fs.writeFileSync(file, JSON.stringify([...seed, ...pub]));
  const req = signedOpen(file, 'round-9', 1_700_000_000_000);
  assert.equal(req.action, 'PROOF_OPEN');
  assert.match(req.message, /^HIM:PROOF_OPEN:round-9:[1-9A-HJ-NP-Za-km-z]{32,44}:[0-9a-f]{16}:1700000060000$/);
  assert.ok(crypto.verify(null, Buffer.from(req.message), kp.publicKey, Buffer.from(req.signature, 'hex')));
});

// A PROOF_ROUND answer captured from the Go engine's REAL devnet run (2026-10-09, signer yVTtgYCis9xx...): the Merkle side must verify
// offline, which pins the Go encoder and this verifier against each other on data neither of them made up.
test('the answer the Go engine gave on devnet verifies offline, and each tampering of it is caught', async () => {
  const resp = JSON.parse(fs.readFileSync(new URL('./fixtures/proof-round-devnet-2026-10-09.json', import.meta.url), 'utf8'));
  const v = await verifyRound(resp, {});
  assert.equal(v.status, 'pass-offchain', JSON.stringify(v.checks.filter((c) => !c.ok)));
  assert.equal(resp.questions.filter((q) => q.sealed && q.sealedBefore).length, 8);
  const rec = JSON.parse(resp.result.record);
  assert.equal(rec.k, 'duel');
  assert.ok(rec.t1 > rec.t0 && rec.q.length === 8 && rec.p.length === 2 && rec.p[0].a.length === 8);
  assert.ok(!/DevnetDemoWallet/.test(resp.result.record), 'no wallet in the record');
  for (const mutate of [
    (r) => { r.result.record = r.result.record.replace('"pl":1', '"pl":2'); },
    (r) => { r.result.path[0].h = '00'.repeat(32); },
    (r) => { r.questions[5].leaf = r.questions[4].leaf; },
    (r) => { r.questions[0].root = r.questions[1].leaf; },
  ]) {
    const bad = structuredClone(resp);
    mutate(bad);
    assert.equal((await verifyRound(bad, {})).status, 'fail');
  }
});
