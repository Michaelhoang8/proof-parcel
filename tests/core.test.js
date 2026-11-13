import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  buildTree,
  createProof,
  verifyProof,
  leafHash,
  nodeHash,
  parseLeaves,
  parseProof,
  parseCheckpoint,
} from '../core.js';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
function oracle(leaves) {
  if (!leaves.length) return sha(Buffer.alloc(0));
  // Independent bottom-up stack folding of complete subtrees.
  const stack = [];
  for (const text of leaves) {
    let item = { size: 1, hash: sha(Buffer.concat([Buffer.from([0]), Buffer.from(text)])) };
    while (stack.length && stack.at(-1).size === item.size) {
      const left = stack.pop();
      item = {
        size: item.size * 2,
        hash: sha(
          Buffer.concat([
            Buffer.from([1]),
            Buffer.from(left.hash, 'hex'),
            Buffer.from(item.hash, 'hex'),
          ]),
        ),
      };
    }
    stack.push(item);
  }
  let right = stack.pop().hash;
  while (stack.length)
    right = sha(
      Buffer.concat([
        Buffer.from([1]),
        Buffer.from(stack.pop().hash, 'hex'),
        Buffer.from(right, 'hex'),
      ]),
    );
  return right;
}
test('empty root and leaf/node domain separation use the specified bytes', async () => {
  assert.equal(
    (await buildTree([])).root,
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  );
  assert.equal(await leafHash(''), sha(Buffer.from([0])));
  assert.equal(await leafHash('café'), sha(Buffer.concat([Buffer.from([0]), Buffer.from('café')])));
  const a = await leafHash('a'),
    b = await leafHash('b');
  assert.equal(
    await nodeHash(a, b),
    sha(Buffer.concat([Buffer.from([1]), Buffer.from(a, 'hex'), Buffer.from(b, 'hex')])),
  );
});
test('all sizes through 128 match an independent stack-folding oracle', async () => {
  for (let size = 0; size <= 128; size++) {
    const leaves = Array.from({ length: size }, (_, i) => `record ${i}`);
    assert.equal((await buildTree(leaves)).root, oracle(leaves));
  }
});
test('every leaf verifies for balanced and unbalanced trees', async () => {
  for (const size of [1, 2, 3, 5, 7, 8, 9, 31, 32, 33, 127, 128]) {
    const tree = await buildTree(Array.from({ length: size }, (_, i) => `leaf-${i}`));
    for (let index = 0; index < size; index++)
      assert.equal(
        (await verifyProof(createProof(tree, index), { root: tree.root, size })).valid,
        true,
      );
  }
});
test('changed leaf, sibling, index, or trusted root cannot silently verify', async () => {
  const tree = await buildTree(['a', 'b', 'c', 'd', 'e']),
    proof = createProof(tree, 1),
    checkpoint = { root: tree.root, size: tree.size };
  assert.equal((await verifyProof({ ...proof, leaf: 'tampered' }, checkpoint)).valid, false);
  const changed = structuredClone(proof);
  changed.siblings[0] = '00'.repeat(32);
  assert.equal((await verifyProof(changed, checkpoint)).valid, false);
  assert.equal((await verifyProof({ ...proof, index: 0 }, checkpoint)).valid, false);
  assert.equal((await verifyProof(proof, { root: '00'.repeat(32), size: 5 })).valid, false);
});
test('tree size is trusted separately instead of being accepted from proof metadata', async () => {
  const tree = await buildTree(['a', 'b', 'c']),
    proof = createProof(tree, 0);
  // Index 0 has the same path directions for sizes 3 and 4. Root alone is insufficient metadata.
  const forged = { ...proof, size: 4 };
  const result = await verifyProof(forged, { root: tree.root, size: 3 });
  assert.equal(result.valid, false);
  assert.match(result.reason, /size/);
});
test('single-leaf proofs need no siblings; empty trees cannot produce proofs', async () => {
  const tree = await buildTree(['']);
  assert.deepEqual(createProof(tree, 0).siblings, []);
  assert.equal((await verifyProof(createProof(tree, 0), { root: tree.root, size: 1 })).valid, true);
  assert.throws(() => createProof({ size: 0 }, 0));
});
test('order, duplicates, and exact Unicode bytes are preserved', async () => {
  assert.notEqual((await buildTree(['a', 'b'])).root, (await buildTree(['b', 'a'])).root);
  assert.notEqual(await leafHash('é'), await leafHash('e\u0301'));
  const tree = await buildTree(['same', 'same', 'other']);
  for (const index of [0, 1])
    assert.equal(
      (await verifyProof(createProof(tree, index), { root: tree.root, size: 3 })).valid,
      true,
    );
});
test('strict proof shapes, hashes, leaf sizes and checkpoint fields reject invalid data', async () => {
  const tree = await buildTree(['a', 'b']),
    proof = createProof(tree, 0);
  for (const patch of [
    { siblings: [] },
    { siblings: ['bad'] },
    { size: 0 },
    { index: -1 },
    { extra: true },
    { format: 'other' },
  ])
    assert.throws(() => parseProof({ ...proof, ...patch }));
  for (const input of [[1], Array(129).fill('a'), ['x'.repeat(4097)], ['\ud800']])
    assert.throws(() => parseLeaves(input));
  assert.throws(() => parseProof('{'));
  assert.throws(() => parseCheckpoint({ root: tree.root, size: 2, extra: true }));
  assert.throws(() => parseCheckpoint({ root: tree.root, size: 2.5 }));
});
test('exports round-trip and proof verification leaves caller data unchanged', async () => {
  const tree = await buildTree(['one', 'two', 'three']);
  const proof = createProof(tree, 2),
    copy = structuredClone(proof);
  const parsed = parseProof(JSON.stringify(proof));
  assert.deepEqual(parsed, proof);
  await verifyProof(proof, { root: tree.root.toUpperCase(), size: 3 });
  assert.deepEqual(proof, copy);
});
