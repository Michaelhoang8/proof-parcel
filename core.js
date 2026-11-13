const encoder = new TextEncoder();
const HEX = /^[0-9a-fA-F]{64}$/;

function leafBytes(text) {
  if (typeof text !== 'string' || !text.isWellFormed())
    throw Error('Leaves must be well-formed Unicode strings.');
  if (text.length > 4096) throw Error('Each leaf is limited to 4,096 UTF-8 bytes.');
  const bytes = encoder.encode(text);
  if (bytes.length > 4096) throw Error('Each leaf is limited to 4,096 UTF-8 bytes.');
  return bytes;
}

function hexBytes(hex) {
  if (typeof hex !== 'string' || !HEX.test(hex))
    throw Error('Hashes must contain exactly 64 hexadecimal characters.');
  return Uint8Array.from(hex.match(/../g), (pair) => parseInt(pair, 16));
}

async function digest(bytes) {
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export async function leafHash(text) {
  const bytes = leafBytes(text),
    input = new Uint8Array(bytes.length + 1);
  input.set(bytes, 1); // Leading 0x00 domain-separates leaves.
  return digest(input);
}

export async function nodeHash(left, right) {
  const input = new Uint8Array(65);
  input[0] = 1;
  input.set(hexBytes(left), 1);
  input.set(hexBytes(right), 33);
  return digest(input);
}

function split(size) {
  let power = 1;
  while (power * 2 < size) power *= 2;
  return power;
}

export function parseLeaves(input) {
  if (typeof input === 'string') {
    if (input.length > 600000) throw Error('Leaf JSON exceeds 600,000 characters.');
    try {
      input = JSON.parse(input);
    } catch {
      throw Error('Use a JSON array of leaf strings.');
    }
  }
  if (!Array.isArray(input) || input.length > 128)
    throw Error('Use a JSON array of at most 128 strings.');
  for (const leaf of input) leafBytes(leaf);
  return [...input];
}

export async function buildTree(input) {
  const leaves = parseLeaves(input);
  const hashes = await Promise.all(leaves.map(leafHash));
  async function build(start, end) {
    if (end - start === 1) return { start, end, hash: hashes[start], left: null, right: null };
    const mid = start + split(end - start);
    const [left, right] = await Promise.all([build(start, mid), build(mid, end)]);
    return { start, end, hash: await nodeHash(left.hash, right.hash), left, right };
  }
  const tree = leaves.length ? await build(0, leaves.length) : null;
  return {
    leaves,
    size: leaves.length,
    root: tree?.hash ?? (await digest(new Uint8Array())),
    tree,
  };
}

export function createProof(built, index) {
  if (!Number.isInteger(index) || index < 0 || index >= built.size)
    throw Error('Choose a leaf index inside the tree.');
  const siblings = [];
  function path(node) {
    if (!node.left) return;
    if (index < node.left.end) {
      path(node.left);
      siblings.push(node.right.hash);
    } else {
      path(node.right);
      siblings.push(node.left.hash);
    }
  }
  path(built.tree);
  return {
    format: 'proof-parcel-v1',
    size: built.size,
    index,
    leaf: built.leaves[index],
    siblings,
  };
}

function directions(size, index) {
  if (size === 1) return [];
  const k = split(size);
  return index < k
    ? [...directions(k, index), 'right']
    : [...directions(size - k, index - k), 'left'];
}

export function parseProof(input) {
  if (typeof input === 'string') {
    if (input.length > 30000) throw Error('Proof JSON exceeds 30,000 characters.');
    try {
      input = JSON.parse(input);
    } catch {
      throw Error('Proof must be valid JSON.');
    }
  }
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    input.format !== 'proof-parcel-v1' ||
    Object.keys(input).some((key) => !['format', 'size', 'index', 'leaf', 'siblings'].includes(key))
  )
    throw Error('Unsupported proof format or unknown fields.');
  if (
    !Number.isInteger(input.size) ||
    input.size < 1 ||
    input.size > 128 ||
    !Number.isInteger(input.index) ||
    input.index < 0 ||
    input.index >= input.size
  )
    throw Error('Proof size must be 1–128 and its index must be inside that tree.');
  leafBytes(input.leaf);
  const sides = directions(input.size, input.index);
  if (!Array.isArray(input.siblings) || input.siblings.length !== sides.length)
    throw Error(`This size/index needs exactly ${sides.length} sibling hashes.`);
  for (const hash of input.siblings) hexBytes(hash);
  return {
    format: input.format,
    size: input.size,
    index: input.index,
    leaf: input.leaf,
    siblings: input.siblings.map((hash) => hash.toLowerCase()),
  };
}

export function parseCheckpoint(input) {
  if (
    !input ||
    typeof input !== 'object' ||
    Array.isArray(input) ||
    Object.keys(input).some((key) => !['root', 'size'].includes(key))
  )
    throw Error('A checkpoint contains only root and size.');
  hexBytes(input.root);
  if (!Number.isInteger(input.size) || input.size < 0 || input.size > 128)
    throw Error('Checkpoint size must be 0–128.');
  return { root: input.root.toLowerCase(), size: input.size };
}

export async function verifyProof(input, checkpointInput) {
  const proof = parseProof(input),
    checkpoint = parseCheckpoint(checkpointInput);
  if (proof.size !== checkpoint.size)
    return {
      valid: false,
      reason: 'Proof size differs from the trusted checkpoint size.',
      checkpoint,
      computedRoot: null,
      steps: [],
    };
  let hash = await leafHash(proof.leaf);
  const initialHash = hash,
    sides = directions(proof.size, proof.index),
    steps = [];
  for (let i = 0; i < sides.length; i++) {
    const before = hash;
    hash =
      sides[i] === 'left'
        ? await nodeHash(proof.siblings[i], hash)
        : await nodeHash(hash, proof.siblings[i]);
    steps.push({ level: i + 1, side: sides[i], sibling: proof.siblings[i], before, after: hash });
  }
  const valid = hash === checkpoint.root;
  return {
    valid,
    reason: valid
      ? 'The leaf reconstructs the trusted root at the declared index and size.'
      : 'The reconstructed root does not match the trusted checkpoint.',
    checkpoint,
    computedRoot: hash,
    leafHash: initialHash,
    steps,
  };
}

export const exampleLeaves = [
  'artifact: api-server | version: 1.0.0 | build: 184',
  'artifact: web-client | version: 1.2.0 | build: 219',
  'artifact: worker | version: 0.8.3 | build: 077',
  'artifact: schema | version: 3 | migration: add_jobs',
  'artifact: docs | version: 1.0.0 | build: 031',
];
