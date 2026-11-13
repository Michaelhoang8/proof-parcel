import {
  buildTree,
  createProof,
  parseProof,
  parseCheckpoint,
  verifyProof,
  exampleLeaves,
} from './core.js';
const $ = (id) => document.getElementById(id),
  esc = (value) =>
    String(value).replace(
      /[&<>"']/g,
      (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c],
    );
let tree = null,
  selected = 0,
  buildVersion = 0,
  verifyVersion = 0;
function notice(id, text, error = false) {
  $(id).textContent = text;
  $(id).className = error ? 'error' : '';
}
function pending() {
  verifyVersion++;
  $('verdict').className = 'verdict pending';
  $('stamp').textContent = 'PENDING';
  $('verdict-title').textContent = 'Ready for a fresh check.';
  $('verdict-text').textContent =
    'Verify the current proof against the separate trusted root and size.';
  $('hash-path').replaceChildren();
  notice('verify-notice', '');
}
function clearTree() {
  buildVersion++;
  tree = null;
  for (const id of ['trust', 'save-checkpoint', 'restore']) $(id).disabled = true;
  $('leaves').replaceChildren();
  $('leaf-count').textContent = 'PENDING';
  $('tree-root').textContent = 'Record edits are pending.';
  $('tree-shape').textContent = 'Rebuild to compute a new checkpoint.';
  notice(
    'build-notice',
    'The verifier retains its own proof and checkpoint until you replace them.',
  );
}
function selectLeaf(index) {
  if (!tree || !tree.size) return;
  selected = index;
  const proof = createProof(tree, index);
  $('proof').value = JSON.stringify(proof, null, 2);
  $('proof-summary').textContent = `LEAF ${index} / ${tree.size} RECORDS`;
  $('tamper').disabled = false;
  $('save-proof').disabled = false;
  $('restore').disabled = false;
  for (const button of $('leaves').querySelectorAll('button'))
    button.classList.toggle('selected', Number(button.dataset.index) === index);
  pending();
}
async function build() {
  clearTree();
  const version = buildVersion;
  notice('build-notice', 'Hashing exact UTF-8 records…');
  try {
    const candidate = await buildTree($('records').value);
    if (version !== buildVersion) return;
    tree = candidate;
    $('leaf-count').textContent = `${tree.size} RECORDS`;
    $('tree-root').textContent = tree.root;
    $('tree-shape').textContent = tree.size
      ? `${tree.size} leaves · SHA-256 · uneven trees are not padded.`
      : 'Empty-tree root: SHA-256 of an empty byte string. No inclusion proof is possible.';
    $('leaves').innerHTML =
      tree.leaves
        .map(
          (leaf, i) =>
            `<li><button data-index="${i}" aria-label="Select record ${i}"><span class="leaf-number">${String(i).padStart(2, '0')}</span><span class="leaf-text">${esc(leaf.length > 150 ? leaf.slice(0, 150) + '…' : leaf || '(empty string)')}<small>${new TextEncoder().encode(leaf).length} UTF-8 BYTES</small></span></button></li>`,
        )
        .join('') ||
      '<li><p class="help">The tree is empty. Add a record to generate an inclusion proof.</p></li>';
    $('trust').disabled = false;
    $('save-checkpoint').disabled = false;
    if (tree.size) selectLeaf(Math.min(selected, tree.size - 1));
    else {
      $('restore').disabled = true;
    }
    notice('build-notice', 'Tree built. The trusted checkpoint has not been changed.');
    return true;
  } catch (error) {
    if (version === buildVersion) notice('build-notice', error.message, true);
    return false;
  }
}
function useCheckpoint() {
  if (!tree) return;
  $('trusted-root').value = tree.root;
  $('trusted-size').value = tree.size;
  pending();
  notice('verify-notice', 'Current tree root and size selected as the trusted checkpoint.');
}
async function verify() {
  pending();
  const version = verifyVersion;
  notice('verify-notice', 'Reconstructing the root…');
  try {
    const proof = parseProof($('proof').value),
      checkpoint = parseCheckpoint({
        root: $('trusted-root').value.trim(),
        size: Number($('trusted-size').value),
      });
    const result = await verifyProof(proof, checkpoint);
    if (version !== verifyVersion) return;
    $('proof-summary').textContent = `LEAF ${proof.index} / ${proof.size} RECORDS`;
    $('verdict').className = 'verdict ' + (result.valid ? 'valid' : 'invalid');
    $('stamp').textContent = result.valid ? 'MATCH' : 'NO MATCH';
    $('verdict-title').textContent = result.valid
      ? 'The record belongs.'
      : 'The claim does not check out.';
    $('verdict-text').textContent = result.reason;
    $('hash-path').innerHTML = result.leafHash
      ? `<div class="hash-step"><h4>LEAF HASH</h4><code>${result.leafHash}</code></div>` +
        result.steps
          .map(
            (step) =>
              `<div class="hash-step"><h4>STEP ${step.level} / SIBLING ON THE ${step.side.toUpperCase()}</h4><p>Sibling hash</p><code>${step.sibling}</code><p>Combined hash</p><code>${step.after}</code></div>`,
          )
          .join('') +
        `<div class="hash-step"><h4>RECONSTRUCTED ROOT</h4><code>${result.computedRoot}</code></div>`
      : '<p class="help">Tree size did not match the trusted checkpoint; no hash path was accepted.</p>';
    notice(
      'verify-notice',
      result.valid
        ? `Verified ${proof.siblings.length} sibling ${proof.siblings.length === 1 ? 'hash' : 'hashes'} against the selected checkpoint.`
        : 'Verification failed. The trusted checkpoint was left unchanged.',
      !result.valid,
    );
  } catch (error) {
    if (version === verifyVersion) {
      $('verdict').className = 'verdict invalid';
      $('stamp').textContent = 'INVALID';
      $('verdict-title').textContent = 'The inputs are not a valid proof.';
      $('verdict-text').textContent = error.message;
      notice('verify-notice', error.message, true);
    }
  }
}
$('records').addEventListener('input', clearTree);
$('build').addEventListener('click', build);
$('reset').addEventListener('click', () => {
  $('records').value = JSON.stringify(exampleLeaves, null, 2);
  build();
});
$('leaves').addEventListener('click', (event) => {
  const button = event.target.closest('button[data-index]');
  if (button) selectLeaf(Number(button.dataset.index));
});
$('trust').addEventListener('click', useCheckpoint);
$('restore').addEventListener('click', () => {
  if (tree?.size) selectLeaf(selected);
});
for (const id of ['proof', 'trusted-root', 'trusted-size'])
  $(id).addEventListener('input', pending);
$('verify-form').addEventListener('submit', (event) => {
  event.preventDefault();
  verify();
});
$('tamper').addEventListener('click', () => {
  try {
    const proof = parseProof($('proof').value);
    proof.leaf += ' [edited]';
    $('proof').value = JSON.stringify(proof, null, 2);
    verify();
  } catch (error) {
    notice('verify-notice', error.message, true);
  }
});
function download(name, value) {
  const url = URL.createObjectURL(
      new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }),
    ),
    a = document.createElement('a');
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
$('save-checkpoint').addEventListener('click', () => {
  if (tree) download('merkle-checkpoint.json', { root: tree.root, size: tree.size });
});
$('save-proof').addEventListener('click', () => {
  try {
    download('inclusion-proof.json', parseProof($('proof').value));
  } catch (error) {
    notice('verify-notice', error.message, true);
  }
});
$('import').addEventListener('change', async () => {
  const file = $('import').files[0];
  $('import').value = '';
  if (!file) return;
  const version = ++verifyVersion;
  try {
    if (file.size > 120000) throw Error('Proof file exceeds 120 KB.');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(await file.arrayBuffer());
    const proof = parseProof(text);
    if (version !== verifyVersion) return;
    $('proof').value = JSON.stringify(proof, null, 2);
    $('proof-summary').textContent = `IMPORTED / LEAF ${proof.index}`;
    $('tamper').disabled = false;
    $('save-proof').disabled = false;
    pending();
    notice('verify-notice', 'Proof imported. Trusted root and size were not changed.');
  } catch (error) {
    if (version === verifyVersion) notice('verify-notice', 'Import failed: ' + error.message, true);
  }
});
$('records').value = JSON.stringify(exampleLeaves, null, 2);
const initialVerificationVersion = verifyVersion;
build().then((ok) => {
  // Initialize the local example only if the user has not edited the verifier meanwhile.
  if (ok && verifyVersion === initialVerificationVersion + 1) {
    useCheckpoint();
    verify();
  }
});
