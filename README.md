# Proof Parcel

A Merkle inclusion-proof workbench with a separate trusted checkpoint. Build a tree from exact text records, select a leaf, inspect its audit path, export a proof, and test whether edits still reconstruct the trusted root.

![Proof Parcel](docs/workbench.png)

## Run

```sh
python run.py --port 8000
```

Open http://127.0.0.1:8000 in a modern browser with Web Crypto and well-formed Unicode string support. Python 3.10+ serves the static interface; Node.js 22+ is needed only for tests. No runtime packages, accounts, keys, or external services are required. Records are processed in the browser and are not uploaded.

The initial example verifies against its own locally generated checkpoint. After that, selecting records or rebuilding a tree never changes the trusted root and size. **Use this checkpoint** is the explicit action that selects the current tree as the verifier's reference.

## Try it

1. Select a record and verify it. The last record in the five-leaf example has a shorter path than records in the four-leaf subtree.
2. Click **Alter the leaf & verify**. The proof no longer reconstructs the trusted root.
3. Restore the selected proof and verify again.
4. Change the trusted tree size. A matching root is not enough to accept size metadata supplied by the proof.
5. Export a proof, change the trusted root, and import the proof again. Import does not replace the root or size; the changed checkpoint still causes failure.
6. Edit the record collection and rebuild. Choose a new checkpoint explicitly if that new tree is the one you intend to trust.

The builder and verifier are separate. Pending edits in the collection do not invalidate an already verified proof against its existing checkpoint. Choosing a new leaf generates a new proof and clears the verification result until you check it.

## Hash construction

The tree follows the SHA-256 Merkle construction described in RFC 6962:

- Empty tree: `SHA-256(empty bytes)`.
- Leaf: `SHA-256(0x00 || UTF-8(record))`.
- Internal node: `SHA-256(0x01 || left_hash_bytes || right_hash_bytes)`.
- For more than one leaf, split at the largest power of two strictly smaller than the subtree size, then recursively hash both parts.

The prefixes domain-separate leaves from internal nodes. Hashes are combined as raw 32-byte values, not concatenated hexadecimal text. Uneven trees are not padded and the final leaf is not duplicated.

Records preserve exact order and bytes. Empty strings and repeated records are allowed. No Unicode normalization is applied, so visually similar strings with different Unicode representations can hash differently. Ill-formed UTF-16 strings are rejected before UTF-8 encoding rather than silently replaced.

## Proof and checkpoint formats

Proofs contain no trusted root:

```json
{
  "format": "proof-parcel-v1",
  "size": 5,
  "index": 4,
  "leaf": "example record",
  "siblings": ["64 hexadecimal characters per sibling hash"]
}
```

The `siblings` array is ordered from the leaf toward the root. Left/right directions are derived from index and size, not accepted as arbitrary proof instructions. The parser requires the exact number of siblings implied by that shape.

A separate checkpoint is:

```json
{
  "root": "64 hexadecimal characters",
  "size": 5
}
```

The placeholder hashes above illustrate the schema; they are not valid hex values. Export buttons produce valid JSON artifacts.

Verification first checks that the proof's size equals the separately selected checkpoint size, then reconstructs and compares the root. Treat **both root and size** as trusted checkpoint data. Obtaining an authentic checkpoint is outside this app's scope. Inclusion does not authenticate a publisher, establish time, prove record uniqueness, or prove that a sequence of trees is append-only. No signatures, Certificate Transparency wire formats, or consistency proofs are implemented.

## Bounds and behavior

- 0–128 leaves, each at most 4,096 UTF-8 bytes.
- Collection JSON up to 600,000 characters.
- Proof JSON up to 30,000 characters; proof files up to 120 KB with strict UTF-8 decoding.
- Proofs require a nonempty tree, a valid index, and exactly the expected sibling count.
- All hashes are 64 hexadecimal characters; uppercase input is accepted and normalized.
- Imported proofs leave trusted checkpoint fields untouched.
- Async version guards discard stale builds or verifications after later edits.
- The record list scrolls within a bounded panel; hash-path details are collapsible.

There is no persistent browser storage. Export a checkpoint and proof before refreshing if you want to keep them. A proof contains its selected record's plaintext plus sibling hashes; consider that content when sharing the file.

## Verify

```sh
node --test
npm run check
python -m unittest discover -s tests -v
```

Nine JavaScript tests cover empty and singleton trees, hash-domain bytes, all tree sizes through 128 against an independent bottom-up stack-folding oracle, every leaf in selected balanced and unbalanced sizes, record/sibling/index/root tampering, separately trusted sizes, Unicode distinctions, strict proof shapes, and JSON round trips. One Python test checks static-serving boundaries, Host validation, and HEAD behavior.

Browser checks cover valid proofs, tampered records, restoration, the uneven five-leaf path, checkpoint-size mismatch, and proof import with a deliberately incorrect trusted root. CI runs Linux with Node 22/24 and Windows with Node 24.

## Structure

`core.js` handles validation, Web Crypto hashing, tree construction, proof generation, and verification. `app.js` connects the independent builder and verifier. `run.py` is a loopback-only development server with an asset allowlist and restrictive content security policy; it is not a production service.

Tree construction hashes each leaf and internal node once, using O(n) hashes and stored nodes. Proof generation and verification follow O(log n) sibling paths. Leaves remain in memory only for the current browser session.

## Reference

[RFC 6962, section 2.1: Merkle Hash Trees and audit paths](https://www.rfc-editor.org/info/rfc6962/) defines the tree construction used here. Proof Parcel applies those hash-tree rules to generic UTF-8 strings; it is not a Certificate Transparency log implementation.
