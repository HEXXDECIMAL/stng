//! Tests for XOR-pair stack string detection (`StringMethod::XorStackPair`).
//!
//! BrickStorm / garble-obfuscated Go binaries encode sensitive strings by storing two
//! non-printable immediate constants on the stack and XOR-ing them byte-by-byte in a
//! counted loop before passing the result to `runtime.slicebytetostring`.  Neither
//! constant is printable in isolation; XOR of the pair yields the plaintext.
//!
//! Each test encodes a synthetic x86-64 byte sequence that exercises exactly one
//! code path in `finalize_xor_pairs`, then asserts the expected decoded value.
//!
//! Encoding reference for `mov dword [rsp + disp8], imm32` (RSP + SIB form):
//!   C7 44 24 <disp8> <imm32-LE>   (8 bytes total)
//!
//! Encoding reference for `movabs rax, imm64` → `mov [rsp + disp8], rax`:
//!   48 B8 <imm64-LE>              (10 bytes)
//!   48 89 44 24 <disp8>           (5 bytes)

use stng::{extract_stack_strings, StringMethod};

// ── helpers ──────────────────────────────────────────────────────────────────

/// Assemble `mov dword [rsp + disp8], imm32` using the RSP-relative SIB form.
fn c7_rsp(disp: u8, imm: u32) -> Vec<u8> {
    let [b0, b1, b2, b3] = imm.to_le_bytes();
    vec![0xC7, 0x44, 0x24, disp, b0, b1, b2, b3]
}

/// Assemble `movabs rax, imm64` (REX.W B8 /0).
fn movabs_rax(imm: u64) -> Vec<u8> {
    let mut v = vec![0x48, 0xB8];
    v.extend_from_slice(&imm.to_le_bytes());
    v
}

/// Assemble `mov [rsp + disp8], rax` (REX.W 89 /r, SIB form).
fn mov_rsp_rax(disp: u8) -> Vec<u8> {
    vec![0x48, 0x89, 0x44, 0x24, disp]
}

/// Collect all decoded strings produced by `XorStackPair` from the given code bytes.
fn xor_pairs(code: &[u8], min_len: usize) -> Vec<String> {
    let results = extract_stack_strings(code, min_len);
    results
        .into_iter()
        .filter(|s| s.method == StringMethod::XorStackPair)
        .map(|s| s.value)
        .collect()
}

// ── basic C7 / four-byte XOR pairs ───────────────────────────────────────────

/// PATH: the exact BrickStorm encoding observed in the wild.
///   0xe0cefe50 XOR 0xa89abf00 (LE) = "PATH"
#[test]
fn test_c7_xor_pair_path() {
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xe0ce_fe50));
    code.extend(c7_rsp(0x14, 0xa89a_bf00));
    code.push(0xC3); // ret

    let decoded = xor_pairs(&code, 4);
    assert!(
        decoded.contains(&"PATH".to_string()),
        "expected PATH in {decoded:?}"
    );
}

/// TERM: another BrickStorm constant pair.
///   0xd0bb9388 XOR 0x9de9d6dc (LE) = "TERM"
#[test]
fn test_c7_xor_pair_term() {
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xd0bb_9388));
    code.extend(c7_rsp(0x14, 0x9de9_d6dc));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(
        decoded.contains(&"TERM".to_string()),
        "expected TERM in {decoded:?}"
    );
}

/// HOME: another BrickStorm constant pair.
///   0xdb70ed3a XOR 0x9e3da272 (LE) = "HOME"
#[test]
fn test_c7_xor_pair_home() {
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xdb70_ed3a));
    code.extend(c7_rsp(0x14, 0x9e3d_a272));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(
        decoded.contains(&"HOME".to_string()),
        "expected HOME in {decoded:?}"
    );
}

/// Two separate functions (separated by `ret`) each encode their own pair.
/// Both should be decoded independently.
#[test]
fn test_two_functions_each_with_xor_pair() {
    let mut code = Vec::new();
    // function 1: PATH
    code.extend(c7_rsp(0x10, 0xe0ce_fe50));
    code.extend(c7_rsp(0x14, 0xa89a_bf00));
    code.push(0xC3); // ret ends scope

    // function 2: TERM
    code.extend(c7_rsp(0x10, 0xd0bb_9388));
    code.extend(c7_rsp(0x14, 0x9de9_d6dc));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(decoded.contains(&"PATH".to_string()), "missing PATH in {decoded:?}");
    assert!(decoded.contains(&"TERM".to_string()), "missing TERM in {decoded:?}");
}

// ── movabs + register-spill XOR pairs ────────────────────────────────────────

/// BrickStorm also uses `movabs rax, imm64` + `mov [rsp+N], rax` pairs.
///
/// Pair chosen so XOR result = "Content-" (8 printable bytes).
/// Both blobs have all bytes ≥ 0x80 so neither is printable on its own:
///   blob1 LE = [0xFF,0xFE,0xFD,0xFC,0xFB,0xFA,0xF9,0xF8]
///   blob2 LE = blob1 LE XOR "Content-" LE
///            = [0xBC,0x91,0x93,0x88,0x9E,0x94,0x8D,0xD5]
///   XOR result = "Content-"  ✓
#[test]
fn test_movabs_xor_pair_8bytes() {
    // blob1: all bytes ≥ 0x80 → non-printable
    let blob1: u64 = u64::from_le_bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8]);
    // blob2: blob1_LE XOR "Content-"_LE; all bytes also ≥ 0x80 → non-printable
    // "Content-" = [0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d]
    // XOR:         [0xBC,0x91,0x93,0x88,0x9E,0x94,0x8D,0xD5]
    let blob2: u64 = u64::from_le_bytes([0xBC, 0x91, 0x93, 0x88, 0x9E, 0x94, 0x8D, 0xD5]);

    let mut code = Vec::new();
    code.extend(movabs_rax(blob1));
    code.extend(mov_rsp_rax(0x10));
    code.extend(movabs_rax(blob2));
    code.extend(mov_rsp_rax(0x18));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(
        decoded.contains(&"Content-".to_string()),
        "expected 'Content-' in {decoded:?}"
    );
}

// ── negative / false-positive tests ──────────────────────────────────────────

/// A single non-printable blob with no partner produces no XOR output.
#[test]
fn test_single_blob_no_output() {
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xe0ce_fe50)); // only one blob
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(decoded.is_empty(), "expected no XOR results, got {decoded:?}");
}

/// Two non-printable blobs whose XOR result is itself non-printable produce no output.
#[test]
fn test_xor_result_nonprintable_no_output() {
    // blob1: 0x01010101, blob2: 0x02020202
    // XOR: [0x03,0x03,0x03,0x03] — not printable (ETX control characters)
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0x0101_0101));
    code.extend(c7_rsp(0x14, 0x0202_0202));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(decoded.is_empty(), "expected no XOR results, got {decoded:?}");
}

/// A printable blob is already captured by the regular stack-string path; it should
/// NOT also appear as an XOR-pair result (only non-printable blobs participate).
#[test]
fn test_printable_blob_not_xor_candidate() {
    // "ABCD" (0x44434241 LE) is printable; it goes via the regular path.
    // A single non-printable blob on the other slot means no XOR pair is possible.
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0x4443_4241)); // "ABCD" — printable
    code.extend(c7_rsp(0x14, 0xe0ce_fe50)); // non-printable
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(decoded.is_empty(), "expected no XOR results, got {decoded:?}");
}

/// When the XOR result is shorter than min_length it is filtered out.
#[test]
fn test_xor_result_below_min_length_filtered() {
    // Blobs of length 4; XOR result = "HI\x00\x00" (2 printable + 2 null).
    // After null-trim → "HI" (2 chars) which is below min_length=4.
    let blob1: u32 = 0x0000_0048; // LE [0x48, 0x00, 0x00, 0x00]
    let blob2: u32 = 0x0000_0021; // LE [0x21, 0x00, 0x00, 0x00]  → XOR[0] = 'i' (0x69)
    // Actually: 0x48 XOR 0x21 = 0x69 = 'i', 0x00 XOR 0x00 = 0x00.
    // Let's instead construct a deliberate 2-char result:
    // blob1 LE = [0xAA, 0xBB, 0x00, 0x00], blob2 LE = [0xEB, 0xDB, 0x00, 0x00]
    // XOR       = [0x41, 0x60, 0x00, 0x00] → trim nulls → [0x41, 0x60]
    // 0x60 = '`' (printable), 0x41 = 'A' → "A`" (2 chars < 4)
    let _ = (blob1, blob2); // suppress warning on unused vars above

    let b1 = u32::from_le_bytes([0xAA, 0xBB, 0x00, 0x00]);
    let b2 = u32::from_le_bytes([0xEB, 0xDB, 0x00, 0x00]);

    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, b1));
    code.extend(c7_rsp(0x14, b2));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(decoded.is_empty(), "expected XOR result filtered by min_length, got {decoded:?}");
}

// ── no interference with regular stack strings ────────────────────────────────

/// Ensure that adding XOR-pair detection does not suppress legitimate
/// printable-immediate stack strings in the same code stream.
#[test]
fn test_regular_stack_strings_still_detected() {
    // "SHELL" can't be stored in a single 4-byte C7 (5 chars), so use movabs.
    // Use movabs rax, 0x4c4c454853 ("SHELL\0\0\0" in LE? No — movabs is 8 bytes.
    // "SHELL\0\0\0" = [0x53,0x48,0x45,0x4c,0x4c,0x00,0x00,0x00] = 0x00_00_00_4c_4c_45_48_53
    let shell_val: u64 = 0x0000_004c_4c45_4853;

    let mut code = Vec::new();
    // printable movabs → regular path
    code.extend(movabs_rax(shell_val));
    code.extend(mov_rsp_rax(0x10));
    // non-printable pair that XORs to "PATH"
    code.extend(c7_rsp(0x18, 0xe0ce_fe50));
    code.extend(c7_rsp(0x1c, 0xa89a_bf00));
    code.push(0xC3);

    let all = extract_stack_strings(&code, 4);

    let has_shell = all.iter().any(|s| s.value.contains("SHELL"));
    let has_path =
        all.iter().any(|s| s.value == "PATH" && s.method == StringMethod::XorStackPair);

    assert!(has_shell, "regular stack string 'SHELL' missing from {all:?}");
    assert!(has_path, "XOR-pair 'PATH' missing from {all:?}");
}

// ── function-scope isolation ──────────────────────────────────────────────────

/// Blobs split across a `call` boundary (which triggers finalization) must not
/// be paired with each other — each function scope is independent.
#[test]
fn test_blobs_across_call_not_paired() {
    // We pick blob values so that if cross-scope pairing happened the XOR would be
    // printable ("PATH"), but it shouldn't because `call` flushes the scope.
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xe0ce_fe50)); // blob in scope 1
    code.push(0xE8);
    code.extend([0x00u8, 0x00, 0x00, 0x00]); // call (flushes scope 1)
    code.extend(c7_rsp(0x10, 0xa89a_bf00)); // blob in scope 2
    code.push(0xC3); // ret (flushes scope 2)

    let decoded = xor_pairs(&code, 4);
    // Each scope has only one blob → no pairs → no XOR output.
    assert!(decoded.is_empty(), "expected no cross-scope pairs, got {decoded:?}");
}

// ── three-or-more blob groups ─────────────────────────────────────────────────

/// When three blobs of the same length are present, only the pair that XORs to
/// printable ASCII should be emitted; spurious pairs should be suppressed.
#[test]
fn test_three_blobs_only_valid_pair_emitted() {
    // blob_a XOR blob_b = "PATH"
    // blob_a XOR blob_c = non-printable
    // blob_b XOR blob_c = non-printable
    //
    // blob_a LE = [0x50, 0xFE, 0xCE, 0xE0]  (from 0xe0cefe50)
    // blob_b LE = [0x00, 0xBF, 0x9A, 0xA8]  (from 0xa89abf00)
    // blob_c LE = [0x01, 0x01, 0x01, 0x01]  (non-printable)
    //
    // a XOR b = [0x50, 0x41, 0x54, 0x48] = "PATH" ✓
    // a XOR c = [0x51, 0xFF, 0xCF, 0xE1] → non-printable ✓
    // b XOR c = [0x01, 0xBE, 0x9B, 0xA9] → non-printable ✓

    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xe0ce_fe50)); // blob_a
    code.extend(c7_rsp(0x14, 0xa89a_bf00)); // blob_b
    code.extend(c7_rsp(0x18, 0x0101_0101)); // blob_c
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert_eq!(decoded, vec!["PATH"], "expected exactly [PATH], got {decoded:?}");
}

// ── duplicate suppression ─────────────────────────────────────────────────────

/// The same non-printable value written to two different stack slots should not
/// produce "AAAA..." from self-XOR (all-zeros result), and duplicate pairs that
/// decode to the same string should only appear once.
#[test]
fn test_duplicate_xor_results_deduplicated() {
    // Write blob_a twice (different displacements) and blob_b twice.
    // Two pairs (a0,b0), (a0,b1), (a1,b0), (a1,b1) all decode to "PATH".
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xe0ce_fe50)); // a0
    code.extend(c7_rsp(0x14, 0xa89a_bf00)); // b0
    code.extend(c7_rsp(0x18, 0xe0ce_fe50)); // a1 (same as a0)
    code.extend(c7_rsp(0x1c, 0xa89a_bf00)); // b1 (same as b0)
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    let path_count = decoded.iter().filter(|s| *s == "PATH").count();
    assert_eq!(path_count, 1, "expected exactly one 'PATH', got {decoded:?}");
}

/// Self-XOR of the same blob (a XOR a = zeros) must not produce output.
#[test]
fn test_self_xor_all_zeros_filtered() {
    // Write blob_a to two stack slots; a XOR a = [0,0,0,0] which is non-printable.
    let mut code = Vec::new();
    code.extend(c7_rsp(0x10, 0xe0ce_fe50));
    code.extend(c7_rsp(0x14, 0xe0ce_fe50)); // identical
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(decoded.is_empty(), "self-XOR should produce nothing, got {decoded:?}");
}

// ── multi-chunk sequence merging ──────────────────────────────────────────────

/// Three consecutive C7-encoded XOR pairs that form a three-chunk string.
///
///   ciphertext[0..2] at disp=0,4,8    (stride=4=chunk_size)
///   key[0..2]        at disp=64,68,72 (key_offset=64)
///   Decoded: "ABCDEFGHIJKL" (12 chars from 3×4-byte chunks)
#[test]
fn test_three_chunk_merge_c7() {
    let ct0: u32 = 0xFFFF_FFFF;
    let ct1: u32 = 0xFEFE_FEFE;
    let ct2: u32 = 0xFDFD_FDFD;
    // key[i] = ciphertext[i] XOR plaintext_chunk[i]
    // key[0] XOR 0xFFFFFFFF = "ABCD" LE → key[0] LE = [0xFF^0x41,0xFF^0x42,0xFF^0x43,0xFF^0x44]
    let k0: u32 = u32::from_le_bytes([0xBE, 0xBD, 0xBC, 0xBB]);
    let k1: u32 = u32::from_le_bytes([0xBB, 0xB8, 0xB9, 0xB6]); // "EFGH"
    let k2: u32 = u32::from_le_bytes([0xB4, 0xB7, 0xB6, 0xB1]); // "IJKL"

    let mut code = Vec::new();
    code.extend(c7_rsp(0, ct0));
    code.extend(c7_rsp(4, ct1));
    code.extend(c7_rsp(8, ct2));
    code.extend(c7_rsp(64, k0));
    code.extend(c7_rsp(68, k1));
    code.extend(c7_rsp(72, k2));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(
        decoded.contains(&"ABCDEFGHIJKL".to_string()),
        "expected 'ABCDEFGHIJKL' in {decoded:?}"
    );
    assert!(!decoded.contains(&"ABCD".to_string()), "'ABCD' should be merged: {decoded:?}");
    assert!(!decoded.contains(&"EFGH".to_string()), "'EFGH' should be merged: {decoded:?}");
    assert!(!decoded.contains(&"IJKL".to_string()), "'IJKL' should be merged: {decoded:?}");
}

/// Three consecutive movabs-encoded XOR pairs forming a 24-byte string.
///
/// Simulates BrickStorm's 8-byte-chunk encoding:
///   ciphertext at disp= 0, 8,16  (stride=8)
///   key        at disp=48,56,64  (key_offset=48)
///   Decoded: "ABCDEFGHIJKLMNOPQRSTUVWX"
#[test]
fn test_three_chunk_merge_movabs() {
    let ct0 = u64::from_le_bytes([0xFF; 8]);
    let ct1 = u64::from_le_bytes([0xFE; 8]);
    let ct2 = u64::from_le_bytes([0xFD; 8]);
    // key[0] = ct[0] XOR "ABCDEFGH" = [0xFF^0x41,…,0xFF^0x48] = [0xBE,0xBD,0xBC,0xBB,0xBA,0xB9,0xB8,0xB7]
    let k0 = u64::from_le_bytes([0xBE, 0xBD, 0xBC, 0xBB, 0xBA, 0xB9, 0xB8, 0xB7]);
    // key[1] = ct[1] XOR "IJKLMNOP" = [0xFE^0x49,…] = [0xB7,0xB4,0xB5,0xB2,0xB3,0xB0,0xB1,0xAE]
    let k1 = u64::from_le_bytes([0xB7, 0xB4, 0xB5, 0xB2, 0xB3, 0xB0, 0xB1, 0xAE]);
    // key[2] = ct[2] XOR "QRSTUVWX" = [0xFD^0x51,…] = [0xAC,0xAF,0xAE,0xA9,0xA8,0xAB,0xAA,0xA5]
    let k2 = u64::from_le_bytes([0xAC, 0xAF, 0xAE, 0xA9, 0xA8, 0xAB, 0xAA, 0xA5]);

    let mut code = Vec::new();
    code.extend(movabs_rax(ct0));
    code.extend(mov_rsp_rax(0));
    code.extend(movabs_rax(ct1));
    code.extend(mov_rsp_rax(8));
    code.extend(movabs_rax(ct2));
    code.extend(mov_rsp_rax(16));
    code.extend(movabs_rax(k0));
    code.extend(mov_rsp_rax(48));
    code.extend(movabs_rax(k1));
    code.extend(mov_rsp_rax(56));
    code.extend(movabs_rax(k2));
    code.extend(mov_rsp_rax(64));
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);
    assert!(
        decoded.contains(&"ABCDEFGHIJKLMNOPQRSTUVWX".to_string()),
        "expected 24-char merged string in {decoded:?}"
    );
    assert!(!decoded.contains(&"ABCDEFGH".to_string()), "'ABCDEFGH' should be merged: {decoded:?}");
    assert!(!decoded.contains(&"IJKLMNOP".to_string()), "'IJKLMNOP' should be merged: {decoded:?}");
    assert!(!decoded.contains(&"QRSTUVWX".to_string()), "'QRSTUVWX' should be merged: {decoded:?}");
}

/// Two consecutive XOR pairs with the same key offset are merged into one string.
///
/// BrickStorm encodes long strings as parallel sequences of immediates on the
/// stack ("ciphertext" and "key").  Each pair covers one chunk; here two 4-byte
/// C7 pairs decode to "ABCD" and "EFGH" and must be concatenated into "ABCDEFGH".
///
/// Layout (all at rsp-relative displacements):
///   ciphertext[0] at disp= 0,  ciphertext[1] at disp= 4  (stride = 4 = chunk_size)
///   key[0]        at disp=32,  key[1]        at disp=36  (key_offset = 32)
///
///   XOR(ciphertext[0], key[0]) = "ABCD"
///   XOR(ciphertext[1], key[1]) = "EFGH"
///   Merged result:               "ABCDEFGH"
#[test]
fn test_multi_chunk_merge() {
    // ciphertext blobs: all bytes 0xFF / 0xFE (non-printable, differ so ct^ct = 0x01…)
    // key[0] = ciphertext[0] XOR "ABCD" = [0xFF^0x41, …] = [0xBE,0xBD,0xBC,0xBB]
    // key[1] = ciphertext[1] XOR "EFGH" = [0xFE^0x45, …] = [0xBB,0xB8,0xB9,0xB6]
    let ct0: u32 = 0xFFFF_FFFF;
    let ct1: u32 = 0xFEFE_FEFE;
    let k0: u32 = u32::from_le_bytes([0xBE, 0xBD, 0xBC, 0xBB]);
    let k1: u32 = u32::from_le_bytes([0xBB, 0xB8, 0xB9, 0xB6]);

    let mut code = Vec::new();
    code.extend(c7_rsp(0, ct0));  // ciphertext[0] at disp=0
    code.extend(c7_rsp(4, ct1));  // ciphertext[1] at disp=4
    code.extend(c7_rsp(32, k0)); // key[0]        at disp=32
    code.extend(c7_rsp(36, k1)); // key[1]        at disp=36
    code.push(0xC3);

    let decoded = xor_pairs(&code, 4);

    assert!(
        decoded.contains(&"ABCDEFGH".to_string()),
        "expected merged 'ABCDEFGH' in {decoded:?}"
    );
    assert!(
        !decoded.contains(&"ABCD".to_string()),
        "'ABCD' should have been merged into 'ABCDEFGH': {decoded:?}"
    );
    assert!(
        !decoded.contains(&"EFGH".to_string()),
        "'EFGH' should have been merged into 'ABCDEFGH': {decoded:?}"
    );
}
