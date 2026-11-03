//! AES-256 (FIPS-197), implemented directly — the SPEC's
//! pattern for small format primitives with public test
//! vectors, following the hand-rolled MD5 in `godot.rs`.
//!
//! Only what the archive readers need: single-block
//! encrypt/decrypt, ECB over block-aligned buffers (Unreal
//! pak index and entry encryption), and CFB with 128-bit
//! segments (Godot's `FileAccessEncrypted` streams). The
//! S-boxes are derived from GF(256) first principles at
//! compile time — multiplicative inverse, then the FIPS-197
//! affine transform — never transcribed, and the derivation
//! is re-proven against the published tables in this
//! module's tests (the same first-principles pattern
//! `ghidra::detection` uses for its byte-search patterns).
//!
//! This is a format primitive, not a general-purpose
//! cryptographic library: no padding scheme, no modes
//! beyond the two the formats use, no attempt at
//! constant-time behaviour. Keys arrive from the tool
//! caller; nothing here generates or stores key material.

use fathom_core::error::{ErrorCode, FathomError};

/// Multiply in GF(256) modulo the AES polynomial
/// x^8 + x^4 + x^3 + x + 1 (0x11b).
const fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0_u8;
    while b != 0 {
        if b & 1 == 1 {
            product ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

/// The multiplicative inverse in GF(256); 0 maps to 0 by
/// the FIPS-197 convention. Computed as a^254 by
/// square-and-multiply.
const fn gf_inv(a: u8) -> u8 {
    if a == 0 {
        return 0;
    }
    let mut result = 1_u8;
    let mut base = a;
    let mut exponent = 254_u16;
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        exponent >>= 1;
    }
    result
}

/// One S-box entry: the affine transform of the GF(256)
/// inverse (FIPS-197 §5.1.1).
const fn sbox_entry(x: u8) -> u8 {
    let inv = gf_inv(x);
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

const fn build_sbox() -> [u8; 256] {
    let mut table = [0_u8; 256];
    let mut i = 0_usize;
    while i < 256 {
        table[i] = sbox_entry(i as u8);
        i += 1;
    }
    table
}

const fn build_inv_sbox() -> [u8; 256] {
    let mut table = [0_u8; 256];
    let mut i = 0_usize;
    while i < 256 {
        table[SBOX[i] as usize] = i as u8;
        i += 1;
    }
    table
}

/// The AES substitution box, derived (see module doc).
pub const SBOX: [u8; 256] = build_sbox();
/// The inverse substitution box, derived by inverting
/// [`SBOX`].
pub const INV_SBOX: [u8; 256] = build_inv_sbox();

/// Round constants for key expansion (FIPS-197 §5.2);
/// AES-256 uses the first seven.
const RCON: [u8; 7] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];

/// AES-256 with its key schedule expanded once (FIPS-197
/// §5.2: Nk = 8, Nr = 14, 60 words of round key).
pub struct Aes256 {
    round_keys: [u8; 240],
}

impl Aes256 {
    pub fn new(key: &[u8; 32]) -> Self {
        let mut round_keys = [0_u8; 240];
        round_keys[..32].copy_from_slice(key);
        let mut i = 8_usize;
        while i < 60 {
            let prev = &round_keys[(i - 1) * 4..(i - 1) * 4 + 4];
            let mut temp = [prev[0], prev[1], prev[2], prev[3]];
            if i.is_multiple_of(8) {
                // SubWord(RotWord(temp)) with the round
                // constant on the first byte.
                temp = [
                    SBOX[prev[1] as usize] ^ RCON[i / 8 - 1],
                    SBOX[prev[2] as usize],
                    SBOX[prev[3] as usize],
                    SBOX[prev[0] as usize],
                ];
            } else if i % 8 == 4 {
                // AES-256's extra SubWord at word 4 mod 8
                // (no rotation).
                temp = [
                    SBOX[prev[0] as usize],
                    SBOX[prev[1] as usize],
                    SBOX[prev[2] as usize],
                    SBOX[prev[3] as usize],
                ];
            }
            for j in 0..4 {
                round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
            }
            i += 1;
        }
        Aes256 { round_keys }
    }

    /// Encrypt one 16-byte block (FIPS-197 §5.1).
    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[0..16]);
        for round in 1..14 {
            sub_bytes(block);
            shift_rows(block);
            mix_columns(block);
            add_round_key(block, &self.round_keys[round * 16..round * 16 + 16]);
        }
        sub_bytes(block);
        shift_rows(block);
        add_round_key(block, &self.round_keys[224..240]);
    }

    /// Decrypt one 16-byte block (FIPS-197 §5.3).
    pub fn decrypt_block(&self, block: &mut [u8; 16]) {
        add_round_key(block, &self.round_keys[224..240]);
        for round in (1..14).rev() {
            inv_shift_rows(block);
            inv_sub_bytes(block);
            add_round_key(block, &self.round_keys[round * 16..round * 16 + 16]);
            inv_mix_columns(block);
        }
        inv_shift_rows(block);
        inv_sub_bytes(block);
        add_round_key(block, &self.round_keys[0..16]);
    }
}

fn add_round_key(state: &mut [u8; 16], key: &[u8]) {
    for i in 0..16 {
        state[i] ^= key[i];
    }
}

fn sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = SBOX[*byte as usize];
    }
}

fn inv_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = INV_SBOX[*byte as usize];
    }
}

/// State byte at (row, column): the state is column-major,
/// `state[4 * column + row]` (FIPS-197 §3.4).
fn shift_rows(state: &mut [u8; 16]) {
    let before = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[4 * column + row] = before[4 * ((column + row) % 4) + row];
        }
    }
}

fn inv_shift_rows(state: &mut [u8; 16]) {
    let before = *state;
    for row in 0..4 {
        for column in 0..4 {
            state[4 * column + row] = before[4 * ((column + 4 - row) % 4) + row];
        }
    }
}

fn mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let at = 4 * column;
        let (a, b, c, d) = (state[at], state[at + 1], state[at + 2], state[at + 3]);
        state[at] = gf_mul(a, 2) ^ gf_mul(b, 3) ^ c ^ d;
        state[at + 1] = a ^ gf_mul(b, 2) ^ gf_mul(c, 3) ^ d;
        state[at + 2] = a ^ b ^ gf_mul(c, 2) ^ gf_mul(d, 3);
        state[at + 3] = gf_mul(a, 3) ^ b ^ c ^ gf_mul(d, 2);
    }
}

fn inv_mix_columns(state: &mut [u8; 16]) {
    for column in 0..4 {
        let at = 4 * column;
        let (a, b, c, d) = (state[at], state[at + 1], state[at + 2], state[at + 3]);
        state[at] = gf_mul(a, 14) ^ gf_mul(b, 11) ^ gf_mul(c, 13) ^ gf_mul(d, 9);
        state[at + 1] = gf_mul(a, 9) ^ gf_mul(b, 14) ^ gf_mul(c, 11) ^ gf_mul(d, 13);
        state[at + 2] = gf_mul(a, 13) ^ gf_mul(b, 9) ^ gf_mul(c, 14) ^ gf_mul(d, 11);
        state[at + 3] = gf_mul(a, 11) ^ gf_mul(b, 13) ^ gf_mul(c, 9) ^ gf_mul(d, 14);
    }
}

fn unaligned(message: &str) -> FathomError {
    FathomError::new(ErrorCode::InvalidRequest, message.to_string())
}

/// ECB-encrypt a block-aligned buffer. Callers own any
/// padding decision: the formats pad with zeroes to the
/// AES block size and record the true length elsewhere.
pub fn ecb_encrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, FathomError> {
    if !data.len().is_multiple_of(16) {
        return Err(unaligned("ECB input length is not a multiple of 16"));
    }
    let cipher = Aes256::new(key);
    let mut out = data.to_vec();
    for block in out.as_chunks_mut::<16>().0 {
        cipher.encrypt_block(block);
    }
    Ok(out)
}

/// ECB-decrypt a block-aligned buffer.
pub fn ecb_decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>, FathomError> {
    if !data.len().is_multiple_of(16) {
        return Err(unaligned("ECB input length is not a multiple of 16"));
    }
    let cipher = Aes256::new(key);
    let mut out = data.to_vec();
    for block in out.as_chunks_mut::<16>().0 {
        cipher.decrypt_block(block);
    }
    Ok(out)
}

/// CFB with 128-bit segments (NIST SP 800-38A §6.2),
/// encrypt: each plaintext block is XORed with the
/// encryption of the previous ciphertext block, starting
/// from the IV. Any input length; the final segment may
/// be partial.
pub fn cfb128_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(key);
    let mut out = Vec::with_capacity(data.len());
    let mut chain = *iv;
    for chunk in data.chunks(16) {
        let mut stream = chain;
        cipher.encrypt_block(&mut stream);
        let mut block = Vec::with_capacity(chunk.len());
        for (index, byte) in chunk.iter().enumerate() {
            block.push(byte ^ stream[index]);
        }
        if chunk.len() == 16 {
            chain.copy_from_slice(&block);
        }
        out.extend_from_slice(&block);
    }
    out
}

/// CFB-128 decrypt, the mirror of [`cfb128_encrypt`].
pub fn cfb128_decrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let cipher = Aes256::new(key);
    let mut out = Vec::with_capacity(data.len());
    let mut chain = *iv;
    for chunk in data.chunks(16) {
        let mut stream = chain;
        cipher.encrypt_block(&mut stream);
        if chunk.len() == 16 {
            chain.copy_from_slice(chunk);
        }
        for (index, byte) in chunk.iter().enumerate() {
            out.push(byte ^ stream[index]);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    fn key32(text: &str) -> [u8; 32] {
        unhex(text).try_into().unwrap()
    }

    #[test]
    fn validation_sboxes_match_the_published_tables() {
        // FIPS-197 Figures 7 and 14, first rows; the same
        // first-16 bytes ghidra::detection searches for.
        let forward: Vec<u8> = SBOX[..16].to_vec();
        assert_eq!(forward, unhex("637c777bf26b6fc53001672bfed7ab76"));
        let inverse: Vec<u8> = INV_SBOX[..16].to_vec();
        assert_eq!(inverse, unhex("52096ad53036a538bf40a39e81f3d7fb"));
        // Full-table spot checks from FIPS-197: S(0x53) and
        // its inverse.
        assert_eq!(SBOX[0x53], 0xed);
        assert_eq!(INV_SBOX[0xed], 0x53);
        for value in 0..=255_u8 {
            assert_eq!(INV_SBOX[SBOX[value as usize] as usize], value);
        }
    }

    #[test]
    fn validation_fips197_appendix_c3_block_vector() {
        let key = key32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let cipher = Aes256::new(&key);
        let mut block: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        cipher.encrypt_block(&mut block);
        assert_eq!(block.to_vec(), unhex("8ea2b7ca516745bfeafc49904b496089"));
        cipher.decrypt_block(&mut block);
        assert_eq!(block.to_vec(), unhex("00112233445566778899aabbccddeeff"));
    }

    #[test]
    fn validation_sp800_38a_ecb_aes256_vectors() {
        // NIST SP 800-38A F.1.5 (ECB-AES256), all four blocks.
        let key = key32("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let plain = unhex(concat!(
            "6bc1bee22e409f96e93d7e117393172a",
            "ae2d8a571e03ac9c9eb76fac45af8e51",
            "30c81c46a35ce411e5fbc1191a0a52ef",
            "f69f2445df4f9b17ad2b417be66c3710"
        ));
        let expected = unhex(concat!(
            "f3eed1bdb5d2a03c064b5a7e3db181f8",
            "591ccb10d410ed26dc5ba74a31362870",
            "b6ed21b99ca6f4f9f153e7b1beafed1d",
            "23304b7a39f9f3ff067d8d8f9e24ecc7"
        ));
        assert_eq!(ecb_encrypt(&key, &plain).unwrap(), expected);
        assert_eq!(ecb_decrypt(&key, &expected).unwrap(), plain);
    }

    #[test]
    fn validation_cfb128_first_segment_from_fips_block() {
        // CFB-128's first segment is E(K, IV) XOR P. With
        // the FIPS-197 key and IV = the FIPS plaintext
        // block, E(K, IV) is the FIPS ciphertext block, so
        // a zero plaintext segment must encrypt to exactly
        // it — a certain vector built from FIPS-197 alone.
        let key = key32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        let iv: [u8; 16] = unhex("00112233445566778899aabbccddeeff")
            .try_into()
            .unwrap();
        let zeros = [0_u8; 16];
        let encrypted = cfb128_encrypt(&key, &iv, &zeros);
        assert_eq!(encrypted, unhex("8ea2b7ca516745bfeafc49904b496089"));
        assert_eq!(cfb128_decrypt(&key, &iv, &encrypted), zeros.to_vec());
    }

    #[test]
    fn validation_cfb128_roundtrip_partial_final_segment() {
        let key = key32("2b7e151628aed2a6abf7158809cf4f3c2b7e151628aed2a6abf7158809cf4f3c");
        let iv = [7_u8; 16];
        let data: Vec<u8> = (0..45_u8)
            .map(|i| i.wrapping_mul(37).wrapping_add(11))
            .collect();
        let encrypted = cfb128_encrypt(&key, &iv, &data);
        assert_eq!(encrypted.len(), data.len());
        assert_ne!(encrypted, data);
        assert_eq!(cfb128_decrypt(&key, &iv, &encrypted), data);
    }

    #[test]
    fn adversarial_ecb_unaligned_input_is_a_typed_error() {
        let key = [0_u8; 32];
        let err = ecb_encrypt(&key, &[1, 2, 3]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
        let err = ecb_decrypt(&key, &[0_u8; 17]).unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidRequest);
    }
}
