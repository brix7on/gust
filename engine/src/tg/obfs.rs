// MTProto obfuscation: client handshake parsing, relay init, four AES-CTR streams.

use aes::Aes256;
use ctr::cipher::KeyIvInit;
use sha2::{Digest, Sha256};

pub use ctr::cipher::StreamCipher;
pub type Ctr = ctr::Ctr128BE<Aes256>;

pub const HANDSHAKE_LEN: usize = 64;
const SKIP_LEN: usize = 8;
const PREKEY_LEN: usize = 32;
const IV_LEN: usize = 16;
const PROTO_TAG_POS: usize = 56;
const DC_IDX_POS: usize = 60;

pub const TAG_ABRIDGED: [u8; 4] = [0xef; 4];
pub const TAG_INTERMEDIATE: [u8; 4] = [0xee; 4];
pub const TAG_SECURE: [u8; 4] = [0xdd; 4];

const RESERVED_STARTS: [[u8; 4]; 7] = [
    *b"HEAD",
    *b"POST",
    *b"GET ",
    *b"OPTI",
    TAG_INTERMEDIATE,
    TAG_SECURE,
    [0x16, 0x03, 0x01, 0x02],
];

pub struct ClientHello {
    pub dc: i32,
    pub media: bool,
    pub test: bool,
    pub dc_idx: i16,
    pub proto_tag: [u8; 4],
    pub prekey_iv: [u8; 48],
}

pub fn new_ctr(key: &[u8], iv: &[u8]) -> Ctr {
    Ctr::new(key.into(), iv.into())
}

pub fn sha(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

pub fn reversed(b: &[u8]) -> Vec<u8> {
    b.iter().rev().copied().collect()
}

pub fn random_bytes(buf: &mut [u8]) {
    getrandom::fill(buf).expect("system random");
}

pub fn parse_client_hello(h: &[u8], secret: &[u8]) -> Option<ClientHello> {
    if h.len() != HANDSHAKE_LEN {
        return None;
    }
    let mut prekey_iv = [0u8; 48];
    prekey_iv.copy_from_slice(&h[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    let key = sha(&prekey_iv[..PREKEY_LEN], secret);
    let mut dec = h.to_vec();
    new_ctr(&key, &prekey_iv[PREKEY_LEN..]).apply_keystream(&mut dec);

    let mut tag = [0u8; 4];
    tag.copy_from_slice(&dec[PROTO_TAG_POS..PROTO_TAG_POS + 4]);
    if tag != TAG_ABRIDGED && tag != TAG_INTERMEDIATE && tag != TAG_SECURE {
        return None;
    }
    let dc_idx = i16::from_le_bytes([dec[DC_IDX_POS], dec[DC_IDX_POS + 1]]);
    let mut dc = dc_idx as i32;
    let (mut media, mut test) = (false, false);
    if dc < 0 {
        dc = -dc;
        media = true;
    }
    if dc >= 10000 {
        dc -= 10000;
        test = true;
    }
    Some(ClientHello { dc, media, test, dc_idx, proto_tag: tag, prekey_iv })
}

pub fn valid_relay_start(r: &[u8]) -> bool {
    if r[0] == 0xef {
        return false;
    }
    if RESERVED_STARTS.iter().any(|s| &r[..4] == s) {
        return false;
    }
    r[4..8] != [0, 0, 0, 0]
}

pub fn make_relay_init(proto_tag: &[u8; 4], dc_idx: i16) -> [u8; HANDSHAKE_LEN] {
    let mut r = [0u8; HANDSHAKE_LEN];
    loop {
        random_bytes(&mut r);
        if valid_relay_start(&r) {
            break;
        }
    }
    let mut enc = r;
    new_ctr(
        &r[SKIP_LEN..SKIP_LEN + PREKEY_LEN],
        &r[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN],
    )
    .apply_keystream(&mut enc);

    let mut tail = [0u8; 8];
    tail[..4].copy_from_slice(proto_tag);
    tail[4..6].copy_from_slice(&dc_idx.to_le_bytes());
    random_bytes(&mut tail[6..]);

    let mut out = r;
    for i in 0..8 {
        let ks = enc[PROTO_TAG_POS + i] ^ r[PROTO_TAG_POS + i];
        out[PROTO_TAG_POS + i] = tail[i] ^ ks;
    }
    out
}

// Client → Telegram direction.
pub struct UpCrypto {
    pub clt_dec: Ctr,
    pub tg_enc: Ctr,
}

// Telegram → client direction.
pub struct DownCrypto {
    pub tg_dec: Ctr,
    pub clt_enc: Ctr,
}

fn skip64(c: &mut Ctr) {
    let mut z = [0u8; HANDSHAKE_LEN];
    c.apply_keystream(&mut z);
}

pub fn new_crypto(prekey_iv: &[u8; 48], secret: &[u8], relay: &[u8; HANDSHAKE_LEN]) -> (UpCrypto, DownCrypto) {
    let mut clt_dec = new_ctr(&sha(&prekey_iv[..PREKEY_LEN], secret), &prekey_iv[PREKEY_LEN..]);
    skip64(&mut clt_dec);

    let rev = reversed(prekey_iv);
    let clt_enc = new_ctr(&sha(&rev[..PREKEY_LEN], secret), &rev[PREKEY_LEN..]);

    let mut tg_enc = new_ctr(
        &relay[SKIP_LEN..SKIP_LEN + PREKEY_LEN],
        &relay[SKIP_LEN + PREKEY_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN],
    );
    skip64(&mut tg_enc);

    let rrev = reversed(&relay[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN]);
    let tg_dec = new_ctr(&rrev[..PREKEY_LEN], &rrev[PREKEY_LEN..]);
    (UpCrypto { clt_dec, tg_enc }, DownCrypto { tg_dec, clt_enc })
}

pub fn valid_secret(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|c| c.is_ascii_hexdigit())
}

pub fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}
