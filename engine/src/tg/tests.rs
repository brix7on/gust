use super::obfs::*;
use super::pool::{backoff_gap, PoolKey};
use super::splitter::Splitter;
use super::*;
use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
use std::sync::Mutex;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio_rustls::rustls::{self, ServerConfig};
use tokio_rustls::TlsAcceptor;

// ---------- fake Telegram Desktop ----------

struct FakeClient {
    hello: Vec<u8>,
    enc: Ctr,
    dec: Ctr,
}

fn fake_client(secret: &[u8], tag: [u8; 4], dc_idx: i16) -> FakeClient {
    let mut r = [0u8; 64];
    loop {
        random_bytes(&mut r);
        if valid_relay_start(&r) {
            break;
        }
    }
    r[56..60].copy_from_slice(&tag);
    r[60..62].copy_from_slice(&dc_idx.to_le_bytes());
    let mut enc = new_ctr(&sha(&r[8..40], secret), &r[40..56]);
    let mut e = r;
    enc.apply_keystream(&mut e);
    let mut hello = r[..56].to_vec();
    hello.extend_from_slice(&e[56..]);
    let rev = reversed(&r[8..56]);
    FakeClient { hello, enc, dec: new_ctr(&sha(&rev[..32], secret), &rev[32..]) }
}

// ---------- fake Telegram DC side ----------

struct Side {
    dec: Ctr,
    enc: Ctr,
    dc_idx: i16,
    tag: [u8; 4],
}

fn parse_relay(init: &[u8]) -> Side {
    let mut dec = new_ctr(&init[8..40], &init[40..56]);
    let mut p = init.to_vec();
    dec.apply_keystream(&mut p);
    let rev = reversed(&init[8..56]);
    Side {
        dec,
        enc: new_ctr(&rev[..32], &rev[32..]),
        dc_idx: i16::from_le_bytes([p[60], p[61]]),
        tag: [p[56], p[57], p[58], p[59]],
    }
}

#[derive(Default)]
struct Rec {
    frames: Vec<Vec<u8>>,
    inits: Vec<(i16, [u8; 4])>,
    init_hosts: Vec<String>,
    paths: Vec<String>,
}

struct Tg {
    rec: Arc<Mutex<Rec>>,
    roots: Arc<RootCertStore>,
    dial: Arc<Dial>,
}

fn make_certs(names: &[&str]) -> (CertificateDer<'static>, PrivateKeyDer<'static>, Arc<RootCertStore>) {
    let ca_key = KeyPair::generate().unwrap();
    let mut cp = CertificateParams::new(Vec::<String>::new()).unwrap();
    cp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cp.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::DigitalSignature];
    let ca = cp.self_signed(&ca_key).unwrap();
    let leaf_key = KeyPair::generate().unwrap();
    let lp = CertificateParams::new(names.iter().map(|s| s.to_string()).collect::<Vec<_>>()).unwrap();
    let leaf = lp.signed_by(&leaf_key, &ca, &ca_key).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(ca.der().clone()).unwrap();
    (
        leaf.der().clone(),
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        Arc::new(roots),
    )
}

async fn read_client_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Option<Vec<u8>> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).await.ok()?;
    let mut n = (h[1] & 0x7f) as usize;
    if n == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).await.ok()?;
        n = u16::from_be_bytes(b) as usize;
    }
    let mut mask = [0u8; 4];
    r.read_exact(&mut mask).await.ok()?;
    let mut p = vec![0u8; n];
    r.read_exact(&mut p).await.ok()?;
    for (i, b) in p.iter_mut().enumerate() {
        *b ^= mask[i & 3];
    }
    Some(p)
}

async fn serve_ws(tls: tokio_rustls::server::TlsStream<TcpStream>, rec: Arc<Mutex<Rec>>) {
    let (rd, mut wr) = tokio::io::split(tls);
    let mut br = BufReader::new(rd);
    let mut first = String::new();
    br.read_line(&mut first).await.ok();
    let path = first.split(' ').nth(1).unwrap_or("").to_string();
    let mut host = String::new();
    loop {
        let mut l = String::new();
        if br.read_line(&mut l).await.unwrap_or(0) == 0 || l == "\r\n" {
            break;
        }
        if let Some(v) = l.strip_prefix("Host: ") {
            host = v.trim().to_string();
        }
    }
    rec.lock().unwrap().paths.push(path);
    let _ = wr
        .write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        .await;
    let Some(init) = read_client_frame(&mut br).await else { return };
    if init.len() != 64 {
        return;
    }
    let mut side = parse_relay(&init);
    {
        let mut g = rec.lock().unwrap();
        g.inits.push((side.dc_idx, side.tag));
        g.init_hosts.push(host);
    }
    while let Some(mut m) = read_client_frame(&mut br).await {
        side.dec.apply_keystream(&mut m);
        rec.lock().unwrap().frames.push(m.clone());
        let mut out = b"OK".to_vec();
        out.extend_from_slice(&m);
        side.enc.apply_keystream(&mut out);
        let mut f = vec![0x82];
        if out.len() < 126 {
            f.push(out.len() as u8);
        } else {
            f.extend_from_slice(&[126, (out.len() >> 8) as u8, out.len() as u8]);
        }
        f.extend_from_slice(&out);
        if wr.write_all(&f).await.is_err() {
            return;
        }
    }
}

async fn start_tg(names: &[&str]) -> Tg {
    let (cert, key, roots) = make_certs(names);
    let cfg = ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    let acc = TlsAcceptor::from(Arc::new(cfg));
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    let rec = Arc::new(Mutex::new(Rec::default()));
    let r2 = rec.clone();
    tokio::spawn(async move {
        loop {
            let Ok((s, _)) = ln.accept().await else { return };
            let (acc, rec) = (acc.clone(), r2.clone());
            tokio::spawn(async move {
                if let Ok(t) = acc.accept(s).await {
                    serve_ws(t, rec).await;
                }
            });
        }
    });
    Tg { rec, roots, dial: Arc::new(Dial::new(addr)) }
}

fn quiet() -> Arc<dyn Fn(String) + Send + Sync> {
    Arc::new(|m| eprintln!("{m}"))
}

fn new_secret() -> String {
    let mut b = [0u8; 16];
    random_bytes(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn start_proxy(pool: usize, tg: Option<&Tg>, redirects: bool) -> (Server, Vec<u8>) {
    let secret = new_secret();
    let mut cfg = Config::new(0, &secret, pool, quiet());
    if let Some(t) = tg {
        cfg.roots = Some(t.roots.clone());
        cfg.dial = Some(t.dial.clone());
    }
    if !redirects {
        cfg.dc_redirects.clear();
    }
    let s = start(cfg).await.unwrap();
    (s, decode_hex(&secret).unwrap())
}

fn intermediate(payload: &[u8]) -> Vec<u8> {
    let mut b = (payload.len() as u32).to_le_bytes().to_vec();
    b.extend_from_slice(payload);
    b
}

async fn connect_client(s: &Server, secret: &[u8], tag: [u8; 4], dc_idx: i16) -> (TcpStream, FakeClient) {
    let fc = fake_client(secret, tag, dc_idx);
    let mut c = TcpStream::connect(s.addr).await.unwrap();
    c.write_all(&fc.hello).await.unwrap();
    (c, fc)
}

async fn send_client(c: &mut TcpStream, fc: &mut FakeClient, data: &[u8]) {
    let mut e = data.to_vec();
    fc.enc.apply_keystream(&mut e);
    c.write_all(&e).await.unwrap();
}

async fn read_client(c: &mut TcpStream, fc: &mut FakeClient, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    tokio::time::timeout(Duration::from_secs(5), c.read_exact(&mut b))
        .await
        .expect("ответ не пришёл")
        .expect("соединение закрыто");
    fc.dec.apply_keystream(&mut b);
    b
}

fn ok_reply(pkt: &[u8]) -> Vec<u8> {
    [b"OK".as_slice(), pkt].concat()
}

async fn wait_for(cond: impl Fn() -> bool) {
    for _ in 0..300 {
        if cond() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("условие не выполнилось");
}

// ---------- tests ----------

// Vector produced by the original Go implementation (GU_VECTOR=file go test -run DumpVector).
#[test]
fn matches_go_vector() {
    let v = include_str!("vector.json");
    let get = |k: &str| -> Vec<u8> {
        let i = v.find(&format!("\"{k}\":\"")).unwrap() + k.len() + 4;
        decode_hex(&v[i..i + v[i..].find('"').unwrap()]).unwrap()
    };
    let secret = get("secret");
    let h = parse_client_hello(&get("hello"), &secret).expect("hello");
    assert_eq!((h.dc, h.media, h.test), (2, true, false));
    let relay: [u8; 64] = get("relay").try_into().unwrap();
    let (mut up, mut down) = new_crypto(&h.prekey_iv, &secret, &relay);

    let mut to_tg = get("c");
    up.clt_dec.apply_keystream(&mut to_tg);
    up.tg_enc.apply_keystream(&mut to_tg);
    assert_eq!(to_tg, get("to_tg"));

    let mut to_client = get("r");
    down.tg_dec.apply_keystream(&mut to_client);
    down.clt_enc.apply_keystream(&mut to_client);
    assert_eq!(to_client, get("to_client"));
}

#[test]
fn splitter_cuts_intermediate_packets() {
    let mut sp = Splitter::new(&TAG_SECURE);
    let (p1, p2) = (intermediate(b"aaaa"), intermediate(&[b'b'; 300]));
    let all = [p1.clone(), p2.clone()].concat();
    let parts = sp.split(&all[..10], &all[..10]);
    assert_eq!(parts, vec![p1.clone()]);
    let parts = sp.split(&all[10..], &all[10..]);
    assert_eq!(parts, vec![p2]);
    assert!(sp.flush().is_none());
}

#[test]
fn splitter_abridged_short_and_long() {
    let mut sp = Splitter::new(&TAG_ABRIDGED);
    let short = [&[2u8][..], b"12345678"].concat();
    let long = [&[0x7fu8, 64, 0, 0][..], &[b'x'; 256]].concat();
    let all = [short.clone(), long.clone()].concat();
    assert_eq!(sp.split(&all, &all), vec![short, long]);
}

#[test]
fn splitter_garbage_length_disables_cutting() {
    let mut sp = Splitter::new(&TAG_SECURE);
    let junk = [0u8; 12];
    assert_eq!(sp.split(&junk, &junk).len(), 1);
    assert_eq!(sp.split(b"abc", b"abc"), vec![b"abc".to_vec()]);
}

#[test]
fn backoff_is_capped() {
    assert_eq!(backoff_gap(1), Duration::from_secs(1));
    assert_eq!(backoff_gap(3), Duration::from_secs(4));
    assert_eq!(backoff_gap(50), Duration::from_secs(15));
}

#[test]
fn link_and_secret() {
    assert_eq!(link(1443, "00112233445566778899aabbccddeeff"), "tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff");
    assert!(valid_secret(&new_secret()));
    assert!(!valid_secret("zz"));
}

#[tokio::test]
async fn ws_path_end_to_end() {
    let tg = start_tg(&["*.web.telegram.org"]).await;
    let (s, secret) = start_proxy(2, Some(&tg), true).await;
    let (mut c, mut fc) = connect_client(&s, &secret, TAG_SECURE, 2).await;

    let (p1, p2, p3) = (intermediate(b"aaaa"), intermediate(&[b'b'; 300]), intermediate(b"cccccccc"));
    send_client(&mut c, &mut fc, &[p1.clone(), p2.clone()].concat()).await;
    send_client(&mut c, &mut fc, &p3[..5]).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    send_client(&mut c, &mut fc, &p3[5..]).await;
    for want in [&p1, &p2, &p3] {
        assert_eq!(read_client(&mut c, &mut fc, want.len() + 2).await, ok_reply(want));
    }
    let g = tg.rec.lock().unwrap();
    assert_eq!(g.frames.len(), 3, "по пакету на кадр");
    assert_eq!(g.inits[0], (2, TAG_SECURE));
    assert_eq!(g.paths[0], "/apiws");
    assert_eq!(g.init_hosts[0], "kws2.web.telegram.org");
    let dialed = tg.dial.dialed.lock().unwrap();
    assert!(dialed.iter().any(|a| a == "149.154.167.220:443"));
    let known: Vec<String> = s.sh.cfg.dc_redirects.values().map(|ip| format!("{ip}:443")).collect();
    assert!(dialed.iter().all(|a| known.contains(a)));
    assert_eq!(s.sh.snapshot().via_ws, 1);
}

#[tokio::test]
async fn media_and_abridged() {
    let tg = start_tg(&["*.web.telegram.org"]).await;
    let (s, secret) = start_proxy(0, Some(&tg), true).await;
    let (mut c, mut fc) = connect_client(&s, &secret, TAG_ABRIDGED, -4).await;
    let pkt = [&[2u8][..], b"12345678"].concat();
    let long = [&[0x7fu8, 64, 0, 0][..], &[b'x'; 256]].concat();
    send_client(&mut c, &mut fc, &[pkt.clone(), long.clone()].concat()).await;
    read_client(&mut c, &mut fc, pkt.len() + 2).await;
    read_client(&mut c, &mut fc, long.len() + 2).await;
    let g = tg.rec.lock().unwrap();
    assert_eq!(g.init_hosts[0], "kws4-1.web.telegram.org");
    assert_eq!((g.inits[0].0, g.frames.len()), (-4, 2));
}

#[tokio::test]
async fn fronting_when_name_does_not_match() {
    let tg = start_tg(&["other.example"]).await;
    let (s, secret) = start_proxy(0, Some(&tg), true).await;
    let (mut c, mut fc) = connect_client(&s, &secret, TAG_SECURE, 2).await;
    let pkt = intermediate(b"ping");
    send_client(&mut c, &mut fc, &pkt).await;
    assert_eq!(read_client(&mut c, &mut fc, pkt.len() + 2).await, ok_reply(&pkt));
}

#[tokio::test]
async fn untrusted_cert_rejected() {
    let tg = start_tg(&["*.web.telegram.org"]).await;
    let (_, _, other) = make_certs(&["x"]);
    let secret = new_secret();
    let mut cfg = Config::new(0, &secret, 0, quiet());
    cfg.roots = Some(other);
    cfg.dial = Some(tg.dial.clone());
    let s = start(cfg).await.unwrap();
    let (mut c, mut fc) = connect_client(&s, &decode_hex(&secret).unwrap(), TAG_SECURE, 2).await;
    send_client(&mut c, &mut fc, &intermediate(b"ping")).await;
    tokio::time::timeout(Duration::from_secs(20), async { while matches!(c.read(&mut [0u8; 64]).await, Ok(n) if n > 0) {} })
        .await
        .expect("соединение не закрылось");
    assert_eq!(s.sh.snapshot().via_ws, 0, "WS засчитан при недоверенном сертификате");
}

#[tokio::test]
async fn tcp_fallback() {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut c, _) = ln.accept().await.unwrap();
        let mut init = [0u8; 64];
        c.read_exact(&mut init).await.unwrap();
        let mut side = parse_relay(&init);
        let mut buf = [0u8; 9];
        c.read_exact(&mut buf).await.unwrap();
        side.dec.apply_keystream(&mut buf);
        let mut out = ok_reply(&buf);
        side.enc.apply_keystream(&mut out);
        c.write_all(&out).await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    let secret = new_secret();
    let mut cfg = Config::new(0, &secret, 0, quiet());
    cfg.dc_redirects.clear();
    cfg.dial = Some(Arc::new(Dial::new(addr)));
    let s = start(cfg).await.unwrap();
    let (mut c, mut fc) = connect_client(&s, &decode_hex(&secret).unwrap(), TAG_SECURE, 3).await;
    let pkt = intermediate(b"hello");
    send_client(&mut c, &mut fc, &pkt).await;
    assert_eq!(read_client(&mut c, &mut fc, pkt.len() + 2).await, ok_reply(&pkt));
    assert_eq!(s.sh.snapshot().via_tcp, 1);
}

#[tokio::test]
async fn wrong_secret() {
    let (s, _) = start_proxy(0, None, false).await;
    let fc = fake_client(&[1u8; 16], TAG_SECURE, 2);
    let mut c = TcpStream::connect(s.addr).await.unwrap();
    c.write_all(&fc.hello).await.unwrap();
    let r = tokio::time::timeout(Duration::from_secs(3), c.read(&mut [0u8; 1])).await.expect("ждали закрытия");
    assert!(matches!(r, Ok(0) | Err(_)));
    wait_for(|| s.sh.snapshot().bad == 1).await;
}

#[tokio::test]
async fn pool_reuse() {
    let tg = start_tg(&["*.web.telegram.org"]).await;
    let (s, secret) = start_proxy(2, Some(&tg), true).await;
    wait_for(|| s.sh.pool.idle_len(PoolKey { dc: 2, media: false, test: false }) == 2).await;
    let (mut c, mut fc) = connect_client(&s, &secret, TAG_SECURE, 2).await;
    let pkt = intermediate(b"x");
    send_client(&mut c, &mut fc, &pkt).await;
    read_client(&mut c, &mut fc, pkt.len() + 2).await;
    assert_eq!(s.sh.snapshot().via_ws, 1);
    assert_eq!(s.sh.st.pool_hits.load(Relaxed), 1);
}

#[tokio::test]
async fn answered_and_dead_sessions_are_counted() {
    let tg = start_tg(&["*.web.telegram.org"]).await;
    let (s, secret) = start_proxy(0, Some(&tg), true).await;
    let (mut c, mut fc) = connect_client(&s, &secret, TAG_SECURE, 2).await;
    let pkt = intermediate(b"x");
    send_client(&mut c, &mut fc, &pkt).await;
    read_client(&mut c, &mut fc, pkt.len() + 2).await;
    drop(c);
    wait_for(|| s.sh.snapshot().answered_ws == 1).await;
    let (c2, _fc2) = connect_client(&s, &secret, TAG_SECURE, 2).await;
    wait_for(|| s.sh.snapshot().via_ws == 2).await;
    drop(c2);
    wait_for(|| s.sh.snapshot().dead_ws == 1).await;
}
