// Minimal WebSocket client (RFC 6455) over TLS: binary frames, masking, ping/pong.

use super::obfs::random_bytes;
use super::Dial;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use tokio_rustls::rustls::client::WebPkiServerVerifier;
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{
    self, CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme,
};
use tokio_rustls::TlsConnector;

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;
const MAX_WS_MESSAGE: usize = 16 << 20;
const TCP_TRIES: usize = 3;
const TCP_STAGGER: Duration = Duration::from_millis(1200);
const TCP_LAST: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum DialError {
    Stage(&'static str, String),
    Handshake(u16),
    Other(#[allow(dead_code)] String),
}

impl DialError {
    // Short reason for the UI, in Russian.
    pub fn short(&self) -> String {
        match self {
            DialError::Stage(st, why) => format!("{st}: {why}"),
            DialError::Handshake(code) => format!("сервер ответил {code}"),
            DialError::Other(_) => "ошибка соединения".into(),
        }
    }
}

fn io_reason(e: &io::Error) -> String {
    use io::ErrorKind::*;
    if let Some(inner) = e.get_ref() {
        if let Some(re) = inner.downcast_ref::<rustls::Error>() {
            return match re {
                rustls::Error::InvalidCertificate(_) => "ошибка сертификата".into(),
                _ => "ошибка соединения".into(),
            };
        }
    }
    match e.kind() {
        TimedOut => "таймаут".into(),
        ConnectionReset | ConnectionAborted => "соединение сброшено".into(),
        ConnectionRefused => "соединение отклонено".into(),
        _ => "ошибка соединения".into(),
    }
}

pub struct DialOpts {
    pub addr: String,
    pub host: String,
    pub path: String,
    pub sni: Option<String>,
    pub no_check: bool,
    pub timeout: Duration,
    pub roots: Option<Arc<RootCertStore>>,
    pub dial: Option<Arc<Dial>>,
}

fn system_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            for c in rustls_native_certs::load_native_certs().certs {
                let _ = store.add(c);
            }
            Arc::new(store)
        })
        .clone()
}

// Fronting: the certificate chain is verified, the host name is not.
#[derive(Debug)]
struct ChainOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

fn tls_config(roots: Arc<RootCertStore>, no_check: bool) -> Result<ClientConfig, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let b = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS12, &rustls::version::TLS13])
        .map_err(|e| e.to_string())?;
    if no_check {
        let v = WebPkiServerVerifier::builder_with_provider(roots, provider).build().map_err(|e| e.to_string())?;
        Ok(b.dangerous().with_custom_certificate_verifier(Arc::new(ChainOnly(v))).with_no_client_auth())
    } else {
        Ok(b.with_root_certificates(roots).with_no_client_auth())
    }
}

type Rd = BufReader<ReadHalf<TlsStream<TcpStream>>>;
type Wr = WriteHalf<TlsStream<TcpStream>>;

struct ReadState {
    r: Rd,
    frag: Vec<u8>,
}

pub struct WsConn {
    w: Mutex<Wr>,
    r: Mutex<ReadState>,
    closed: AtomicBool,
    #[allow(dead_code)]
    pub created: Instant,
}

pub async fn dial_ws(o: DialOpts) -> Result<WsConn, DialError> {
    let stage = std::sync::Mutex::new("TCP");
    let set = |s: &'static str| *stage.lock().unwrap() = s;
    match tokio::time::timeout(o.timeout, dial_inner(&o, &set)).await {
        Ok(r) => r,
        Err(_) => Err(DialError::Stage(*stage.lock().unwrap(), "таймаут".into())),
    }
}

async fn dial_inner(o: &DialOpts, set: &(dyn Fn(&'static str) + Sync)) -> Result<WsConn, DialError> {
    let raw = tcp_race(o).await.map_err(|e| DialError::Stage("TCP", io_reason(&e)))?;
    let _ = raw.set_nodelay(true);

    set("TLS");
    let roots = o.roots.clone().unwrap_or_else(system_roots);
    let cfg = tls_config(roots, o.no_check).map_err(DialError::Other)?;
    let sni = o.sni.clone().unwrap_or_else(|| o.host.clone());
    let name = ServerName::try_from(sni).map_err(|e| DialError::Other(e.to_string()))?;
    let tls = TlsConnector::from(Arc::new(cfg))
        .connect(name, raw)
        .await
        .map_err(|e| DialError::Stage("TLS", io_reason(&e)))?;

    set("WebSocket");
    let (rh, mut wh) = tokio::io::split(tls);
    let mut key = [0u8; 16];
    random_bytes(&mut key);
    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        o.path,
        o.host,
        base64(&key)
    );
    wh.write_all(req.as_bytes()).await.map_err(|e| DialError::Other(e.to_string()))?;
    let mut br = BufReader::with_capacity(64 << 10, rh);
    let mut line = String::new();
    br.read_line(&mut line).await.map_err(|e| DialError::Other(e.to_string()))?;
    let code: u16 = line.split(' ').nth(1).and_then(|c| c.trim().parse().ok()).unwrap_or(0);
    loop {
        let mut h = String::new();
        let n = br.read_line(&mut h).await.map_err(|e| DialError::Other(e.to_string()))?;
        if n == 0 || h == "\r\n" || h == "\n" {
            break;
        }
    }
    if code != 101 {
        return Err(DialError::Handshake(code));
    }
    Ok(WsConn {
        w: Mutex::new(wh),
        r: Mutex::new(ReadState { r: br, frag: Vec::new() }),
        closed: AtomicBool::new(false),
        created: Instant::now(),
    })
}

// Staggered TCP attempts: a dropped SYN costs one stagger, not the whole timeout.
async fn tcp_race(o: &DialOpts) -> io::Result<TcpStream> {
    let mut set = tokio::task::JoinSet::new();
    let mut started = 0;
    let mut last = io::Error::from(io::ErrorKind::TimedOut);
    loop {
        if started < TCP_TRIES {
            started += 1;
            let (dial, addr) = (o.dial.clone(), o.addr.clone());
            set.spawn(async move {
                match dial {
                    Some(d) => d.connect(&addr).await,
                    None => TcpStream::connect(&addr).await,
                }
            });
        }
        let wait = if started < TCP_TRIES { TCP_STAGGER } else { TCP_LAST };
        match tokio::time::timeout(wait, set.join_next()).await {
            Ok(Some(Ok(Ok(s)))) => return Ok(s),
            Ok(Some(Ok(Err(e)))) => last = e,
            Ok(Some(Err(_))) => {}
            Ok(None) => return Err(last),
            Err(_) if started >= TCP_TRIES => return Err(io::Error::from(io::ErrorKind::TimedOut)),
            Err(_) => {}
        }
    }
}

pub fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn build_frame(op: u8, data: &[u8]) -> Vec<u8> {
    let n = data.len();
    let mut h = Vec::with_capacity(14 + n);
    h.push(0x80 | op);
    if n < 126 {
        h.push(0x80 | n as u8);
    } else if n < 65536 {
        h.extend_from_slice(&[0x80 | 126, (n >> 8) as u8, n as u8]);
    } else {
        h.push(0x80 | 127);
        h.extend_from_slice(&(n as u64).to_be_bytes());
    }
    let mut mask = [0u8; 4];
    random_bytes(&mut mask);
    h.extend_from_slice(&mask);
    h.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i & 3]));
    h
}

fn eof() -> io::Error {
    io::Error::new(io::ErrorKind::UnexpectedEof, "websocket закрыт")
}

impl WsConn {
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    // Several binary frames in a single write.
    pub async fn send(&self, parts: &[Vec<u8>]) -> io::Result<()> {
        if self.is_closed() {
            return Err(eof());
        }
        let mut buf = Vec::new();
        for p in parts {
            buf.extend_from_slice(&build_frame(OP_BINARY, p));
        }
        let mut w = self.w.lock().await;
        w.write_all(&buf).await?;
        w.flush().await
    }

    async fn write_ctl(&self, op: u8, data: &[u8]) {
        let f = build_frame(op, data);
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            let mut w = self.w.lock().await;
            let _ = w.write_all(&f).await;
            let _ = w.flush().await;
        })
        .await;
    }

    // Next message; Err(UnexpectedEof) — the server closed the connection.
    pub async fn recv(&self) -> io::Result<Vec<u8>> {
        let mut st = self.r.lock().await;
        loop {
            let (op, payload, fin) = read_frame(&mut st.r).await?;
            match op {
                OP_CLOSE => {
                    let code = &payload[..payload.len().min(2)];
                    self.write_ctl(OP_CLOSE, code).await;
                    self.closed.store(true, Ordering::Relaxed);
                    return Err(eof());
                }
                OP_PING => {
                    self.write_ctl(OP_PONG, &payload).await;
                }
                OP_PONG => {}
                OP_CONT | OP_TEXT | OP_BINARY => {
                    if fin && st.frag.is_empty() {
                        return Ok(payload);
                    }
                    st.frag.extend_from_slice(&payload);
                    if st.frag.len() > MAX_WS_MESSAGE {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "слишком большое сообщение WebSocket"));
                    }
                    if fin {
                        return Ok(std::mem::take(&mut st.frag));
                    }
                }
                _ => {}
            }
        }
    }

    pub async fn close(&self) {
        if !self.closed.swap(true, Ordering::Relaxed) {
            self.write_ctl(OP_CLOSE, &[]).await;
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            let _ = self.w.lock().await.shutdown().await;
        })
        .await;
    }

    // Non-blocking check of an idle pooled connection: has the server closed it?
    pub async fn alive(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let Ok(mut st) = self.r.try_lock() else { return true };
        if !st.r.buffer().is_empty() {
            return true;
        }
        match tokio::time::timeout(Duration::from_millis(1), st.r.fill_buf()).await {
            Ok(Ok(b)) => !b.is_empty(),
            Ok(Err(_)) => false,
            Err(_) => true,
        }
    }
}

async fn read_frame(r: &mut Rd) -> io::Result<(u8, Vec<u8>, bool)> {
    let mut hdr = [0u8; 2];
    r.read_exact(&mut hdr).await?;
    let fin = hdr[0] & 0x80 != 0;
    let op = hdr[0] & 0x0f;
    let mut n = (hdr[1] & 0x7f) as u64;
    if n == 126 {
        let mut b = [0u8; 2];
        r.read_exact(&mut b).await?;
        n = u16::from_be_bytes(b) as u64;
    } else if n == 127 {
        let mut b = [0u8; 8];
        r.read_exact(&mut b).await?;
        n = u64::from_be_bytes(b);
    }
    if n > MAX_WS_MESSAGE as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "слишком большой кадр WebSocket"));
    }
    let masked = hdr[1] & 0x80 != 0;
    let mut mask = [0u8; 4];
    if masked {
        r.read_exact(&mut mask).await?;
    }
    let mut payload = vec![0u8; n as usize];
    r.read_exact(&mut payload).await?;
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i & 3];
        }
    }
    Ok((op, payload, fin))
}
