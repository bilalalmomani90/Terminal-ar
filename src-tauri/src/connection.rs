//! Connection Engine (المرحلة 7، الدفعة الأولى): اقتران وتشفير على الشبكة المحلية فقط.
//!
//! التصميم (وصادق بحدوده):
//! - القناة: بروتوكول Noise (XX، X25519، ChaChaPoly، BLAKE2s) عبر TCP. المفتاح الثابت لكل جهاز يُنشأ مرة
//!   ويُحفظ في ملف داخل بيانات التطبيق (محمي بصلاحيات ملفات المستخدم فقط، كمفاتيح SSH؛ لا DPAPI بعد).
//! - الاقتران: الجهاز المضيف يفعّل «وضع الاقتران» فيعرض رمزاً من 6 أرقام صالحاً دقيقتين وبـ3 محاولات خاطئة
//!   كحد أقصى (يمنع من يصل للشبكة من إزعاجك بطلبات). الحماية من هجوم الوسيط ليست الرمز بل **رمز التحقق
//!   (SAS)**: 6 أرقام مشتقة من سجل المصافحة تظهر على الجهازين، ويؤكد المستخدم تطابقها على كليهما، ثم يوافق
//!   صاحب الجهاز المضيف. وسيط يعترض يحصل على SAS مختلف على كل طرف.
//! - بعد الاقتران يُثبَّت المفتاح العام (pinning): تغيّر هوية الجهاز = رفض الاتصال.
//! - الصلاحيات: لكل جهاز مقترن قائمة سماح (أدوات/إجراءات وتدفقات). لا طرفية عن بعد ولا أوامر حرة.
//! - الرحلات خارج الشبكة المحلية (VPN / Relay) غير منفَّذة هنا: انظر docs/CONNECTION.md.
//!
//! المنفذ يستمع على كل الشبكة المحلية فقط عندما يفعّله المشرف صراحة؛ وجدار ويندوز سيسأل عن السماح.

use crate::plugin;
use crate::security;
use crate::storage::{now, Db, DeviceRow};
use crate::workflow::{self, Item, PStep, ProcessExec};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use snow::Builder;
use snow::TransportState;
use std::collections::{BTreeMap, HashMap};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const DEFAULT_PORT: u16 = 47821;
const NOISE: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_JSON: usize = 60_000;
const MAX_OUTPUT_CHARS: usize = 12_000;
const PAIR_CODE_SECS: u64 = 120;
const PAIR_MAX_ATTEMPTS: u32 = 3;
const MAX_CONNECTIONS: usize = 4;
const DECISION_WAIT: Duration = Duration::from_secs(120);

type R<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// الهوية
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Identity {
    private: Vec<u8>,
    pub public: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    private: String,
    public: String,
}

pub fn fingerprint_of(public: &[u8]) -> String {
    let d = Sha256::digest(public);
    d.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

fn noise_params() -> R<snow::params::NoiseParams> {
    NOISE.parse().map_err(|e| format!("إعداد Noise: {e}"))
}

impl Identity {
    pub fn generate() -> R<Identity> {
        let kp = Builder::new(noise_params()?)
            .generate_keypair()
            .map_err(|e| format!("توليد المفاتيح: {e}"))?;
        Ok(Identity {
            private: kp.private,
            public: kp.public,
        })
    }

    pub fn load_or_create(path: &Path) -> R<Identity> {
        if path.exists() {
            let txt = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
            let f: IdentityFile =
                serde_json::from_str(&txt).map_err(|e| format!("ملف الهوية تالف: {e}"))?;
            let private = B64.decode(f.private).map_err(|e| e.to_string())?;
            let public = B64.decode(f.public).map_err(|e| e.to_string())?;
            if private.len() != 32 || public.len() != 32 {
                return Err("ملف الهوية غير صالح".into());
            }
            return Ok(Identity { private, public });
        }
        let id = Identity::generate()?;
        let f = IdentityFile {
            private: B64.encode(&id.private),
            public: B64.encode(&id.public),
        };
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        std::fs::write(
            path,
            serde_json::to_string_pretty(&f).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        Ok(id)
    }

    pub fn fingerprint(&self) -> String {
        fingerprint_of(&self.public)
    }
}

// ---------------------------------------------------------------------------
// الرسائل والقناة المشفرة
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RItem {
    /// "tool:<id>/<action>" أو "wf:<id>"
    pub item: String,
    pub title: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Msg {
    PairHello {
        name: String,
        proof: String,
    },
    PairProceed,
    PairConfirm {
        ok: bool,
    },
    PairResult {
        ok: bool,
        name: String,
        reason: String,
    },
    Hello {
        name: String,
    },
    HelloAck {
        name: String,
    },
    List,
    ListResult {
        items: Vec<RItem>,
    },
    Run {
        item: String,
    },
    RunResult {
        ok: bool,
        status: String,
        output: String,
    },
    Error {
        message: String,
    },
}

fn write_frame(s: &mut TcpStream, data: &[u8]) -> R<()> {
    if data.len() > u16::MAX as usize {
        return Err("إطار كبير".into());
    }
    s.write_all(&(data.len() as u16).to_be_bytes())
        .and_then(|_| s.write_all(data))
        .and_then(|_| s.flush())
        .map_err(|e| e.to_string())
}

fn read_frame(s: &mut TcpStream) -> R<Vec<u8>> {
    let mut len = [0u8; 2];
    s.read_exact(&mut len).map_err(|e| e.to_string())?;
    let n = u16::from_be_bytes(len) as usize;
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

pub struct Channel {
    stream: TcpStream,
    tr: TransportState,
    pub remote: Vec<u8>,
    pub hash: Vec<u8>,
}

impl Channel {
    fn finish(stream: TcpStream, hs: snow::HandshakeState) -> R<Channel> {
        let hash = hs.get_handshake_hash().to_vec();
        let remote = hs
            .get_remote_static()
            .ok_or("لم يصل المفتاح الثابت للطرف الآخر")?
            .to_vec();
        let tr = hs.into_transport_mode().map_err(|e| e.to_string())?;
        Ok(Channel {
            stream,
            tr,
            remote,
            hash,
        })
    }

    pub fn initiator(mut stream: TcpStream, id: &Identity) -> R<Channel> {
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        let mut hs = Builder::new(noise_params()?)
            .local_private_key(&id.private)
            .build_initiator()
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 65535];
        let n = hs.write_message(&[], &mut buf).map_err(|e| e.to_string())?;
        write_frame(&mut stream, &buf[..n])?;
        let f = read_frame(&mut stream)?;
        hs.read_message(&f, &mut buf).map_err(|e| e.to_string())?;
        let n = hs.write_message(&[], &mut buf).map_err(|e| e.to_string())?;
        write_frame(&mut stream, &buf[..n])?;
        Channel::finish(stream, hs)
    }

    pub fn responder(mut stream: TcpStream, id: &Identity) -> R<Channel> {
        stream
            .set_read_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        stream
            .set_write_timeout(Some(Duration::from_secs(15)))
            .map_err(|e| e.to_string())?;
        let mut hs = Builder::new(noise_params()?)
            .local_private_key(&id.private)
            .build_responder()
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0u8; 65535];
        let f = read_frame(&mut stream)?;
        hs.read_message(&f, &mut buf).map_err(|e| e.to_string())?;
        let n = hs.write_message(&[], &mut buf).map_err(|e| e.to_string())?;
        write_frame(&mut stream, &buf[..n])?;
        let f = read_frame(&mut stream)?;
        hs.read_message(&f, &mut buf).map_err(|e| e.to_string())?;
        Channel::finish(stream, hs)
    }

    pub fn set_timeout(&self, secs: u64) -> R<()> {
        self.stream
            .set_read_timeout(Some(Duration::from_secs(secs)))
            .map_err(|e| e.to_string())
    }

    pub fn send(&mut self, m: &Msg) -> R<()> {
        let json = serde_json::to_vec(m).map_err(|e| e.to_string())?;
        if json.len() > MAX_JSON {
            return Err("الرسالة كبيرة جداً".into());
        }
        let mut out = vec![0u8; json.len() + 64];
        let n = self
            .tr
            .write_message(&json, &mut out)
            .map_err(|e| e.to_string())?;
        write_frame(&mut self.stream, &out[..n])
    }

    pub fn recv(&mut self) -> R<Msg> {
        let f = read_frame(&mut self.stream)?;
        let mut out = vec![0u8; f.len()];
        let n = self
            .tr
            .read_message(&f, &mut out)
            .map_err(|e| format!("فشل فك التشفير: {e}"))?;
        serde_json::from_slice(&out[..n]).map_err(|e| format!("رسالة غير صالحة: {e}"))
    }
}

// ---------------------------------------------------------------------------
// رمز التحقق والإثبات
// ---------------------------------------------------------------------------

/// رمز التحقق المقارَن بالعين: 6 أرقام من سجل المصافحة.
pub fn sas_of(hash: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"TAR-SAS-v1");
    h.update(hash);
    let d = h.finalize();
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

fn pair_proof(code: &str, hash: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"TAR-PAIR-v1");
    h.update(code.as_bytes());
    h.update(hash);
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn ct_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn random_code() -> R<String> {
    let kp = Identity::generate()?;
    let n = u32::from_be_bytes([kp.private[0], kp.private[1], kp.private[2], kp.private[3]]);
    Ok(format!("{:06}", n % 1_000_000))
}

fn trunc_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let t: String = s.chars().take(max).collect();
        format!("{t}…[اقتُطع]")
    }
}

pub fn local_ip() -> Option<String> {
    let s = UdpSocket::bind("0.0.0.0:0").ok()?;
    s.connect("8.8.8.8:80").ok()?; // لا تُرسل أي حزمة
    Some(s.local_addr().ok()?.ip().to_string())
}

// ---------------------------------------------------------------------------
// البيئة (لعزل الاتصال عن tauri وللاختبار)
// ---------------------------------------------------------------------------

pub trait Host: Send + Sync {
    fn db(&self) -> &Db;
    fn tools_dir(&self) -> PathBuf;
    /// إشعار للواجهة: kind مثل pair_request | pair_sas | pair_done | pair_failed
    fn notify(&self, kind: &str, id: u64, text: &str);
}

// ---------------------------------------------------------------------------
// الحالة
// ---------------------------------------------------------------------------

struct Pairing {
    code: String,
    expires: Instant,
    attempts: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingPair {
    pub id: u64,
    pub name: String,
    pub fingerprint: String,
    pub sas: String,
}

struct Listener {
    stop: Arc<AtomicBool>,
    port: u16,
    lan: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnStatus {
    pub fingerprint: String,
    pub name: String,
    pub listening: bool,
    pub port: Option<u16>,
    pub lan: bool,
    pub local_ip: Option<String>,
    pub pairing_code: Option<String>,
    pub pairing_secs_left: Option<u64>,
}

pub struct Conn {
    identity: Identity,
    name: String,
    listener: Mutex<Option<Listener>>,
    pairing: Mutex<Option<Pairing>>,
    pending: Mutex<Vec<PendingPair>>,
    host_decisions: Mutex<HashMap<u64, Sender<bool>>>,
    client_confirms: Mutex<HashMap<u64, Sender<bool>>>,
    next_id: AtomicU64,
    active: AtomicUsize,
    run_lock: Mutex<()>,
}

fn default_name() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "Terminal AR".into())
}

fn noop_emit(_: &str, _: &str, _: &str, _: &str) {}

impl Conn {
    pub fn new(identity: Identity) -> Conn {
        Conn {
            identity,
            name: default_name(),
            listener: Mutex::new(None),
            pairing: Mutex::new(None),
            pending: Mutex::new(Vec::new()),
            host_decisions: Mutex::new(HashMap::new()),
            client_confirms: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            active: AtomicUsize::new(0),
            run_lock: Mutex::new(()),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn fingerprint(&self) -> String {
        self.identity.fingerprint()
    }

    fn next(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn status(&self) -> ConnStatus {
        let l = self.listener.lock().ok();
        let (listening, port, lan) = match l.as_ref().and_then(|g| g.as_ref()) {
            Some(x) => (true, Some(x.port), x.lan),
            None => (false, None, false),
        };
        let (code, left) = match self.pairing.lock() {
            Ok(g) => match g.as_ref() {
                Some(p) if Instant::now() < p.expires => (
                    Some(p.code.clone()),
                    Some(
                        p.expires
                            .saturating_duration_since(Instant::now())
                            .as_secs(),
                    ),
                ),
                _ => (None, None),
            },
            Err(_) => (None, None),
        };
        ConnStatus {
            fingerprint: self.fingerprint(),
            name: self.name.clone(),
            listening,
            port,
            lan,
            local_ip: local_ip(),
            pairing_code: code,
            pairing_secs_left: left,
        }
    }

    pub fn pending(&self) -> Vec<PendingPair> {
        self.pending.lock().map(|g| g.clone()).unwrap_or_default()
    }

    // ---- الاستماع ----

    pub fn listen_start(self: &Arc<Self>, host: Arc<dyn Host>, port: u16, lan: bool) -> R<u16> {
        let mut slot = self.listener.lock().map_err(|_| "قفل داخلي".to_string())?;
        if slot.is_some() {
            return Err("الاستماع يعمل بالفعل".into());
        }
        let bind_ip = if lan { "0.0.0.0" } else { "127.0.0.1" };
        let l = TcpListener::bind((bind_ip, port))
            .map_err(|e| format!("تعذّر فتح المنفذ {port}: {e}"))?;
        let real = l.local_addr().map_err(|e| e.to_string())?.port();
        l.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        *slot = Some(Listener {
            stop: stop.clone(),
            port: real,
            lan,
        });
        let me = self.clone();
        std::thread::spawn(move || loop {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            match l.accept() {
                Ok((s, _peer)) => {
                    if me.active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                        continue; // يُغلق الاتصال بإسقاطه
                    }
                    let _ = s.set_nonblocking(false);
                    let _ = s.set_nodelay(true);
                    me.active.fetch_add(1, Ordering::SeqCst);
                    let me2 = me.clone();
                    let host2 = host.clone();
                    std::thread::spawn(move || {
                        if let Err(e) = me2.handle_conn(host2.as_ref(), s) {
                            let _ =
                                host2
                                    .db()
                                    .audit_add("conn_error", "host", &trunc_chars(&e, 200));
                        }
                        me2.active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(_) => std::thread::sleep(Duration::from_millis(200)),
            }
        });
        Ok(real)
    }

    pub fn listen_stop(&self) {
        if let Ok(mut slot) = self.listener.lock() {
            if let Some(l) = slot.take() {
                l.stop.store(true, Ordering::SeqCst);
            }
        }
        if let Ok(mut p) = self.pairing.lock() {
            *p = None;
        }
    }

    pub fn pairing_start(&self) -> R<String> {
        if self
            .listener
            .lock()
            .map_err(|_| "قفل داخلي".to_string())?
            .is_none()
        {
            return Err("فعّل استقبال الاتصالات أولاً".into());
        }
        let code = random_code()?;
        *self.pairing.lock().map_err(|_| "قفل داخلي".to_string())? = Some(Pairing {
            code: code.clone(),
            expires: Instant::now() + Duration::from_secs(PAIR_CODE_SECS),
            attempts: 0,
        });
        Ok(code)
    }

    pub fn pairing_cancel(&self) {
        if let Ok(mut p) = self.pairing.lock() {
            *p = None;
        }
    }

    /// قرار صاحب الجهاز المضيف على طلب اقتران معلّق.
    pub fn decide(&self, id: u64, accept: bool) -> R<()> {
        let tx = self
            .host_decisions
            .lock()
            .map_err(|_| "قفل داخلي".to_string())?
            .get(&id)
            .cloned()
            .ok_or("الطلب غير موجود أو انتهى")?;
        tx.send(accept).map_err(|_| "انتهى الطلب".to_string())
    }

    /// تأكيد المستخدم (على الجهاز المبادر) أن رمز التحقق متطابق.
    pub fn client_confirm(&self, id: u64, accept: bool) -> R<()> {
        let tx = self
            .client_confirms
            .lock()
            .map_err(|_| "قفل داخلي".to_string())?
            .get(&id)
            .cloned()
            .ok_or("الطلب غير موجود أو انتهى")?;
        tx.send(accept).map_err(|_| "انتهى الطلب".to_string())
    }

    // ---- جهة المضيف ----

    fn handle_conn(self: &Arc<Self>, host: &dyn Host, stream: TcpStream) -> R<()> {
        let mut ch = Channel::responder(stream, &self.identity)?;
        ch.set_timeout(30)?;
        match ch.recv()? {
            Msg::PairHello { name, proof } => self.host_pairing(host, &mut ch, &name, &proof),
            Msg::Hello { name } => self.host_session(host, &mut ch, &name),
            _ => Err("رسالة أولى غير متوقعة".into()),
        }
    }

    fn host_pairing(&self, host: &dyn Host, ch: &mut Channel, name: &str, proof: &str) -> R<()> {
        // 1) رمز الاقتران
        let verdict: Result<(), &'static str> = {
            let mut g = self.pairing.lock().map_err(|_| "قفل داخلي".to_string())?;
            let now_t = Instant::now();
            if g.as_ref()
                .map(|p| now_t > p.expires || p.attempts >= PAIR_MAX_ATTEMPTS)
                .unwrap_or(false)
            {
                *g = None;
            }
            match g.as_mut() {
                None => Err("الاقتران غير مفعّل على هذا الجهاز أو انتهى الرمز"),
                Some(p) => {
                    if ct_eq(&pair_proof(&p.code, &ch.hash), proof) {
                        *g = None; // الرمز يُستعمل مرة واحدة
                        Ok(())
                    } else {
                        p.attempts += 1;
                        let burn = p.attempts >= PAIR_MAX_ATTEMPTS;
                        if burn {
                            *g = None;
                        }
                        Err("رمز الاقتران غير صحيح")
                    }
                }
            }
        };
        if let Err(msg) = verdict {
            let _ = host.db().audit_add("pair_denied", name, msg);
            let _ = ch.send(&Msg::Error {
                message: msg.to_string(),
            });
            return Err(msg.to_string());
        }

        // 2) تسجيل الطلب والانتظار: تأكيد المبادر ثم قرار صاحب هذا الجهاز
        let id = self.next();
        let sas = sas_of(&ch.hash);
        let fp = fingerprint_of(&ch.remote);
        let (tx, rx) = channel::<bool>();
        self.host_decisions
            .lock()
            .map_err(|_| "قفل داخلي".to_string())?
            .insert(id, tx);
        self.pending
            .lock()
            .map_err(|_| "قفل داخلي".to_string())?
            .push(PendingPair {
                id,
                name: name.to_string(),
                fingerprint: fp.clone(),
                sas: sas.clone(),
            });
        host.notify("pair_request", id, &format!("{name}|{sas}"));

        let result = (|| -> R<(bool, &'static str)> {
            ch.send(&Msg::PairProceed)?;
            ch.set_timeout(130)?;
            let initiator_ok = matches!(ch.recv()?, Msg::PairConfirm { ok: true });
            if !initiator_ok {
                return Ok((false, "لم يؤكد الجهاز الآخر تطابق الرمز"));
            }
            match rx.recv_timeout(DECISION_WAIT) {
                Ok(true) => Ok((true, "")),
                Ok(false) => Ok((false, "رفض صاحب الجهاز الاقتران")),
                Err(_) => Ok((false, "انتهت مهلة موافقة صاحب الجهاز")),
            }
        })();

        if let Ok(mut m) = self.host_decisions.lock() {
            m.remove(&id);
        }
        if let Ok(mut p) = self.pending.lock() {
            p.retain(|x| x.id != id);
        }
        host.notify("pair_closed", id, "");

        let (ok, reason) = result?;
        if ok {
            host.db().device_put(&DeviceRow {
                fingerprint: fp.clone(),
                name: name.to_string(),
                public_key: B64.encode(&ch.remote),
                role: "controller".into(),
                added_at: now(),
                last_seen: None,
                last_addr: None,
            })?;
            let _ = host.db().audit_add("pair_ok", name, &fp);
        } else {
            let _ = host.db().audit_add("pair_denied", name, reason);
        }
        ch.send(&Msg::PairResult {
            ok,
            name: self.name.clone(),
            reason: reason.to_string(),
        })?;
        Ok(())
    }

    fn host_session(&self, host: &dyn Host, ch: &mut Channel, name: &str) -> R<()> {
        let fp = fingerprint_of(&ch.remote);
        let dev = host.db().device_get(&fp)?;
        match dev {
            Some(d) if d.role == "controller" => {}
            _ => {
                let _ = host.db().audit_add("conn_rejected", name, &fp);
                let _ = ch.send(&Msg::Error {
                    message: "هذا الجهاز غير مقترن".into(),
                });
                return Err("اتصال من جهاز غير مقترن".into());
            }
        }
        let dev_name = dev_name_of(host.db(), &fp);
        host.db().device_touch(&fp)?;
        ch.send(&Msg::HelloAck {
            name: self.name.clone(),
        })?;
        ch.set_timeout(60)?;
        loop {
            let m = match ch.recv() {
                Ok(m) => m,
                Err(_) => return Ok(()), // أغلق الطرف الآخر أو انتهت المهلة
            };
            match m {
                Msg::List => {
                    let items = self.allowed_items(host, &fp)?;
                    ch.send(&Msg::ListResult { items })?;
                }
                Msg::Run { item } => {
                    let allowed = host.db().allow_get(&fp)?;
                    if !allowed.contains(&item) {
                        let _ = host.db().audit_add("remote_denied", &dev_name, &item);
                        ch.send(&Msg::Error {
                            message: "غير مسموح لهذا الجهاز".into(),
                        })?;
                        continue;
                    }
                    let _ = host.db().audit_add("remote_run", &dev_name, &item);
                    let out = self.exec_item(host, &item);
                    let (ok, status, output) = match out {
                        Ok((st, text)) => (st == "ok", st, text),
                        Err(e) => (false, "refused".to_string(), e),
                    };
                    let _ =
                        host.db()
                            .audit_add("remote_end", &dev_name, &format!("{item}: {status}"));
                    ch.send(&Msg::RunResult {
                        ok,
                        status,
                        output: trunc_chars(&output, MAX_OUTPUT_CHARS),
                    })?;
                }
                _ => {
                    ch.send(&Msg::Error {
                        message: "طلب غير مدعوم".into(),
                    })?;
                }
            }
        }
    }

    /// العناصر المسموحة لجهاز والموجودة فعلاً (أداة مفعّلة/تدفق محفوظ).
    pub fn allowed_items(&self, host: &dyn Host, fp: &str) -> R<Vec<RItem>> {
        let allowed = host.db().allow_get(fp)?;
        Ok(catalog(host.db())?
            .into_iter()
            .filter(|i| allowed.contains(&i.item))
            .collect())
    }

    fn exec_item(&self, host: &dyn Host, item: &str) -> R<(String, String)> {
        let _g = self
            .run_lock
            .try_lock()
            .map_err(|_| "يعمل الآن تشغيل آخر عن بعد".to_string())?;
        if let Some(rest) = item.strip_prefix("tool:") {
            let (tool, action) = rest.split_once('/').ok_or("صيغة عنصر غير صالحة")?;
            return exec_tool(host, tool, action);
        }
        if let Some(id) = item.strip_prefix("wf:") {
            return exec_wf(host, id);
        }
        Err("نوع عنصر غير معروف".into())
    }

    // ---- جهة المبادر ----

    fn connect(&self, addr: &str) -> R<TcpStream> {
        let addr = if addr.contains(':') {
            addr.to_string()
        } else {
            format!("{addr}:{DEFAULT_PORT}")
        };
        let sa = addr
            .to_socket_addrs()
            .map_err(|e| format!("عنوان غير صالح: {e}"))?
            .next()
            .ok_or("عنوان غير صالح")?;
        let s = TcpStream::connect_timeout(&sa, Duration::from_secs(8))
            .map_err(|e| format!("تعذّر الاتصال: {e}"))?;
        let _ = s.set_nodelay(true);
        Ok(s)
    }

    /// يقترن بجهاز مضيف. يُستدعى في خيط منفصل؛ الواجهة تؤكد الرمز عبر client_confirm.
    pub fn pair_client(
        self: &Arc<Self>,
        host: &dyn Host,
        id: u64,
        addr: &str,
        code: &str,
    ) -> R<DeviceRow> {
        let (tx, rx) = channel::<bool>();
        self.client_confirms
            .lock()
            .map_err(|_| "قفل داخلي".to_string())?
            .insert(id, tx);
        let out = self.pair_client_inner(host, id, addr, code, &rx);
        if let Ok(mut m) = self.client_confirms.lock() {
            m.remove(&id);
        }
        out
    }

    fn pair_client_inner(
        &self,
        host: &dyn Host,
        id: u64,
        addr: &str,
        code: &str,
        rx: &std::sync::mpsc::Receiver<bool>,
    ) -> R<DeviceRow> {
        let stream = self.connect(addr)?;
        let mut ch = Channel::initiator(stream, &self.identity)?;
        ch.send(&Msg::PairHello {
            name: self.name.clone(),
            proof: pair_proof(code.trim(), &ch.hash),
        })?;
        ch.set_timeout(30)?;
        match ch.recv()? {
            Msg::PairProceed => {}
            Msg::Error { message } => return Err(message),
            _ => return Err("رد غير متوقع".into()),
        }
        let sas = sas_of(&ch.hash);
        host.notify("pair_sas", id, &sas);
        let ok = rx.recv_timeout(DECISION_WAIT).unwrap_or(false);
        ch.send(&Msg::PairConfirm { ok })?;
        if !ok {
            return Err("ألغيت الاقتران".into());
        }
        ch.set_timeout(130)?;
        match ch.recv()? {
            Msg::PairResult { ok: true, name, .. } => {
                let row = DeviceRow {
                    fingerprint: fingerprint_of(&ch.remote),
                    name,
                    public_key: B64.encode(&ch.remote),
                    role: "host".into(),
                    added_at: now(),
                    last_seen: Some(now()),
                    last_addr: Some(addr.to_string()),
                };
                host.db().device_put(&row)?;
                let _ = host.db().audit_add("pair_ok", &row.name, &row.fingerprint);
                Ok(row)
            }
            Msg::PairResult { reason, .. } => Err(reason),
            Msg::Error { message } => Err(message),
            _ => Err("رد غير متوقع".into()),
        }
    }

    /// اتصال بجهاز مقترن (دور host) مع تثبيت هويته.
    fn connect_known(&self, db: &Db, fp: &str, addr_override: Option<&str>) -> R<Channel> {
        let dev = db.device_get(fp)?.ok_or("الجهاز غير مقترن")?;
        if dev.role != "host" {
            return Err("هذا الجهاز مقترن للاتصال بك وليس للاتصال به".into());
        }
        let addr = addr_override
            .map(|s| s.to_string())
            .or(dev.last_addr.clone())
            .ok_or("لا يوجد عنوان محفوظ لهذا الجهاز")?;
        let stream = self.connect(&addr)?;
        let mut ch = Channel::initiator(stream, &self.identity)?;
        let pinned = B64.decode(&dev.public_key).map_err(|e| e.to_string())?;
        if ch.remote != pinned {
            let _ = db.audit_add("identity_mismatch", &dev.name, &addr);
            return Err(
                "هوية الجهاز تغيّرت عن المثبّتة عند الاقتران — رُفض الاتصال (قد يكون هجوماً)".into(),
            );
        }
        ch.send(&Msg::Hello {
            name: self.name.clone(),
        })?;
        ch.set_timeout(30)?;
        match ch.recv()? {
            Msg::HelloAck { .. } => {}
            Msg::Error { message } => return Err(message),
            _ => return Err("رد غير متوقع".into()),
        }
        if let Some(a) = addr_override {
            let mut d = dev;
            d.last_addr = Some(a.to_string());
            d.last_seen = Some(now());
            db.device_put(&d)?;
        }
        Ok(ch)
    }

    pub fn remote_list(&self, db: &Db, fp: &str, addr: Option<&str>) -> R<Vec<RItem>> {
        let mut ch = self.connect_known(db, fp, addr)?;
        ch.send(&Msg::List)?;
        match ch.recv()? {
            Msg::ListResult { items } => Ok(items),
            Msg::Error { message } => Err(message),
            _ => Err("رد غير متوقع".into()),
        }
    }

    pub fn remote_run(
        &self,
        db: &Db,
        fp: &str,
        item: &str,
        addr: Option<&str>,
    ) -> R<(bool, String, String)> {
        let mut ch = self.connect_known(db, fp, addr)?;
        ch.set_timeout(300)?;
        ch.send(&Msg::Run {
            item: item.to_string(),
        })?;
        match ch.recv()? {
            Msg::RunResult { ok, status, output } => Ok((ok, status, output)),
            Msg::Error { message } => Err(message),
            _ => Err("رد غير متوقع".into()),
        }
    }
}

fn dev_name_of(db: &Db, fp: &str) -> String {
    db.device_get(fp)
        .ok()
        .flatten()
        .map(|d| d.name)
        .unwrap_or_else(|| fp.to_string())
}

/// قائمة كل ما يمكن السماح به لجهاز: إجراءات الأدوات المفعّلة (وضع run) والتدفقات المحفوظة.
pub fn catalog(db: &Db) -> R<Vec<RItem>> {
    let mut out = Vec::new();
    for row in db.tools_list()? {
        let info = match plugin::to_info(row) {
            Ok(i) => i,
            Err(_) => continue,
        };
        if !info.enabled {
            continue;
        }
        for a in &info.manifest.actions {
            if a.mode != "run" {
                continue;
            }
            out.push(RItem {
                item: format!("tool:{}/{}", info.id, a.id),
                title: format!("{} ← {}", info.name, a.title),
            });
        }
    }
    for w in db.wf_list()? {
        out.push(RItem {
            item: format!("wf:{}", w.id),
            title: format!("تدفق: {}", w.name),
        });
    }
    Ok(out)
}

fn collect_output(rep: &workflow::RunReport) -> String {
    let mut s = String::new();
    for st in &rep.steps {
        s.push_str(&format!("[{}] {} — {}\n", st.status, st.title, st.note));
        if !st.stdout.trim().is_empty() {
            s.push_str(st.stdout.trim());
            s.push('\n');
        }
        if !st.stderr.trim().is_empty() {
            s.push_str("[stderr] ");
            s.push_str(st.stderr.trim());
            s.push('\n');
        }
    }
    s
}

fn exec_tool(host: &dyn Host, tool: &str, action: &str) -> R<(String, String)> {
    let db = host.db();
    // البوابة الأصلية للأدوات: الصلاحيات الممنوحة وتعطيل الأداة
    let plan = security::plan_run(db, &host.tools_dir(), tool, action)?;
    if plan.mode != "run" {
        return Err("إجراءات الإدراج (insert) لا تُشغَّل عن بعد".into());
    }
    if !plan.warnings.is_empty() {
        return Err(format!(
            "رُفض عن بعد: يحوي أنماطاً حساسة ({})؛ يُشغَّل محلياً مع تأكيد فقط",
            plan.warnings.len()
        ));
    }
    let row = db.tool_get(tool)?.ok_or("الأداة غير موجودة")?;
    let info = plugin::to_info(row)?;
    let confirm = info
        .manifest
        .actions
        .iter()
        .find(|a| a.id == action)
        .map(|a| a.confirm)
        .unwrap_or(true);
    if confirm {
        return Err("هذا الإجراء يتطلب تأكيداً محلياً ولا يُشغَّل عن بعد".into());
    }
    let step = PStep {
        id: "remote".into(),
        title: plan.title.clone(),
        kind: "run".into(),
        shell: workflow::host_shell(&plan.shell).into(),
        commands: plan.steps.clone(),
        cwd: plan.cwd.clone(),
        when: None,
        on_error: "stop".into(),
        retries: 0,
        timeout: Duration::from_secs(120),
    };
    let cancel = AtomicBool::new(false);
    let rep = workflow::run_prepared(
        "remote",
        &[Item::Single(step)],
        &BTreeMap::new(),
        &ProcessExec,
        &cancel,
        &noop_emit,
    );
    Ok((rep.status.clone(), collect_output(&rep)))
}

fn exec_wf(host: &dyn Host, id: &str) -> R<(String, String)> {
    let db = host.db();
    let row = db.wf_get(id)?.ok_or("التدفق غير موجود")?;
    let wf = workflow::parse(&row.body).map_err(|d| d.message)?;
    let dir = host.tools_dir();
    let plan = workflow::plan(db, &dir, &wf)?;
    if !plan.missing.is_empty() {
        return Err(format!(
            "التدفق يحتاج صلاحيات غير معتمدة محلياً: {}",
            plan.missing.join("، ")
        ));
    }
    if !plan.warnings.is_empty() {
        return Err("رُفض عن بعد: التدفق يحوي أنماطاً حساسة؛ يُشغَّل محلياً فقط".into());
    }
    let prepared = workflow::prepare(db, &dir, &wf)?;
    let cancel = AtomicBool::new(false);
    let rep = workflow::run_prepared(
        &wf.id,
        &prepared.items,
        &wf.variables,
        &ProcessExec,
        &cancel,
        &noop_emit,
    );
    Ok((rep.status.clone(), collect_output(&rep)))
}

// ---------------------------------------------------------------------------
// اختبارات (حلقة محلية حقيقية على 127.0.0.1)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHost {
        db: Db,
        dir: PathBuf,
    }

    impl TestHost {
        fn new() -> Arc<TestHost> {
            Arc::new(TestHost {
                db: Db::open_in_memory().unwrap(),
                dir: std::env::temp_dir().join("tar-conn-test"),
            })
        }
    }

    impl Host for TestHost {
        fn db(&self) -> &Db {
            &self.db
        }
        fn tools_dir(&self) -> PathBuf {
            self.dir.clone()
        }
        fn notify(&self, _kind: &str, _id: u64, _text: &str) {}
    }

    fn pair(
        a: &Arc<Conn>,
        ha: &Arc<TestHost>,
        b: &Arc<Conn>,
        hb: &Arc<TestHost>,
        port: u16,
        code: &str,
        host_accepts: bool,
    ) -> R<DeviceRow> {
        // الجهاز a هو المضيف، و b هو المبادر. نحاكي واجهتي المستخدمين بخيطين.
        let a2 = a.clone();
        let decider = std::thread::spawn(move || {
            for _ in 0..200 {
                if let Some(p) = a2.pending().first() {
                    let _ = a2.decide(p.id, host_accepts);
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let b2 = b.clone();
        let confirmer = std::thread::spawn(move || {
            for _ in 0..200 {
                let id = 1; // أول طلب مبادر في الاختبار
                if b2.client_confirm(id, true).is_ok() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let _ = ha;
        let r = b.pair_client(hb.as_ref(), 1, &format!("127.0.0.1:{port}"), code);
        let _ = decider.join();
        let _ = confirmer.join();
        r
    }

    fn setup() -> (Arc<Conn>, Arc<TestHost>, Arc<Conn>, Arc<TestHost>, u16) {
        let ha = TestHost::new();
        let hb = TestHost::new();
        let a = Arc::new(Conn::new(Identity::generate().unwrap()));
        let b = Arc::new(Conn::new(Identity::generate().unwrap()));
        let port = a.listen_start(ha.clone(), 0, false).unwrap();
        (a, ha, b, hb, port)
    }

    #[test]
    fn sas_and_fingerprint_are_stable_and_short() {
        assert_eq!(sas_of(b"abc"), sas_of(b"abc"));
        assert_ne!(sas_of(b"abc"), sas_of(b"abd"));
        assert_eq!(sas_of(b"abc").len(), 6);
        assert_eq!(fingerprint_of(&[1u8; 32]).len(), 16);
        let c = random_code().unwrap();
        assert_eq!(c.len(), 6);
        assert!(c.chars().all(|x| x.is_ascii_digit()));
    }

    #[test]
    fn identity_is_persisted_and_reloaded() {
        let p = std::env::temp_dir().join(format!("tar-id-{}.json", now()));
        let a = Identity::load_or_create(&p).unwrap();
        let b = Identity::load_or_create(&p).unwrap();
        assert_eq!(a.public, b.public);
        assert_eq!(a.fingerprint(), b.fingerprint());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn pairing_requires_active_mode_and_correct_code() {
        let (a, _ha, b, hb, port) = setup();
        // بلا وضع اقتران
        let r = b.pair_client(hb.as_ref(), 1, &format!("127.0.0.1:{port}"), "123456");
        assert!(r.unwrap_err().contains("غير مفعّل"));
        // رمز خاطئ
        a.pairing_start().unwrap();
        let r = b.pair_client(hb.as_ref(), 2, &format!("127.0.0.1:{port}"), "000000x");
        assert!(r.unwrap_err().contains("غير صحيح"));
        a.listen_stop();
    }

    #[test]
    fn code_burns_after_three_wrong_attempts() {
        let (a, _ha, b, hb, port) = setup();
        let code = a.pairing_start().unwrap();
        for i in 0..PAIR_MAX_ATTEMPTS {
            let r = b.pair_client(
                hb.as_ref(),
                10 + i as u64,
                &format!("127.0.0.1:{port}"),
                "bad",
            );
            assert!(r.is_err());
        }
        let r = b.pair_client(hb.as_ref(), 99, &format!("127.0.0.1:{port}"), &code);
        assert!(r.is_err(), "الرمز الصحيح بعد 3 محاولات خاطئة يجب أن يُرفض");
        a.listen_stop();
    }

    #[test]
    fn full_pairing_then_list_and_denied_run() {
        let (a, ha, b, hb, port) = setup();
        let code = a.pairing_start().unwrap();
        let dev = pair(&a, &ha, &b, &hb, port, &code, true).unwrap();
        assert_eq!(dev.role, "host");
        assert_eq!(dev.fingerprint, a.fingerprint());
        // كل طرف سجّل الآخر
        assert_eq!(ha.db.device_list().unwrap().len(), 1);
        assert_eq!(ha.db.device_list().unwrap()[0].role, "controller");
        assert_eq!(ha.db.device_list().unwrap()[0].fingerprint, b.fingerprint());
        // لا شيء مسموح بعد
        let items = b.remote_list(&hb.db, &a.fingerprint(), None).unwrap();
        assert!(items.is_empty());
        // تشغيل غير مسموح
        let err = b
            .remote_run(&hb.db, &a.fingerprint(), "wf:anything", None)
            .unwrap_err();
        assert!(err.contains("غير مسموح"), "{err}");
        a.listen_stop();
    }

    #[test]
    fn host_decline_prevents_pairing() {
        let (a, ha, b, hb, port) = setup();
        let code = a.pairing_start().unwrap();
        let r = pair(&a, &ha, &b, &hb, port, &code, false);
        assert!(r.unwrap_err().contains("رفض"));
        assert!(ha.db.device_list().unwrap().is_empty());
        assert!(hb.db.device_list().unwrap().is_empty());
        a.listen_stop();
    }

    #[test]
    fn unpaired_device_is_rejected_and_unpair_blocks_access() {
        let (a, ha, b, hb, port) = setup();
        // جهاز لم يقترن: لا يملك سجلاً عند b أصلاً
        assert!(b.remote_list(&hb.db, "deadbeef", None).is_err());
        let code = a.pairing_start().unwrap();
        pair(&a, &ha, &b, &hb, port, &code, true).unwrap();
        assert!(b.remote_list(&hb.db, &a.fingerprint(), None).is_ok());
        // المضيف يلغي الاقتران
        ha.db.device_delete(&b.fingerprint()).unwrap();
        let err = b.remote_list(&hb.db, &a.fingerprint(), None).unwrap_err();
        assert!(err.contains("غير مقترن"), "{err}");
        a.listen_stop();
    }

    #[test]
    fn changed_host_identity_is_refused() {
        let (a, ha, b, hb, port) = setup();
        let code = a.pairing_start().unwrap();
        pair(&a, &ha, &b, &hb, port, &code, true).unwrap();
        a.listen_stop();
        std::thread::sleep(Duration::from_millis(300));
        // مضيف آخر بهوية مختلفة على المنفذ نفسه يدّعي أنه a
        let ha2 = TestHost::new();
        let imposter = Arc::new(Conn::new(Identity::generate().unwrap()));
        let p2 = imposter.listen_start(ha2, port, false).unwrap();
        assert_eq!(p2, port);
        let err = b.remote_list(&hb.db, &a.fingerprint(), None).unwrap_err();
        assert!(err.contains("هوية الجهاز تغيّرت"), "{err}");
        imposter.listen_stop();
    }

    #[test]
    fn allowed_item_runs_a_workflow_remotely() {
        let (a, ha, b, hb, port) = setup();
        let code = a.pairing_start().unwrap();
        pair(&a, &ha, &b, &hb, port, &code, true).unwrap();
        // تدفق بسيط على المضيف (أمر echo يعمل في sh وcmd)، مع منح صلاحياته محلياً
        let body = r#"{"id":"hi","name":"hi","steps":[{"id":"a","run":"echo hello-remote","shell":"cmd"}]}"#;
        let wf = workflow::parse(body).unwrap();
        ha.db.wf_put(&wf.id, &wf.name, body).unwrap();
        workflow::set_grants(&ha.db, "hi", &["process.run".to_string()]).unwrap();
        ha.db
            .allow_set(&b.fingerprint(), &["wf:hi".to_string()])
            .unwrap();
        let items = b.remote_list(&hb.db, &a.fingerprint(), None).unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].item, "wf:hi");
        let (ok, status, out) = b
            .remote_run(&hb.db, &a.fingerprint(), "wf:hi", None)
            .unwrap();
        assert!(ok, "{status} {out}");
        assert!(out.contains("hello-remote"), "{out}");
        a.listen_stop();
    }
}
