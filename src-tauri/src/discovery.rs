//! اكتشاف الأجهزة على الشبكة (mDNS) وعناوين الشبكة المحلية/VPN.
//!
//! - الكمبيوتر (شاشة القفل) يعلن خدمة `_tarlock._tcp` باسمه ومنفذه *دون الرمز السري*؛ الرمز يظهر على شاشته فقط.
//! - الهاتف يبحث عن الخدمة ويعرض قائمة بالأسماء؛ يختار المستخدم ثم يُدخل الرمز المعروض على الكمبيوتر.
//! - العناوين المقبولة: شبكات خاصة (10/8، 172.16/12، 192.168/16) ونطاق VPN مثل Tailscale (100.64/10).
//!   لا عناوين عامة ولا loopback ولا link-local، فلا يقبل التطبيق الاتصال بعنوان إنترنت عشوائي.
//! - mDNS لا يعبر الراوترات ولا الإنترنت؛ عبر VPN أدخل عنوان VPN يدوياً أو من QR.

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

type R<T> = Result<T, String>;

pub const SERVICE: &str = "_tarlock._tcp.local.";
const MAX_ADDRS: usize = 4;

pub fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// هل العنوان مقبول للاتصال (شبكة خاصة أو VPN)؟
pub fn is_usable_v4(ip: Ipv4Addr) -> bool {
    if ip.is_loopback()
        || ip.is_unspecified()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
    {
        return false;
    }
    ip.is_private() || is_cgnat(ip)
}

/// عناوين هذا الجهاز الصالحة، الشبكة المحلية أولاً ثم VPN.
pub fn local_addrs() -> Vec<Ipv4Addr> {
    let mut v: Vec<Ipv4Addr> = match if_addrs::get_if_addrs() {
        Ok(list) => list
            .into_iter()
            .filter_map(|i| match i.ip() {
                IpAddr::V4(a) if is_usable_v4(a) => Some(a),
                _ => None,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort_by_key(|a| (is_cgnat(*a), a.octets()));
    v.dedup();
    v
}

/// يحلّل «ip:port,ip:port» ويرفض أي عنوان غير مقبول. يرجع قائمة (ip, port) بحد أقصى 4.
pub fn parse_addr_list(s: &str) -> R<Vec<(Ipv4Addr, u16)>> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let (ip, port) = part
            .rsplit_once(':')
            .ok_or_else(|| format!("العنوان بلا منفذ: {part}"))?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| format!("عنوان غير صالح: {part}"))?;
        let port: u16 = port.parse().map_err(|_| format!("منفذ غير صالح: {part}"))?;
        if port == 0 {
            return Err(format!("منفذ غير صالح: {part}"));
        }
        if !is_usable_v4(ip) {
            return Err(format!(
                "العنوان {ip} ليس شبكة محلية ولا VPN (مسموح: 10.x و172.16-31.x و192.168.x و100.64-127.x)"
            ));
        }
        out.push((ip, port));
    }
    if out.is_empty() {
        return Err("لا يوجد عنوان".into());
    }
    out.truncate(MAX_ADDRS);
    Ok(out)
}

/// اسم صالح كعنصر DNS: حروف وأرقام وشرطة فقط (الاسم العربي يبقى في خاصية name).
pub fn sanitize_label(name: &str) -> String {
    let s: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let s = s.trim_matches('-').to_string();
    let s = if s.is_empty() {
        "terminal-ar".to_string()
    } else {
        s
    };
    s.chars().take(40).collect()
}

/// إعلان mDNS يبقى ما دام الكائن حياً.
pub struct Advertiser {
    daemon: ServiceDaemon,
}

impl Advertiser {
    pub fn start(name: &str, port: u16, addrs: &[Ipv4Addr]) -> R<Self> {
        if addrs.is_empty() {
            return Err("لا توجد عناوين شبكة".into());
        }
        let daemon = ServiceDaemon::new().map_err(|e| format!("mDNS: {e}"))?;
        let label = sanitize_label(name);
        let host = format!("{label}.local.");
        let ips = addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let props = [("name", name), ("v", "1")];
        let info = ServiceInfo::new(SERVICE, &label, &host, ips.as_str(), port, &props[..])
            .map_err(|e| format!("mDNS: {e}"))?;
        daemon.register(info).map_err(|e| format!("mDNS: {e}"))?;
        Ok(Advertiser { daemon })
    }
}

impl Drop for Advertiser {
    fn drop(&mut self) {
        let _ = self.daemon.shutdown();
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Found {
    pub name: String,
    /// «ip:port» لكل عنوان مقبول، الشبكة المحلية أولاً
    pub addrs: Vec<String>,
}

/// يبحث `secs` ثانية عن أجهزة تعلن الخدمة. يرجع القائمة (قد تكون فارغة).
pub fn browse(secs: u64) -> R<Vec<Found>> {
    let daemon = ServiceDaemon::new().map_err(|e| format!("mDNS: {e}"))?;
    let rx = daemon.browse(SERVICE).map_err(|e| format!("mDNS: {e}"))?;
    let deadline = Instant::now() + Duration::from_secs(secs.clamp(1, 10));
    let mut found: Vec<Found> = Vec::new();
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        match rx.recv_timeout(left) {
            Ok(ServiceEvent::ServiceResolved(info)) => {
                let port = info.get_port();
                let mut ips: Vec<Ipv4Addr> = info
                    .get_addresses()
                    .iter()
                    .filter_map(|a| match a {
                        IpAddr::V4(v) if is_usable_v4(*v) => Some(*v),
                        _ => None,
                    })
                    .collect();
                ips.sort_by_key(|a| (is_cgnat(*a), a.octets()));
                if ips.is_empty() || port == 0 {
                    continue;
                }
                let name = info
                    .get_property_val_str("name")
                    .map(str::to_string)
                    .unwrap_or_else(|| info.get_fullname().to_string());
                let addrs: Vec<String> = ips.iter().map(|a| format!("{a}:{port}")).collect();
                if let Some(f) = found.iter_mut().find(|f| f.name == name) {
                    f.addrs = addrs;
                } else {
                    found.push(Found { name, addrs });
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
    let _ = daemon.shutdown();
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn usable_addresses_are_private_or_vpn_only() {
        for ok in [
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.1",
            "192.168.1.20",
            "100.64.0.1",
            "100.127.255.254",
        ] {
            assert!(is_usable_v4(ip(ok)), "{ok}");
        }
        for bad in [
            "8.8.8.8",
            "127.0.0.1",
            "0.0.0.0",
            "169.254.1.1",
            "172.32.0.1",
            "172.15.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "224.0.0.251",
            "255.255.255.255",
            "1.1.1.1",
        ] {
            assert!(!is_usable_v4(ip(bad)), "{bad}");
        }
    }

    #[test]
    fn parse_addr_list_accepts_lists_and_rejects_bad_entries() {
        let v = parse_addr_list("192.168.1.20:47821, 100.101.102.103:47821").unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(v[0], (ip("192.168.1.20"), 47821));
        assert!(parse_addr_list("").is_err());
        assert!(parse_addr_list("192.168.1.20").is_err());
        assert!(parse_addr_list("192.168.1.20:0").is_err());
        assert!(parse_addr_list("192.168.1.20:99999").is_err());
        assert!(parse_addr_list("8.8.8.8:47821").is_err());
        assert!(parse_addr_list("127.0.0.1:47821").is_err());
        // عنوان سيّئ واحد يرفض القائمة كلها
        assert!(parse_addr_list("192.168.1.20:47821,8.8.8.8:47821").is_err());
        assert!(parse_addr_list("example.com:47821").is_err());
    }

    #[test]
    fn parse_addr_list_caps_at_four_entries() {
        let s = (1..=9)
            .map(|i| format!("10.0.0.{i}:1000"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(parse_addr_list(&s).unwrap().len(), MAX_ADDRS);
    }

    #[test]
    fn labels_are_dns_safe() {
        assert_eq!(sanitize_label("My PC"), "My-PC");
        assert_eq!(sanitize_label("حاسوبي"), "terminal-ar");
        assert_eq!(sanitize_label("--a--"), "a");
        assert!(sanitize_label(&"x".repeat(100)).len() <= 40);
    }

    #[test]
    fn local_addrs_are_all_usable_and_lan_first() {
        let v = local_addrs();
        assert!(v.iter().all(|a| is_usable_v4(*a)));
        let first_vpn = v.iter().position(|a| is_cgnat(*a));
        if let Some(i) = first_vpn {
            assert!(v[i..].iter().all(|a| is_cgnat(*a)));
        }
    }
}
