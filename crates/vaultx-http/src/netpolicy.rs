//! Egress network policy: IP classification and SSRF defenses.
//!
//! # Rebinding contract (caller obligation)
//!
//! DNS rebinding is defeated by binding resolution to the *validated*
//! connection target, not by string inspection alone. The transport layer
//! must therefore follow this sequence exactly (plan §20):
//!
//! 1. canonicalize the destination ([`crate::canonical::CanonicalUrl`]);
//! 2. if the host is an IP *literal*, [`EgressGuard::check_host`] decides
//!    immediately;
//! 3. otherwise resolve DNS **after** parsing, then call
//!    [`EgressGuard::recheck_resolved`] on every returned address and
//!    connect **only** to an address that passed the re-check. Resolving
//!    before validation, or connecting to a different resolver result,
//!    violates this contract.
//!
//! Hostname-only approval from step 2 (`Ok(Classification::Global)`) is a
//! provisional pass; it never authorizes a connection by itself.
//!
//! # Hard invariant
//!
//! Cloud metadata-service endpoints are never permitted, even when
//! private destinations are explicitly allowed via configuration.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::HttpPolicyError;

/// Security-relevant class of an IP address under egress policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Classification {
    /// IPv4 `127.0.0.0/8`, IPv6 `::1`.
    Loopback,
    /// IPv4 `169.254.0.0/16` (minus metadata specials), IPv6 `fe80::/10`.
    LinkLocal,
    /// RFC 1918 space, CGNAT `100.64.0.0/10`, benchmark/doc ranges
    /// (`192.0.0.0/24`, `198.18.0.0/15`), unique-local `fc00::/7`.
    Private,
    /// IPv4 `224.0.0.0/4`, IPv6 `ff00::/8`.
    Multicast,
    /// IPv4 `0.0.0.0/8`, IPv6 `::`.
    Unspecified,
    /// Cloud instance metadata endpoints (`169.254.169.254`,
    /// `169.254.170.2`, `fd00:ec2::254`). Never egress-allowed.
    MetadataService,
    /// Globally routable public address space.
    Global,
}

impl std::fmt::Display for Classification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Loopback => "loopback",
            Self::LinkLocal => "link-local",
            Self::Private => "private",
            Self::Multicast => "multicast",
            Self::Unspecified => "unspecified",
            Self::MetadataService => "metadata-service",
            Self::Global => "global",
        };
        f.write_str(text)
    }
}

/// Well-known AWS EC2/ECS credential endpoint.
const METADATA_V4_1: [u8; 4] = [169, 254, 169, 254];
/// GCP metadata server (`metadata.google.internal`).
const METADATA_V4_2: [u8; 4] = [169, 254, 170, 2];

/// Classifies an IP address for egress purposes.
///
/// Mapped (`::ffff:0:0/96`) and NAT64 (`64:ff9b::/96`) forms are
/// classified by their embedded IPv4 address so tunneling tricks cannot
/// disguise a private target.
#[must_use]
pub fn classify_ip(ip: IpAddr) -> Classification {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => {
            // ::ffff:0:0/96 — unwrap mapped IPv4 before anything else.
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_v4(v4);
            }
            // 64:ff9b::/96 — NAT64 prefix embeds the IPv4 target in the
            // final four octets.
            if v6.segments()[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
                let o = v6.octets();
                return classify_v4(Ipv4Addr::new(o[12], o[13], o[14], o[15]));
            }
            if v6 == Ipv6Addr::LOCALHOST {
                return Classification::Loopback;
            }
            if v6.is_unspecified() {
                return Classification::Unspecified;
            }
            // Instance metadata over ULA must be checked before the
            // generic fc00::/7 bucket swallows it.
            if v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x254] {
                return Classification::MetadataService;
            }
            let seg = v6.segments();
            if (0xfe80..=0xfebf).contains(&seg[0]) {
                return Classification::LinkLocal;
            }
            if (seg[0] & 0xfe00) == 0xfc00 {
                return Classification::Private;
            }
            if (seg[0] & 0xff00) == 0xff00 {
                return Classification::Multicast;
            }
            Classification::Global
        }
    }
}

fn classify_v4(v4: Ipv4Addr) -> Classification {
    let o = v4.octets();
    if o == METADATA_V4_1 || o == METADATA_V4_2 {
        return Classification::MetadataService;
    }
    if o[0] == 127 {
        return Classification::Loopback;
    }
    if o[0] == 169 && o[1] == 254 {
        return Classification::LinkLocal;
    }
    // 0.0.0.0/8 ("this network") is treated wholesale as unspecified.
    if o[0] == 0 {
        return Classification::Unspecified;
    }
    if
    // 10.0.0.0/8
    o[0] == 10
        // 172.16.0.0/12
        || (o[0] == 172 && (0x10..=0x1f).contains(&o[1]))
        // 192.168.0.0/16
        || (o[0] == 192 && o[1] == 168)
        // 100.64.0.0/10 carrier-grade NAT (Tailscale et al.)
        || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
    {
        return Classification::Private;
    }
    // 192.0.0.0/24 (IETF protocol assignments) and 198.18.0.0/15
    // (benchmarking): conservative "private" treatment keeps them out of
    // default-deny bypasses while remaining honest about scope.
    if o[0] == 192 && o[1] == 0 && o[2] == 0 {
        return Classification::Private;
    }
    if o[0] == 198 && (o[1] == 18 || o[1] == 19) {
        return Classification::Private;
    }
    if o[0] & 0xf0 == 0xe0 {
        return Classification::Multicast;
    }
    Classification::Global
}

/// Whether connections to `c` may proceed.
///
/// [`Classification::Global`] always passes; every other class passes
/// only when `allow_private_destinations` is enabled — except
/// [`Classification::MetadataService`], which is **never** allowed. This
/// is a hard invariant, not a configurable default.
#[must_use]
pub const fn is_egress_allowed(c: Classification, allow_private_destinations: bool) -> bool {
    match c {
        Classification::Global => true,
        Classification::MetadataService => false,
        _ => allow_private_destinations,
    }
}

/// Gate applied to destinations before connection.
///
/// Literal IPs are decided immediately; hostnames receive a provisional
/// pass and **must** be re-checked against resolved addresses via
/// [`EgressGuard::recheck_resolved`] after DNS (see the module-level
/// rebinding contract).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressGuard {
    allow_private: bool,
}

impl EgressGuard {
    /// Creates a guard; `allow_private` permits loopback/link-local/
    /// private/multicast/unspecified classes but never metadata
    /// endpoints.
    #[must_use]
    pub const fn new(allow_private: bool) -> Self {
        Self { allow_private }
    }

    /// Checks a destination host string.
    ///
    /// Accepts bare IPv4/IPv6 literals and bracketed IPv6 (`[::1]`,
    /// matching [`crate::canonical::CanonicalUrl::host`] output).
    ///
    /// # Errors
    /// Returns [`HttpPolicyError::PrivateDestination`] when the host is
    /// an IP literal whose class is not allowed. Hostnames are returned
    /// as [`Classification::Global`] — a provisional pass pending the
    /// mandatory post-DNS re-check.
    pub fn check_host(&self, host: &str) -> Result<Classification, HttpPolicyError> {
        let unbracketed = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        match unbracketed.parse::<IpAddr>() {
            Ok(ip) => {
                let class = classify_ip(ip);
                self.ensure_allowed(class)?;
                Ok(class)
            }
            Err(_) => Ok(Classification::Global),
        }
    }

    /// Re-checks every address a resolver produced for a destination.
    /// Must be called by transport after DNS and before connecting.
    ///
    /// # Errors
    /// Returns [`HttpPolicyError::PrivateDestination`] naming the class
    /// of the first disallowed address. An empty slice passes vacuously;
    /// treating empty resolution as fatal is the transport's job.
    pub fn recheck_resolved(&self, ips: &[IpAddr]) -> Result<(), HttpPolicyError> {
        for ip in ips {
            self.ensure_allowed(classify_ip(*ip))?;
        }
        Ok(())
    }

    fn ensure_allowed(&self, class: Classification) -> Result<(), HttpPolicyError> {
        if is_egress_allowed(class, self.allow_private) {
            Ok(())
        } else {
            Err(HttpPolicyError::PrivateDestination(class))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> Classification {
        classify_ip(s.parse().expect("valid ip"))
    }

    #[test]
    fn ipv4_classification_table() {
        let table = [
            ("0.0.0.0", Classification::Unspecified),
            ("0.255.255.255", Classification::Unspecified),
            ("1.0.0.0", Classification::Global),
            ("8.8.8.8", Classification::Global),
            ("10.0.0.0", Classification::Private),
            ("10.255.255.255", Classification::Private),
            ("11.0.0.1", Classification::Global),
            ("100.63.255.255", Classification::Global),
            ("100.64.0.0", Classification::Private),
            ("100.100.100.100", Classification::Private),
            ("100.127.255.255", Classification::Private),
            ("100.128.0.0", Classification::Global),
            ("127.0.0.0", Classification::Loopback),
            ("127.0.0.1", Classification::Loopback),
            ("127.255.255.255", Classification::Loopback),
            ("128.0.0.1", Classification::Global),
            ("169.253.255.255", Classification::Global),
            ("169.254.0.0", Classification::LinkLocal),
            ("169.254.0.1", Classification::LinkLocal),
            ("169.254.169.253", Classification::LinkLocal),
            ("169.254.169.254", Classification::MetadataService),
            ("169.254.170.2", Classification::MetadataService),
            ("169.254.255.255", Classification::LinkLocal),
            ("169.255.0.1", Classification::Global),
            ("172.15.255.255", Classification::Global),
            ("172.16.0.0", Classification::Private),
            ("172.31.255.255", Classification::Private),
            ("172.32.0.0", Classification::Global),
            ("191.255.255.255", Classification::Global),
            ("192.0.0.0", Classification::Private),
            ("192.0.0.255", Classification::Private),
            ("192.0.1.0", Classification::Global),
            ("192.167.255.255", Classification::Global),
            ("192.168.0.0", Classification::Private),
            ("192.168.255.255", Classification::Private),
            ("192.169.0.0", Classification::Global),
            ("198.17.255.255", Classification::Global),
            ("198.18.0.0", Classification::Private),
            ("198.19.255.255", Classification::Private),
            ("198.20.0.0", Classification::Global),
            ("223.255.255.255", Classification::Global),
            ("224.0.0.1", Classification::Multicast),
            ("239.255.255.255", Classification::Multicast),
            ("240.0.0.1", Classification::Global),
            ("255.255.255.255", Classification::Global),
        ];
        for (ip_str, expected) in table {
            assert_eq!(c(ip_str), expected, "misclassified {ip_str}");
        }
    }

    #[test]
    fn ipv6_classification_table() {
        let table = [
            ("::", Classification::Unspecified),
            ("::1", Classification::Loopback),
            ("fe80::1", Classification::LinkLocal),
            ("febf:ffff::1", Classification::LinkLocal),
            ("fec0::1", Classification::Global), // deprecated site-local: not enumerated
            ("fc00::1", Classification::Private),
            ("fd00::1", Classification::Private),
            ("fdff::1", Classification::Private),
            ("fd00:ec2::254", Classification::MetadataService),
            ("fd01:ec2::254", Classification::Private), // only the exact ULA is metadata
            ("ff02::1", Classification::Multicast),
            ("2001:db8::1", Classification::Global),
            ("2606:4700::1111", Classification::Global),
        ];
        for (ip_str, expected) in table {
            assert_eq!(c(ip_str), expected, "misclassified {ip_str}");
        }
    }

    #[test]
    fn tunneled_forms_are_unwrapped_before_classification() {
        assert_eq!(c("::ffff:127.0.0.1"), Classification::Loopback);
        assert_eq!(c("::ffff:10.0.0.5"), Classification::Private);
        assert_eq!(c("::ffff:169.254.169.254"), Classification::MetadataService);
        assert_eq!(c("::ffff:8.8.8.8"), Classification::Global);
        assert_eq!(c("::ffff:172.16.9.9"), Classification::Private);

        assert_eq!(c("64:ff9b::7f00:1"), Classification::Loopback);
        assert_eq!(c("64:ff9b::a00:1"), Classification::Private); // 10.0.0.1
        assert_eq!(c("64:ff9b::808:808"), Classification::Global); // 8.8.8.8
    }

    #[test]
    fn display_names_are_stable() {
        assert_eq!(
            Classification::MetadataService.to_string(),
            "metadata-service"
        );
        assert_eq!(Classification::LinkLocal.to_string(), "link-local");
    }

    #[test]
    fn metadata_service_is_never_allowed_even_with_private_enabled() {
        for class in [
            Classification::Loopback,
            Classification::LinkLocal,
            Classification::Private,
            Classification::Multicast,
            Classification::Unspecified,
            Classification::MetadataService,
        ] {
            assert!(!is_egress_allowed(class, false));
        }
        assert!(!is_egress_allowed(Classification::MetadataService, true));
        for class in [
            Classification::Loopback,
            Classification::LinkLocal,
            Classification::Private,
            Classification::Multicast,
            Classification::Unspecified,
        ] {
            assert!(is_egress_allowed(class, true));
        }
        assert!(is_egress_allowed(Classification::Global, false));
        assert!(is_egress_allowed(Classification::Global, true));
    }

    #[test]
    fn guard_decides_literals_and_provisionally_passes_hostnames() {
        let strict = EgressGuard::new(false);
        assert_eq!(
            strict.check_host("8.8.8.8").unwrap(),
            Classification::Global
        );
        assert_eq!(
            strict.check_host("[2606:4700::1111]").unwrap(),
            Classification::Global
        );
        let err = strict.check_host("127.0.0.1").unwrap_err();
        assert!(matches!(
            err,
            HttpPolicyError::PrivateDestination(Classification::Loopback)
        ));
        let err = strict.check_host("[::1]").unwrap_err();
        assert!(matches!(
            err,
            HttpPolicyError::PrivateDestination(Classification::Loopback)
        ));

        // Hostnames get a provisional pass regardless of mode; DNS
        // re-check remains mandatory.
        assert_eq!(
            strict.check_host("api.example.com").unwrap(),
            Classification::Global
        );

        let lax = EgressGuard::new(true);
        assert!(lax.check_host("192.168.1.10").is_ok());
        let err = lax.check_host("169.254.169.254").unwrap_err();
        assert!(matches!(
            err,
            HttpPolicyError::PrivateDestination(Classification::MetadataService)
        ));
    }

    #[test]
    fn guard_rechecks_resolved_addresses_for_rebinding_defense() {
        let strict = EgressGuard::new(false);
        assert!(strict
            .recheck_resolved(&["8.8.8.8".parse().unwrap(), "1.1.1.1".parse().unwrap()])
            .is_ok());
        // Classic rebinding payload: public name resolving to loopback.
        let err = strict
            .recheck_resolved(&["203.0.113.9".parse().unwrap(), "127.0.0.1".parse().unwrap()])
            .unwrap_err();
        assert!(matches!(
            err,
            HttpPolicyError::PrivateDestination(Classification::Loopback)
        ));

        let lax = EgressGuard::new(true);
        assert!(lax.recheck_resolved(&["10.1.2.3".parse().unwrap()]).is_ok());
        let err = lax
            .recheck_resolved(&["fd00:ec2::254".parse().unwrap()])
            .unwrap_err();
        assert!(matches!(
            err,
            HttpPolicyError::PrivateDestination(Classification::MetadataService)
        ));

        // Empty resolution passes vacuously; transport owns that policy.
        assert!(strict.recheck_resolved(&[]).is_ok());
    }
}
