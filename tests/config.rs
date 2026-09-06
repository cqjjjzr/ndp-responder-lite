mod support;
use ndp_responder_lite::config::Config;
use support::*;
const MINIMAL: &str = r#"
[[responder]]
prefix = "2001:db8:1::100:0/112"
interface = "up"
"#;

#[test]
fn minimal_configuration_has_documented_defaults() {
    let c = Config::parse_from_str(MINIMAL).unwrap();
    assert_eq!(c.interface_names(), vec!["up"]);
    let l = c.limits;
    assert_eq!(l.max_queued, 4096);
    assert_eq!((l.packets_per_second, l.burst), (200, 400));
    assert_eq!(l.reply_timeout_ms, 3000);
}

#[test]
fn parse_errors_cover_missing_fields_unknown_fields_and_types() {
    for (label, text) in [
        ("empty", String::new()),
        ("empty rules", "responder=[]".into()),
        (
            "missing prefix",
            MINIMAL.replace("prefix = \"2001:db8:1::100:0/112\"", ""),
        ),
        (
            "missing interface",
            MINIMAL.replace("interface = \"up\"", ""),
        ),
        ("unknown field", format!("{MINIMAL}\nrevers=true")),
        ("unknown mode", format!("{MINIMAL}\nmode=\"proeb\"")),
        ("wrong type", format!("{MINIMAL}\nreverse=1")),
        ("unknown limit", format!("{MINIMAL}\n[limits]\nmax_queud=1")),
        (
            "negative limit",
            format!("{MINIMAL}\n[limits]\nmax_queued=-1"),
        ),
        (
            "ipv4",
            MINIMAL.replace("2001:db8:1::100:0/112", "192.0.2.0/24"),
        ),
    ] {
        assert!(Config::parse_from_str(&text).is_err(), "{label}");
    }
}

#[test]
fn numeric_limits_accept_positive_values_without_policy_caps() {
    for (field, maximum) in [
        ("max_queued", i64::MAX as u64),
        ("packets_per_second", u64::from(u32::MAX)),
        ("burst", u64::from(u32::MAX)),
        ("reply_timeout_ms", i64::MAX as u64),
    ] {
        for value in [0, 1, maximum] {
            let parsed = Config::parse_from_str(&format!("{MINIMAL}\n[limits]\n{field}={value}"));
            assert_eq!(parsed.is_ok(), value != 0, "{field}={value}: {parsed:?}");
        }
    }
}

#[test]
fn rule_counts_have_no_policy_caps() {
    let mut c = config();
    let template = c.responder[0].clone();
    c.responder = (0..257)
        .map(|i| {
            let mut rule = template.clone();
            rule.prefix = format!("2001:db8:1::{i:x}:0/112").parse().unwrap();
            rule
        })
        .collect();
    assert!(c.validate().is_ok());
}

#[test]
fn broad_unicast_parent_is_accepted() {
    let mut c = config();
    c.responder[0].prefix = "4000::/2".parse().unwrap();
    assert!(c.validate().is_ok());
}

#[test]
fn invalid_interface_names_are_rejected_before_socket_setup() {
    for name in [
        "",
        ".",
        "..",
        "eth:0",
        "two names",
        "slash/name",
        "nul\0name",
        "0123456789abcdef",
    ] {
        let mut c = config();
        c.responder[0].interface = name.into();
        assert!(c.validate().is_err(), "{name:?}");
    }
}

#[test]
fn disjoint_rules_and_ula_addresses_are_accepted() {
    let text = MINIMAL.replace("2001:db8:1::", "fd00:1234::");
    assert!(Config::parse_from_str(&text).is_ok());
    let mut c = config();
    let mut other = c.responder[0].clone();
    other.prefix = "2001:db8:1:0:1::/80".parse().unwrap();
    c.responder.push(other);
    assert!(c.validate().is_ok());
    assert_eq!(c.interface_names(), vec!["up"]);
}

#[test]
fn programmatic_configuration_is_validated_at_engine_construction() {
    let mut invalid = config();
    invalid.limits.burst = 0;
    assert!(ndp_responder_lite::engine::ResponderEngine::new(invalid).is_err());
}

#[test]
fn invalid_prefixes_are_rejected() {
    for prefix in [
        "2001:db8:1::100:1/112",
        "fe00::/8",
        "ff00::/8",
        "::/3",
        "::1/128",
        "fe80::/128",
    ] {
        let mut c = config();
        c.responder[0].prefix = prefix.parse().unwrap();
        assert!(c.validate().is_err(), "{prefix}");
    }
}

#[test]
fn overlap_is_rejected_only_on_the_same_interface() {
    for prefix in ["2001:db8:1::100:0/112", "2001:db8:1::100:0/113"] {
        let mut c = config();
        let mut second = c.responder[0].clone();
        second.prefix = prefix.parse().unwrap();
        c.responder.push(second);
        assert!(c.validate().is_err());
    }
    let mut c = config();
    let mut second = c.responder[0].clone();
    second.interface = "side".into();
    c.responder.push(second);
    assert!(c.validate().is_ok());
    assert_eq!(c.interface_names(), vec!["side", "up"]);
}

#[test]
fn removed_options_are_rejected() {
    for option in [
        "mode = \"static\"",
        "mode = \"probe\"",
        "downstream = \"down\"",
        "upstream = \"up\"",
        "reverse = true",
        "on_link = \"2001:db8:1::/64\"",
        "autowire = true",
        "autovia = true",
    ] {
        assert!(Config::parse_from_str(&format!("{MINIMAL}\n{option}")).is_err());
    }
    assert!(Config::parse_from_str(&MINIMAL.replace("[[responder]]", "[[proxy]]")).is_err());
    for limit in [
        "max_pending",
        "max_waiters",
        "retransmit_ms",
        "attempts",
        "dad_window_ms",
    ] {
        assert!(Config::parse_from_str(&format!("{MINIMAL}\n[limits]\n{limit}=1")).is_err());
    }
}

#[test]
fn configuration_errors_preserve_diagnostics() {
    let error = Config::parse_from_str("[").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(error.get_ref().unwrap().is::<toml::de::Error>());
    assert!(error.to_string().contains("TOML parse error"));

    let error = Config::parse_from_str("responder = []").unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(error.to_string(), "configure at least one responder rule");
}
