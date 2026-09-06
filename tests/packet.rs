mod support;
use ndp_responder_lite::packet;
use support::*;

#[test]
fn independent_wire_fixtures_parse_multicast_unicast_and_dad_solicitations() {
    let mut nud = Wire::ns(A, "fe80::a", target());
    nud.destination_mac = UP;
    nud.destination = target();
    nud.options.clear();
    let fixtures = [
        Wire::ns(A, "fe80::a", target()),
        Wire::ns(A, "::", target()),
        nud,
    ];
    for fixture in fixtures {
        let bytes = fixture.bytes();
        let parsed = packet::parse_solicitation_frame(&bytes).expect("valid fixture");
        assert_eq!(parsed.source, fixture.source);
        assert_eq!(parsed.destination, fixture.destination);
        assert_eq!(parsed.target, fixture.target);
        assert_eq!(parsed.source_mac, fixture.source_mac);
        assert_eq!(parsed.destination_mac, fixture.destination_mac);
    }
}

#[test]
fn encoder_matches_independent_wire_fields_and_checksum() {
    for (destination, mac, flags) in [
        ("fe80::a", A, 0x40),
        ("ff02::1", multicast(ip("ff02::1")), 0),
    ] {
        let expected = Wire::na(UP, "fe80::1", mac, destination, target(), flags);
        assert_eq!(
            Wire::read(&packet::build_neighbor_advertisement(
                UP,
                ip("fe80::1"),
                mac,
                ip(destination),
                target()
            )),
            expected
        );
    }
}

#[test]
fn malformed_fixed_fields_are_rejected_with_other_fields_valid() {
    let cases = [
        ("ethertype", 12, 0x08),
        ("ipv6 version", 14, 0x40),
        ("hop limit", 21, 254),
        ("icmp code", 55, 1),
        ("icmp type", 54, 134),
        ("multicast source MAC", 6, 3),
        ("multicast MAC mismatch", 5, 0x99),
        ("zero option length", 79, 0),
        ("oversized option", 79, 2),
        ("SLLA mismatch", 85, 0x99),
    ];
    for (label, offset, value) in cases {
        let mut bytes = Wire::ns(A, "fe80::a", target()).bytes();
        bytes[offset] = value;
        repair(&mut bytes);
        assert!(
            packet::parse_solicitation_frame(&bytes).is_none(),
            "{label}"
        );
    }
}

#[test]
fn invalid_address_and_option_combinations_are_rejected() {
    let base = Wire::ns(A, "fe80::a", target());
    let mut cases = Vec::new();
    let mut p = base.clone();
    p.source = ip("ff02::1");
    cases.push(("multicast source", p));
    let mut p = base.clone();
    p.source_mac = [0; 6];
    cases.push(("zero MAC", p));
    let mut p = base.clone();
    p.target = ip("::");
    cases.push(("unspecified target", p));
    let mut p = base.clone();
    p.target = ip("ff02::1");
    cases.push(("multicast target", p));
    let mut p = base.clone();
    p.source = ip("::");
    cases.push(("DAD SLLA", p));
    let mut p = base.clone();
    p.options.clear();
    cases.push(("multicast NS missing SLLA", p));
    let mut p = base.clone();
    p.destination = ip("ff02::2");
    p.destination_mac = multicast(p.destination);
    cases.push(("wrong group", p));
    let mut p = base.clone();
    p.destination = ip("::");
    p.destination_mac = UP;
    cases.push(("unspecified destination", p));
    let mut p = base;
    p.destination = ip("fe80::99");
    p.destination_mac = UP;
    cases.push(("unicast target mismatch", p));
    for (label, p) in cases {
        assert!(
            packet::parse_solicitation_frame(&p.bytes()).is_none(),
            "{label}"
        );
    }
}

#[test]
fn irrelevant_lla_options_are_ignored_in_any_order() {
    let mut nud = Wire::ns(A, "fe80::a", target());
    nud.destination_mac = UP;
    nud.destination = target();
    nud.options.clear();
    for original in [
        Wire::ns(A, "fe80::a", target()),
        Wire::ns(A, "::", target()),
        nud,
    ] {
        let irrelevant = 2;
        for size in [8, 16] {
            let mut option = vec![0xff; size];
            option[0] = irrelevant;
            option[1] = (size / 8) as u8;
            for first in [false, true] {
                let mut packet = original.clone();
                if first {
                    packet.options.splice(..0, option.clone());
                } else {
                    packet.options.extend_from_slice(&option);
                }
                packet.options.extend_from_slice(&option);
                assert!(
                    packet::parse_solicitation_frame(&packet.bytes()).is_some(),
                    "{packet:?}"
                );
            }
        }
    }
}

#[test]
fn irrelevant_options_still_require_valid_framing() {
    for mut packet in [
        Wire::ns(A, "fe80::a", target()),
        Wire::ns(C, "fe80::c", target()),
    ] {
        let irrelevant = 2;
        let original = packet.options.clone();
        for option in [
            vec![irrelevant],
            vec![irrelevant, 0, 0, 0, 0, 0, 0, 0],
            vec![irrelevant, 2, 0, 0, 0, 0, 0, 0],
        ] {
            packet.options = original.clone();
            packet.options.extend(option);
            assert!(packet::parse_solicitation_frame(&packet.bytes()).is_none());
        }
    }
}

#[test]
fn repeated_valid_lla_options_are_accepted() {
    for mut packet in [
        Wire::ns(A, "fe80::a", target()),
        Wire::ns(C, "fe80::c", target()),
    ] {
        packet.options.extend_from_within(..);
        assert!(packet::parse_solicitation_frame(&packet.bytes()).is_some());
        packet.options[15] ^= 1;
        assert!(packet::parse_solicitation_frame(&packet.bytes()).is_none());
    }
}

#[test]
fn checksum_payload_length_and_every_truncation_are_checked() {
    let valid = Wire::ns(A, "fe80::a", target()).bytes();
    for len in 0..valid.len() {
        assert!(
            packet::parse_solicitation_frame(&valid[..len]).is_none(),
            "length {len}"
        );
    }
    let mut corrupt = valid.clone();
    corrupt[56] ^= 1;
    assert!(packet::parse_solicitation_frame(&corrupt).is_none());
    let mut too_long = valid.clone();
    too_long[18..20].copy_from_slice(&65535u16.to_be_bytes());
    assert!(packet::parse_solicitation_frame(&too_long).is_none());
    let mut short = valid.clone();
    short[18..20].copy_from_slice(&23u16.to_be_bytes());
    assert!(packet::parse_solicitation_frame(&short).is_none());
    let mut padded = valid.clone();
    padded.extend_from_slice(&[0xff; 64]);
    assert!(packet::parse_solicitation_frame(&padded).is_some());
}

fn extended(original: &[u8], kinds: &[u8]) -> Vec<u8> {
    let mut frame = original[..54].to_vec();
    frame[20] = kinds[0];
    for (i, _) in kinds.iter().enumerate() {
        frame.extend_from_slice(&[kinds.get(i + 1).copied().unwrap_or(58), 0, 0, 0, 0, 0, 0, 0]);
    }
    frame.extend_from_slice(&original[54..]);
    let size = (frame.len() - 54) as u16;
    frame[18..20].copy_from_slice(&size.to_be_bytes());
    frame
}

#[test]
fn extension_limits_and_fragment_rejection_are_enforced() {
    let base = Wire::ns(A, "fe80::a", target()).bytes();
    for kinds in [vec![0], vec![60], vec![0, 60], vec![60; 8]] {
        assert!(
            packet::parse_solicitation_frame(&extended(&base, &kinds)).is_some(),
            "{kinds:?}"
        );
    }
    for kinds in [vec![44], vec![60, 44], vec![60, 0], vec![0, 0], vec![60; 9]] {
        assert!(
            packet::parse_solicitation_frame(&extended(&base, &kinds)).is_none(),
            "{kinds:?}"
        );
    }
    let mut invalid = extended(&base, &[0]);
    invalid[55] = 255;
    assert!(packet::parse_solicitation_frame(&invalid).is_none());
    let mut discard = extended(&base, &[60]);
    discard[56] = 0x80;
    assert!(packet::parse_solicitation_frame(&discard).is_none());
}

#[test]
fn ignored_reserved_fields_and_unknown_options_are_accepted() {
    let mut p = Wire::ns(A, "::", target());
    p.options = vec![253, 1, 1, 2, 3, 4, 5, 6];
    let mut bytes = p.bytes();
    bytes[58..62].copy_from_slice(&[1, 2, 3, 4]);
    repair(&mut bytes);
    assert!(packet::parse_solicitation_frame(&bytes).is_some());
}

proptest::proptest! {
    #[test]
    fn arbitrary_frames_are_total(bytes in proptest::collection::vec(proptest::num::u8::ANY,0..8192)) {
        if let Some(parsed)=packet::parse_solicitation_frame(&bytes) {
            proptest::prop_assert!(!parsed.target.is_multicast() && !parsed.target.is_unspecified());
            proptest::prop_assert_eq!(bytes[21],255);
        }
    }
    #[test]
    fn valid_unknown_options_and_one_field_corruption_reach_option_validation(
        kind in 3u8..=255, payload in proptest::collection::vec(proptest::num::u8::ANY,6..128)) {
        let size=(payload.len()+2).div_ceil(8)*8;
        let mut p=Wire::ns(A,"::",target()); p.options=vec![0;size]; p.options[0]=kind; p.options[1]=(size/8) as u8;
        p.options[2..2+payload.len()].copy_from_slice(&payload);
        let bytes=p.bytes(); proptest::prop_assert!(packet::parse_solicitation_frame(&bytes).is_some());
        p.options[1]=0; proptest::prop_assert!(packet::parse_solicitation_frame(&p.bytes()).is_none());
    }
    #[test]
    fn address_mapping_and_output_checksum_hold_for_all_target_suffixes(suffix in proptest::num::u32::ANY) {
        let t=std::net::Ipv6Addr::from(u128::from(target()) & !0xffff_ffff | u128::from(suffix));
        proptest::prop_assert_eq!(packet::compute_solicited_node_address(t),group(t));
        let bytes=packet::build_neighbor_advertisement(UP,ip("fe80::1"),A,ip("fe80::a"),t);
        proptest::prop_assert_eq!(Wire::read(&bytes),Wire::na(UP,"fe80::1",A,"fe80::a",t,0x40));
    }
}

#[test]
fn checksum_libraries_agree_on_odd_and_maximum_payloads() {
    for length in [24, 25, 32, 1500, 65534, 65535] {
        let mut wire = Wire::ns(A, "::", target());
        wire.options = vec![0xff; length - 24];
        let frame = wire.bytes();
        assert_eq!(
            packet::compute_icmpv6_checksum(wire.source, wire.destination, &frame[54..]),
            0
        );
        let mut corrupt = frame;
        corrupt[62] ^= 1;
        assert_ne!(
            packet::compute_icmpv6_checksum(wire.source, wire.destination, &corrupt[54..]),
            0
        );
    }
}

#[test]
fn advertisements_are_not_accepted_as_requests() {
    for flags in [0, 0x20, 0x40, 0x80, 0xe0] {
        let mut advertisement = answer();
        advertisement.flags = flags;
        assert!(packet::parse_solicitation_frame(&advertisement.bytes()).is_none());
    }
}
