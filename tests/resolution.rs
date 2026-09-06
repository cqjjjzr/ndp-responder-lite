mod support;
use std::time::Duration;
use support::*;

#[test]
fn each_request_is_answered_immediately_without_downstream_interfaces() {
    let mut w = World::new(config());
    w.interfaces.truncate(1);
    w.refresh();
    for (mac, source) in [(A, "fe80::a"), (C, "2001:db8:1::c"), (A, "fe80::a")] {
        assert_tx(
            &w.receive("up", &Wire::ns(mac, source, target())),
            &[("up", Wire::na(UP, "fe80::1", mac, source, target(), 0x40))],
        );
    }
    assert_eq!(w.engine.queued_count(), 0);
    assert!(w.tick(1000).is_empty());
    assert!(w.tick(3000).is_empty());
}

#[test]
fn unicast_nud_without_slla_is_answered_only_at_our_mac() {
    let mut w = World::new(config());
    let mut request = Wire::ns(A, "fe80::a", target());
    request.destination = target();
    request.destination_mac = C;
    request.options.clear();
    assert!(w.receive("up", &request).is_empty());
    request.destination_mac = UP;
    assert_tx(
        &w.receive("up", &request),
        &[("up", Wire::na(UP, "fe80::1", A, "fe80::a", target(), 0x40))],
    );
}

#[test]
fn unrelated_interfaces_addresses_advertisements_and_own_frames_are_ignored() {
    let mut w = World::new(config());
    for name in ["down", "missing"] {
        assert!(
            w.receive(name, &Wire::ns(A, "fe80::a", target()))
                .is_empty()
        );
    }
    for target in [ip("2001:db8:1::a"), ip("fe80::99"), ip("2001:db8:2::1")] {
        assert!(w.receive("up", &Wire::ns(A, "fe80::a", target)).is_empty());
    }
    for mac in [UP, DOWN] {
        assert!(
            w.receive("up", &Wire::ns(mac, "fe80::a", target()))
                .is_empty()
        );
    }
    let reply = Wire::na(A, "fe80::a", UP, "fe80::1", target(), 0x40);
    assert!(w.receive("up", &reply).is_empty());
    assert_eq!(w.receive("up", &Wire::ns(A, "fe80::a", target())).len(), 1);
}

#[test]
fn disjoint_prefixes_and_interfaces_select_the_correct_response() {
    let mut c = config();
    let mut second = c.responder[0].clone();
    second.prefix = "2001:db8:1::200:0/112".parse().unwrap();
    c.responder.push(second);
    let mut third = c.responder[0].clone();
    third.interface = "down".into();
    c.responder.push(third);
    let mut w = World::new(c);
    for t in [
        target(),
        ip("2001:db8:1::200:0"),
        ip("2001:db8:1::200:ffff"),
    ] {
        assert_tx(
            &w.receive("up", &Wire::ns(A, "fe80::a", t)),
            &[("up", Wire::na(UP, "fe80::1", A, "fe80::a", t, 0x40))],
        );
    }
    assert_tx(
        &w.receive("down", &Wire::ns(A, "fe80::a", target())),
        &[(
            "down",
            Wire::na(DOWN, "fe80::2", A, "fe80::a", target(), 0x40),
        )],
    );
}

#[test]
fn submillisecond_traffic_cannot_starve_rate_refill() {
    let mut c = config();
    c.limits.burst = 1;
    c.limits.packets_per_second = 1000;
    let mut w = World::new(c);
    let request = Wire::ns(A, "fe80::a", target());
    assert_eq!(w.receive("up", &request).len(), 1);
    let mut accepted = 0;
    for micros in (100..=10_000).step_by(100) {
        w.at(Duration::from_micros(micros));
        accepted += w.receive("up", &request).len();
    }
    assert_eq!(accepted, 10);
}

#[test]
fn interface_refresh_preserves_rate_limits_and_queued_replies() {
    let mut c = config();
    c.limits.burst = 1;
    c.limits.packets_per_second = 1;
    let mut w = World::new(c);
    let request = Wire::ns(A, "fe80::a", target());
    let tx = w.receive("up", &request).pop().unwrap();
    w.engine.record_send_failure(tx, true, w.now);
    w.interfaces[1].index += 1;
    w.interfaces.reverse();
    w.refresh();
    assert!(w.receive("up", &request).is_empty());
    assert_eq!(w.engine.queued_count(), 1);
    assert_eq!(w.tick(1000).len(), 1);
}

#[test]
fn full_rate_range_and_long_deadlines_do_not_overflow() {
    let mut c = config();
    c.limits.packets_per_second = u32::MAX;
    c.limits.burst = u32::MAX;
    c.limits.reply_timeout_ms = u64::MAX;
    let mut w = World::new(c);
    w.at(Duration::MAX - Duration::from_millis(1));
    let tx = w
        .receive("up", &Wire::ns(A, "fe80::a", target()))
        .pop()
        .unwrap();
    w.engine.record_send_failure(tx, true, w.now);
    assert!(w.engine.process_timer_tick(Duration::MAX).is_empty());
    assert_eq!(w.engine.queued_count(), 0);
}

proptest::proptest! {
    #[test]
    fn request_floods_and_send_failures_stay_within_queue_and_packet_budgets(
        sequence in proptest::collection::vec((proptest::num::u16::ANY, proptest::bool::ANY, 0u64..2000),1..100)) {
        let mut c=config(); c.limits.max_queued=4;
        c.limits.packets_per_second=10; c.limits.burst=10;
        let mut w=World::new(c); let mut sent=0usize;
        for (suffix,dad,elapsed) in sequence {
            w.at(w.now+Duration::from_millis(elapsed));
            let t=std::net::Ipv6Addr::from((u128::from(target()) & !0xffff) | u128::from(suffix));
            let output=w.receive("up",&Wire::ns(A,if dad {"::"} else {"fe80::a"},t));
            let output: Vec<_> = output.into_iter().chain(w.engine.process_timer_tick(w.now)).collect();
            for tx in output {
                let wire=Wire::read(&tx.frame);
                sent+=1;
                proptest::prop_assert_eq!(&tx.interface,"up");
                proptest::prop_assert_eq!(wire.source_mac,UP);
                proptest::prop_assert_eq!(wire.kind,136);
                proptest::prop_assert!(sent <= 10 + (w.now.as_millis()/100) as usize);
                w.engine.record_send_failure(tx, true, w.now);
            }
            proptest::prop_assert!(w.engine.queued_count() <= 4);
        }
        w.at(w.now+Duration::from_secs(4));
        proptest::prop_assert!(w.engine.process_timer_tick(w.now).is_empty());
        proptest::prop_assert_eq!(w.engine.queued_count(),0);
    }
}
