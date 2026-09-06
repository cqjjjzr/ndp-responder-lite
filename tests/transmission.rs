mod support;
use std::time::Duration;
use support::*;

#[test]
fn transient_send_failure_retries_without_extending_expiry() {
    let mut w = World::new(config());
    let tx = w
        .receive("up", &Wire::ns(A, "fe80::a", target()))
        .pop()
        .unwrap();
    w.engine.record_send_failure(tx, true, w.now);
    assert_eq!(w.engine.stats.transmitted, 0);
    let tx = w.tick(50).pop().unwrap();
    assert_tx(
        std::slice::from_ref(&tx),
        &[("up", Wire::na(UP, "fe80::1", A, "fe80::a", target(), 0x40))],
    );
    w.engine
        .record_send_failure(tx, true, Duration::from_millis(3000));
    assert_eq!(w.engine.queued_count(), 0);
    assert_eq!(w.engine.stats.send_errors, 2);
    assert_eq!(w.engine.stats.queue_dropped, 1);
}

#[test]
fn permanent_failure_is_counted_and_success_counts_only_completed_sends() {
    let mut w = World::new(config());
    let tx = w
        .receive("up", &Wire::ns(A, "fe80::a", target()))
        .pop()
        .unwrap();
    w.engine.record_send_failure(tx, false, w.now);
    assert_eq!(w.engine.queued_count(), 0);
    assert_eq!(w.engine.stats.transmitted, 0);
    assert_eq!(w.engine.stats.send_errors, 1);
    w.engine.record_sent();
    assert_eq!(w.engine.stats.transmitted, 1);
}

#[test]
fn reply_queue_is_bounded_deduplicated_and_expires() {
    let mut c = config();
    c.limits.max_queued = 1;
    let mut w = World::new(c);
    let request = Wire::ns(A, "fe80::a", target());
    let tx = w.receive("up", &request).pop().unwrap();
    w.engine.record_send_failure(tx, true, w.now);
    assert!(w.receive("up", &request).is_empty());
    assert_eq!(w.engine.queued_count(), 1);
    assert_eq!(w.engine.stats.queue_dropped, 0);
    assert!(
        w.receive("up", &Wire::ns(C, "fe80::c", target()))
            .is_empty()
    );
    assert_eq!(w.engine.queued_count(), 1);
    assert_eq!(w.engine.stats.queue_dropped, 1);
    assert!(w.tick(3000).is_empty());
    assert_eq!(w.engine.queued_count(), 0);
}

#[test]
fn changed_egress_discards_queued_frames() {
    let mut w = World::new(config());
    let tx = w
        .receive("up", &Wire::ns(A, "fe80::a", target()))
        .pop()
        .unwrap();
    w.engine.record_send_failure(tx, true, w.now);
    w.interfaces[0].index += 1;
    w.refresh();
    assert_eq!(w.engine.queued_count(), 0);
    assert!(w.tick(50).is_empty());
}

#[test]
fn queued_reply_has_priority_over_new_requests_on_the_same_interface() {
    let mut c = config();
    c.limits.burst = 1;
    c.limits.packets_per_second = 1000;
    let mut w = World::new(c);
    let old = Wire::ns(A, "fe80::a", target());
    let tx = w.receive("up", &old).pop().unwrap();
    w.engine.record_send_failure(tx, true, w.now);
    w.at(Duration::from_millis(1));
    assert!(
        w.receive("up", &Wire::ns(C, "fe80::c", target()))
            .is_empty()
    );
    assert_tx(
        &w.tick(1),
        &[("up", Wire::na(UP, "fe80::1", A, "fe80::a", target(), 0x40))],
    );
    assert_tx(
        &w.tick(2),
        &[("up", Wire::na(UP, "fe80::1", C, "fe80::c", target(), 0x40))],
    );
}

#[test]
fn expired_queue_entry_cannot_suppress_a_fresh_request_before_tick() {
    let mut w = World::new(config());
    let request = Wire::ns(A, "fe80::a", target());
    let tx = w.receive("up", &request).pop().unwrap();
    w.engine.record_send_failure(tx, true, w.now);
    w.at(Duration::from_millis(3000));
    assert_tx(
        &w.receive("up", &request),
        &[("up", Wire::na(UP, "fe80::1", A, "fe80::a", target(), 0x40))],
    );
    assert!(w.tick(3000).is_empty());
    assert_eq!(w.engine.stats.queue_dropped, 1);
}

#[test]
fn losing_interface_cancels_queued_reply() {
    let mut w = World::new(config());
    let reply = w.receive("up", &Wire::ns(A, "::", target())).pop().unwrap();
    w.engine.record_send_failure(reply, true, w.now);
    w.interfaces.remove(0);
    w.refresh();
    assert_eq!(w.engine.queued_count(), 0);
    assert!(w.tick(50).is_empty());
}

#[test]
fn restored_interface_cannot_revive_a_stale_reply() {
    let mut w = World::new(config());
    let reply = w.receive("up", &Wire::ns(A, "::", target())).pop().unwrap();
    let interface = w.interfaces.remove(0);
    w.refresh();
    w.interfaces.push(interface);
    w.refresh();
    w.engine.record_send_failure(reply, true, w.now);
    assert_eq!(w.engine.queued_count(), 0);
}

#[test]
fn unrelated_interface_loss_does_not_cancel_reply() {
    let mut w = World::new(config());
    let reply = w.receive("up", &Wire::ns(A, "::", target())).pop().unwrap();
    w.engine.record_send_failure(reply, true, w.now);
    w.interfaces.pop();
    w.refresh();
    assert_eq!(w.tick(50).len(), 1);
}
