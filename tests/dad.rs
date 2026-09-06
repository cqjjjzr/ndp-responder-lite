mod support;
use support::*;

#[test]
fn whole_prefix_is_reserved_with_unsolicited_all_nodes_advertisements() {
    let mut w = World::new(config());
    w.interfaces.truncate(1);
    w.refresh();
    for t in [
        ip("2001:db8:1::100:0"),
        target(),
        ip("2001:db8:1::100:ffff"),
    ] {
        for mac in [A, C] {
            let mut request = Wire::ns(mac, "::", t);
            request.options = vec![14, 1, 1, 2, 3, 4, 5, 6];
            assert_tx(
                &w.receive("up", &request),
                &[(
                    "up",
                    Wire::na(UP, "fe80::1", multicast(ip("ff02::1")), "ff02::1", t, 0),
                )],
            );
        }
    }
    assert!(w.tick(1000).is_empty());
}

#[test]
fn dad_and_normal_resolution_have_independent_wire_semantics() {
    let mut w = World::new(config());
    for dad in [true, false, true] {
        let mut request = Wire::ns(A, if dad { "::" } else { "fe80::a" }, target());
        request
            .options
            .splice(..0, [2, 1, 255, 255, 255, 255, 255, 255]);
        let (mac, destination, flags) = if dad {
            (multicast(ip("ff02::1")), "ff02::1", 0)
        } else {
            (A, "fe80::a", 0x40)
        };
        assert_tx(
            &w.receive("up", &request),
            &[(
                "up",
                Wire::na(UP, "fe80::1", mac, destination, target(), flags),
            )],
        );
    }
}

#[test]
fn dad_outside_reservation_or_on_other_interfaces_is_ignored() {
    let mut w = World::new(config());
    assert!(w.receive("down", &Wire::ns(A, "::", target())).is_empty());
    for target in [
        ip("2001:db8:1::ff:ffff"),
        ip("2001:db8:1::101:0"),
        ip("fe80::99"),
    ] {
        assert!(w.receive("up", &Wire::ns(A, "::", target)).is_empty());
    }
}
