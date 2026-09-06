#[path = "network/capture.rs"]
mod capture;
#[path = "network/harness.rs"]
mod harness;
mod support;

use harness::{Network, ROUTED, TARGET, UPSTREAM, pause, run_case, wait_for};
use std::{fs, path::Path};
use support::{Wire, ip, repair};
use xshell::{Shell, cmd};

fn solicitation(n: &Network, node: &str, target: &str, dad: bool) -> Wire {
    Wire::ns(
        n.mac(node),
        if dad {
            "::"
        } else if node == "b" {
            TARGET
        } else {
            UPSTREAM
        },
        ip(target),
    )
}

fn nd(frame: &[u8], kind: u8, target: &str) -> bool {
    frame.len() >= 78
        && frame[12..14] == [0x86, 0xdd]
        && frame[20] == 58
        && frame[54] == kind
        && frame[62..78] == ip(target).octets()
}

fn dad_failed(n: &Network, node: &str, address: &str) -> bool {
    n.address(node, address)
        .is_some_and(|a| a["dadfailed"] == true)
}

macro_rules! network_test {
    ($name:ident, $body:expr) => {
        #[test]
        #[ignore = "requires root and Linux network tools; use just test-network"]
        fn $name() {
            run_case(stringify!($name), "", $body);
        }
    };
}

fn lla_options(n: &Network, dad: bool) {
    let target = "2001:db8:1::100:ad";
    let mut requester = n.raw("a");
    let mut peer = n.raw("b");
    let mut request = solicitation(n, "a", target, dad);
    let original = request.options.clone();
    request.options.extend([2, 2]);
    request.options.extend([255; 14]);
    request.options.extend(original);
    requester.send(&request.bytes());
    let reply = requester.expect(|p| nd(p, 136, target));
    assert_eq!(reply[58], if dad { 0 } else { 0x40 });
    assert!(peer.collect(300, |p| nd(p, 135, target)).is_none());
}
network_test!(lla_options_resolution, |n| lla_options(n, false));
network_test!(lla_options_dad, |n| lla_options(n, true));

fn address_refresh(n: &Network, dad: bool) {
    let target = "2001:db8:1::100:ab";
    let mut requester = n.raw("a");
    n.run(
        "responder",
        cmd!(n.sh, "ip -6 addr add 2001:db8:1::100:ac/128 dev eth2 nodad"),
    );
    pause(1200);
    assert_eq!(
        fs::read_to_string(n.artifacts.join("daemon.log"))
            .unwrap()
            .matches("listening")
            .count(),
        1
    );
    requester.send(&solicitation(n, "a", target, dad).bytes());
    requester.expect(|p| nd(p, 136, target));
}
network_test!(address_refresh_resolution, |n| address_refresh(n, false));
network_test!(address_refresh_dad, |n| address_refresh(n, true));

network_test!(cold_resolution, |n| {
    for (node, dev) in [("a", "eth1"), ("responder", "eth1"), ("responder", "eth2")] {
        n.run(node, cmd!(n.sh, "ip -6 neigh flush dev {dev}"));
    }
    let mut capture = n.raw("a");
    n.ping("a", TARGET);
    let na = capture.expect(|p| nd(p, 136, TARGET));
    assert_eq!(na[58], 64);
    assert_eq!(na[6..12], n.mac("responder"));
    let reply =
        capture.expect(|p| p.len() > 54 && p[54] == 129 && p[22..38] == ip(TARGET).octets());
    assert_eq!(reply[21], 63, "kernel forwarding must decrement hop limit");
});

fn malformed(n: &Network, fault: &str) {
    let target = "2001:db8:1::100:99";
    let mut sender = n.raw("a");
    let mut downstream = n.raw("b");
    let request = solicitation(n, "a", target, false).bytes();
    let mut bad = request.clone();
    let (offset, value) = match fault {
        "hop_limit" => (21, 254),
        "code" => (55, 1),
        "checksum" => (56, request[56] ^ 1),
        "option_length" => (79, 0),
        "fragment" => (20, 44),
        _ => unreachable!(),
    };
    bad[offset] = value;
    if fault == "fragment" {
        bad.splice(54..54, [58, 0, 0, 0, 0, 0, 0, 1]);
        let size = (bad.len() - 54) as u16;
        bad[18..20].copy_from_slice(&size.to_be_bytes());
    } else if fault != "checksum" {
        repair(&mut bad);
    }
    sender.send(&bad);
    assert!(sender.collect(300, |p| nd(p, 136, target)).is_none());
    sender.send(&request);
    sender.expect(|p| nd(p, 136, target));
    assert!(downstream.collect(300, |p| nd(p, 135, target)).is_none());
}
network_test!(malformed_hop_limit, |n| malformed(n, "hop_limit"));
network_test!(malformed_code, |n| malformed(n, "code"));
network_test!(malformed_checksum, |n| malformed(n, "checksum"));
network_test!(malformed_option_length, |n| malformed(n, "option_length"));
network_test!(malformed_fragment, |n| malformed(n, "fragment"));

network_test!(absent_host_is_claimed_without_discovery, |n| {
    let target = "2001:db8:1::100:99";
    let mut sender = n.raw("a");
    let mut downstream = n.raw("b");
    sender.send(&solicitation(n, "a", target, false).bytes());
    sender.expect(|p| nd(p, 136, target));
    assert!(downstream.collect(300, |p| nd(p, 135, target)).is_none());
});

network_test!(hop_by_hop_nd_reaches_engine, |n| {
    let mut sender = n.raw("a");
    let mut request = solicitation(n, "a", TARGET, false).bytes();
    request[20] = 0;
    request.splice(54..54, [58, 0, 0, 0, 0, 0, 0, 0]);
    let size = (request.len() - 54) as u16;
    request[18..20].copy_from_slice(&size.to_be_bytes());
    sender.send(&request);
    sender.expect(|p| nd(p, 136, TARGET));
});

network_test!(unique_downstream_dad, |n| {
    let address = "2001:db8:1::100:77";
    n.run("b", cmd!(n.sh, "ip -6 addr add {address}/128 dev eth1"));
    wait_for(|| {
        n.address("b", address)
            .is_some_and(|a| a["tentative"] != true)
    });
    assert!(!dad_failed(n, "b", address));
});

network_test!(simultaneous_dad, |n| {
    let address = "2001:db8:1::100:88";
    for node in ["a", "b"] {
        n.run(node, cmd!(n.sh, "ip -6 addr add {address}/128 dev eth1"));
    }
    wait_for(|| dad_failed(n, "a", address));
    wait_for(|| {
        n.address("b", address)
            .is_some_and(|a| a["tentative"] != true)
    });
    assert!(!dad_failed(n, "b", address));
});

network_test!(dad_nonce_and_scope, |n| {
    let mut sender = n.raw("a");
    let mut downstream = n.raw("b");
    for i in [1, 2] {
        let address = format!("2001:db8:1::100:{}", 90 + i);
        let mut request = solicitation(n, "a", &address, true);
        request.options.extend([14, 1]);
        request.options.extend([i; 6]);
        sender.send(&request.bytes());
        let reply = sender.expect(|p| nd(p, 136, &address));
        assert_eq!(reply[58], 0);
        assert_eq!(reply[38..54], ip("ff02::1").octets());
        assert!(downstream.collect(300, |p| nd(p, 135, &address)).is_none());
    }
    sender.send(&solicitation(n, "a", "fe80::999", true).bytes());
    assert!(sender.collect(300, |p| nd(p, 136, "fe80::999")).is_none());
});

network_test!(unicast_nud, |n| {
    let mut sender = n.raw("a");
    let mut request = solicitation(n, "a", TARGET, false);
    request.destination = ip(TARGET);
    request.destination_mac = n.mac("responder");
    request.options.clear();
    sender.send(&request.bytes());
    sender.expect(|p| nd(p, 136, TARGET));
});

network_test!(interface_recovery, |n| {
    n.run("responder", cmd!(n.sh, "ip link set eth1 down"));
    pause(1200);
    n.run("responder", cmd!(n.sh, "ip link set eth1 up"));
    wait_for(|| {
        n.json("responder", cmd!(n.sh, "ip -j -6 addr show dev eth1"))[0]["addr_info"]
            .as_array()
            .unwrap()
            .iter()
            .any(|a| a["scope"] == "link" && a["tentative"] != true)
    });
    n.run(
        "responder",
        cmd!(n.sh, "ip -6 addr add 2001:db8:1::1/64 dev eth1 nodad"),
    );
    pause(1200);
    n.run("a", cmd!(n.sh, "ip -6 neigh flush dev eth1"));
    n.ping("a", TARGET);
});

network_test!(path_mtu, |n| {
    n.run("responder", cmd!(n.sh, "ip link set eth2 mtu 1280"));
    let mut capture = n.raw("a");
    n.output(
        "a",
        cmd!(n.sh, "ping -6 -n -c 1 -W 1 -M do -s 1400 {TARGET}"),
    );
    let frame = capture.expect(|p| p.len() >= 62 && p[20] == 58 && p[54] == 2);
    assert_eq!(u32::from_be_bytes(frame[58..62].try_into().unwrap()), 1280);
});

network_test!(static_dad, |n| {
    let address = "2001:db8:1:0:1::99";
    n.run("a", cmd!(n.sh, "ip -6 addr add {address}/128 dev eth1"));
    wait_for(|| dad_failed(n, "a", address));
});

network_test!(duplicate_dad, |n| {
    let address = "2001:db8:1::100:66";
    n.run(
        "b",
        cmd!(n.sh, "ip -6 addr add {address}/128 dev eth1 nodad"),
    );
    n.run("a", cmd!(n.sh, "ip -6 addr add {address}/128 dev eth1"));
    wait_for(|| dad_failed(n, "a", address));
});

network_test!(routing_b_to_a, |n| n.ping("b", UPSTREAM));
network_test!(routing_d_to_a, |n| n.ping("d", UPSTREAM));
network_test!(routing_a_to_e, |n| n.ping("a", ROUTED));
network_test!(routing_d_to_e, |n| n.ping("d", ROUTED));

network_test!(snooping_router_port, |n| {
    n.run(
        "large",
        cmd!(n.sh, "ip -6 addr add fe80::111/64 dev br0 nodad"),
    );
    n.run(
        "large",
        cmd!(
            n.sh,
            "ip link set br0 type bridge mcast_query_response_interval 100"
        ),
    );
    n.run("large", cmd!(n.sh, "ip link set br0 type bridge mcast_snooping 1 mcast_querier 1 mcast_query_response_interval 100"));
    n.run(
        "large",
        cmd!(
            n.sh,
            "bridge mdb add dev br0 port eth2 grp ff02::1:ff00:2 permanent"
        ),
    );
    pause(2000);
    let mut sender = n.raw("a");
    let request = solicitation(n, "a", TARGET, false).bytes();
    sender.send(&request);
    assert!(sender.collect(300, |p| nd(p, 136, TARGET)).is_none());
    n.run(
        "large",
        cmd!(n.sh, "ip link set eth3 type bridge_slave mcast_router 2"),
    );
    sender.send(&request);
    sender.expect(|p| nd(p, 136, TARGET));
    n.ping("a", TARGET);
    n.run("a", cmd!(n.sh, "ip -6 addr add {TARGET}/128 dev eth1"));
    wait_for(|| dad_failed(n, "a", TARGET));
});

fn link_scope(n: &Network, dad: bool) {
    let target = "2001:db8:1::100:fa";
    let mut downstream = n.raw("b");
    let mut upstream = n.raw("a");
    downstream.send(&solicitation(n, "b", target, dad).bytes());
    assert!(upstream.collect(300, |p| nd(p, 135, target)).is_none());
    upstream.send(&solicitation(n, "a", target, dad).bytes());
    upstream.expect(|p| nd(p, 136, target));
    assert!(downstream.collect(300, |p| nd(p, 135, target)).is_none());
}
network_test!(downstream_resolution_stays_on_link, |n| link_scope(
    n, false
));
network_test!(downstream_dad_stays_on_link, |n| link_scope(n, true));

network_test!(static_reply_needs_no_downstream_link, |n| {
    n.run("responder", cmd!(n.sh, "ip link set eth3 down"));
    pause(1200);
    let mut requester = n.raw("a");
    requester.send(&solicitation(n, "a", ROUTED, false).bytes());
    requester.expect(|p| nd(p, 136, ROUTED));
});

network_test!(multicast_without_promiscuous_mode, |n| {
    let links = n.json("responder", cmd!(n.sh, "ip -j -d link show dev eth1"));
    assert_eq!(links[0]["promiscuity"], 0);
    assert!(links[0]["allmulti"].as_u64().unwrap() > 0);
    n.ping("a", TARGET);
});

#[test]
#[ignore = "requires root and Linux network tools; use just test-network"]
fn nptv6_static_external_pool() {
    run_case(
        "nptv6_static_external_pool",
        "\n[[responder]]\nprefix = '2001:db8:2:0:cf47::/112'\ninterface = 'eth1'\n",
        |n| {
            let internal = "fd00:2::2";
            let external = "2001:db8:2:0:cf47::2";
            let upstream = "2001:db8:2::a";
            n.run(
                "a",
                cmd!(n.sh, "ip -6 addr add {upstream}/64 dev eth1 nodad"),
            );
            n.run(
                "b",
                cmd!(n.sh, "ip -6 addr add {internal}/64 dev eth1 nodad"),
            );
            n.run(
                "responder",
                cmd!(n.sh, "ip -6 route add fd00:2::/64 dev eth2"),
            );
            n.run(
                "responder",
                cmd!(n.sh, "ip -6 route add 2001:db8:2::/64 dev eth1"),
            );
            n.run(
                "responder",
                cmd!(
                    n.sh,
                    "ip6tables -t raw -A PREROUTING -i eth1 -d {external} -j CT --notrack"
                ),
            );
            n.run(
                "responder",
                cmd!(
                    n.sh,
                    "ip6tables -t raw -A PREROUTING -i eth2 -s {internal} -j CT --notrack"
                ),
            );
            n.run("responder", cmd!(n.sh, "ip6tables -t mangle -A PREROUTING -i eth1 -d {external} -j DNPT --src-pfx 2001:db8:2::/64 --dst-pfx fd00:2::/64"));
            n.run("responder", cmd!(n.sh, "ip6tables -t mangle -A POSTROUTING -o eth1 -s {internal} -j SNPT --src-pfx fd00:2::/64 --dst-pfx 2001:db8:2::/64"));
            let mut capture = n.raw("a");
            n.run(
                "a",
                cmd!(n.sh, "ping -6 -n -I {upstream} -c 2 -W 3 {external}"),
            );
            capture.expect(|p| nd(p, 136, external));
            capture.expect(|p| p.len() > 54 && p[54] == 129 && p[22..38] == ip(external).octets());
            n.run(
                "b",
                cmd!(n.sh, "ping -6 -n -I {internal} -c 2 -W 3 {upstream}"),
            );
        },
    );
}

network_test!(outgoing_frames_are_filtered, |n| {
    let target = "2001:db8:1::100:fe";
    let local = n.raw("responder");
    let mut upstream = n.raw("a");
    let request = solicitation(n, "a", target, false).bytes();
    local.send(&request);
    assert!(upstream.collect(300, |p| nd(p, 136, target)).is_none());
    upstream.send(&request);
    upstream.expect(|p| nd(p, 136, target));
});

network_test!(discard_route_bounds_downstream_discovery, |n| {
    let pool = "2001:db8:1::100:0/112";
    let absent = "2001:db8:1::100:99";
    n.run("responder", cmd!(n.sh, "ip -6 route del {pool} dev eth2"));
    n.run("responder", cmd!(n.sh, "ip -6 route add blackhole {pool}"));
    n.run(
        "responder",
        cmd!(n.sh, "ip -6 route add {TARGET}/128 dev eth2"),
    );
    let mut upstream = n.raw("a");
    let mut downstream = n.raw("b");
    upstream.send(&solicitation(n, "a", absent, false).bytes());
    upstream.expect(|p| nd(p, 136, absent));
    assert!(
        !n.output("a", cmd!(n.sh, "ping -6 -n -c 1 -W 1 {absent}"))
            .status
            .success()
    );
    assert!(downstream.collect(300, |p| nd(p, 135, absent)).is_none());
    let neighbors = n.json("responder", cmd!(n.sh, "ip -j -6 neigh show dev eth2"));
    assert!(
        neighbors
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["dst"] != absent)
    );
    n.run("responder", cmd!(n.sh, "ip -6 neigh flush dev eth2"));
    n.ping("a", TARGET);
    downstream.expect(|p| nd(p, 135, TARGET));
});

#[test]
#[ignore = "requires root and Linux network tools; use just test-network"]
fn cleanup_after_failure_and_sigterm() {
    let _serial = harness::SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let sh = Shell::new().unwrap();
    let baseline = cmd!(sh, "ip netns list").read().unwrap();
    let executable = std::env::current_exe().unwrap();
    let root = tempfile::Builder::new()
        .prefix("ndp-lifecycle-")
        .tempdir()
        .unwrap();
    for (fault, message) in [
        ("deploy", "injected deployment failure"),
        ("setup", "injected setup failure"),
        ("case", "injected test failure"),
        ("interrupt", "network test interrupted"),
    ] {
        let artifacts = root.path().join(fault);
        // Let the child finish its cleanup; a killing timeout bypasses destructors.
        let output = cmd!(
            sh,
            "{executable} --ignored --exact cold_resolution --nocapture"
        )
        .env("NDP_TEST_FAULT", fault)
        .env("NDP_TEST_ARTIFACTS", &artifacts)
        .ignore_status()
        .output()
        .unwrap();
        assert_eq!(output.status.code(), Some(101), "{fault}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(message),
            "{fault}: {output:?}"
        );
        let runs: Vec<_> = fs::read_dir(&artifacts)
            .unwrap()
            .map(|p| p.unwrap().path())
            .collect();
        assert_eq!(runs.len(), 1);
        let cleanup: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(runs[0].join("cleanup.json")).unwrap())
                .unwrap();
        assert_eq!(cleanup["complete"], true, "{cleanup}");
        for ns in cleanup["namespaces"].as_array().unwrap() {
            assert!(!Path::new("/run/netns").join(ns.as_str().unwrap()).exists());
        }
        let process = runs[0].join("process.json");
        assert_eq!(process.exists(), fault != "deploy");
        if process.exists() {
            let value: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(process).unwrap()).unwrap();
            assert!(
                !Path::new(&format!("/proc/{}", value["pid"])).exists(),
                "daemon survived cleanup"
            );
        }
        assert_eq!(cmd!(sh, "ip netns list").read().unwrap(), baseline);
    }
}
