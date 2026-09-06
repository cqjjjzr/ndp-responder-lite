use serde_json::Value;
use std::{
    cell::Cell,
    fs::{self, File},
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::PathBuf,
    process::{Child, Command, Output},
    sync::{
        Mutex, Once,
        atomic::{AtomicI32, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use xshell::{Shell, cmd};

use super::capture::Capture;

pub const TARGET: &str = "2001:db8:1::100:2";
pub const UPSTREAM: &str = "2001:db8:1::a";
pub const ROUTED: &str = "2001:db8:1:0:1::2";
const NODES: &[&str] = &[
    "large",
    "small",
    "a",
    "c",
    "responder",
    "b",
    "d",
    "router",
    "e",
];
const LINKS: &[(&str, &str, &str, &str)] = &[
    ("large", "eth1", "a", "eth1"),
    ("large", "eth2", "c", "eth1"),
    ("large", "eth3", "responder", "eth1"),
    ("small", "eth1", "b", "eth1"),
    ("small", "eth2", "d", "eth1"),
    ("small", "eth3", "responder", "eth2"),
    ("responder", "eth3", "router", "eth1"),
    ("router", "eth2", "e", "eth1"),
];
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);
static SIGNALS: Once = Once::new();
// The cleanup audit compares the host namespace list, so serialize this test binary.
pub static SERIAL: Mutex<()> = Mutex::new(());

extern "C" fn interrupt(signal: libc::c_int) {
    INTERRUPTED.store(signal, Ordering::Relaxed);
}

pub fn check_interrupt() {
    assert_eq!(
        INTERRUPTED.load(Ordering::Relaxed),
        0,
        "network test interrupted"
    );
}

pub fn pause(millis: u64) {
    let end = Instant::now() + Duration::from_millis(millis);
    while Instant::now() < end {
        check_interrupt();
        thread::sleep(Duration::from_millis(20).min(end.saturating_duration_since(Instant::now())));
    }
}

pub fn wait_for(mut condition: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    while !condition() {
        assert!(Instant::now() < end, "condition timed out");
        pause(50);
    }
}

pub struct Network {
    pub sh: Shell,
    pub artifacts: PathBuf,
    temporary: TempDir,
    namespaces: Vec<String>,
    daemon: Option<Child>,
    capture_index: Cell<usize>,
}

impl Network {
    pub fn new(case: &str, extra_config: &str) -> Self {
        // SAFETY: geteuid has no arguments or memory requirements.
        assert_eq!(unsafe { libc::geteuid() }, 0, "use just test-network");
        SIGNALS.call_once(|| {
            for signal in [libc::SIGINT, libc::SIGTERM] {
                // SAFETY: the handler only stores into a lock-free atomic.
                assert_ne!(
                    unsafe { libc::signal(signal, interrupt as *const () as libc::sighandler_t) },
                    libc::SIG_ERR
                );
            }
        });
        check_interrupt();
        let temporary = tempfile::Builder::new()
            .prefix("ndptest-")
            .tempdir()
            .unwrap();
        let name = temporary.path().file_name().unwrap();
        let root = std::env::var_os("NDP_TEST_ARTIFACTS")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/artifacts"));
        let artifacts = root.join(format!("{}-{case}", name.to_string_lossy()));
        fs::create_dir_all(&artifacts).unwrap();
        eprintln!("artifacts: {}", artifacts.display());
        let mut n = Self {
            sh: Shell::new().unwrap(),
            artifacts,
            temporary,
            namespaces: Vec::new(),
            daemon: None,
            capture_index: Cell::new(0),
        };
        for node in NODES {
            let ns = n.ns(node);
            n.namespaces.push(ns.clone());
            cmd!(n.sh, "timeout -k 1 30 ip netns add {ns}")
                .quiet()
                .run()
                .unwrap();
            n.run(node, cmd!(n.sh, "ip link set lo up"));
        }
        for (i, &(left, left_dev, right, right_dev)) in LINKS.iter().enumerate() {
            let peer = format!("peer{i}");
            let right_ns = n.ns(right);
            n.run(
                left,
                cmd!(n.sh, "ip link add {left_dev} type veth peer name {peer}"),
            );
            n.run(left, cmd!(n.sh, "ip link set {peer} netns {right_ns}"));
            n.run(right, cmd!(n.sh, "ip link set {peer} name {right_dev}"));
            assert_ne!(fault(), "deploy", "injected deployment failure");
        }
        n.setup();
        n.start(extra_config);
        assert_ne!(fault(), "setup", "injected setup failure");
        n
    }

    pub fn ns(&self, node: &str) -> String {
        format!(
            "{}-{node}",
            self.temporary.path().file_name().unwrap().to_string_lossy()
        )
    }

    fn in_namespace(&self, node: &str, command: xshell::Cmd<'_>) -> xshell::Cmd<'_> {
        let command: Command = command.into();
        let args = std::iter::once(command.get_program()).chain(command.get_args());
        let ns = self.ns(node);
        cmd!(self.sh, "timeout -k 1 30 ip netns exec {ns} {args...}")
    }

    pub fn run(&self, node: &str, command: xshell::Cmd<'_>) -> String {
        check_interrupt();
        let output = self.in_namespace(node, command).read().unwrap();
        check_interrupt();
        output
    }

    pub fn output(&self, node: &str, command: xshell::Cmd<'_>) -> Output {
        check_interrupt();
        let output = self
            .in_namespace(node, command)
            .ignore_status()
            .output()
            .unwrap();
        check_interrupt();
        output
    }

    pub fn json(&self, node: &str, command: xshell::Cmd<'_>) -> Value {
        serde_json::from_str(&self.run(node, command)).unwrap()
    }

    pub fn address(&self, node: &str, address: &str) -> Option<Value> {
        self.json(node, cmd!(self.sh, "ip -j -6 addr"))
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|link| link["addr_info"].as_array().unwrap())
            .find(|a| a["local"] == address)
            .cloned()
    }

    pub fn mac(&self, node: &str) -> [u8; 6] {
        let links = self.json(node, cmd!(self.sh, "ip -j link show dev eth1"));
        let bytes: Vec<_> = links[0]["address"]
            .as_str()
            .unwrap()
            .split(':')
            .map(|v| u8::from_str_radix(v, 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    pub fn ping(&self, source: &str, target: &str) {
        self.run(
            source,
            cmd!(self.sh, "ping -6 -n -c 2 -i 0.2 -W 3 {target}"),
        );
    }

    pub fn raw(&self, node: &str) -> Capture {
        let old = File::open("/proc/thread-self/ns/net").unwrap();
        let new = File::open(format!("/run/netns/{}", self.ns(node))).unwrap();
        // SAFETY: both files own valid network namespace descriptors; only this test thread moves.
        assert_eq!(
            unsafe { libc::setns(new.as_raw_fd(), libc::CLONE_NEWNET) },
            0
        );
        let socket = Capture::socket();
        // Restore before handling socket errors so unwinding always happens in the original namespace.
        assert_eq!(
            unsafe { libc::setns(old.as_raw_fd(), libc::CLONE_NEWNET) },
            0
        );
        let index = self.capture_index.get() + 1;
        self.capture_index.set(index);
        Capture::new(
            socket.unwrap(),
            &self.artifacts.join(format!("{index}-{node}.pcap")),
        )
    }

    pub fn assert_running(&mut self) {
        assert!(
            self.daemon.as_mut().unwrap().try_wait().unwrap().is_none(),
            "daemon exited"
        );
    }

    fn setup(&self) {
        for node in NODES {
            self.run(node, cmd!(self.sh, "sysctl -qw net.ipv6.conf.all.disable_ipv6=0 net.ipv6.conf.default.disable_ipv6=0 net.ipv6.conf.all.forwarding=0 net.ipv6.conf.default.accept_ra=0 net.ipv6.conf.all.accept_ra=0"));
            for link in self
                .json(node, cmd!(self.sh, "ip -j link"))
                .as_array()
                .unwrap()
            {
                let dev = link["ifname"].as_str().unwrap();
                if !dev.starts_with("eth") {
                    continue;
                }
                self.run(node, cmd!(self.sh, "ip link set {dev} up"));
                self.run(node, cmd!(self.sh, "ip -6 addr flush dev {dev}"));
                self.run(node, cmd!(self.sh, "sysctl -qw net.ipv6.conf.{dev}.accept_ra=0 net.ipv6.conf.{dev}.autoconf=0 net.ipv6.conf.{dev}.dad_transmits=1 net.ipv6.conf.{dev}.accept_dad=1 net.ipv6.conf.{dev}.enhanced_dad=1"));
            }
        }
        for node in ["large", "small"] {
            self.run(
                node,
                cmd!(self.sh, "ip link add br0 type bridge mcast_snooping 0"),
            );
            self.run(node, cmd!(self.sh, "ip link set br0 up"));
            for dev in ["eth1", "eth2", "eth3"] {
                self.run(node, cmd!(self.sh, "ip link set {dev} master br0"));
            }
        }
        for (node, dev, addresses) in [
            ("a", "eth1", ["fe80::a/64", "2001:db8:1::a/64"]),
            ("c", "eth1", ["fe80::c/64", "2001:db8:1::c/64"]),
            ("b", "eth1", ["fe80::b/64", "2001:db8:1::100:2/112"]),
            ("d", "eth1", ["fe80::d/64", "2001:db8:1::100:4/112"]),
            ("responder", "eth1", ["fe80::1/64", "2001:db8:1::1/64"]),
            ("responder", "eth2", ["fe80::2/64", "2001:db8:1::100:1/112"]),
            ("responder", "eth3", ["fe80::3/64", "fd00:ffff::1/64"]),
            ("router", "eth1", ["fe80::4/64", "fd00:ffff::2/64"]),
            ("router", "eth2", ["fe80::5/64", "2001:db8:1:0:1::1/80"]),
            ("e", "eth1", ["fe80::e/64", "2001:db8:1:0:1::2/80"]),
        ] {
            for address in addresses {
                self.run(
                    node,
                    cmd!(self.sh, "ip -6 addr add {address} dev {dev} nodad"),
                );
            }
        }
        for node in ["responder", "router"] {
            self.run(
                node,
                cmd!(self.sh, "sysctl -qw net.ipv6.conf.all.forwarding=1"),
            );
        }
        self.run(
            "responder",
            cmd!(
                self.sh,
                "ip -6 route replace 2001:db8:1:0:1::/80 via fd00:ffff::2 dev eth3"
            ),
        );
        for (node, gateway) in [
            ("b", "fe80::2"),
            ("d", "fe80::2"),
            ("e", "fe80::5"),
            ("router", "fe80::3"),
        ] {
            self.run(
                node,
                cmd!(
                    self.sh,
                    "ip -6 route replace default via {gateway} dev eth1"
                ),
            );
        }
        for node in ["a", "c"] {
            assert!(
                self.run(node, cmd!(self.sh, "ip -6 route show default"))
                    .is_empty()
            );
        }
    }

    fn start(&mut self, extra: &str) {
        let config = format!(
            "[[responder]]\nprefix = '2001:db8:1::100:0/112'\ninterface = 'eth1'\n\n[[responder]]\nprefix = '2001:db8:1:0:1::/80'\ninterface = 'eth1'\n{extra}"
        );
        let executable = self.temporary.path().join("daemon");
        let configuration = self.temporary.path().join("config.toml");
        let binary = std::env::var_os("NDP_TEST_BINARY")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_ndp-responder-lite")));
        fs::copy(&binary, &executable).unwrap();
        fs::set_permissions(self.temporary.path(), fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(&configuration, &config).unwrap();
        fs::set_permissions(&configuration, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(self.artifacts.join("config.toml"), config).unwrap();
        let log = File::create(self.artifacts.join("daemon.log")).unwrap();
        let ns = self.ns("responder");
        let mut command: Command = cmd!(self.sh, "ip netns exec {ns} setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=+net_raw --ambient-caps=+net_raw --bounding-set=-all,+net_raw --no-new-privs {executable} --config {configuration}").into();
        self.daemon = Some(
            command
                .env("RUST_LOG", "info")
                .stdout(log.try_clone().unwrap())
                .stderr(log)
                .spawn()
                .unwrap(),
        );
        let pid = self.daemon.as_ref().unwrap().id();
        fs::write(
            self.artifacts.join("process.json"),
            serde_json::json!({"pid": pid, "binary": binary}).to_string(),
        )
        .unwrap();
        wait_for(|| {
            self.assert_running();
            fs::read_to_string(self.artifacts.join("daemon.log"))
                .unwrap()
                .matches("listening")
                .count()
                == 1
        });
        let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        let field = |key: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(key))
                .unwrap()
                .trim()
        };
        assert_eq!(
            field("Uid:").split_whitespace().collect::<Vec<_>>(),
            ["65534"; 4]
        );
        assert_eq!(u64::from_str_radix(field("CapEff:"), 16).unwrap(), 1 << 13);
        assert_eq!(u64::from_str_radix(field("CapBnd:"), 16).unwrap(), 1 << 13);
        assert_eq!(field("NoNewPrivs:"), "1");
        fs::write(self.artifacts.join("status.txt"), status).unwrap();
    }
}

impl Drop for Network {
    fn drop(&mut self) {
        let mut errors = Vec::new();
        if let Some(mut daemon) = self.daemon.take() {
            if matches!(daemon.try_wait(), Ok(None)) {
                // SAFETY: this is our unreaped child; its PID cannot have been reused.
                unsafe {
                    libc::kill(daemon.id() as i32, libc::SIGTERM);
                }
            }
            let end = Instant::now() + Duration::from_secs(5);
            loop {
                match daemon.try_wait() {
                    Ok(Some(status)) => {
                        let _ = fs::write(self.artifacts.join("exit.txt"), status.to_string());
                        break;
                    }
                    Ok(None) if Instant::now() < end => thread::sleep(Duration::from_millis(20)),
                    _ => {
                        if let Err(e) = daemon.kill().and_then(|()| daemon.wait().map(|_| ())) {
                            errors.push(e.to_string());
                        }
                        break;
                    }
                }
            }
        }
        for ns in self.namespaces.iter().rev() {
            if !PathBuf::from("/run/netns").join(ns).exists() {
                continue;
            }
            if let Err(e) = cmd!(self.sh, "timeout -k 1 30 ip netns del {ns}")
                .quiet()
                .run()
            {
                errors.push(e.to_string());
            }
        }
        let manifest = serde_json::json!({"complete": errors.is_empty(), "errors": errors, "namespaces": self.namespaces});
        if let Err(e) = fs::write(self.artifacts.join("cleanup.json"), manifest.to_string()) {
            errors.push(e.to_string());
        }
        // Give artifacts back to the invoking user, including logs from failed tests.
        if let (Ok(uid), Ok(gid)) = (std::env::var("SUDO_UID"), std::env::var("SUDO_GID")) {
            let owner = format!("{uid}:{gid}");
            let artifacts = &self.artifacts;
            if let Err(e) = cmd!(self.sh, "timeout -k 1 30 chown -R {owner} {artifacts}")
                .quiet()
                .run()
            {
                errors.push(e.to_string());
            }
        }
        if !errors.is_empty() {
            if thread::panicking() {
                eprintln!("cleanup failed: {errors:?}");
            } else {
                panic!("cleanup failed: {errors:?}");
            }
        }
    }
}

pub fn fault() -> String {
    std::env::var("NDP_TEST_FAULT").unwrap_or_default()
}

pub fn run_case(name: &str, extra: &str, test: impl FnOnce(&Network)) {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut network = Network::new(name, extra);
    assert_ne!(fault(), "case", "injected test failure");
    if fault() == "interrupt" {
        // SAFETY: signal targets the current process, whose handler is installed above.
        unsafe {
            libc::raise(libc::SIGTERM);
        }
        check_interrupt();
    }
    test(&network);
    network.assert_running();
}
