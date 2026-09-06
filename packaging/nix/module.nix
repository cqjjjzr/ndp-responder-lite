flake: { config, lib, pkgs, ... }:
let
  cfg = config.services.ndp-responder-lite;
  format = pkgs.formats.toml { };
  configuration = format.generate "ndp-responder-lite.toml" cfg.settings;
in {
  options.services.ndp-responder-lite = {
    enable = lib.mkEnableOption "Linux static IPv6 neighbor discovery responder";
    package = lib.mkOption {
      type = lib.types.package;
      default = flake.packages.${pkgs.stdenv.hostPlatform.system}.ndp-responder-lite;
      description = "ndp-responder-lite package to run.";
    };
    settings = lib.mkOption {
      type = format.type;
      default = { };
      description = "Configuration written to ndp-responder-lite.toml.";
    };
    enableForwarding = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Enable kernel IPv6 forwarding.";
    };
  };
  config = lib.mkIf cfg.enable {
    boot.kernel.sysctl = lib.mkIf cfg.enableForwarding {
      "net.ipv6.conf.all.forwarding" = lib.mkDefault 1;
    };
    systemd.services.ndp-responder-lite = {
      description = "Linux static IPv6 neighbor discovery responder";
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];
      serviceConfig = {
        ExecStartPre = "${lib.getExe cfg.package} --config ${configuration} --check";
        ExecStart = "${lib.getExe cfg.package} --config ${configuration}";
        Restart = "on-failure";
        RestartSec = "2s";
        DynamicUser = true;
        AmbientCapabilities = [ "CAP_NET_RAW" ];
        CapabilityBoundingSet = [ "CAP_NET_RAW" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [ "AF_PACKET" "AF_INET6" "AF_UNIX" ];
        RestrictRealtime = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        UMask = "0077";
      };
    };
  };
}
