{
  description = "Linux static IPv6 neighbor discovery responder";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          ndp-responder-lite = pkgs.callPackage ./packaging/nix/package.nix { };
          default = self.packages.${system}.ndp-responder-lite;
        });
      overlays.default = final: prev: {
        ndp-responder-lite = final.callPackage ./packaging/nix/package.nix { };
      };
      nixosModules.default = import ./packaging/nix/module.nix self;
      checks = forAllSystems (system: {
        package = self.packages.${system}.ndp-responder-lite;
        module = (nixpkgs.lib.nixosSystem {
          inherit system;
          modules = [
            self.nixosModules.default
            ({ pkgs, ... }: {
              system.stateVersion = "25.11";
              services.ndp-responder-lite = {
                enable = true;
                settings.responder = [{
                  prefix = "2001:db8:1::100:0/112";
                  interface = "eth0";
                }];
              };
            })
          ];
        }).config.systemd.units."ndp-responder-lite.service".unit;
      });
      devShells = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.mkShell {
            packages = with pkgs; [ cargo rustc rustfmt clippy rust-analyzer pkg-config just iproute2 iputils iptables util-linux procps coreutils tcpdump ];
          };
        });
    };
}
