{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "ndp-responder-lite";
  version = (builtins.fromTOML (builtins.readFile ../../Cargo.toml)).package.version;
  src = lib.fileset.toSource {
    root = ../../.;
    fileset = lib.fileset.unions [
      ../../Cargo.toml ../../Cargo.lock ../../src ../../README.adoc ../../LICENSE
      ../../THIRD_PARTY_NOTICES.md
      (lib.fileset.fileFilter (file: file.hasExt "rs") ../../tests)
    ];
  };
  cargoLock.lockFile = ../../Cargo.lock;
  postInstall = ''
    install -Dm644 -t "$out/share/doc/ndp-responder-lite" LICENSE THIRD_PARTY_NOTICES.md
  '';
  meta = {
    description = "Linux static IPv6 neighbor discovery responder";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "ndp-responder-lite";
  };
}
