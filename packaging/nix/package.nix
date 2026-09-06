{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "ndp-responder-lite";
  version = (builtins.fromTOML (builtins.readFile ../../Cargo.toml)).package.version;
  src = lib.fileset.toSource {
    root = ../../.;
    fileset = lib.fileset.unions [
      ../../Cargo.toml ../../Cargo.lock ../../src ../../README.adoc ../../LICENSE
      (lib.fileset.fileFilter (file: file.hasExt "rs") ../../tests)
    ];
  };
  cargoLock.lockFile = ../../Cargo.lock;
  meta = {
    description = "Linux static IPv6 neighbor discovery responder";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "ndp-responder-lite";
  };
}
