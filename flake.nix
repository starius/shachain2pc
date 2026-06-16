{
  description = "shachain2pc: maliciously-secure two-party shachain (emp-ag2pc backend)";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;
        opensslDev = lib.getDev pkgs.openssl;
        opensslLib = lib.getLib pkgs.openssl;
        shellStdenv = if pkgs ? gcc14Stdenv then pkgs.gcc14Stdenv else pkgs.stdenv;
        ccBin = "${shellStdenv.cc}/bin";
      in {
        devShells.default = (pkgs.mkShell.override { stdenv = shellStdenv; }) {
          packages = with pkgs; [
            cmake
            ninja
            gnumake
            git
            openssl
            pkg-config
            python3
            shellStdenv.cc
          ];
          shellHook = ''
            export CC='${ccBin}/cc'
            export CXX='${ccBin}/c++'
            export OPENSSL_ROOT_DIR='${opensslDev}'
            export OPENSSL_INCLUDE_DIR='${opensslDev}/include'
            export OPENSSL_CRYPTO_LIBRARY='${opensslLib}/lib/libcrypto.so'
          '';
        };
      });
}
