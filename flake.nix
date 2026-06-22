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

        # Reproducible, patched emp stack (emp-tool + emp-ot + emp-ag2pc) built into
        # /nix/store. Replaces tools/bootstrap-emp.sh (which cloned into ./.deps).
        # Pins match the bootstrap script's commit set; the prg-alignment patch is
        # applied here so cross-mode and assert-enabled builds are correct.
        # Built with a fixed -march (x86-64-v3 + AES/PCLMUL) instead of -march=native
        # so the derivation is reproducible; the header-only AG2PC hot path is still
        # recompiled with the consumer's own flags when it includes these headers.
        empTool = pkgs.fetchFromGitHub {
          owner = "emp-toolkit"; repo = "emp-tool";
          rev = "22e3387dcdf99a7f13b0f5505b4b8d515d4cde3a";
          sha256 = "1wlphrb55z40ry9j5jj336skdrvxximmj9zdjvq1rqsv4mb34rc4";
        };
        empOt = pkgs.fetchFromGitHub {
          owner = "emp-toolkit"; repo = "emp-ot";
          rev = "95719775bf18082701d0f544c697b1246a3cb3e4";
          sha256 = "1q7k2wbw6s59axhbmfma8byqv38h8cvamgiw4jwcd3mknha8sh6y";
        };
        empAg2pc = pkgs.fetchFromGitHub {
          owner = "emp-toolkit"; repo = "emp-ag2pc";
          rev = "546d5e442e084958d5b5c9ca85c83b91aa3d9cc9";
          sha256 = "14whakbbfb4ph7mgahxlnzvsh66qr4w98z8rpkw36czdkg7yk7kk";
        };
        # The current emp-tool dropped the legacy Bristol circuit files, but
        # protocol/circuit_gen loads the standard sha-256.txt. Pull it from the last
        # emp-tool commit that shipped it.
        sha256Txt = pkgs.fetchurl {
          url = "https://raw.githubusercontent.com/emp-toolkit/emp-tool/11093a7d2160e7e7a4dcae3ffd9e6935bf2b8c1c/emp-tool/circuits/files/bristol_format/sha-256.txt";
          sha256 = "1qlg30ff6k6228hjp456vci4pn72ic4xqsh8nyma2q7p905xiriv";
        };

        emp = shellStdenv.mkDerivation {
          pname = "emp-shachain2pc";
          version = "ag2pc-546d5e4";
          dontUnpack = true;
          dontConfigure = true;
          dontInstall = true;
          nativeBuildInputs = [ pkgs.cmake pkgs.ninja pkgs.git pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
          buildPhase = ''
            runHook preBuild
            cp -r ${empTool} emp-tool
            cp -r ${empOt} emp-ot
            cp -r ${empAg2pc} emp-ag2pc
            chmod -R u+w emp-tool emp-ot emp-ag2pc
            ( cd emp-ag2pc && patch -p1 < ${./patches/emp-ag2pc-546d5e4-align-prg-random-data.patch} )

            flags="-O3 -march=x86-64-v3 -maes -mpclmul"
            for pkg in emp-tool emp-ot emp-ag2pc; do
              cmake -S "$pkg" -B "build-$pkg" -GNinja \
                -DCMAKE_BUILD_TYPE=Release \
                -DCMAKE_CXX_FLAGS="$flags" \
                -DCMAKE_INSTALL_PREFIX="$out" \
                -DCMAKE_PREFIX_PATH="$out" \
                -DCMAKE_INSTALL_LIBDIR=lib \
                -DEMP_TOOL_NATIVE_ARCH=OFF \
                -DEMP_TOOL_BUILD_TESTS=OFF -DEMP_TOOL_BUILD_BENCHMARKS=OFF \
                -DEMP_OT_BUILD_TESTS=OFF \
                -DEMP_AG2PC_BUILD_TESTS=OFF -DEMP_AG2PC_BUILD_EXAMPLES=OFF \
                -DEMP_AG2PC_BUILD_BENCHES=OFF
              cmake --build "build-$pkg" -j''${NIX_BUILD_CORES:-4}
              cmake --install "build-$pkg"
            done

            # emp-ag2pc is header-only; its install does not copy headers under this
            # prefix layout, so copy them explicitly.
            cp -r emp-ag2pc/emp-ag2pc "$out/include/"
            install -Dm644 ${sha256Txt} \
              "$out/include/emp-tool/circuits/files/bristol_format/sha-256.txt"
            runHook postBuild
          '';
        };
      in {
        packages.emp = emp;

        devShells.default = (pkgs.mkShell.override { stdenv = shellStdenv; }) {
          packages = with pkgs; [
            cmake
            ninja
            gnumake
            git
            openssl
            protobuf
            pkg-config
            python3
            cargo
            clippy
            rustc
            rustfmt
            shellStdenv.cc
          ];
          shellHook = ''
            export CC='${ccBin}/cc'
            export CXX='${ccBin}/c++'
            export OPENSSL_ROOT_DIR='${opensslDev}'
            export OPENSSL_INCLUDE_DIR='${opensslDev}/include'
            export OPENSSL_CRYPTO_LIBRARY='${opensslLib}/lib/libcrypto.so'
            # emp is built reproducibly by nix in /nix/store. EMP_PREFIX points at
            # it; the Makefile and both the C++ and Rust SHA-256 gadget paths read
            # EMP_PREFIX directly, so no .deps checkout/symlink is involved.
            export EMP_PREFIX='${emp}'
          '';
        };
      });
}
