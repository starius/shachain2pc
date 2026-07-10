{
  description = "shachain2pc: maliciously-secure two-party shachain";

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

        # Reproducible emp stack (emp-tool + emp-ot + emp-ag2pc) built into
        # /nix/store. Replaces cpp/tools/bootstrap-emp.sh.
        # Built with a fixed -march (x86-64-v3 + AES/PCLMUL) instead of -march=native
        # so the derivation is reproducible; the header-only AG2PC hot path is still
        # recompiled with the consumer's own flags when it includes these headers.
        empTool = pkgs.fetchFromGitHub {
          owner = "emp-toolkit"; repo = "emp-tool";
          rev = "2ea73a31c54091bd15979ff884e24fa77c3f9673";
          hash = "sha256-A6Z8GpJsRqvJvVLBiHdTbO5XaRW8Xkm36TuelNrTKd8=";
        };
        empOt = pkgs.fetchFromGitHub {
          owner = "emp-toolkit"; repo = "emp-ot";
          rev = "39b207ec320001c0901c62819bf083194026b6a9";
          hash = "sha256-5eVTaG0KDSQLu+4/X4gCMguAT+piNLdzzncY8CU6C2M=";
        };
        empAg2pc = pkgs.fetchFromGitHub {
          owner = "emp-toolkit"; repo = "emp-ag2pc";
          rev = "a245ca0f67abaf2d48c711e3c050ce961e60ad29";
          hash = "sha256-SuyZmtjeqOmLtJaZnpv6S6nuCLa/ZAi5U/p91JU7XZU=";
        };
        # The current emp-tool dropped the legacy Bristol circuit files, but
        # both implementations load the standard sha-256.txt. Pull it from the
        # last emp-tool commit that shipped it.
        sha256Txt = pkgs.fetchurl {
          url = "https://raw.githubusercontent.com/emp-toolkit/emp-tool/11093a7d2160e7e7a4dcae3ffd9e6935bf2b8c1c/emp-tool/circuits/files/bristol_format/sha-256.txt";
          sha256 = "1qlg30ff6k6228hjp456vci4pn72ic4xqsh8nyma2q7p905xiriv";
        };

        emp = shellStdenv.mkDerivation {
          pname = "emp-shachain2pc";
          version = "ag2pc-a245ca0";
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
            # tikv-jemalloc-sys runs autoconf probes with -Werror. Nix
            # hardening enables _FORTIFY_SOURCE, and glibc warns if those
            # probes compile at -O0, so keep C build scripts optimized.
            export CFLAGS='-O2'
            export OPENSSL_ROOT_DIR='${opensslDev}'
            export OPENSSL_INCLUDE_DIR='${opensslDev}/include'
            export OPENSSL_CRYPTO_LIBRARY='${opensslLib}/lib/libcrypto.so'
            # emp is built reproducibly by nix in /nix/store. EMP_PREFIX points at
            # it; the C++ Makefile and Rust SHA-256 gadget path read
            # EMP_PREFIX directly, so no .deps checkout/symlink is involved.
            export EMP_PREFIX='${emp}'
          '';
        };
      });
}
