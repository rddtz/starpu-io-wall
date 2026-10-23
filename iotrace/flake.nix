{
  description = "iotrace: eBPF block-I/O tracer, static build";

  # Same nixpkgs as star-fletcher/flake.lock, to share the store on PCAD.
  inputs.nixpkgs.url = "github:nixos/nixpkgs/714a5f8c4ead6b31148d829288440ed033ccc041";

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      s = pkgs.pkgsStatic;
      # Unwrapped clang for -target bpf: no cc-wrapper hardening flags.
      bpfClang = "${pkgs.llvmPackages.clang-unwrapped}/bin/clang"
        + " -I${s.libbpf}/include -I${pkgs.linuxHeaders}/include";
    in {
      # vmlinux.h is not committed, and the build sandbox has no
      # /sys/kernel/btf. Generate it first, then build with a path: ref so
      # the untracked file is part of the source:
      #   nix shell nixpkgs#bpftools -c make BPFTOOL=bpftool vmlinux.h
      #   nix build path:.#iotrace-static
      packages.${system} = {
        iotrace-static = s.stdenv.mkDerivation {
          pname = "iotrace";
          version = "0.1";
          src = ./.;

          nativeBuildInputs = [ s.buildPackages.pkg-config pkgs.bpftools ];
          buildInputs = [ s.libbpf s.elfutils s.zlib ];

          buildPhase = ''
            test -f vmlinux.h || { echo "vmlinux.h missing, see flake.nix"; exit 1; }
            rm -f iotrace iotrace.bpf.o iotrace.skel.h
            make iotrace \
              CC="$CC" \
              CLANG="${bpfClang}" \
              BPFTOOL=bpftool \
              LIBBPF_CFLAGS="$($PKG_CONFIG --cflags libbpf)" \
              LIBBPF_LIBS="-static $($PKG_CONFIG --static --libs libbpf)"
          '';

          installPhase = ''
            install -Dm755 iotrace $out/bin/iotrace
          '';
        };
        default = self.packages.${system}.iotrace-static;
      };
    };
}
