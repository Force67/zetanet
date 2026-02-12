{
  description = "Development shell for building and testing Zetanet";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        lib = pkgs.lib;
      in
      {
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            gnumake
            premake5
            pkg-config
            openssl
            python3
          ] ++ lib.optionals stdenv.isLinux [
            gcc14
            mold
            gdb
            lldb
            clang-tools
          ] ++ lib.optionals stdenv.isDarwin [
            llvmPackages.clang
            lldb
            clang-tools
          ];

          shellHook = ''
            export ZETANET_NIX=1
            export CC="${if pkgs.stdenv.isLinux then "${pkgs.gcc14}/bin/gcc" else "${pkgs.llvmPackages.clang}/bin/clang"}"
            export CXX="${if pkgs.stdenv.isLinux then "${pkgs.gcc14}/bin/g++" else "${pkgs.llvmPackages.clang}/bin/clang++"}"

            ${lib.optionalString pkgs.stdenv.isLinux ''
              export LD="${pkgs.mold}/bin/mold"
              export LDFLAGS="-fuse-ld=mold''${LDFLAGS:+ $LDFLAGS}"
            ''}

            echo "Zetanet dev shell loaded"
            echo "Generate build files: premake5 gmake2"
            echo "Generate STL build files: premake5 --use-stl gmake2"
            echo "Build debug targets: make config=debug"
            echo "Build release targets: make config=release"
            echo "Build core library only: make config=debug zetanet"
            echo "Run samples (when fully linked): ./bin/SimpleServer_64 and ./bin/SimpleClient_64"
          '';
        };
      });
}
