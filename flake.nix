{
  description = "viaos: an immutable, Docker-first Linux for edge devices";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});

      # One OS per architecture. `debug` adds a root shell on the serial
      # console, for QEMU and bring-up; it is never what a fleet runs.
      mkViaos =
        {
          system,
          debug ? false,
          modules ? [ ],
        }:
        nixpkgs.lib.nixosSystem {
          inherit system;
          specialArgs = { inherit self; };
          modules = [
            ./nix/viaos.nix
            { viaos.debug = debug; }
          ]
          ++ modules;
        };
    in
    {
      packages = forAll (
        pkgs:
        let
          via =
            crate: bin: description:
            pkgs.callPackage ./nix/via.nix { inherit crate bin description; };
          via-console = pkgs.callPackage ./nix/web.nix { };
          via-server = (via "via-server" "via-server" "viaos control plane").override {
            web = via-console;
          };
        in
        {
          via-agent = via "via-agent" "via-agent" "viaos device agent";
          inherit via-console via-server;
          # Secure Boot signing shells out to sbsign, openssl and efitools.
          via = (via "via-cli" "via" "viaos operator tools: flash, release, ssh").override {
            # The official compose, from the same nixpkgs as the OS's.
            docker = pkgs.docker-client;
            runtimeInputs = with pkgs; [
              sbsigntool
              openssl
              efitools
            ];
          };
          default = self.packages.${pkgs.stdenv.hostPlatform.system}.via;

          # `docker load < result`, then run with VIA_PUBLIC_URL set and a
          # volume on /data. See docs/deploy.md.
          via-server-image = pkgs.dockerTools.buildLayeredImage {
            name = "via-server";
            tag = "latest";
            contents = [
              pkgs.coreutils
              pkgs.cacert
            ];
            extraCommands = "mkdir -p data tmp && chmod 1777 tmp";
            config = {
              Entrypoint = [ "${via-server}/bin/via-server" ];
              Env = [
                "VIA_DATA_DIR=/data"
                "VIA_LISTEN=0.0.0.0:8080"
              ];
              ExposedPorts."8080/tcp" = { };
              Volumes."/data" = { };
            };
          };
        }
      );

      nixosModules.via-server = import ./nix/server-module.nix { inherit self; };

      # `nix flake check`: the control plane's NixOS module, end to end.
      checks.x86_64-linux.via-server = import ./nix/server-test.nix {
        inherit self;
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
      };
      # viaos.toml's Wi-Fi, network, time and proxy settings on a booted system.
      checks.x86_64-linux.settings = import ./nix/settings-test.nix {
        inherit self;
        pkgs = nixpkgs.legacyPackages.x86_64-linux;
      };

      nixosConfigurations = {
        viaos-x86_64 = mkViaos { system = "x86_64-linux"; };
        viaos-x86_64-debug = mkViaos {
          system = "x86_64-linux";
          debug = true;
        };
        viaos-aarch64 = mkViaos { system = "aarch64-linux"; };
        # The x86_64 OS plus the NVIDIA driver: see nix/nvidia.nix.
        viaos-x86_64-nvidia = mkViaos {
          system = "x86_64-linux";
          modules = [ { viaos.nvidia.enable = true; } ];
        };
      };

      # `nix build .#image-x86_64` -> result/viaos_<version>.raw
      images = {
        x86_64 = self.nixosConfigurations.viaos-x86_64.config.system.build.image;
        x86_64-debug = self.nixosConfigurations.viaos-x86_64-debug.config.system.build.image;
        aarch64 = self.nixosConfigurations.viaos-aarch64.config.system.build.image;
        x86_64-nvidia = self.nixosConfigurations.viaos-x86_64-nvidia.config.system.build.image;
      };

      # `nix build .#updates.x86_64` -> the files a device updates itself from
      updates = {
        x86_64 = self.nixosConfigurations.viaos-x86_64.config.system.build.update;
        x86_64-debug = self.nixosConfigurations.viaos-x86_64-debug.config.system.build.update;
        aarch64 = self.nixosConfigurations.viaos-aarch64.config.system.build.update;
        x86_64-nvidia = self.nixosConfigurations.viaos-x86_64-nvidia.config.system.build.update;
      };

      devShells = forAll (pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            mtools
            qemu
          ];
        };
      });
    };
}
