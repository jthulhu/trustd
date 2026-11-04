{
  description = "trustd";

  inputs = {
    crane.url = "github:ipetkov/crane";
    advisory-db = {
      url = "github:rustsec/advisory-db";
      flake = false;
    };
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs = {
        nixpkgs.follows = "nixpkgs";
      };
    };
  };

  outputs = { self, nixpkgs, flake-parts, crane, rust-overlay, advisory-db } @ inputs:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwing" "aarch64-darwin" ];
      
      perSystem = { pkgs, system, ... }:
        let
          rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          crane-lib = (crane.mkLib pkgs).overrideToolchain rust-toolchain;
          src = crane-lib.cleanCargoSource ./.;

          common-args = {
            inherit src;

            strictDeps = true;

            buildInputs = with pkgs; [
              sqlcipher
            ];
            
            nativeBuildInputs = with pkgs; [
              pkg-config
            ];
          };

          cargo-artifacts = crane-lib.buildDepsOnly common-args;

          cald = crane-lib.buildPackage (common-args // {
            inherit cargo-artifacts;
          });
        in {
          _module.args.pkgs = import nixpkgs { 
            inherit system;
            overlays = [
              (import rust-overlay)
            ];
          };

          packages.default = cald;

          devShells.default = crane-lib.devShell {
            inputsFrom = [ cald ];

            packages = with pkgs; [
              cargo-edit
              cargo-audit
              cargo-deny

              rust-analyzer
              crates-lsp
            ];
          };
        };

      flake = {
        nixosModules.default = { config, lib, pkgs, ... }:
          let
            inherit (lib) mkEnableOption mkOption getExe getExe';
            inherit (lib.strings) contactMapAttrsStringSet concatMapStringsSep;
            inherit (pkgs) writeText writeShellScript;
            service-name = "trustd";
            full-name = "ad._2mon.${service-name}";
            cfg = config.services.${service-name};
            policy-file = writeText {
              name = "policy.toml";
              text = contactMapAttrsStringSet 
                "\n"
                (app-id: packages:
                  "${app-id} = [${concatMapStringsSep ", " (pkg: ''"${getExe pkg}"'') packages}]"
                )
                cfg.permissions;
            };
            config-file = writeText {
              name = "config.toml";
              text = ''
                policy_path = "${policy-file}"
              '';
            };
            gen-secret = writeShellScript "gen-secret" ''
              if [ ! -f  /etc/credstore.encrypted/trustd-$1-database-key.cred ]; then
                  ${getExe' "head" pkgs.coreutils} -c32 </dev/urandom \
                      | ${getExe' "systemd-creds" pkgs.systemd} encrypt --name=database-key - /etc/credstore.encrypted/trustd-$1-database-key.cred
              fi
            '';
          in {
            options.services.${service-name} = {
              enable = mkEnableOption "${service-name} trust broker";
              users = mkOption {
                type = with lib.types; listOf str;
                default = [];
                description = "Users for which ${service-name} is enabled.";
              };
              permissions = mkOption {
                type = with lib.types; attrsOf (listOf package);
              };
              package = mkOption {
                type = with lib.types; package;
                default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
                description = "The underlying `${service-name}` package to be used.";
              };
            };

            config = lib.mkIf cfg.enable {
              systemd.targets.multi-user.wants = map (user: "${service-name}@${user}.service") cfg.users;
              systemd.services."${service-name}@" = {
                description = "A trust broker for %i.";
                after = [ "local-fs.target" ];

                serviceConfig = {
                  ExecPreStart = "${gen-secret} %i";
                  ExecStart = "${lib.getExe cfg.package} -c ${config-file}";
                  Type = "simple";

                  User = "%i";
                  Group = "%i";

                  LoadCredentialEncrypted = "database-key:/etc/credstore.encrypted/trustd-%i-database-key.cred";

                  PrivateNetwork = true;
                  RestrictAddressFamilies = [ "AF_UNIX" ];
                  ProtectHostname = true;

                  ProtectSystem = "strict";
                  ProtectHome = "tmpfs";

                  ReadWritePaths = [
                    "%h/.local/share/${full-name}"
                    "%h/.config/${full-name}"
                    "%h/.cache/${full-name}"
                    "/run/user/%U/bus"
                  ];

                  Environment = [
                    "XDG_DATA_HOME=%h/.local/share"
                    "XDG_CONFIG_HOME=%h/.config"
                    "XDG_CACHE_HOME=%h/.cache"
                    "DBUS_SESSION_BUS_ADDRESS=unix:path/run/user/%U/bus"
                  ];

                  PrivateTmp = true;
                };
              };
            };
          };
      };
    };
}
