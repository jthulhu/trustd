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

      perSystem = { pkgs, system, lib, ... }:
        let
          rust-toolchain = pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
          crane-lib = (crane.mkLib pkgs).overrideToolchain rust-toolchain;
          src = lib.cleanSourceWith {
            src = ./.; 
            name = "source";
            filter = path: type: 
              # Also include the markdown readmes, since they are referenced inside the Rust
              # sources, as documentation.
              (builtins.match ".*/README.md$" path != null)
              || (crane-lib.filterCargoSources path type);
          };

          common-args = {
            inherit src;

            strictDeps = true;

            buildInputs = with pkgs; [
              openssl
            ];

            nativeBuildInputs = with pkgs; [
              pkg-config
              rustPlatform.bindgenHook
            ];
          };

          cargo-artifacts = crane-lib.buildDepsOnly common-args;

          trustd = crane-lib.buildPackage (common-args // {
            inherit cargo-artifacts;
            pname = "trustd";
            cargoExtraArgs = "-p trustd";

            meta = {
              mainProgram = "trustd";
              homepage = "https://github.com/jthulhu/trust";
              description = "trustd is a trust broker";
            };
          });
          test-pkg = crane-lib.buildPackage (common-args // {
            inherit cargo-artifacts;
            pname = "trustd-tests";
            cargoExtraArgs = "-p trustd-tests";
          });
          testers = {
            get-secret = lib.getExe' test-pkg "get-secret";
          };
        in {
          _module.args.pkgs = import nixpkgs {
            inherit system;
            overlays = [
              (import rust-overlay)
            ];
          };

          packages.default = trustd;

          checks = {
            spin-trustd = pkgs.testers.runNixOSTest {
              name = "spin-trustd";

              nodes = {
                wonderland = { pkgs, ... }: {

                  imports = [
                    self.nixosModules.default
                  ];

                  services.dbus.implementation = "broker";

                  environment.systemPackages = [
                    test-pkg
                    pkgs.sshpass
                    pkgs.file
                  ];

                  users.users.alice = {
                    password = "lewis";
                    uid = 1000;
                    createHome = true;
                    isNormalUser = true;
                  };

                  services.openssh = {
                    enable = true;
                    settings = {
                      StrictModes = false;
                    };
                  };

                  services.logind.settings.Login.UserStopDelaySec = "1s";

                  services.trustd = {
                    enable = true;
                    policy = {
                      alice = {
                        "ad._2mon.test.SecretGetter" = [ testers.get-secret ];
                        "ad._2mon.test.OtherApp" = [ testers.get-secret ];
                      };
                    };
                  };
                };
              };

              testScript = ''
                start_all()

                wonderland.wait_for_unit("multi-user.target")
                wonderland.wait_for_open_port(22)

                wonderland.succeed(
                    "sshpass -p lewis "
                    "ssh -tt -F /dev/null -o StrictHostKeyChecking=no alice@localhost "
                    "</dev/null >/dev/null 2>&1 "
                    "sleep infinity & echo $! >/tmp/ssh.pid"
                )
                wonderland.wait_until_succeeds("systemctl is-active user@1000.service")
                wonderland.wait_until_succeeds("systemctl is-active trustd@1000.service")

                secret1 = wonderland.succeed("su - alice -c 'get-secret ad._2mon.test.SecretGetter'")
                secret2 = wonderland.succeed("su - alice -c 'get-secret ad._2mon.test.SecretGetter'")
                secret3 = wonderland.succeed("su - alice -c 'get-secret ad._2mon.test.OtherApp'")

                assert secret1 == secret2, "getting secrets should be idempotent"
                assert secret1 != secret3, "different applications should have different secrets"

                wonderland.succeed("pkill -f 'ssh.*alice@'")
                wonderland.wait_until_succeeds("! systemctl is-active user@1000.service")
                wonderland.fail("systemctl is-active trustd@1000.service")
              '';
            };
          };

          devShells.default = crane-lib.devShell {
            inputsFrom = [ trustd ];

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
        nixosModules = rec {
          trust = { config, lib, pkgs, ... }:
            let
              inherit (lib) mkEnableOption mkOption getExe getExe';
              inherit (lib.strings) concatMapAttrsStringSep concatMapStringsSep;
              inherit (pkgs) writeText writeShellScript;
              service-name = "trustd";
              cfg = config.services.${service-name};
              policy-file = writeText 
                "policy.toml"               
                (concatMapAttrsStringSep
                  "\n"
                  (user: permissions:
                    concatMapAttrsStringSep
                      "\n"
                      (app-id: packages:
                        "\"${user}\".\"${app-id}\" = [${concatMapStringsSep ", " (pkg: ''"${if lib.isDerivation pkg then getExe pkg else pkg}"'') packages}]"
                      )
                      permissions
                  )
                  cfg.policy
                );

              config-file = writeText
                "config.toml" 
                ''
                policy_path = "${policy-file}"
              '';

              gen-secret = writeShellScript "gen-secret" ''
              path="/etc/credstore.encrypted/trustd-$1/database-key.cred"
              if [ ! -f  "$path" ]; then
                  echo "Generating first-time secret"
                  mkdir -p "$(dirname "$path")"
                  ${getExe' pkgs.coreutils "head"} -c32 </dev/urandom \
                      | ${getExe' pkgs.systemd "systemd-creds"} encrypt --name=database-key - "$path"
              fi
            '';
            in {
              options.services.${service-name} = {
                enable = mkEnableOption "${service-name} trust broker";
                policy = mkOption {
                  type = with lib.types; attrsOf (attrsOf (listOf (either package str)));
                  default = {};
                  description = "Users for which ${service-name} is enabled.";
                };
                package = mkOption {
                  type = with lib.types; package;
                  default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
                  description = "The underlying `${service-name}` package to be used.";
                };
              };

              config = lib.mkIf cfg.enable {
                systemd.services = {
                  # The role of this service is to create a system secret for trustd.
                  "${service-name}-keygen@" = {
                    
                    description = "key generation for ${service-name}@%i.";

                    serviceConfig = {
                      Type = "oneshot";
                      ExecStart = "${gen-secret} \"%i\"";
                      RemainAfterExit = true;
                    };
                  };

                  "${service-name}@" = {
                    description = "trust broker";
                    after = [
                      "${service-name}-keygen@%i.service" 
                      "user@%i.service" # This should only start after `user@%i` has finished setup, ...
                    ];
                    # ... it should stop when `user@%i` stops ...
                    bindsTo = [ "user@%i.service" ];
                    # ... and it should be started alongside `user@%i`.
                    # 
                    # PS: in the [Install] section (which contains `WantedBy`), there is no
                    # expansion.  Instead, referencing other templates passes the argument over.
                    wantedBy = [ "user@.service" ];
                    upheldBy = [ "user@.service" ];
                    requires = [ "${service-name}-keygen@%i.service" ];

                    serviceConfig = {
                      ExecStart = "${lib.getExe cfg.package} -c ${config-file}";
                      # Considers the service as started when it has claimed its `BusName` over the
                      # system bus.
                      Type = "notify";

                      LoadCredentialEncrypted = [
                        "database-key:/etc/credstore.encrypted/trustd-%i/database-key.cred" 
                      ];

                      User = "%i";
                      Group = "users";

                      PrivateNetwork = true;
                      RestrictAddressFamilies = [ "AF_UNIX" ];
                      ProtectHostname = true;
                      NoNewPrivileges = true;

                      PAMName = "systemd-user";
                      
                      ProtectSystem = "strict";

                      PrivateTmp = true;
                    };
                  };
                };
              };
            };
          default = trust;
          home-manager = { config, ... }: {
            home-manager.sharedModules = [
              ({ lib, ... }: 
                let
                  inherit (lib) mkOption;
                in {
                  options.services.trustd = mkOption {
                    type = with lib.types; attrsOf (attrsOf (listOf (either package str)));
                    default = {};
                  };
                })
            ];

            services.trustd.policy = builtins.mapAttrs 
              (user: cfg: cfg.services.trustd)
              config.home-manager.users;
          };
        };
      }; 
    };
}
