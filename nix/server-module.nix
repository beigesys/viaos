# `services.via-server`: the control plane on a NixOS host.
#
#   services.via-server = {
#     enable = true;
#     domain = "via.example.com";   # Caddy terminates TLS for it
#   };
#
# Then, once: `sudo -u via-server via-server token create <you>`, and point
# Claude at https://via.example.com/mcp with that token.
{ self }:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.via-server;
  inherit (lib) mkOption types;
in
{
  options.services.via-server = {
    enable = lib.mkEnableOption "the viaos control plane";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.via-server;
      defaultText = lib.literalExpression "viaos.packages.\${system}.via-server";
    };
    domain = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "via.example.com";
      description = ''
        Serve the control plane at https://<domain> through Caddy, which
        gets and renews the certificate. Leave null to put your own proxy
        in front, and set publicUrl.
      '';
    };
    publicUrl = mkOption {
      type = types.str;
      default = "https://${cfg.domain}";
      defaultText = lib.literalExpression ''"https://''${domain}"'';
      description = "The URL devices and people reach the server at.";
    };
    listen = mkOption {
      type = types.str;
      default = "127.0.0.1:8471";
      description = "Address the server itself listens on, behind the proxy.";
    };
    trustedKeys = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        Public keys (from `via keygen`) devices require OS updates and
        releases to be signed by. Written into provisioning images.
      '';
    };
    environmentFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Extra environment, e.g. VIA_ADMIN_TOKEN=..., VIA_SECRET_KEY=... or VIA_GITHUB_CLIENT_SECRET=..., kept out of the store.";
    };
    github = {
      clientId = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = ''
          Client ID of a GitHub OAuth app, to let people sign in to the console
          with GitHub. Put VIA_GITHUB_CLIENT_SECRET in environmentFile.
        '';
      };
      org = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Only members of this organisation can sign in. Its owners are admins; other members get what grants give them.";
      };
      adminTeam = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "Slug of a team in the organisation whose members are also admins.";
      };
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    # `via-server token ...` run by hand finds the same database.
    environment.variables.VIA_DATA_DIR = "/var/lib/via-server";

    systemd.services.via-server = {
      description = "viaos control plane";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      # Provisioning copies the base image with cp.
      path = [ pkgs.coreutils ];
      environment = {
        VIA_LISTEN = cfg.listen;
        VIA_PUBLIC_URL = cfg.publicUrl;
        VIA_DATA_DIR = "/var/lib/via-server";
      }
      // lib.optionalAttrs (cfg.trustedKeys != [ ]) {
        VIA_TRUSTED_KEYS = lib.concatStringsSep "," cfg.trustedKeys;
      }
      // lib.optionalAttrs (cfg.github.clientId != null) {
        VIA_GITHUB_CLIENT_ID = cfg.github.clientId;
        VIA_GITHUB_ORG = cfg.github.org;
      }
      // lib.optionalAttrs (cfg.github.adminTeam != null) {
        VIA_GITHUB_ADMIN_TEAM = cfg.github.adminTeam;
      };
      serviceConfig = {
        ExecStart = "${lib.getExe cfg.package} serve";
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
        StateDirectory = "via-server";
        Restart = "always";
        User = "via-server";
        Group = "via-server";
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ "/var/lib/via-server" ];
      };
    };

    users.users.via-server = {
      isSystemUser = true;
      group = "via-server";
      home = "/var/lib/via-server";
    };
    users.groups.via-server = { };

    services.caddy = lib.mkIf (cfg.domain != null) {
      enable = true;
      virtualHosts.${cfg.domain}.extraConfig = ''
        encode zstd gzip
        reverse_proxy ${cfg.listen}
      '';
    };
    networking.firewall.allowedTCPPorts = lib.mkIf (cfg.domain != null) [
      80
      443
    ];
  };
}
