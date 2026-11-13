# Wired and Wi-Fi networking, and the settings viaos.toml gives them.
#
# networkd addresses every link; iwd only joins Wi-Fi networks. Before
# either starts, `via-agent system` writes what viaos.toml asks for:
# iwd's network files in /var/lib/iwd, static addressing as networkd files
# in /run/systemd/network (which outrank the defaults below by name), the
# time zone and NTP servers, and the proxy. See
# crates/via-agent/src/system.rs.
{
  lib,
  pkgs,
  self,
  ...
}:
let
  agent = self.packages.${pkgs.stdenv.hostPlatform.system}.via-agent;
in
{
  networking.useNetworkd = true;
  systemd.network.networks."10-wired" = {
    # Real interfaces only. A veth is `ether` too, and networkd taking one
    # keeps it off Docker's bridge: no published ports, no container network.
    matchConfig = {
      Type = "ether";
      Kind = "!*";
    };
    networkConfig.DHCP = "yes";
  };
  systemd.network.networks."20-wifi" = {
    matchConfig = {
      Type = "wlan";
      WLANInterfaceType = "station";
    };
    networkConfig.DHCP = "yes";
  };
  # Either link is enough to be online: a Wi-Fi device has no cable in, and
  # a wired one usually has no Wi-Fi network to join.
  systemd.network.wait-online.anyInterface = true;

  networking.wireless.iwd = {
    enable = true;
    # networkd addresses Wi-Fi the same way as wired, static or DHCP.
    settings.General.EnableNetworkConfiguration = false;
  };

  systemd.services.viaos-settings = {
    description = "Apply viaos.toml network and system settings";
    wantedBy = [ "multi-user.target" ];
    # Early, without the usual dependencies: networkd starts before
    # sysinit.target, and everything listed reads what this writes.
    unitConfig = {
      DefaultDependencies = false;
      RequiresMountsFor = [
        "/boot"
        "/var/lib"
      ];
    };
    wants = [ "network-pre.target" ];
    before = [
      "network-pre.target"
      "systemd-networkd.service"
      "iwd.service"
      "systemd-timesyncd.service"
      "docker.service"
      "via-agent.service"
      "shutdown.target"
    ];
    conflicts = [ "shutdown.target" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      ExecStart = "${lib.getExe agent} system";
    };
    environment.VIA_CONFIG = lib.mkDefault "/boot/viaos.toml";
  };
}
