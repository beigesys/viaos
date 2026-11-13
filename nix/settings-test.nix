# viaos.toml's network and system settings, applied by `via-agent system`
# at boot: static wired addressing, Wi-Fi through iwd, time and proxy. The
# Wi-Fi network is a simulated radio (mac80211_hwsim) with hostapd on its
# second interface, so the device joins it exactly as it would a real one.
{ self, pkgs }:
let
  ssid = "viaos test";
  passphrase = "not a real secret";
in
pkgs.testers.runNixOSTest {
  name = "viaos-settings";
  node.specialArgs = { inherit self; };
  nodes.machine =
    { lib, ... }:
    {
      imports = [ ./network.nix ];
      # The test's own vlan address would be a second one on eth1.
      networking.interfaces = lib.mkForce { };
      environment.etc."viaos.toml".text = ''
        [[wifi]]
        ssid = "${ssid}"
        passphrase = "${passphrase}"
        priority = 1

        [[wifi]]
        ssid = "café, upstairs"
        passphrase = "elsewhere-1"

        [network]
        mode = "static"
        address = "10.9.8.7/24"
        gateway = "10.9.8.1"
        dns = ["10.9.8.53"]
        interfaces = ["wired"]

        [time]
        timezone = "America/New_York"
        ntp = ["ntp.example.test"]

        [proxy]
        https = "http://proxy.example.test:3128"
        no_proxy = [".plant.lan"]
      '';
      systemd.services.viaos-settings.environment.VIA_CONFIG = "/etc/viaos.toml";
      # Test VMs turn it off, as their clock is the host's; viaos has it on.
      services.timesyncd.enable = lib.mkForce true;

      # Two radios: wlan0 is the device's, wlan1 the access point.
      boot.kernelModules = [ "mac80211_hwsim" ];
      systemd.services.iwd.serviceConfig.ExecStart = [
        ""
        "${pkgs.iwd}/libexec/iwd --nointerfaces wlan1"
      ];
      services.hostapd = {
        enable = true;
        radios.wlan1 = {
          band = "2g";
          channel = 1;
          countryCode = "US";
          networks.wlan1 = {
            inherit ssid;
            authentication = {
              mode = "wpa2-sha1";
              wpaPassword = passphrase;
            };
          };
        };
      };
      # The access point's DHCP server answers on it.
      networking.firewall.trustedInterfaces = [ "wlan1" ];
      systemd.network.networks."01-access-point" = {
        matchConfig.Name = "wlan1";
        address = [ "10.77.0.1/24" ];
        networkConfig.DHCPServer = true;
      };
      environment.systemPackages = [ pkgs.iwd ];
    };

  testScript = ''
    machine.wait_for_unit("viaos-settings.service")

    with subtest("static address on the wired link"):
        machine.wait_until_succeeds("ip -4 addr show eth1 | grep -q 'inet 10.9.8.7/24'")
        machine.succeed("ip route show default | grep -q 'via 10.9.8.1 dev eth1'")
        machine.wait_until_succeeds("resolvectl dns eth1 | grep -q 10.9.8.53")

    with subtest("time zone and NTP servers"):
        assert machine.succeed("readlink /etc/localtime").strip().endswith("America/New_York")
        assert machine.succeed("date +%Z").strip() in ("EST", "EDT")
        machine.wait_for_unit("systemd-timesyncd.service")
        machine.succeed("timedatectl show-timesync -p SystemNTPServers | grep -q ntp.example.test")

    with subtest("proxy for Docker and the agent"):
        env = machine.succeed("cat /run/via/proxy.env")
        assert "HTTPS_PROXY=http://proxy.example.test:3128" in env, env
        assert "NO_PROXY=localhost,127.0.0.1,::1,.plant.lan" in env, env

    with subtest("Wi-Fi, through iwd and networkd"):
        machine.succeed("test -f '/var/lib/iwd/viaos test.psk'")
        # Not plain letters and digits: iwd names it by the SSID's hex.
        machine.succeed("test -f /var/lib/iwd/=636166c3a92c207570737461697273.psk")
        machine.wait_until_succeeds("iwctl station wlan0 show | grep -q 'State.*connected'", timeout=90)
        # A lease from the access point's DHCP server, over the air. (A ping
        # back proves nothing more: both ends are this one kernel.)
        machine.wait_until_succeeds("ip -4 addr show wlan0 | grep -q 'inet 10.77.0.'", timeout=60)
  '';
}
