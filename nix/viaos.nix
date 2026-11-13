# The viaos operating system.
#
# Disk layout (GPT):
#
#   esp           vfat   systemd-boot, one UKI per OS version, viaos.toml
#   viaos_<v>     erofs  /nix/store for version v (slot A)    } dm-verity,
#   viaos_<v>_v   hash   its verity tree                        } read-only
#   _empty x2            slot B, filled by systemd-sysupdate
#   var           ext4   created and grown on first boot
#
# `/` is tmpfs. Everything that survives a reboot lives on /var. Each UKI
# carries the verity root hash of its own store, so choosing a boot entry
# chooses a slot; boot counting falls back to the previous entry when a new
# one fails to reach boot-complete.target.
{
  config,
  lib,
  pkgs,
  modulesPath,
  self,
  ...
}:
let
  cfg = config.viaos;
  inherit (cfg) version;
  efiArch = pkgs.stdenv.hostPlatform.efiArch;
  agent = self.packages.${pkgs.stdenv.hostPlatform.system}.via-agent;

  # Store slots are sized for growth: a later version must fit in the slot
  # the current one does not occupy.
  storeSize = "2G";
  veritySize = "64M";
  verityBlocks = {
    VerityDataBlockSizeBytes = 4096;
    VerityHashBlockSizeBytes = 4096;
  };

  # repart finds its disk through `/`, which is tmpfs here. The ESP is on
  # the boot disk whatever the hardware names it (vda, nvme0n1, mmcblk0),
  # so find the disk through the ESP's label instead.
  repartVar = pkgs.writeShellScript "viaos-repart" ''
    set -eu
    part=$(${pkgs.coreutils}/bin/readlink -f /dev/disk/by-partlabel/esp)
    disk=$(${pkgs.coreutils}/bin/readlink -f /sys/class/block/''${part##*/}/..)
    exec ${config.boot.initrd.systemd.package}/bin/systemd-repart \
      --definitions=/etc/repart.d --dry-run=no --empty=refuse \
      /dev/''${disk##*/}
  '';
in
{
  imports = [
    "${modulesPath}/image/repart.nix"
    "${modulesPath}/profiles/minimal.nix"
    "${modulesPath}/profiles/perlless.nix"
    ./firmware.nix
    ./network.nix
    ./sysupdate.nix
    ./rpi.nix
  ];

  options.viaos = {
    debug = lib.mkEnableOption "a passwordless root shell on the serial console";
    version = lib.mkOption {
      type = lib.types.str;
      default = lib.fileContents ../VERSION;
      description = "OS version. Updates install only versions that sort higher.";
    };
  };

  config = {
    system.stateVersion = "26.05";
    system.image.id = "viaos";
    system.image.version = version;
    system.nixos.distroName = "viaos";
    # No static hostname: it would outrank the one the agent sets from
    # viaos.toml. The agent always sets one.
    networking.hostName = "";

    # ---- boot ----

    boot.loader.grub.enable = false;
    boot.initrd.systemd.enable = true;
    boot.kernelParams = [
      "console=tty0"
    ]
    ++ lib.optional pkgs.stdenv.hostPlatform.isx86_64 "console=ttyS0,115200"
    ++ lib.optional pkgs.stdenv.hostPlatform.isAarch64 "console=ttyAMA0,115200";
    boot.initrd.availableKernelModules = [
      "virtio_pci"
      "virtio_blk"
      "virtio_scsi"
      "nvme"
      "ahci"
      "sd_mod"
      "usb_storage"
      "uas"
      "xhci_pci"
      "mmc_block"
      "sdhci_pci"
    ];

    # The UKI file name carries the version and the boot-counting suffix, so
    # a fresh install gets the same three tries a fresh update does.
    system.boot.loader.ukiFile = "viaos_${version}.efi";

    image.repart = {
      name = "viaos";
      # OVMF and most firmware want 512-byte sectors on a raw image.
      sectorSize = 512;
      # mkfs.erofs takes its block size from the sector size. 512-byte erofs
      # blocks mount, but libblkid does not recognise them, so udev never
      # marks the verity device ready and boot waits for /usr forever.
      mkfsOptions.erofs = [ "-b4096" ];
      verityStore = {
        enable = true;
        ukiPath = "/EFI/Linux/viaos_${version}+3-0.efi";
      };
      partitions = {
        "00-esp" = {
          contents = {
            "/EFI/BOOT/BOOT${lib.toUpper efiArch}.EFI".source =
              "${pkgs.systemd}/lib/systemd/boot/efi/systemd-boot${efiArch}.efi";
            "/loader/loader.conf".source = pkgs.writeText "loader.conf" ''
              timeout 2
              editor no
            '';
            "/viaos.toml".source = ./viaos.example.toml;
          };
          repartConfig = {
            Type = "esp";
            Format = "vfat";
            Label = "esp";
            SizeMinBytes = "512M";
            SizeMaxBytes = "512M";
          };
        };
        # 4K verity blocks, not the 512-byte sectors: the hash tree is an
        # eighth the size and there is less of it to check at boot.
        "10-store-verity".repartConfig = verityBlocks // {
          Label = "viaos_${version}_v";
          Minimize = lib.mkForce "off";
          SizeMinBytes = veritySize;
          SizeMaxBytes = veritySize;
        };
        "20-store".repartConfig = verityBlocks // {
          Label = "viaos_${version}";
          Minimize = lib.mkForce "off";
          SizeMinBytes = storeSize;
          SizeMaxBytes = storeSize;
        };
        # Slot B. sysupdate claims partitions labelled `_empty` of the right
        # type and relabels them with the version it wrote.
        "30-store-verity-b".repartConfig = {
          Type = config.image.repart.partitions."10-store-verity".repartConfig.Type;
          Label = "_empty";
          SizeMinBytes = veritySize;
          SizeMaxBytes = veritySize;
        };
        "40-store-b".repartConfig = {
          Type = config.image.repart.partitions."20-store".repartConfig.Type;
          Label = "_empty";
          SizeMinBytes = storeSize;
          SizeMaxBytes = storeSize;
        };
      };
    };

    # /var is made on the device, not shipped in the image, so one image fits
    # any disk size. The initrd grows it to fill whatever is left.
    boot.initrd.systemd.repart.enable = true;
    boot.initrd.systemd.services.systemd-repart =
      let
        espUnit = "dev-disk-by\\x2dpartlabel-esp.device";
      in
      {
        serviceConfig = {
          ExecStart = lib.mkForce [
            " "
            "${repartVar}"
          ];
          StandardOutput = "journal+console";
          StandardError = "journal+console";
        };
        # After /usr is up, as upstream orders it: repart only adds a
        # partition, which leaves the open verity device alone, whereas
        # running alongside veritysetup races udev for the usr device.
        requires = [ espUnit ];
        after = lib.mkForce [
          espUnit
          "sysusr-usr.mount"
        ];
        before = [ "sysroot-var.mount" ];
      };
    boot.initrd.systemd.storePaths = [
      repartVar
      "${pkgs.coreutils}/bin/readlink"
    ];
    # linux-generic, not `var`: repart derives a var partition's UUID from
    # the machine-id, which the initrd of a first boot does not have yet.
    systemd.repart.partitions."50-var" = {
      Type = "linux-generic";
      Format = "ext4";
      Label = "var";
      FactoryReset = "yes";
    };

    fileSystems = {
      "/" = {
        fsType = "tmpfs";
        options = [
          "mode=0755"
          "size=25%"
        ];
      };
      "/var" = {
        device = "/dev/disk/by-partlabel/var";
        fsType = "ext4";
        neededForBoot = true;
      };
      "/boot" = {
        device = "/dev/disk/by-partlabel/esp";
        fsType = "vfat";
        options = [
          "umask=0077"
          "nofail"
        ];
      };
    };

    # ---- a read-only system ----

    nix.enable = false;
    system.switch.enable = false;
    system.disableInstallerTools = true;
    documentation.enable = false;
    # No /usr/bin/env on a read-only /usr.
    system.activationScripts.usrbinenv = lib.mkForce "";
    users.mutableUsers = false;
    users.allowNoPasswordLogin = true;
    services.journald.storage = "persistent";

    # ---- containers ----

    virtualisation.docker = {
      enable = true;
      # Devices run images, they do not build them: no buildx, and no git
      # for building from a repository URL. xfsprogs brings Python for one
      # script; Docker only needs it for XFS-backed storage, which viaos
      # does not use.
      package = pkgs.docker.override {
        buildxSupport = false;
        gitMinimal = pkgs.emptyDirectory;
        xfsprogs = pkgs.emptyDirectory;
      };
      daemon.settings = {
        log-driver = "local";
        log-opts.max-size = "10m";
        live-restore = true;
      };
    };
    # viaos.toml's [proxy], for image pulls; see network.nix.
    systemd.services.docker.serviceConfig.EnvironmentFile = [ "-/run/via/proxy.env" ];

    # The files an update to this version is made of; see update.nix.
    system.build.update = pkgs.callPackage ./update.nix {
      inherit version;
      image = config.system.build.image;
      uki = "${config.system.build.uki}/${config.system.boot.loader.ukiFile}";
      arch = pkgs.stdenv.hostPlatform.uname.processor;
    };

    # ---- the agent ----

    # The agent runs this docker's `compose`. A build of `via` pins the same one
    # (see flake.nix), so a file reads the same on both.
    environment.systemPackages = [ agent ];

    systemd.services.via-agent = {
      description = "viaos device agent";
      wantedBy = [ "multi-user.target" ];
      after = [
        "docker.service"
        "network-online.target"
        "boot.mount"
      ];
      wants = [
        "docker.service"
        "network-online.target"
      ];
      serviceConfig = {
        ExecStart = "${lib.getExe agent} run";
        Restart = "always";
        RestartSec = 5;
        StateDirectory = "via";
        # viaos.toml's [proxy], for the control plane and downloads.
        EnvironmentFile = [ "-/run/via/proxy.env" ];
      };
      environment = {
        VIA_CONFIG = "/boot/viaos.toml";
        VIA_DOCKER = "${config.virtualisation.docker.package}/bin/docker";
        VIA_SYSUPDATE = "${config.systemd.package}/lib/systemd/systemd-sysupdate";
      };
    };

    # A boot is good once Docker answers and the agent has reached the
    # control plane (see crates/via-agent/src/ready.rs). Reaching
    # boot-complete.target marks the boot entry good; a trial boot of a new
    # version that is not good in five minutes is marked bad and rebooted
    # into the version before it.
    systemd.services.viaos-ready = {
      description = "Check this boot is good";
      after = [
        "docker.service"
        "via-agent.service"
      ];
      wants = [
        "docker.service"
        "via-agent.service"
      ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${lib.getExe agent} ready --timeout-secs 300";
        TimeoutStartSec = "infinity";
      };
      environment = {
        VIA_CONFIG = "/boot/viaos.toml";
        VIA_BLESS_BOOT = "${config.systemd.package}/lib/systemd/systemd-bless-boot";
      };
    };
    systemd.targets.boot-complete = {
      requires = [ "viaos-ready.service" ];
      after = [ "viaos-ready.service" ];
    };

    # ---- access ----

    services.openssh = {
      enable = true;
      settings = {
        PasswordAuthentication = false;
        KbdInteractiveAuthentication = false;
        PermitRootLogin = "prohibit-password";
      };
      # Keys come from viaos.toml via the agent; /etc is rebuilt every boot.
      authorizedKeysFiles = [ "/var/lib/via/authorized_keys" ];
      hostKeys = [
        {
          path = "/var/lib/ssh/ssh_host_ed25519_key";
          type = "ed25519";
        }
      ];
    };

    services.getty.autologinUser = lib.mkIf cfg.debug "root";
    boot.initrd.systemd.emergencyAccess = cfg.debug;
    users.users.root.hashedPassword = lib.mkIf (!cfg.debug) "!";
  };
}
