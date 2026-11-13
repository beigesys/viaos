# The NVIDIA variant: the driver, and containers that can use the GPU.
#
#   services:
#     inference:
#       deploy:
#         resources:
#           reservations:
#             devices: [{ driver: nvidia, count: all, capabilities: [gpu] }]
#
# Docker hands a request like that to the Container Device Interface: at boot
# nvidia-ctk writes a spec for the GPUs it finds to /run/cdi (not /etc, which
# is rebuilt from the read-only store), and Docker injects the devices, the
# driver's libraries and nvidia-smi from it. Images bring their own CUDA.
#
# The open kernel modules, which NVIDIA supports from Turing on: GTX 16xx,
# RTX 20xx and everything after, and the data-center cards of those
# generations. Older cards need the closed modules (`viaos.nvidia.open =
# false`) and a driver branch that still knows them; viaos does not build that.
#
# A variant is its own line of OS versions: its devices update only to builds
# of the same variant (see VARIANT_ID in os-release, and update.nix).
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.viaos.nvidia;
  toolkit = config.hardware.nvidia-container-toolkit.package;
in
{
  options.viaos.nvidia = {
    enable = lib.mkEnableOption "the NVIDIA driver and GPU access for containers";
    open = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Use NVIDIA's open kernel modules, which need a Turing or newer GPU.";
    };
  };

  config = lib.mkIf cfg.enable {
    system.nixos.variant_id = "nvidia";
    system.nixos.variantName = "NVIDIA";
    # The driver alone is about 1 GB, as much as the rest of the OS.
    viaos.storeSize = "3G";

    # The driver is the only unfree software in viaos.
    nixpkgs.config.allowUnfreePredicate =
      pkg:
      builtins.elem (lib.getName pkg) [
        "nvidia-x11"
        "nvidia-persistenced"
      ];

    # How NixOS turns the driver on; it starts no X server.
    services.xserver.videoDrivers = [ "nvidia" ];
    hardware.nvidia = {
      inherit (cfg) open;
      package = config.boot.kernelPackages.nvidiaPackages.production;
      # A container that drives a display needs DRM KMS.
      modesetting.enable = true;
      # Keeps the GPU initialised with no client, so a CUDA process starts
      # without waiting for it.
      nvidiaPersistenced = true;
      nvidiaSettings = false;
      videoAcceleration = false;
    };
    # Mesa is for the host's own rendering, and a headless host does none.
    # Containers bring their own; NVIDIA's GL libraries reach them via CDI.
    hardware.graphics.package = pkgs.emptyDirectory;

    hardware.nvidia-container-toolkit.enable = true;
    # Docker looks for nvidia-cdi-hook on its PATH to accept `driver: nvidia`
    # and `--gpus`, and then injects `nvidia.com/gpu` devices from the spec.
    # Only that: with nvidia-container-runtime-hook there too, Docker falls
    # back to the legacy hook, which can't work here, and says that instead
    # of what's wrong.
    virtualisation.docker.extraPackages = [
      (pkgs.runCommand "nvidia-cdi-hook" { } ''
        mkdir -p $out/bin
        ln -s ${lib.getOutput "tools" toolkit}/bin/nvidia-cdi-hook $out/bin/
      '')
    ];
    # NixOS makes Docker require the spec generator. Without a GPU (one that
    # failed, or a box flashed with the wrong image) the generator fails, and
    # Docker with it, and every boot would roll back. Want it instead: Docker
    # starts either way and GPU containers say what's missing.
    systemd.services.nvidia-container-toolkit-cdi-generator = {
      requiredBy = lib.mkForce [ ];
      wantedBy = [ "docker.service" ];
      before = [ "docker.service" ];
    };
  };
}
