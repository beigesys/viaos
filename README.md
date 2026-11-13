# viaos

An open, immutable Linux for edge devices: NixOS-built, upstream Docker, A/B
OS updates with automatic rollback, and an optional control plane that
devices dial out to, so they can sit behind NAT. Claude runs it through MCP;
a web console, built into the server, covers enrolling, logs, shells,
secrets and administration through the same tools.

```text
 Claude ──MCP──▶ via-server ◀──WebSocket (outbound)── via-agent ── dockerd
   │                 │                                    │
   └──MCP──▶ via (on your laptop: flash SD cards)     viaos image
```

## Try it

`docs/deploy.md` covers running the control plane for real (NixOS module or
container, TLS, tokens, signing, Secure Boot). To try it on one machine:

```bash
# 1. Build an image (x86_64 here; aarch64 for Raspberry Pi 4)
nix build .#images.x86_64 -o result-x86

# 2. Run a control plane and make yourself a token
mkdir -p data/base && ln -s $(readlink -f result-x86)/viaos_1.raw data/base/viaos-x86_64.raw
export VIA_DATA_DIR=data VIA_SERVER=http://localhost:8080
export VIA_TOKEN=$(cargo run -q -p via-server -- token create me)
VIA_PUBLIC_URL=http://<this machine's LAN address>:8080 cargo run -p via-server &

# 3. Point Claude at it
claude mcp add --transport http via $VIA_SERVER/mcp --header "Authorization: Bearer $VIA_TOKEN"
claude mcp add via-local -- sudo -E via mcp     # for flashing attached disks
```

Then ask:

- "Make a provisioning image for a Pi and an x86 box on fleet `line`."
- "Flash it to the SD card I just plugged in."
- "How's line-07 doing?"
- "Update all of fleet `line` to version 2."
- "What's using the disk on line-07?" (`exec`)

Or open the server's address in a browser and sign in with the token.

`via ssh line-07` opens a shell on a device wherever it is, through its own
outbound connection.

A device without a control plane is still fully manageable:
`claude mcp add line-07 -- ssh root@line-07 via-agent mcp`.

## Pieces

| Path | What |
| --- | --- |
| `nix/viaos.nix` | The OS: verity-protected A/B `/nix/store`, tmpfs `/`, `/var` grown on first boot |
| `nix/sysupdate.nix`, `nix/update.nix` | OS update files and how sysupdate installs them |
| `nix/network.nix` | Wired and Wi-Fi (networkd, iwd), and viaos.toml's network, time and proxy settings applied at boot |
| `nix/firmware.nix` | The firmware shipped: common Ethernet, Wi-Fi and Bluetooth chips; `viaos.firmware` adds more |
| `nix/server-module.nix` | `services.via-server` for NixOS, with Caddy for TLS; `nix/server-test.nix` boots it in a VM |
| `nix/rpi.nix` | Raspberry Pi 4 / 400 / CM4 boot chain (firmware → U-Boot → systemd-boot) |
| `nix/nvidia.nix` | The NVIDIA variant (`images.x86_64-nvidia`): driver, and GPUs for containers via CDI |
| `crates/via-agent` | Device daemon: applies `viaos.toml`, holds the control-plane link, serves device MCP |
| `crates/via-server` | Control plane: registry, enrollment, provisioning images, OS updates, fleet MCP |
| `web/` | The web console: Bun, React, Tailwind. `nix/web.nix` builds it into `via-server` |
| `crates/via-link` | Byte streams multiplexed over the device's one WebSocket |
| `crates/via-cli` | `via` on the operator's machine: flash SD cards, release apps and OS versions (optionally signed, and for Secure Boot), `ssh` and `forward` into devices |
| `crates/via-image` | The boot partition of a raw image, opened in place |
| `crates/via-{core,compose,bundle,runtime,deploy}` | App releases, from [beigesys/via](https://github.com/beigesys/via) |

The OS is about 1.1 GB installed. An OS update downloads about 610 MB, and
the raw image is 4.7 GB (two 2 GB store slots), so it needs an 8 GB disk.

`viaos.toml` on the boot partition configures a device (hostname, control
plane, SSH keys, Wi-Fi, addressing, time zone, proxy); see `nix/viaos.example.toml`. `docs/MCP.md` lists the tools.

## Development

```bash
cargo test --workspace
nix build .#images.x86_64-debug        # adds a root shell on the serial console
scripts/qemu.sh result/viaos_1.raw     # boot it; SSH on localhost:2222
```
