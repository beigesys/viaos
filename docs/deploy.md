# Running a control plane

The control plane is one binary with one SQLite file. It needs a public
HTTPS address that devices can reach. Devices dial out to it, so they can
be behind NAT; the server cannot be.

## Compose

A device runs your file with the official `docker compose`, so it means what it
means on your laptop: `extends`, `include`, profiles, `env_file`, `configs`,
`secrets`, replicas, `network_mode: service:x` and the rest. There is no Via
parser to disagree with it. `via` and the OS pin the same Compose from the same
nixpkgs.

`via release` runs `docker compose config`, `build` and `pull`, then packs:

- the file Compose flattened, with `${VARS}` left for the device,
- the local files it reads: bind mount sources under the project, `env_file`s,
  `configs` and `secrets` from files, and `.env`, all covered by the signature,
- the images, because a device doesn't pull.

On the device it runs from `/var/lib/via/apps/<app>/` as `docker compose -p <app>`,
so `docker compose ls` and `ps` work there too. What differs from your laptop:

- `up` never pulls or builds. A release brought its images.
- A file in a bind mount that a container wrote stays across releases. A file the
  release carries is overwritten by the next one.
- A path outside the project, like `../data:/data`, fails the build. An absolute
  path means that path on the device.
- `up` runs again when the device boots, so an app comes back even without a
  `restart:`. A service without one still won't restart if it crashes; the build
  warns.

## 1. Run it

On NixOS, with Caddy getting the certificate:

```nix
{
  inputs.viaos.url = "github:beigesys/viaos";
  outputs = { nixpkgs, viaos, ... }: {
    nixosConfigurations.via = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        viaos.nixosModules.via-server
        {
          services.via-server = {
            enable = true;
            domain = "via.example.com";
            trustedKeys = [ "<public key from `via keygen`>" ];
          };
        }
      ];
    };
  };
}
```

Anywhere else, as a container behind any TLS proxy:

```bash
docker run -d --name via -p 127.0.0.1:8080:8080 -v via:/data \
  -e VIA_PUBLIC_URL=https://via.example.com \
  -e VIA_TRUSTED_KEYS=<public key> \
  ghcr.io/beigesys/viaos:latest
```

A matching Caddyfile:

```text
via.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

The proxy must pass WebSockets through, which Caddy does by default.
Uploads are gigabytes, so it must not cap request bodies.

CI publishes that image from every commit on `main`, as `:latest` and
`:<commit>`, for x86_64. To build it yourself:
`nix build .#via-server-image && docker load < result`, then run
`via-server:latest`.

On Railway: run the image as a service, with a volume on `/data` and
`VIA_PUBLIC_URL`, `VIA_ADMIN_TOKEN` and `VIA_TRUST_PROXY=2` set. To redeploy on every commit, give
the repository a `RAILWAY_SERVICE` variable and a `RAILWAY_TOKEN` secret holding
a project token.

## 2. Make yourself a token

```bash
sudo -u via-server via-server token create ana            # NixOS
docker exec via via-server token create ana               # container
```

That prints a token once, for an admin unless you give it a role:
`--role developer --fleet line-07`. See [Who can do what](#who-can-do-what).
`token list` shows when each was last used, and `token revoke <name>` revokes
one at once.
Every tool call is audited under the token's name.

## 3. Sign what devices run

```bash
via keygen ~/.config/via/signing.key    # writes signing.key and signing.key.pub
```

Put the `.pub` contents in `trustedKeys` / `VIA_TRUSTED_KEYS`. Every
provisioning image made from then on writes that key into the device's
`viaos.toml`. Those devices then refuse OS updates and app releases that
are not signed by it. Keep the private key off the server: it belongs in
CI or on the machine you release from.

## 4. Signing

Off by default, as on balenaOS: images and releases are plain, devices get
updates from your server over HTTPS, and only an admin can publish an OS. No
key lives on whatever machine ran `via`.

To turn it on later:

- **Release signing.** `via keygen <path>` makes a key. Sign with
  `--sign-key <path>` (or `VIA_SIGNING_KEY`), and give the server the `.pub`
  as `VIA_TRUSTED_KEYS`: it then refuses anything that key didn't sign.
- **Secure Boot.** `via secure-boot keygen <dir>` makes keys; pass
  `--secure-boot <dir>` (or `VIA_SECURE_BOOT_KEYS`) to `via base-image` and
  `via os-release`. A device whose firmware is in setup mode enrolls them on
  first boot and from then on runs only what they signed, so losing them means
  re-imaging those devices. The keys replace the firmware's own, Microsoft's
  included: hardware whose graphics or network card loads a Microsoft-signed
  option ROM won't show a picture or PXE boot.

Keep keys with your release secrets, never on the server.

## 5. Give it an OS

Nothing to do: each `v<N>` release on GitHub carries plain base images
(`viaos-<arch>.raw.zst`), and a server with no base image for an architecture
fetches the latest one at startup, then checks hourly. `VIA_IMAGE_SOURCE`
points it elsewhere (`<source>/viaos-<arch>.raw.zst`), or `none` turns it off.

To use your own build instead:

```bash
export VIA_SERVER=https://via.example.com VIA_TOKEN=<token>
nix build .#images.x86_64 -o image && via base-image image/viaos_1.raw --arch x86_64
nix build .#images.aarch64 -o image-arm && via base-image image-arm/viaos_1.raw --arch aarch64
```

For each new OS version, bump `VERSION` and push a `v<N>` tag:
`.github/workflows/release.yml` builds both architectures and attaches the base
images and OS updates (`viaos-update-<arch>.tar`) to the release. With the
`VIA_SERVER` and `VIA_TOKEN` repository secrets it also publishes them to that
control plane. By hand: `nix build .#updates.x86_64 -o update` and
`via os-release update`.

## 6. Point Claude at it

```bash
claude mcp add --transport http via https://via.example.com/mcp \
  --header "Authorization: Bearer $VIA_TOKEN"
claude mcp add via-local -- sudo -E via mcp    # flashing, releases
```

## Deploy from GitHub

A repository can upload releases from GitHub Actions with no token stored in
it: each run asks GitHub for a short-lived OIDC token made out to your server,
and the server checks GitHub's signature, the repository and the ref.

1. An admin adds the repository on the Access page, under "Publish from
   GitHub", or with `add_publisher`: `owner/name`, the apps it may release, and
   the refs it may release from (`refs/heads/via` and `refs/tags/v*` unless you
   say otherwise; `*` matches anything). The page then shows the workflow file.
2. Add it to the repository as `.github/workflows/via.yml`:

   ```yaml
   name: via
   on:
     push:
       branches: [via]
       tags: ["v*"]
   permissions:
     id-token: write
     contents: read
   jobs:
     release:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: beigesys/viaos/action@main
           with:
             server: https://via.example.com
             app: web
             arch: x86_64 aarch64
   ```

3. Push to `via`, or push a `v*` tag. The action downloads `via` from the
   latest viaos release (`via-version: v<N>` pins one), sets up QEMU when it
   builds for an architecture other than the runner's, and runs `via release`.
   Inputs: `server`, `app`, `file` (default `compose.yaml`), `arch`,
   `working-directory`. Its output `release` is the number it got.

A run's token can upload releases of the repository's apps and do nothing
else: not `/mcp`, not a deploy, not another app. `server` must be the server's
`VIA_PUBLIC_URL` exactly, because that is who the token is made out to. The
repository's numeric id is pinned the first time it publishes (or when you give
`repository_id`), so a repository deleted and made again, or a renamed one
whose old name someone else took, is refused until an admin adds it again.
Pull requests from forks get no token. Each upload is audited as
`github-actions:<owner/name>@<ref>`.

Without `--release`, `via release` asks the server for the next number, one
more than the highest the app has. Every ask gets a new number, so re-running a
workflow makes a new release and never meets the old one, and numbers made by
hand and by CI share one count. A build that fails after asking leaves a gap.
Elsewhere than GitHub, `VIA_TOKEN` still works, in the action too.

### Following

A fleet can follow an app: each release uploaded from then on is deployed to
its devices, and those of the fleets under it, as each architecture's build
arrives. Set it on the fleet's Releases tab under "Deploy new releases", or
with `follow_app`; it needs developer on the fleet. It is the same deploy a
person starts, held to the health gate and rolled back on the device if it
fails. A device that was offline, or joins the fleet later, gets the newest
such release when it connects. Each device is sent a release once:
one that failed its gate isn't sent it again, and one someone deployed an older
release to by hand keeps it until the next. Every deploy is in the audit log as
`auto_deploy`.

## Variables and secrets

A release holds no secrets. In the compose file, a bare name says a service
needs a value the release does not carry:

```yaml
services:
  web:
    environment:
      - API_KEY          # supplied per fleet or device
      - LOG_LEVEL=info   # baked into the release
```

Set values on the console's Variables page (or with `set_variable`), for a
whole fleet or one device, and for every service that declares the name or just
one of them. A value can also be for every app (leave out `app`), like a site id
that each app reads: it reaches any service, in any app, that declares the name.
The strongest value wins, weakest first:

1. the release's default (below)
2. fleet, for every app
3. fleet
4. fleet, for one service
5. device, for every app
6. device
7. device, for one service

A device's value always beats a fleet's, even one aimed at a service. A service
never receives a name it did not declare, however the value was aimed.

Online devices re-apply at once and offline ones catch up when they reconnect.
Only containers whose environment actually changed are replaced. Every other
container keeps running with the same ID, including ones that `depends_on` the
replaced service, because each container is compared on its own and nothing
cascades. A value set for one service leaves the rest alone, and so does moving
a value between layers without changing it. The change still answers to the
health gate: if it fails, the device puts back the last values that passed,
replacing only those containers again, and `deploy.state` in `device_health`
says `rolled_back`. The value you set stays on the server, and the device tries
again the next time it changes. A device page warns when a running release is
missing a name.

Mark a value secret and it is encrypted on the server and never shown again.
The key is `secret.key` in the data directory, or `VIA_SECRET_KEY`: back it up
separately from the database, because without it the secrets are gone, and
with it a stolen backup is readable. Devices receive plaintext over their TLS
connection and keep it readable by root only, in `/var/lib/via/env.json` and, as
the last values that passed the gate, in each release's `applied-env.json`, so
a release restarts, rolls back and recovers with no network. Don't give Claude
a real secret: it would pass through the conversation. Use the console.

### Describing them in the release

A top-level `x-via` in the compose file says what a release takes. Every field
is optional, and a plain `docker compose up` ignores it:

```yaml
x-via:
  variables:
    API_KEY: { description: "Key for the upstream API", secret: true, services: [web] }
    LOG_LEVEL: { description: "How much to say", default: "info" }
```

- `services` gives the name to those services, the same as each listing a bare
  `- KEY`. Services that list it, or use `${KEY}`, get it as well.
- `default` is the weakest value. It is written into the release, so a device
  applies it offline. A name with a default never counts as missing.
- `required` defaults to true, or false if there is a default. An optional name
  with no value isn't reported as missing.
- `secret: true` tells the console to ask for a secret. It can't have a default,
  because a release holds no secrets; the build refuses it. It doesn't stop
  someone setting a plain value.

`${KEY}` anywhere in a service works as it does in Compose, including `:-`
defaults and `:?` errors, and its value comes from the app's variables. A value
set for one service reaches that container's environment; `${KEY}` is read once
for the whole file, so it takes the app's value.

Bad names and a secret with a default fail the build. A release with
no `x-via` still works, and its bare names are reported as required. `via-server`
reads this from the release's `deployment.json` when a bundle is uploaded and
keeps it beside the bundle; it never parses compose or runs anything from a
bundle. `list_variables` returns each app's newest release's description under
`schemas`.

## The web console

It is the server's own address, with nothing more to install. Navigation is one
hierarchy, Fleets > fleet > device, with Apps and OS beside it, and the sidebar
opens out as you go. Sign in with an API token or GitHub, and see only the
fleets you have a role on, with only the controls that role allows. It calls the
same tools Claude does, so the audit log covers both.

### Who can do what

Admins can do everything. Anyone else gets a role on a fleet, which covers every
fleet under it, or on every fleet, from the Access page or `set_grant`:

| Role | Can |
|---|---|
| Observer | See the fleet's devices, health, logs, journal, releases and variables |
| Operator | Also change its devices' tags and their own variables |
| Developer | Also deploy, update the OS, set the fleet's variables, run commands and open terminals on its devices, enroll devices, and add, move or delete fleets under it |

A grant names a GitHub user (`github:<login>`), a GitHub team
(`github-team:<slug>`), everyone in the GitHub organisation (`github-org`), or an
API token (`token:<name>`); someone gets the strongest role any of those gives
them. Fleets and devices outside your grants don't exist for you: they aren't
listed, and naming one gets "no fleet named". A new server has no grants, so only
admins can do anything until you give out roles. A server upgraded from before
roles grants `github-org` observer on every fleet, which is what members could do
before; remove that grant to let in only the people and teams you name.

Still an admin's alone: tokens, grants, the audit log, device types, OS updates
and base images, fleets at the top level, and which repositories publish from
GitHub. Uploading an app release needs developer on some fleet, since apps
aren't any one fleet's, or a GitHub Actions run of a repository that publishes
the app (see [Deploy from GitHub](#deploy-from-github)).

`via-server token create ci --role developer --fleet line-07` makes a token
with a role on one fleet; leave out `--fleet` for every fleet.

### Fleets inside fleets

Fleets nest as deep as you like, so a level can mean a customer, a site or a
house. A fleet's variables reach everything under it, and the nearer fleet wins,
with the device above them all. A deploy or OS update sent to a fleet covers
everything under it too, and the preview lists which devices that is. Tags, such
as `customer:acme`, are labels for finding fleets from the Fleets page and change
nothing else. Names stay unique across the whole tree. Each fleet's Settings page
moves it, tags it, or deletes it once it's empty.

### Signing in with GitHub

1. Create an OAuth app under your organisation's settings. Its callback URL is
   `<public url>/v1/auth/github/callback`.
2. Give the server `VIA_GITHUB_CLIENT_ID`, `VIA_GITHUB_CLIENT_SECRET` and
   `VIA_GITHUB_ORG` (with the NixOS module: `github.clientId`, `github.org`, and
   the secret in `environmentFile`).
3. If the organisation restricts OAuth apps, an owner approves this one.

Only active members of the organisation get in. Its owners are admins, and so is
anyone on the team named by `VIA_GITHUB_ADMIN_TEAM`. Other members get what
grants give them, and a member with none is turned away. Team grants are checked
at sign-in, members of child teams included, so a new team grant reaches someone
when they next sign in; grants to a user or the organisation apply at once. A
session lasts 12 hours, so someone removed from the organisation or a team loses
access within that time. For GitHub Enterprise Server, set `VIA_GITHUB_URL`.

Requests from people not signed in (signing in, OAuth, enrolling, and tokens
the server doesn't know) are limited to 30 a minute from each address, with a
burst of 30; a refused enrollment counts, a good one doesn't. Behind proxies,
set `VIA_TRUST_PROXY` to how many add to X-Forwarded-For (1 for one nginx, 2 on
Railway) so the limit applies to the client rather than to the proxy. Signed-in requests aren't
limited.


### Connecting Claude with GitHub

With GitHub sign-in on, an MCP client needs no token:

```bash
claude mcp add --transport http via https://via.example.com/mcp
```

Then `/mcp` in Claude Code to sign in. In claude.ai, add
`https://via.example.com/mcp` as a custom connector. Either way you sign in with
GitHub in a browser and approve the client on a page that says where its access
is going. It gets your roles, and works on `/mcp` alone.

Access tokens last an hour, and each refresh asks GitHub again, so someone
removed from the organisation is out within the hour. GitHub's token for each
connection is kept sealed with the server's secret key. An admin can see every
connection on the Access page and revoke one at once.

### Hardware

What Enroll offers comes from the server, so adding a board needs no console
change:

```bash
via-server device-type set rock-5b --name "Rock 5B" --arch aarch64 --detail "RK3588, UEFI"
via-server device-type list
via-server device-type remove rock-5b
```

A type uses `viaos-<id>.raw` if one was uploaded with `via base-image
--device-type <id>`, and otherwise the base image for its architecture.
Enroll marks a type with neither as `no image`. The arm64 base image serves both
Raspberry Pi and generic UEFI boards. Registering a type doesn't build an OS for
it: x86_64 and aarch64 are the architectures this repository builds.

To work on it:

```bash
cd web && bun install
VIA_SERVER=http://localhost:8471 bun run dev
```

`bun run build` and a rebuild of `via-server` embed it. After changing
`web/bun.lock`, update the hash in `nix/web.nix`.

## Reaching a device

Devices are behind NAT, so everything goes over their own connection:

```bash
via ssh line-07                   # a shell (needs your key in the device's ssh keys)
via ssh line-07 journalctl -b     # a command
via forward line-07 8080 9000     # localhost:9000 on your machine -> device port 8080
```

Claude uses `exec` for the same thing, and the console has a terminal for the
device and for each of its containers.
