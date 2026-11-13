# MCP surface

Claude is the first way in. Every operation is a typed function first; MCP
tools, the CLI, and the web console (which calls these same tools) sit on top.

## Target prompts

These are the acceptance tests. A tool exists because one of these needs it.

| Prompt | Tools | Status |
| --- | --- | --- |
| "How's line-07 doing?" | `list_devices`, `device_health`, `logs`, `journal`, `exec` | works |
| "Update all of fleet X to version Y" (OS) | `list_os_versions`, `update_os` (dry_run first) | works |
| "Update all of fleet X to version Y" (apps) | local `release_app`, then `list_releases`, `deploy` (dry_run first) | works, including rollback on a failed health gate |
| "Provision the attached device" | `create_provisioning_image`, then local `list_disks`, `flash_image` | works; not yet tried on a real card |
| "Make a provisioning image for a Pi and an x86 box on fleet X" | `create_provisioning_image` x2 | works: both enrolled into one fleet (Pi image booted in emulated arm64 UEFI; not yet on a real Pi) |

## Servers

| Server | Where | Tools |
| --- | --- | --- |
| device | `via-agent mcp` on the device (stdio) | `device_health`, `logs`, `journal`, `exec`, `os_update`, `deploy`, `sync_env` |
| fleet | `via-server` at `/mcp` (HTTP, API token or GitHub sign-in) | `list_fleets`, `device_metrics`, `create_fleet`, `update_fleet`, `update_device`, `delete_fleet`, `list_devices`, `device_health`, `logs`, `journal`, `exec`, `list_os_versions`, `update_os`, `list_releases`, `release_details`, `release_contents`, `os_version_details`, `deploy`, `create_provisioning_image`, `list_provisioning_images`, `fleet_provisioning`, `set_fleet_provisioning`, `list_variables`, `set_variable`, `update_variables`, `delete_variable`, `set_device_type`, `delete_device_type`, `audit_log`, `list_tokens`, `create_token`, `revoke_token`, `list_connections`, `revoke_connection`, `list_grants`, `set_grant`, `delete_grant` |
| local | `via mcp` on the operator's machine (stdio, root) | `list_disks`, `flash_image`, `flash_status`, `release_app` |

The fleet server forwards device tools over each device's outbound
connection, adding only a `device` argument, so a tool behaves the same
through the control plane as over `ssh device via-agent mcp`.

## Variables

`set_variable` and `delete_variable` take the `app` and `key`, exactly one of
`fleet` or `device`, and optionally a `service`; without one, the value is for
every service that declares the name. Without `app` it is for every app (and
can't name a service), stored with `app` as `""`. `set_variable` also takes `value` and
`secret`. It adds a `warning` to its result when the app's newest release doesn't
give that name to that service. Each value is stored separately, so deleting the
one for a service leaves the rest.

`sync_env`, which the server calls, takes `apps` and `services`, and a name left
out is removed. `list_variables` returns:

```json
{
  "variables": [
    { "scope": "fleet", "target": "lab", "app": "hello", "service": "web",
      "key": "API_KEY", "value": null, "secret": true,
      "updated_at": 1793622449, "updated_by": "admin" }
  ],
  "schemas": [
    { "app": "hello", "release": "1", "variables": [
      { "key": "API_KEY", "services": ["web"], "description": "...",
        "default": null, "secret": true, "required": true }
    ] }
  ]
}
```

`service` is null for a value that isn't aimed at one service, and `value` is
null for a secret. `schemas` has each app's newest release, and its `variables`
are what that release describes in `x-via` plus any bare `- KEY` it doesn't
describe. [deploy.md](deploy.md#variables-and-secrets) has the precedence.

## Rules

1. Every tool carries MCP's read-only or destructive hint. Tools that change
   many devices take `dry_run` and return the plan when it is set.
2. Long work returns at once and reports progress where the caller already
   looks: an OS update under `os.update` in `device_health`, a flash in
   `flash_status`.
3. No tool returns a secret, with one exception: `create_token` returns the
   new token, once, because that is its job. Enrollment tokens are written
   straight into an image or onto a device; the tool returns a path or a
   device id, never the token. Secret variables are write-only, and no
   variable's value goes in the audit log.
4. Every fleet call is written to the audit log with the token's name, its
   arguments and whether it succeeded.
5. A token that isn't an admin's reaches only the fleets its grants cover,
   and only as far as its role there allows; anything else answers with an
   error naming the role needed, or as if the fleet or device didn't exist.
   See "Who can do what" in deploy.md.

## Provisioning without a rebuild

One generic image per architecture (`x86_64`, `aarch64`). Provisioning writes
`viaos.toml` (control plane URL, single-use enrollment token, hostname) onto
the image's FAT boot partition. `create_provisioning_image` copies the base
image, writes that one file and compresses the result: about 7 seconds, no
Nix on the server.

The same file carries the device's network and system settings: `[[wifi]]`,
`[network]`, `[time]` and `[proxy]` (see `nix/viaos.example.toml`).
`via-agent system` applies them early in every boot, before networkd, iwd,
timesyncd and Docker start. A fleet can keep defaults for them with
`set_fleet_provisioning`; a new image takes each section from the nearest
fleet up the tree that sets it, unless `create_provisioning_image` is given
its own. Wi-Fi passphrases are sealed like secrets and shown only as
`has_passphrase`.
