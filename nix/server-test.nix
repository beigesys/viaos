# The control plane as the NixOS module runs it: behind Caddy, with tokens,
# roles, MCP, WebSockets and a large upload going through the proxy.
{ self, pkgs }:
pkgs.testers.runNixOSTest {
  name = "via-server";
  nodes.machine = {
    imports = [ self.nixosModules.via-server ];
    services.via-server = {
      enable = true;
      domain = "via.test";
    };
    # No ACME in the sandbox: Caddy's own CA instead.
    services.caddy.globalConfig = "local_certs";
    networking.hosts."127.0.0.1" = [ "via.test" ];
    environment.systemPackages = [ pkgs.curl ];
    virtualisation.diskSize = 2048;
  };
  testScript = ''
    import json

    def mcp(token, method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
        out = machine.succeed(
            f"curl -sf http://127.0.0.1:8471/mcp -H 'Authorization: Bearer {token}' "
            "-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' "
            "-H 'MCP-Protocol-Version: 2025-06-18' "
            f"-d '{body}'"
        )
        return json.loads(out)

    def call(token, tool, args):
        return mcp(token, "tools/call", {"name": tool, "arguments": args})["result"]

    machine.wait_for_unit("via-server.service")
    machine.wait_until_succeeds("curl -sf http://127.0.0.1:8471/healthz")

    admin = machine.succeed("sudo -u via-server VIA_DATA_DIR=/var/lib/via-server via-server token create ana").strip()
    viewer = machine.succeed("sudo -u via-server VIA_DATA_DIR=/var/lib/via-server via-server token create bo --role observer").strip()

    machine.fail("curl -sf http://127.0.0.1:8471/mcp -H 'Authorization: Bearer nope' -d '{}'")

    r = call(admin, "create_fleet", {"fleet": "line"})
    assert not r.get("isError"), r
    r = call(viewer, "list_fleets", {})
    assert r["structuredContent"]["fleets"][0]["name"] == "line", r
    r = call(viewer, "create_fleet", {"fleet": "other"})
    assert r.get("isError"), r
    # A role on one fleet sees only that fleet.
    call(admin, "create_fleet", {"fleet": "other"})
    dev = machine.succeed("sudo -u via-server VIA_DATA_DIR=/var/lib/via-server via-server token create ci --role developer --fleet other").strip()
    r = call(dev, "list_fleets", {})
    assert [f["name"] for f in r["structuredContent"]["fleets"]] == ["other"], r
    assert r["structuredContent"]["fleets"][0]["access"] == "developer", r

    # Base images and OS updates are an admin's.
    machine.fail(f"curl -sf -X PUT http://127.0.0.1:8471/v1/base/x86_64 -H 'Authorization: Bearer {viewer}' -d x")

    # Through Caddy, over TLS: the API, a WebSocket upgrade (a device's
    # connection; refused for want of a credential, but by via-server, not
    # the proxy), and an upload bigger than any default body limit.
    machine.wait_for_unit("caddy.service")
    ca = "/var/lib/caddy/.local/share/caddy/pki/authorities/local/root.crt"
    https = f"curl -sf --cacert {ca} https://via.test"
    machine.wait_until_succeeds(f"{https}/healthz")
    code = machine.succeed(
        f"curl -s -o /dev/null -w '%{{http_code}}' --cacert {ca} --http1.1 https://via.test/v1/connect "
        "-H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' "
        "-H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='"
    )
    assert code == "401", code

    # The console is compiled in, and a token buys a cookie that works in its
    # place and carries the viewer's limits with it.
    page = machine.succeed(f"{https}/some/deep/link")
    assert '<div id="root">' in page, page
    headers = machine.succeed(
        f"curl -si --cacert {ca} https://via.test/v1/session -H 'Content-Type: application/json' "
        f"-d '{{\"token\": \"{viewer}\"}}'"
    )
    assert "HttpOnly" in headers and "SameSite=Strict" in headers and "Secure" in headers, headers
    cookie = f"-H 'Cookie: via_session={viewer}'"
    who = json.loads(machine.succeed(f"{https}/v1/session {cookie}"))
    assert who == {"name": "bo", "role": "member", "subjects": ["token:bo"]}, who
    machine.fail(f"{https}/v1/session {cookie} -H 'Origin: https://evil.example'")

    # Secrets: write-only, and encrypted at rest.
    r = call(admin, "set_variable", {"app": "hello", "key": "API_KEY", "value": "hunter2hunter2", "secret": True, "fleet": "line"})
    assert not r.get("isError"), r
    r = call(viewer, "set_variable", {"app": "hello", "key": "X", "value": "y", "fleet": "line"})
    assert r.get("isError"), r
    r = call(viewer, "list_variables", {})
    assert r["structuredContent"]["variables"][0]["value"] is None, r
    machine.fail("grep -rq hunter2hunter2 /var/lib/via-server")
    machine.succeed("test $(stat -c %a /var/lib/via-server/secret.key) = 600")

    machine.succeed("head -c 300M /dev/urandom > /tmp/big")
    machine.succeed(f"{https}/v1/os/x86_64/9/viaos_9.efi -X PUT -H 'Authorization: Bearer {admin}' -T /tmp/big")
    machine.succeed("cmp /tmp/big /var/lib/via-server/os/x86_64/9/viaos_9.efi || cmp /tmp/big $(find /var/lib/via-server -name viaos_9.efi | head -1)")

    machine.succeed("sudo -u via-server VIA_DATA_DIR=/var/lib/via-server via-server token revoke bo")
    machine.fail(f"curl -sf http://127.0.0.1:8471/mcp -H 'Authorization: Bearer {viewer}' -d '{{}}'")
  '';
}
