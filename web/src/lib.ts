// Everything the console knows, it asks through the same MCP tools Claude
// uses. Roles and the audit log therefore cover both, with nothing to keep in
// step.

export class SignedOut extends Error {}

const PROTOCOL = "2026-07-28";

export async function tool<T = any>(name: string, args: Record<string, unknown> = {}): Promise<T> {
  const res = await fetch("/mcp", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      "MCP-Protocol-Version": PROTOCOL,
      "Mcp-Method": "tools/call",
      "Mcp-Name": name,
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: {
        name,
        arguments: args,
        _meta: {
          "io.modelcontextprotocol/protocolVersion": PROTOCOL,
          "io.modelcontextprotocol/clientInfo": { name: "via-console", version: "0" },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    }),
  });
  if (res.status === 401) throw new SignedOut("signed out");
  if (!res.ok) throw new Error((await res.text()) || `${name}: ${res.status}`);
  const body = await res.json();
  if (body.error) throw new Error(body.error.message);
  const r = body.result;
  const text = r.content?.[0]?.text ?? "";
  if (r.isError) throw new Error(text || `${name} failed`);
  if (r.structuredContent) return r.structuredContent;
  try {
    return JSON.parse(text);
  } catch {
    return text as T;
  }
}

export type Caller = { name: string; role: "admin" | "member" };

/** A role on a fleet. Each can do what the ones before it can. */
export type Level = "observer" | "operator" | "developer";
const RANK: Record<Level, number> = { observer: 1, operator: 2, developer: 3 };
export const atLeast = (has: Level | undefined, need: Level) => !!has && RANK[has] >= RANK[need];

export async function whoami(): Promise<Caller | null> {
  const res = await fetch("/v1/session");
  return res.ok ? res.json() : null;
}

export async function signIn(token: string): Promise<Caller> {
  const res = await fetch("/v1/session", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) throw new Error(res.status === 401 ? "That token isn't one this server knows." : await res.text());
  return res.json();
}

export async function authOptions(): Promise<{ github: { org: string } | null }> {
  const res = await fetch("/v1/auth");
  return res.ok ? res.json() : { github: null };
}

export async function signOut() {
  await fetch("/v1/session", { method: "DELETE" });
}

export type Device = {
  id: string;
  /** Its slug. */
  name: string;
  /** What people call it; empty means use the slug. */
  title: string;
  note: string;
  fleet: string;
  arch: string | null;
  os_version: string | null;
  agent_version: string | null;
  enrolled_at: number;
  last_seen: number | null;
  online: boolean;
  os_update?: OsUpdate;
  /** Its own. */
  tags: string[];
  /** From the fleets it sits in. */
  inherited_tags?: string[];
};

export type OsUpdate = {
  version: string;
  from_version: string | null;
  started_at: number;
  finished_at: number | null;
  state: string;
  progress: number | null;
  detail: string | null;
  offline_since: number | null;
};

/** One reading: `memory_mb` for the device, and each service's. */
export type MetricSample = { at: number; memory_mb: number; cpu_percent: number; services: Record<string, { memory_mb: number; cpu_percent: number }> };
export type Metrics = {
  interval_secs: number;
  memory_total_mb: number | null;
  samples: MetricSample[];
  processes: { name: string; processes: number; mb: number }[];
  disk: { device: string; total_mb: number; unallocated_mb: number; partitions: { device: string; label: string | null; size_mb: number; in_use_as: string | null; free_mb: number | null }[] } | null;
  docker: { images_mb: number; containers_mb: number; volumes_mb: number; build_cache_mb: number } | null;
  volumes: { name: string; declared: boolean; used_by: string[]; mb: number | null; containers?: number }[] | null;
};

/** `access` is the caller's role on it. */
export type Fleet = { name: string; title: string; note: string; parent: string | null; tags: string[]; devices: number; access: Level };

/** What to call a fleet or device: its title, or its slug without one. */
export const called = (x: { name: string; title?: string } | undefined, fallback = "") => x?.title || x?.name || fallback;

/** The server's slug rule: lowercase letters, digits and single dashes. */
export function slug(from: string): string {
  return from
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+/, "")
    .slice(0, 63)
    .replace(/-+$/, "");
}

/** A fleet and those above it, outermost first. */
export function lineage(fleets: Fleet[], name: string): string[] {
  const out: string[] = [];
  for (let f = fleets.find((x) => x.name === name); f && !out.includes(f.name); f = fleets.find((x) => x.name === f?.parent)) out.unshift(f.name);
  return out;
}

/** A fleet and everything under it. */
export function under(fleets: Fleet[], name: string): string[] {
  const out = [name];
  for (let i = 0; i < out.length; i++) for (const f of fleets) if (f.parent === out[i] && !out.includes(f.name)) out.push(f.name);
  return out;
}

export type Release = {
  app: string;
  release: number;
  artifacts: { arch: string; sha256: string; size_mb: number }[];
};

/** `variant` (e.g. `nvidia`) is absent for the plain OS. */
export type OsVersion = { arch: string; variant?: string; version: string; files: string[]; size_mb: number };

export type Variable = {
  app: string;
  service?: string | null;
  key: string;
  scope: "fleet" | "device";
  target: string;
  secret: boolean;
  value: string | null;
  updated_at: number;
  updated_by: string;
};

export type SchemaVariable = {
  key: string;
  services: string[];
  description: string | null;
  default: string | null;
  secret: boolean;
  required: boolean;
};

export type Schema = { app: string; release: string | number; variables: SchemaVariable[] };

/** Newest first, comparing the numbers inside version strings as numbers. */
export function byVersionDesc(a: string | number, b: string | number) {
  return String(b).localeCompare(String(a), undefined, { numeric: true });
}

export type Health = {
  host: {
    hostname: string;
    os: string | null;
    kernel: string | null;
    uptime_secs: number | null;
    load: [number, number, number] | null;
    cpus: number;
    memory: { total_mb: number; available_mb: number; used_percent: number } | null;
    disks: { mount: string; total_mb: number; free_mb: number; used_percent: number }[];
    temperatures_c: { zone: string; celsius: number }[];
  };
  os: {
    version: string | null;
    secure_boot: boolean;
    update: { version: string; state: string; progress_percent?: number; error?: string } | null;
  };
  engine: { version?: string; error?: string } | null;
  release: {
    app?: string;
    current: string | null;
    previous: string | null;
    deploying: string | null;
    converged: boolean;
    missing_env?: Record<string, string[]>;
    error?: string;
  };
  deploy: { app: string; release: number; state: string; error?: string; rolled_back_to?: string } | null;
  services: { service: string; container?: string; status: string; health: string }[] | { error: string };
};

export function ago(unix: number | null | undefined): string {
  if (!unix) return "never";
  const s = Math.max(0, Date.now() / 1000 - unix);
  if (s < 10) return "just now";
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function duration(secs: number | null | undefined): string {
  if (secs == null) return "–";
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  return `${Math.floor(secs / 86400)}d ${Math.floor((secs % 86400) / 3600)}h`;
}

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return n < 1073741824 ? `${(n / 1048576).toFixed(1)} MB` : `${(n / 1073741824).toFixed(2)} GB`;
}

export function gb(mb: number): string {
  return mb < 1024 ? `${mb} MB` : `${(mb / 1024).toFixed(1)} GB`;
}

export function when(unix: number): string {
  return new Date(unix * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Whether tags satisfy a filter: the exact tag, or a bare key for any value of it. */
export function hasTag(tags: string[], wanted: string): boolean {
  return tags.some((t) => t === wanted || t.startsWith(`${wanted}=`));
}

/** A fleet's tags and those of the fleets above it. */
export function fleetTags(fleets: Fleet[], name: string): string[] {
  return [...new Set(lineage(fleets, name).flatMap((n) => fleets.find((f) => f.name === n)?.tags ?? []))];
}

/** Each tag, and each key that has values, for a filter to offer. */
export function tagChoices(tags: string[]): { value: string; label: string; detail?: string }[] {
  const keys = [...new Set(tags.filter((t) => t.includes("=")).map((t) => t.split("=")[0]))];
  return [
    ...keys.map((k) => ({ value: k, label: k, detail: "any value" })),
    ...[...new Set(tags)].filter((t) => !keys.includes(t)).map((t) => ({ value: t, label: t })),
  ].sort((a, b) => a.value.localeCompare(b.value));
}
