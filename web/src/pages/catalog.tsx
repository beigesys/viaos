import { useQueries, useQuery } from "@tanstack/react-query";
import { lazy, Suspense, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ago, byVersionDesc, bytes, gb, tool, type Health, type OsVersion, type Release, type SchemaVariable } from "../lib";
import { Badge, Button, Combobox, Copy, Empty, Failure, Headline, Pip, Section } from "../ui";
import { devicePath, fleetPath, fleetTrail, useDevices, useFleets } from "./fleet";

const Editor = lazy(() => import("../editor"));

export const appPath = (app: string) => `/apps/${encodeURIComponent(app)}`;
export const releasePath = (app: string, release: number | string) => `${appPath(app)}/releases/${release}`;
export const osPath = (version: string) => `/os/${encodeURIComponent(version)}`;

/** Where a release page sits: under the device or fleet it was reached from,
 *  or under Apps. Its own links and breadcrumbs stay there. */
function useReleaseScope(app: string, release: string): { base: string; trail: [string, string][]; heading: string } {
  const { fleet, device } = useParams();
  const fleets = useFleets();
  if (fleet) {
    const owner = device ? devicePath(fleet, device) : fleetPath(fleet);
    return {
      base: `${owner}/releases/${encodeURIComponent(app)}/${release}`,
      trail: [...fleetTrail(fleets.data, fleet, true), ...(device ? ([[device, owner]] as [string, string][]) : []), ["Releases", `${owner}/releases`]],
      heading: `${app} · release ${release}`,
    };
  }
  return { base: releasePath(app, release), trail: [["Apps", "/apps"], [app, appPath(app)]], heading: `release ${release}` };
}

function useReleases() {
  return useQuery({ queryKey: ["releases"], queryFn: () => tool<{ releases: Release[] }>("list_releases").then((r) => r.releases) });
}

function useOsVersions() {
  return useQuery({ queryKey: ["os-versions"], queryFn: () => tool<{ versions: OsVersion[] }>("list_os_versions").then((r) => r.versions) });
}

/** Which devices run what. Only devices know, so this asks the connected ones. */
const ASK_AT_MOST = 50;
export function useRunning() {
  const devices = useDevices();
  const online = (devices.data ?? []).filter((d) => d.online).slice(0, ASK_AT_MOST);
  const health = useQueries({
    queries: online.map((d) => ({
      queryKey: ["health", d.name],
      queryFn: () => tool<Health>("device_health", { device: d.name }),
      refetchInterval: 15000,
    })),
  });
  return online.flatMap((d, i) => {
    const r = health[i].data?.release;
    return r?.app && r.current ? [{ device: d, app: r.app, release: String(r.current) }] : [];
  });
}

function Table({ heads, children }: { heads: [string, string?][]; children: React.ReactNode }) {
  return (
    <div className="border border-rule bg-sheet">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-rule bg-well text-left">
            {heads.map(([h, c]) => (
              <th key={h} className={`label px-3 py-1.5 font-medium ${c ?? ""}`}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

const tr = "h-10 cursor-pointer border-b border-rule transition-colors last:border-b-0 hover:bg-well max-sm:h-11";
const td = "px-3";

function DeviceLinks({ devices, none }: { devices: { name: string; fleet: string; online: boolean }[]; none: string }) {
  if (devices.length === 0) return <p className="py-2 text-sm text-ink-3">{none}</p>;
  return (
    <>
      {devices.map((d) => (
        <Link key={`${d.fleet}/${d.name}`} to={devicePath(d.fleet, d.name)} className="flex items-center gap-2.5 row text-sm hover:bg-well">
          <Pip state={d.online ? "ok" : "bad"} />
          <span className="font-mono font-medium">{d.name}</span>
          <span className="ml-auto font-mono text-xs text-ink-3">{d.fleet}</span>
        </Link>
      ))}
    </>
  );
}

export function AppsPage() {
  const nav = useNavigate();
  const releases = useReleases();
  const running = useRunning();
  const apps = Object.entries((releases.data ?? []).reduce<Record<string, Release[]>>((all, r) => ((all[r.app] ??= []).push(r), all), {}));
  return (
    <>
      <Headline>Apps</Headline>
      <Failure error={releases.error} />
      {releases.isSuccess && apps.length === 0 && (
        <div className="border border-rule bg-sheet px-3">
          <Empty title="No apps yet.">Build and upload one from a compose file with <code className="font-mono text-xs">via release</code>.</Empty>
        </div>
      )}
      {apps.length > 0 && (
        <Table heads={[["App"], ["Latest"], ["Releases", "max-sm:hidden"], ["Running on", "text-right"]]}>
          {apps.map(([app, rs]) => (
            <tr key={app} className={tr} onClick={() => nav(appPath(app))}>
              <td className={td}>
                <Link to={appPath(app)} onClick={(e) => e.stopPropagation()} className="font-mono font-semibold">
                  {app}
                </Link>
              </td>
              <td className={`${td} font-mono text-xs`}>{Math.max(...rs.map((r) => r.release))}</td>
              <td className={`${td} font-mono text-xs text-ink-2 max-sm:hidden`}>{rs.length}</td>
              <td className={`${td} text-right font-mono text-xs`}>{running.filter((r) => r.app === app).length}</td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}

export function AppPage() {
  const { app = "" } = useParams();
  const nav = useNavigate();
  const releases = useReleases();
  const running = useRunning().filter((r) => r.app === app);
  const rs = (releases.data ?? []).filter((r) => r.app === app).sort((a, b) => b.release - a.release);
  return (
    <>
      <Headline trail={[["Apps", "/apps"]]}>{app}</Headline>
      <Failure error={releases.error} />
      {releases.isSuccess && rs.length === 0 && (
        <div className="border border-rule bg-sheet px-3">
          <Empty title="No releases of this app." />
        </div>
      )}
      {rs.length > 0 && (
        <Table heads={[["Release"], ["Builds"], ["Running on", "text-right"]]}>
          {rs.map((r, i) => (
            <tr key={r.release} className={tr} onClick={() => nav(releasePath(app, r.release))}>
              <td className={td}>
                <span className="flex items-center gap-2">
                  <Link to={releasePath(app, r.release)} onClick={(e) => e.stopPropagation()} className="font-mono font-semibold">
                    {r.release}
                  </Link>
                  {i === 0 && <Badge tone="latest">latest</Badge>}
                  {running.some((x) => x.release === String(r.release)) && <Badge tone="running">running</Badge>}
                </span>
              </td>
              <td className={`${td} font-mono text-xs text-ink-2`}>{r.artifacts.map((a) => `${a.arch} ${gb(a.size_mb)}`).join(", ")}</td>
              <td className={`${td} text-right font-mono text-xs`}>{running.filter((x) => x.release === String(r.release)).length}</td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}

type Port = { host_ip?: string; host_port?: number; container_port: number; protocol?: string };
type Mount = { type?: string; source?: string; target?: string };
type Details = {
  uploaded_at: number;
  artifacts: { arch: string; sha256: string; size_mb: number }[];
  services: { name: string; image: string | { reference?: string; digest?: string }; ports: Port[]; depends_on: string[]; healthcheck: boolean; restart: unknown; mounts: Mount[]; privileged: boolean; network_mode: string | null; takes: string[] }[];
  volumes: string[];
  networks: string[];
  health_gate: { timeout_secs: number; stable_secs: number };
  variables: SchemaVariable[];
};

function Row({ k, children }: { k: string; children: React.ReactNode }) {
  return (
    <div className="row justify-between gap-4 text-sm">
      <span className="label">{k}</span>
      <span className="min-w-0 text-right font-mono text-xs break-words">{children}</span>
    </div>
  );
}

const portText = (p: Port) => `${p.host_port ?? "auto"}:${p.container_port}${p.protocol && p.protocol !== "tcp" ? `/${p.protocol}` : ""}`;

type ImageInfo = {
  reference: string;
  digest: string;
  media_type: string;
  size: number;
  layers: { digest: string; size: number }[];
  created: string | null;
  architecture: string | null;
  os: string | null;
  config: { Env?: string[]; Entrypoint?: string[] | null; Cmd?: string[] | null; User?: string; WorkingDir?: string; ExposedPorts?: Record<string, unknown>; Labels?: Record<string, string> | null; Volumes?: Record<string, unknown> | null; StopSignal?: string } | null;
  config_text: string | null;
  manifest_text: string | null;
};
type Contents = {
  arch: string;
  builds: string[];
  created_at: string | null;
  builder: string | null;
  compose: string | null;
  deployment: string;
  bundle_manifest: string;
  images: ImageInfo[];
  files: { path: string; size: number; role: string }[];
};

function TextFile({ text, language, label }: { text: string; language: "yaml" | "json"; label: string }) {
  return (
    <div className="flex h-[calc(100dvh-5.5rem)] min-h-64 flex-col">
      <div className="mb-2 flex items-center justify-between gap-3">
        <span className="font-mono text-xs text-ink-3">{label}</span>
        <Copy text={text} />
      </div>
      <div className="min-h-0 flex-1">
        <Suspense fallback={<div className="h-full border border-rule bg-well" />}>
          <Editor key={text} value={text} language={language} label={label} fill />
        </Suspense>
      </div>
    </div>
  );
}

function ImageCard({ image }: { image: ImageInfo }) {
  const [raw, setRaw] = useState<"" | "config" | "manifest">("");
  const c = image.config;
  const list = (v?: string[] | null) => (v?.length ? v.join(" ") : null);
  const facts: [string, string | null | undefined][] = [
    ["Digest", image.digest],
    ["Size", bytes(image.size)],
    ["Platform", [image.os, image.architecture].filter(Boolean).join("/")],
    ["Built", image.created],
    ["Entrypoint", list(c?.Entrypoint)],
    ["Command", list(c?.Cmd)],
    ["User", c?.User],
    ["Working dir", c?.WorkingDir],
    ["Ports", Object.keys(c?.ExposedPorts ?? {}).join(", ")],
    ["Volumes", Object.keys(c?.Volumes ?? {}).join(", ")],
    ["Stop signal", c?.StopSignal],
  ];
  return (
    <Section
      title={<span className="normal-case">{image.reference}</span>}
      aside={
        <span className="flex gap-1">
          {(["config", "manifest"] as const).map((k) => (
            <Button key={k} tone={raw === k ? "plain" : "quiet"} size="sm" aria-pressed={raw === k} onClick={() => setRaw(raw === k ? "" : k)}>
              {k} json
            </Button>
          ))}
        </span>
      }
    >
      {raw ? (
        <div className="py-3">
          <Suspense fallback={<div className="h-36 border border-rule bg-well" />}>
            <Editor key={raw} value={(raw === "config" ? image.config_text : image.manifest_text) ?? ""} language="json" label={`${image.reference} ${raw}`} />
          </Suspense>
        </div>
      ) : (
        <>
          {facts
            .filter(([, v]) => v)
            .map(([k, v]) => (
              <Row key={k} k={k}>
                <span className="block truncate" title={v ?? undefined}>
                  {v}
                </span>
              </Row>
            ))}
          {(c?.Env ?? []).map((e) => (
            <Row key={e} k={e.split("=")[0]}>
              <span className="block truncate" title={e}>
                {e.slice(e.indexOf("=") + 1)}
              </span>
            </Row>
          ))}
          {Object.entries(c?.Labels ?? {}).map(([k, v]) => (
            <Row key={k} k={k}>
              <span className="block truncate" title={v}>
                {v}
              </span>
            </Row>
          ))}
          {image.layers.map((l, i) => (
            <Row key={l.digest} k={`Layer ${i + 1}`}>
              <span className="flex items-center justify-end gap-3">
                <span className="min-w-0 truncate text-ink-3" title={l.digest}>
                  {l.digest}
                </span>
                <span className="shrink-0">{bytes(l.size)}</span>
              </span>
            </Row>
          ))}
        </>
      )}
    </Section>
  );
}

export function ReleasePage() {
  const { app = "", release = "", view } = useParams();
  const [params, setParams] = useSearchParams();
  const arch = params.get("arch") ?? undefined;
  const titles: Record<string, string> = { compose: "Compose", deployment: "Deployment", images: "Images", files: "Files" };
  const title = view ? titles[view] : undefined;
  const contents = useQuery({
    queryKey: ["release-contents", app, release, arch],
    queryFn: () => tool<Contents>("release_contents", { app, release: Number(release), ...(arch ? { arch } : {}) }),
    enabled: !!view,
  });
  const c = contents.data;
  const scope = useReleaseScope(app, release);
  const trail: [string, string][] = [...scope.trail, ...(title ? ([[scope.heading, scope.base]] as [string, string][]) : [])];
  if (!view) return <ReleaseOverview app={app} release={release} trail={trail} heading={scope.heading} />;
  return (
    <>
      <Headline
        trail={trail}
        aside={
          c && c.builds.length > 1 ? (
            <Combobox aria-label="Build" mono className="w-40" value={c.arch} onChange={(a) => setParams({ arch: a }, { replace: true })} options={c.builds.map((b) => ({ value: b, label: b }))} />
          ) : c ? (
            <span className="font-mono text-xs text-ink-3">{c.arch}</span>
          ) : undefined
        }
      >
        {title ?? view}
      </Headline>
      <Failure error={contents.error} />
      {contents.isPending && <p className="py-3 text-sm text-ink-3">Reading the bundle…</p>}
      {c && view === "compose" &&
        (c.compose != null ? (
          <TextFile text={c.compose} language="yaml" label="compose.yaml, as written" />
        ) : (
          <div className="border border-rule bg-sheet px-3">
            <Empty title="This release was built without its compose file.">The Deployment page shows what it runs.</Empty>
          </div>
        ))}
      {c && view === "deployment" && <TextFile text={c.deployment} language="json" label="deployment.json, what the device actually runs" />}
      {c && view === "images" && c.images.map((i) => <ImageCard key={i.reference} image={i} />)}
      {c && view === "files" && (
        <div className="border border-rule bg-sheet">
          <table className="w-full table-fixed border-collapse text-sm">
            <thead>
              <tr className="border-b border-rule bg-well text-left">
                <th className="label px-3 py-1.5 font-medium">Path</th>
                <th className="label px-3 py-1.5 font-medium max-sm:hidden">What it is</th>
                <th className="label w-24 px-3 py-1.5 text-right font-medium">Size</th>
              </tr>
            </thead>
            <tbody>
              {c.files.map((f) => (
                <tr key={f.path} className="h-10 border-b border-rule last:border-b-0 max-sm:h-11">
                  <td className="truncate px-3 font-mono text-xs" title={f.path}>
                    {f.path}
                  </td>
                  <td className="truncate px-3 text-xs text-ink-3 max-sm:hidden" title={f.role}>
                    {f.role}
                  </td>
                  <td className="px-3 text-right font-mono text-xs">{bytes(f.size)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

function ReleaseOverview({ app, release, trail, heading }: { app: string; release: string; trail: [string, string][]; heading: string }) {
  const q = useQuery({ queryKey: ["release", app, release], queryFn: () => tool<Details>("release_details", { app, release: Number(release) }) });
  const running = useRunning().filter((r) => r.app === app && r.release === release);
  const d = q.data;
  return (
    <>
      <Headline trail={trail}>{heading}</Headline>
      <Failure error={q.error} />
      {d && (
        <div className="grid gap-x-5 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-start">
          <div className="min-w-0">
            <Section title="Services">
              {d.services.map((s) => (
                <div key={s.name} className="row block py-2 text-sm">
                  <div className="flex flex-wrap items-baseline justify-between gap-x-4">
                    <span className="font-mono font-semibold">{s.name}</span>
                    <span className="min-w-0 truncate font-mono text-xs text-ink-2" title={typeof s.image === "string" ? s.image : s.image.digest}>{typeof s.image === "string" ? s.image : s.image.reference}</span>
                  </div>
                  <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 font-mono text-xs text-ink-3">
                    {s.ports.length > 0 && <span>ports {s.ports.map(portText).join(", ")}</span>}
                    {s.depends_on.length > 0 && <span>after {s.depends_on.join(", ")}</span>}
                    {s.mounts.length > 0 && <span>mounts {s.mounts.map((m) => m.target).join(", ")}</span>}
                    {s.network_mode && <span>network {s.network_mode}</span>}
                    {s.healthcheck && <span>healthcheck</span>}
                    {s.privileged && <span className="text-warn">privileged</span>}
                  </div>
                </div>
              ))}
            </Section>
            <Section title="Variables">
              {d.variables.length === 0 && <p className="row text-sm text-ink-3">It takes none. Set values on a fleet or device.</p>}
              {d.variables.map((v) => (
                <div key={v.key} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 row text-sm sm:grid-cols-[minmax(0,13rem)_8rem_minmax(0,1fr)_auto]">
                  <span className="truncate font-mono text-[0.82rem] font-medium">{v.key}</span>
                  <span className="truncate font-mono text-xs text-ink-2 max-sm:col-span-2 max-sm:row-start-2">{v.services.join(", ") || "all"}</span>
                  <span className="truncate text-xs text-ink-3 max-sm:col-span-2 max-sm:row-start-3">{v.description ?? (v.default != null ? `default: ${v.default}` : "")}</span>
                  <span className="max-sm:col-start-2 max-sm:row-start-1">{v.required && v.default == null ? <Badge tone="warn">required</Badge> : v.default != null ? <Badge>default</Badge> : null}</span>
                </div>
              ))}
            </Section>
          </div>
          <div className="min-w-0">
            <Section title="Running on">
              <DeviceLinks devices={running.map((r) => r.device)} none="Not running on any connected device." />
            </Section>
            <Section title="Release">
              <Row k="Uploaded">{ago(d.uploaded_at)}</Row>
              <Row k="Health gate">{`${d.health_gate.stable_secs}s stable within ${d.health_gate.timeout_secs}s`}</Row>
              {d.volumes.length > 0 && <Row k="Volumes">{d.volumes.join(", ")}</Row>}
              {d.networks.length > 0 && <Row k="Networks">{d.networks.join(", ")}</Row>}
            </Section>
            <Section title="Builds">
              {d.artifacts.map((a) => (
                <div key={a.arch} className="row block">
                  <div className="flex justify-between gap-3 font-mono text-xs">
                    <span>{a.arch}</span>
                    <span className="text-ink-3">{gb(a.size_mb)}</span>
                  </div>
                  <p className="truncate font-mono text-[0.68rem] text-ink-3" title={a.sha256}>
                    {a.sha256}
                  </p>
                </div>
              ))}
            </Section>
          </div>
        </div>
      )}
    </>
  );
}

export function OsPage() {
  const nav = useNavigate();
  const versions = useOsVersions();
  const devices = useDevices();
  const byVersion = Object.entries((versions.data ?? []).reduce<Record<string, OsVersion[]>>((all, v) => ((all[v.version] ??= []).push(v), all), {})).sort((a, b) => byVersionDesc(a[0], b[0]));
  return (
    <>
      <Headline>OS</Headline>
      <Failure error={versions.error} />
      {versions.isSuccess && byVersion.length === 0 && (
        <div className="border border-rule bg-sheet px-3">
          <Empty title="No OS versions yet.">Publish one with <code className="font-mono text-xs">via os-release</code>.</Empty>
        </div>
      )}
      {byVersion.length > 0 && (
        <Table heads={[["Version"], ["Builds"], ["Devices on it", "text-right"]]}>
          {byVersion.map(([version, vs], i) => (
            <tr key={version} className={tr} onClick={() => nav(osPath(version))}>
              <td className={td}>
                <span className="flex items-center gap-2">
                  <Link to={osPath(version)} onClick={(e) => e.stopPropagation()} className="font-mono font-semibold">
                    {version}
                  </Link>
                  {i === 0 && <Badge tone="latest">latest</Badge>}
                  {(devices.data ?? []).some((d) => d.os_version === version) && <Badge tone="running">running</Badge>}
                </span>
              </td>
              <td className={`${td} font-mono text-xs text-ink-2`}>{vs.map((v) => `${v.arch} ${gb(v.size_mb)}`).join(", ")}</td>
              <td className={`${td} text-right font-mono text-xs`}>{(devices.data ?? []).filter((d) => d.os_version === version).length}</td>
            </tr>
          ))}
        </Table>
      )}
    </>
  );
}

type OsDetails = { builds: { arch: string; published_at: number; size_mb: number; files: { name: string; size_mb: number; sha256: string | null }[] }[] };

export function OsVersionPage() {
  const { version = "", fleet } = useParams();
  const fleets = useFleets();
  const q = useQuery({ queryKey: ["os-version", version], queryFn: () => tool<OsDetails>("os_version_details", { version }) });
  const devices = useDevices();
  const on = (devices.data ?? []).filter((d) => d.os_version === version);
  return (
    <>
      <Headline trail={fleet ? [...fleetTrail(fleets.data, fleet, true), ["Releases", `${fleetPath(fleet)}/releases`]] : [["OS", "/os"]]}>version {version}</Headline>
      <Failure error={q.error} />
      {q.data && (
        <div className="grid gap-x-5 lg:grid-cols-[minmax(0,1fr)_22rem] lg:items-start">
          <div className="min-w-0">
            {q.data.builds.map((b) => (
              <Section key={b.arch} title={b.arch} aside={<span className="label">{gb(b.size_mb)} · {ago(b.published_at)}</span>}>
                {b.files.map((f) => (
                  <div key={f.name} className="row block">
                    <div className="flex items-baseline justify-between gap-3 font-mono text-xs">
                      <span className="min-w-0 truncate" title={f.name}>
                        {f.name}
                      </span>
                      <span className="shrink-0 text-ink-3">{gb(f.size_mb)}</span>
                    </div>
                    {f.sha256 && (
                      <p className="truncate font-mono text-[0.68rem] text-ink-3" title={f.sha256}>
                        {f.sha256}
                      </p>
                    )}
                  </div>
                ))}
              </Section>
            ))}
          </div>
          <Section title="Devices on it">
            <DeviceLinks devices={on} none="No device runs this version." />
          </Section>
        </div>
      )}
    </>
  );
}
