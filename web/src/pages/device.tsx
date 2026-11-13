import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ago, byVersionDesc, called, duration, gb, lineage, tool, type Health, type MetricSample, type Metrics, type OsUpdate, type OsVersion } from "../lib";
import { Terminal } from "../terminal";
import { Button, Checkbox, Combobox, Failure, Headline, Input, Notice, Pip, Section } from "../ui";
import { devicePath, fleetTrail, NameAndNote, TagEditor, useCan, useDevices, useFleets } from "./fleet";
import { ScopeVariables } from "./variables";
import { Deployables, RunDialog, type Run } from "./releases";

function Gauge({ label, percent, detail }: { label: string; percent: number; detail: string }) {
  const hot = percent >= 90 ? "bg-bad" : percent >= 75 ? "bg-warn" : "bg-ink-2";
  return (
    <div className="row block py-2">
      <div className="flex items-baseline justify-between gap-3">
        <span className="font-mono text-xs">{label}</span>
        <span className="font-mono text-xs text-ink-3">{detail}</span>
      </div>
      <div className="bargraph mt-1">
        <div className={`h-full ${hot}`} style={{ width: `${Math.min(100, percent)}%` }} />
      </div>
    </div>
  );
}

/** `name` is for things with real names, whose case matters. */
function Row({ k, v, name }: { k: string; v: React.ReactNode; name?: boolean }) {
  return (
    <div className="row justify-between gap-4 text-sm">
      <span className={name ? "min-w-0 truncate font-mono text-xs" : "label"}>{k}</span>
      <span className="text-right font-mono text-xs">{v}</span>
    </div>
  );
}

export function serviceState(s: { status: string; health: string }): "ok" | "warn" | "bad" | "off" {
  const status = s.status.toLowerCase();
  const health = s.health.toLowerCase();
  if (!status.includes("running")) return status.includes("exit") || status.includes("dead") ? "bad" : "off";
  if (health.includes("unhealthy")) return "bad";
  if (health.includes("starting")) return "warn";
  return "ok";
}

const LINE_COLOURS = ["#8fb8d8", "#9cc7a6", "#d3b483", "#b9a9d6", "#d69aa6", "#8fcfc6"];

function Logs({ device, services, service, setService }: { device: string; services: string[]; service: string; setService: (s: string) => void }) {
  const [follow, setFollow] = useState(true);
  const [filter, setFilter] = useState("");
  const q = useQuery({
    queryKey: ["logs", device, service],
    queryFn: () =>
      tool<{ lines: { service: string; at?: string; line: string }[]; note?: string }>("logs", {
        device,
        tail: 500,
        ...(service ? { service } : {}),
      }),
    refetchInterval: follow ? 3000 : false,
  });
  const box = useRef<HTMLDivElement>(null);
  const lines = (q.data?.lines ?? []).filter((l) => !filter || l.line.toLowerCase().includes(filter.toLowerCase()));
  useEffect(() => {
    if (follow && box.current) box.current.scrollTop = box.current.scrollHeight;
  }, [follow, q.data, filter]);
  return (
    <div className="tty flex h-full min-h-[20rem] flex-col">
      <div className="flex flex-wrap items-center gap-2 border-b border-rule px-2 py-2">
        <Combobox aria-label="Service" mono className="w-44 max-sm:w-36" value={service} onChange={setService} options={[{ value: "", label: "all services" }, ...services.map((s) => ({ value: s, label: s }))]} />
        <Input aria-label="Filter lines" placeholder="filter lines" value={filter} onChange={(e) => setFilter(e.target.value)} className="max-w-44 min-w-0 flex-1 font-mono" />
        <Checkbox className="ml-auto font-mono" checked={follow} onChange={(e) => setFollow(e.target.checked)}>
          follow
        </Checkbox>
      </div>
      <div ref={box} className="min-h-0 flex-1 overflow-auto p-3 font-mono text-[0.76rem] leading-[1.55]">
        {q.error ? <p className="text-bad">{(q.error as Error).message}</p> : null}
        {lines.length === 0 && !q.isPending && !q.error && <p className="text-ink-3">{q.data?.note ?? "No output."}</p>}
        {lines.map((l, i) => (
          <div key={i} className="whitespace-pre-wrap break-all">
            {services.length > 1 && !service && (
              <span className="mr-2 select-none" style={{ color: LINE_COLOURS[Math.max(0, services.indexOf(l.service)) % LINE_COLOURS.length] }}>
                {l.service}
              </span>
            )}
            {l.line}
          </div>
        ))}
      </div>
    </div>
  );
}

function Journal({ device }: { device: string }) {
  const q = useQuery({
    queryKey: ["journal", device],
    queryFn: () => tool<{ entries: { at: string; event: string; release?: string | number; detail?: string }[] }>("journal", { device, limit: 100 }),
    refetchInterval: 8000,
  });
  return (
    <div>
      <Failure error={q.error} />
      {q.data?.entries.length === 0 && <p className="py-6 text-sm text-ink-2">Nothing deployed here yet.</p>}
      {q.data?.entries.map((e, i) => (
        <div key={i} className="grid grid-cols-[10rem_1fr] gap-x-4 row text-sm max-sm:grid-cols-1">
          <span className="font-mono text-xs text-ink-3">{e.at.replace("T", " ").slice(0, 19)}</span>
          <span>
            <span className="font-medium">{e.event.replaceAll("_", " ")}</span>
            {e.release != null && <span className="ml-2 font-mono text-xs text-ink-2">release {e.release}</span>}
            {e.detail && <span className="mt-0.5 block font-mono text-xs break-words text-ink-3">{e.detail}</span>}
          </span>
        </div>
      ))}
    </div>
  );
}

function OsUpdate({ device, arch, current, disabled }: { device: string; arch?: string | null; current?: string | null; disabled: boolean }) {
  const q = useQuery({
    queryKey: ["os-versions"],
    queryFn: () => tool<{ versions: OsVersion[] }>("list_os_versions").then((r) => r.versions),
  });
  const [run, setRun] = useState<Run | null>(null);
  const [version, setVersion] = useState("");
  if (!q.data) return null;
  const all = q.data.filter((v) => v.arch === arch).sort((a, b) => byVersionDesc(a.version, b.version));
  if (all.length === 0) return <p className="row text-xs text-ink-3">No OS versions published for {arch ?? "this device"}.</p>;
  const latest = all[0].version;
  const newer = (v: string) => current == null || byVersionDesc(current, v) > 0;
  const options = all.filter((v) => v.version !== current);
  const chosen = options.find((v) => v.version === version) ?? options[0];
  const rolling = chosen != null && !newer(chosen.version);
  return (
    <div className="row block py-2">
      <p className="mb-1.5 text-xs text-ink-2">{current === latest ? "On the latest OS." : <>Version <span className="font-mono">{latest}</span> is available.</>}</p>
      {options.length > 0 && (
        <div className="flex gap-2">
          <Combobox
            aria-label="OS version"
            className="flex-1"
            value={chosen?.version ?? ""}
            onChange={setVersion}
            options={options.map((v) => ({
              value: v.version,
              label: `Version ${v.version}`,
              detail: gb(v.size_mb),
              badge: v.version === latest ? "latest" : newer(v.version) ? undefined : "older",
            }))}
          />
          <Button
            disabled={disabled || !chosen}
            tone={rolling ? "plain" : "primary"}
            onClick={() => chosen && setRun({ title: `${rolling ? "Roll" : "Update"} ${device} ${rolling ? "back " : ""}to OS ${chosen.version}`, tool: "update_os", args: { version: chosen.version, device }, verbs: rolling ? ["Roll back", "Rolling back"] : undefined, warning: "The device reboots. Its containers stop for about a minute." })}
          >
            {rolling ? "Roll back" : "Update"}
          </Button>
        </div>
      )}
      {run && <RunDialog run={run} onClose={() => setRun(null)} />}
    </div>
  );
}

type Shell = { id: number; container?: string };

/** Shells on this device, host or container, in tabs. They stay connected while
 *  you look at anything else on the device's page. */
function Shells({ device, services, visible, container, onSelect }: { device: string; services: { service: string; container?: string }[]; visible: boolean; container?: string; onSelect: (container?: string) => void }) {
  const [shells, setShells] = useState<Shell[]>([]);
  const [active, setActive] = useState(0);
  const next = useRef(1);
  const add = (c?: string) => {
    const id = next.current++;
    setShells((all) => [...all, { id, container: c }]);
    setActive(id);
    return id;
  };
  const current = shells.find((s) => s.id === active);
  // A link here names a container: go to its shell, opening one if need be.
  useEffect(() => {
    if (!visible) return;
    if (current && current.container === container) return;
    const found = shells.find((s) => s.container === container);
    if (found) setActive(found.id);
    else if (container || shells.length === 0) add(container);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, container]);
  const name = (s: Shell) => (s.container ? (services.find((x) => x.container === s.container)?.service ?? s.container) : "host");
  const choose = (s: Shell) => {
    setActive(s.id);
    onSelect(s.container);
  };
  const close = (s: Shell) => {
    const rest = shells.filter((x) => x.id !== s.id);
    setShells(rest);
    if (s.id !== active) return;
    const last = rest[rest.length - 1];
    if (last) choose(last);
    else onSelect(undefined);
  };
  return (
    <div className={visible ? "flex h-full min-h-0 flex-col" : "hidden"}>
      <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1">
        <div className="strip min-w-0" role="tablist" aria-label="Shells">
          {shells.map((s) => (
            <span key={s.id} className="flex flex-none items-center">
              <button role="tab" aria-selected={s.id === active} className="tab font-mono" onClick={() => choose(s)}>
                {name(s)}
              </button>
              <Button tone="quiet" size="sm" className="ml-0.5 px-1" aria-label={`Close the ${name(s)} shell`} title="Close" onClick={() => close(s)}>
                ×
              </Button>
            </span>
          ))}
        </div>
        <Combobox
          aria-label="New shell"
          className="ml-auto w-44"
          mono
          value=" "
          placeholder="New shell…"
          onChange={(v) => {
            const c = v === "host" ? undefined : v;
            add(c);
            onSelect(c);
          }}
          options={[{ value: "host", label: "host" }, ...services.flatMap((s) => (s.container ? [{ value: s.container, label: s.service }] : []))]}
        />
      </div>
      <div className="min-h-0 flex-1">
        {shells.map((s) => (
          <div key={s.id} className={s.id === active ? "h-full" : "hidden"}>
            <Terminal device={device} container={s.container} active={visible && s.id === active} />
          </div>
        ))}
      </div>
    </div>
  );
}

type Tab = "status" | "services" | "logs" | "terminal" | "journal" | "releases" | "variables";

const UPDATE_STEPS: [string, string][] = [["started", "Asked"], ["downloading", "Downloading"], ["installing", "Installing"], ["rebooting", "Rebooting"], ["waiting", "Waiting for it to come back"], ["done", "Running"]];

/** How far an OS update has got, from the moment it starts until it settles.
 *  Results stay up for a day; a new update replaces them. */
export function OsUpdateProgress({ update: u }: { update: OsUpdate }) {
  const [, tick] = useState(0);
  useEffect(() => {
    if (u.finished_at) return;
    const t = setInterval(() => tick((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, [u.finished_at]);
  const finished = u.finished_at ?? 0;
  if (finished && Date.now() / 1000 - finished > 86400) return null;
  const elapsed = (u.finished_at ?? Math.floor(Date.now() / 1000)) - u.started_at;
  const bad = u.state === "rolled_back" || u.state === "failed" || u.state === "lost";
  const known = UPDATE_STEPS.findIndex(([s]) => s === u.state);
  // A state we have no step for (`verifying`, say) still shows, as itself.
  const at = known < 0 ? 1 : known;
  const title: Record<string, string> = { done: `Now on OS ${u.version}`, rolled_back: `OS ${u.version} rolled back`, failed: `OS ${u.version} failed`, lost: `Lost touch during OS ${u.version}` };
  return (
    <div className={`mb-4 border bg-sheet px-3 py-2 ${bad ? "border-bad" : u.state === "done" ? "border-rule" : "border-warn"}`} role="status">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1 text-sm">
        <span className="font-medium">
          {title[u.state] ?? `Updating to OS ${u.version}`}
          {u.from_version && <span className="ml-2 font-mono text-xs font-normal text-ink-3">from {u.from_version}</span>}
        </span>
        <span className="font-mono text-xs text-ink-3">{duration(elapsed)}</span>
      </div>
      {!bad && u.state !== "done" && (
        <ol className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 font-mono text-xs">
          {UPDATE_STEPS.map(([s, label], i) => (
            <li key={s} className={i === at ? "font-semibold text-ink" : i < at ? "text-ink-2" : "text-ink-3"} aria-current={i === at ? "step" : undefined}>
              {i < at ? "✓ " : ""}
              {i === at && known < 0 ? u.state : label}
              {i === at && u.progress != null ? ` ${u.progress}%` : ""}
            </li>
          ))}
        </ol>
      )}
      {u.state === "waiting" && <p className="mt-1 text-xs text-ink-3">It's expected to be offline now. A version that doesn't pass its boot check rolls back by itself, about five minutes after booting.</p>}
      {u.detail && <p className={`mt-1 text-xs ${bad ? "text-bad" : "text-ink-2"}`}>{u.detail}</p>}
    </div>
  );
}

function useMetrics(device: string, online: boolean) {
  const [history, setHistory] = useState<MetricSample[]>([]);
  // Kept apart from the query's own error, which it clears at the start of each
  // retry until there has been a success: anything shown from that blinks.
  const [unsupported, setUnsupported] = useState(false);
  const since = useRef<number | undefined>(undefined);
  useEffect(() => {
    setHistory([]);
    setUnsupported(false);
    since.current = undefined;
  }, [device]);
  const q = useQuery({
    queryKey: ["metrics", device],
    queryFn: async () => {
      const m = await tool<Metrics>("device_metrics", { device, ...(since.current ? { since: since.current } : {}) }).catch((e) => {
        setUnsupported(true);
        throw e;
      });
      setUnsupported(false);
      if (m.samples.length) {
        since.current = m.samples[m.samples.length - 1].at;
        setHistory(m.samples.slice(-1));
      }
      return m;
    },
    refetchInterval: unsupported ? 60_000 : 5000,
    enabled: online,
    retry: false,
  });
  return { metrics: q.data, history, unsupported };
}

const percent = (v?: number | null) => (v == null ? "–" : `${v.toFixed(v < 10 ? 1 : 0)}%`);
const amount = (v?: number | null) => (v == null ? "–" : mb(v));
const stateWord = (s: { health: string; status: string }) => (s.health.toLowerCase() === "none" ? s.status.toLowerCase() : s.health.toLowerCase());

const mb = (v: number) => (v < 1 ? `${Math.round(v * 1024)} KB` : v < 1024 ? `${v.toFixed(v < 10 ? 1 : 0)} MB` : `${(v / 1024).toFixed(1)} GB`);

function Storage({ m }: { m: Metrics }) {
  const declared = m.volumes?.filter((v) => v.declared) ?? [];
  const others = m.volumes?.filter((v) => !v.declared) ?? [];
  const d = m.disk;
  const partName = (p: NonNullable<Metrics["disk"]>["partitions"][number]) => p.label ?? p.device;
  return (
    <>
      <Section title="Volumes">
        {!m.volumes && <p className="row text-sm text-ink-3">Measuring…</p>}
        {m.volumes && declared.length === 0 && <p className="row text-sm text-ink-3">The running release declares no volumes.</p>}
        {declared.map((v) => (
          <Row name key={v.name} k={v.name} v={<>{v.used_by.length > 0 && <span className="mr-3 text-ink-3">{v.used_by.join(", ")}</span>}{v.mb == null ? "not created yet" : mb(v.mb)}</>} />
        ))}
        {others.map((v) => (
          <Row name key={v.name} k={`${v.name} (not in this release)`} v={v.mb == null ? "–" : mb(v.mb)} />
        ))}
      </Section>
      {d && (
        <Section title={`Whole disk · ${d.device} · ${mb(d.total_mb)}`}>
          {d.partitions.map((p) =>
            p.free_mb != null && p.size_mb > 0 ? (
              <Gauge key={p.device} label={p.in_use_as ?? partName(p)} percent={((p.size_mb - p.free_mb) / p.size_mb) * 100} detail={`${mb(p.free_mb)} free of ${mb(p.size_mb)}`} />
            ) : (
              <Row name key={p.device} k={partName(p)} v={<>{p.in_use_as ? "running OS" : "other OS slot"} · {mb(p.size_mb)}</>} />
            ),
          )}
          {d.unallocated_mb > 0 && <Row k="Unallocated" v={mb(d.unallocated_mb)} />}
          {m.docker && (
            <>
              <Row k="Docker images" v={mb(m.docker.images_mb)} />
              <Row k="Docker containers" v={mb(m.docker.containers_mb)} />
              <Row k="Docker volumes" v={mb(m.docker.volumes_mb)} />
              {m.docker.build_cache_mb > 0 && <Row k="Docker build cache" v={mb(m.docker.build_cache_mb)} />}
            </>
          )}
        </Section>
      )}
    </>
  );
}

export function DevicePage() {
  const nav = useNavigate();
  const { fleet = "", device: name = "", tab: tabParam, container } = useParams();
  const developer = useCan(fleet, "developer");
  const operator = useCan(fleet, "operator");
  const devices = useDevices();
  const device = devices.data?.find((d) => d.name === name && d.fleet === fleet);
  const online = !!device?.online;
  const tab = (tabParam as Tab) || "status";
  const [params] = useSearchParams();
  const logService = params.get("service") ?? "";
  const base = devicePath(fleet, name);
  const showLogs = (s: string) => nav(`${base}/logs${s ? `?service=${encodeURIComponent(s)}` : ""}`, { replace: true });
  const open = (t: Tab, inContainer?: string) => nav(`${base}/${t}${inContainer ? `/${encodeURIComponent(inContainer)}` : ""}`, { replace: true });
  // Shells stay connected while you look at other parts of the device.
  const [shellsOpened, setShellsOpened] = useState(false);
  useEffect(() => {
    if (tab === "terminal") setShellsOpened(true);
  }, [tab]);

  const health = useQuery({
    queryKey: ["health", name],
    queryFn: () => tool<Health>("device_health", { device: name }),
    refetchInterval: 5000,
    enabled: online,
  });
  const h = online ? health.data : undefined;
  const services = Array.isArray(h?.services) ? h.services : [];
  const missing = Object.entries(h?.release.missing_env ?? {});
  const { metrics, history, unsupported } = useMetrics(name, online);
  const qc = useQueryClient();
  const tagging = useMutation({
    mutationFn: (tags: string[]) => tool("update_device", { device: name, tags }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["devices"] }),
  });
  const naming = useMutation({
    mutationFn: (change: { title?: string; note?: string }) => tool("update_device", { device: name, ...change }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["devices"] }),
  });
  const latest = history[history.length - 1];
  const titles: Record<Tab, string> = { status: "", services: container ?? "Service", logs: "Logs", terminal: "Terminal", journal: "Journal", releases: "Releases", variables: "Variables" };
  const title = titles[tab];
  const fleets = useFleets();
  const trail: [string, string][] = [...fleetTrail(fleets.data, fleet, true), ...(title ? ([[called(device, name), base]] as [string, string][]) : [])];

  if (devices.isSuccess && !device) {
    return (
      <>
        <Headline trail={fleetTrail(fleets.data, fleet, true)}>{name}</Headline>
        <p className="py-4 text-sm">No device named {name} in {fleet}.</p>
      </>
    );
  }
  // Until the list has loaded, it isn't known to be offline.
  const unknown = !device;
  const updating = !!device?.os_update && !device.os_update.finished_at;
  const needsDevice = (what: string) => unknown ? null : <p className="py-4 text-sm text-ink-2">{what} {device?.last_seen ? `It was last seen ${ago(device.last_seen)}.` : ""}</p>;

  return (
    <>
      <Headline
        trail={trail}
        aside={
          unknown ? undefined : <p className="flex items-center gap-2 text-sm max-sm:hidden">
            <Pip state={online ? "ok" : updating ? "warn" : "bad"} />
            {online ? `Connected · up ${duration(h?.host.uptime_secs)}` : updating ? "Rebooting for an update" : `Not answering · last seen ${ago(device?.last_seen)}`}
          </p>
        }
      >
        {title || called(device, name)}
      </Headline>
      {device?.os_update && <OsUpdateProgress update={device.os_update} />}

      {tab === "status" && (
        <div>
          <p className="mb-4 flex min-h-5 items-center gap-2 text-sm sm:hidden">
            {!unknown && <Pip state={online ? "ok" : "bad"} />}
            {!unknown && (online ? `Connected · up ${duration(h?.host.uptime_secs)}` : `Not answering · last seen ${ago(device?.last_seen)}`)}
          </p>
          <Failure error={online ? health.error : null} />
          {missing.length > 0 && (
            <div className="mb-4">
              <Notice>
                <p className="font-medium">Waiting on variables</p>
                {missing.map(([svc, keys]) => (
                  <p key={svc} className="mt-0.5 font-mono text-xs text-ink-2">
                    {svc}: {keys.join(", ")}
                  </p>
                ))}
                <Button size="sm" className="mt-1.5" onClick={() => open("variables")}>
                  Set them
                </Button>
              </Notice>
            </div>
          )}
          <div className="grid gap-x-4 lg:grid-cols-2 lg:items-start">
            <div className="min-w-0">
            <Section title={h?.release.app && h.release.current ? <Link to={`${base}/releases/${encodeURIComponent(h.release.app)}/${h.release.current}`} className="hover:text-ink hover:underline">{h.release.app} · release {h.release.current}</Link> : "App"}>
              {!h && <p className="row text-sm text-ink-3">{online || unknown ? "Asking the device…" : "Not connected."}</p>}
              {h && services.length === 0 && <p className="row text-sm text-ink-2">No release running.</p>}
              {services.length > 0 && (
                <div className="row label gap-2.5 !min-h-7">
                  <span className="min-w-0 flex-1">Service</span>
                  <span className="w-14 text-right">CPU</span>
                  <span className="w-16 text-right">Memory</span>
                  {developer && <span className="w-12" />}
                </div>
              )}
              {services.map((s) => (
                <div key={s.service} className="row gap-2.5 text-sm">
                  <Link to={`${base}/services/${encodeURIComponent(s.service)}`} className="flex min-w-0 flex-1 items-center gap-2.5 hover:underline">
                    <Pip state={serviceState(s)} />
                    <span className="min-w-0 truncate font-mono text-[0.82rem] font-medium">{s.service}</span>
                    <span className="ml-auto font-mono text-xs text-ink-3 max-sm:hidden">{stateWord(s)}</span>
                  </Link>
                  <span className="w-14 text-right font-mono text-xs">{percent(latest?.services[s.service]?.cpu_percent)}</span>
                  <span className="w-16 text-right font-mono text-xs">{amount(latest?.services[s.service]?.memory_mb)}</span>
                  {developer && (
                    <span className="w-12 text-right">
                      {s.container && (
                        <Button tone="quiet" size="sm" title={`Shell in ${s.container}`} onClick={() => open("terminal", s.container!)}>
                          Shell
                        </Button>
                      )}
                    </span>
                  )}
                </div>
              ))}
              {h?.deploy && !["running"].includes(h.deploy.state) && (
                <p className={`row text-xs ${h.deploy.error ? "text-bad" : "text-ink-2"}`}>
                  {h.deploy.app} {h.deploy.release}: {h.deploy.error ?? h.deploy.state}
                </p>
              )}
            </Section>
            {h && (
              <Section title="Capacity">
                {h.host.memory && <Gauge label="memory" percent={h.host.memory.used_percent} detail={`${gb(h.host.memory.total_mb - h.host.memory.available_mb)} of ${gb(h.host.memory.total_mb)}`} />}
                {latest && <Row k="CPU" v={percent(latest.cpu_percent)} />}
                {h.host.disks.map((d) => (
                  <Gauge key={d.mount} label={d.mount} percent={d.used_percent} detail={`${gb(d.free_mb)} free`} />
                ))}
                {h.host.temperatures_c.slice(0, 3).map((t) => (
                  <Row key={t.zone} k={t.zone} v={`${t.celsius.toFixed(0)}°C`} />
                ))}
              </Section>
            )}
            </div>
            <Section title="System">
              <Row k="OS" v={device?.os_version ?? "–"} />
              <Row k="Arch" v={device?.arch ?? "–"} />
              <Row k="Kernel" v={h?.host.kernel ?? "–"} />
              <Row k="Secure Boot" v={h ? (h.os.secure_boot ? "enforcing" : "off") : "–"} />
              <Row k="Docker" v={h?.engine?.version ?? "–"} />
              <Row k="Load" v={h?.host.load ? `${h.host.load[0].toFixed(2)} / ${h.host.cpus} cpu` : "–"} />
              {h?.os.update && (
                <p className={`row text-xs ${h.os.update.error ? "text-bad" : "text-ink-2"}`}>
                  OS {h.os.update.version}: {h.os.update.error ?? `${h.os.update.state}${h.os.update.progress_percent != null ? ` ${h.os.update.progress_percent}%` : ""}`}
                </p>
              )}
              {developer && <OsUpdate device={name} arch={device?.arch} current={device?.os_version} disabled={!online} />}
            </Section>
            {device && <NameAndNote key={device.id} slug={device.name} title={device.title} note={device.note} readOnly={!operator} pending={naming.isPending} error={naming.error} onSave={(c) => naming.mutate(c)} />}
            <TagEditor tags={device?.tags ?? []} inherited={device?.inherited_tags} known={(devices.data ?? []).flatMap((d) => d.tags)} pending={tagging.isPending} readOnly={!operator} onChange={(tags) => tagging.mutate(tags)} />
            <Failure error={tagging.error} />
            {metrics && <Storage m={metrics} />}
            {metrics && metrics.processes.length > 0 && (
              <Section title="Memory by program">
                {metrics.processes.map((p) => (
                  <Row name key={p.name} k={p.name} v={<>{p.processes > 1 && <span className="mr-3 text-ink-3">×{p.processes}</span>}{mb(p.mb)}</>} />
                ))}
              </Section>
            )}
            {unsupported && online && !metrics && (
              <Section title="Memory and storage detail">
                <p className="row text-sm text-ink-3">Needs a newer OS on this device.</p>
              </Section>
            )}
          </div>
        </div>
      )}
      {tab === "services" && (() => {
        const s = services.find((x) => x.service === container);
        const now = container ? latest?.services[container] : undefined;
        if (!online) return needsDevice("This lives on the device, so it has to be connected.");
        if (!s) return h ? <p className="py-4 text-sm text-ink-2">No service called {container} in the running release.</p> : null;
        return (
          <>
            <Section title="Now" aside={developer && s.container ? <Button tone="quiet" size="sm" onClick={() => open("terminal", s.container!)}>Shell</Button> : undefined}>
              <Row k="State" v={<span className="inline-flex items-center gap-2"><Pip state={serviceState(s)} />{stateWord(s)}</span>} />
              <Row k="CPU" v={percent(now?.cpu_percent)} />
              <Row k="Memory" v={amount(now?.memory_mb)} />
              {s.container && <Row k="Container" v={s.container} />}
            </Section>
            <div className="h-[calc(100dvh-16rem)] min-h-96">
              <Logs device={name} services={services.map((x) => x.service)} service={s.service} setService={(x) => nav(x ? `${base}/services/${encodeURIComponent(x)}` : `${base}/logs`)} />
            </div>
          </>
        );
      })()}
      {tab === "logs" && (online ? <div className="h-[calc(100dvh-5.5rem)]"><Logs device={name} services={services.map((s) => s.service)} service={logService} setService={showLogs} /></div> : needsDevice("Logs live on the device, so it has to be connected."))}
      {tab === "terminal" && !online && needsDevice("A shell needs the device to be connected.")}
      {developer && online && shellsOpened && (
        <div className={tab === "terminal" ? "h-[calc(100dvh-5.5rem)]" : "hidden"}>
          <Shells device={name} services={services} visible={tab === "terminal"} container={container} onSelect={(c) => open("terminal", c)} />
        </div>
      )}
      {tab === "journal" && (online ? <Section title="Journal"><Journal device={name} /></Section> : needsDevice("The journal lives on the device, so it has to be connected."))}
      {tab === "releases" && <Deployables target={{ device: name }} base={base} label={name} os={false} arch={device?.arch} running={h?.release.app && h.release.current ? [{ app: h.release.app, release: String(h.release.current) }] : []} />}
      {tab === "variables" && <ScopeVariables scope="device" target={name} inherits={lineage(fleets.data ?? [], fleet)} app={h?.release.app} />}
    </>
  );
}
