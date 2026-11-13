import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { byVersionDesc, gb, tool, type OsVersion, type Release } from "../lib";
import { Badge, Button, Empty, Failure, Modal, Section } from "../ui";
import { useCan, useDevices } from "./fleet";

export type Run = { title: string; tool: string; args: Record<string, unknown>; warning?: string; verbs?: [string, string] };

type Outcome = { device: string; skipped?: string; would_run?: boolean; started?: boolean; error?: string };

/** Show exactly which devices an action touches, then do it. */
export function RunDialog({ run, onClose }: { run: Run; onClose: () => void }) {
  const preview = useQuery({
    queryKey: ["dry-run", run.tool, run.args],
    queryFn: () => tool<{ devices: Outcome[] }>(run.tool, { ...run.args, dry_run: true }),
    gcTime: 0,
  });
  const client = useQueryClient();
  const go = useMutation({
    mutationFn: () => tool<{ devices: Outcome[] }>(run.tool, run.args),
    onSuccess: () => client.invalidateQueries(),
  });
  const [verb, doing] = run.verbs ?? (run.tool === "update_os" ? ["Update", "Updating"] : ["Deploy", "Deploying"]);
  // For one device, the page behind says how it is going from here. A list stays,
  // because it may be the only place that says what happened to each.
  const started = go.data?.devices;
  useEffect(() => {
    if (started?.length === 1 && started[0].started) onClose();
  }, [started, onClose]);
  const rows = go.data?.devices ?? preview.data?.devices ?? [];
  const runnable = preview.data?.devices.some((d) => d.would_run);
  return (
    <Modal title={run.title} onClose={onClose}>
      {run.warning && !go.data && <p className="mb-3 text-sm text-ink-2">{run.warning}</p>}
      <Failure error={preview.error ?? go.error} />
      <div className="max-h-72 overflow-auto">
        {rows.map((d) => (
          <div key={d.device} className="row justify-between gap-4 text-sm">
            <span className="font-medium">{d.device}</span>
            <span className={`text-right text-xs ${d.error ? "text-bad" : d.skipped ? "text-ink-3" : ""}`}>
              {d.error ?? (d.skipped ? `skipped: ${d.skipped}` : d.started ? doing : `Will ${verb.toLowerCase()}`)}
            </span>
          </div>
        ))}
        {preview.data && rows.length === 0 && <p className="py-2 text-sm text-ink-2">No devices there.</p>}
      </div>
      <div className="mt-5 flex justify-end gap-2">
        <form method="dialog">
          <Button type="submit">{go.data ? "Close" : "Cancel"}</Button>
        </form>
        {!go.data && (
          <Button tone="primary" disabled={!runnable || go.isPending} onClick={() => go.mutate()}>
            {go.isPending ? `${doing}…` : verb}
          </Button>
        )}
      </div>
    </Modal>
  );
}

// One set of columns for apps and the OS, so everything lines up.
const rowClass = "row grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 gap-y-1 sm:grid-cols-[minmax(0,12rem)_minmax(0,14rem)_minmax(0,1fr)_auto]";

/** What can be sent to this fleet or device. Where you are says where it goes. */
export function Deployables({ target, base, label, running = [], runningOs = [], os = true, arch }: { target: { fleet: string } | { device: string }; base: string; label: string; running?: { app: string; release: string }[]; runningOs?: string[]; os?: boolean; arch?: string | null }) {
  const devices = useDevices();
  const fleet = "fleet" in target ? target.fleet : devices.data?.find((d) => d.name === target.device)?.fleet;
  const admin = useCan(fleet, "developer");
  const releases = useQuery({
    queryKey: ["releases"],
    queryFn: () => tool<{ releases: Release[] }>("list_releases").then((r) => r.releases),
  });
  const versions = useQuery({
    queryKey: ["os-versions"],
    queryFn: () => tool<{ versions: OsVersion[] }>("list_os_versions").then((r) => r.versions),
    enabled: os,
  });
  const [run, setRun] = useState<Run | null>(null);

  const apps = Object.entries(
    (releases.data ?? []).reduce<Record<string, Release[]>>((all, r) => {
      (all[r.app] ??= []).push(r);
      return all;
    }, {}),
  );
  const osByVersion = Object.entries(
    (versions.data ?? []).reduce<Record<string, OsVersion[]>>((all, v) => {
      (all[v.version] ??= []).push(v);
      return all;
    }, {}),
  ).sort((a, b) => byVersionDesc(a[0], b[0]));

  return (
    <>
      <Section title="Apps">
        <Failure error={releases.error} />
        {releases.data?.length === 0 && <Empty title="No releases uploaded.">Build and upload one from a compose file with <code className="font-mono text-xs">via release</code>.</Empty>}
        {apps.flatMap(([app, rs]) =>
          [...rs].sort((a, b) => byVersionDesc(a.release, b.release)).map((r, i) => (
            <div key={`${app}/${r.release}`} className={rowClass}>
              <span className="truncate font-mono text-sm font-semibold max-sm:row-start-1">
                {i === 0 ? app : <span aria-hidden className="max-sm:hidden" />}
              </span>
              <span className="flex items-center gap-2 font-mono text-sm max-sm:col-span-2 max-sm:row-start-2">
                <Link to={`${base}/releases/${encodeURIComponent(app)}/${r.release}`} className="hover:underline">
                  release {r.release}
                </Link>
                {running.some((x) => x.app === app && x.release === String(r.release)) && <Badge tone="running">running</Badge>}
                {i === 0 && <Badge tone="latest">latest</Badge>}
              </span>
              <span className="truncate font-mono text-xs text-ink-3 max-sm:col-span-2 max-sm:row-start-3">
                {r.artifacts.filter((a) => !arch || a.arch === arch).map((a) => `${a.arch} ${gb(a.size_mb)}`).join(", ")}
              </span>
              {admin && (
                <Button
                  size="sm"
                  className="max-sm:col-start-2 max-sm:row-start-1"
                  onClick={() =>
                    setRun({
                      title: `Deploy ${app} ${r.release} to ${label}`,
                      tool: "deploy",
                      args: { app, release: r.release, ...target },
                      warning: "Containers are replaced. A device that fails the health gate goes back to its previous release by itself.",
                    })
                  }
                >
                  Deploy
                </Button>
              )}
            </div>
          )),
        )}
      </Section>

      {os && (
        <Section title="Operating system">
          <Failure error={versions.error} />
          {versions.data?.length === 0 && <Empty title="No OS versions uploaded.">Publish one with <code className="font-mono text-xs">via os-release</code>.</Empty>}
          {osByVersion.map(([version, vs], i) => (
            <div key={version} className={rowClass}>
              <Link to={`${base}/os/${encodeURIComponent(version)}`} className="truncate font-mono text-sm font-semibold hover:underline max-sm:row-start-1">
                version {version}
              </Link>
              <span className="flex items-center gap-2 max-sm:col-span-2 max-sm:row-start-2">{runningOs.includes(version) && <Badge tone="running">running</Badge>}{i === 0 && <Badge tone="latest">latest</Badge>}</span>
              <span className="truncate font-mono text-xs text-ink-3 max-sm:col-span-2 max-sm:row-start-3">{vs.map((v) => `${v.arch} ${gb(v.size_mb)}`).join(", ")}</span>
              {admin && (
                <Button
                  size="sm"
                  className="max-sm:col-start-2 max-sm:row-start-1"
                  onClick={() =>
                    setRun({
                      title: `Update ${label} to OS ${version}`,
                      tool: "update_os",
                      args: { version, ...target },
                      warning: "Each device reboots, stopping its containers for about a minute. A version that fails to boot rolls back by itself.",
                    })
                  }
                >
                  Update
                </Button>
              )}
            </div>
          ))}
        </Section>
      )}
      {run && <RunDialog run={run} onClose={() => setRun(null)} />}
    </>
  );
}
