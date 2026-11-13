import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, type ReactNode } from "react";
import { Link, matchPath, useLocation } from "react-router-dom";
import { deviceState, signOut, tool, type Caller, type Health, type Release } from "./lib";
import { Mark, ThemeSwitch } from "./main";
import { Button, Pip } from "./ui";
import { appPath, osPath, releasePath } from "./pages/catalog";
import { serviceState } from "./pages/device";
import { devicePath, fleetPath, useCan, useDevices } from "./pages/fleet";

function Item({ to, active, children }: { to: string; active?: boolean; children: ReactNode }) {
  return (
    <Link to={to} aria-current={active ? "page" : undefined} className="side">
      {children}
    </Link>
  );
}

/** A level of the hierarchy opened out. Same left edge as its parent: depth
 *  shows as a titled group, not as a growing margin. */
function Group({ title, to, children }: { title: ReactNode; to: string; children: ReactNode }) {
  return (
    <div className="side-group border-y border-rule bg-paper py-1">
      <Link to={to} className="label flex h-7 items-center gap-2 px-3 hover:text-ink">
        {title}
      </Link>
      {children}
    </div>
  );
}

function DeviceItems({ fleet, device, tab, current }: { fleet: string; device: string; tab: string; current?: string }) {
  const devices = useDevices();
  const d = devices.data?.find((x) => x.fleet === fleet && x.name === device);
  const health = useQuery({
    queryKey: ["health", device],
    queryFn: () => tool<Health>("device_health", { device }),
    refetchInterval: 5000,
    enabled: !!d?.online,
  });
  const services = Array.isArray(health.data?.services) && d?.online ? health.data.services : [];
  const base = devicePath(fleet, device);
  const developer = useCan(fleet, "developer");
  // A waiting device has nothing to ask yet, only what it will be given.
  const tabs = ([["status", "Status"], ["logs", "Logs"], ["terminal", "Terminal"], ["journal", "Journal"], ["releases", "Releases"], ["variables", "Variables"]] as [string, string][]).filter(([t]) => (developer || t !== "terminal") && (!d?.waiting || t === "status" || t === "variables"));
  return (
    <Group
      to={base}
      title={
        <>
          <Pip state={deviceState(d)} />
          <span className="truncate normal-case">{device}</span>
        </>
      }
    >
      {tabs.map(([t, label]) => (
        <Item key={t} to={t === "status" ? base : `${base}/${t}`} active={tab === t}>
          {label}
        </Item>
      ))}
      {services.length > 0 && <p className="label mt-1 flex h-6 items-center px-3">Services</p>}
      {services.map((s) => {
        const on = tab === "services" && current === s.service;
        return (
          <Item key={s.service} to={`${base}/services/${encodeURIComponent(s.service)}`} active={on}>
            <Pip state={serviceState(s)} />
            <span className="truncate font-mono text-[0.8rem]">{s.service}</span>
          </Item>
        );
      })}
    </Group>
  );
}

function ReleaseItems({ base, release, view, title }: { base: string; release: string; view: string; title?: string }) {
  const views: [string, string][] = [["", "Overview"], ["compose", "Compose"], ["deployment", "Deployment"], ["images", "Images"], ["files", "Files"]];
  return (
    <Group to={base} title={<span className="truncate normal-case">{title ?? `release ${release}`}</span>}>
      {views.map(([v, label]) => (
        <Item key={v} to={v ? `${base}/${v}` : base} active={view === v}>
          {label}
        </Item>
      ))}
    </Group>
  );
}

function AppItems({ app, release }: { app: string; release?: string }) {
  const q = useQuery({ queryKey: ["releases"], queryFn: () => tool<{ releases: Release[] }>("list_releases").then((r) => r.releases) });
  const rs = (q.data ?? []).filter((r) => r.app === app).sort((a, b) => b.release - a.release);
  return (
    <Group to={appPath(app)} title={<span className="truncate normal-case">{app}</span>}>
      {rs.map((r) => (
        <Item key={r.release} to={releasePath(app, r.release)} active={release === String(r.release)}>
          Release {r.release}
        </Item>
      ))}
    </Group>
  );
}

export function Sidebar({ me, open, onClose }: { me: Caller; open: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const { pathname, search } = useLocation();
  const at = (pattern: string) => matchPath(pattern, pathname)?.params;
  const device = at("/fleets/:fleet/devices/:device") ?? at("/fleets/:fleet/devices/:device/:tab/*");
  const fleet = at("/fleets/:fleet/*");
  const fleetTab = device ? "" : (at("/fleets/:fleet/:tab/*")?.tab ?? at("/fleets/:fleet/:tab")?.tab ?? "");
  const scoped = at("/fleets/:fleet/devices/:device/releases/:app/:release") ?? at("/fleets/:fleet/devices/:device/releases/:app/:release/:view") ?? at("/fleets/:fleet/releases/:app/:release") ?? at("/fleets/:fleet/releases/:app/:release/:view");
  const scopedBase = scoped?.fleet && scoped.app && scoped.release ? `${scoped.device ? devicePath(scoped.fleet, scoped.device) : fleetPath(scoped.fleet)}/releases/${encodeURIComponent(scoped.app)}/${scoped.release}` : null;
  const app = at("/apps/:app/*");
  const release = at("/apps/:app/releases/:release") ?? at("/apps/:app/releases/:release/:view");
  const os = at("/os/:version");
  const admin = me.role === "admin";
  const developer = useCan(fleet?.fleet, "developer");

  useEffect(() => {
    onClose();
    // A link was followed: on a phone, get out of the way.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname, search]);

  useEffect(() => {
    if (!open) return;
    const esc = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    addEventListener("keydown", esc);
    return () => removeEventListener("keydown", esc);
  }, [open, onClose]);

  return (
    <>
      {open && <div className="fixed inset-0 z-30 bg-black/50 lg:hidden" onClick={onClose} />}
      <aside
        className={`fixed inset-y-0 left-0 z-40 flex w-64 flex-col border-r border-rule bg-sheet transition-transform duration-150 lg:sticky lg:top-0 lg:z-0 lg:h-dvh lg:w-auto lg:translate-x-0 lg:transition-none ${open ? "translate-x-0" : "invisible -translate-x-full lg:visible"}`}
        aria-label="Navigation"
      >
        <Link to="/" className="flex h-12 flex-none items-center gap-2 border-b border-rule px-3 text-sm font-semibold tracking-wide uppercase">
          <Mark className="size-4" />
          viaos
        </Link>
        <nav className="min-h-0 flex-1 overflow-y-auto py-1">
          <Item to="/" active={pathname === "/"}>
            Fleets
          </Item>
          {fleet?.fleet && (
            <Group to={fleetPath(fleet.fleet)} title={<span className="truncate normal-case">{fleet.fleet}</span>}>
              <Item to={fleetPath(fleet.fleet)} active={!device && (!fleetTab || fleetTab === "devices")}>
                Devices
              </Item>
              <Item to={`${fleetPath(fleet.fleet)}/releases`} active={fleetTab === "releases"}>
                Releases
              </Item>
              <Item to={`${fleetPath(fleet.fleet)}/variables`} active={fleetTab === "variables"}>
                Variables
              </Item>
              {developer && (
                <Item to={`${fleetPath(fleet.fleet)}/enroll`} active={fleetTab === "enroll"}>
                  Enroll
                </Item>
              )}
              {developer && (
                <Item to={`${fleetPath(fleet.fleet)}/settings`} active={fleetTab === "settings"}>
                  Settings
                </Item>
              )}
            </Group>
          )}
          {device?.device && device.fleet && <DeviceItems fleet={device.fleet} device={device.device} tab={device.tab ?? "status"} current={device["*"]} />}
          {scopedBase && scoped?.release && <ReleaseItems base={scopedBase} release={scoped.release} view={scoped.view ?? ""} title={`${scoped.app} · release ${scoped.release}`} />}
          <Item to="/apps" active={pathname === "/apps"}>
            Apps
          </Item>
          {app?.app && <AppItems app={app.app} release={release?.release} />}
          {app?.app && release?.release && <ReleaseItems base={releasePath(app.app, release.release)} release={release.release} view={release.view ?? ""} />}
          <Item to="/os" active={pathname === "/os"}>
            OS
          </Item>
          {os?.version && (
            <Group to="/os" title="Version">
              <Item to={osPath(os.version)} active>
                Version {os.version}
              </Item>
            </Group>
          )}
        </nav>
        <div className="flex-none border-t border-rule py-1">
          {admin && (
            <>
              <Item to="/audit" active={pathname.startsWith("/audit")}>
                Audit
              </Item>
              <Item to="/access" active={pathname.startsWith("/access")}>
                Access
              </Item>
            </>
          )}
          <p className="label mt-1 truncate border-t border-rule px-3 pt-2">
            {me.name}
            {admin && " · admin"}
          </p>
          <div className="flex items-center justify-between px-1 pb-1">
            <ThemeSwitch />
            <Button
              tone="quiet"
              size="sm"
              onClick={async () => {
                await signOut();
                qc.setQueryData(["session"], null);
                qc.clear();
              }}
            >
              Sign out
            </Button>
          </div>
        </div>
      </aside>
    </>
  );
}
