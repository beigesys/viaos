import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ago, atLeast, fleetTags, hasTag, lineage, tagChoices, tool, under, type Device, type Fleet, type Level } from "../lib";
import { useIsAdmin } from "../main";
import { Button, buttonClass, Combobox, Empty, Failure, Field, Headline, Input, Modal, Pip, Readout, Section, Tag } from "../ui";
import { useRunning } from "./catalog";
import { EnrollTab } from "./enroll";
import { Deployables } from "./releases";
import { ScopeVariables } from "./variables";

export function useDevices() {
  return useQuery({
    queryKey: ["devices"],
    queryFn: () => tool<{ devices: Device[] }>("list_devices").then((r) => r.devices),
    refetchInterval: 5000,
  });
}

export function useFleets() {
  return useQuery({
    queryKey: ["fleets"],
    queryFn: () => tool<{ fleets: Fleet[] }>("list_fleets").then((r) => r.fleets),
    refetchInterval: 15000,
  });
}

/** Whether the caller holds `need` on `fleet`. Admins hold everything. */
export function useCan(fleet: string | undefined, need: Level) {
  const admin = useIsAdmin();
  const fleets = useFleets();
  return admin || atLeast(fleets.data?.find((f) => f.name === fleet)?.access, need);
}

/** Breadcrumbs down to a fleet. With `include`, the fleet itself is one of them. */
export function fleetTrail(fleets: Fleet[] | undefined, fleet: string, include: boolean): [string, string][] {
  const chain = lineage(fleets ?? [], fleet);
  const names = chain.length ? chain : [fleet];
  return [["Fleets", "/"], ...(include ? names : names.slice(0, -1)).map((f): [string, string] => [f, fleetPath(f)])];
}

export const fleetPath = (fleet: string) => `/fleets/${encodeURIComponent(fleet)}`;
export const devicePath = (fleet: string, device: string) => `${fleetPath(fleet)}/devices/${encodeURIComponent(device)}`;

function AddFleet({ primary, parent }: { primary?: boolean; parent?: string }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const create = useMutation({
    mutationFn: () => tool("create_fleet", { fleet: name.trim(), ...(parent ? { parent } : {}) }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["fleets"] });
      setOpen(false);
      nav(fleetPath(name.trim()));
    },
  });
  const title = parent ? `Add a fleet under ${parent}` : "Add fleet";
  return (
    <>
      <Button tone={primary ? "primary" : "plain"} size="sm" onClick={() => setOpen(true)}>
        {parent ? "Add sub-fleet" : "Add fleet"}
      </Button>
      {open && (
        <Modal title={title} onClose={() => setOpen(false)}>
          <form
            className="space-y-4"
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
          >
            <Field label="Name" hint="A customer, a site, a building, a line: whatever this level means to you. Unique across the whole tree.">
              <Input autoFocus aria-label="New fleet name" placeholder="acme" value={name} onChange={(e) => setName(e.target.value)} />
            </Field>
            <Failure error={create.error} />
            <div className="flex justify-end gap-2">
              <Button onClick={() => setOpen(false)}>Cancel</Button>
              <Button tone="primary" type="submit" disabled={!name.trim() || create.isPending}>
                Add
              </Button>
            </div>
          </form>
        </Modal>
      )}
    </>
  );
}

function FleetTable({ rows, all, devices, showPath }: { rows: Fleet[]; all: Fleet[]; devices: Device[]; showPath?: boolean }) {
  const nav = useNavigate();
  const count = (fleet: string, online: boolean) => {
    const tree = under(all, fleet);
    return devices.filter((d) => tree.includes(d.fleet) && d.online === online).length;
  };
  return (
    <div className="mb-4 border border-rule bg-sheet">
      <table className="w-full table-fixed border-collapse text-sm">
        <thead>
          <tr className="border-b border-rule bg-well text-left">
            <th className="label px-3 py-1.5 font-medium">Fleet</th>
            <th className="label px-3 py-1.5 font-medium max-sm:hidden">Tags</th>
            <th className="label w-20 px-3 py-1.5 text-right font-medium">Online</th>
            <th className="label w-20 px-3 py-1.5 text-right font-medium">Offline</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((f) => {
            const off = count(f.name, false);
            const above = lineage(all, f.name).slice(0, -1);
            const kids = all.filter((x) => x.parent === f.name).length;
            return (
              <tr key={f.name} onClick={() => nav(fleetPath(f.name))} className="h-10 cursor-pointer border-b border-rule transition-colors last:border-b-0 hover:bg-well max-sm:h-11">
                <td className="truncate px-3">
                  {showPath && above.length > 0 && <span className="font-mono text-xs text-ink-3">{above.join(" / ")} / </span>}
                  <Link to={fleetPath(f.name)} onClick={(e) => e.stopPropagation()} className="font-mono font-semibold">
                    {f.name}
                  </Link>
                  {kids > 0 && <span className="ml-2 font-mono text-xs text-ink-3">+{kids}</span>}
                </td>
                <td className="truncate px-3 max-sm:hidden">
                  <span className="flex h-5 flex-wrap gap-1 overflow-hidden">
                    {f.tags.map((t) => (
                      <Tag key={t} tag={t} />
                    ))}
                  </span>
                </td>
                <td className="px-3 text-right font-mono text-xs">{count(f.name, true)}</td>
                <td className={`px-3 text-right font-mono text-xs ${off ? "font-semibold text-bad" : "text-ink-3"}`}>{off}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

/** The top of the hierarchy. Searching looks through every level of it. */
export function FleetsPage() {
  const admin = useIsAdmin();
  const fleets = useFleets();
  const devices = useDevices();
  const [text, setText] = useState("");
  // In the address, so a filter can be refreshed and passed on.
  const [params, setParams] = useSearchParams();
  const wanted = params.getAll("tag");
  const setWanted = (tags: string[]) => setParams(tags.map((t): [string, string] => ["tag", t]), { replace: true });
  const all = fleets.data ?? [];
  const allDevices = devices.data ?? [];
  const known = [...all.flatMap((f) => f.tags), ...allDevices.flatMap((d) => d.tags)];
  const q = text.trim().toLowerCase();
  const searching = !!q || wanted.length > 0;
  const matches = (tags: string[], words: string) => wanted.every((w) => hasTag(tags, w)) && `${words} ${tags.join(" ")}`.toLowerCase().includes(q);
  const rows = searching ? all.filter((f) => matches(fleetTags(all, f.name), lineage(all, f.name).join(" "))) : all.filter((f) => !f.parent);
  const found = searching ? allDevices.filter((d) => matches([...d.tags, ...(d.inherited_tags ?? [])], `${d.name} ${d.fleet}`)) : [];
  return (
    <>
      <Headline aside={admin ? <AddFleet primary={fleets.isSuccess && all.length === 0} /> : undefined}>Fleets</Headline>
      <Failure error={fleets.error} />
      {fleets.isSuccess && all.length === 0 && (
        <div className="border border-rule bg-sheet px-3">
          <Empty title="No fleets yet.">Fleets group devices, and can sit inside each other: customer, site, building, whatever fits. Add one, then enroll devices from its page.</Empty>
        </div>
      )}
      {all.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <Input aria-label="Search fleets and devices" placeholder="Search every level…" value={text} onChange={(e) => setText(e.target.value)} className="max-w-64 max-sm:max-w-none" />
          {known.length > 0 && <Combobox aria-label="Filter by tag" mono className="w-52 max-sm:w-full" value="" onChange={(t) => t && !wanted.includes(t) && setWanted([...wanted, t])} placeholder="Filter by tag" options={tagChoices(known).filter((o) => !wanted.includes(o.value))} />}
          {wanted.map((t) => (
            <Tag key={t} tag={t}>
              <Button tone="quiet" size="sm" className="ml-0.5 px-1" aria-label={`Stop filtering by ${t}`} onClick={() => setWanted(wanted.filter((x) => x !== t))}>
                ×
              </Button>
            </Tag>
          ))}
        </div>
      )}
      {searching && rows.length === 0 && found.length === 0 && <p className="py-3 text-sm text-ink-3">Nothing matches.</p>}
      {rows.length > 0 && <FleetTable rows={rows} all={all} devices={allDevices} showPath={searching} />}
      {found.length > 0 && <DeviceTable devices={found} all={all} showFleet />}
    </>
  );
}

/** A fleet's or device's own tags, and adding to them. */
export function TagEditor({ tags, inherited = [], known, pending, readOnly, onChange }: { tags: string[]; inherited?: string[]; known: string[]; pending: boolean; readOnly?: boolean; onChange: (tags: string[]) => void }) {
  const [draft, setDraft] = useState("");
  const add = () => {
    if (draft.trim() && !tags.includes(draft.trim())) onChange([...tags, draft.trim()]);
    setDraft("");
  };
  const quiet = inherited.filter((t) => !tags.includes(t));
  return (
    <Section title="Tags">
      <div className="row flex-wrap gap-1.5">
        {tags.length + quiet.length === 0 && <span className="text-sm text-ink-3">No tags</span>}
        {tags.map((t) => (
          <Tag key={t} tag={t}>
            {!readOnly && (
              <Button tone="quiet" size="sm" className="ml-0.5 px-1" aria-label={`Remove tag ${t}`} disabled={pending} onClick={() => onChange(tags.filter((x) => x !== t))}>
                ×
              </Button>
            )}
          </Tag>
        ))}
        {quiet.map((t) => (
          <Tag key={t} tag={t} quiet />
        ))}
      </div>
      {!readOnly && (
        <form
          className="row gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            add();
          }}
        >
          <Combobox creatable mono aria-label="New tag" className="flex-1" value={draft} onChange={setDraft} placeholder="site=dallas, or just a word" options={[...new Set(known)].filter((t) => !tags.includes(t)).sort().map((t) => ({ value: t, label: t }))} />
          <Button type="submit" size="sm" disabled={!draft.trim() || pending}>
            Add
          </Button>
        </form>
      )}
    </Section>
  );
}

function SettingsTab({ fleet, fleets }: { fleet: string; fleets: Fleet[] }) {
  const qc = useQueryClient();
  const nav = useNavigate();
  const me = fleets.find((f) => f.name === fleet);
  const remove = useMutation({
    mutationFn: () => tool("delete_fleet", { fleet }),
    onSuccess: () => {
      nav(me?.parent ? fleetPath(me.parent) : "/");
      qc.invalidateQueries({ queryKey: ["fleets"] });
      qc.invalidateQueries({ queryKey: ["variables"] });
    },
  });
  const update = useMutation({
    mutationFn: (args: Record<string, unknown>) => tool("update_fleet", { fleet, ...args }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["fleets"] });
      qc.invalidateQueries({ queryKey: ["devices"] });
    },
  });
  const admin = useIsAdmin();
  // Moving or deleting it is up to whoever runs where it would go, or went.
  const placeable = (p: string | null) => (p ? admin || atLeast(fleets.find((f) => f.name === p)?.access, "developer") : admin);
  if (!me) return null;
  const empty = me.devices === 0 && !fleets.some((f) => f.parent === fleet);
  const canDelete = empty && placeable(me.parent);
  const inside = under(fleets, fleet);
  const known = fleets.flatMap((f) => f.tags);
  return (
    <div className="grid gap-x-4 lg:grid-cols-2 lg:items-start">
      <TagEditor tags={me.tags} known={known} pending={update.isPending} onChange={(tags) => update.mutate({ tags })} />
      <Section title="Sits under">
        <div className="row gap-2">
          <Combobox
            aria-label="Parent fleet"
            mono
            className="flex-1"
            value={me.parent ?? ""}
            disabled={update.isPending || !placeable(me.parent)}
            onChange={(p) => p !== (me.parent ?? "") && update.mutate(p ? { parent: p } : { top_level: true })}
            options={[...(admin ? [{ value: "", label: "Nothing (top level)" }] : []), ...fleets.filter((f) => !inside.includes(f.name) && placeable(f.name)).map((f) => ({ value: f.name, label: f.name, detail: lineage(fleets, f.name).slice(0, -1).join(" / ") || undefined }))]}
          />
        </div>
      </Section>
      <div className="lg:col-span-2">
        <Failure error={update.error ?? remove.error} />
      </div>
      <Section title="Delete">
        <div className="row justify-between gap-3">
          <span className="min-w-0 text-sm text-ink-2">{!empty ? "Not empty, so it can't be deleted" : canDelete ? "Empty" : me.parent ? `Deleting it needs developer on ${me.parent}` : "Deleting it needs an admin"}</span>
          <Button tone="danger" size="sm" disabled={!canDelete || remove.isPending} onClick={() => confirm(`Delete fleet ${fleet}?`) && remove.mutate()}>
            Delete fleet
          </Button>
        </div>
      </Section>
    </div>
  );
}

function DevicesTab({ fleet, devices, loaded, canEnroll, hasChildren }: { fleet: string; devices: Device[]; loaded: boolean; canEnroll: boolean; hasChildren: boolean }) {
  const [filter, setFilter] = useState("");
  const shown = devices
    .filter((d) => !filter || `${d.name} ${d.arch} ${d.os_version} ${d.tags.join(" ")}`.toLowerCase().includes(filter.toLowerCase()))
    .sort((a, b) => Number(a.online) - Number(b.online) || a.name.localeCompare(b.name));
  if (loaded && devices.length === 0 && hasChildren) return null;
  if (loaded && devices.length === 0) {
    return (
      <div className="border border-rule bg-sheet px-3">
        <Empty title="No devices in this fleet yet.">
          <p className="mb-3">Make an image, boot a device from it, and it shows up here.</p>
          {canEnroll && (
            <Link className={buttonClass("primary")} to={`${fleetPath(fleet)}/enroll`}>
              Enroll a device
            </Link>
          )}
        </Empty>
      </div>
    );
  }
  return (
    <>
      {devices.length > 5 && <Input aria-label="Filter devices" placeholder="Filter devices…" value={filter} onChange={(e) => setFilter(e.target.value)} className="mb-3 sm:max-w-64" />}
      {shown.length > 0 && <DeviceTable devices={shown} />}
    </>
  );
}

function DeviceTable({ devices, all, showFleet }: { devices: Device[]; all?: Fleet[]; showFleet?: boolean }) {
  const nav = useNavigate();
  const heads = [["Device", ""], ["Tags", "max-lg:hidden"], ...(showFleet ? [["Fleet", "max-sm:hidden"]] : []), ["Arch", "max-md:hidden"], ["OS", "max-sm:hidden"], ["Agent", "max-md:hidden"], ["Last seen", "text-right"]];
  return (
    <div className="border border-rule bg-sheet">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b border-rule bg-well text-left">
            {heads.map(([h, c]) => (
              <th key={h} className={`label px-3 py-1.5 font-medium ${c}`}>
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {devices.map((d) => (
            <tr key={d.id} onClick={() => nav(devicePath(d.fleet, d.name))} className="cursor-pointer h-10 border-b border-rule transition-colors last:border-b-0 hover:bg-well max-sm:h-11">
              <td className="px-3">
                <div className="flex items-center gap-2.5">
                  <Pip state={d.online ? "ok" : d.os_update && !d.os_update.finished_at ? "warn" : "bad"} />
                  <div className="min-w-0">
                    <Link to={devicePath(d.fleet, d.name)} onClick={(e) => e.stopPropagation()} className="block truncate font-mono font-semibold">
                      {d.name}
                    </Link>
                    <span className="block truncate font-mono text-xs text-ink-3 sm:hidden">
                      {d.arch ?? "–"} · os {d.os_version ?? "–"}
                    </span>
                  </div>
                </div>
              </td>
              <td className="px-3 max-lg:hidden">
                <span className="flex h-5 max-w-80 flex-wrap gap-1 overflow-hidden">
                  {d.tags.map((t) => (
                    <Tag key={t} tag={t} />
                  ))}
                  {showFleet && (d.inherited_tags ?? []).filter((t) => !d.tags.includes(t)).map((t) => <Tag key={t} tag={t} quiet />)}
                </span>
              </td>
              {showFleet && <td className="truncate px-3 font-mono text-xs text-ink-2 max-sm:hidden">{lineage(all ?? [], d.fleet).join(" / ")}</td>}
              <td className="px-3 font-mono text-xs text-ink-2 max-md:hidden">{d.arch ?? "–"}</td>
              <td className="px-3 font-mono text-xs max-sm:hidden">{d.os_version ?? "–"}</td>
              <td className="px-3 font-mono text-xs text-ink-2 max-md:hidden">{d.agent_version ?? "–"}</td>
              <td className={`px-3 text-right font-mono text-xs whitespace-nowrap ${d.os_update && !d.os_update.finished_at ? "text-warn" : d.online ? "text-ink-3" : "text-bad"}`}>{d.os_update && !d.os_update.finished_at ? `updating to ${d.os_update.version}${d.os_update.progress != null ? ` ${d.os_update.progress}%` : ""}` : d.online ? "connected" : ago(d.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function FleetReleases({ fleet, tree, devices }: { fleet: string; tree: string[]; devices: Device[] }) {
  const running = useRunning().filter((r) => tree.includes(r.device.fleet));
  return <Deployables target={{ fleet }} base={fleetPath(fleet)} label={fleet} running={running} runningOs={devices.flatMap((d) => d.os_version ?? [])} />;
}

/** One fleet: its devices, what it runs, its settings, and how devices join it. */
export function FleetPage() {
  const { fleet = "", tab } = useParams();
  const developer = useCan(fleet, "developer");
  const fleets = useFleets();
  const devices = useDevices();
  const all = fleets.data ?? [];
  const tree = under(all, fleet);
  const everything = (devices.data ?? []).filter((d) => tree.includes(d.fleet));
  const mine = everything.filter((d) => d.fleet === fleet);
  const children = all.filter((f) => f.parent === fleet);
  const on = everything.filter((d) => d.online).length;
  const off = everything.length - on;

  if (fleets.isSuccess && !fleets.data.some((f) => f.name === fleet)) {
    return (
      <>
        <Headline trail={[["Fleets", "/"]]}>{fleet}</Headline>
        <div className="border border-rule bg-sheet px-3">
          <Empty title="No fleet by that name.">
            <Link className="underline underline-offset-3" to="/">
              All fleets
            </Link>
          </Empty>
        </div>
      </>
    );
  }

  const titles: Record<string, string> = { releases: "Releases", variables: "Variables", enroll: "Enroll", settings: "Settings" };
  const title = tab ? titles[tab] : undefined;
  return (
    <>
      <Headline
        trail={fleetTrail(fleets.data, fleet, !!title)}
        aside={
          <>
            {everything.length > 0 && (
              <span className="flex gap-3 max-sm:hidden">
                <Readout n={on} label="online" state="ok" />
                <Readout n={off} label="offline" state={off ? "bad" : "off"} />
              </span>
            )}
            {developer && !title && <AddFleet parent={fleet} />}
          </>
        }
      >
        {title ?? fleet}
      </Headline>
      <Failure error={devices.error} />
      {(!tab || tab === "devices") && (
        <>
          {children.length > 0 && <FleetTable rows={children} all={all} devices={devices.data ?? []} />}
          <DevicesTab fleet={fleet} devices={mine} loaded={devices.isSuccess} canEnroll={developer} hasChildren={children.length > 0} />
        </>
      )}
      {tab === "releases" && <FleetReleases fleet={fleet} tree={tree} devices={everything} />}
      {tab === "variables" && <ScopeVariables scope="fleet" target={fleet} inherits={lineage(all, fleet).slice(0, -1)} />}
      {tab === "enroll" && <EnrollTab fleet={fleet} />}
      {tab === "settings" && developer && <SettingsTab fleet={fleet} fleets={all} />}
    </>
  );
}
