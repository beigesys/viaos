import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { lazy, Suspense, useState } from "react";
import { diff, format, parse, type Change } from "../envtext";
import { ago, tool, type Schema, type SchemaVariable, type Variable } from "../lib";
import { useCan } from "./fleet";
import { Badge, Button, Checkbox, Combobox, Failure, Input, Section } from "../ui";

const Editor = lazy(() => import("../editor"));

export function useVariables() {
  return useQuery({
    queryKey: ["variables"],
    queryFn: () => tool<{ variables: Variable[]; schemas?: Schema[] }>("list_variables"),
  });
}

function useApps() {
  return useQuery({
    queryKey: ["releases"],
    queryFn: () => tool<{ releases: { app: string }[] }>("list_releases").then((r) => r.releases),
  });
}

type Outcome = { set: number; deleted: number; warnings?: string[]; devices: { device: string; pending?: string; error?: string }[] };

function summary(r: Outcome) {
  const failed = r.devices.filter((d) => d.error);
  const warned = r.warnings?.length ? ` ${r.warnings.join(" ")}` : "";
  if (failed.length) return `Saved, but ${failed.map((d) => `${d.device}: ${d.error}`).join("; ")}.${warned}`;
  const pending = r.devices.filter((d) => d.pending).length;
  const sent = r.devices.length - pending;
  return `Saved. Sent to ${sent} ${sent === 1 ? "device" : "devices"}${pending ? `, ${pending} offline will get it when they reconnect` : ""}. Only services whose values changed restart.${warned}`;
}

type Scope = { scope: "fleet" | "device"; target: string };

function useUpdate({ scope, target }: Scope, app: string, onDone: (message: string) => void) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (change: Change) =>
      tool<Outcome>("update_variables", {
        app,
        [scope]: target,
        set: change.set.map((e) => ({ key: e.key, value: e.value, secret: e.secret, ...(e.service ? { service: e.service } : {}) })),
        delete: change.delete.map((d) => ({ key: d.key, ...(d.service ? { service: d.service } : {}) })),
      }),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ["variables"] });
      onDone(summary(r));
    },
  });
}

// One set of columns, so every row lines up whatever is in its cells.
const row = "row grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 text-sm sm:grid-cols-[minmax(0,13rem)_6.5rem_minmax(0,1fr)_8.5rem_10rem]";
const stack = "max-sm:col-span-2";

function Actions({ children }: { children: React.ReactNode }) {
  return <div className="flex justify-end gap-1 max-sm:col-start-2 max-sm:row-start-1">{children}</div>;
}

type RowData = {
  key: string;
  service: string | null;
  value: string | null;
  secret: boolean;
  kind: "here" | "inherited" | "declared";
  where: React.ReactNode;
  overridden?: boolean;
  title?: string;
  required?: boolean;
  description?: string | null;
  origin?: string;
};

function ValueRow({ r, admin, at, app, onDone }: { r: RowData; admin: boolean; at: Scope; app: string; onDone: (m: string) => void }) {
  const [editing, setEditing] = useState(false);
  const [value, setValue] = useState("");
  const [secret, setSecret] = useState(r.secret);
  const update = useUpdate(at, app, (m) => {
    setEditing(false);
    onDone(m);
  });
  const entry = { key: r.key, service: r.service };
  const start = () => {
    setValue(r.secret ? "" : (r.kind === "declared" ? "" : (r.value ?? "")));
    setSecret(r.secret);
    update.reset();
    setEditing(true);
  };
  const save = () => update.mutate({ set: [{ ...entry, value, secret }], delete: [] });

  return (
    <div className={`${row} ${r.overridden ? "opacity-55" : ""}`} title={r.title}>
      <span className="truncate font-mono text-[0.82rem] font-medium">{r.key}</span>
      <span className={`truncate font-mono text-xs text-ink-2 ${stack} max-sm:row-start-3`}>{r.service ?? <span className="text-ink-3">all</span>}</span>
      {editing ? (
        <form
          className={`flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 ${stack} sm:col-span-2`}
          onSubmit={(e) => {
            e.preventDefault();
            save();
          }}
        >
          <Input
            autoFocus
            required
            aria-label={`Value of ${r.key}`}
            type={secret ? "password" : "text"}
            autoComplete="new-password"
            spellCheck={false}
            placeholder={r.secret ? "New value" : (r.value ?? "")}
            className="min-w-0 flex-1 font-mono"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") setEditing(false);
            }}
          />
          <Checkbox checked={secret} onChange={(e) => setSecret(e.target.checked)}>
            Secret
          </Checkbox>
        </form>
      ) : (
        <>
          <span className={`truncate font-mono text-xs ${stack} max-sm:row-start-2 ${r.kind === "declared" ? "text-ink-3" : "text-ink-2"}`}>
            {r.kind === "declared" ? (r.value != null ? `default: ${r.value}` : (r.description ?? "not set")) : r.secret ? "••••••••" : r.value}
          </span>
          <span className={`flex min-w-0 items-center gap-2 truncate text-xs text-ink-3 ${stack} max-sm:row-start-4`}>{r.where}</span>
        </>
      )}
      <Actions>
        {editing ? (
          <>
            <Button tone="quiet" size="sm" onClick={() => setEditing(false)}>
              Cancel
            </Button>
            <Button tone="primary" size="sm" disabled={!value || update.isPending} onClick={save}>
              {update.isPending ? "Saving" : "Save"}
            </Button>
          </>
        ) : admin ? (
          <>
            {r.kind === "here" && (
              <Button tone="quiet" size="sm" className="hover:text-bad" disabled={update.isPending} onClick={() => update.mutate({ set: [], delete: [entry] })}>
                Delete
              </Button>
            )}
            <Button tone="quiet" size="sm" onClick={start}>
              {r.kind === "here" ? "Edit" : r.kind === "inherited" ? "Override" : "Set"}
            </Button>
          </>
        ) : null}
      </Actions>
      {update.error ? (
        <div className="col-span-full">
          <Failure error={update.error} />
        </div>
      ) : null}
    </div>
  );
}

function AddRow({ at, app, schema, onDone, onCancel }: { at: Scope; app: string; schema?: Schema; onDone: (m: string) => void; onCancel: () => void }) {
  const [key, setKey] = useState("");
  const [service, setService] = useState("");
  const [value, setValue] = useState("");
  const [picked, setPicked] = useState<boolean | null>(null);
  const declared = schema?.variables.find((v) => v.key === key);
  const secret = picked ?? declared?.secret ?? true;
  const services = [...new Set(schema?.variables.flatMap((v) => v.services) ?? [])];
  const update = useUpdate(at, app, (m) => {
    onDone(m);
    onCancel();
  });
  const save = () => update.mutate({ set: [{ key: key.trim(), service: service.trim() || null, value, secret }], delete: [] });
  return (
    <form
      autoComplete="off"
      className={row}
      onSubmit={(e) => {
        e.preventDefault();
        save();
      }}
    >
      <Combobox creatable mono required aria-label="Name" className={stack} value={key} onChange={(k) => setKey(k.toUpperCase())} placeholder="NAME" options={(schema?.variables ?? []).map((v) => ({ value: v.key, label: v.key, detail: v.description ?? undefined, badge: v.required ? "required" : undefined }))} />
      {app ? <Combobox aria-label="Service" mono creatable={services.length === 0} className={stack} value={service} onChange={setService} placeholder="all" options={[{ value: "", label: "all" }, ...services.map((s) => ({ value: s, label: s }))]} /> : <span className={`font-mono text-xs text-ink-3 ${stack}`}>all</span>}
      <div className={`flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1 ${stack} sm:col-span-2`}>
        <Input required aria-label="Value" type={secret ? "password" : "text"} autoComplete="new-password" spellCheck={false} placeholder="value" className="min-w-0 flex-1 font-mono" value={value} onChange={(e) => setValue(e.target.value)} />
        <Checkbox checked={secret} onChange={(e) => setPicked(e.target.checked)}>
          Secret
        </Checkbox>
      </div>
      <div className={`flex justify-end gap-1 ${stack}`}>
        <Button tone="quiet" size="sm" onClick={onCancel}>
          Cancel
        </Button>
        <Button tone="primary" size="sm" type="submit" disabled={!key.trim() || !value || update.isPending}>
          {update.isPending ? "Saving" : "Save"}
        </Button>
      </div>
      {update.error ? (
        <div className="col-span-full">
          <Failure error={update.error} />
        </div>
      ) : null}
    </form>
  );
}

function TextMode({ at, app, own, inherited, declared, onDone }: { at: Scope; app: string; own: Variable[]; inherited: Variable[]; declared: SchemaVariable[]; onDone: (m: string) => void }) {
  const [text, setText] = useState(() => format(own, inherited, declared));
  const [generation, setGeneration] = useState(0);
  const parsed = parse(text);
  const { change, errors } = diff(own, parsed.entries);
  const problems = [...parsed.errors, ...errors];
  const count = change.set.length + change.delete.length;
  const update = useUpdate(at, app, onDone);
  return (
    <div className="py-3">
      <Suspense fallback={<div className="h-36 border border-rule bg-well" />}>
        <Editor key={generation} value={text} onChange={setText} label={app ? `Variables of ${app}` : "Variables for every app"} />
      </Suspense>
      <div className="mt-2 flex flex-wrap items-center justify-between gap-3">
        <p className="min-w-0 text-xs text-ink-3">
          <code className="font-mono">NAME=value</code>, <code className="font-mono">secret NAME=value</code>, and <code className="font-mono">[service]</code> for one service. Lines starting with # are ignored.
        </p>
        <div className="flex gap-1">
          <Button
            tone="quiet"
            size="sm"
            disabled={count === 0}
            onClick={() => {
              setText(format(own, inherited, declared));
              setGeneration((g) => g + 1);
            }}
          >
            Discard
          </Button>
          <Button tone="primary" size="sm" disabled={count === 0 || problems.length > 0 || update.isPending} onClick={() => update.mutate(change)}>
            {update.isPending ? "Saving" : count ? `Save ${count} ${count === 1 ? "change" : "changes"}` : "No changes"}
          </Button>
        </div>
      </div>
      {problems.map((p) => (
        <p key={p} role="alert" className="mt-1 border-l-2 border-bad pl-3 text-sm text-bad">
          {p}
        </p>
      ))}
      <Failure error={update.error} />
    </div>
  );
}

function AppVariables({ app, at, own, inherited, schema, suggest, admin }: { app: string; at: Scope; own: Variable[]; inherited: Variable[]; schema?: Schema; suggest?: Schema; admin: boolean }) {
  const [mode, setMode] = useState<"table" | "text">("table");
  const [adding, setAdding] = useState(false);
  const [note, setNote] = useState("");
  const same = (a: { key: string; service?: string | null }, b: { key: string; service?: string | null }) => a.key === b.key && (a.service ?? "") === (b.service ?? "");
  const declared = (schema?.variables ?? []).filter((d) => ![...own, ...inherited].some((v) => v.key === d.key));
  const here = at.scope === "device" ? "this device" : "this fleet";
  const rows: RowData[] = [
    ...own.map((v): RowData => ({ key: v.key, service: v.service ?? null, value: v.value, secret: v.secret, kind: "here", where: here, title: `${v.updated_by}, ${ago(v.updated_at)}` })),
    ...inherited.map((v, i): RowData => {
      // Listed nearest first, so anything earlier that matches beats this one.
      const beaten = own.some((o) => same(o, v)) || inherited.slice(0, i).some((o) => same(o, v));
      return { key: v.key, service: v.service ?? null, value: v.value, secret: v.secret, kind: "inherited", where: beaten ? `fleet ${v.target}, overridden` : `fleet ${v.target}`, overridden: beaten, origin: v.target };
    }),
    ...declared.map((d): RowData => ({ key: d.key, service: d.services.length === 1 ? d.services[0] : null, value: d.default, secret: d.secret, kind: "declared", required: d.required, description: d.description, where: d.required && d.default == null ? <Badge tone="warn">required</Badge> : "release default" })),
  ].sort((a, b) => a.key.localeCompare(b.key) || (a.service ?? "").localeCompare(b.service ?? ""));

  const label = app || "Every app";
  return (
    <Section
      title={label}
      aside={
        admin ? (
          <span className="flex gap-1" role="group" aria-label={`Edit ${label} as`}>
            {(["table", "text"] as const).map((m) => (
              <Button key={m} tone={mode === m ? "plain" : "quiet"} size="sm" aria-pressed={mode === m} onClick={() => setMode(m)}>
                {m}
              </Button>
            ))}
          </span>
        ) : undefined
      }
    >
      {mode === "text" ? (
        <TextMode key={own.map((v) => `${v.service}/${v.key}/${v.value}/${v.updated_at}`).join()} at={at} app={app} own={own} inherited={inherited} declared={declared} onDone={setNote} />
      ) : (
        <>
          <div className={`${row} max-sm:hidden`}>
            {["Name", "Service", "Value", "Where", ""].map((h, i) => (
              <span key={i} className="label">
                {h}
              </span>
            ))}
          </div>
          {rows.map((r) => (
            <ValueRow key={`${r.kind}/${r.origin ?? ""}/${r.service ?? ""}/${r.key}/${r.value}`} r={r} admin={admin} at={at} app={app} onDone={setNote} />
          ))}
          {rows.length === 0 && !adding && <p className="row text-sm text-ink-3">{app ? `Nothing set for ${app} yet.` : "Nothing set for every app yet. A value here reaches each service, in any app, that lists its name in its compose environment."}</p>}
          {adding && <AddRow at={at} app={app} schema={schema ?? suggest} onDone={setNote} onCancel={() => setAdding(false)} />}
          {admin && !adding && (
            <div className="py-1.5">
              <Button tone="quiet" size="sm" onClick={() => setAdding(true)}>
                + Add variable
              </Button>
            </div>
          )}
        </>
      )}
      {note && <p className="border-t border-rule py-2 text-xs text-ink-2">{note}</p>}
    </Section>
  );
}

/** The values set on one fleet or device, and what it inherits from the
 *  fleets above: `inherits` is those, outermost first. */
export function ScopeVariables({ scope, target, inherits, app: runningApp }: { scope: "fleet" | "device"; target: string; inherits: string[]; app?: string }) {
  // A fleet's values are a developer's; a device's own, an operator's.
  const admin = useCan(scope === "fleet" ? target : inherits[inherits.length - 1], scope === "fleet" ? "developer" : "operator");
  const vars = useVariables();
  const releases = useApps();
  const schemas = vars.data?.schemas ?? [];
  const own = (vars.data?.variables ?? []).filter((v) => v.scope === scope && v.target === target);
  // Nearest first, the order they take effect in reverse.
  const inherited = [...inherits].reverse().flatMap((f) => (vars.data?.variables ?? []).filter((v) => v.scope === "fleet" && v.target === f));
  const offered = scope === "fleet" ? (releases.data ?? []).map((r) => r.app) : runningApp ? [runningApp] : [];
  // "" is every app, and comes first.
  const apps = ["", ...[...new Set([...own.map((v) => v.app), ...inherited.map((v) => v.app), ...offered])].filter(Boolean).sort()];
  // For every app, any app's declared names are worth suggesting.
  const everyApp: Schema = { app: "", release: "", variables: [...new Map(schemas.flatMap((s) => s.variables).map((v) => [v.key, { ...v, services: [] }])).values()] };
  return (
    <div className="min-w-0">
      <Failure error={vars.error} />
      {apps.map((app) => (
        <AppVariables key={app} app={app} at={{ scope, target }} own={own.filter((v) => v.app === app)} inherited={inherited.filter((v) => v.app === app)} schema={app ? schemas.find((s) => s.app === app) : undefined} suggest={app ? undefined : everyApp} admin={admin} />
      ))}
    </div>
  );
}
