import { useState, type ReactNode } from "react";
import { Button, Checkbox, Combobox, Field, Input } from "../ui";

/** As `fleet_provisioning` shows them: passphrases only as `has_passphrase`. */
type ShownWifi = { ssid: string; hidden?: boolean; priority?: number; has_passphrase?: boolean };
type Network = { mode?: "dhcp" | "static"; address?: string; gateway?: string; dns?: string[]; interfaces?: ("wired" | "wifi")[] };
type Time = { timezone?: string; ntp?: string[] };
type Proxy = { http?: string; https?: string; no_proxy?: string[] };
export type Shown = { wifi?: ShownWifi[]; network?: Network; time?: Time; proxy?: Proxy };

type Wifi = { ssid: string; passphrase?: string; hidden?: boolean; priority?: number };
export type Settings = { wifi?: Wifi[]; network?: Network; time?: Time; proxy?: Proxy };

type Row = { ssid: string; passphrase: string; hidden: boolean; stored: boolean };

export type Form = {
  wifi: Row[];
  mode: "dhcp" | "static";
  address: string;
  gateway: string;
  dns: string;
  wired: boolean;
  wifiLink: boolean;
  timezone: string;
  ntp: string;
  http: string;
  https: string;
  noProxy: string;
};

const list = (s: string) => s.split(/[\s,]+/).filter(Boolean);

export function formFrom(s: Shown | undefined): Form {
  const links = s?.network?.interfaces ?? [];
  return {
    wifi: (s?.wifi ?? []).map((w) => ({ ssid: w.ssid, passphrase: "", hidden: !!w.hidden, stored: !!w.has_passphrase })),
    mode: s?.network?.mode ?? "dhcp",
    address: s?.network?.address ?? "",
    gateway: s?.network?.gateway ?? "",
    dns: (s?.network?.dns ?? []).join(", "),
    wired: links.length === 0 || links.includes("wired"),
    wifiLink: links.length === 0 || links.includes("wifi"),
    timezone: s?.time?.timezone ?? "",
    ntp: (s?.time?.ntp ?? []).join(", "),
    http: s?.proxy?.http ?? "",
    https: s?.proxy?.https ?? "",
    noProxy: (s?.proxy?.no_proxy ?? []).join(", "),
  };
}

/** The sections to send: each one that has something in it, or that the
 *  fleet had, so emptying it here overrides what it would inherit. A stored
 *  passphrase left blank is left out, which keeps it. */
export function settingsFrom(f: Form, had: Shown | undefined): Settings {
  const out: Settings = {};
  const rows = f.wifi.filter((w) => w.ssid.trim());
  if (rows.length || had?.wifi) {
    out.wifi = rows.map((w, i) => ({
      ssid: w.ssid.trim(),
      ...(w.stored && !w.passphrase ? {} : { passphrase: w.passphrase }),
      ...(w.hidden ? { hidden: true } : {}),
      priority: rows.length - i,
    }));
  }
  const dns = list(f.dns);
  if (f.mode === "static" || dns.length || had?.network) {
    const interfaces = [...(f.wired ? ["wired" as const] : []), ...(f.wifiLink ? ["wifi" as const] : [])];
    out.network = {
      mode: f.mode,
      ...(f.mode === "static" ? { address: f.address.trim(), ...(f.gateway.trim() ? { gateway: f.gateway.trim() } : {}) } : {}),
      dns,
      interfaces: interfaces.length === 2 ? [] : interfaces,
    };
  }
  if (f.timezone.trim() || f.ntp.trim() || had?.time) {
    out.time = { ...(f.timezone.trim() ? { timezone: f.timezone.trim() } : {}), ntp: list(f.ntp) };
  }
  if (f.http.trim() || f.https.trim() || f.noProxy.trim() || had?.proxy) {
    out.proxy = {
      ...(f.http.trim() ? { http: f.http.trim() } : {}),
      ...(f.https.trim() ? { https: f.https.trim() } : {}),
      no_proxy: list(f.noProxy),
    };
  }
  return out;
}

/** One line saying what the form holds, for when it is folded away. */
export function summary(f: Form): string {
  const wifi = f.wifi.filter((w) => w.ssid.trim()).length;
  return [
    f.mode === "static" ? `Static ${f.address || "address"}` : "DHCP",
    wifi ? `${wifi} Wi-Fi network${wifi > 1 ? "s" : ""}` : null,
    f.timezone || null,
    f.http || f.https ? "Proxy" : null,
  ]
    .filter(Boolean)
    .join(" · ");
}

const zones: string[] = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone") ?? [];

export function SystemSettings({ form, onChange }: { form: Form; onChange: (f: Form) => void }) {
  const set = (patch: Partial<Form>) => onChange({ ...form, ...patch });
  const setRow = (i: number, patch: Partial<Row>) => set({ wifi: form.wifi.map((w, j) => (j === i ? { ...w, ...patch } : w)) });
  const move = (i: number) => {
    const next = [...form.wifi];
    [next[i - 1], next[i]] = [next[i], next[i - 1]];
    set({ wifi: next });
  };
  return (
    <div className="space-y-4">
      <Field label="Wi-Fi" hint={form.wifi.length ? "Tried top first." : undefined}>
        <div className="space-y-2">
          {form.wifi.map((w, i) => (
            <div key={i} className="flex items-center gap-2">
              <Input aria-label="SSID" className="min-w-0 flex-1" value={w.ssid} onChange={(e) => setRow(i, { ssid: e.target.value })} placeholder="SSID" maxLength={32} />
              <Input
                aria-label="Passphrase"
                className="min-w-0 flex-1"
                type="password"
                autoComplete="new-password"
                value={w.passphrase}
                onChange={(e) => setRow(i, { passphrase: e.target.value })}
                placeholder={w.stored ? "Stored" : "Open"}
              />
              <Checkbox checked={w.hidden} onChange={(e) => setRow(i, { hidden: e.target.checked })}>
                Hidden
              </Checkbox>
              <Button size="sm" tone="quiet" aria-label="Try earlier" disabled={i === 0} onClick={() => move(i)}>
                ↑
              </Button>
              <Button size="sm" tone="quiet" aria-label="Remove" onClick={() => set({ wifi: form.wifi.filter((_, j) => j !== i) })}>
                ×
              </Button>
            </div>
          ))}
          <Button size="sm" onClick={() => set({ wifi: [...form.wifi, { ssid: "", passphrase: "", hidden: false, stored: false }] })}>
            Add network
          </Button>
        </div>
      </Field>
      <Field label="Addressing">
        <div className="flex flex-wrap items-center gap-4">
          <Checkbox checked={form.mode === "static"} onChange={(e) => set({ mode: e.target.checked ? "static" : "dhcp" })}>
            Static IPv4
          </Checkbox>
          <Checkbox checked={form.wired} onChange={(e) => set({ wired: e.target.checked })}>
            Wired
          </Checkbox>
          <Checkbox checked={form.wifiLink} onChange={(e) => set({ wifiLink: e.target.checked })}>
            Wi-Fi
          </Checkbox>
        </div>
      </Field>
      {form.mode === "static" && (
        <div className="grid grid-cols-2 gap-2">
          <Input aria-label="Address" className="font-mono" value={form.address} onChange={(e) => set({ address: e.target.value })} placeholder="192.168.10.20/24" required />
          <Input aria-label="Gateway" className="font-mono" value={form.gateway} onChange={(e) => set({ gateway: e.target.value })} placeholder="Gateway 192.168.10.1" />
        </div>
      )}
      <Field label="DNS servers" hint={form.mode === "dhcp" ? "Optional. Replace the ones DHCP offers." : "Optional."}>
        <Input className="font-mono" value={form.dns} onChange={(e) => set({ dns: e.target.value })} placeholder="192.168.10.1, 1.1.1.1" />
      </Field>
      <div className="grid grid-cols-2 gap-2">
        <Field label="Time zone">
          <Combobox aria-label="Time zone" creatable value={form.timezone} onChange={(v) => set({ timezone: v })} placeholder="UTC" options={zones.map((z) => ({ value: z, label: z }))} />
        </Field>
        <Field label="NTP servers">
          <Input className="font-mono" value={form.ntp} onChange={(e) => set({ ntp: e.target.value })} placeholder="OS default" />
        </Field>
      </div>
      <Field label="Proxy" hint="For the agent, Docker and app containers.">
        <div className="space-y-2">
          <div className="grid grid-cols-2 gap-2">
            <Input aria-label="HTTP proxy" className="font-mono" value={form.http} onChange={(e) => set({ http: e.target.value })} placeholder="HTTP http://proxy:3128" />
            <Input aria-label="HTTPS proxy" className="font-mono" value={form.https} onChange={(e) => set({ https: e.target.value })} placeholder="HTTPS http://proxy:3128" />
          </div>
          <Input aria-label="No proxy" className="font-mono" value={form.noProxy} onChange={(e) => set({ noProxy: e.target.value })} placeholder="No proxy .plant.lan, 10.0.0.0/8" />
        </div>
      </Field>
    </div>
  );
}

/** A folded section of a form: one line until opened. */
export function Fold({ title, detail, children }: { title: string; detail?: string; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="border-y border-rule">
      <button type="button" aria-expanded={open} onClick={() => setOpen(!open)} className="flex w-full cursor-pointer items-baseline justify-between gap-3 py-2 text-left">
        <span className="label">
          {open ? "▾" : "▸"} {title}
        </span>
        {!open && detail && <span className="truncate font-mono text-xs text-ink-3">{detail}</span>}
      </button>
      {open && <div className="pb-4">{children}</div>}
    </div>
  );
}
