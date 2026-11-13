import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ago, gb, slug, tool } from "../lib";
import { Button, buttonClass, Combobox, Copy, Empty, Failure, Field, Input, Notice, Section, Textarea } from "../ui";
import { useCan } from "./fleet";

type Image = { file: string; fleet?: string | null; download: string; size_mb: number; created_at?: number };
type DeviceType = { id: string; name: string; arch: string; detail: string; ready: boolean };

function Written({ image }: { image: Image }) {
  const cmd = `curl -sL ${image.download} | zstdcat | sudo dd of=/dev/sdX bs=4M status=progress conv=fsync`;
  return (
    <div className="border-b border-rule py-3">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <span className="font-mono text-sm font-medium break-all">{image.file}</span>
        <span className="font-mono text-xs text-ink-3">
          {gb(image.size_mb)}
          {image.created_at ? ` · ${ago(image.created_at)}` : ""}
        </span>
      </div>
      <div className="mt-2.5 flex flex-wrap gap-2">
        <a href={image.download} className={buttonClass("primary")}>
          Download
        </a>
        <Copy text={cmd} label="Copy write command" />
      </div>
    </div>
  );
}

export function EnrollTab({ fleet }: { fleet: string }) {
  const allowed = useCan(fleet, "developer");
  const qc = useQueryClient();
  const [hostname, setHostname] = useState("");
  const [picked, setPicked] = useState("");
  const [keys, setKeys] = useState("");
  const images = useQuery({
    queryKey: ["images"],
    queryFn: () => tool<{ device_types: DeviceType[]; images: Image[] }>("list_provisioning_images"),
    refetchInterval: 15000,
  });
  const types = images.data?.device_types ?? [];
  const chosen = types.find((t) => t.id === picked) ?? types.find((t) => t.ready) ?? types[0];
  const make = useMutation({
    mutationFn: () =>
      tool<Image>("create_provisioning_image", {
        fleet,
        device_type: chosen?.id,
        ...(hostname.trim() ? { title: hostname.trim() } : {}),
        ssh_keys: keys.split("\n").map((k) => k.trim()).filter(Boolean),
      }),
    onSuccess: () => {
      setHostname("");
      qc.invalidateQueries({ queryKey: ["images"] });
          },
  });
  const waiting = (images.data?.images ?? []).filter((i) => !i.fleet || i.fleet === fleet).sort((a, b) => (b.created_at ?? 0) - (a.created_at ?? 0));

  return (
    <>
      <div className="grid gap-x-5 lg:grid-cols-[minmax(0,26rem)_minmax(0,1fr)] lg:items-start">
        <Section title={`New image for ${fleet}`}>
          <form
            className="space-y-4 py-3"
            onSubmit={(e) => {
              e.preventDefault();
              make.mutate();
            }}
          >
            <Field label="Hardware" hint={chosen?.detail}>
              <Combobox
                aria-label="Hardware"
                placeholder="Loading…"
                value={chosen?.id ?? ""}
                onChange={setPicked}
                options={types.map((t) => ({ value: t.id, label: t.name, detail: t.detail, group: t.arch, badge: t.ready ? undefined : "no image" }))}
              />
            </Field>
            <Field label="Name" hint={slug(hostname) ? <>Hostname and slug <span className="font-mono">{slug(hostname)}</span></> : "Optional. The device keeps the hostname it reports otherwise."}>
              <Input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="Packing scale" maxLength={100} />
            </Field>
            <Field label="SSH keys" hint="Optional, one per line. Allowed to log in as root.">
              <Textarea value={keys} onChange={(e) => setKeys(e.target.value)} rows={2} placeholder="ssh-ed25519 AAAA…" />
            </Field>
            {chosen && !chosen.ready && (
              <Notice>
                No base image for {chosen.name} on this server yet. Upload one with <code className="font-mono text-xs">via base-image --device-type {chosen.id}</code>, or <code className="font-mono text-xs">{chosen.arch}</code> to share it across that architecture.
              </Notice>
            )}
            <Failure error={make.error} />
            <Button tone="primary" type="submit" disabled={!allowed || !fleet || make.isPending || !chosen?.ready}>
              {make.isPending ? "Making it, up to a minute…" : "Make image"}
            </Button>
            {!allowed && <p className="text-xs text-ink-3">Making images needs developer on {fleet}.</p>}
          </form>
        </Section>

        <div className="min-w-0">
          <Section title="Ready to write">
            <Failure error={images.error} />
            {images.data && waiting.length === 0 && <Empty title="No images waiting.">Each one carries a single-use token, so it's for one device, and it's deleted once that device enrolls.</Empty>}
            {waiting.map((i) => (
              <Written key={i.download} image={i} />
            ))}
          </Section>
        </div>
      </div>
    </>
  );
}
