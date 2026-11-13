// Publishing from GitHub, on the Access page, and fleets following an app, on
// a fleet's Releases tab.

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { lineage, tool, type Release } from "../lib";
import { Button, Copy, Empty, Failure, Field, Input, Modal, Section } from "../ui";
import { useCan, useFleets } from "./fleet";

type Publisher = { repository: string; repository_id: string | null; refs: string[]; apps: string[]; workflow: string };
type Follow = { fleet: string; app: string; since: number };

const row = "row grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 text-sm sm:grid-cols-[minmax(0,1fr)_minmax(0,10rem)_minmax(0,14rem)_auto]";

function Workflow({ publisher, onClose }: { publisher: Publisher; onClose: () => void }) {
  return (
    <Modal title={`.github/workflows/via.yml in ${publisher.repository}`} onClose={onClose}>
      <pre className="max-h-96 overflow-auto border border-rule bg-well p-3 font-mono text-xs">{publisher.workflow}</pre>
      <div className="mt-4 flex justify-end gap-2">
        <Copy text={publisher.workflow} label="Copy workflow" />
        <form method="dialog">
          <Button type="submit">Close</Button>
        </form>
      </div>
    </Modal>
  );
}

/** Repositories whose Actions runs upload releases with no stored token. */
export function Publishers() {
  const qc = useQueryClient();
  const publishers = useQuery({
    queryKey: ["publishers"],
    queryFn: () => tool<{ publishers: Publisher[] }>("list_publishers").then((r) => r.publishers),
  });
  const [shown, setShown] = useState<Publisher | null>(null);
  const [repository, setRepository] = useState("");
  const [apps, setApps] = useState("");
  const [refs, setRefs] = useState("");
  const list = (s: string) => s.split(/[\s,]+/).filter(Boolean);
  const add = useMutation({
    mutationFn: () => tool<{ publisher: Publisher; workflow: string }>("add_publisher", { repository: repository.trim(), apps: list(apps), refs: list(refs) }),
    onSuccess: (r) => {
      setRepository("");
      setApps("");
      setRefs("");
      setShown({ ...r.publisher, workflow: r.workflow });
      qc.invalidateQueries({ queryKey: ["publishers"] });
    },
  });
  const remove = useMutation({
    mutationFn: (repo: string) => tool("remove_publisher", { repository: repo }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["publishers"] }),
  });

  return (
    <div className="grid gap-x-5 lg:grid-cols-[minmax(0,1fr)_24rem] lg:items-start">
      <Section title="Publish from GitHub">
        <Failure error={publishers.error ?? remove.error} />
        {publishers.data?.length === 0 && <Empty title="No repositories publish here.">A repository added here uploads releases from GitHub Actions with no token.</Empty>}
        {publishers.data?.map((p) => (
          <div key={p.repository} className={row}>
            <span className="truncate font-mono font-medium">{p.repository}</span>
            <span className="truncate font-mono text-xs text-ink-2 max-sm:hidden">{p.apps.join(", ")}</span>
            <span className="truncate font-mono text-xs text-ink-3 max-sm:hidden">{p.refs.join(", ")}</span>
            <span className="flex gap-1">
              <Button tone="quiet" size="sm" onClick={() => setShown(p)}>
                Workflow
              </Button>
              <Button tone="quiet" size="sm" className="hover:text-bad" disabled={remove.isPending} onClick={() => remove.mutate(p.repository)}>
                Remove
              </Button>
            </span>
          </div>
        ))}
      </Section>
      <Section title="Add a repository">
        <form
          className="space-y-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
            add.mutate();
          }}
        >
          <Field label="Repository">
            <Input required value={repository} onChange={(e) => setRepository(e.target.value)} placeholder="owner/name" className="font-mono" />
          </Field>
          <Field label="Apps it may release">
            <Input required value={apps} onChange={(e) => setApps(e.target.value)} placeholder="web, api" className="font-mono" />
          </Field>
          <Field label="Refs" hint="Leave empty for refs/heads/via and refs/tags/v*.">
            <Input value={refs} onChange={(e) => setRefs(e.target.value)} placeholder="refs/heads/via, refs/tags/v*" className="font-mono" />
          </Field>
          <Failure error={add.error} />
          <Button tone="primary" type="submit" disabled={!repository.trim() || !list(apps).length || add.isPending}>
            Add
          </Button>
        </form>
      </Section>
      {shown && <Workflow publisher={shown} onClose={() => setShown(null)} />}
    </div>
  );
}

/** Which apps this fleet deploys as soon as a new release is uploaded. */
export function Following({ fleet }: { fleet: string }) {
  const qc = useQueryClient();
  const developer = useCan(fleet, "developer");
  const fleets = useFleets();
  const releases = useQuery({
    queryKey: ["releases"],
    queryFn: () => tool<{ releases: Release[] }>("list_releases").then((r) => r.releases),
  });
  const follows = useQuery({
    queryKey: ["follows"],
    queryFn: () => tool<{ follows: Follow[] }>("list_follows").then((r) => r.follows),
  });
  const change = useMutation({
    mutationFn: ({ app, follow }: { app: string; follow: boolean }) => tool("follow_app", { fleet, app, follow }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["follows"] }),
  });
  const above = lineage(fleets.data ?? [], fleet);
  const apps = [...new Set((releases.data ?? []).map((r) => r.app))].sort();
  if (!apps.length) return null;
  return (
    <Section title="Deploy new releases">
      <Failure error={follows.error ?? change.error} />
      {apps.map((app) => {
        const own = follows.data?.find((f) => f.fleet === fleet && f.app === app);
        const inherited = follows.data?.find((f) => f.fleet !== fleet && f.app === app && above.includes(f.fleet));
        return (
          <div key={app} className="row grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-4 text-sm sm:grid-cols-[minmax(0,12rem)_minmax(0,1fr)_auto]">
            <span className="truncate font-mono font-semibold">{app}</span>
            <span className="truncate text-xs text-ink-2 max-sm:hidden">
              {own ? `Each release after ${own.since}, as it is uploaded` : inherited ? `Each new release, followed by ${inherited.fleet}` : "By hand"}
            </span>
            {developer && (
              <Button size="sm" tone={own ? "quiet" : "plain"} disabled={change.isPending} onClick={() => change.mutate({ app, follow: !own })}>
                {own ? "Stop" : "Follow"}
              </Button>
            )}
          </div>
        );
      })}
    </Section>
  );
}
