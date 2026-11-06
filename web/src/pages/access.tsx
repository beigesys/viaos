import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { ago, authOptions, tool, type Level } from "../lib";
import { useIsAdmin, useMe } from "../main";
import { Button, Combobox, Copy, Empty, Failure, Field, Headline, Input, Section } from "../ui";
import { useFleets } from "./fleet";

type Token = { name: string; role: string; created_at: number; last_used: number | null };
type Grant = { subject: string; fleet: string | null; level: Level };
type Kind = "github" | "github-team" | "github-org" | "token";

const ROLES: { value: Level; label: string; detail: string }[] = [
  { value: "observer", label: "Observer", detail: "Looks: devices, health, logs, releases, variables" },
  { value: "operator", label: "Operator", detail: "Also changes devices' tags and their own variables" },
  { value: "developer", label: "Developer", detail: "Also deploys, updates the OS, sets fleet variables, opens terminals, enrolls devices" },
];

function who(subject: string, org?: string) {
  if (subject === "github-org") return `Everyone in ${org ?? "the GitHub organisation"}`;
  const [kind, name] = subject.split(/:(.*)/s);
  return kind === "github" ? `${name} on GitHub` : kind === "github-team" ? `GitHub team ${name}` : `Token ${name}`;
}

export function Access() {
  const admin = useIsAdmin();
  const me = useMe();
  const qc = useQueryClient();
  const fleets = useFleets();
  const options = useQuery({ queryKey: ["auth-options"], queryFn: authOptions });
  const org = options.data?.github?.org;
  const where = [{ value: "", label: "Every fleet" }, ...(fleets.data ?? []).map((f) => ({ value: f.name, label: f.name }))];

  const tokens = useQuery({
    queryKey: ["tokens"],
    queryFn: () => tool<{ tokens: Token[] }>("list_tokens").then((r) => r.tokens),
  });
  const grants = useQuery({
    queryKey: ["grants"],
    queryFn: () => tool<{ grants: Grant[] }>("list_grants").then((r) => r.grants),
  });
  const changed = () => {
    qc.invalidateQueries({ queryKey: ["tokens"] });
    qc.invalidateQueries({ queryKey: ["grants"] });
  };

  const [name, setName] = useState("");
  const [tokenRole, setTokenRole] = useState<Level | "admin">("admin");
  const [tokenFleet, setTokenFleet] = useState("");
  const create = useMutation({
    mutationFn: () =>
      tool<{ name: string; token: string }>("create_token", {
        name: name.trim(),
        ...(tokenRole === "admin" ? {} : { role: tokenRole, ...(tokenFleet ? { fleet: tokenFleet } : {}) }),
      }),
    onSuccess: () => {
      setName("");
      changed();
    },
  });
  const revoke = useMutation({
    mutationFn: (n: string) => tool("revoke_token", { name: n }),
    onSuccess: changed,
  });

  const [kind, setKind] = useState<Kind>("github");
  const [subject, setSubject] = useState("");
  const [fleet, setFleet] = useState("");
  const [level, setLevel] = useState<Level>("observer");
  const full = kind === "github-org" ? "github-org" : `${kind}:${subject.trim()}`;
  const grant = useMutation({
    mutationFn: () => tool("set_grant", { subject: full, role: level, ...(fleet ? { fleet } : {}) }),
    onSuccess: () => {
      setSubject("");
      changed();
    },
  });
  const ungrant = useMutation({
    mutationFn: (g: Grant) => tool("delete_grant", { subject: g.subject, ...(g.fleet ? { fleet: g.fleet } : {}) }),
    onSuccess: changed,
  });

  const server = location.origin;
  const grantsOf = (t: Token) => (grants.data ?? []).filter((g) => g.subject === `token:${t.name}`);
  return (
    <>
      <Headline>Access</Headline>
      <div className="grid gap-x-5 lg:grid-cols-[minmax(0,1fr)_24rem] lg:items-start">
        <div>
          <Section title="Who can do what">
            <Failure error={grants.error ?? ungrant.error} />
            {grants.data?.length === 0 && <Empty title="Nobody but admins.">Grant someone a role on a fleet, and it covers every fleet under it.</Empty>}
            {grants.data?.map((g) => (
              <div key={`${g.subject}/${g.fleet ?? ""}`} className="row grid grid-cols-[minmax(0,1fr)_8rem_auto] items-center gap-x-4 text-sm sm:grid-cols-[minmax(0,1fr)_minmax(0,12rem)_6rem_auto]">
                <span className="truncate font-medium">{who(g.subject, org)}</span>
                <span className="truncate font-mono text-xs text-ink-2 max-sm:hidden">{g.fleet ?? "every fleet"}</span>
                <span className="truncate font-mono text-xs text-ink-2">
                  {g.level}
                  <span className="sm:hidden"> on {g.fleet ?? "every fleet"}</span>
                </span>
                <Button tone="quiet" size="sm" className="hover:text-bad" disabled={ungrant.isPending} onClick={() => ungrant.mutate(g)}>
                  Remove
                </Button>
              </div>
            ))}
            <p className="py-2 text-xs text-ink-3">Admins can do everything and need no grant. With GitHub sign-in, organisation owners are admins. Someone gets a new team grant when they next sign in.</p>
          </Section>

          <Section title="Tokens">
            <Failure error={tokens.error ?? revoke.error} />
            {tokens.data?.length === 0 && <Empty title="No named tokens yet.">Signing in with the bootstrap admin token works until you make one.</Empty>}
            {tokens.data?.map((t) => (
              <div key={t.name} className="row grid grid-cols-[minmax(0,1fr)_8rem_auto] items-center gap-x-4 text-sm sm:grid-cols-[minmax(0,1fr)_minmax(0,12rem)_9rem_auto]">
                <span className="truncate font-medium">
                  {t.name}
                  {t.name === me.name && <span className="ml-2 font-mono text-xs font-normal text-ink-3">you</span>}
                </span>
                <span className="truncate font-mono text-xs text-ink-2">
                  {t.role === "admin" ? "admin" : grantsOf(t).map((g) => `${g.level} on ${g.fleet ?? "every fleet"}`).join(", ") || "nothing yet"}
                </span>
                <span className="font-mono text-xs text-ink-3 max-sm:hidden">used {ago(t.last_used)}</span>
                {admin && (
                  <Button
                    tone="quiet"
                    size="sm"
                    className="hover:text-bad"
                    disabled={revoke.isPending || t.name === me.name}
                    title={t.name === me.name ? "This would sign you out with no way back in" : undefined}
                    onClick={() => revoke.mutate(t.name)}
                  >
                    Revoke
                  </Button>
                )}
              </div>
            ))}
          </Section>
        </div>

        <div>
          <Section title="Grant a role">
            <form
              className="space-y-4 py-3"
              onSubmit={(e) => {
                e.preventDefault();
                grant.mutate();
              }}
            >
              <Field label="Who">
                <Combobox
                  aria-label="Who"
                  value={kind}
                  onChange={(k) => setKind(k as Kind)}
                  options={[
                    { value: "github", label: "A GitHub user" },
                    { value: "github-team", label: "A GitHub team", detail: org ? `in ${org}` : undefined },
                    { value: "github-org", label: "Everyone in the organisation", detail: org },
                    { value: "token", label: "A token" },
                  ]}
                />
              </Field>
              {kind !== "github-org" && (
                <Field label={kind === "github" ? "Login" : kind === "github-team" ? "Team slug" : "Token"}>
                  {kind === "token" ? (
                    <Combobox aria-label="Token" mono value={subject} onChange={setSubject} options={(tokens.data ?? []).filter((t) => t.role !== "admin").map((t) => ({ value: t.name, label: t.name }))} />
                  ) : (
                    <Input required value={subject} onChange={(e) => setSubject(e.target.value)} placeholder={kind === "github" ? "octocat" : "line-ops"} className="font-mono" />
                  )}
                </Field>
              )}
              <Field label="Where" hint="Includes every fleet under it.">
                <Combobox aria-label="Where" mono value={fleet} onChange={setFleet} options={where} />
              </Field>
              <Field label="Role">
                <Combobox aria-label="Role" value={level} onChange={(l) => setLevel(l as Level)} options={ROLES} />
              </Field>
              <Failure error={grant.error} />
              <Button tone="primary" type="submit" disabled={(kind !== "github-org" && !subject.trim()) || grant.isPending}>
                Grant
              </Button>
            </form>
          </Section>

          <Section title="New token">
            <form
              className="space-y-4 py-3"
              onSubmit={(e) => {
                e.preventDefault();
                create.mutate();
              }}
            >
              <Field label="For">
                <Input required value={name} onChange={(e) => setName(e.target.value)} placeholder="ana, or ci" />
              </Field>
              <Field label="Role">
                <Combobox aria-label="Token role" value={tokenRole} onChange={(r) => setTokenRole(r as Level | "admin")} options={[{ value: "admin", label: "Admin", detail: "Everything, everywhere" }, ...ROLES]} />
              </Field>
              {tokenRole !== "admin" && (
                <Field label="Where" hint="Includes every fleet under it.">
                  <Combobox aria-label="Token fleet" mono value={tokenFleet} onChange={setTokenFleet} options={where} />
                </Field>
              )}
              <Failure error={create.error} />
              <Button tone="primary" type="submit" disabled={!name.trim() || create.isPending}>
                Make token
              </Button>
            </form>
            {create.data && (
              <div className="mb-3 border-l-2 border-rule-strong pl-3">
                <p className="text-sm font-medium">{create.data.name}'s token, shown this once:</p>
                <p className="my-2 font-mono text-xs break-all">{create.data.token}</p>
                <div className="flex flex-wrap gap-2">
                  <Copy text={create.data.token} label="Copy token" />
                  <Copy text={`claude mcp add --transport http via ${server}/mcp --header "Authorization: Bearer ${create.data.token}"`} label="Copy for Claude" />
                </div>
              </div>
            )}
          </Section>
        </div>
      </div>
    </>
  );
}
