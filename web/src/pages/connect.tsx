import { useMutation, useQuery } from "@tanstack/react-query";
import { Mark } from "../main";
import { Button, buttonClass, Copy, Failure, Input } from "../ui";

type Pending = { request: string; client: string | null; host: string; local: boolean; who: string; admin: boolean };

async function pending(): Promise<Pending | null> {
  const res = await fetch("/oauth/request");
  if (res.status === 404) return null;
  if (!res.ok) throw new Error("Couldn't read this request.");
  return res.json();
}

// A loopback answer comes back as a link to show: the person may have
// approved on another machine, where localhost is nobody.
async function decide({ request, allow }: { request: string; allow: boolean }): Promise<string | null> {
  const res = await fetch("/oauth/decide", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ request, allow }),
  });
  if (!res.ok) throw new Error("This request has expired. Start again from your client.");
  const { redirect, loopback } = (await res.json()) as { redirect: string; loopback: boolean };
  if (loopback) return redirect;
  location.assign(redirect);
  return null;
}

export function Connect() {
  const request = useQuery({ queryKey: ["connect"], queryFn: pending, retry: false });
  const answer = useMutation({ mutationFn: decide });
  const p = request.data;
  const link = answer.data;
  return (
    <main className="flex min-h-dvh items-center justify-center p-4">
      <div className="w-full max-w-sm border border-rule bg-sheet">
        <div className="flex items-center justify-between border-b border-rule bg-well px-4 py-2.5">
          <span className="flex items-center gap-2 text-sm font-semibold tracking-wide uppercase">
            <Mark className="size-4" />
            viaos
          </span>
          <span className="label">Connect</span>
        </div>
        <div className="space-y-3 p-4 text-sm">
          <Failure error={request.error ?? answer.error} />
          {request.isSuccess && !p && <p>This request has expired. Start again from your client.</p>}
          {link ? (
            <>
              <p className="font-semibold">Allowed.</p>
              <Input readOnly value={link} className="font-mono text-xs" onFocus={(e) => e.currentTarget.select()} />
              <p className="text-ink-2">On another machine? Paste this link where your terminal asks for it. Use it within a minute.</p>
              <div className="flex gap-2 pt-1">
                <a href={link} className={buttonClass("primary")}>
                  Open
                </a>
                <Copy text={link} />
              </div>
            </>
          ) : p && (
            <>
              <p>
                <strong className="font-semibold">{p.local ? "A program on this computer" : p.host}</strong> wants to use viaos as {p.who}.
              </p>
              {p.client && <p className="text-ink-2">It calls itself {p.client}.</p>}
              <p className="text-ink-2">{p.admin ? "You're an admin, so it can do everything you can, on every fleet: deploy, run commands on devices, and manage access." : "It can do what your roles allow, on the fleets you can see."}</p>
              {p.local && <p className="text-ink-2">Any program on this computer can ask this. Allow it only if you just started this connection.</p>}
              <div className="flex gap-2 pt-1">
                <Button tone="primary" disabled={answer.isPending} onClick={() => answer.mutate({ request: p.request, allow: true })}>
                  Allow
                </Button>
                <Button tone="quiet" disabled={answer.isPending} onClick={() => answer.mutate({ request: p.request, allow: false })}>
                  Deny
                </Button>
              </div>
            </>
          )}
        </div>
      </div>
    </main>
  );
}
