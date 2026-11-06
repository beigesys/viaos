import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { authOptions, signIn } from "../lib";
import { Mark } from "../main";
import { Button, buttonClass, Failure, Field, Input } from "../ui";

function refusal(code: string | null, org?: string) {
  switch (code) {
    case null:
      return null;
    case "not_member":
      return `That GitHub account isn't a member of ${org ?? "the organisation"}.`;
    case "no_access":
      return "That GitHub account hasn't been given access to anything here yet. An admin can grant it a role on the Access page.";
    case "restricted":
      return `${org ?? "The organisation"} hasn't approved this app yet. An owner can approve it in the organisation's third-party access settings.`;
    case "denied":
      return "GitHub sign-in was cancelled.";
    case "state":
      return "That sign-in expired. Try again.";
    default:
      return "GitHub sign-in failed. The server's log has the reason.";
  }
}

export function Login() {
  const qc = useQueryClient();
  const options = useQuery({ queryKey: ["auth-options"], queryFn: authOptions });
  const [token, setToken] = useState("");
  const [error, setError] = useState<unknown>();
  const [busy, setBusy] = useState(false);
  const [useToken, setUseToken] = useState(false);
  const github = options.data?.github;
  const refused = refusal(new URLSearchParams(location.search).get("auth"), github?.org);
  return (
    <main className="flex min-h-dvh items-center justify-center p-4">
      <div className="w-full max-w-sm border border-rule bg-sheet">
        <div className="flex items-center justify-between border-b border-rule bg-well px-4 py-2.5">
          <span className="flex items-center gap-2 text-sm font-semibold tracking-wide uppercase">
            <Mark className="size-4" />
            viaos
          </span>
          <span className="label">Control plane</span>
        </div>
        <div className="space-y-4 p-4">
          {refused && <Failure error={refused} />}
          {github && (
            <a href="/v1/auth/github" className={`${buttonClass("primary")} w-full`}>
              <svg aria-hidden viewBox="0 0 16 16" className="size-4">
                <path fill="currentColor" d="M8 0a8 8 0 0 0-2.53 15.59c.4.07.55-.17.55-.38v-1.34c-2.23.48-2.7-1.07-2.7-1.07-.36-.92-.89-1.17-.89-1.17-.73-.5.05-.49.05-.49.81.06 1.23.83 1.23.83.72 1.23 1.88.87 2.34.67.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.22 2.2.82a7.6 7.6 0 0 1 4 0c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.28.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48v2.2c0 .21.15.46.55.38A8 8 0 0 0 8 0Z" />
              </svg>
              Sign in with GitHub
            </a>
          )}
          {github && <p className="text-xs text-ink-3">For members of {github.org}.</p>}
          {github && !useToken ? (
            <Button tone="quiet" size="sm" onClick={() => setUseToken(true)}>
              Use an API token
            </Button>
          ) : (
            options.isSuccess && (
              <form
                className="space-y-4"
                onSubmit={async (e) => {
                  e.preventDefault();
                  setBusy(true);
                  setError(undefined);
                  try {
                    const caller = await signIn(token);
                    history.replaceState(null, "", location.pathname);
                    qc.setQueryData(["session"], caller);
                  } catch (err) {
                    setError(err);
                  } finally {
                    setBusy(false);
                  }
                }}
              >
                <Field label="API token" hint={<>Make one on the server: <code className="font-mono">via-server token create &lt;you&gt;</code></>}>
                  <Input autoFocus aria-label="API token" type="password" autoComplete="current-password" value={token} onChange={(e) => setToken(e.target.value)} placeholder="via_…" />
                </Field>
                <Failure error={error} />
                <Button tone={github ? "plain" : "primary"} type="submit" className="w-full" disabled={!token.trim() || busy}>
                  {busy ? "Checking…" : "Sign in"}
                </Button>
              </form>
            )
          )}
        </div>
      </div>
    </main>
  );
}
