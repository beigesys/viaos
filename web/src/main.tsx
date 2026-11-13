import { QueryCache, QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import { createContext, StrictMode, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import "./index.css";
import { SignedOut, whoami, type Caller } from "./lib";
import { Access } from "./pages/access";
import { Audit } from "./pages/audit";
import { AppPage, AppsPage, OsPage, OsVersionPage, ReleasePage } from "./pages/catalog";
import { DevicePage } from "./pages/device";
import { FleetPage, FleetsPage } from "./pages/fleet";
import { Connect } from "./pages/connect";
import { Login } from "./pages/login";
import { Sidebar } from "./sidebar";
import { Button, Menu } from "./ui";

const client = new QueryClient({
  queryCache: new QueryCache({
    onError: (e) => {
      if (e instanceof SignedOut) client.setQueryData(["session"], null);
    },
  }),
  defaultOptions: {
    queries: {
      retry: (n, e) => !(e instanceof SignedOut) && n < 1,
      refetchOnWindowFocus: true,
    },
  },
});

const Me = createContext<Caller>({ name: "", role: "member" });
export const useMe = () => useContext(Me);
export const useIsAdmin = () => useMe().role === "admin";

type Theme = "light" | "dark" | "auto";

function applyTheme(theme: Theme) {
  const dark = theme === "dark" || (theme === "auto" && matchMedia("(prefers-color-scheme: dark)").matches);
  document.documentElement.dataset.theme = dark ? "dark" : "light";
}

function storedTheme(): Theme {
  try {
    return (localStorage.getItem("via-theme") as Theme) || "auto";
  } catch {
    return "auto";
  }
}
applyTheme(storedTheme());

export function ThemeSwitch() {
  const [theme, setTheme] = useState<Theme>(storedTheme);
  useEffect(() => {
    applyTheme(theme);
    try {
      localStorage.setItem("via-theme", theme);
    } catch {}
    const q = matchMedia("(prefers-color-scheme: dark)");
    const on = () => applyTheme(theme);
    q.addEventListener("change", on);
    return () => q.removeEventListener("change", on);
  }, [theme]);
  const next: Record<Theme, Theme> = { auto: "light", light: "dark", dark: "auto" };
  return (
    <Button tone="quiet" size="sm" onClick={() => setTheme(next[theme])} title="Change theme">
      {theme}
    </Button>
  );
}

function Mark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 16 16" aria-hidden className={className}>
      <path fill="currentColor" d="M3 3h4v10H3v-2h2V5H3V3Zm6 0h4v2h-2v6h2v2H9V3Z" />
    </svg>
  );
}
export { Mark };

function Shell({ me, children }: { me: Caller; children: ReactNode }) {
  const [menu, setMenu] = useState(false);
  const close = useCallback(() => setMenu(false), []);
  return (
    <Menu.Provider value={() => setMenu(true)}>
      <div className="min-h-dvh lg:grid lg:grid-cols-[13.5rem_minmax(0,1fr)]">
        <Sidebar me={me} open={menu} onClose={close} />
        <main className="min-w-0 px-4 pb-6 sm:px-5">{children}</main>
      </div>
    </Menu.Provider>
  );
}

function App() {
  // An MCP client's sign-in, which needs no console session.
  if (location.pathname === "/connect") return <Connect />;
  return <Console />;
}

function Console() {
  const session = useQuery({ queryKey: ["session"], queryFn: whoami, staleTime: 60_000 });
  if (session.isPending) return null;
  if (!session.data) return <Login />;
  return (
    <Me.Provider value={session.data}>
      <BrowserRouter>
        <Shell me={session.data}>
          <Routes>
            <Route path="/" element={<FleetsPage />} />
            <Route path="/fleets/:fleet" element={<FleetPage />} />
            <Route path="/fleets/:fleet/:tab" element={<FleetPage />} />
            <Route path="/fleets/:fleet/releases/:app/:release" element={<ReleasePage />} />
            <Route path="/fleets/:fleet/releases/:app/:release/:view" element={<ReleasePage />} />
            <Route path="/fleets/:fleet/os/:version" element={<OsVersionPage />} />
            <Route path="/fleets/:fleet/devices/:device/releases/:app/:release" element={<ReleasePage />} />
            <Route path="/fleets/:fleet/devices/:device/releases/:app/:release/:view" element={<ReleasePage />} />
            <Route path="/fleets/:fleet/devices/:device" element={<DevicePage />} />
            <Route path="/fleets/:fleet/devices/:device/:tab" element={<DevicePage />} />
            <Route path="/fleets/:fleet/devices/:device/:tab/:container" element={<DevicePage />} />
            <Route path="/apps" element={<AppsPage />} />
            <Route path="/apps/:app" element={<AppPage />} />
            <Route path="/apps/:app/releases/:release" element={<ReleasePage />} />
            <Route path="/apps/:app/releases/:release/:view" element={<ReleasePage />} />
            <Route path="/os" element={<OsPage />} />
            <Route path="/os/:version" element={<OsVersionPage />} />
            <Route path="/audit" element={<Audit />} />
            <Route path="/access" element={<Access />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Shell>
      </BrowserRouter>
    </Me.Provider>
  );
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
