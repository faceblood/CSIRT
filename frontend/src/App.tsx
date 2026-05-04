import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";

type Tab =
  | "health"
  | "inventory"
  | "catalog"
  | "generate"
  | "rawbulk"
  | "history"
  | "jobs"
  | "runner"
  | "exercise"
  | "simulate"
  | "upload";

async function apiJson<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (init?.body && !(init.body instanceof FormData)) {
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
  }
  const res = await fetch(path, { ...init, headers });
  const text = await res.text();
  if (!res.ok) {
    throw new Error(text || `${res.status} ${res.statusText}`);
  }
  return text ? (JSON.parse(text) as T) : ({} as T);
}

async function apiVoid(path: string, init?: RequestInit): Promise<void> {
  const headers: Record<string, string> = {
    ...(init?.headers as Record<string, string> | undefined),
  };
  if (init?.body && !(init.body instanceof FormData)) {
    headers["Content-Type"] = headers["Content-Type"] ?? "application/json";
  }
  const res = await fetch(path, { ...init, headers });
  if (!res.ok) {
    throw new Error((await res.text()) || `${res.status} ${res.statusText}`);
  }
}

/** Optional syslog collector overrides for job start APIs */
function fortisiemExtras(fsIp: string, fsPort: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const ip = fsIp.trim();
  const ps = fsPort.trim();
  if (ip) out.fortisiem_ip = ip;
  if (ps) {
    const p = Number(ps);
    if (!Number.isFinite(p)) throw new Error("FortiSIEM port must be a number");
    out.fortisiem_port = p;
  }
  return out;
}

function TabBtn({
  id,
  active,
  onPick,
  children,
}: {
  id: Tab;
  active: Tab;
  onPick: (t: Tab) => void;
  children: React.ReactNode;
}) {
  const on = active === id;
  return (
    <button
      type="button"
      onClick={() => onPick(id)}
      className={`rounded-lg px-3 py-1.5 text-sm font-medium transition-colors ${
        on ? "bg-emerald-600 text-white" : "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"
      }`}
    >
      {children}
    </button>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("health");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const run = useCallback(async <T,>(fn: () => Promise<T>): Promise<T | undefined> => {
    setError(null);
    setBusy(true);
    try {
      return await fn();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      return undefined;
    } finally {
      setBusy(false);
    }
  }, []);

  const tabs = useMemo(
    () =>
      (
        [
          ["health", "Health"],
          ["inventory", "Inventory"],
          ["catalog", "Sources"],
          ["generate", "Generate"],
          ["rawbulk", "Raw / bulk"],
          ["history", "History"],
          ["jobs", "Jobs"],
          ["runner", "Playbook"],
          ["exercise", "Exercise"],
          ["simulate", "Simulate"],
          ["upload", "Upload"],
        ] as const
      ).map(([id, label]) => (
        <TabBtn key={id} id={id} active={tab} onPick={setTab}>
          {label}
        </TabBtn>
      )),
    [tab],
  );

  return (
    <div className="min-h-screen">
      <header className="border-b border-zinc-800 bg-zinc-900/80 backdrop-blur">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-2 px-4 py-3">
          <h1 className="mr-4 text-lg font-semibold tracking-tight text-white">FortiSIEM simulator</h1>
          {tabs}
          {busy ? (
            <span className="ml-auto text-xs text-zinc-500">Working…</span>
          ) : (
            <span className="ml-auto text-xs text-zinc-600">Proxy → /api</span>
          )}
        </div>
      </header>
      <main className="mx-auto max-w-6xl px-4 py-6">
        {error ? (
          <div className="mb-4 rounded-lg border border-red-900 bg-red-950/50 px-4 py-3 text-sm text-red-200">{error}</div>
        ) : null}

        {tab === "health" ? <HealthPanel run={run} /> : null}
        {tab === "inventory" ? <InventoryPanel run={run} /> : null}
        {tab === "catalog" ? <CatalogPanel run={run} /> : null}
        {tab === "generate" ? <GeneratePanel run={run} /> : null}
        {tab === "rawbulk" ? <RawBulkPanel run={run} /> : null}
        {tab === "history" ? <HistoryPanel run={run} /> : null}
        {tab === "jobs" ? <JobsPanel run={run} /> : null}
        {tab === "runner" ? <RunnerPanel run={run} /> : null}
        {tab === "exercise" ? <ExercisePanel run={run} /> : null}
        {tab === "simulate" ? <SimulatePanel run={run} /> : null}
        {tab === "upload" ? <UploadPanel run={run} /> : null}
      </main>
    </div>
  );
}

function PanelCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="rounded-xl border border-zinc-800 bg-zinc-900/40 p-5 shadow-xl">
      <h2 className="mb-4 text-base font-semibold text-white">{title}</h2>
      {children}
    </section>
  );
}

function HealthPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [data, setData] = useState<Record<string, unknown> | null>(null);
  useEffect(() => {
    void run(async () => {
      const j = await apiJson<Record<string, unknown>>("/api/health");
      setData(j);
      return j;
    });
  }, [run]);
  return (
    <PanelCard title="Health">
      <pre className="overflow-auto rounded-lg bg-black/40 p-4 text-xs text-emerald-400">{JSON.stringify(data, null, 2)}</pre>
      <button
        type="button"
        className="mt-3 rounded-lg bg-zinc-700 px-4 py-2 text-sm hover:bg-zinc-600"
        onClick={() =>
          void run(async () => {
            const j = await apiJson<Record<string, unknown>>("/api/health");
            setData(j);
          })
        }
      >
        Refresh
      </button>
    </PanelCard>
  );
}

function InventoryPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [slice, setSlice] = useState<"hosts" | "users" | "c2">("hosts");
  const [hosts, setHosts] = useState<unknown[]>([]);
  const [users, setUsers] = useState<unknown[]>([]);
  const [c2, setC2] = useState<unknown[]>([]);
  const [editHost, setEditHost] = useState<Record<string, string> | null>(null);
  const [editUser, setEditUser] = useState<Record<string, string> | null>(null);
  const [editC2, setEditC2] = useState<Record<string, string> | null>(null);

  const loadHosts = () =>
    run(async () => setHosts(await apiJson<unknown[]>("/api/inventory/hosts")));
  const loadUsers = () =>
    run(async () => setUsers(await apiJson<unknown[]>("/api/inventory/users")));
  const loadC2 = () => run(async () => setC2(await apiJson<unknown[]>("/api/inventory/c2")));

  useEffect(() => {
    void loadHosts();
    void loadUsers();
    void loadC2();
  }, [run]);

  const deleteHost = (id: string) =>
    run(async () => {
      if (!confirm(`Delete host ${id}?`)) return;
      await apiVoid(`/api/inventory/hosts/${encodeURIComponent(id)}`, { method: "DELETE" });
      setEditHost((h) => (h?.id === id ? null : h));
      await loadHosts();
    });

  const deleteUser = (id: string) =>
    run(async () => {
      if (!confirm(`Delete user ${id}?`)) return;
      await apiVoid(`/api/inventory/users/${encodeURIComponent(id)}`, { method: "DELETE" });
      setEditUser((u) => (u?.id === id ? null : u));
      await loadUsers();
    });

  const deleteC2Row = (id: string) =>
    run(async () => {
      if (!confirm(`Delete C2 row ${id}?`)) return;
      await apiVoid(`/api/inventory/c2/${encodeURIComponent(id)}`, { method: "DELETE" });
      setEditC2((c) => (c?.id === id ? null : c));
      await loadC2();
    });

  const btn = (id: typeof slice, label: string) => (
    <button
      type="button"
      onClick={() => setSlice(id)}
      className={`rounded-lg px-3 py-1.5 text-sm ${slice === id ? "bg-emerald-600 text-white" : "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"}`}
    >
      {label}
    </button>
  );

  return (
    <PanelCard title="Inventory">
      <div className="mb-4 flex flex-wrap gap-2">
        {btn("hosts", "Hosts")}
        {btn("users", "Users")}
        {btn("c2", "C2 / egress")}
      </div>
      <p className="mb-3 text-sm text-zinc-400">
        CSV-backed store under <code className="text-zinc-300">data/inventory/</code>. Import hosts via{" "}
        <code className="text-zinc-300">POST /api/inventory/hosts/import</code>.
      </p>

      {slice === "hosts" ? (
        <>
          <InventoryAddHostForm run={run} onAdded={() => void loadHosts()} />
          {editHost ? (
            <div className="mb-4 rounded-lg border border-amber-900/40 bg-amber-950/25 p-4 text-sm">
              <div className="mb-3 font-medium text-amber-200">Edit host ({editHost.id})</div>
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    await apiJson(`/api/inventory/hosts/${encodeURIComponent(editHost.id)}`, {
                      method: "PUT",
                      body: JSON.stringify({
                        hostname: editHost.hostname,
                        ip: editHost.ip,
                        os: editHost.os ?? "",
                        os_family: editHost.os_family || "linux",
                        role: editHost.role ?? "",
                        reporting_ip: editHost.reporting_ip?.trim() || null,
                        group: editHost.group ?? "",
                      }),
                    });
                    setEditHost(null);
                    await loadHosts();
                  });
                }}
              >
                <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  <input
                    required
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
                    placeholder="hostname"
                    value={editHost.hostname}
                    onChange={(ev) => setEditHost({ ...editHost, hostname: ev.target.value })}
                  />
                  <input
                    required
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
                    placeholder="ip"
                    value={editHost.ip}
                    onChange={(ev) => setEditHost({ ...editHost, ip: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="os"
                    value={editHost.os ?? ""}
                    onChange={(ev) => setEditHost({ ...editHost, os: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="os_family"
                    value={editHost.os_family ?? ""}
                    onChange={(ev) => setEditHost({ ...editHost, os_family: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="role"
                    value={editHost.role ?? ""}
                    onChange={(ev) => setEditHost({ ...editHost, role: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
                    placeholder="reporting_ip"
                    value={editHost.reporting_ip ?? ""}
                    onChange={(ev) => setEditHost({ ...editHost, reporting_ip: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="group"
                    value={editHost.group ?? ""}
                    onChange={(ev) => setEditHost({ ...editHost, group: ev.target.value })}
                  />
                </div>
                <div className="flex gap-2 pt-2">
                  <button type="submit" className="rounded bg-emerald-700 px-3 py-1 text-xs text-white">
                    Save
                  </button>
                  <button type="button" className="rounded bg-zinc-700 px-3 py-1 text-xs" onClick={() => setEditHost(null)}>
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          ) : null}
          <a
            href="/api/inventory/hosts/export"
            download="hosts.csv"
            className="mb-3 inline-block rounded-lg border border-zinc-600 px-3 py-1.5 text-sm text-sky-400 hover:bg-zinc-800"
          >
            Download hosts.csv
          </a>
          <div className="max-h-96 overflow-auto rounded-lg border border-zinc-800">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-zinc-800 text-zinc-300">
                <tr>
                  <th className="p-2">id</th>
                  <th className="p-2">hostname</th>
                  <th className="p-2">ip</th>
                  <th className="p-2">os_family</th>
                  <th className="p-2">role</th>
                  <th className="p-2 w-28">actions</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => {
                  const row = h as Record<string, string>;
                  return (
                    <tr key={row.id} className="border-t border-zinc-800 hover:bg-zinc-800/50">
                      <td className="p-2 font-mono text-zinc-500">{row.id}</td>
                      <td className="p-2">{row.hostname}</td>
                      <td className="p-2">{row.ip}</td>
                      <td className="p-2">{row.os_family}</td>
                      <td className="p-2">{row.role}</td>
                      <td className="p-2 whitespace-nowrap">
                        <button type="button" className="text-sky-400 hover:underline" onClick={() => setEditHost({ ...row })}>
                          Edit
                        </button>
                        <span className="mx-1 text-zinc-600">·</span>
                        <button type="button" className="text-red-400 hover:underline" onClick={() => void deleteHost(row.id)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <button type="button" className="mt-3 rounded-lg bg-zinc-700 px-4 py-2 text-sm hover:bg-zinc-600" onClick={() => void loadHosts()}>
            Reload hosts
          </button>
        </>
      ) : null}

      {slice === "users" ? (
        <>
          <InventoryAddUserForm run={run} onAdded={() => void loadUsers()} />
          {editUser ? (
            <div className="mb-4 rounded-lg border border-amber-900/40 bg-amber-950/25 p-4 text-sm">
              <div className="mb-3 font-medium text-amber-200">Edit user ({editUser.id})</div>
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    await apiJson(`/api/inventory/users/${encodeURIComponent(editUser.id)}`, {
                      method: "PUT",
                      body: JSON.stringify({
                        domain: editUser.domain || "corp",
                        sam: editUser.sam,
                        upn: editUser.upn?.trim() || null,
                        sid: editUser.sid?.trim() || null,
                        role: editUser.role?.trim() || null,
                      }),
                    });
                    setEditUser(null);
                    await loadUsers();
                  });
                }}
              >
                <div className="flex flex-wrap gap-2">
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="domain"
                    value={editUser.domain ?? ""}
                    onChange={(ev) => setEditUser({ ...editUser, domain: ev.target.value })}
                  />
                  <input
                    required
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
                    placeholder="sam"
                    value={editUser.sam ?? ""}
                    onChange={(ev) => setEditUser({ ...editUser, sam: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
                    placeholder="upn"
                    value={editUser.upn ?? ""}
                    onChange={(ev) => setEditUser({ ...editUser, upn: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
                    placeholder="sid"
                    value={editUser.sid ?? ""}
                    onChange={(ev) => setEditUser({ ...editUser, sid: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="role"
                    value={editUser.role ?? ""}
                    onChange={(ev) => setEditUser({ ...editUser, role: ev.target.value })}
                  />
                </div>
                <div className="flex gap-2 pt-2">
                  <button type="submit" className="rounded bg-emerald-700 px-3 py-1 text-xs text-white">
                    Save
                  </button>
                  <button type="button" className="rounded bg-zinc-700 px-3 py-1 text-xs" onClick={() => setEditUser(null)}>
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          ) : null}
          <div className="max-h-96 overflow-auto rounded-lg border border-zinc-800">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-zinc-800 text-zinc-300">
                <tr>
                  <th className="p-2">id</th>
                  <th className="p-2">domain</th>
                  <th className="p-2">sam</th>
                  <th className="p-2">upn</th>
                  <th className="p-2">role</th>
                  <th className="p-2 w-28">actions</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const row = u as Record<string, string | undefined>;
                  return (
                    <tr key={row.id} className="border-t border-zinc-800 hover:bg-zinc-800/50">
                      <td className="p-2 font-mono text-zinc-500">{row.id}</td>
                      <td className="p-2">{row.domain}</td>
                      <td className="p-2">{row.sam}</td>
                      <td className="p-2">{row.upn ?? "—"}</td>
                      <td className="p-2">{row.role ?? "—"}</td>
                      <td className="p-2 whitespace-nowrap">
                        <button
                          type="button"
                          className="text-sky-400 hover:underline"
                          onClick={() =>
                            setEditUser({
                              id: row.id ?? "",
                              domain: row.domain ?? "corp",
                              sam: row.sam ?? "",
                              upn: row.upn ?? "",
                              sid: row.sid ?? "",
                              role: row.role ?? "",
                            })
                          }
                        >
                          Edit
                        </button>
                        <span className="mx-1 text-zinc-600">·</span>
                        <button type="button" className="text-red-400 hover:underline" onClick={() => row.id && void deleteUser(row.id)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <button type="button" className="mt-3 rounded-lg bg-zinc-700 px-4 py-2 text-sm hover:bg-zinc-600" onClick={() => void loadUsers()}>
            Reload users
          </button>
        </>
      ) : null}

      {slice === "c2" ? (
        <>
          <InventoryAddC2Form run={run} onAdded={() => void loadC2()} />
          {editC2 ? (
            <div className="mb-4 rounded-lg border border-amber-900/40 bg-amber-950/25 p-4 text-sm">
              <div className="mb-3 font-medium text-amber-200">Edit C2 ({editC2.id})</div>
              <form
                className="space-y-2"
                onSubmit={(e) => {
                  e.preventDefault();
                  void run(async () => {
                    await apiJson(`/api/inventory/c2/${encodeURIComponent(editC2.id)}`, {
                      method: "PUT",
                      body: JSON.stringify({
                        ip: editC2.ip ?? "",
                        domain: editC2.domain ?? "",
                        country: editC2.country || "N/A",
                        asn: editC2.asn || "N/A",
                        role: editC2.role || "c2",
                      }),
                    });
                    setEditC2(null);
                    await loadC2();
                  });
                }}
              >
                <div className="flex flex-wrap gap-2">
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
                    placeholder="ip"
                    value={editC2.ip ?? ""}
                    onChange={(ev) => setEditC2({ ...editC2, ip: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="domain"
                    value={editC2.domain ?? ""}
                    onChange={(ev) => setEditC2({ ...editC2, domain: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="role"
                    value={editC2.role ?? ""}
                    onChange={(ev) => setEditC2({ ...editC2, role: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="country"
                    value={editC2.country ?? ""}
                    onChange={(ev) => setEditC2({ ...editC2, country: ev.target.value })}
                  />
                  <input
                    className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs"
                    placeholder="asn"
                    value={editC2.asn ?? ""}
                    onChange={(ev) => setEditC2({ ...editC2, asn: ev.target.value })}
                  />
                </div>
                <div className="flex gap-2 pt-2">
                  <button type="submit" className="rounded bg-emerald-700 px-3 py-1 text-xs text-white">
                    Save
                  </button>
                  <button type="button" className="rounded bg-zinc-700 px-3 py-1 text-xs" onClick={() => setEditC2(null)}>
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          ) : null}
          <div className="max-h-96 overflow-auto rounded-lg border border-zinc-800">
            <table className="w-full text-left text-xs">
              <thead className="sticky top-0 bg-zinc-800 text-zinc-300">
                <tr>
                  <th className="p-2">id</th>
                  <th className="p-2">ip</th>
                  <th className="p-2">domain</th>
                  <th className="p-2">role</th>
                  <th className="p-2">country</th>
                  <th className="p-2 w-28">actions</th>
                </tr>
              </thead>
              <tbody>
                {c2.map((c) => {
                  const row = c as Record<string, string>;
                  return (
                    <tr key={row.id} className="border-t border-zinc-800 hover:bg-zinc-800/50">
                      <td className="p-2 font-mono text-zinc-500">{row.id}</td>
                      <td className="p-2">{row.ip}</td>
                      <td className="p-2">{row.domain}</td>
                      <td className="p-2">{row.role}</td>
                      <td className="p-2">{row.country}</td>
                      <td className="p-2 whitespace-nowrap">
                        <button type="button" className="text-sky-400 hover:underline" onClick={() => setEditC2({ ...row })}>
                          Edit
                        </button>
                        <span className="mx-1 text-zinc-600">·</span>
                        <button type="button" className="text-red-400 hover:underline" onClick={() => void deleteC2Row(row.id)}>
                          Delete
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          <button type="button" className="mt-3 rounded-lg bg-zinc-700 px-4 py-2 text-sm hover:bg-zinc-600" onClick={() => void loadC2()}>
            Reload C2
          </button>
        </>
      ) : null}
    </PanelCard>
  );
}

function InventoryAddHostForm({
  run,
  onAdded,
}: {
  run: <T,>(fn: () => Promise<T>) => Promise<T | undefined>;
  onAdded: () => void;
}) {
  const [hostname, setHostname] = useState("");
  const [ip, setIp] = useState("");
  const [osFamily, setOsFamily] = useState("linux");
  const [role, setRole] = useState("");
  const [note, setNote] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await apiJson("/api/inventory/hosts", {
        method: "POST",
        body: JSON.stringify({
          hostname: hostname.trim(),
          ip: ip.trim(),
          os_family: osFamily.trim() || "linux",
          role: role.trim(),
        }),
      });
      setNote("Host added");
      setHostname("");
      setIp("");
      onAdded();
    });
  };
  return (
    <form className="mb-4 rounded-lg border border-zinc-800 bg-black/20 p-3 text-sm" onSubmit={submit}>
      <div className="mb-2 font-medium text-zinc-300">Add host</div>
      <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
        <input
          required
          placeholder="hostname"
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
          value={hostname}
          onChange={(ev) => setHostname(ev.target.value)}
        />
        <input
          required
          placeholder="ip"
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
          value={ip}
          onChange={(ev) => setIp(ev.target.value)}
        />
        <input
          placeholder="os_family"
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
          value={osFamily}
          onChange={(ev) => setOsFamily(ev.target.value)}
        />
        <input placeholder="role" className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs" value={role} onChange={(ev) => setRole(ev.target.value)} />
      </div>
      <button type="submit" className="mt-2 rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600">
        Create host
      </button>
      {note ? <span className="ml-3 text-xs text-emerald-500">{note}</span> : null}
    </form>
  );
}

function InventoryAddUserForm({
  run,
  onAdded,
}: {
  run: <T,>(fn: () => Promise<T>) => Promise<T | undefined>;
  onAdded: () => void;
}) {
  const [domain, setDomain] = useState("corp");
  const [sam, setSam] = useState("");
  const [note, setNote] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await apiJson("/api/inventory/users", {
        method: "POST",
        body: JSON.stringify({ domain: domain.trim() || "corp", sam: sam.trim() }),
      });
      setNote("User added");
      setSam("");
      onAdded();
    });
  };
  return (
    <form className="mb-4 rounded-lg border border-zinc-800 bg-black/20 p-3 text-sm" onSubmit={submit}>
      <div className="mb-2 font-medium text-zinc-300">Add user</div>
      <div className="flex flex-wrap gap-2">
        <input placeholder="domain" className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs" value={domain} onChange={(ev) => setDomain(ev.target.value)} />
        <input
          required
          placeholder="sam"
          className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
          value={sam}
          onChange={(ev) => setSam(ev.target.value)}
        />
        <button type="submit" className="rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600">
          Create user
        </button>
      </div>
      {note ? <span className="mt-2 block text-xs text-emerald-500">{note}</span> : null}
    </form>
  );
}

function InventoryAddC2Form({
  run,
  onAdded,
}: {
  run: <T,>(fn: () => Promise<T>) => Promise<T | undefined>;
  onAdded: () => void;
}) {
  const [ip, setIp] = useState("");
  const [domain, setDomain] = useState("");
  const [role, setRole] = useState("c2");
  const [note, setNote] = useState("");
  const submit = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      await apiJson("/api/inventory/c2", {
        method: "POST",
        body: JSON.stringify({
          ip: ip.trim(),
          domain: domain.trim(),
          role: role.trim() || "c2",
        }),
      });
      setNote("Row added");
      setIp("");
      setDomain("");
      onAdded();
    });
  };
  return (
    <form className="mb-4 rounded-lg border border-zinc-800 bg-black/20 p-3 text-sm" onSubmit={submit}>
      <div className="mb-2 font-medium text-zinc-300">Add C2 / egress row</div>
      <div className="flex flex-wrap gap-2">
        <input placeholder="ip" className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs" value={ip} onChange={(ev) => setIp(ev.target.value)} />
        <input placeholder="domain" className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs" value={domain} onChange={(ev) => setDomain(ev.target.value)} />
        <input placeholder="role" className="w-28 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-xs" value={role} onChange={(ev) => setRole(ev.target.value)} />
        <button type="submit" className="rounded bg-emerald-700 px-3 py-1 text-xs text-white hover:bg-emerald-600">
          Create
        </button>
      </div>
      {note ? <span className="mt-2 block text-xs text-emerald-500">{note}</span> : null}
    </form>
  );
}

function RawBulkPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [reportingIp, setReportingIp] = useState("10.0.0.1");
  const [hostname, setHostname] = useState("HOST");
  const [framing, setFraming] = useState("bsd");
  const [pri, setPri] = useState("<134>");
  const [appName, setAppName] = useState("");
  const [body, setBody] = useState("test message from simulator");
  const [dryRaw, setDryRaw] = useState(true);
  const [rawOut, setRawOut] = useState("");

  const [bulkLines, setBulkLines] = useState("line one\nline two");
  const [bulkMode, setBulkMode] = useState("verbatim");
  const [dryBulk, setDryBulk] = useState(true);
  const [bulkOut, setBulkOut] = useState("");

  const [fsIp, setFsIp] = useState("");
  const [fsPort, setFsPort] = useState("");
  const [collectorHint, setCollectorHint] = useState("");

  useEffect(() => {
    void run(async () => {
      const h = await apiJson<{ fortisiem_ip?: string; fortisiem_port?: number }>("/api/health");
      if (h.fortisiem_ip != null && h.fortisiem_port != null) {
        setCollectorHint(`Default collector: ${h.fortisiem_ip}:${h.fortisiem_port}`);
      }
    });
  }, [run]);

  const fortisiemFields = (): Record<string, unknown> => {
    const ip = fsIp.trim();
    const ps = fsPort.trim();
    const out: Record<string, unknown> = {};
    if (ip) out.fortisiem_ip = ip;
    if (ps) {
      const p = Number(ps);
      if (!Number.isFinite(p)) throw new Error("FortiSIEM port must be a number");
      out.fortisiem_port = p;
    }
    return out;
  };

  const sendRaw = (e: FormEvent) => {
    e.preventDefault();
    void run(async () => {
      let extra: Record<string, unknown> = {};
      try {
        extra = fortisiemFields();
      } catch (err) {
        setRawOut(err instanceof Error ? err.message : String(err));
        return;
      }
      const out = await apiJson<{ payload: string; status: string }>("/api/raw", {
        method: "POST",
        body: JSON.stringify({
          reporting_ip: reportingIp,
          hostname,
          framing,
          pri,
          app_name: appName || null,
          body,
          dry_run: dryRaw,
          ...extra,
        }),
      });
      setRawOut(JSON.stringify(out, null, 2));
    });
  };

  const sendBulk = (e: FormEvent) => {
    e.preventDefault();
    const lines = bulkLines.split(/\r?\n/).filter((x) => x.length > 0);
    void run(async () => {
      let extra: Record<string, unknown> = {};
      try {
        extra = fortisiemFields();
      } catch (err) {
        setBulkOut(err instanceof Error ? err.message : String(err));
        return;
      }
      const out = await apiJson<{ count: number }>("/api/bulk", {
        method: "POST",
        body: JSON.stringify({
          reporting_ip: reportingIp,
          lines,
          framing: "bsd",
          pri,
          mode: bulkMode,
          dry_run: dryBulk,
          ...extra,
        }),
      });
      setBulkOut(JSON.stringify(out, null, 2));
    });
  };

  return (
    <PanelCard title="Raw syslog & bulk lines">
      <div className="space-y-8">
        {collectorHint ? <p className="text-xs text-zinc-500">{collectorHint}</p> : null}
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block text-sm">
            FortiSIEM IP (optional override)
            <input
              className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs"
              value={fsIp}
              onChange={(ev) => setFsIp(ev.target.value)}
            />
          </label>
          <label className="block text-sm">
            FortiSIEM port (optional)
            <input
              className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs"
              placeholder="514"
              value={fsPort}
              onChange={(ev) => setFsPort(ev.target.value)}
            />
          </label>
        </div>
        <div>
          <h3 className="mb-2 text-sm font-medium text-white">Raw framed payload</h3>
          <p className="mb-3 text-xs text-zinc-500">Builds PRI + timestamp + hostname + body per framing (same as POST /api/raw).</p>
          <form className="space-y-3 text-sm" onSubmit={sendRaw}>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block">
                Reporting IP
                <input className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={reportingIp} onChange={(ev) => setReportingIp(ev.target.value)} />
              </label>
              <label className="block">
                Hostname
                <input className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={hostname} onChange={(ev) => setHostname(ev.target.value)} />
              </label>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block">
                Framing
                <select className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2" value={framing} onChange={(ev) => setFraming(ev.target.value)}>
                  <option value="bsd">bsd</option>
                  <option value="rfc5424">rfc5424</option>
                </select>
              </label>
              <label className="block">
                PRI
                <input className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={pri} onChange={(ev) => setPri(ev.target.value)} />
              </label>
            </div>
            <label className="block">
              App name (optional)
              <input className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={appName} onChange={(ev) => setAppName(ev.target.value)} />
            </label>
            <label className="block">
              Body
              <textarea className="mt-1 h-24 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={body} onChange={(ev) => setBody(ev.target.value)} />
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={dryRaw} onChange={(ev) => setDryRaw(ev.target.checked)} />
              Dry run
            </label>
            <button type="submit" className="rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500">
              Send raw
            </button>
          </form>
          {rawOut ? <pre className="mt-3 max-h-40 overflow-auto rounded-lg bg-black/40 p-3 text-xs">{rawOut}</pre> : null}
        </div>

        <div className="border-t border-zinc-800 pt-8">
          <h3 className="mb-2 text-sm font-medium text-white">Bulk lines</h3>
          <p className="mb-3 text-xs text-zinc-500">One syslog payload fragment per line — POST /api/bulk (uses reporting IP above).</p>
          <form className="space-y-3 text-sm" onSubmit={sendBulk}>
            <label className="block">
              Lines
              <textarea className="mt-1 h-36 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={bulkLines} onChange={(ev) => setBulkLines(ev.target.value)} />
            </label>
            <label className="block">
              Mode
              <select className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2" value={bulkMode} onChange={(ev) => setBulkMode(ev.target.value)}>
                <option value="verbatim">verbatim</option>
                <option value="wrap">wrap</option>
              </select>
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={dryBulk} onChange={(ev) => setDryBulk(ev.target.checked)} />
              Dry run
            </label>
            <button type="submit" className="rounded-lg bg-sky-700 px-4 py-2 text-sm text-white hover:bg-sky-600">
              Send bulk
            </button>
          </form>
          {bulkOut ? <pre className="mt-3 max-h-40 overflow-auto rounded-lg bg-black/40 p-3 text-xs">{bulkOut}</pre> : null}
        </div>
      </div>
    </PanelCard>
  );
}

function CatalogPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [sources, setSources] = useState<unknown[]>([]);
  const [campaigns, setCampaigns] = useState<{ id: string; label: string; steps: unknown[] }[]>([]);
  useEffect(() => {
    void run(async () => {
      const [s, c] = await Promise.all([
        apiJson<unknown[]>("/api/sources"),
        apiJson<{ id: string; label: string; steps: unknown[] }[]>("/api/campaigns"),
      ]);
      setSources(s);
      setCampaigns(c);
    });
  }, [run]);
  return (
    <PanelCard title="Sources & campaigns">
      <h3 className="mb-2 text-sm font-medium text-zinc-300">Generators</h3>
      <ul className="space-y-2 text-sm">
        {sources.map((s) => {
          const row = s as { id: string; label: string; event_types: { id: string }[] };
          return (
            <li key={row.id} className="rounded-lg border border-zinc-800 px-3 py-2">
              <span className="font-medium text-emerald-400">{row.id}</span>
              <span className="text-zinc-400"> — {row.label}</span>
              <span className="ml-2 text-xs text-zinc-600">({row.event_types?.length ?? 0} event types)</span>
            </li>
          );
        })}
      </ul>
      <h3 className="mb-2 mt-8 text-sm font-medium text-zinc-300">Campaigns</h3>
      <ul className="space-y-2 text-sm">
        {campaigns.map((c) => {
          const steps = (c.steps ?? []) as {
            idx?: number;
            tactic?: string;
            technique?: string;
            source_id?: string;
            event_type?: string;
          }[];
          return (
            <li key={c.id} className="rounded-lg border border-zinc-800 px-3 py-2">
              <details>
                <summary className="cursor-pointer text-zinc-200 marker:text-zinc-500">
                  <span className="font-medium text-sky-400">{c.id}</span>
                  <span className="text-zinc-400"> — {c.label}</span>
                  <span className="ml-2 text-xs text-zinc-600">({steps.length} steps)</span>
                </summary>
                <ol className="mt-2 max-h-56 list-decimal space-y-1 overflow-auto pl-5 text-xs text-zinc-400">
                  {steps.map((st, i) => (
                    <li key={st.idx ?? i}>
                      <span className="text-zinc-500">{st.idx ?? i + 1}.</span> {st.tactic ?? "?"} / {st.technique ?? "?"}{" "}
                      <span className="font-mono text-emerald-600">{st.source_id}</span> ·{" "}
                      <span className="font-mono text-zinc-300">{st.event_type}</span>
                    </li>
                  ))}
                </ol>
              </details>
            </li>
          );
        })}
      </ul>
    </PanelCard>
  );
}

function GeneratePanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [sources, setSources] = useState<{ id: string; event_types: { id: string }[] }[]>([]);
  const [sourceId, setSourceId] = useState("");
  const [eventType, setEventType] = useState("");
  const [paramsJson, setParamsJson] = useState("{}");
  const [count, setCount] = useState(1);
  const [dryRun, setDryRun] = useState(true);
  const [fsIp, setFsIp] = useState("");
  const [fsPort, setFsPort] = useState("");
  const [collectorHint, setCollectorHint] = useState("");
  const [last, setLast] = useState<string>("");

  useEffect(() => {
    void run(async () => {
      const s = await apiJson<{ id: string; event_types: { id: string }[] }[]>("/api/sources");
      setSources(s);
      if (s[0]) {
        setSourceId(s[0].id);
        setEventType(s[0].event_types[0]?.id ?? "");
      }
    });
  }, [run]);

  useEffect(() => {
    void run(async () => {
      const h = await apiJson<{ fortisiem_ip?: string; fortisiem_port?: number }>("/api/health");
      if (h.fortisiem_ip != null && h.fortisiem_port != null) {
        setCollectorHint(`Default collector from server: ${h.fortisiem_ip}:${h.fortisiem_port}`);
      }
    });
  }, [run]);

  const etOptions = sources.find((x) => x.id === sourceId)?.event_types ?? [];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    let params: Record<string, unknown> = {};
    try {
      params = JSON.parse(paramsJson) as Record<string, unknown>;
    } catch {
      setLast("Invalid JSON in params");
      return;
    }
    void run(async () => {
      const body: Record<string, unknown> = {
        source_id: sourceId,
        event_type: eventType,
        params,
        count,
        dry_run: dryRun,
      };
      const ip = fsIp.trim();
      const portStr = fsPort.trim();
      if (ip) body.fortisiem_ip = ip;
      if (portStr) {
        const p = Number(portStr);
        if (!Number.isFinite(p)) {
          setLast("FortiSIEM port must be a number");
          return;
        }
        body.fortisiem_port = p;
      }
      const out = await apiJson<{ results: unknown[] }>("/api/generate", {
        method: "POST",
        body: JSON.stringify(body),
      });
      setLast(JSON.stringify(out, null, 2));
    });
  };

  return (
    <PanelCard title="Generate single-source events">
      {collectorHint ? <p className="mb-3 text-xs text-zinc-500">{collectorHint}</p> : null}
      <form className="space-y-3 text-sm" onSubmit={submit}>
        <label className="block">
          <span className="text-zinc-400">Source</span>
          <select
            className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2"
            value={sourceId}
            onChange={(ev) => {
              setSourceId(ev.target.value);
              const s = sources.find((x) => x.id === ev.target.value);
              setEventType(s?.event_types[0]?.id ?? "");
            }}
          >
            {sources.map((s) => (
              <option key={s.id} value={s.id}>
                {s.id}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="text-zinc-400">Event type</span>
          <select
            className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2"
            value={eventType}
            onChange={(ev) => setEventType(ev.target.value)}
          >
            {etOptions.map((et) => (
              <option key={et.id} value={et.id}>
                {et.id}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="text-zinc-400">Params (JSON)</span>
          <textarea
            className="mt-1 h-28 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs"
            value={paramsJson}
            onChange={(ev) => setParamsJson(ev.target.value)}
          />
        </label>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="text-zinc-400">FortiSIEM IP (optional)</span>
            <input
              className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs"
              placeholder="override collector IP"
              value={fsIp}
              onChange={(ev) => setFsIp(ev.target.value)}
            />
          </label>
          <label className="block">
            <span className="text-zinc-400">FortiSIEM port (optional)</span>
            <input
              className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs"
              placeholder="514"
              value={fsPort}
              onChange={(ev) => setFsPort(ev.target.value)}
            />
          </label>
        </div>
        <div className="flex flex-wrap gap-4">
          <label className="flex items-center gap-2">
            Count
            <input
              type="number"
              min={1}
              className="w-24 rounded border border-zinc-700 bg-zinc-950 px-2 py-1"
              value={count}
              onChange={(ev) => setCount(Number(ev.target.value))}
            />
          </label>
          <label className="flex items-center gap-2">
            <input type="checkbox" checked={dryRun} onChange={(ev) => setDryRun(ev.target.checked)} />
            Dry run
          </label>
        </div>
        <button type="submit" className="rounded-lg bg-emerald-600 px-4 py-2 font-medium text-white hover:bg-emerald-500">
          Send
        </button>
      </form>
      {last ? (
        <pre className="mt-4 max-h-64 overflow-auto rounded-lg bg-black/40 p-3 text-xs text-zinc-300">{last}</pre>
      ) : null}
    </PanelCard>
  );
}

function HistoryPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [rows, setRows] = useState<unknown[]>([]);
  const [limit, setLimit] = useState(100);
  const [sourceFilter, setSourceFilter] = useState("");
  const [jobFilter, setJobFilter] = useState("");

  const load = () =>
    run(async () => {
      const qs = new URLSearchParams();
      qs.set("limit", String(Math.min(500, Math.max(1, limit))));
      const sid = sourceFilter.trim();
      const jid = jobFilter.trim();
      if (sid) qs.set("source_id", sid);
      if (jid) qs.set("job_id", jid);
      const list = await apiJson<unknown[]>(`/api/history?${qs.toString()}`);
      setRows(list);
    });
  useEffect(() => {
    void load();
  }, [run]);
  return (
    <PanelCard title="Recent history">
      <div className="mb-3 flex flex-wrap items-end gap-3 text-sm">
        <label className="flex flex-col gap-1">
          <span className="text-xs text-zinc-500">Limit</span>
          <input
            type="number"
            min={1}
            max={500}
            className="w-20 rounded border border-zinc-700 bg-zinc-950 px-2 py-1"
            value={limit}
            onChange={(ev) => setLimit(Number(ev.target.value))}
          />
        </label>
        <label className="min-w-[140px] flex flex-col gap-1">
          <span className="text-xs text-zinc-500">Source id</span>
          <input
            className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
            placeholder="e.g. linux"
            value={sourceFilter}
            onChange={(ev) => setSourceFilter(ev.target.value)}
          />
        </label>
        <label className="min-w-[200px] flex flex-col gap-1">
          <span className="text-xs text-zinc-500">Job id</span>
          <input
            className="rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs"
            placeholder="UUID"
            value={jobFilter}
            onChange={(ev) => setJobFilter(ev.target.value)}
          />
        </label>
        <button type="button" className="rounded-lg bg-zinc-700 px-3 py-1.5 text-sm" onClick={() => void load()}>
          Refresh
        </button>
      </div>
      <div className="max-h-[480px] space-y-2 overflow-auto">
        {rows.map((r) => {
          const e = r as Record<string, unknown>;
          return (
            <div key={String(e.id)} className="rounded-lg border border-zinc-800 bg-black/30 p-3 text-xs">
              <div className="flex flex-wrap gap-2 text-zinc-400">
                <span>{String(e.ts)}</span>
                <span className="text-emerald-500">{String(e.status)}</span>
                <span>{String(e.source_id ?? "—")}</span>
                {e.job_id ? <span className="font-mono text-zinc-500">{String(e.job_id)}</span> : null}
                <span>{String(e.reporting_ip)}</span>
              </div>
              <div className="mt-1 font-mono text-zinc-300">{String(e.payload_preview ?? "")}</div>
            </div>
          );
        })}
      </div>
    </PanelCard>
  );
}

function JobsPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [jid, setJid] = useState("");
  const [jumpIdx, setJumpIdx] = useState("1");
  const [status, setStatus] = useState<string>("");

  const refresh = () =>
    run(async () => {
      if (!jid.trim()) return;
      const s = await apiJson<unknown>(`/api/jobs/${encodeURIComponent(jid.trim())}`);
      setStatus(JSON.stringify(s, null, 2));
    });

  const act = (path: string) =>
    run(async () => {
      if (!jid.trim()) return;
      await apiJson(`/api/jobs/${encodeURIComponent(jid.trim())}${path}`, { method: "POST" });
      await refresh();
    });

  const jumpInject = () =>
    run(async () => {
      if (!jid.trim()) return;
      const n = Number.parseInt(jumpIdx, 10);
      if (!Number.isFinite(n) || n < 1) throw new Error("Jump target must be a positive integer (1-based inject index)");
      await apiJson(`/api/jobs/${encodeURIComponent(jid.trim())}/jump-inject`, {
        method: "POST",
        body: JSON.stringify({ inject_idx: n }),
      });
      await refresh();
    });

  return (
    <PanelCard title="Job control">
      <p className="mb-3 text-sm text-zinc-400">Use job IDs returned by playbook, keepalive, simulate, or exercise runs.</p>
      <div className="flex flex-wrap gap-2">
        <input
          className="min-w-[280px] flex-1 rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-sm"
          placeholder="job UUID"
          value={jid}
          onChange={(ev) => setJid(ev.target.value)}
        />
        <button type="button" className="rounded-lg bg-zinc-700 px-3 py-2 text-sm" onClick={() => void refresh()}>
          Status
        </button>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <button type="button" className="rounded-lg bg-amber-700 px-3 py-2 text-sm" onClick={() => void act("/pause")}>
          Pause
        </button>
        <button type="button" className="rounded-lg bg-emerald-700 px-3 py-2 text-sm" onClick={() => void act("/resume")}>
          Resume
        </button>
        <button type="button" className="rounded-lg bg-zinc-700 px-3 py-2 text-sm" onClick={() => void act("/skip-inject")}>
          Skip inject
        </button>
        <label className="flex items-center gap-2 text-sm text-zinc-400">
          Jump to
          <input
            type="number"
            min={1}
            className="w-16 rounded border border-zinc-700 bg-zinc-950 px-2 py-1 text-zinc-100"
            value={jumpIdx}
            onChange={(ev) => setJumpIdx(ev.target.value)}
          />
        </label>
        <button type="button" className="rounded-lg bg-indigo-700 px-3 py-2 text-sm" onClick={() => void jumpInject()}>
          Jump (exercise)
        </button>
        <button type="button" className="rounded-lg bg-red-900 px-3 py-2 text-sm" onClick={() => void act("/stop")}>
          Stop
        </button>
      </div>
      {status ? <pre className="mt-4 max-h-96 overflow-auto rounded-lg bg-black/40 p-4 text-xs">{status}</pre> : null}
    </PanelCard>
  );
}

function RunnerPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [actorsJson, setActorsJson] = useState("{}");
  const [stepDelay, setStepDelay] = useState(0.3);
  const [intervalSec, setIntervalSec] = useState(60);
  const [jobFsIp, setJobFsIp] = useState("");
  const [jobFsPort, setJobFsPort] = useState("");
  const [msg, setMsg] = useState("");

  const startPlaybook = () =>
    run(async () => {
      let actors: Record<string, string | null> = {};
      try {
        actors = JSON.parse(actorsJson) as Record<string, string | null>;
      } catch {
        setMsg("Invalid actors JSON");
        return;
      }
      let extras: Record<string, unknown> = {};
      try {
        extras = fortisiemExtras(jobFsIp, jobFsPort);
      } catch (e) {
        setMsg(e instanceof Error ? e.message : String(e));
        return;
      }
      const out = await apiJson<{ job_id: string }>("/api/playbook/start", {
        method: "POST",
        body: JSON.stringify({
          campaign_id: "apt_mitre",
          actors,
          mode: "auto",
          step_delay: stepDelay,
          ...extras,
        }),
      });
      setMsg(`Playbook job ${out.job_id} — use Jobs tab for pause/stop`);
    });

  const startKeepalive = () =>
    run(async () => {
      let extras: Record<string, unknown> = {};
      try {
        extras = fortisiemExtras(jobFsIp, jobFsPort);
      } catch (e) {
        setMsg(e instanceof Error ? e.message : String(e));
        return;
      }
      const out = await apiJson<{ job_id: string }>("/api/keepalive/start", {
        method: "POST",
        body: JSON.stringify({
          interval_seconds: intervalSec,
          ...extras,
        }),
      });
      setMsg(`Keepalive job ${out.job_id} — use Jobs tab for pause/stop`);
    });

  return (
    <PanelCard title="Playbook & baseline">
      <p className="mb-4 text-sm text-zinc-400">
        Starts background jobs for the condensed APT MITRE playbook or round-robin FortiGate/FortiProxy/Linux benign noise. Control them from the Jobs tab (
        <code className="text-zinc-300">/api/jobs/…</code>
        ). Leave collector fields empty to use server defaults from Health.
      </p>
      <div className="mb-6 grid gap-3 sm:grid-cols-2">
        <label className="block text-xs text-zinc-400">
          FortiSIEM IP (optional)
          <input className="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-sm" value={jobFsIp} onChange={(ev) => setJobFsIp(ev.target.value)} />
        </label>
        <label className="block text-xs text-zinc-400">
          FortiSIEM port (optional)
          <input className="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-sm" placeholder="514" value={jobFsPort} onChange={(ev) => setJobFsPort(ev.target.value)} />
        </label>
      </div>
      <div className="space-y-6">
        <div>
          <h3 className="mb-2 text-sm font-medium text-white">APT playbook</h3>
          <label className="block text-sm text-zinc-400">
            Actors JSON (optional slot IDs)
            <textarea
              className="mt-1 h-28 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs text-zinc-100"
              value={actorsJson}
              onChange={(ev) => setActorsJson(ev.target.value)}
            />
          </label>
          <label className="mt-2 flex items-center gap-2 text-sm text-zinc-400">
            Step delay (s)
            <input
              type="number"
              step={0.05}
              min={0}
              className="w-28 rounded border border-zinc-700 bg-zinc-950 px-2 py-1"
              value={stepDelay}
              onChange={(ev) => setStepDelay(Number(ev.target.value))}
            />
          </label>
          <button type="button" className="mt-3 rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500" onClick={() => void startPlaybook()}>
            Start playbook
          </button>
        </div>
        <div className="border-t border-zinc-800 pt-6">
          <h3 className="mb-2 text-sm font-medium text-white">Keepalive baseline</h3>
          <label className="flex items-center gap-2 text-sm text-zinc-400">
            Interval (seconds)
            <input
              type="number"
              step={1}
              min={1}
              className="w-28 rounded border border-zinc-700 bg-zinc-950 px-2 py-1"
              value={intervalSec}
              onChange={(ev) => setIntervalSec(Number(ev.target.value))}
            />
          </label>
          <button type="button" className="mt-3 rounded-lg bg-sky-700 px-4 py-2 text-sm text-white hover:bg-sky-600" onClick={() => void startKeepalive()}>
            Start keepalive
          </button>
        </div>
      </div>
      {msg ? <p className="mt-4 text-sm text-emerald-400">{msg}</p> : null}
    </PanelCard>
  );
}

function ExercisePanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [mode, setMode] = useState<"run" | "edit">("run");
  const [list, setList] = useState<{ id: string; label: string; inject_count: number }[]>([]);
  const [eid, setEid] = useState("");
  const [actorsJson, setActorsJson] = useState("{}");
  const [scale, setScale] = useState(1);
  const [jobFsIp, setJobFsIp] = useState("");
  const [jobFsPort, setJobFsPort] = useState("");
  const [msg, setMsg] = useState("");
  const [timeline, setTimeline] = useState<{ idx: number; name: string; offset: string }[]>([]);
  const [editorDoc, setEditorDoc] = useState("{}");

  useEffect(() => {
    void run(async () => {
      const rows = await apiJson<{ id: string; label: string; inject_count: number }[]>("/api/exercises");
      setList(rows);
      if (rows.length) setEid((prev) => prev || rows[0].id);
    });
  }, [run]);

  useEffect(() => {
    if (!eid || mode !== "run") return;
    void run(async () => {
      const t = await apiJson<{ injects: { idx: number; name: string; offset: string }[] }>(
        `/api/exercises/${encodeURIComponent(eid)}/timeline`,
      );
      setTimeline(t.injects);
    });
  }, [eid, mode, run]);

  useEffect(() => {
    if (!eid || mode !== "edit") return;
    void run(async () => {
      const doc = await apiJson<Record<string, unknown>>(`/api/exercises/${encodeURIComponent(eid)}`);
      setEditorDoc(JSON.stringify(doc, null, 2));
    });
  }, [eid, mode, run]);

  const runEx = () =>
    run(async () => {
      let actors: Record<string, string | null> = {};
      try {
        actors = JSON.parse(actorsJson) as Record<string, string | null>;
      } catch {
        setMsg("Invalid actors JSON");
        return;
      }
      let extras: Record<string, unknown> = {};
      try {
        extras = fortisiemExtras(jobFsIp, jobFsPort);
      } catch (e) {
        setMsg(e instanceof Error ? e.message : String(e));
        return;
      }
      const out = await apiJson<{ job_id: string }>(`/api/exercises/${encodeURIComponent(eid)}/run`, {
        method: "POST",
        body: JSON.stringify({ actors, time_scale: scale, ...extras }),
      });
      setMsg(`Started job ${out.job_id}`);
    });

  const reloadEditor = () =>
    run(async () => {
      if (!eid) return;
      const doc = await apiJson<Record<string, unknown>>(`/api/exercises/${encodeURIComponent(eid)}`);
      setEditorDoc(JSON.stringify(doc, null, 2));
      setMsg("Loaded from server");
    });

  const saveEditor = () =>
    run(async () => {
      let doc: Record<string, unknown>;
      try {
        doc = JSON.parse(editorDoc) as Record<string, unknown>;
      } catch {
        setMsg("Invalid JSON — fix before save");
        return;
      }
      if (!doc.id || typeof doc.id !== "string") {
        setMsg('Exercise JSON must include string "id"');
        return;
      }
      await apiJson("/api/exercises", { method: "POST", body: JSON.stringify(doc) });
      const rows = await apiJson<{ id: string; label: string; inject_count: number }[]>("/api/exercises");
      setList(rows);
      setEid(String(doc.id));
      setMsg(`Saved ${String(doc.id)}`);
    });

  const deleteExercise = () =>
    run(async () => {
      if (!eid || !confirm(`Delete exercise "${eid}" from disk?`)) return;
      await apiJson(`/api/exercises/${encodeURIComponent(eid)}`, { method: "DELETE" });
      const rows = await apiJson<{ id: string; label: string; inject_count: number }[]>("/api/exercises");
      setList(rows);
      const next = rows[0]?.id ?? "";
      setEid(next);
      setEditorDoc("{}");
      setMsg(rows.length ? `Deleted — selected ${next}` : "Deleted — no scenarios left");
    });

  const newTemplate = () => {
    const id = `scenario_${Date.now()}`;
    setEditorDoc(
      JSON.stringify(
        {
          id,
          label: "Untitled tabletop",
          description: "",
          required_actors: [],
          injects: [
            {
              name: "sample inject",
              offset: "0s",
              narrative: "",
              role: "",
              expected_decision: "",
              log_actions: [],
            },
          ],
        },
        null,
        2,
      ),
    );
    setMsg(`Template with id "${id}" — edit and Save`);
  };

  const exBtn = (m: typeof mode, label: string) => (
    <button
      type="button"
      onClick={() => {
        setMode(m);
        setMsg("");
      }}
      className={`rounded-lg px-3 py-1.5 text-sm ${mode === m ? "bg-emerald-600 text-white" : "bg-zinc-800 text-zinc-300 hover:bg-zinc-700"}`}
    >
      {label}
    </button>
  );

  return (
    <PanelCard title="Tabletop exercises">
      <div className="mb-4 flex flex-wrap gap-2">
        {exBtn("run", "Run")}
        {exBtn("edit", "Edit JSON")}
      </div>

      <label className="block text-sm">
        <span className="text-zinc-400">Exercise</span>
        <select
          className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2"
          value={eid}
          onChange={(ev) => setEid(ev.target.value)}
          disabled={list.length === 0}
        >
          {list.length === 0 ? <option value="">— none —</option> : null}
          {list.map((x) => (
            <option key={x.id} value={x.id}>
              {x.label} ({x.inject_count} injects)
            </option>
          ))}
        </select>
      </label>
      {list.length === 0 ? <p className="mt-2 text-sm text-amber-600">No scenarios found — switch to Edit JSON and use New template, then Save.</p> : null}

      {mode === "run" ? (
        <>
          {timeline.length > 0 ? (
            <div className="mt-3 rounded-lg border border-zinc-800 bg-black/25 p-3 text-xs">
              <div className="mb-2 font-medium text-zinc-400">Timeline (runner order — use index for Jobs → Jump)</div>
              <ol className="max-h-40 list-decimal space-y-1 overflow-auto pl-4 text-zinc-300">
                {timeline.map((inj) => (
                  <li key={inj.idx}>
                    <span className="font-mono text-emerald-500">#{inj.idx}</span> {inj.name || "(unnamed)"}{" "}
                    <span className="text-zinc-600">offset {inj.offset}</span>
                  </li>
                ))}
              </ol>
            </div>
          ) : null}
          <label className="mt-3 block text-sm">
            <span className="text-zinc-400">Actors (JSON — host/user IDs)</span>
            <textarea className="mt-1 h-32 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={actorsJson} onChange={(ev) => setActorsJson(ev.target.value)} />
          </label>
          <label className="mt-3 flex items-center gap-2 text-sm">
            Time scale
            <input type="number" step="0.1" min={0.1} className="w-28 rounded border border-zinc-700 bg-zinc-950 px-2 py-1" value={scale} onChange={(ev) => setScale(Number(ev.target.value))} />
          </label>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <label className="block text-xs text-zinc-400">
              FortiSIEM IP (optional)
              <input className="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs" value={jobFsIp} onChange={(ev) => setJobFsIp(ev.target.value)} />
            </label>
            <label className="block text-xs text-zinc-400">
              FortiSIEM port (optional)
              <input className="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs" placeholder="514" value={jobFsPort} onChange={(ev) => setJobFsPort(ev.target.value)} />
            </label>
          </div>
          <button type="button" className="mt-4 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500" onClick={() => void runEx()}>
            Run exercise
          </button>
        </>
      ) : (
        <>
          <p className="mt-3 text-xs text-zinc-500">
            Full document as stored under <code className="text-zinc-400">data/exercises/</code>. Saving replaces the file for <code className="text-zinc-400">id</code>.
          </p>
          <textarea
            className="mt-2 h-[min(420px,50vh)] w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs leading-relaxed"
            spellCheck={false}
            value={editorDoc}
            onChange={(ev) => setEditorDoc(ev.target.value)}
          />
          <div className="mt-3 flex flex-wrap gap-2">
            <button type="button" className="rounded-lg bg-zinc-700 px-3 py-2 text-sm hover:bg-zinc-600" onClick={() => void reloadEditor()}>
              Reload from server
            </button>
            <button type="button" className="rounded-lg bg-emerald-700 px-3 py-2 text-sm text-white hover:bg-emerald-600" onClick={() => void saveEditor()}>
              Save
            </button>
            <button type="button" className="rounded-lg bg-indigo-800 px-3 py-2 text-sm text-white hover:bg-indigo-700" onClick={newTemplate}>
              New template
            </button>
            <button type="button" className="rounded-lg bg-red-950 px-3 py-2 text-sm text-red-200 hover:bg-red-900" onClick={() => void deleteExercise()}>
              Delete scenario
            </button>
          </div>
        </>
      )}
      {msg ? <p className="mt-3 text-sm text-emerald-400">{msg}</p> : null}
    </PanelCard>
  );
}

function SimulatePanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [body, setBody] = useState(`{
  "plan": [
    {
      "source_id": "linux",
      "event_types": ["baseline_cron"],
      "count": 3,
      "params": {}
    }
  ],
  "min_delay": 0.2,
  "max_delay": 0.6,
  "loop": false,
  "interval_seconds": 30,
  "max_rounds": 0
}`);
  const [simFsIp, setSimFsIp] = useState("");
  const [simFsPort, setSimFsPort] = useState("");
  const [msg, setMsg] = useState("");

  const start = () =>
    run(async () => {
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(body) as Record<string, unknown>;
      } catch {
        setMsg("Invalid JSON");
        return;
      }
      try {
        Object.assign(parsed, fortisiemExtras(simFsIp, simFsPort));
      } catch (e) {
        setMsg(e instanceof Error ? e.message : String(e));
        return;
      }
      const out = await apiJson<{ job_id: string }>("/api/simulate", {
        method: "POST",
        body: JSON.stringify(parsed),
      });
      setMsg(`Job ${out.job_id} — control under Jobs tab`);
    });

  return (
    <PanelCard title="Multi-source simulate job">
      <div className="mb-3 grid gap-3 sm:grid-cols-2">
        <label className="block text-xs text-zinc-400">
          FortiSIEM IP (optional)
          <input className="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs" value={simFsIp} onChange={(ev) => setSimFsIp(ev.target.value)} />
        </label>
        <label className="block text-xs text-zinc-400">
          FortiSIEM port (optional)
          <input className="mt-1 w-full rounded border border-zinc-700 bg-zinc-950 px-2 py-1 font-mono text-xs" placeholder="514" value={simFsPort} onChange={(ev) => setSimFsPort(ev.target.value)} />
        </label>
      </div>
      <textarea className="h-64 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono text-xs" value={body} onChange={(ev) => setBody(ev.target.value)} />
      <button type="button" className="mt-3 rounded-lg bg-emerald-600 px-4 py-2 text-sm text-white hover:bg-emerald-500" onClick={() => void start()}>
        Start simulate
      </button>
      {msg ? <p className="mt-3 text-sm text-emerald-400">{msg}</p> : null}
    </PanelCard>
  );
}

function UploadPanel({ run }: { run: <T,>(fn: () => Promise<T>) => Promise<T | undefined> }) {
  const [reportingIp, setReportingIp] = useState("10.0.0.1");
  const [mode, setMode] = useState("verbatim");
  const [result, setResult] = useState("");

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    const fd = new FormData(e.target as HTMLFormElement);
    void run(async () => {
      const res = await fetch("/api/upload", { method: "POST", body: fd });
      const text = await res.text();
      if (!res.ok) throw new Error(text);
      setResult(text);
    });
  };

  return (
    <PanelCard title="Upload syslog lines">
      <form className="space-y-3 text-sm" onSubmit={onSubmit}>
        <label className="block">
          Reporting IP
          <input
            name="reporting_ip"
            className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2 font-mono"
            value={reportingIp}
            onChange={(ev) => setReportingIp(ev.target.value)}
          />
        </label>
        <label className="block">
          Mode
          <select name="mode" className="mt-1 w-full rounded-lg border border-zinc-700 bg-zinc-950 px-3 py-2" value={mode} onChange={(ev) => setMode(ev.target.value)}>
            <option value="verbatim">verbatim</option>
            <option value="wrap">wrap</option>
          </select>
        </label>
        <label className="block">
          File
          <input name="file" type="file" className="mt-1 block w-full text-zinc-400" required />
        </label>
        <button type="submit" className="rounded-lg bg-emerald-600 px-4 py-2 text-white">
          Upload &amp; send
        </button>
      </form>
      {result ? <pre className="mt-4 max-h-64 overflow-auto rounded-lg bg-black/40 p-3 text-xs">{result}</pre> : null}
    </PanelCard>
  );
}
