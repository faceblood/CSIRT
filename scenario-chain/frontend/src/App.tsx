import { useCallback, useEffect, useMemo, useState } from "react";
import type { CatalogSource } from "./lib/api";
import { fetchSources, postStep } from "./lib/api";

type StepRow = {
  id: string;
  source_id: string;
  event_type: string;
  count: number;
  params_json: string;
};

function newId() {
  return crypto.randomUUID();
}

export default function App() {
  const [catalog, setCatalog] = useState<CatalogSource[]>([]);
  const [catalogErr, setCatalogErr] = useState<string | null>(null);

  const [chain, setChain] = useState<StepRow[]>([]);
  const [cursor, setCursor] = useState(0);
  const [results, setResults] = useState<Record<string, unknown>[]>([]);

  const [collectorIp, setCollectorIp] = useState("");
  const [collectorPort, setCollectorPort] = useState("");
  const [dryRunGlobal, setDryRunGlobal] = useState(false);

  const [builderSource, setBuilderSource] = useState("");
  const [builderEvent, setBuilderEvent] = useState("");
  const [builderCount, setBuilderCount] = useState(1);
  const [builderParams, setBuilderParams] = useState("{}");

  useEffect(() => {
    fetchSources()
      .then((rows) => {
        setCatalog(rows);
        setCatalogErr(null);
        if (rows.length && !builderSource) {
          setBuilderSource(rows[0].id);
          setBuilderEvent(rows[0].event_types[0]?.id ?? "");
        }
      })
      .catch((e: Error) => setCatalogErr(e.message));
  }, []);

  useEffect(() => {
    const src = catalog.find((s) => s.id === builderSource);
    if (!src) return;
    const et = src.event_types.find((e) => e.id === builderEvent);
    if (!et && src.event_types.length) {
      setBuilderEvent(src.event_types[0].id);
    }
  }, [builderSource, builderEvent, catalog]);

  const selectedCatalog = useMemo(
    () => catalog.find((s) => s.id === builderSource),
    [catalog, builderSource]
  );

  const addStep = () => {
    const trimmed = builderParams.trim();
    if (trimmed) {
      try {
        JSON.parse(trimmed);
      } catch {
        alert("Params must be valid JSON");
        return;
      }
    }
    setChain((c) => [
      ...c,
      {
        id: newId(),
        source_id: builderSource,
        event_type: builderEvent,
        count: Math.max(1, builderCount),
        params_json: trimmed || "{}",
      },
    ]);
  };

  const move = (idx: number, dir: -1 | 1) => {
    setChain((c) => {
      const j = idx + dir;
      if (j < 0 || j >= c.length) return c;
      const copy = [...c];
      [copy[idx], copy[j]] = [copy[j], copy[idx]];
      return copy;
    });
  };

  const removeAt = (idx: number) => {
    setChain((c) => {
      const next = c.filter((_, i) => i !== idx);
      setCursor((cur) => {
        if (next.length === 0) return 0;
        if (idx < cur) return cur - 1;
        return Math.min(cur, next.length - 1);
      });
      return next;
    });
  };

  const parseParams = (raw: string): Record<string, unknown> => {
    const t = raw.trim();
    if (!t) return {};
    return JSON.parse(t) as Record<string, unknown>;
  };

  const nextLog = useCallback(async () => {
    if (cursor >= chain.length) return;
    const row = chain[cursor];
    let params: Record<string, unknown> = {};
    try {
      params = parseParams(row.params_json);
    } catch {
      alert("Step params JSON is invalid; fix the row before running.");
      return;
    }
    const fortisiem_ip = collectorIp.trim() || undefined;
    const fortisiem_port = collectorPort.trim() ? Number(collectorPort) : undefined;
    if (collectorPort.trim() && Number.isNaN(fortisiem_port)) {
      alert("Collector port must be a number");
      return;
    }
    try {
      const res = await postStep({
        source_id: row.source_id,
        event_type: row.event_type,
        count: row.count,
        params,
        fortisiem_ip,
        fortisiem_port,
        dry_run: dryRunGlobal,
      });
      setResults((r) => [
        ...r,
        {
          step_id: row.id,
          source_id: row.source_id,
          event_type: row.event_type,
          count: row.count,
          ...res,
          at: new Date().toISOString(),
        },
      ]);
      setCursor((c) => c + 1);
    } catch (e) {
      alert(e instanceof Error ? e.message : String(e));
    }
  }, [chain, collectorIp, collectorPort, cursor, dryRunGlobal]);

  const labelForSource = (id: string) => catalog.find((s) => s.id === id)?.label ?? id;

  return (
    <div className="min-h-screen pb-28">
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-20">
        <div className="mx-auto max-w-5xl px-4 py-4 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h1 className="text-xl font-semibold tracking-tight">Scenario Chain</h1>
            <p className="text-sm text-slate-400">Compose steps, then advance one batch at a time.</p>
          </div>
          {catalogErr && (
            <div className="text-sm text-rose-400 max-w-md text-right">Catalog error: {catalogErr}</div>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-5xl px-4 py-8 space-y-10">
        <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-4">
          <h2 className="text-lg font-medium text-slate-200">Builder</h2>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-slate-400">Source</span>
              <select
                className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
                value={builderSource}
                onChange={(e) => setBuilderSource(e.target.value)}
              >
                {catalog.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-slate-400">Event type</span>
              <select
                className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
                value={builderEvent}
                onChange={(e) => setBuilderEvent(e.target.value)}
              >
                {(selectedCatalog?.event_types ?? []).map((et) => (
                  <option key={et.id} value={et.id}>
                    {et.label}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex flex-col gap-1 text-sm">
              <span className="text-slate-400">Count (per step)</span>
              <input
                type="number"
                min={1}
                className="rounded-md border border-slate-700 bg-slate-950 px-3 py-2"
                value={builderCount}
                onChange={(e) => setBuilderCount(Number(e.target.value))}
              />
            </label>
            <div className="flex items-end">
              <button
                type="button"
                onClick={addStep}
                className="w-full rounded-md bg-emerald-600 px-4 py-2 font-medium text-white hover:bg-emerald-500"
              >
                Add step
              </button>
            </div>
          </div>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-slate-400">Optional JSON params</span>
            <textarea
              className="min-h-[88px] rounded-md border border-slate-700 bg-slate-950 px-3 py-2 font-mono text-xs"
              value={builderParams}
              onChange={(e) => setBuilderParams(e.target.value)}
              placeholder='{"qname": "evil.example.com"}'
            />
          </label>

          {chain.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-400 border-b border-slate-800">
                    <th className="py-2 pr-2">#</th>
                    <th className="py-2 pr-2">Source</th>
                    <th className="py-2 pr-2">Event</th>
                    <th className="py-2 pr-2">Count</th>
                    <th className="py-2 pr-2">Params</th>
                    <th className="py-2 pr-2 w-32">Order</th>
                  </tr>
                </thead>
                <tbody>
                  {chain.map((row, idx) => (
                    <tr key={row.id} className="border-b border-slate-800/80 align-top">
                      <td className="py-2 pr-2 text-slate-500">{idx + 1}</td>
                      <td className="py-2 pr-2">{labelForSource(row.source_id)}</td>
                      <td className="py-2 pr-2 font-mono text-xs">{row.event_type}</td>
                      <td className="py-2 pr-2">{row.count}</td>
                      <td className="py-2 pr-2 font-mono text-xs break-all max-w-xs">{row.params_json}</td>
                      <td className="py-2 pr-2 flex gap-1 flex-wrap">
                        <button
                          type="button"
                          className="rounded bg-slate-800 px-2 py-1 text-xs hover:bg-slate-700"
                          onClick={() => move(idx, -1)}
                        >
                          Up
                        </button>
                        <button
                          type="button"
                          className="rounded bg-slate-800 px-2 py-1 text-xs hover:bg-slate-700"
                          onClick={() => move(idx, 1)}
                        >
                          Down
                        </button>
                        <button
                          type="button"
                          className="rounded bg-rose-900/60 px-2 py-1 text-xs hover:bg-rose-800"
                          onClick={() => removeAt(idx)}
                        >
                          Remove
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <section className="rounded-xl border border-slate-800 bg-slate-900/50 p-6 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
            <h2 className="text-lg font-medium text-slate-200">Runner</h2>
            <button
              type="button"
              disabled={cursor >= chain.length || chain.length === 0}
              onClick={nextLog}
              className="rounded-lg bg-sky-600 px-6 py-3 text-lg font-semibold text-white shadow-lg shadow-sky-900/40 disabled:opacity-40 disabled:cursor-not-allowed hover:bg-sky-500"
            >
              Next log
            </button>
          </div>

          {chain.length === 0 && <p className="text-slate-500 text-sm">Add steps above, then run the chain.</p>}

          <ul className="space-y-2">
            {chain.map((row, idx) => {
              const active = idx === cursor;
              return (
                <li
                  key={row.id}
                  className={`rounded-lg border px-4 py-3 ${
                    active
                      ? "border-sky-500 bg-sky-950/40 ring-2 ring-sky-500/50"
                      : "border-slate-800 bg-slate-950/40"
                  }`}
                >
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <span className="font-medium">
                      {idx + 1}. {labelForSource(row.source_id)} —{" "}
                      <span className="font-mono text-sm">{row.event_type}</span>
                    </span>
                    <span className="text-slate-400 text-sm">×{row.count}</span>
                  </div>
                  {active && (
                    <p className="mt-2 text-sm text-sky-300">← current step (uses batch count above)</p>
                  )}
                </li>
              );
            })}
          </ul>

          {results.length > 0 && (
            <div>
              <h3 className="text-sm font-medium text-slate-300 mb-2">Results</h3>
              <ul className="space-y-3 max-h-80 overflow-y-auto text-xs font-mono">
                {results.map((r, i) => (
                  <li key={i} className="rounded border border-slate-800 bg-black/30 p-3 break-all">
                    <pre className="whitespace-pre-wrap">{JSON.stringify(r, null, 2)}</pre>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      </main>

      <div className="fixed bottom-0 left-0 right-0 z-30 border-t border-slate-800 bg-slate-900/95 backdrop-blur">
        <div className="mx-auto max-w-5xl px-4 py-3 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-3 items-center">
            <label className="flex items-center gap-2 text-sm">
              <span className="text-slate-400">Collector IP</span>
              <input
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1 w-40"
                placeholder="override"
                value={collectorIp}
                onChange={(e) => setCollectorIp(e.target.value)}
              />
            </label>
            <label className="flex items-center gap-2 text-sm">
              <span className="text-slate-400">Port</span>
              <input
                className="rounded border border-slate-700 bg-slate-950 px-2 py-1 w-24"
                placeholder="514"
                value={collectorPort}
                onChange={(e) => setCollectorPort(e.target.value)}
              />
            </label>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={dryRunGlobal}
                onChange={(e) => setDryRunGlobal(e.target.checked)}
              />
              <span className="text-slate-300">Dry run (no UDP)</span>
            </label>
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              className="rounded-md border border-slate-600 px-3 py-1.5 text-sm hover:bg-slate-800"
              onClick={() => {
                setChain([]);
                setCursor(0);
                setResults([]);
              }}
            >
              Reset chain
            </button>
            <button
              type="button"
              className="rounded-md border border-slate-600 px-3 py-1.5 text-sm hover:bg-slate-800"
              onClick={() => setCursor(0)}
            >
              Reset cursor
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
