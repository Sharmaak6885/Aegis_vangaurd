"use client";

import { useState, useEffect, useRef } from "react";
import { useRouter } from "next/navigation";
import {
  Play,
  StopCircle,
  Terminal,
  CheckCircle2,
  XCircle,
  Loader2,
  ShieldAlert,
} from "lucide-react";
import clsx from "clsx";

interface ModuleStatus {
  name: string;
  status: "pending" | "running" | "done" | "failed";
  findings: number;
  duration: number;
}

export default function ScanPage() {
  const router = useRouter();
  const [isScanning, setIsScanning] = useState(false);
  const [logs, setLogs] = useState<string[]>([]);
  const [modules, setModules] = useState<ModuleStatus[]>([]);
  const [totalFindings, setTotalFindings] = useState(0);
  const [target, setTarget] = useState("https://app.archscale.in");
  
  const logsEndRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  const startScan = () => {
    if (isScanning) return;
    
    setIsScanning(true);
    setLogs(["Initializing security assessment..."]);
    setModules([]);
    setTotalFindings(0);

    const es = new EventSource(`/api/scan?target=${encodeURIComponent(target)}&modules=all`);
    eventSourceRef.current = es;

    es.addEventListener("start", (e) => {
      const data = JSON.parse(e.data);
      setLogs((prev) => [...prev, data.message]);
    });

    es.addEventListener("log", (e) => {
      const data = JSON.parse(e.data);
      setLogs((prev) => [...prev, data.message]);
    });

    es.addEventListener("module_complete", (e) => {
      const data = JSON.parse(e.data);
      setLogs((prev) => [...prev, data.message]);
      
      setModules((prev) => [
        ...prev,
        {
          name: data.module,
          status: data.status === "OK" ? "done" : "failed",
          findings: data.findingsCount,
          duration: data.duration,
        }
      ]);
      
      setTotalFindings((prev) => prev + data.findingsCount);
    });

    es.addEventListener("complete", (e) => {
      setLogs((prev) => [...prev, "Scan complete! Generating reports..."]);
      setTimeout(() => {
        router.push("/findings"); // Redirect to findings when done
      }, 2000);
    });

    es.addEventListener("error", (e) => {
      const data = JSON.parse(e.data);
      if (data.message) {
        setLogs((prev) => [...prev, `[ERROR] ${data.message}`]);
      }
    });

    es.addEventListener("done", (e) => {
      es.close();
      setIsScanning(false);
      const data = JSON.parse(e.data);
      setLogs((prev) => [...prev, `Process exited with code ${data.code}`]);
    });
  };

  const stopScan = () => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      setIsScanning(false);
      setLogs((prev) => [...prev, "Scan aborted by user."]);
    }
  };

  return (
    <div className="p-8 max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-[var(--color-text-primary)]">
            Active Security Scan
          </h1>
          <p className="text-[var(--color-text-secondary)] mt-1">
            Execute real-time offensive assessment across {target}
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          <input 
            type="text" 
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={isScanning}
            className="px-4 py-2 bg-[var(--color-bg-elevated)] border border-[var(--color-border)] rounded-md text-sm text-[var(--color-text-primary)] w-64 focus:outline-none focus:border-blue-500 transition-colors"
          />
          {!isScanning ? (
            <button 
              onClick={startScan}
              className="px-5 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-md flex items-center gap-2 font-medium text-sm transition-colors"
            >
              <Play size={16} />
              Start Scan
            </button>
          ) : (
            <button 
              onClick={stopScan}
              className="px-5 py-2.5 bg-red-500/10 hover:bg-red-500/20 text-red-500 border border-red-500/20 rounded-md flex items-center gap-2 font-medium text-sm transition-colors"
            >
              <StopCircle size={16} />
              Abort Scan
            </button>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Terminal Output */}
        <div className="lg:col-span-2 flex flex-col h-[600px] bg-[#0A0A0A] border border-[var(--color-border)] rounded-xl overflow-hidden shadow-2xl relative">
          <div className="flex items-center gap-2 px-4 py-3 bg-[#111111] border-b border-[#222]">
            <Terminal size={16} className="text-gray-400" />
            <span className="text-xs font-mono text-gray-400 uppercase tracking-wider">Live Execution Log</span>
            {isScanning && <Loader2 size={14} className="text-blue-500 animate-spin ml-auto" />}
          </div>
          <div className="flex-1 p-4 overflow-y-auto font-mono text-[13px] leading-relaxed text-gray-300">
            {logs.length === 0 ? (
              <div className="flex items-center justify-center h-full text-gray-600">
                Ready to initiate sequence.
              </div>
            ) : (
              logs.map((log, i) => (
                <div key={i} className="mb-1 whitespace-pre-wrap">
                  {log}
                </div>
              ))
            )}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* Modules Progress Sidebar */}
        <div className="flex flex-col gap-6">
          <div className="p-6 bg-[var(--color-bg-elevated)] border border-[var(--color-border)] rounded-xl">
            <h3 className="text-sm font-semibold text-[var(--color-text-primary)] mb-4">Live Findings</h3>
            <div className="flex items-end gap-3">
              <span className="text-5xl font-bold tracking-tighter text-blue-500">{totalFindings}</span>
              <span className="text-sm text-[var(--color-text-secondary)] mb-2">vulnerabilities</span>
            </div>
          </div>

          <div className="flex-1 p-5 bg-[var(--color-bg-elevated)] border border-[var(--color-border)] rounded-xl overflow-y-auto">
            <h3 className="text-sm font-semibold text-[var(--color-text-primary)] mb-4 flex items-center justify-between">
              Module Execution
              <span className="text-xs font-normal text-[var(--color-text-muted)]">
                {modules.length} / 14 Complete
              </span>
            </h3>
            
            <div className="space-y-3">
              {modules.map((m, i) => (
                <div key={i} className="flex items-start justify-between p-3 rounded-lg bg-[var(--color-bg)] border border-[var(--color-border)]">
                  <div className="flex items-center gap-3">
                    {m.status === "done" ? (
                      <CheckCircle2 size={16} className="text-green-500 mt-0.5 shrink-0" />
                    ) : (
                      <XCircle size={16} className="text-red-500 mt-0.5 shrink-0" />
                    )}
                    <div>
                      <div className="text-sm font-medium text-[var(--color-text-primary)]">{m.name}</div>
                      <div className="text-xs text-[var(--color-text-muted)] mt-0.5">{m.duration}s elapsed</div>
                    </div>
                  </div>
                  {m.findings > 0 && (
                    <div className="flex items-center gap-1.5 px-2 py-1 bg-amber-500/10 border border-amber-500/20 rounded text-amber-500">
                      <ShieldAlert size={12} />
                      <span className="text-xs font-semibold">{m.findings}</span>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
