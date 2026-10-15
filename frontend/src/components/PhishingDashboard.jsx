import React, { useEffect, useMemo, useState } from "react";
import axios from "axios";
import { Toaster, toast } from "sonner";
import {
  ShieldAlert,
  ShieldCheck,
  Target,
  Activity,
  Link as LinkIcon,
  History as HistoryIcon,
  AlertTriangle,
  Trash2,
  PlayCircle,
  BookOpen,
  Lock,
  Loader2,
  CheckCircle2,
  XCircle,
} from "lucide-react";

import { Card } from "./ui/card";
import { Button } from "./ui/button";
import { Textarea } from "./ui/textarea";
import { Badge } from "./ui/badge";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "./ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import RiskGauge from "./RiskGauge";

const BACKEND_URL = (process.env.REACT_APP_BACKEND_URL || "https://aiphishing.onrender.com").replace(/\/+$/, "");
const API = `${BACKEND_URL}/api`;
const HISTORY_KEY = "phish_detector_history_v1";
const MAX_HISTORY = 25;

const LEVEL_STYLES = {
  Safe: { text: "text-[#00E676]", border: "border-[#00E676]/40", chip: "bg-[#00E676]/10 text-[#00E676] border-[#00E676]/40" },
  "Low Risk": { text: "text-[#00E5FF]", border: "border-[#00E5FF]/40", chip: "bg-[#00E5FF]/10 text-[#00E5FF] border-[#00E5FF]/40" },
  "Medium Risk": { text: "text-[#FFD700]", border: "border-[#FFD700]/40", chip: "bg-[#FFD700]/10 text-[#FFD700] border-[#FFD700]/40" },
  "High Risk": { text: "text-[#FF9900]", border: "border-[#FF9900]/40", chip: "bg-[#FF9900]/10 text-[#FF9900] border-[#FF9900]/40" },
  Critical: { text: "text-[#FF3366]", border: "border-[#FF3366]/40", chip: "bg-[#FF3366]/10 text-[#FF3366] border-[#FF3366]/40" },
};

const styleFor = (level) => LEVEL_STYLES[level] || LEVEL_STYLES["Low Risk"];

const StatCard = ({ label, value, testId, accent }) => (
  <div className="cyber-card p-6 animate-fade-up">
    <div className="overline">{label}</div>
    <div
      className={`mt-3 font-mono text-3xl font-semibold ${accent || "text-slate-100"}`}
      data-testid={testId}
    >
      {value}
    </div>
  </div>
);

export default function PhishingDashboard() {
  const [message, setMessage] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [samples, setSamples] = useState([]);
  const [history, setHistory] = useState([]);

  // Load history + samples once
  useEffect(() => {
    try {
      const raw = localStorage.getItem(HISTORY_KEY);
      if (raw) setHistory(JSON.parse(raw));
    } catch { /* ignore */ }

    axios.get(`${API}/samples`).then((r) => setSamples(r.data.samples || [])).catch(() => {});
  }, []);

  const stats = useMemo(() => {
    const total = history.length;
    const phishing = history.filter((h) => ["Critical", "High Risk"].includes(h.risk_level)).length;
    const safe = history.filter((h) => h.risk_level === "Safe").length;
    const avg = total ? Math.round(history.reduce((s, h) => s + h.risk_score, 0) / total) : 0;
    return { total, phishing, safe, avg };
  }, [history]);

  const persist = (next) => {
    setHistory(next);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
  };

  const onAnalyze = async () => {
    const text = message.trim();
    if (!text) {
      toast.error("Please enter a message to analyze.");
      return;
    }
    setLoading(true);
    try {
      const { data } = await axios.post(`${API}/analyze`, { message: text });
      setResult(data);
      const entry = {
        id: `${Date.now()}`,
        time: new Date().toISOString(),
        preview: text.slice(0, 80),
        risk_score: data.risk_score,
        risk_level: data.risk_level,
        verdict: data.verdict,
      };
      persist([entry, ...history].slice(0, MAX_HISTORY));
      toast.success("Analysis complete");
    } catch (e) {
      const msg = e?.response?.data?.detail || "Unable to analyze the message. Please try again.";
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const onClear = () => {
    setMessage("");
    setResult(null);
  };

  const onLoadSample = (idx) => {
    const s = samples[Number(idx)];
    if (s) {
      setMessage(s.text);
      setResult(null);
      toast.message(`Loaded sample: ${s.label}`);
    }
  };

  const clearHistory = () => {
    persist([]);
    toast.message("History cleared");
  };

  const s = result ? styleFor(result.risk_level) : null;

  return (
    <div className="min-h-screen text-slate-100">
      <Toaster theme="dark" richColors position="top-right" />

      {/* Header */}
      <header
        className="sticky top-0 z-30 border-b border-cyber-border backdrop-blur-xl"
        style={{ background: "rgba(5,10,20,0.72)" }}
      >
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-md flex items-center justify-center border border-[#00F0FF]/60 bg-[#00F0FF]/5">
              <ShieldAlert className="w-5 h-5 text-[#00F0FF]" />
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">AI Phishing Attack Detector</h1>
              <p className="text-xs text-slate-400 hidden sm:block">
                Analyze suspicious messages and identify potential phishing threats using AI.
              </p>
            </div>
          </div>
          <div className="hidden md:flex items-center gap-2 text-xs text-slate-400 font-mono">
            <Lock className="w-3.5 h-3.5 text-[#00E676]" />
            <span>LOCAL · NO MESSAGES STORED SERVER-SIDE</span>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        {/* Stats row */}
        <section className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <StatCard label="Total Analyzed" value={stats.total} testId="stat-total" />
          <StatCard label="Phishing Detected" value={stats.phishing} testId="stat-phishing" accent="text-[#FF3366]" />
          <StatCard label="Safe Messages" value={stats.safe} testId="stat-safe" accent="text-[#00E676]" />
          <StatCard label="Avg Risk Score" value={`${stats.avg}%`} testId="stat-avg" accent="text-[#00F0FF]" />
        </section>

        {/* Input + Result */}
        <section className="grid grid-cols-12 gap-6">
          {/* Left: Input */}
          <div className="col-span-12 lg:col-span-5 space-y-6">
            <Card className="cyber-card p-6">
              <div className="flex items-center gap-2 mb-4">
                <Target className="w-4 h-4 text-[#00F0FF]" />
                <span className="overline">Message Input</span>
              </div>
              <Textarea
                data-testid="message-input"
                value={message}
                onChange={(e) => setMessage(e.target.value)}
                placeholder="Paste suspicious SMS, email, or message here..."
                className="min-h-[220px] font-mono text-sm bg-[#0F172A] border-cyber-border focus-visible:ring-[#00F0FF] focus-visible:ring-1 resize-y"
              />
              <div className="mt-4 flex flex-wrap gap-2">
                <Button
                  data-testid="analyze-btn"
                  onClick={onAnalyze}
                  disabled={loading}
                  className="neon-btn rounded-md px-5 py-2 h-10 font-medium"
                >
                  {loading ? (
                    <><Loader2 className="w-4 h-4 mr-2 animate-spin" /> Analyzing</>
                  ) : (
                    <><PlayCircle className="w-4 h-4 mr-2" /> Analyze Message</>
                  )}
                </Button>
                <Button
                  data-testid="clear-btn"
                  variant="outline"
                  onClick={onClear}
                  className="rounded-md px-4 h-10 border-cyber-border text-slate-300 hover:bg-slate-800/60 hover:text-white"
                >
                  <XCircle className="w-4 h-4 mr-2" /> Clear
                </Button>
                <div className="flex-1 min-w-[180px]">
                  <Select onValueChange={onLoadSample}>
                    <SelectTrigger
                      data-testid="sample-select"
                      className="bg-[#0F172A] border-cyber-border text-slate-300 h-10 rounded-md"
                    >
                      <div className="flex items-center gap-2">
                        <BookOpen className="w-4 h-4 text-[#00F0FF]" />
                        <SelectValue placeholder="Load Sample" />
                      </div>
                    </SelectTrigger>
                    <SelectContent className="bg-[#0A1120] border-cyber-border text-slate-200">
                      {samples.map((s, i) => (
                        <SelectItem key={i} value={String(i)} data-testid={`sample-item-${i}`}>
                          {s.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <p className="mt-4 text-[11px] text-slate-500 font-mono">
                Privacy: messages are analyzed on-demand and never persisted server-side. History stays in your browser.
              </p>
            </Card>
          </div>

          {/* Right: Result */}
          <div className="col-span-12 lg:col-span-7">
            {result ? (
              <div className="space-y-6">
                <Card className={`p-6 md:p-8 cyber-card ${s.border}`}>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
                    <RiskGauge score={result.risk_score} level={result.risk_level} />
                    <div>
                      <div className="overline">Phishing Risk</div>
                      <div className={`mt-2 font-mono text-4xl font-semibold ${s.text}`} data-testid="risk-score">
                        {result.risk_score}%
                      </div>
                      <div className="mt-4 overline">Risk Level</div>
                      <Badge
                        data-testid="risk-level"
                        className={`mt-2 rounded-md border font-mono text-xs px-3 py-1 ${s.chip}`}
                      >
                        {result.risk_level.toUpperCase()}
                      </Badge>
                      <div className="mt-4 overline">Verdict</div>
                      <div className="mt-2 text-lg font-medium" data-testid="verdict">
                        {result.verdict}
                      </div>
                    </div>
                  </div>
                </Card>

                <div className="grid grid-cols-12 gap-6">
                  {/* Indicators */}
                  <Card className="col-span-12 md:col-span-6 cyber-card p-6" data-testid="indicators-card">
                    <div className="flex items-center gap-2 mb-4">
                      <AlertTriangle className="w-4 h-4 text-[#FF9900]" />
                      <span className="overline">Suspicious Indicators</span>
                    </div>
                    {result.indicators.length ? (
                      <ul className="space-y-2 text-sm">
                        {result.indicators.map((label, i) => (
                          <li key={i} className="flex items-start gap-2" data-testid={`indicator-${i}`}>
                            <CheckCircle2 className="w-4 h-4 text-[#FF3366] mt-0.5 flex-shrink-0" />
                            <span className="text-slate-200">{label}</span>
                          </li>
                        ))}
                      </ul>
                    ) : (
                      <div className="flex items-center gap-2 text-slate-400 text-sm">
                        <ShieldCheck className="w-4 h-4 text-[#00E676]" />
                        No rule-based indicators matched.
                      </div>
                    )}
                  </Card>

                  {/* URL analysis */}
                  <Card className="col-span-12 md:col-span-6 cyber-card p-6" data-testid="urls-card">
                    <div className="flex items-center gap-2 mb-4">
                      <LinkIcon className="w-4 h-4 text-[#00F0FF]" />
                      <span className="overline">URL Analysis</span>
                    </div>
                    {result.url_findings.length ? (
                      <ul className="space-y-4">
                        {result.url_findings.map((u, i) => {
                          const us = { High: "text-[#FF3366]", Medium: "text-[#FFD700]", Low: "text-[#00E676]" }[u.risk] || "text-slate-300";
                          return (
                            <li key={i} className="border border-cyber-border rounded-md p-3" data-testid={`url-${i}`}>
                              <div className="font-mono text-xs break-all text-slate-200">{u.url}</div>
                              <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono text-slate-400">
                                <span>HTTPS: <span className={u.https ? "text-[#00E676]" : "text-[#FF3366]"}>{u.https ? "yes" : "no"}</span></span>
                                <span>IP-based: <span className={u.ip_based ? "text-[#FF3366]" : "text-slate-300"}>{u.ip_based ? "yes" : "no"}</span></span>
                                <span>Shortener: <span className={u.shortener ? "text-[#FF9900]" : "text-slate-300"}>{u.shortener ? "yes" : "no"}</span></span>
                                <span>Overall: <span className={us}>{u.risk}</span></span>
                              </div>
                              {u.reasons.length > 0 && (
                                <div className="mt-2 text-[11px] text-slate-400">
                                  {u.reasons.map((r, k) => <div key={k}>• {r}</div>)}
                                </div>
                              )}
                            </li>
                          );
                        })}
                      </ul>
                    ) : (
                      <div className="text-slate-400 text-sm">No URLs detected in the message.</div>
                    )}
                  </Card>

                  {/* Explainable AI */}
                  <Card className="col-span-12 cyber-card p-6" data-testid="explanation-card">
                    <div className="flex items-center gap-2 mb-3">
                      <Activity className="w-4 h-4 text-[#00F0FF]" />
                      <span className="overline">Why was this message flagged?</span>
                    </div>
                    <p className="text-sm text-slate-200 leading-relaxed" data-testid="ai-explanation">
                      {result.ai_explanation}
                    </p>
                    {result.explainable_reasons.length > 0 && (
                      <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
                        {result.explainable_reasons.map((r, i) => (
                          <div key={i} className="border border-cyber-border rounded-md p-3">
                            <div className="text-xs font-mono text-[#00F0FF]">{r.category.toUpperCase()}</div>
                            <div className="text-sm text-slate-200 mt-1">{r.description}</div>
                          </div>
                        ))}
                      </div>
                    )}
                  </Card>

                  {/* Recommendation */}
                  <Card className={`col-span-12 cyber-card p-6 ${s.border}`} data-testid="recommendation-card">
                    <div className="flex items-center gap-2 mb-3">
                      <ShieldCheck className={`w-4 h-4 ${s.text}`} />
                      <span className="overline">Recommended Action</span>
                    </div>
                    <p className="text-sm text-slate-200 leading-relaxed">{result.recommendation}</p>
                  </Card>
                </div>
              </div>
            ) : (
              <Card className="cyber-card p-10 h-full flex flex-col items-center justify-center text-center min-h-[420px]">
                <div className="w-14 h-14 rounded-md border border-[#00F0FF]/40 flex items-center justify-center mb-4 bg-[#00F0FF]/5">
                  <ShieldAlert className="w-7 h-7 text-[#00F0FF]" />
                </div>
                <div className="overline">Awaiting Analysis</div>
                <h3 className="mt-3 text-xl font-medium">Paste a message on the left to begin.</h3>
                <p className="mt-2 max-w-md text-sm text-slate-400">
                  The detector scans for urgency, credential requests, financial fraud, brand impersonation,
                  suspicious URLs and manipulative language patterns.
                </p>
              </Card>
            )}
          </div>
        </section>

        {/* History */}
        <section>
          <Card className="cyber-card p-6" data-testid="history-card">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <HistoryIcon className="w-4 h-4 text-[#00F0FF]" />
                <span className="overline">Analysis History</span>
              </div>
              {history.length > 0 && (
                <Button
                  variant="outline"
                  onClick={clearHistory}
                  data-testid="clear-history-btn"
                  className="h-8 rounded-md border-cyber-border text-slate-300 hover:bg-slate-800/60 hover:text-white text-xs"
                >
                  <Trash2 className="w-3.5 h-3.5 mr-1.5" /> Clear
                </Button>
              )}
            </div>
            {history.length === 0 ? (
              <div className="text-sm text-slate-400">No analyses yet. Run your first analysis to build history.</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="border-cyber-border hover:bg-transparent">
                    <TableHead className="text-slate-400 font-mono text-xs">Time</TableHead>
                    <TableHead className="text-slate-400 font-mono text-xs">Preview</TableHead>
                    <TableHead className="text-slate-400 font-mono text-xs text-right">Score</TableHead>
                    <TableHead className="text-slate-400 font-mono text-xs">Level</TableHead>
                    <TableHead className="text-slate-400 font-mono text-xs">Verdict</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.map((h, i) => {
                    const hs = styleFor(h.risk_level);
                    return (
                      <TableRow key={h.id} className="border-cyber-border" data-testid={`history-row-${i}`}>
                        <TableCell className="font-mono text-xs text-slate-400">
                          {new Date(h.time).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}
                        </TableCell>
                        <TableCell className="text-sm text-slate-300 max-w-[420px] truncate">{h.preview}</TableCell>
                        <TableCell className={`text-right font-mono ${hs.text}`}>{h.risk_score}%</TableCell>
                        <TableCell>
                          <Badge className={`rounded-md border font-mono text-[10px] px-2 py-0.5 ${hs.chip}`}>
                            {h.risk_level.toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-slate-300">{h.verdict}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </Card>
        </section>

        <footer className="pt-4 pb-8 text-[11px] text-slate-500 font-mono text-center">
          Defensive analysis tool · Rule-based scoring + AI reasoning · For cybersecurity awareness only.
        </footer>
      </main>
    </div>
  );
}
