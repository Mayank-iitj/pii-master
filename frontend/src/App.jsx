import React, { useState, useCallback, useEffect, useRef } from 'react';
import {
  BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer
} from 'recharts';
import { scanText, maskText } from './api';

/* ─── Constants ───────────────────────────────────────────────────────────── */

const COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
const PIE_COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#a855f7', '#ec4899'];

const NAV_ITEMS = [
  { id: 'scanner',    icon: '🔍', label: 'Scanner' },
  { id: 'findings',   icon: '🔎', label: 'Findings' },
  { id: 'compliance', icon: '📋', label: 'Compliance' },
  { id: 'masking',    icon: '🔒', label: 'Masking' },
];

const SAMPLE_TEXT = `Dear John Smith,

Your appointment with Dr. Sarah Johnson is confirmed for March 15, 2026.

Patient Details:
- Name: John Smith
- DOB: 04/15/1985
- SSN: 123-45-6789
- Email: john.smith@example.com
- Phone: (555) 123-4567
- Address: 123 Main Street, Springfield, IL 62701

Insurance: Member ID: INS12345678
Diagnosis: ICD-10 Code J18.9 (Pneumonia)

Payment Information:
Credit Card: 4532-1234-5678-9012
PAN Card: ABCPD1234E

API Configuration:
api_key = "sk-proj-abcdefghij1234567890"
password = "SuperSecret123!"

Please bring your passport (P1234567) and Aadhaar (2345 6789 0123) to the appointment.

Best regards,
Springfield Medical Center`;

/* ─── Welcome Screen Component ────────────────────────────────────────────── */

function WelcomeScreen({ onComplete }) {
  const [exiting, setExiting] = useState(false);

  useEffect(() => {
    const timer = setTimeout(() => {
      setExiting(true);
      setTimeout(onComplete, 800);
    }, 2600);
    return () => clearTimeout(timer);
  }, [onComplete]);

  return (
    <div className={`welcome-overlay ${exiting ? 'exiting' : ''}`}>
      <div className="welcome-scan-line" />
      <div className="welcome-particles">
        {Array.from({ length: 8 }).map((_, i) => (
          <div key={i} className="welcome-particle" />
        ))}
      </div>

      <div className="welcome-shield-container">
        <div className="welcome-shield-ring" />
        <div className="welcome-shield-ring" />
        <div className="welcome-shield-ring" />
        <div className="welcome-shield-icon">🛡️</div>
      </div>

      <div className="welcome-title">PII Shield</div>
      <div className="welcome-subtitle">Enterprise PII Detection & Compliance Engine</div>

      <div className="welcome-loader">
        <div className="welcome-loader-bar">
          <div className="welcome-loader-fill" />
        </div>
        <div className="welcome-loader-text">Initializing security engines...</div>
      </div>
    </div>
  );
}

/* ─── Toast System ────────────────────────────────────────────────────────── */

function useToast() {
  const [toasts, setToasts] = useState([]);
  const idRef = useRef(0);

  const addToast = useCallback((message, type = 'info') => {
    const id = ++idRef.current;
    const icons = { success: '✅', error: '❌', info: 'ℹ️' };
    setToasts(prev => [...prev, { id, message, type, icon: icons[type] || 'ℹ️' }]);
    setTimeout(() => {
      setToasts(prev => prev.map(t => t.id === id ? { ...t, exiting: true } : t));
      setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 300);
    }, 3500);
  }, []);

  const ToastContainer = () => (
    <div className="toast-container">
      {toasts.map(t => (
        <div key={t.id} className={`toast ${t.type} ${t.exiting ? 'exiting' : ''}`}>
          <span className="toast-icon">{t.icon}</span>
          <span className="toast-message">{t.message}</span>
        </div>
      ))}
    </div>
  );

  return { addToast, ToastContainer };
}

/* ─── Animated Counter ────────────────────────────────────────────────────── */

function AnimatedCount({ value, duration = 600 }) {
  const [display, setDisplay] = useState(0);
  const prevRef = useRef(0);

  useEffect(() => {
    const start = prevRef.current;
    const end = value;
    if (start === end) return;

    const startTime = performance.now();
    const step = (now) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      setDisplay(Math.round(start + (end - start) * eased));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
    prevRef.current = end;
  }, [value, duration]);

  return <span className="count-up">{display}</span>;
}

/* ─── Score Ring (SVG) ────────────────────────────────────────────────────── */

function ScoreRing({ score, color, size = 56 }) {
  const r = (size - 8) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const colorMap = { low: '#22c55e', medium: '#eab308', high: '#f97316', critical: '#ef4444' };
  const strokeColor = colorMap[color] || '#3b82f6';

  return (
    <div className="score-ring-container" style={{ width: size, height: size }}>
      <svg className="score-ring" width={size} height={size}>
        <circle className="score-ring-bg" cx={size / 2} cy={size / 2} r={r} />
        <circle
          className="score-ring-fill"
          cx={size / 2} cy={size / 2} r={r}
          stroke={strokeColor}
          strokeDasharray={circ}
          strokeDashoffset={offset}
          style={{ filter: `drop-shadow(0 0 4px ${strokeColor}40)` }}
        />
      </svg>
      <div className="score-ring-text" style={{ color: strokeColor }}>{score}%</div>
    </div>
  );
}

/* ─── Custom Tooltip for Charts ───────────────────────────────────────────── */

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background: '#1a2035',
      border: '1px solid rgba(51,65,85,0.6)',
      borderRadius: '10px',
      padding: '0.75rem 1rem',
      boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
      fontSize: '0.8rem',
    }}>
      <div style={{ color: '#f1f5f9', fontWeight: 700, marginBottom: 4 }}>
        {payload[0].name || label}
      </div>
      <div style={{ color: payload[0].color || '#3b82f6' }}>
        Count: {payload[0].value}
      </div>
    </div>
  );
}

/* ─── Finding Card ────────────────────────────────────────────────────────── */

function FindingCard({ finding, compact = false }) {
  const [expanded, setExpanded] = useState(false);
  const sev = finding.sensitivity || 'medium';
  const explanation = finding.explanation || {};

  return (
    <div className={`finding-card ${sev}`} onClick={() => setExpanded(!expanded)}>
      <div className="finding-header">
        <span className="finding-type">{finding.entity_name || finding.entity_type}</span>
        <div className="finding-badges">
          <span className={`badge ${sev}`}>{sev}</span>
          <span className="badge method">{finding.detection_method}</span>
          <span className="badge medium">{(finding.confidence * 100).toFixed(0)}%</span>
        </div>
      </div>

      {finding.value_masked && (
        <div className="finding-detail">Value: <code>{finding.value_masked}</code></div>
      )}
      <div className="finding-detail">
        Risk: {finding.risk_score?.toFixed(2)} ({finding.risk_tier})
      </div>

      {finding.regulations_impacted?.length > 0 && (
        <div className="finding-regulations">
          {finding.regulations_impacted.map((r, i) => (
            <span key={i} className="reg-badge">{r}</span>
          ))}
        </div>
      )}

      {expanded && !compact && explanation.summary && (
        <div className="finding-explanation">
          <strong>Explanation:</strong> {explanation.summary}
          {explanation.remediation && (
            <>
              <br /><br /><strong>Remediation:</strong><br />{explanation.remediation}
            </>
          )}
          {explanation.compliance && (
            <>
              <br /><br /><strong>Compliance:</strong><br />{explanation.compliance}
            </>
          )}
        </div>
      )}
    </div>
  );
}

/* ─── Compliance View ─────────────────────────────────────────────────────── */

function ComplianceView({ scanResult }) {
  const compSummary = scanResult.compliance_summary || {};
  const findings = scanResult.findings || [];

  const fwViolations = {};
  findings.forEach(f => {
    (f.compliance_violations || []).forEach(v => {
      const fw = v.framework;
      if (!fwViolations[fw]) fwViolations[fw] = { total: 0, critical: 0, high: 0, rules: new Set() };
      fwViolations[fw].total++;
      if (v.severity === 'critical') fwViolations[fw].critical++;
      if (v.severity === 'high') fwViolations[fw].high++;
      fwViolations[fw].rules.add(v.rule_id);
    });
  });

  return (
    <div className="compliance-grid">
      {Object.entries(compSummary).map(([name, info]) => {
        const violations = fwViolations[name] || { total: 0, critical: 0, high: 0, rules: new Set() };
        const score = Math.max(0, 100 - violations.critical * 25 - violations.high * 15);
        const scoreColor = score >= 80 ? 'low' : score >= 50 ? 'medium' : score >= 25 ? 'high' : 'critical';

        return (
          <div key={name} className="fw-card">
            <div className="fw-card-header">
              <span className="fw-name">{name}</span>
              <ScoreRing score={score} color={scoreColor} />
            </div>
            <div className="fw-detail"><span>Version</span><span>{info.version}</span></div>
            <div className="fw-detail"><span>Total Rules</span><span>{info.total_rules}</span></div>
            <div className="fw-detail">
              <span>Violations Found</span>
              <span style={{ color: violations.total > 0 ? '#ef4444' : '#22c55e', fontWeight: 700 }}>
                {violations.total}
              </span>
            </div>
            <div className="fw-detail">
              <span>Critical</span>
              <span style={{ color: '#ef4444', fontWeight: 700 }}>{violations.critical}</span>
            </div>
            <div className="fw-detail">
              <span>High</span>
              <span style={{ color: '#f97316', fontWeight: 700 }}>{violations.high}</span>
            </div>
            <div className="fw-detail">
              <span>Rules Violated</span>
              <span style={{ fontWeight: 700 }}>{violations.rules.size}</span>
            </div>
          </div>
        );
      })}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   Main App
   ═══════════════════════════════════════════════════════════════════════════ */

export default function App() {
  const [showWelcome, setShowWelcome] = useState(true);
  const [appReady, setAppReady] = useState(false);
  const [view, setView] = useState('scanner');
  const [prevView, setPrevView] = useState('scanner');
  const [viewKey, setViewKey] = useState(0);
  const [inputText, setInputText] = useState(SAMPLE_TEXT);
  const [scanResult, setScanResult] = useState(null);
  const [maskResult, setMaskResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [maskStrategy, setMaskStrategy] = useState('partial');
  const [sourceType, setSourceType] = useState('text');

  const { addToast, ToastContainer } = useToast();

  const handleWelcomeComplete = useCallback(() => {
    setShowWelcome(false);
    setAppReady(true);
  }, []);

  // View transition
  const switchView = useCallback((newView) => {
    if (newView === view) return;
    setPrevView(view);
    setView(newView);
    setViewKey(k => k + 1);
  }, [view]);

  const handleScan = useCallback(async () => {
    if (!inputText.trim()) return;
    setLoading(true);
    setMaskResult(null);
    try {
      const result = await scanText(inputText, { sourceType });
      setScanResult(result);
      const count = result?.summary?.total_findings || 0;
      if (count > 0) {
        const crit = result?.summary?.severity_distribution?.critical || 0;
        addToast(
          `Scan complete — ${count} PII finding${count !== 1 ? 's' : ''} detected${crit > 0 ? ` (${crit} critical!)` : ''}`,
          crit > 0 ? 'error' : 'success'
        );
      } else {
        addToast('Scan complete — no PII detected', 'success');
      }
    } catch (err) {
      console.error(err);
      addToast('Scan failed. Is the backend running on port 8000?', 'error');
    } finally {
      setLoading(false);
    }
  }, [inputText, sourceType, addToast]);

  const handleMask = useCallback(async () => {
    if (!inputText.trim()) return;
    setLoading(true);
    try {
      const result = await maskText(inputText, maskStrategy);
      setMaskResult(result);
      addToast(`${result.total_masks} PII items masked successfully`, 'success');
    } catch (err) {
      console.error(err);
      addToast('Masking failed. Is the backend running?', 'error');
    } finally {
      setLoading(false);
    }
  }, [inputText, maskStrategy, addToast]);

  const summary = scanResult?.summary || {};
  const findings = scanResult?.findings || [];
  const sevDist = summary.severity_distribution || {};
  const entityCounts = summary.entity_counts || {};

  const sevData = Object.entries(sevDist).map(([k, v]) => ({ name: k, count: v }));
  const entityData = Object.entries(entityCounts).map(([k, v]) => ({ name: k, count: v }))
    .sort((a, b) => b.count - a.count);

  return (
    <>
      {/* Welcome Screen */}
      {showWelcome && <WelcomeScreen onComplete={handleWelcomeComplete} />}

      {/* Toast Notifications */}
      <ToastContainer />

      {/* Scan Progress Bar */}
      {loading && (
        <div className="scan-progress">
          <div className="scan-progress-bar" />
        </div>
      )}

      {/* Main App */}
      <div className={`app ${showWelcome ? 'with-welcome' : ''} ${appReady ? 'revealed' : ''}`}>

        {/* ── Header ── */}
        <header className="header">
          <div className="header-brand">
            <span className="shield-icon">🛡️</span>
            <span className="brand-text">PII Shield</span>
          </div>

          <nav className="header-nav">
            {NAV_ITEMS.map(item => (
              <button
                key={item.id}
                className={`nav-btn ${view === item.id ? 'active' : ''}`}
                onClick={() => switchView(item.id)}
              >
                <span className="nav-icon">{item.icon}</span>
                <span className="nav-label">{item.label}</span>
              </button>
            ))}
          </nav>

          <div className="header-status">
            <div className="live-indicator">
              <span className="pulse-dot" />
              Live
            </div>
          </div>
        </header>

        {/* ── Main Content ── */}
        <main className="main">

          {/* Summary Ribbon */}
          {scanResult && (
            <div className="summary-ribbon">
              <span>🛡️</span>
              Last scan: {summary.total_findings || 0} findings
              &nbsp;·&nbsp;
              {scanResult.detection_time_ms?.toFixed(0)}ms
              &nbsp;·&nbsp;
              {findings.filter(f => f.sensitivity === 'critical').length} critical
            </div>
          )}

          {/* Stats Grid */}
          {scanResult && (
            <div className="stats-grid" key={`stats-${scanResult.scan_id || ''}`}>
              <div className="stat-card">
                <div className="stat-label">Total Findings</div>
                <div className="stat-value">
                  <AnimatedCount value={summary.total_findings || 0} />
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Critical</div>
                <div className="stat-value critical">
                  <AnimatedCount value={sevDist.critical || 0} />
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">High</div>
                <div className="stat-value high">
                  <AnimatedCount value={sevDist.high || 0} />
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Medium</div>
                <div className="stat-value medium">
                  <AnimatedCount value={sevDist.medium || 0} />
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Low</div>
                <div className="stat-value low">
                  <AnimatedCount value={sevDist.low || 0} />
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Scan Time</div>
                <div className="stat-value">
                  <AnimatedCount value={Math.round(scanResult.detection_time_ms || 0)} />
                  <span style={{ fontSize: '0.9rem', fontWeight: 500, color: '#64748b', marginLeft: 2 }}>ms</span>
                </div>
              </div>
            </div>
          )}

          {/* ── View Content ── */}
          <div className="view-enter" key={viewKey}>

            {/* Scanner View */}
            {view === 'scanner' && (
              <>
                <div className="scanner-panel">
                  <div className="panel">
                    <div className="panel-title">
                      <span className="panel-icon">📝</span> Input Text
                    </div>
                    <textarea
                      value={inputText}
                      onChange={e => setInputText(e.target.value)}
                      placeholder="Paste text, log entries, API payloads, or any content to scan for PII..."
                      spellCheck={false}
                    />
                    <div className="controls">
                      <button
                        className={`btn btn-primary ${loading ? 'btn-scanning' : ''}`}
                        onClick={handleScan}
                        disabled={loading}
                      >
                        {loading ? '⏳ Scanning...' : '🔍 Scan for PII'}
                      </button>
                      <select value={sourceType} onChange={e => setSourceType(e.target.value)}>
                        <option value="text">📄 Text</option>
                        <option value="log">📋 Log</option>
                        <option value="api">🔌 API</option>
                        <option value="email">📧 Email</option>
                        <option value="database">🗄️ Database</option>
                      </select>
                      <button
                        className="btn btn-secondary"
                        onClick={() => { setInputText(''); setScanResult(null); setMaskResult(null); }}
                      >
                        ✕ Clear
                      </button>
                    </div>
                  </div>

                  <div className="panel">
                    <div className="panel-title">
                      <span className="panel-icon">📊</span> Results Summary
                    </div>
                    {!scanResult ? (
                      <div className="empty-state">
                        <div className="empty-state-icon">🔍</div>
                        <p>Click "Scan for PII" to analyze the input text</p>
                      </div>
                    ) : findings.length === 0 ? (
                      <div className="empty-state">
                        <div className="empty-state-icon">✅</div>
                        <p>No PII detected in the input</p>
                      </div>
                    ) : (
                      <div className="results-scroll">
                        {findings.map((f, i) => (
                          <FindingCard key={i} finding={f} compact />
                        ))}
                      </div>
                    )}
                  </div>
                </div>

                {/* Charts */}
                {scanResult && findings.length > 0 && (
                  <div className="charts-row">
                    <div className="chart-container">
                      <div className="panel-title">
                        <span className="panel-icon">🎯</span> Severity Distribution
                      </div>
                      <ResponsiveContainer width="100%" height={260}>
                        <PieChart>
                          <Pie
                            data={sevData.filter(d => d.count > 0)}
                            dataKey="count"
                            nameKey="name"
                            cx="50%"
                            cy="50%"
                            outerRadius={85}
                            innerRadius={40}
                            paddingAngle={3}
                            label={({ name, count }) => `${name}: ${count}`}
                            animationBegin={200}
                            animationDuration={800}
                          >
                            {sevData.map((entry, i) => (
                              <Cell key={i} fill={COLORS[entry.name] || '#6b7280'} />
                            ))}
                          </Pie>
                          <Tooltip content={<CustomTooltip />} />
                        </PieChart>
                      </ResponsiveContainer>
                    </div>
                    <div className="chart-container">
                      <div className="panel-title">
                        <span className="panel-icon">📊</span> Entity Types Found
                      </div>
                      <ResponsiveContainer width="100%" height={260}>
                        <BarChart data={entityData.slice(0, 10)} layout="vertical">
                          <CartesianGrid strokeDasharray="3 3" stroke="rgba(51,65,85,0.4)" />
                          <XAxis type="number" stroke="#64748b" fontSize={12} />
                          <YAxis type="category" dataKey="name" width={110} stroke="#64748b" tick={{ fontSize: 11 }} />
                          <Tooltip content={<CustomTooltip />} />
                          <Bar dataKey="count" radius={[0, 6, 6, 0]} animationDuration={800}>
                            {entityData.map((_, i) => (
                              <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                            ))}
                          </Bar>
                        </BarChart>
                      </ResponsiveContainer>
                    </div>
                  </div>
                )}
              </>
            )}

            {/* Findings View */}
            {view === 'findings' && (
              <div className="panel">
                <div className="panel-title">
                  <span className="panel-icon">🔎</span>
                  Detailed Findings ({findings.length})
                </div>
                {findings.length === 0 ? (
                  <div className="empty-state">
                    <div className="empty-state-icon">🔍</div>
                    <p>Run a scan first to see detailed findings</p>
                  </div>
                ) : (
                  <div className="results-scroll" style={{ maxHeight: '70vh' }}>
                    {findings.map((f, i) => (
                      <FindingCard key={i} finding={f} />
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Compliance View */}
            {view === 'compliance' && (
              <div className="panel">
                <div className="panel-title">
                  <span className="panel-icon">📋</span>
                  Compliance Framework Status
                </div>
                {!scanResult ? (
                  <div className="empty-state">
                    <div className="empty-state-icon">📋</div>
                    <p>Run a scan to see compliance status</p>
                  </div>
                ) : (
                  <ComplianceView scanResult={scanResult} />
                )}
              </div>
            )}

            {/* Masking View */}
            {view === 'masking' && (
              <div className="scanner-panel">
                <div className="panel">
                  <div className="panel-title">
                    <span className="panel-icon">🔒</span> Data Masking
                  </div>
                  <textarea
                    value={inputText}
                    onChange={e => setInputText(e.target.value)}
                    placeholder="Enter text to mask PII..."
                    spellCheck={false}
                  />
                  <div className="controls">
                    <button
                      className={`btn btn-primary ${loading ? 'btn-scanning' : ''}`}
                      onClick={handleMask}
                      disabled={loading}
                    >
                      {loading ? '⏳ Masking...' : '🔒 Mask PII'}
                    </button>
                    <select value={maskStrategy} onChange={e => setMaskStrategy(e.target.value)}>
                      <option value="partial">🎭 Partial Mask</option>
                      <option value="full">██ Full Mask</option>
                      <option value="hash">🔑 Hash</option>
                      <option value="redact">🚫 Redact</option>
                      <option value="tokenize">🔄 Tokenize</option>
                    </select>
                  </div>
                </div>
                <div className="panel">
                  <div className="panel-title">
                    <span className="panel-icon">📄</span> Masked Output
                  </div>
                  {maskResult ? (
                    <>
                      <div className="masked-text">{maskResult.masked_text}</div>
                      <div className="time-badge">
                        🔒 {maskResult.total_masks} masks applied &nbsp;·&nbsp;
                        {maskResult.original_length} → {maskResult.masked_length} chars
                      </div>
                      {maskResult.redaction_preview && (
                        <>
                          <div className="panel-title" style={{ marginTop: '1.25rem' }}>
                            <span className="panel-icon">👁️</span> Preview
                          </div>
                          <div className="masked-text">{maskResult.redaction_preview}</div>
                        </>
                      )}
                    </>
                  ) : (
                    <div className="empty-state">
                      <div className="empty-state-icon">🔒</div>
                      <p>Click "Mask PII" to see the masked output</p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </main>

        {/* ── Footer ── */}
        <footer className="footer">
          PII Shield v1.0.0 — Enterprise PII Detection & Compliance Engine
        </footer>
      </div>
    </>
  );
}
