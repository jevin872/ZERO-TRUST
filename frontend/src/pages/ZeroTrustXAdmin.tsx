import React, { useState, useEffect, useRef } from "react";
import api, { getDeviceFingerprint } from "../services/api";
import { User, Session, ScoringRule, AuditLog, Threat, SecurityEvent } from "../types";
import { 
  Users, Key, ShieldAlert, FileText, Settings, Play, 
  Terminal, UserX, UserCheck, AlertTriangle, AlertCircle, X, ShieldCheck
} from "lucide-react";
import { Bar, Line } from "react-chartjs-2";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

export const ZeroTrustXAdmin: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"users" | "rules" | "logs" | "threats" | "simulator">("users");
  
  // Dashboard stats
  const [stats, setStats] = useState<any>({
    total_users: 0,
    active_sessions: 0,
    recently_blocked: 0,
    unresolved_threats: 0,
    risk_distribution: { LOW: 0, MEDIUM_LOW: 0, MEDIUM_HIGH: 0, HIGH: 0, CRITICAL: 0 }
  });
  
  // Active states
  const [users, setUsers] = useState<User[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [rules, setRules] = useState<ScoringRule[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [liveAlerts, setLiveAlerts] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  // Selected User Detail Drawer
  const [selectedUser, setSelectedUser] = useState<User | null>(null);
  const [selectedUserScore, setSelectedUserScore] = useState<any>(null);
  const [selectedUserHistory, setSelectedUserHistory] = useState<SecurityEvent[]>([]);

  // Simulation Console Form
  const [selectedSimUser, setSelectedSimUser] = useState("");
  const [selectedSimEvent, setSelectedSimEvent] = useState("UNKNOWN_DEVICE");

  // Scoring Rule Editor State
  const [editingRule, setEditingRule] = useState<ScoringRule | null>(null);
  const [ruleForm, setRuleForm] = useState({
    organization_id: "DEMO_BANK",
    event_type: "",
    score_impact: 0,
    severity: "LOW",
    is_enabled: true,
    repeated_threshold: 1,
    time_window: 300,
    recovery_delay: 3600,
    recovery_rate: 2
  });

  const wsRef = useRef<WebSocket | null>(null);

  const fetchStatsAndMain = async () => {
    try {
      const statsRes = await api.get("/admin/dashboard");
      setStats(statsRes.data);

      if (activeTab === "users") {
        const [uRes, sRes] = await Promise.all([
          api.get("/admin/users"),
          api.get("/admin/sessions")
        ]);
        setUsers(uRes.data);
        setSessions(sRes.data);
      } else if (activeTab === "rules") {
        const rRes = await api.get("/admin/scoring-rules");
        setRules(rRes.data);
      } else if (activeTab === "logs") {
        const lRes = await api.get("/admin/audit-logs");
        setLogs(lRes.data);
      } else if (activeTab === "threats") {
        const tRes = await api.get("/admin/threats");
        setThreats(tRes.data);
      }
    } catch (err) {
      console.error("SOC failed to load database stats:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    fetchStatsAndMain();
  }, [activeTab]);

  // Connect to Admin WebSockets for real-time streaming updates
  useEffect(() => {
    const wsUrl = `ws://${window.location.hostname}:8000/api/v1/ws/admin`;
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.type === "SECURITY_EVENT") {
          const e = payload.event;
          const message = `[ALERT] User ${e.username} Score: ${e.previous_trust_score} -> ${e.new_trust_score} (${e.event_type}) | Action: ${e.action_taken}`;
          
          // Push notification toast
          setLiveAlerts((prev) => [message, ...prev.slice(0, 4)]);
          
          // Trigger dynamic reload of lists
          fetchStatsAndMain();
          
          // If the currently inspected user is the affected user, reload details
          if (selectedUser && selectedUser.id === e.user_id) {
            handleSelectUser(selectedUser);
          }
        }
      } catch (err) {
        console.error("Failed to parse WebSocket alert:", err);
      }
    };

    ws.onclose = () => {
      console.log("WebSocket SOC connection closed.");
    };

    return () => {
      ws.close();
    };
  }, [selectedUser]);

  const handleSelectUser = async (user: User) => {
    setSelectedUser(user);
    setSelectedUserScore(null);
    setSelectedUserHistory([]);
    try {
      const [scoreRes, historyRes] = await Promise.all([
        api.get(`/admin/users/${user.id}/trust-score`),
        api.get(`/admin/users/${user.id}/trust-history`)
      ]);
      setSelectedUserScore(scoreRes.data);
      setSelectedUserHistory(historyRes.data);
    } catch (err) {
      console.error("Failed to load user SOC overview:", err);
    }
  };

  const handleBlockUser = async (userId: number) => {
    try {
      await api.post(`/admin/users/${userId}/block`);
      fetchStatsAndMain();
      if (selectedUser?.id === userId) {
        handleSelectUser(selectedUser);
      }
    } catch (err) {
      alert("Eviction / block action failed.");
    }
  };

  const handleUnblockUser = async (userId: number) => {
    try {
      await api.post(`/admin/users/${userId}/unblock`);
      fetchStatsAndMain();
      if (selectedUser?.id === userId) {
        handleSelectUser(selectedUser);
      }
    } catch (err) {
      alert("Unblock action failed.");
    }
  };

  const handleTerminateSession = async (userId: number, sessionId: string) => {
    try {
      await api.post(`/admin/users/${userId}/terminate-session`, { session_id: sessionId });
      fetchStatsAndMain();
    } catch (err) {
      alert("Failed to evict session.");
    }
  };

  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      if (editingRule) {
        await api.put(`/admin/scoring-rules/${editingRule.id}`, ruleForm);
        setEditingRule(null);
      } else {
        await api.post("/admin/scoring-rules", ruleForm);
      }
      setRuleForm({
        organization_id: "DEMO_BANK",
        event_type: "",
        score_impact: 0,
        severity: "LOW",
        is_enabled: true,
        repeated_threshold: 1,
        time_window: 300,
        recovery_delay: 3600,
        recovery_rate: 2
      });
      fetchStatsAndMain();
    } catch (err: any) {
      alert(err.response?.data?.detail || "Rule update failed.");
    }
  };

  const handleTriggerSimulation = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSimUser) {
      alert("Please select a target user to run the attack simulation.");
      return;
    }
    try {
      await api.post("/admin/simulate", {
        user_id: parseInt(selectedSimUser),
        event_type: selectedSimEvent,
        ip_address: "192.168.10.15",
        device_info: getDeviceFingerprint()
      });
      alert(`Simulation event '${selectedSimEvent}' injected! View the timeline or dashboard to see the live score shift.`);
    } catch (err: any) {
      alert(err.response?.data?.detail || "Telemetry injection failed.");
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "LOW": return "var(--color-low)";
      case "MEDIUM_LOW": return "var(--color-med-low)";
      case "MEDIUM_HIGH": return "var(--color-medium)";
      case "HIGH": return "var(--color-high)";
      case "CRITICAL": return "var(--color-critical)";
      default: return "var(--accent-blue)";
    }
  };

  const getRiskBadgeClass = (risk: string) => {
    switch (risk) {
      case "LOW": return "badge-low";
      case "MEDIUM_LOW": return "badge-medium-low";
      case "MEDIUM_HIGH": return "badge-medium-high";
      case "HIGH": return "badge-high";
      case "CRITICAL": return "badge-critical";
      default: return "";
    }
  };

  // Chart Details
  const riskLabels = Object.keys(stats.risk_distribution);
  const riskValues = Object.values(stats.risk_distribution);

  const barData = {
    labels: riskLabels,
    datasets: [
      {
        label: "Registered Users",
        data: riskValues,
        backgroundColor: [
          "rgba(16, 185, 129, 0.5)", // Low
          "rgba(52, 211, 153, 0.5)", // Med-low
          "rgba(245, 158, 11, 0.5)",  // Med-high
          "rgba(239, 68, 68, 0.5)",   // High
          "rgba(127, 29, 29, 0.5)"    // Critical
        ],
        borderColor: [
          "var(--color-low)", "var(--color-med-low)", "var(--color-medium)", "var(--color-high)", "var(--color-critical)"
        ],
        borderWidth: 1.5
      }
    ]
  };

  const barOptions = {
    responsive: true,
    maintainAspectRatio: false,
    scales: {
      y: { grid: { color: "rgba(255,255,255,0.05)" }, ticks: { color: "#9ca3af" } },
      x: { grid: { display: false }, ticks: { color: "#9ca3af" } }
    },
    plugins: { legend: { display: false } }
  };

  return (
    <div style={{ maxWidth: "1400px", margin: "0 auto", padding: "40px 20px" }}>
      
      {/* Live WebSockets Alerts Banner */}
      {liveAlerts.length > 0 && (
        <div style={{ marginBottom: "24px" }}>
          <span style={{ fontSize: "11px", color: "var(--color-high)", textTransform: "uppercase", fontWeight: "700", letterSpacing: "1px", display: "block", marginBottom: "8px" }}>
            🚨 Live SOC Event Stream (WebSockets)
          </span>
          <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
            {liveAlerts.map((alert, idx) => (
              <div key={idx} style={{ background: "rgba(239, 68, 68, 0.08)", border: "1px solid rgba(239,68,68,0.2)", borderRadius: "8px", padding: "10px 16px", fontSize: "13px", color: "var(--color-high)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span>{alert}</span>
                <X size={14} style={{ cursor: "pointer", color: "var(--text-secondary)" }} onClick={() => setLiveAlerts(liveAlerts.filter((_, i) => i !== idx))} />
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top Banner Stats */}
      <div className="stat-card-grid">
        <div className="glass-card stat-card">
          <span className="stat-lbl">Total Users</span>
          <div className="stat-val" style={{ color: "white" }}>{stats.total_users}</div>
        </div>
        <div className="glass-card stat-card">
          <span className="stat-lbl">Active Sessions</span>
          <div className="stat-val" style={{ color: "var(--accent-cyan)" }}>{stats.active_sessions}</div>
        </div>
        <div className="glass-card stat-card">
          <span className="stat-lbl">Unresolved Threats</span>
          <div className="stat-val" style={{ color: "var(--color-medium)" }}>{stats.unresolved_threats}</div>
        </div>
        <div className="glass-card stat-card">
          <span className="stat-lbl">Recently Blocked</span>
          <div className="stat-val" style={{ color: "var(--color-high)" }}>{stats.recently_blocked}</div>
        </div>
      </div>

      {/* Admin tabs */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "30px", flexWrap: "wrap", gap: "15px" }}>
        <div>
          <h2>ZeroTrustX Security Operations Center (SOC)</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "14px" }}>
            Organization-specific policies, real-time threat intelligence feeds, and adaptive session evictions.
          </p>
        </div>

        <div style={{ display: "flex", gap: "8px", background: "var(--bg-tertiary)", padding: "4px", borderRadius: "10px", border: "1px solid var(--border-light)" }}>
          <button onClick={() => setActiveTab("users")} className="btn" style={{ background: activeTab === "users" ? "var(--accent-purple)" : "transparent", padding: "6px 12px", fontSize: "13px" }}>
            Users & Sessions
          </button>
          <button onClick={() => setActiveTab("threats")} className="btn" style={{ background: activeTab === "threats" ? "var(--accent-purple)" : "transparent", padding: "6px 12px", fontSize: "13px" }}>
            Threat Intel
          </button>
          <button onClick={() => setActiveTab("rules")} className="btn" style={{ background: activeTab === "rules" ? "var(--accent-purple)" : "transparent", padding: "6px 12px", fontSize: "13px" }}>
            Scoring Policies
          </button>
          <button onClick={() => setActiveTab("logs")} className="btn" style={{ background: activeTab === "logs" ? "var(--accent-purple)" : "transparent", padding: "6px 12px", fontSize: "13px" }}>
            Audit Logs
          </button>
          <button onClick={() => setActiveTab("simulator")} className="btn" style={{ background: activeTab === "simulator" ? "var(--accent-purple)" : "transparent", padding: "6px 12px", fontSize: "13px", borderColor: "rgba(139,92,246,0.3)" }}>
            <Play size={12} /> Attack Simulator
          </button>
        </div>
      </div>

      {loading && (
        <div style={{ display: "flex", justifyContent: "center", padding: "40px" }}>
          <p style={{ color: "var(--text-secondary)" }}>Querying SOC state databases...</p>
        </div>
      )}

      {!loading && (
        <div className="dashboard-grid">
          
          {/* TAB 1: USERS & ACTIVE SESSIONS */}
          {activeTab === "users" && (
            <>
              <div className="col-7" style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
                
                {/* Users Registry */}
                <div className="glass-card">
                  <h3>User Registry Risk Monitoring</h3>
                  <div className="data-table-container">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Username</th>
                          <th>Tenant</th>
                          <th>Score</th>
                          <th>Risk Band</th>
                          <th>Account status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {users.map((usr) => (
                          <tr key={usr.id} style={{ cursor: "pointer", background: selectedUser?.id === usr.id ? "rgba(139,92,246,0.06)" : "transparent" }} onClick={() => handleSelectUser(usr)}>
                            <td><strong>{usr.username}</strong></td>
                            <td><code>{usr.organization_id}</code></td>
                            <td>{usr.is_blocked ? (
                              <span style={{ color: "var(--text-muted)", textDecoration: "line-through" }}>Blocked</span>
                            ) : (
                              <strong>100</strong> // placeholder, will reload details on selection
                            )}</td>
                            <td>
                              {usr.is_blocked ? (
                                <span className="badge badge-high">Blocked</span>
                              ) : (
                                <span className="badge badge-low">LOW</span>
                              )}
                            </td>
                            <td>
                              {usr.is_blocked ? (
                                <span style={{ color: "var(--color-high)" }}>Suspended</span>
                              ) : (
                                <span style={{ color: "var(--color-low)" }}>Active</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Active Sessions */}
                <div className="glass-card">
                  <h3>Active Sessions Eviction Monitor</h3>
                  <div className="data-table-container">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>User ID</th>
                          <th>IP Address</th>
                          <th>Client Device</th>
                          <th>Evict</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sessions.map((sess) => (
                          <tr key={sess.id}>
                            <td>User #{sess.user_id}</td>
                            <td><code>{sess.ip_address}</code></td>
                            <td style={{ maxWidth: "200px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              {sess.user_agent || "Unknown"}
                            </td>
                            <td>
                              <button onClick={() => handleTerminateSession(sess.user_id, sess.id)} className="btn btn-danger" style={{ padding: "4px 8px", fontSize: "11px" }}>
                                Revoke Session
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>

              {/* USER DETAILS INSPECTOR DRAWER */}
              <div className="col-5">
                <div className="glass-card" style={{ position: "sticky", top: "100px", minHeight: "500px" }}>
                  {selectedUser ? (
                    <div>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "20px" }}>
                        <div>
                          <h3 style={{ fontSize: "20px" }}>User Profile: {selectedUser.username}</h3>
                          <span style={{ fontSize: "12px", color: "var(--text-secondary)" }}>ID: #{selectedUser.id} | Org: {selectedUser.organization_id}</span>
                        </div>
                        <div>
                          {selectedUser.is_blocked ? (
                            <button onClick={() => handleUnblockUser(selectedUser.id)} className="btn btn-secondary" style={{ color: "var(--color-low)" }}>
                              <UserCheck size={14} /> Unblock User
                            </button>
                          ) : (
                            <button onClick={() => handleBlockUser(selectedUser.id)} className="btn btn-danger">
                              <UserX size={14} /> Lock Account
                            </button>
                          )}
                        </div>
                      </div>

                      {/* Display Score Metric if loaded */}
                      {selectedUserScore && (
                        <div style={{ background: "rgba(0,0,0,0.2)", borderRadius: "12px", padding: "16px", marginBottom: "20px", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                          <div>
                            <span className="stat-lbl">Continuous Trust Score</span>
                            <div style={{ fontSize: "36px", fontWeight: "800", color: getRiskColor(selectedUserScore.risk_level) }}>
                              {selectedUserScore.trust_score} / 100
                            </div>
                          </div>
                          <div>
                            <span className="stat-lbl">Active Policy Control</span>
                            <div style={{ fontWeight: "700", marginTop: "4px" }}>
                              <span className={`badge ${getRiskBadgeClass(selectedUserScore.risk_level)}`}>
                                {selectedUserScore.decision}
                              </span>
                            </div>
                          </div>
                        </div>
                      )}

                      <h4>Scoring Degradation Feed</h4>
                      <div style={{ marginTop: "15px", maxHeight: "300px", overflowY: "auto", paddingRight: "10px" }}>
                        <div className="timeline">
                          {selectedUserHistory.length === 0 ? (
                            <p style={{ color: "var(--text-muted)", fontSize: "13px" }}>No scoring logs available for user.</p>
                          ) : (
                            selectedUserHistory.map((h) => (
                              <div className="timeline-item" key={h.id}>
                                <div className={`timeline-dot ${h.score_change < 0 ? "negative" : "positive"}`}></div>
                                <div className="timeline-content" style={{ padding: "8px 12px" }}>
                                  <div style={{ display: "flex", justifyContent: "space-between", fontSize: "12px" }}>
                                    <span style={{ fontWeight: "600", color: h.score_change < 0 ? "var(--color-high)" : "var(--color-low)" }}>
                                      {h.event_type}
                                    </span>
                                    <span style={{ color: "var(--text-muted)", fontSize: "10px" }}>{new Date(h.timestamp).toLocaleTimeString()}</span>
                                  </div>
                                  <p style={{ fontSize: "11px", color: "var(--text-secondary)", margin: "4px 0" }}>{h.explainable_reason}</p>
                                  <div style={{ fontSize: "10px", display: "flex", justifyContent: "space-between" }}>
                                    <span>Impact: <strong style={{ color: h.score_change < 0 ? "var(--color-high)" : "var(--color-low)" }}>{h.score_change > 0 ? `+${h.score_change}` : h.score_change}</strong></span>
                                    <span>Result Score: <strong>{h.new_trust_score}</strong></span>
                                  </div>
                                </div>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", height: "400px", color: "var(--text-muted)" }}>
                      <ShieldCheck size={48} style={{ marginBottom: "15px", color: "var(--color-low)" }} />
                      <p>Select a user to audit trust history, enforce manual locks, and revoke active sessions.</p>
                    </div>
                  )}
                </div>
              </div>
            </>
          )}

          {/* TAB 2: THREAT INTELLIGENCE (SOC CHARTS) */}
          {activeTab === "threats" && (
            <>
              {/* Distribution Charts */}
              <div className="col-5">
                <div className="glass-card" style={{ height: "320px" }}>
                  <h3>Risk Level Distributions</h3>
                  <div style={{ position: "relative", height: "220px", marginTop: "15px" }}>
                    <Bar data={barData} options={barOptions} />
                  </div>
                </div>
              </div>

              <div className="col-7">
                <div className="glass-card" style={{ height: "320px", display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", color: "var(--text-secondary)" }}>
                  <ShieldAlert size={40} style={{ marginBottom: "10px" }} />
                  <h4>Dynamic Threat Evaluation Model</h4>
                  <p style={{ fontSize: "13px", padding: "0 40px", textAlign: "center", marginTop: "5px" }}>
                    Telemetry feeds map continuous evaluations. High-severity signals immediately populate the active threat alert matrices below.
                  </p>
                </div>
              </div>

              {/* Threats Grid Table */}
              <div className="col-12">
                <div className="glass-card">
                  <h3>Active Anomalous Threat Alerts</h3>
                  <div className="data-table-container">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Timestamp</th>
                          <th>Affected User</th>
                          <th>Anomaly Flag</th>
                          <th>Severity</th>
                          <th>Threat Description</th>
                          <th>Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {threats.length === 0 ? (
                          <tr>
                            <td colSpan={6} style={{ textAlign: "center", color: "var(--text-muted)", padding: "30px" }}>No anomalies flagged. Clean ledger.</td>
                          </tr>
                        ) : (
                          threats.map((t) => (
                            <tr key={t.id}>
                              <td>{new Date(t.timestamp).toLocaleString()}</td>
                              <td><strong>{t.username}</strong></td>
                              <td><code>{t.event_type}</code></td>
                              <td>
                                <span className={`badge ${t.severity === "CRITICAL" ? "badge-high" : "badge-medium-high"}`}>{t.severity}</span>
                              </td>
                              <td style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{t.description}</td>
                              <td>
                                {t.is_resolved ? (
                                  <span className="badge badge-low">Resolved</span>
                                ) : (
                                  <span style={{ color: "var(--color-medium)" }}>Unresolved</span>
                                )}
                              </td>
                            </tr>
                          ))
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              </div>
            </>
          )}

          {/* TAB 3: SCORING RULES */}
          {activeTab === "rules" && (
            <div className="col-12">
              <div className="glass-card">
                <h3>Organization-Specific Policy Engine Configuration</h3>
                <p style={{ color: "var(--text-secondary)", fontSize: "13px", marginTop: "4px", marginBottom: "20px" }}>
                  Adjust score impacts, severities, repeated-event aggregation thresholds, and windows for multiple sectors.
                </p>

                {editingRule && (
                  <form onSubmit={handleSaveRule} className="glass-card" style={{ background: "rgba(0,0,0,0.3)", marginBottom: "30px", border: "1px solid var(--accent-purple)" }}>
                    <h4 style={{ marginBottom: "20px" }}>Edit Scoring Rule ({ruleForm.organization_id} - {ruleForm.event_type})</h4>
                    
                    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "20px" }}>
                      <div className="form-group">
                        <label className="form-label">Score Impact</label>
                        <input
                          type="number"
                          required
                          className="form-input"
                          value={ruleForm.score_impact}
                          onChange={(e) => setRuleForm({ ...ruleForm, score_impact: parseInt(e.target.value) })}
                        />
                      </div>

                      <div className="form-group">
                        <label className="form-label">Severity</label>
                        <select
                          className="form-input"
                          value={ruleForm.severity}
                          onChange={(e) => setRuleForm({ ...ruleForm, severity: e.target.value })}
                        >
                          <option value="LOW">LOW</option>
                          <option value="MEDIUM">MEDIUM</option>
                          <option value="HIGH">HIGH</option>
                          <option value="CRITICAL">CRITICAL</option>
                        </select>
                      </div>

                      <div className="form-group">
                        <label className="form-label">Escalation Threshold</label>
                        <input
                          type="number"
                          required
                          min={1}
                          className="form-input"
                          value={ruleForm.repeated_threshold}
                          onChange={(e) => setRuleForm({ ...ruleForm, repeated_threshold: parseInt(e.target.value) })}
                        />
                      </div>

                      <div className="form-group">
                        <label className="form-label">Time Window (Seconds)</label>
                        <input
                          type="number"
                          required
                          min={10}
                          className="form-input"
                          value={ruleForm.time_window}
                          onChange={(e) => setRuleForm({ ...ruleForm, time_window: parseInt(e.target.value) })}
                        />
                      </div>

                      <div className="form-group">
                        <label style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer", fontSize: "14px", marginTop: "24px" }}>
                          <input
                            type="checkbox"
                            checked={ruleForm.is_enabled}
                            onChange={(e) => setRuleForm({ ...ruleForm, is_enabled: e.target.checked })}
                          />
                          Rule Enabled
                        </label>
                      </div>
                    </div>

                    <div style={{ display: "flex", gap: "10px", marginTop: "20px", justifyContent: "flex-end" }}>
                      <button type="submit" className="btn btn-primary">Save Changes</button>
                      <button type="button" className="btn btn-secondary" onClick={() => setEditingRule(null)}>Cancel</button>
                    </div>
                  </form>
                )}

                <div className="data-table-container">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Organization</th>
                        <th>Event Type</th>
                        <th>Impact</th>
                        <th>Severity</th>
                        <th>Escalation Logic</th>
                        <th>Rule Status</th>
                        <th>Configure</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rules.map((rule) => (
                        <tr key={rule.id}>
                          <td><code>{rule.organization_id}</code></td>
                          <td><code>{rule.event_type}</code></td>
                          <td style={{ color: rule.score_impact < 0 ? "var(--color-high)" : "var(--color-low)", fontWeight: "700" }}>
                            {rule.score_impact > 0 ? `+${rule.score_impact}` : rule.score_impact}
                          </td>
                          <td>
                            <span className={`badge ${rule.severity === "LOW" ? "badge-low" : rule.severity === "MEDIUM" ? "badge-medium-low" : "badge-medium-high"}`}>{rule.severity}</span>
                          </td>
                          <td style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
                            1.5x Penalty if triggered {rule.repeated_threshold}x in {rule.time_window}s
                          </td>
                          <td>
                            {rule.is_enabled ? (
                              <span className="badge badge-low">Active</span>
                            ) : (
                              <span className="badge" style={{ background: "rgba(255,255,255,0.05)", color: "var(--text-muted)" }}>Disabled</span>
                            )}
                          </td>
                          <td>
                            <button
                              onClick={() => {
                                setEditingRule(rule);
                                setRuleForm({
                                  organization_id: rule.organization_id,
                                  event_type: rule.event_type,
                                  score_impact: rule.score_impact,
                                  severity: rule.severity,
                                  is_enabled: rule.is_enabled,
                                  repeated_threshold: rule.repeated_threshold,
                                  time_window: rule.time_window,
                                  recovery_delay: rule.recovery_delay,
                                  recovery_rate: rule.recovery_rate
                                });
                              }}
                              className="btn btn-secondary"
                              style={{ padding: "6px 12px" }}
                            >
                              <Settings size={12} /> Configure
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>

              </div>
            </div>
          )}

          {/* TAB 4: SYSTEM AUDIT LOGS */}
          {activeTab === "logs" && (
            <div className="col-12">
              <div className="glass-card">
                <h3>System Administrative Audit Trail</h3>
                <div className="data-table-container" style={{ marginTop: "15px" }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Timestamp</th>
                        <th>Actor</th>
                        <th>Target</th>
                        <th>Action</th>
                        <th>IP Address</th>
                        <th>Reasoning</th>
                      </tr>
                    </thead>
                    <tbody>
                      {logs.map((log) => (
                        <tr key={log.id}>
                          <td>{new Date(log.timestamp).toLocaleString()}</td>
                          <td><code>{log.actor_username}</code></td>
                          <td>{log.target_username ? <code>{log.target_username}</code> : <span style={{ color: "var(--text-muted)" }}>None</span>}</td>
                          <td>
                            <span className="badge" style={{ background: "rgba(139,92,246,0.1)", color: "var(--accent-purple)", border: "1px solid rgba(139,92,246,0.2)" }}>{log.action}</span>
                          </td>
                          <td><code>{log.ip_address || "System"}</code></td>
                          <td style={{ fontSize: "13px", color: "var(--text-secondary)" }}>{log.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: TELEMETRY ATTACK SIMULATOR */}
          {activeTab === "simulator" && (
            <div className="col-12">
              <div className="glass-card" style={{ border: "1px solid rgba(239,68,68,0.25)", background: "rgba(239,68,68,0.01)" }}>
                <h3 style={{ color: "var(--color-high)", display: "flex", alignItems: "center", gap: "8px" }}>
                  <Play size={18} /> Cybersecurity Lab Telemetry Simulation Panel
                </h3>
                <p style={{ color: "var(--text-secondary)", fontSize: "14px", marginTop: "4px", marginBottom: "20px" }}>
                  Generate controlled client-side telemetry signals directly to evaluate how the ZeroTrustX dynamic trust engines degrade scores and evict sessions.
                </p>

                <form onSubmit={handleTriggerSimulation} className="glass-card" style={{ background: "rgba(0,0,0,0.2)", border: "1px solid var(--border-light)", maxWidth: "600px" }}>
                  <div className="form-group">
                    <label className="form-label">Select Target User Account</label>
                    <select
                      className="form-input"
                      value={selectedSimUser}
                      onChange={(e) => setSelectedSimUser(e.target.value)}
                      required
                    >
                      <option value="">-- Choose User --</option>
                      {users.map((u) => (
                        <option key={u.id} value={u.id}>
                          {u.username} (ID: #{u.id} | Org: {u.organization_id})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-group" style={{ marginTop: "16px" }}>
                    <label className="form-label">Choose Telemetry Event Type</label>
                    <select
                      className="form-input"
                      value={selectedSimEvent}
                      onChange={(e) => setSelectedSimEvent(e.target.value)}
                    >
                      <option value="UNKNOWN_DEVICE">Simulate Unknown Device Fingerprint (-10)</option>
                      <option value="LOGIN_FAILURE">Simulate Failed Login attempt (-10)</option>
                      <option value="MFA_FAILURE">Simulate MFA Verification failure (-15)</option>
                      <option value="EXCESSIVE_API_REQUESTS">Simulate Excessive API request rate (-15)</option>
                      <option value="UNAUTHORIZED_RESOURCE_ACCESS">Simulate Unauthorized resource access (-15)</option>
                      <option value="SUSPICIOUS_ACTIVITY">Simulate General suspicious behavior (-15)</option>
                      <option value="LARGE_TRANSACTION">Simulate Large transfer simulation (-20)</option>
                      <option value="NORMAL_VERIFIED_ACTIVITY">Simulate Normal Verified activity (+2)</option>
                    </select>
                  </div>

                  <button type="submit" className="btn btn-primary" style={{ width: "100%", marginTop: "24px", background: "linear-gradient(135deg, var(--color-high), var(--accent-purple))" }}>
                    Inject Security telemetry Event
                  </button>
                </form>

                <div className="glass-card" style={{ marginTop: "24px", background: "rgba(0,0,0,0.15)", border: "1px solid var(--border-light)" }}>
                  <h4 style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "15px", marginBottom: "10px" }}>
                    <Terminal size={14} style={{ color: "var(--accent-cyan)" }} /> Demonstration Lab Run Guide (Steps 1–6)
                  </h4>
                  <ol style={{ fontSize: "13px", color: "var(--text-secondary)", paddingLeft: "20px", display: "flex", flexDirection: "column", gap: "8px" }}>
                    <li>Select the customer user in the dropdown above.</li>
                    <li>Fire <strong>Simulate Unknown Device</strong> (Score drops to 90).</li>
                    <li>Fire <strong>Simulate Failed Login</strong> (Score drops to 80).</li>
                    <li>Fire <strong>Simulate MFA Failure</strong> (Score drops to 65).</li>
                    <li>Fire <strong>Simulate Excessive API Requests</strong> (Score drops to 50).</li>
                    <li>Fire <strong>Simulate Unauthorized Resource Access</strong> (Score drops to 35).</li>
                    <li>Fire <strong>Simulate General Suspicious Behavior</strong> (Score drops to 20, triggering **CRITICAL** lockout, evicting all tokens, and suspending the account).</li>
                  </ol>
                </div>
              </div>
            </div>
          )}

        </div>
      )}

    </div>
  );
};
export default ZeroTrustXAdmin;
