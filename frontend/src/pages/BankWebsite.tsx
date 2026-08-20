import React, { useState, useEffect } from "react";
import api, { getDeviceFingerprint } from "../services/api";
import { BankAccount, BankTransaction, BankBeneficiary } from "../types";
import { Globe, Smartphone, Landmark, Send, UserPlus, CreditCard, Lock, CheckCircle, ShieldAlert, AlertCircle } from "lucide-react";

interface BankWebsiteProps {
  user: any;
  onLogout: () => void;
}

export const BankWebsite: React.FC<BankWebsiteProps> = ({ user, onLogout }) => {
  const [balanceData, setBalanceData] = useState<BankAccount | null>(null);
  const [transactions, setTransactions] = useState<BankTransaction[]>([]);
  const [beneficiaries, setBeneficiaries] = useState<BankBeneficiary[]>([]);
  const [loading, setLoading] = useState(true);
  
  // Transfer Form State
  const [amount, setAmount] = useState("");
  const [description, setDescription] = useState("");
  const [beneficiaryAcct, setBeneficiaryAcct] = useState("");
  const [transferError, setTransferError] = useState("");
  const [transferSuccess, setTransferSuccess] = useState("");

  // Beneficiary Form State
  const [newBeneName, setNewBeneName] = useState("");
  const [newBeneAcct, setNewBeneAcct] = useState("");
  const [newBeneBank, setNewBeneBank] = useState("ZeroTrust Demo Bank");
  const [beneError, setBeneError] = useState("");
  const [beneSuccess, setBeneSuccess] = useState("");

  // MFA Panel State
  const [mfaSetup, setMfaSetup] = useState<{ secret_key: string; qr_code_base64: string; is_enabled: boolean } | null>(null);
  const [mfaCode, setMfaCode] = useState("");
  const [mfaError, setMfaError] = useState("");
  const [mfaSuccess, setMfaSuccess] = useState("");
  const [mfaOpen, setMfaOpen] = useState(false);

  // Security warning state (reloads on dynamic score drop)
  const [trustSummary, setTrustSummary] = useState<{ trust_score: number; risk_level: string; decision: string } | null>(null);

  const fetchBankData = async () => {
    try {
      const [balRes, txRes, beneRes, scoreRes] = await Promise.all([
        api.get("/bank/balance"),
        api.get("/bank/transactions"),
        api.get("/bank/beneficiaries"),
        api.get("/users/me/trust-score")
      ]);
      setBalanceData(balRes.data);
      setTransactions(txRes.data);
      setBeneficiaries(beneRes.data);
      setTrustSummary(scoreRes.data);
    } catch (err: any) {
      console.error("Bank data fetch error:", err);
      if (err.response?.status === 401 || err.response?.status === 403) {
        onLogout(); // Session revoked or blocked
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBankData();
    // Poll bank state & score every 4 seconds to observe continuous telemetry
    const interval = setInterval(fetchBankData, 4000);
    return () => clearInterval(interval);
  }, []);

  const handleTransfer = async (e: React.FormEvent) => {
    e.preventDefault();
    setTransferError("");
    setTransferSuccess("");
    
    if (parseFloat(amount) <= 0) {
      setTransferError("Amount must be greater than zero.");
      return;
    }

    try {
      const res = await api.post("/bank/transfer", {
        amount: parseFloat(amount),
        description,
        beneficiary_account_number: beneficiaryAcct
      });
      setTransferSuccess(res.data.message);
      setAmount("");
      setDescription("");
      setBeneficiaryAcct("");
      fetchBankData();
    } catch (err: any) {
      setTransferError(err.response?.data?.detail || "Transfer simulation failed.");
    }
  };

  const handleAddBeneficiary = async (e: React.FormEvent) => {
    e.preventDefault();
    setBeneError("");
    setBeneSuccess("");

    try {
      await api.post("/bank/beneficiaries", {
        name: newBeneName,
        account_number: newBeneAcct,
        bank_name: newBeneBank
      });
      setBeneSuccess(`Beneficiary '${newBeneName}' added successfully.`);
      setNewBeneName("");
      setNewBeneAcct("");
      setNewBeneBank("ZeroTrust Demo Bank");
      fetchBankData();
    } catch (err: any) {
      setBeneError(err.response?.data?.detail || "Failed to add beneficiary.");
    }
  };

  const handleOpenMfa = async () => {
    setMfaError("");
    setMfaSuccess("");
    try {
      const res = await api.post("/auth/mfa/setup");
      setMfaSetup(res.data);
      setMfaOpen(true);
    } catch (err: any) {
      setMfaError("Failed to initiate MFA setup.");
    }
  };

  const handleVerifyMfa = async (e: React.FormEvent) => {
    e.preventDefault();
    setMfaError("");
    setMfaSuccess("");
    try {
      await api.post("/auth/mfa/verify", { token: mfaCode });
      setMfaSuccess("MFA linked successfully!");
      setMfaCode("");
      setTimeout(() => {
        setMfaOpen(false);
        setMfaSetup(null);
        fetchBankData();
      }, 1500);
    } catch (err: any) {
      setMfaError(err.response?.data?.detail || "Verification failed.");
    }
  };

  const clientIP = window.location.hostname;
  const userAgent = navigator.userAgent;

  if (loading && !balanceData) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "80vh" }}>
        <p style={{ color: "var(--text-secondary)" }}>Loading Online Banking System...</p>
      </div>
    );
  }

  const isRestricted = trustSummary?.decision === "RESTRICT_SENSITIVE_OPERATIONS" || trustSummary?.decision === "TERMINATE_SESSION_AND_BLOCK";
  const mfaRequired = trustSummary?.decision === "REQUIRE_MFA";

  return (
    <div style={{ background: "#f8fafc", color: "#1e293b", minHeight: "100vh", paddingBottom: "50px" }}>
      
      {/* Simulation Banner */}
      <div style={{ background: "#0284c7", color: "white", padding: "8px", textTransform: "uppercase", fontSize: "12px", fontWeight: "bold", letterSpacing: "1px", textAlign: "center" }}>
        ⚠️ DEMO / SIMULATED BANKING ENVIRONMENT — FOR CYBERSECURITY RESEARCH ONLY
      </div>

      <div style={{ maxWidth: "1280px", margin: "0 auto", padding: "30px 20px" }}>
        
        {/* Risk Alerts */}
        {isRestricted && (
          <div style={{ background: "#fef2f2", border: "1px solid #ef4444", borderRadius: "12px", padding: "16px", marginBottom: "24px", display: "flex", gap: "12px", alignItems: "center" }}>
            <ShieldAlert style={{ color: "#ef4444" }} size={24} />
            <div>
              <strong style={{ color: "#991b1b" }}>Adaptive Policy Enforced: PRIVILEGES RESTRICTED</strong>
              <p style={{ color: "#7f1d1d", fontSize: "14px" }}>
                ZeroTrustX has detected elevated session risk (Trust Score: {trustSummary?.trust_score}, Risk Level: {trustSummary?.risk_level}). Sensitive operations (Simulated Transfers, Adding Beneficiaries) are temporarily disabled.
              </p>
            </div>
          </div>
        )}

        {mfaRequired && !isRestricted && (
          <div style={{ background: "#fffbeb", border: "1px solid #f59e0b", borderRadius: "12px", padding: "16px", marginBottom: "24px", display: "flex", gap: "12px", alignItems: "center" }}>
            <AlertCircle style={{ color: "#d97706" }} size={24} />
            <div>
              <strong style={{ color: "#92400e" }}>Additional MFA Verification Required</strong>
              <p style={{ color: "#78350f", fontSize: "14px" }}>
                Active Session Trust Score is {trustSummary?.trust_score} (Medium-High Risk). Please verify your identity using the MFA Authenticator below before proceeding with operations.
              </p>
            </div>
          </div>
        )}

        {/* Customer Top Account Bar */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "16px", background: "white", borderRadius: "16px", border: "1px solid #e2e8f0", padding: "24px", marginBottom: "30px", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
          <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
            <div style={{ background: "#e0f2fe", borderRadius: "12px", padding: "12px", color: "#0284c7" }}>
              <Landmark size={32} />
            </div>
            <div>
              <span style={{ fontSize: "13px", color: "#64748b" }}>Simulated Bank Client</span>
              <h2 style={{ fontSize: "22px", color: "#0f172a" }}>{user?.username}</h2>
            </div>
          </div>

          <div style={{ display: "flex", gap: "40px" }}>
            <div>
              <span style={{ fontSize: "12px", color: "#64748b", textTransform: "uppercase" }}>Simulated Balance</span>
              <div style={{ fontSize: "28px", fontWeight: "800", color: "#0f172a" }}>
                ${balanceData?.balance.toLocaleString(undefined, { minimumFractionDigits: 2 })}
              </div>
            </div>
            <div>
              <span style={{ fontSize: "12px", color: "#64748b", textTransform: "uppercase" }}>Account Number</span>
              <div style={{ fontSize: "16px", fontWeight: "600", color: "#0f172a", marginTop: "8px" }}>
                <code>{balanceData?.account_number}</code>
              </div>
            </div>
          </div>
        </div>

        {/* Dash Grid */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(12, 1fr)", gap: "24px" }}>
          
          {/* LEFT: TRANSFER & BENEFICIARY */}
          <div style={{ gridColumn: "span 7" }} className="mobile-col-12">
            
            {/* Transfer Simulation */}
            <div style={{ background: "white", border: "1px solid #e2e8f0", borderRadius: "16px", padding: "24px", marginBottom: "24px", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
              <h3 style={{ fontSize: "18px", color: "#0f172a", marginBottom: "20px", display: "flex", alignItems: "center", gap: "8px" }}>
                <Send size={18} style={{ color: "#0284c7" }} /> Simulated Transfer Portal
              </h3>

              {transferError && <div style={{ background: "#fef2f2", color: "#b91c1c", padding: "12px", borderRadius: "8px", fontSize: "13px", marginBottom: "16px" }}>{transferError}</div>}
              {transferSuccess && <div style={{ background: "#ecfdf5", color: "#047857", padding: "12px", borderRadius: "8px", fontSize: "13px", marginBottom: "16px" }}>{transferSuccess}</div>}

              <form onSubmit={handleTransfer}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "16px" }}>
                  <div className="form-group">
                    <label style={{ color: "#64748b", fontSize: "12px", textTransform: "uppercase" }}>Select Beneficiary Account</label>
                    <select
                      className="form-input"
                      style={{ background: "#f8fafc", color: "#1e293b", borderColor: "#cbd5e1" }}
                      value={beneficiaryAcct}
                      required
                      disabled={isRestricted}
                      onChange={(e) => setBeneficiaryAcct(e.target.value)}
                    >
                      <option value="">-- Choose Account --</option>
                      {beneficiaries.map((b) => (
                        <option key={b.id} value={b.account_number}>
                          {b.name} ({b.bank_name})
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="form-group">
                    <label style={{ color: "#64748b", fontSize: "12px", textTransform: "uppercase" }}>Transfer Amount ($)</label>
                    <input
                      type="number"
                      required
                      disabled={isRestricted}
                      className="form-input"
                      style={{ background: "#f8fafc", color: "#1e293b", borderColor: "#cbd5e1" }}
                      placeholder="0.00"
                      value={amount}
                      onChange={(e) => setAmount(e.target.value)}
                    />
                  </div>
                </div>

                <div className="form-group" style={{ marginTop: "16px" }}>
                  <label style={{ color: "#64748b", fontSize: "12px", textTransform: "uppercase" }}>Transfer Memo</label>
                  <input
                    type="text"
                    required
                    disabled={isRestricted}
                    className="form-input"
                    style={{ background: "#f8fafc", color: "#1e293b", borderColor: "#cbd5e1" }}
                    placeholder="e.g. Utility Payment"
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                  />
                </div>

                <button
                  type="submit"
                  disabled={isRestricted}
                  className="btn btn-primary"
                  style={{ width: "100%", marginTop: "20px", background: "#0284c7" }}
                >
                  Confirm Simulated Transfer
                </button>
              </form>
            </div>

            {/* Beneficiaries Panel */}
            <div style={{ background: "white", border: "1px solid #e2e8f0", borderRadius: "16px", padding: "24px", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
              <h3 style={{ fontSize: "18px", color: "#0f172a", marginBottom: "20px", display: "flex", alignItems: "center", gap: "8px" }}>
                <UserPlus size={18} style={{ color: "#0284c7" }} /> Add Simulated Beneficiary
              </h3>

              {beneError && <div style={{ background: "#fef2f2", color: "#b91c1c", padding: "12px", borderRadius: "8px", fontSize: "13px", marginBottom: "16px" }}>{beneError}</div>}
              {beneSuccess && <div style={{ background: "#ecfdf5", color: "#047857", padding: "12px", borderRadius: "8px", fontSize: "13px", marginBottom: "16px" }}>{beneSuccess}</div>}

              <form onSubmit={handleAddBeneficiary}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "12px" }}>
                  <input
                    type="text"
                    required
                    disabled={isRestricted}
                    className="form-input"
                    style={{ background: "#f8fafc", color: "#1e293b", borderColor: "#cbd5e1" }}
                    placeholder="Beneficiary Name"
                    value={newBeneName}
                    onChange={(e) => setNewBeneName(e.target.value)}
                  />
                  <input
                    type="text"
                    required
                    disabled={isRestricted}
                    className="form-input"
                    style={{ background: "#f8fafc", color: "#1e293b", borderColor: "#cbd5e1" }}
                    placeholder="Account Number"
                    value={newBeneAcct}
                    onChange={(e) => setNewBeneAcct(e.target.value)}
                  />
                  <input
                    type="text"
                    required
                    disabled={isRestricted}
                    className="form-input"
                    style={{ background: "#f8fafc", color: "#1e293b", borderColor: "#cbd5e1" }}
                    placeholder="Bank Name"
                    value={newBeneBank}
                    onChange={(e) => setNewBeneBank(e.target.value)}
                  />
                </div>
                <button
                  type="submit"
                  disabled={isRestricted}
                  className="btn btn-secondary"
                  style={{ width: "100%", marginTop: "16px", borderColor: "#cbd5e1", color: "#0284c7" }}
                >
                  Link Beneficiary
                </button>
              </form>
            </div>
          </div>

          {/* RIGHT: TRANS, INFO & SECURITY */}
          <div style={{ gridColumn: "span 5" }} className="mobile-col-12">
            
            {/* Session Info */}
            <div style={{ background: "white", border: "1px solid #e2e8f0", borderRadius: "16px", padding: "24px", marginBottom: "24px", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
              <h3 style={{ fontSize: "16px", color: "#0f172a", marginBottom: "16px" }}>Session Metadata Telemetry</h3>
              <div style={{ fontSize: "13px", color: "#64748b", display: "flex", flexDirection: "column", gap: "10px" }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span>Host IP:</span>
                  <code style={{ color: "#0f172a" }}>{clientIP}</code>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <span>Device Fingerprint:</span>
                  <code style={{ color: "#0f172a", fontSize: "11px" }}>{getDeviceFingerprint()}</code>
                </div>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span>User Agent:</span>
                  <span style={{ color: "#0f172a", maxWidth: "180px", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={userAgent}>
                    {userAgent}
                  </span>
                </div>
              </div>
            </div>

            {/* MFA Security Shield */}
            <div style={{ background: "white", border: "1px solid #e2e8f0", borderRadius: "16px", padding: "24px", marginBottom: "24px", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
              <h3 style={{ fontSize: "16px", color: "#0f172a", marginBottom: "12px", display: "flex", alignItems: "center", gap: "8px" }}>
                <Lock size={16} style={{ color: "#0284c7" }} /> MFA Authorization Lock
              </h3>
              
              {mfaOpen ? (
                <form onSubmit={handleVerifyMfa} style={{ border: "1px solid #e2e8f0", borderRadius: "8px", padding: "12px", background: "#f8fafc", marginTop: "12px" }}>
                  {mfaSetup?.qr_code_base64 && (
                    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", marginBottom: "12px" }}>
                      <img src={mfaSetup.qr_code_base64} alt="QR Code" style={{ width: "130px", border: "2px solid #fff" }} />
                      <code style={{ fontSize: "10px", marginTop: "6px", color: "#0284c7" }}>Secret: {mfaSetup.secret_key}</code>
                    </div>
                  )}
                  {mfaError && <p style={{ color: "#ef4444", fontSize: "12px", marginBottom: "6px" }}>{mfaError}</p>}
                  {mfaSuccess && <p style={{ color: "#10b981", fontSize: "12px", marginBottom: "6px" }}>{mfaSuccess}</p>}

                  <input
                    type="text"
                    required
                    className="form-input"
                    placeholder="Enter 6-digit MFA Token"
                    maxLength={6}
                    value={mfaCode}
                    style={{ background: "white", color: "#1e293b", borderColor: "#cbd5e1" }}
                    onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                  />
                  <div style={{ display: "flex", gap: "8px", marginTop: "8px" }}>
                    <button type="submit" className="btn btn-primary" style={{ flex: 1, padding: "6px", background: "#0284c7" }}>Verify</button>
                    <button type="button" className="btn btn-secondary" style={{ flex: 1, padding: "6px" }} onClick={() => setMfaOpen(false)}>Cancel</button>
                  </div>
                </form>
              ) : (
                <div>
                  {user?.mfa_record?.is_enabled || mfaSetup?.is_enabled ? (
                    <div style={{ display: "flex", alignItems: "center", gap: "8px", color: "#10b981", fontWeight: "600", fontSize: "14px" }}>
                      <CheckCircle size={18} /> Enabled (+5 trust score boost)
                    </div>
                  ) : (
                    <button onClick={handleOpenMfa} className="btn btn-primary" style={{ width: "100%", background: "#0284c7" }}>
                      Bind MFA Token
                    </button>
                  )}
                </div>
              )}
            </div>

            {/* Transactions History List */}
            <div style={{ background: "white", border: "1px solid #e2e8f0", borderRadius: "16px", padding: "24px", boxShadow: "0 1px 3px rgba(0,0,0,0.05)" }}>
              <h3 style={{ fontSize: "16px", color: "#0f172a", marginBottom: "16px" }}>Transaction Ledger</h3>
              <div style={{ maxHeight: "250px", overflowY: "auto" }}>
                {transactions.length === 0 ? (
                  <p style={{ color: "#64748b", fontSize: "13px" }}>No simulated transactions registered.</p>
                ) : (
                  transactions.map((tx) => (
                    <div key={tx.id} style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "10px 0", borderBottom: "1px solid #e2e8f0" }}>
                      <div>
                        <div style={{ fontWeight: "600", fontSize: "13px", color: "#0f172a" }}>{tx.description}</div>
                        <span style={{ fontSize: "11px", color: "#94a3b8" }}>{new Date(tx.timestamp).toLocaleDateString()}</span>
                      </div>
                      <div style={{ fontWeight: "700", fontSize: "14px", color: tx.transaction_type === "TRANSFER_OUT" ? "#ef4444" : "#10b981" }}>
                        {tx.transaction_type === "TRANSFER_OUT" ? "-" : "+"}${tx.amount.toFixed(2)}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>

          </div>

        </div>

      </div>
    </div>
  );
};
export default BankWebsite;
