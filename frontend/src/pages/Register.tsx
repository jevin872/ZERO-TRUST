import React, { useState } from "react";
import api from "../services/api";

interface RegisterProps {
  onNavigateToLogin: () => void;
}

export const Register: React.FC<RegisterProps> = ({ onNavigateToLogin }) => {
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationId, setOrganizationId] = useState("DEMO_BANK");
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setSuccess("");
    setLoading(true);

    try {
      await api.post("/auth/register", {
        username,
        email,
        password,
        organization_id: organizationId,
      });
      setSuccess("Registration successful! Redirecting to login...");
      setTimeout(() => {
        onNavigateToLogin();
      }, 1500);
    } catch (err: any) {
      setError(err.response?.data?.detail || "Registration failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <div className="glass-card auth-card">
        <div className="auth-header">
          <div style={{ fontSize: "40px", marginBottom: "12px" }}>🛡️</div>
          <h2 className="auth-title">Create Account</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "14px" }}>
            Register to join the Zero Trust framework
          </p>
        </div>

        {error && (
          <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid var(--color-high)", color: "var(--color-high)", borderRadius: "8px", padding: "12px", marginBottom: "20px", fontSize: "14px" }}>
            {error}
          </div>
        )}

        {success && (
          <div style={{ background: "rgba(16,185,129,0.1)", border: "1px solid var(--color-low)", color: "var(--color-low)", borderRadius: "8px", padding: "12px", marginBottom: "20px", fontSize: "14px" }}>
            {success}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input
              type="text"
              required
              className="form-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. janesec"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Email Address</label>
            <input
              type="email"
              required
              className="form-input"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="e.g. jane@corp.local"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input
              type="password"
              required
              className="form-input"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••"
            />
          </div>

          <div className="form-group">
            <label className="form-label">Select Organization</label>
            <select
              className="form-input"
              value={organizationId}
              onChange={(e) => setOrganizationId(e.target.value)}
            >
              <option value="DEMO_BANK">Demo Simulated Bank (Finance)</option>
              <option value="HOSPITAL">Metro Health Center (Healthcare)</option>
            </select>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "10px", padding: "12px" }}
          >
            {loading ? "Registering..." : "Create Account"}
          </button>
        </form>

        <div style={{ marginTop: "24px", textAlign: "center", fontSize: "14px", color: "var(--text-secondary)" }}>
          Already have an account?{" "}
          <span
            onClick={onNavigateToLogin}
            style={{ color: "var(--accent-cyan)", cursor: "pointer", fontWeight: "600" }}
          >
            Log In
          </span>
        </div>
      </div>
    </div>
  );
};
