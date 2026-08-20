import React, { useState } from "react";
import api, { getDeviceFingerprint } from "../services/api";

interface LoginProps {
  onLoginSuccess: (user: any, token: string, roles: string[]) => void;
  onNavigateToRegister: () => void;
}

export const Login: React.FC<LoginProps> = ({ onLoginSuccess, onNavigateToRegister }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaToken, setMfaToken] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  // Store credentials temporarily for MFA verification
  const [tempAuth, setTempAuth] = useState<{ token: string; user: any } | null>(null);

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const response = await api.post("/auth/login", {
        username,
        password,
        device_fingerprint: getDeviceFingerprint(),
      });

      const { access_token, refresh_token, mfa_required } = response.data;

      // Save token to localStorage so subsequent calls can authenticate
      localStorage.setItem("token", access_token);
      localStorage.setItem("refresh_token", refresh_token);

      // Get user profile to determine roles
      const profileResponse = await api.get("/users/me");
      const user = profileResponse.data;
      const roles = user.roles.map((r: any) => r.name);

      if (mfa_required) {
        setTempAuth({ token: access_token, user });
        setMfaRequired(true);
      } else {
        localStorage.setItem("user", JSON.stringify(user));
        onLoginSuccess(user, access_token, roles);
      }
    } catch (err: any) {
      // Clear token if set before error
      localStorage.removeItem("token");
      localStorage.removeItem("refresh_token");
      setError(err.response?.data?.detail || "Invalid username or password.");
    } finally {
      setLoading(false);
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      await api.post("/auth/mfa/verify", {
        token: mfaToken,
      });

      // MFA Success
      if (tempAuth) {
        localStorage.setItem("user", JSON.stringify(tempAuth.user));
        const roles = tempAuth.user.roles.map((r: any) => r.name);
        onLoginSuccess(tempAuth.user, tempAuth.token, roles);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || "Invalid MFA code. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  if (mfaRequired) {
    return (
      <div className="auth-container">
        <div className="glass-card auth-card">
          <div className="auth-header">
            <div style={{ fontSize: "40px", marginBottom: "12px" }}>🔐</div>
            <h2 className="auth-title">Two-Factor Authentication</h2>
            <p style={{ color: "var(--text-secondary)", fontSize: "14px" }}>
              Enter the 6-digit verification code from your authenticator app
            </p>
          </div>

          {error && (
            <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid var(--color-high)", color: "var(--color-high)", borderRadius: "8px", padding: "12px", marginBottom: "20px", fontSize: "14px" }}>
              {error}
            </div>
          )}

          <form onSubmit={handleMfaSubmit}>
            <div className="form-group">
              <label className="form-label">Verification Code</label>
              <input
                type="text"
                required
                className="form-input"
                maxLength={6}
                style={{ letterSpacing: "8px", textAlign: "center", fontSize: "20px", fontWeight: "700" }}
                value={mfaToken}
                onChange={(e) => setMfaToken(e.target.value.replace(/\D/g, ""))}
                placeholder="000000"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn btn-primary"
              style={{ width: "100%", marginTop: "10px", padding: "12px" }}
            >
              {loading ? "Verifying..." : "Verify Code"}
            </button>
            
            <button
              type="button"
              className="btn btn-secondary"
              style={{ width: "100%", marginTop: "10px" }}
              onClick={() => {
                localStorage.removeItem("token");
                localStorage.removeItem("refresh_token");
                setMfaRequired(false);
                setTempAuth(null);
                setMfaToken("");
              }}
            >
              Back to Login
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="glass-card auth-card">
        <div className="auth-header">
          <div style={{ fontSize: "40px", marginBottom: "12px" }}>🛡️</div>
          <h2 className="auth-title">Zero Trust Sign In</h2>
          <p style={{ color: "var(--text-secondary)", fontSize: "14px" }}>
            Sign in to start your secure session
          </p>
        </div>

        {error && (
          <div style={{ background: "rgba(239,68,68,0.1)", border: "1px solid var(--color-high)", color: "var(--color-high)", borderRadius: "8px", padding: "12px", marginBottom: "20px", fontSize: "14px" }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLoginSubmit}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input
              type="text"
              required
              className="form-input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter your username"
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

          <button
            type="submit"
            disabled={loading}
            className="btn btn-primary"
            style={{ width: "100%", marginTop: "10px", padding: "12px" }}
          >
            {loading ? "Signing In..." : "Sign In"}
          </button>
        </form>

        <div style={{ marginTop: "24px", textAlign: "center", fontSize: "14px", color: "var(--text-secondary)" }}>
          Don't have an account?{" "}
          <span
            onClick={onNavigateToRegister}
            style={{ color: "var(--accent-cyan)", cursor: "pointer", fontWeight: "600" }}
          >
            Sign Up
          </span>
        </div>
      </div>
    </div>
  );
};
