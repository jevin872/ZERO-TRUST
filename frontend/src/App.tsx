import React, { useState, useEffect } from "react";
import api, { setToken, getDeviceFingerprint } from "./services/api";
import { User } from "./types";
import { Register } from "./pages/Register";
import { Login } from "./pages/Login";
import { BankWebsite } from "./pages/BankWebsite";
import { ZeroTrustXAdmin } from "./pages/ZeroTrustXAdmin";
import { Landmark, ShieldAlert, LogOut, ChevronLeft } from "lucide-react";

export const App: React.FC = () => {
  const [portal, setPortal] = useState<"gate" | "bank" | "soc">("gate");
  const [user, setUser] = useState<User | null>(null);
  const [authView, setAuthView] = useState<"login" | "register">("login");
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState("");

  // Attempt to restore session on boot
  useEffect(() => {
    const token = localStorage.getItem("access_token");
    if (token) {
      setToken(token);
      api.get("/users/me")
        .then((res) => {
          setUser(res.data);
          // Auto-route based on roles
          const isAdmin = res.data.roles.some((r: any) => r.name === "ADMIN");
          if (isAdmin) {
            setPortal("soc");
          } else {
            setPortal("bank");
          }
        })
        .catch(() => {
          handleLogout();
        })
        .finally(() => setLoading(false));
    } else {
      setLoading(false);
    }
  }, []);

  const handleLoginSuccess = (userData: User, accessToken: string) => {
    setUser(userData);
    setToken(accessToken);
    localStorage.setItem("access_token", accessToken);
    setErrorMessage("");

    const isAdmin = userData.roles.some((r: any) => r.name === "ADMIN");
    if (portal === "soc" && !isAdmin) {
      // Reject standard user logging into SOC console
      setErrorMessage("Access Denied: Administrative security privileges required.");
      handleLogout();
      return;
    }

    if (isAdmin) {
      setPortal("soc");
    } else {
      setPortal("bank");
    }
  };

  const handleLogout = () => {
    setUser(null);
    setToken("");
    localStorage.removeItem("access_token");
    setPortal("gate");
    setAuthView("login");
  };

  if (loading) {
    return (
      <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100vh", background: "var(--bg-primary)" }}>
        <p style={{ color: "var(--text-secondary)" }}>Configuring Zero Trust handshake...</p>
      </div>
    );
  }

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      
      {/* Dynamic Global Navbar */}
      <header className="navbar">
        <div style={{ display: "flex", alignItems: "center", gap: "10px", cursor: "pointer" }} onClick={handleLogout}>
          <ShieldAlert className="glow-logo" size={24} style={{ color: "var(--accent-purple)" }} />
          <h1 className="nav-logo">ZeroTrustX Secure Bank</h1>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          {portal !== "gate" && (
            <button onClick={handleLogout} className="btn btn-secondary" style={{ display: "flex", alignItems: "center", gap: "8px", padding: "6px 12px", fontSize: "13px" }}>
              <ChevronLeft size={14} /> Back to Hub
            </button>
          )}

          {user && (
            <div style={{ display: "flex", alignItems: "center", gap: "14px" }}>
              <span style={{ fontSize: "14px", color: "var(--text-secondary)" }}>
                Logged in: <strong>{user.username}</strong>
              </span>
              <button onClick={handleLogout} className="btn btn-danger" style={{ display: "flex", alignItems: "center", gap: "6px", padding: "6px 12px" }}>
                <LogOut size={14} /> Exit Session
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Main Portals Router */}
      <main style={{ flex: 1 }}>
        {portal === "gate" && (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", minHeight: "75vh", padding: "20px" }}>
            <div style={{ textAlign: "center", marginBottom: "40px" }}>
              <h2 style={{ fontSize: "36px", fontWeight: "800", background: "linear-gradient(135deg, white, #9ca3af)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent" }}>
                ZeroTrustX Simulation Platform
              </h2>
              <p style={{ color: "var(--text-secondary)", marginTop: "10px" }}>
                Select a user role gateway to interact with continuous authentication policies.
              </p>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "30px", maxWidth: "900px", width: "100%" }} className="mobile-col-12">
              
              {/* BANK CLIENT PANEL */}
              <div 
                className="glass-card hover-glow" 
                style={{ cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", padding: "40px 30px", border: "1px solid rgba(255,255,255,0.06)", transition: "all 0.3s ease" }}
                onClick={() => {
                  setPortal("bank");
                  setAuthView("login");
                  setErrorMessage("");
                }}
              >
                <div style={{ background: "rgba(2,132,199,0.1)", borderRadius: "50%", padding: "20px", color: "#0284c7", marginBottom: "20px" }}>
                  <Landmark size={48} />
                </div>
                <h3>Consumer Banking Website</h3>
                <p style={{ color: "var(--text-secondary)", fontSize: "14px", textAlign: "center", marginTop: "10px" }}>
                  Simulate client-side balance inquiries, beneficiaries, and transactions. Actions trigger real-time security events.
                </p>
              </div>

              {/* SECURITY SOC PANEL */}
              <div 
                className="glass-card hover-glow" 
                style={{ cursor: "pointer", display: "flex", flexDirection: "column", alignItems: "center", padding: "40px 30px", border: "1px solid rgba(139,92,246,0.15)", transition: "all 0.3s ease" }}
                onClick={() => {
                  setPortal("soc");
                  setAuthView("login");
                  setErrorMessage("");
                }}
              >
                <div style={{ background: "rgba(139,92,246,0.1)", borderRadius: "50%", padding: "20px", color: "var(--accent-purple)", marginBottom: "20px" }}>
                  <ShieldAlert size={48} />
                </div>
                <h3>SOC Administrator Dashboard</h3>
                <p style={{ color: "var(--text-secondary)", fontSize: "14px", textAlign: "center", marginTop: "10px" }}>
                  View real-time event logs, dynamic trust timeline graphs, resolve threat flags, and configure policy thresholds.
                </p>
              </div>

            </div>
          </div>
        )}

        {/* BANK CLIENT ROUTER */}
        {portal === "bank" && (
          <>
            {!user ? (
              authView === "login" ? (
                <Login 
                  onLoginSuccess={handleLoginSuccess} 
                  onNavigateToRegister={() => setAuthView("register")} 
                />
              ) : (
                <Register 
                  onNavigateToLogin={() => setAuthView("login")} 
                />
              )
            ) : (
              <BankWebsite user={user} onLogout={handleLogout} />
            )}
          </>
        )}

        {/* ADMIN SOC ROUTER */}
        {portal === "soc" && (
          <>
            {!user ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center" }}>
                {errorMessage && (
                  <div style={{ maxWidth: "420px", background: "rgba(239,68,68,0.1)", border: "1px solid var(--color-high)", color: "var(--color-high)", borderRadius: "8px", padding: "12px", marginTop: "30px", fontSize: "14px", textAlign: "center" }}>
                    {errorMessage}
                  </div>
                )}
                <Login 
                  onLoginSuccess={handleLoginSuccess} 
                  onNavigateToRegister={() => setPortal("gate")} 
                />
              </div>
            ) : (
              <ZeroTrustXAdmin />
            )}
          </>
        )}
      </main>

      {/* Footer */}
      <footer style={{ borderTop: "1px solid var(--border-light)", padding: "16px 20px", textAlign: "center", fontSize: "12px", color: "var(--text-muted)" }}>
        ZeroTrustX cybersecurity laboratory research platform. Powered by FastAPI, WebSockets & React.
      </footer>

    </div>
  );
};
export default App;
