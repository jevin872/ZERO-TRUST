import axios from "axios";

// Configure base API URL (Vite environment variables or localhost fallback)
const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

// Ensure a persistent device fingerprint is generated for this browser session
let deviceFingerprint = localStorage.getItem("device_fingerprint");
if (!deviceFingerprint) {
  deviceFingerprint = "fp_" + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
  localStorage.setItem("device_fingerprint", deviceFingerprint);
}

export const getDeviceFingerprint = () => deviceFingerprint || "unknown_browser";

const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request Interceptor: Attach bearer token and device fingerprint header
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    config.headers["X-Device-Fingerprint"] = getDeviceFingerprint();
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Transparent Refresh-Token Rotation & Auth Eviction
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    
    // Check if error is 401 and we haven't retried yet
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      const refreshToken = localStorage.getItem("refresh_token");
      
      if (refreshToken) {
        try {
          // Attempt token refresh
          // Note: POST /auth/refresh takes token as a query parameter or body. Our auth API handles query param: POST /auth/refresh?refresh_token={token}
          const response = await axios.post(`${API_URL}/auth/refresh?refresh_token=${refreshToken}`);
          const { access_token } = response.data;
          
          localStorage.setItem("token", access_token);
          originalRequest.headers.Authorization = `Bearer ${access_token}`;
          
          return api(originalRequest);
        } catch (refreshError) {
          // Refresh token expired or invalid: evict user session
          localStorage.removeItem("token");
          localStorage.removeItem("refresh_token");
          localStorage.removeItem("user");
          window.location.reload();
        }
      }
    }
    return Promise.reject(error);
  }
);

export const setToken = (token: string) => {
  localStorage.setItem("token", token);
};

export default api;
