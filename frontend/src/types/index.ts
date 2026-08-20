export interface Role {
  id: number;
  name: string;
}

export interface User {
  id: number;
  username: string;
  email: string;
  is_blocked: boolean;
  blocked_until?: string;
  organization_id: string;
  created_at: string;
  roles: Role[];
}

export interface Session {
  id: string;
  user_id: number;
  ip_address: string;
  user_agent?: string;
  is_active: boolean;
  created_at: string;
  expires_at: string;
}

export interface Device {
  id: number;
  user_id: number;
  device_fingerprint: string;
  is_trusted: boolean;
  last_used_at: string;
}

export interface SecurityEvent {
  id: number;
  user_id: number;
  session_id?: string;
  organization_id: string;
  event_type: string;
  severity: string;
  ip_address: string;
  device_info?: string;
  timestamp: string;
  previous_trust_score: number;
  score_change: number;
  new_trust_score: number;
  risk_level: string;
  action_taken: string;
  explainable_reason: string;
}

export interface ExplainableFactor {
  event: string;
  impact: number;
  reason: string;
}

export interface ExplainableTrustScore {
  trust_score: number;
  risk_level: string;
  decision: string;
  factors: ExplainableFactor[];
}

export interface ScoringRule {
  id: number;
  organization_id: string;
  event_type: string;
  score_impact: number;
  severity: string;
  is_enabled: boolean;
  repeated_threshold: number;
  time_window: number;
  recovery_delay: number;
  recovery_rate: number;
}

export interface AuditLog {
  id: number;
  actor_username: string;
  target_username?: string;
  action: string;
  ip_address?: string;
  reason?: string;
  timestamp: string;
}

export interface BankAccount {
  account_number: string;
  balance: number;
}

export interface BankTransaction {
  id: number;
  transaction_type: string;
  amount: number;
  description: string;
  timestamp: string;
}

export interface BankBeneficiary {
  id: number;
  name: string;
  account_number: string;
  bank_name: string;
}

export interface Threat {
  id: number;
  user_id: number;
  username: string;
  event_type: string;
  severity: string;
  description: string;
  is_resolved: boolean;
  timestamp: string;
}
