const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

export interface Scan {
  id: string;
  repository: string;
  commit_sha: string;
  branch: string;
  trigger_type: string;
  scan_type: string;
  tool: string;
  status: string;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  started_at: string;
  completed_at: string;
  duration_seconds: number;
  target_path?: string;
  message?: string;
}

export interface ScanCreateRequest {
  repository: string;
  branch: string;
  commit_sha?: string;
  tool: string;
  scan_type?: string;
  trigger_type?: string;
  target_path?: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  scanner: string;
  rule_id: string;
  cwe: string[];
  cve: string[];
  title: string;
  description: string;
  severity: string;
  confidence: string;
  file_path: string;
  start_line: number;
  end_line: number;
  code_snippet: string;
  remediable: boolean;
  remediation_hint: string;
  status: string;
  created_at: string;
}

export interface Fix {
  id: string;
  finding_id: string;
  codemod_name: string;
  file_path: string;
  original_code: string;
  fixed_code: string;
  status: string;
  validation_passed: boolean;
  rescan_passed: boolean;
  pr_url: string;
  error: string;
  applied_at: string;
}

export interface MetricsSummary {
  total_scans: number;
  avg_duration_sec: number;
  avg_fix_accuracy_rate: number;
  avg_false_positive_rate: number;
  total_findings: number;
  total_fixes: number;
  compliant_scans: number;
}

async function request<T>(path: string, params?: Record<string, string>): Promise<T> {
  const url = new URL(`${API_URL}${path}`);
  if (params) {
    Object.entries(params).forEach(([k, v]) => url.searchParams.set(k, v));
  }

  const res = await fetch(url.toString(), {
    headers: { 'Content-Type': 'application/json' },
  });

  if (!res.ok) {
    throw new Error(`API error: ${res.status} ${res.statusText}`);
  }

  return res.json() as Promise<T>;
}

export const api = {
  scans: (params?: { limit?: string; page?: string }) =>
    request<Scan[]>('/api/v1/scans', params as Record<string, string>),

  scan: (id: string) =>
    request<Scan>(`/api/v1/scans/${id}`),

  createScan: async (data: ScanCreateRequest) => {
    const res = await fetch(`${API_URL}/api/v1/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(`Failed to create scan: ${res.status} ${text}`);
    }
    return res.json() as Promise<Scan>;
  },

  findings: (params?: { severity?: string; status?: string; scanner?: string }) =>
    request<Finding[]>('/api/v1/findings', params as Record<string, string>),

  finding: (id: string) =>
    request<Finding>(`/api/v1/findings/${id}`),

  updateFindingStatus: async (id: string, status: string) => {
    const res = await fetch(`${API_URL}/api/v1/findings/${id}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) throw new Error(`Failed to update status: ${res.status}`);
    return res.json();
  },

  fixes: () =>
    request<Fix[]>('/api/v1/fixes'),

  metrics: () =>
    request<MetricsSummary>('/api/v1/metrics/summary'),

  health: () =>
    request<{ status: string; timestamp: string }>('/api/v1/health'),
};
