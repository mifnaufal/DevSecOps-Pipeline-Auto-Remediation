import { useState } from 'react';
import Head from 'next/head';
import useSWR from 'swr';
import { api, Finding } from '../lib/api';

export default function FindingsPage() {
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const { data: findings, error } = useSWR(
    `/api/v1/findings?severity=${severity}&status=${status}`,
    () => api.findings({ severity: severity || undefined, status: status || undefined }),
    { refreshInterval: 30000 }
  );

  const severityColor = (sev: string) => {
    switch (sev) {
      case 'critical': return 'badge-critical';
      case 'high': return 'badge-high';
      case 'medium': return 'badge-medium';
      case 'low': return 'badge-low';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const statusActions = ['new', 'confirmed', 'remediated', 'false_positive', 'accepted_risk'];

  const handleStatusChange = async (id: string, newStatus: string) => {
    try {
      await api.updateFindingStatus(id, newStatus);
      // SWR will refetch automatically
      window.location.reload();
    } catch (e) {
      alert('Failed to update status');
    }
  };

  return (
    <>
      <Head><title>Findings — DevSecOps Dashboard</title></Head>
      <main className="min-h-screen p-8">
        <div className="max-w-7xl mx-auto">
          <header className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900">Security Findings</h1>
            <p className="text-gray-600 mt-1">Detected vulnerabilities with remediation status</p>
          </header>

          {/* Filters */}
          <div className="card mb-6">
            <div className="flex gap-4 flex-wrap">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Severity</label>
                <select
                  className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value)}
                >
                  <option value="">All</option>
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">Status</label>
                <select
                  className="border border-gray-300 rounded-md px-3 py-2 text-sm"
                  value={status}
                  onChange={(e) => setStatus(e.target.value)}
                >
                  <option value="">All</option>
                  <option value="new">New</option>
                  <option value="confirmed">Confirmed</option>
                  <option value="remediated">Remediated</option>
                  <option value="false_positive">False Positive</option>
                  <option value="accepted_risk">Accepted Risk</option>
                </select>
              </div>
              <div className="ml-auto self-end">
                <a href="/" className="btn-primary">← Back to Dashboard</a>
              </div>
            </div>
          </div>

          {/* Findings Table */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
              <p className="text-red-700">Failed to load findings. Is the API server running?</p>
            </div>
          )}

          <div className="card">
            {!findings ? (
              <p className="text-center py-8 text-gray-500">Loading...</p>
            ) : findings.length === 0 ? (
              <p className="text-center py-8 text-gray-500">No findings match your filters</p>
            ) : (
              <div className="space-y-3">
                {findings.map((f: Finding) => (
                  <div key={f.id} className="border border-gray-200 rounded-lg overflow-hidden">
                    {/* Summary Row */}
                    <div
                      className="p-4 bg-white hover:bg-gray-50 cursor-pointer flex items-center gap-4"
                      onClick={() => setExpandedId(expandedId === f.id ? null : f.id)}
                    >
                      <span className={`badge ${severityColor(f.severity)}`}>
                        {f.severity.toUpperCase()}
                      </span>
                      <span className="text-sm font-mono text-gray-500 w-24 truncate">
                        {f.scanner}
                      </span>
                      <span className="flex-1 text-sm font-medium truncate">{f.title}</span>
                      <span className="text-sm text-gray-500 font-mono">
                        {f.file_path}:{f.start_line}
                      </span>
                      <span className="badge bg-gray-100 text-gray-600">{f.status}</span>
                      <span className="text-gray-400">{expandedId === f.id ? '▼' : '▶'}</span>
                    </div>

                    {/* Expanded Details */}
                    {expandedId === f.id && (
                      <div className="p-4 bg-gray-50 border-t border-gray-200">
                        <div className="grid grid-cols-2 gap-4 mb-4">
                          <div>
                            <span className="text-xs font-medium text-gray-500 uppercase">Rule ID</span>
                            <p className="text-sm font-mono">{f.rule_id}</p>
                          </div>
                          <div>
                            <span className="text-xs font-medium text-gray-500 uppercase">CWE</span>
                            <p className="text-sm font-mono">{f.cwe.join(', ') || 'N/A'}</p>
                          </div>
                          <div>
                            <span className="text-xs font-medium text-gray-500 uppercase">Confidence</span>
                            <p className="text-sm">{f.confidence}</p>
                          </div>
                          <div>
                            <span className="text-xs font-medium text-gray-500 uppercase">Remediable</span>
                            <p className="text-sm">{f.remediiable !== false ? '✅ Yes' : '❌ No'}</p>
                          </div>
                        </div>

                        {f.remediation_hint && (
                          <div className="bg-blue-50 border border-blue-200 rounded p-3 mb-3">
                            <span className="text-xs font-medium text-blue-700">💡 Remediation Hint</span>
                            <p className="text-sm text-blue-800 mt-1">{f.remediation_hint}</p>
                          </div>
                        )}

                        {f.code_snippet && (
                          <div className="mb-3">
                            <span className="text-xs font-medium text-gray-500 uppercase">Code Snippet</span>
                            <pre className="bg-gray-900 text-green-400 p-3 rounded text-xs overflow-x-auto mt-1">
                              {f.code_snippet}
                            </pre>
                          </div>
                        )}

                        {/* Status Actions */}
                        <div className="flex gap-2">
                          <span className="text-xs text-gray-500 self-center mr-2">Update Status:</span>
                          {statusActions.map((s) => (
                            <button
                              key={s}
                              className={`text-xs px-2 py-1 rounded border ${
                                f.status === s
                                  ? 'bg-blue-600 text-white border-blue-600'
                                  : 'bg-white text-gray-700 border-gray-300 hover:bg-gray-100'
                              }`}
                              onClick={() => handleStatusChange(f.id, s)}
                            >
                              {s}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}

            <div className="mt-4 pt-4 border-t text-sm text-gray-500">
              Total: {findings?.length || 0} findings
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
