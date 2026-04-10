import { useState } from 'react';
import Head from 'next/head';
import useSWR from 'swr';
import { api, Scan, ScanCreateRequest } from '../lib/api';

const fetcher = (url: string) => fetch(url).then((r) => r.json());

const TOOLS = ['semgrep', 'trivy', 'zap', 'nuclei', 'custom'] as const;
const SCAN_TYPES = ['sast', 'sca', 'dast', 'secrets', 'iac', 'custom'] as const;
const TRIGGERS = ['manual', 'push', 'pull_request', 'schedule'] as const;

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const limit = 20;

  // Modal state
  const [showModal, setShowModal] = useState(false);
  const [form, setForm] = useState<ScanCreateRequest>({
    repository: '',
    branch: '',
    tool: 'semgrep',
    scan_type: 'sast',
    trigger_type: 'manual',
    commit_sha: '',
    target_path: '',
  });
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState('');
  const [formSuccess, setFormSuccess] = useState('');

  const { data: scans, error, mutate } = useSWR(
    `/api/v1/scans?limit=${limit}&page=${page}`,
    () => api.scans({ limit: String(limit), page: String(page) }),
    { refreshInterval: 30000 }
  );

  const handleCreateScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError('');
    setFormSuccess('');

    if (!form.repository || !form.branch || !form.tool) {
      setFormError('Repository, Branch, and Tool are required.');
      return;
    }

    setSubmitting(true);
    try {
      const result = await api.createScan(form);
      setFormSuccess(`Scan created! ID: ${result.id}`);
      setForm({
        repository: '',
        branch: '',
        tool: 'semgrep',
        scan_type: 'sast',
        trigger_type: 'manual',
        commit_sha: '',
        target_path: '',
      });
      mutate(); // refresh the scan list
      setTimeout(() => {
        setShowModal(false);
        setFormSuccess('');
      }, 2000);
    } catch (err: any) {
      setFormError(err.message || 'Failed to create scan');
    } finally {
      setSubmitting(false);
    }
  };

  const severityBadge = (count: number, label: string, color: string) => (
    <span className={`badge`} style={{ backgroundColor: color + '22', color }}>
      {label}: {count}
    </span>
  );

  const statusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'bg-green-100 text-green-800';
      case 'running': return 'bg-blue-100 text-blue-800';
      case 'failed': return 'bg-red-100 text-red-800';
      case 'queued': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <>
      <Head><title>Scans — DevSecOps Dashboard</title></Head>
      <main className="min-h-screen p-8">
        <div className="max-w-7xl mx-auto">
          <header className="mb-8 flex justify-between items-center">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">Scan History</h1>
              <p className="text-gray-600 mt-1">All security scan executions</p>
            </div>
            <div className="flex gap-3">
              <button
                className="btn-primary bg-green-600 hover:bg-green-700 text-white"
                onClick={() => setShowModal(true)}
              >
                ＋ New Scan
              </button>
              <a href="/" className="btn-primary">← Back to Dashboard</a>
            </div>
          </header>

          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
              <p className="text-red-700">Failed to load scans. Is the API server running?</p>
            </div>
          )}

          <div className="card">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-200">
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Status</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Tool</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Repository</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Branch</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Findings</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Duration</th>
                  <th className="text-left py-3 px-4 text-sm font-medium text-gray-500">Started</th>
                </tr>
              </thead>
              <tbody>
                {!scans ? (
                  <tr><td colSpan={7} className="text-center py-8 text-gray-500">Loading...</td></tr>
                ) : scans.length === 0 ? (
                  <tr><td colSpan={7} className="text-center py-8 text-gray-500">No scans found. Click &quot;New Scan&quot; to start one.</td></tr>
                ) : (
                  scans.map((scan: Scan) => (
                    <tr key={scan.id} className="border-b border-gray-100 hover:bg-gray-50">
                      <td className="py-3 px-4">
                        <span className={`badge ${statusColor(scan.status)}`}>{scan.status}</span>
                      </td>
                      <td className="py-3 px-4 text-sm font-mono">{scan.tool}</td>
                      <td className="py-3 px-4 text-sm">{scan.repository}</td>
                      <td className="py-3 px-4 text-sm font-mono">{scan.branch}</td>
                      <td className="py-3 px-4">
                        <div className="flex gap-1 flex-wrap">
                          {severityBadge(scan.critical_count, 'C', '#dc2626')}
                          {severityBadge(scan.high_count, 'H', '#ea580c')}
                          {severityBadge(scan.medium_count, 'M', '#ca8a04')}
                          {severityBadge(scan.low_count, 'L', '#16a34a')}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-sm">{scan.duration_seconds}s</td>
                      <td className="py-3 px-4 text-sm text-gray-500">
                        {new Date(scan.started_at).toLocaleString()}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>

            {/* Pagination */}
            <div className="flex justify-between items-center mt-4 pt-4 border-t">
              <button
                className="btn-primary disabled:opacity-50"
                disabled={page <= 1}
                onClick={() => setPage(p => p - 1)}
              >
                ← Previous
              </button>
              <span className="text-sm text-gray-500">Page {page}</span>
              <button
                className="btn-primary disabled:opacity-50"
                disabled={!scans || scans.length < limit}
                onClick={() => setPage(p => p + 1)}
              >
                Next →
              </button>
            </div>
          </div>
        </div>

        {/* New Scan Modal */}
        {showModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
            <div className="bg-white rounded-xl shadow-2xl w-full max-w-lg p-6 mx-4">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-bold text-gray-900">Start New Scan</h2>
                <button
                  className="text-gray-400 hover:text-gray-600 text-2xl leading-none"
                  onClick={() => { setShowModal(false); setFormError(''); }}
                >
                  ×
                </button>
              </div>

              <form onSubmit={handleCreateScan}>
                {formError && (
                  <div className="bg-red-50 border border-red-200 rounded-lg p-3 mb-4">
                    <p className="text-red-700 text-sm">{formError}</p>
                  </div>
                )}
                {formSuccess && (
                  <div className="bg-green-50 border border-green-200 rounded-lg p-3 mb-4">
                    <p className="text-green-700 text-sm">{formSuccess}</p>
                  </div>
                )}

                <div className="space-y-4">
                  {/* Repository */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Repository <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="owner/repo or /path/to/code"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                      value={form.repository}
                      onChange={e => setForm({ ...form, repository: e.target.value })}
                    />
                  </div>

                  {/* Branch */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Branch <span className="text-red-500">*</span>
                    </label>
                    <input
                      type="text"
                      required
                      placeholder="main"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                      value={form.branch}
                      onChange={e => setForm({ ...form, branch: e.target.value })}
                    />
                  </div>

                  {/* Commit SHA */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Commit SHA <span className="text-gray-400">(optional)</span>
                    </label>
                    <input
                      type="text"
                      placeholder="abc123..."
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm font-mono"
                      value={form.commit_sha}
                      onChange={e => setForm({ ...form, commit_sha: e.target.value })}
                    />
                  </div>

                  {/* Target Path */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Target Path / URL <span className="text-gray-400">(optional)</span>
                    </label>
                    <input
                      type="text"
                      placeholder="/app/src or https://example.com"
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                      value={form.target_path}
                      onChange={e => setForm({ ...form, target_path: e.target.value })}
                    />
                  </div>

                  {/* Tool */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Tool <span className="text-red-500">*</span>
                    </label>
                    <select
                      required
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                      value={form.tool}
                      onChange={e => setForm({ ...form, tool: e.target.value })}
                    >
                      {TOOLS.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>

                  {/* Scan Type */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Scan Type
                    </label>
                    <select
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                      value={form.scan_type}
                      onChange={e => setForm({ ...form, scan_type: e.target.value as any })}
                    >
                      {SCAN_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>

                  {/* Trigger */}
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Trigger
                    </label>
                    <select
                      className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent text-sm"
                      value={form.trigger_type}
                      onChange={e => setForm({ ...form, trigger_type: e.target.value as any })}
                    >
                      {TRIGGERS.map(t => <option key={t} value={t}>{t}</option>)}
                    </select>
                  </div>
                </div>

                {/* Buttons */}
                <div className="flex gap-3 mt-6">
                  <button
                    type="submit"
                    disabled={submitting}
                    className="flex-1 bg-green-600 hover:bg-green-700 disabled:bg-green-300 text-white font-medium py-2 px-4 rounded-lg transition"
                  >
                    {submitting ? 'Creating...' : 'Start Scan'}
                  </button>
                  <button
                    type="button"
                    disabled={submitting}
                    className="flex-1 bg-gray-200 hover:bg-gray-300 disabled:bg-gray-100 text-gray-800 font-medium py-2 px-4 rounded-lg transition"
                    onClick={() => { setShowModal(false); setFormError(''); }}
                  >
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}
      </main>
    </>
  );
}
