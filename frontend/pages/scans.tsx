import { useState } from 'react';
import Head from 'next/head';
import useSWR from 'swr';
import { api, Scan } from '../lib/api';

const fetcher = (url: string) => fetch(url).then((r) => r.json());

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const limit = 20;

  const { data: scans, error } = useSWR(
    `/api/v1/scans?limit=${limit}&page=${page}`,
    () => api.scans({ limit: String(limit), page: String(page) }),
    { refreshInterval: 30000 }
  );

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
            <a href="/" className="btn-primary">← Back to Dashboard</a>
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
                  <tr><td colSpan={7} className="text-center py-8 text-gray-500">No scans found</td></tr>
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
      </main>
    </>
  );
}
