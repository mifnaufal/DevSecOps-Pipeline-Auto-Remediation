import Head from 'next/head';
import useSWR from 'swr';
import { api, MetricsSummary, Scan, Finding } from '../lib/api';
import MetricCard from '../components/MetricCard';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { LineChart, Line, ResponsiveContainer as RContainer, CartesianGrid as RCG, Tooltip as RTooltip, YAxis as RYAxis } from 'recharts';

export default function Home() {
  const { data: metrics, error: metricsErr } = useSWR(
    '/api/v1/metrics/summary',
    () => api.metrics(),
    { refreshInterval: 30000 }
  );

  const { data: scans } = useSWR(
    '/api/v1/scans?limit=10',
    () => api.scans({ limit: '10' }),
    { refreshInterval: 30000 }
  );

  const { data: findings } = useSWR(
    '/api/v1/findings',
    () => api.findings({}),
    { refreshInterval: 60000 }
  );

  // Compute severity breakdown from live findings
  const severityData = (findings || []).reduce((acc: Record<string, number>, f: Finding) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  const severityChartData = [
    { name: 'Critical', count: severityData['critical'] || 0, fill: '#dc2626' },
    { name: 'High', count: severityData['high'] || 0, fill: '#ea580c' },
    { name: 'Medium', count: severityData['medium'] || 0, fill: '#ca8a04' },
    { name: 'Low', count: severityData['low'] || 0, fill: '#16a34a' },
  ];

  // Build timeline data from scans
  const timelineData = (scans || [])
    .slice()
    .reverse()
    .map((s: Scan) => ({
      time: new Date(s.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      duration: s.duration_seconds || 0,
      status: s.status,
    }));

  return (
    <>
      <Head>
        <title>DevSecOps Dashboard</title>
        <meta name="description" content="Security Pipeline Dashboard" />
      </Head>

      <main className="min-h-screen p-8">
        <div className="max-w-7xl mx-auto">
          <header className="mb-8 flex justify-between items-center">
            <div>
              <h1 className="text-3xl font-bold text-gray-900">
                🔒 DevSecOps Auto-Remediation
              </h1>
              <p className="text-gray-600 mt-1">
                Security vulnerability detection and automated remediation pipeline
              </p>
            </div>
            <a href="/scans" className="btn-primary bg-green-600 hover:bg-green-700 text-white">
              ＋ New Scan
            </a>
          </header>

          {/* KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            {metricsErr ? (
              <>
                <MetricCard title="Total Scans" value="—" variant="error" />
                <MetricCard title="Open Findings" value="—" variant="error" />
                <MetricCard title="Fixes Applied" value="—" variant="error" />
                <MetricCard title="Fix Accuracy" value="—" variant="error" />
              </>
            ) : !metrics ? (
              <>
                <MetricCard title="Total Scans" value="..." />
                <MetricCard title="Open Findings" value="..." />
                <MetricCard title="Fixes Applied" value="..." />
                <MetricCard title="Fix Accuracy" value="..." />
              </>
            ) : (
              <>
                <MetricCard
                  title="Total Scans"
                  value={metrics.total_scans}
                />
                <MetricCard
                  title="Open Findings"
                  value={metrics.total_findings}
                  variant="warning"
                />
                <MetricCard
                  title="Fixes Applied"
                  value={metrics.total_fixes}
                  variant="success"
                />
                <MetricCard
                  title="Fix Accuracy"
                  value={`${Math.round(metrics.avg_fix_accuracy_rate)}%`}
                  variant="success"
                />
              </>
            )}
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">Severity Distribution</h2>
              {findings && findings.length > 0 ? (
                <ResponsiveContainer width="100%" height={250}>
                  <BarChart data={severityChartData}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="name" />
                    <YAxis />
                    <Tooltip />
                    <Legend />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {severityChartData.map((entry, i) => (
                        <Bar key={i} dataKey="count" fill={entry.fill} radius={[4, 4, 0, 0]} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <p className="text-gray-400 text-center py-8">No findings data yet</p>
              )}
            </div>
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">Pipeline Execution Timeline</h2>
              {timelineData.length > 0 ? (
                <RContainer width="100%" height={250}>
                  <LineChart data={timelineData}>
                    <RCG strokeDasharray="3 3" />
                    <XAxis dataKey="time" />
                    <RYAxis label={{ value: 'Duration (s)', angle: -90, position: 'insideLeft' }} />
                    <RTooltip />
                    <Line
                      type="monotone"
                      dataKey="duration"
                      stroke="#3b82f6"
                      strokeWidth={2}
                      dot={{ r: 4 }}
                    />
                  </LineChart>
                </RContainer>
              ) : (
                <p className="text-gray-400 text-center py-8">No scan data yet</p>
              )}
            </div>
          </div>

          {/* Quick Links */}
          <div className="card">
            <h2 className="text-lg font-semibold mb-4">Quick Links</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <a href="/scans" className="btn-primary text-center">
                View Scans
              </a>
              <a href="/findings" className="btn-primary text-center">
                Explore Findings
              </a>
              <a href="http://localhost:9090" target="_blank" rel="noopener noreferrer" className="btn-primary text-center">
                Prometheus
              </a>
              <a href="http://localhost:3001" target="_blank" rel="noopener noreferrer" className="btn-primary text-center">
                Grafana
              </a>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}
