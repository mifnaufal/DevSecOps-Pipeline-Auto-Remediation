import Head from 'next/head';
import MetricCard from '../components/MetricCard';
import SeverityChart from '../components/SeverityChart';
import PipelineTimeline from '../components/PipelineTimeline';

export default function Home() {
  return (
    <>
      <Head>
        <title>DevSecOps Dashboard</title>
        <meta name="description" content="Security Pipeline Dashboard" />
      </Head>

      <main className="min-h-screen p-8">
        <div className="max-w-7xl mx-auto">
          <header className="mb-8">
            <h1 className="text-3xl font-bold text-gray-900">
              🔒 DevSecOps Auto-Remediation
            </h1>
            <p className="text-gray-600 mt-1">
              Security vulnerability detection and automated remediation pipeline
            </p>
          </header>

          {/* KPI Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            <MetricCard
              title="Total Scans"
              value="127"
              trend="+12%"
              trendDirection="up"
            />
            <MetricCard
              title="Open Findings"
              value="34"
              trend="-8%"
              trendDirection="down"
              variant="warning"
            />
            <MetricCard
              title="Fixes Applied"
              value="89"
              trend="+15%"
              trendDirection="up"
              variant="success"
            />
            <MetricCard
              title="Fix Accuracy"
              value="92%"
              trend="+2%"
              trendDirection="up"
              variant="success"
            />
          </div>

          {/* Charts Row */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">Severity Distribution</h2>
              <SeverityChart />
            </div>
            <div className="card">
              <h2 className="text-lg font-semibold mb-4">Pipeline Execution Timeline</h2>
              <PipelineTimeline />
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
