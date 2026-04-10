import { Finding } from '../lib/api';
import { severityColor, formatDate, truncateHash } from '../lib/utils';

interface FindingTableProps {
  findings: Finding[];
  onStatusChange?: (id: string, status: string) => void;
}

export default function FindingTable({ findings, onStatusChange }: FindingTableProps) {
  const statusOptions = ['new', 'confirmed', 'remediated', 'false_positive', 'accepted_risk'];

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-gray-200">
            <th className="text-left py-3 px-3 font-medium text-gray-500">Severity</th>
            <th className="text-left py-3 px-3 font-medium text-gray-500">Title</th>
            <th className="text-left py-3 px-3 font-medium text-gray-500">File</th>
            <th className="text-left py-3 px-3 font-medium text-gray-500">Scanner</th>
            <th className="text-left py-3 px-3 font-medium text-gray-500">CWE</th>
            <th className="text-left py-3 px-3 font-medium text-gray-500">Status</th>
            <th className="text-left py-3 px-3 font-medium text-gray-500">Date</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr key={f.id} className="border-b border-gray-100 hover:bg-gray-50">
              <td className="py-2 px-3">
                <span
                  className="badge text-xs"
                  style={{
                    backgroundColor: severityColor(f.severity) + '22',
                    color: severityColor(f.severity),
                  }}
                >
                  {f.severity.toUpperCase()}
                </span>
              </td>
              <td className="py-2 px-3 max-w-xs truncate" title={f.title}>
                {f.title}
              </td>
              <td className="py-2 px-3 font-mono text-xs">
                {f.file_path}:{f.start_line}
              </td>
              <td className="py-2 px-3 text-xs">{f.scanner}</td>
              <td className="py-2 px-3 font-mono text-xs">
                {f.cwe.map((c) => truncateHash(c, 7)).join(', ')}
              </td>
              <td className="py-2 px-3">
                {onStatusChange ? (
                  <select
                    className="text-xs border border-gray-300 rounded px-2 py-1"
                    value={f.status}
                    onChange={(e) => onStatusChange(f.id, e.target.value)}
                  >
                    {statusOptions.map((s) => (
                      <option key={s} value={s}>{s}</option>
                    ))}
                  </select>
                ) : (
                  <span className="badge bg-gray-100 text-gray-600 text-xs">{f.status}</span>
                )}
              </td>
              <td className="py-2 px-3 text-xs text-gray-500">
                {formatDate(f.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
