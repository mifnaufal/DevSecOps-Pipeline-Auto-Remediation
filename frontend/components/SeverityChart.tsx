import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const sampleData = [
  { name: 'Critical', count: 8, fill: '#dc2626' },
  { name: 'High', count: 26, fill: '#ea580c' },
  { name: 'Medium', count: 45, fill: '#ca8a04' },
  { name: 'Low', count: 12, fill: '#16a34a' },
];

export default function SeverityChart() {
  return (
    <ResponsiveContainer width="100%" height={250}>
      <BarChart data={sampleData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="name" />
        <YAxis />
        <Tooltip />
        <Legend />
        <Bar dataKey="count" fill="#3b82f6" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
