import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const sampleData = [
  { time: '10:00', duration: 45, status: 'success' },
  { time: '10:30', duration: 52, status: 'success' },
  { time: '11:00', duration: 38, status: 'success' },
  { time: '11:30', duration: 120, status: 'warning' },
  { time: '12:00', duration: 41, status: 'success' },
  { time: '12:30', duration: 0, status: 'failed' },
  { time: '13:00', duration: 44, status: 'success' },
];

export default function PipelineTimeline() {
  return (
    <ResponsiveContainer width="100%" height={250}>
      <LineChart data={sampleData}>
        <CartesianGrid strokeDasharray="3 3" />
        <XAxis dataKey="time" />
        <YAxis label={{ value: 'Duration (s)', angle: -90, position: 'insideLeft' }} />
        <Tooltip />
        <Line
          type="monotone"
          dataKey="duration"
          stroke="#3b82f6"
          strokeWidth={2}
          dot={{ r: 4 }}
        />
      </LineChart>
    </ResponsiveContainer>
  );
}
