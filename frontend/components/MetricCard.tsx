export default function MetricCard({
  title,
  value,
  trend,
  trendDirection,
  variant = 'default',
}: {
  title: string;
  value: string | number;
  trend?: string;
  trendDirection?: 'up' | 'down';
  variant?: 'default' | 'success' | 'warning' | 'error';
}) {
  const variantClasses = {
    default: 'border-l-4 border-blue-500',
    success: 'border-l-4 border-green-500',
    warning: 'border-l-4 border-yellow-500',
    error: 'border-l-4 border-red-500',
  };

  const trendColor = trendDirection === 'up' ? 'text-green-600' : 'text-red-600';

  return (
    <div className={`card ${variantClasses[variant]}`}>
      <h3 className="text-sm font-medium text-gray-500">{title}</h3>
      <p className="text-3xl font-bold mt-2">{value}</p>
      {trend && (
        <p className={`text-sm mt-1 ${trendColor}`}>
          {trendDirection === 'up' ? '↑' : '↓'} {trend} vs last week
        </p>
      )}
    </div>
  );
}
