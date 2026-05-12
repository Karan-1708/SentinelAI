import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Cell,
  ResponsiveContainer,
} from 'recharts'

interface ShapFeature {
  feature: string
  shap_value: number
  feature_value?: number
}

interface Props {
  features: ShapFeature[]
  maxDisplay?: number
}

export default function ShapWaterfallChart({ features, maxDisplay = 15 }: Props) {
  const sorted = [...features]
    .sort((a, b) => Math.abs(b.shap_value) - Math.abs(a.shap_value))
    .slice(0, maxDisplay)

  return (
    <div className="w-full">
      <h3 className="text-sm font-semibold text-slate-300 mb-2">
        SHAP Feature Contributions
      </h3>
      <p className="text-xs text-slate-500 mb-3">
        Red → pushes toward attack classification. Blue → pushes toward benign.
      </p>
      <ResponsiveContainer width="100%" height={Math.max(200, sorted.length * 28)}>
        <BarChart
          layout="vertical"
          data={sorted}
          margin={{ top: 0, right: 30, bottom: 0, left: 140 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
          <XAxis
            type="number"
            stroke="#475569"
            tick={{ fontSize: 10, fill: '#94a3b8' }}
            label={{ value: 'SHAP value', position: 'insideBottom', offset: -5, fill: '#64748b', fontSize: 10 }}
          />
          <YAxis
            type="category"
            dataKey="feature"
            width={135}
            tick={{ fontSize: 10, fill: '#94a3b8' }}
          />
          <Tooltip
            content={({ payload }) => {
              if (!payload?.length) return null
              const d = payload[0].payload as ShapFeature
              return (
                <div className="bg-slate-800 border border-slate-600 rounded p-2 text-xs">
                  <p className="text-slate-200 font-semibold">{d.feature}</p>
                  <p className="text-slate-400">SHAP: {d.shap_value.toFixed(4)}</p>
                  {d.feature_value !== undefined && (
                    <p className="text-slate-400">Value: {d.feature_value.toFixed(2)}</p>
                  )}
                </div>
              )
            }}
          />
          <Bar dataKey="shap_value" radius={[0, 2, 2, 0]}>
            {sorted.map((entry, index) => (
              <Cell
                key={index}
                fill={entry.shap_value > 0 ? '#dc2626' : '#2563eb'}
              />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
