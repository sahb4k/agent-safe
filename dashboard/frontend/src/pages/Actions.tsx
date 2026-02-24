import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useActions } from '../api/hooks'
import RiskBadge from '../components/RiskBadge'

export default function Actions() {
  const [tag, setTag] = useState('')
  const [risk, setRisk] = useState('')

  const params: Record<string, string> = {}
  if (tag) params.tag = tag
  if (risk) params.risk = risk

  const { data: actions, isLoading } = useActions(params)

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">Actions</h2>

      <div className="flex gap-3 mb-4">
        <select value={tag} onChange={(e) => setTag(e.target.value)} className="border rounded px-2 py-1 text-sm bg-white">
          <option value="">All tags</option>
          <option value="kubernetes">Kubernetes</option>
          <option value="aws">AWS</option>
        </select>
        <select value={risk} onChange={(e) => setRisk(e.target.value)} className="border rounded px-2 py-1 text-sm bg-white">
          <option value="">All risks</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {isLoading && <p className="text-gray-400">Loading...</p>}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {actions?.map((a) => (
          <Link
            key={a.name}
            to={`/actions/${a.name}`}
            className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 hover:shadow-md transition-shadow"
          >
            <div className="flex items-start justify-between">
              <h3 className="font-mono text-sm font-medium">{a.name}</h3>
              <RiskBadge risk={a.risk_class} />
            </div>
            <p className="text-xs text-gray-500 mt-2 line-clamp-2">{a.description}</p>
            <div className="flex gap-1.5 mt-3 flex-wrap">
              {a.tags.map((t) => (
                <span key={t} className="text-xs px-1.5 py-0.5 bg-blue-50 text-blue-700 rounded">{t}</span>
              ))}
              {a.reversible && (
                <span className="text-xs px-1.5 py-0.5 bg-green-50 text-green-700 rounded">reversible</span>
              )}
            </div>
          </Link>
        ))}
      </div>

      {actions && actions.length === 0 && (
        <p className="text-gray-400 text-center py-8">No actions match your filters</p>
      )}
    </div>
  )
}
