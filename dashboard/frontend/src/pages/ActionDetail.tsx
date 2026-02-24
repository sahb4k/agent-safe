import { useParams, Link } from 'react-router-dom'
import { useActionDetail } from '../api/hooks'
import RiskBadge from '../components/RiskBadge'

export default function ActionDetail() {
  const { name } = useParams<{ name: string }>()
  const { data: action, isLoading } = useActionDetail(name ?? '')

  if (isLoading) return <p className="text-gray-400">Loading...</p>
  if (!action) return <p className="text-gray-400">Action not found</p>

  return (
    <div>
      <Link to="/actions" className="text-sm text-blue-600 hover:underline">&larr; All Actions</Link>

      <div className="mt-3 flex items-center gap-3">
        <h2 className="text-xl font-semibold font-mono">{action.name}</h2>
        <RiskBadge risk={action.risk_class} />
        <span className="text-xs text-gray-400">v{action.version}</span>
      </div>

      <p className="text-gray-600 mt-2">{action.description}</p>

      {/* Tags */}
      <div className="flex gap-1.5 mt-3">
        {action.tags.map((t) => (
          <span key={t} className="text-xs px-2 py-0.5 bg-blue-50 text-blue-700 rounded">{t}</span>
        ))}
        {action.reversible && (
          <span className="text-xs px-2 py-0.5 bg-green-50 text-green-700 rounded">
            reversible &rarr; {action.rollback_action}
          </span>
        )}
      </div>

      {/* Parameters */}
      <div className="mt-6">
        <h3 className="text-sm font-medium text-gray-500 mb-2">Parameters</h3>
        <div className="bg-white rounded-lg shadow-sm border border-gray-200">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
              <tr>
                <th className="px-4 py-2 text-left">Name</th>
                <th className="px-4 py-2 text-left">Type</th>
                <th className="px-4 py-2 text-left">Required</th>
                <th className="px-4 py-2 text-left">Description</th>
              </tr>
            </thead>
            <tbody>
              {action.parameters.map((p) => (
                <tr key={p.name} className="border-t border-gray-50">
                  <td className="px-4 py-2 font-mono text-xs">{p.name}</td>
                  <td className="px-4 py-2 text-xs">{p.type}</td>
                  <td className="px-4 py-2 text-xs">{p.required ? 'yes' : 'no'}</td>
                  <td className="px-4 py-2 text-xs text-gray-500">{p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Target types */}
      <div className="mt-6">
        <h3 className="text-sm font-medium text-gray-500 mb-2">Target Types</h3>
        <div className="flex gap-2">
          {action.target_types.map((t) => (
            <span key={t} className="text-xs px-2 py-1 bg-gray-100 rounded font-mono">{t}</span>
          ))}
        </div>
      </div>

      {/* Prechecks */}
      {action.prechecks.length > 0 && (
        <div className="mt-6">
          <h3 className="text-sm font-medium text-gray-500 mb-2">Prechecks</h3>
          <ul className="space-y-1">
            {action.prechecks.map((pc) => (
              <li key={pc.name} className="text-sm bg-white border rounded px-3 py-2">
                <span className="font-medium">{pc.name}</span>
                <span className="text-gray-500 ml-2">{pc.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Credentials */}
      {action.credentials && (
        <div className="mt-6">
          <h3 className="text-sm font-medium text-gray-500 mb-2">Credentials</h3>
          <pre className="text-xs bg-gray-800 text-gray-100 rounded p-3 overflow-auto">
            {JSON.stringify(action.credentials, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
