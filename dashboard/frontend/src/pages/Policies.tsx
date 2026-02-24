import { useState } from 'react'
import { usePolicies, useMatchAnalysis } from '../api/hooks'
import StatusBadge from '../components/StatusBadge'

export default function Policies() {
  const { data: policies } = usePolicies()
  const { data: analysis } = useMatchAnalysis()
  const [showAnalysis, setShowAnalysis] = useState(false)

  const matchMap = new Map(analysis?.map((a) => [a.rule_name, a]) ?? [])

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold">Policies</h2>
        <button
          onClick={() => setShowAnalysis(!showAnalysis)}
          className="text-sm px-3 py-1 border rounded hover:bg-gray-100"
        >
          {showAnalysis ? 'Hide' : 'Show'} match analysis
        </button>
      </div>

      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
            <tr>
              <th className="px-4 py-2 text-left">Priority</th>
              <th className="px-4 py-2 text-left">Name</th>
              <th className="px-4 py-2 text-left">Decision</th>
              <th className="px-4 py-2 text-left">Actions</th>
              <th className="px-4 py-2 text-left">Environments</th>
              {showAnalysis && <th className="px-4 py-2 text-left">Matching Targets</th>}
              <th className="px-4 py-2 text-left">Reason</th>
            </tr>
          </thead>
          <tbody>
            {policies?.map((r) => {
              const match = matchMap.get(r.name)
              return (
                <tr key={r.name} className="border-t border-gray-50 hover:bg-gray-50">
                  <td className="px-4 py-2 font-mono">{r.priority}</td>
                  <td className="px-4 py-2 font-medium">{r.name}</td>
                  <td className="px-4 py-2"><StatusBadge decision={r.decision} /></td>
                  <td className="px-4 py-2 font-mono text-xs">
                    {r.match_actions.length > 2
                      ? `${r.match_actions.slice(0, 2).join(', ')} +${r.match_actions.length - 2}`
                      : r.match_actions.join(', ')}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {r.match_environments?.join(', ') ?? 'all'}
                  </td>
                  {showAnalysis && (
                    <td className="px-4 py-2 text-xs">
                      {match ? (
                        <span className={match.matching_target_count > 0 ? 'text-blue-600 font-medium' : 'text-gray-400'}>
                          {match.matching_target_count} target{match.matching_target_count !== 1 ? 's' : ''}
                        </span>
                      ) : '—'}
                    </td>
                  )}
                  <td className="px-4 py-2 text-xs text-gray-500">{r.reason}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
