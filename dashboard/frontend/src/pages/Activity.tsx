import { useActivityFeed } from '../api/hooks'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'

export default function Activity() {
  const { data: feed, isLoading } = useActivityFeed(100)

  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-xl font-semibold">Activity Feed</h2>
        <span className="text-xs text-gray-400">Auto-refreshes every 5s</span>
      </div>

      {isLoading && <p className="text-gray-400">Loading...</p>}

      <div className="space-y-2">
        {feed?.map((e) => (
          <div
            key={e.event_id}
            className="bg-white rounded-lg shadow-sm border border-gray-200 px-4 py-3 flex items-center gap-4"
          >
            <span className="text-xs text-gray-400 w-36 shrink-0">
              {new Date(e.timestamp).toLocaleString()}
            </span>
            <span className="inline-block px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600 w-24 text-center shrink-0">
              {e.event_type}
            </span>
            <span className="font-mono text-xs flex-1 min-w-0 truncate">{e.action}</span>
            <span className="font-mono text-xs text-gray-500 flex-1 min-w-0 truncate">{e.target}</span>
            <StatusBadge decision={e.decision} />
            <RiskBadge risk={e.risk_class} />
          </div>
        ))}
        {feed && feed.length === 0 && (
          <p className="text-gray-400 text-center py-8">No activity yet</p>
        )}
      </div>
    </div>
  )
}
