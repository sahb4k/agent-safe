import { useAuditStats, useTimeline, useRecentDecisions } from '../api/hooks'
import StatsCard from '../components/StatsCard'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

export default function Dashboard() {
  const { data: stats } = useAuditStats()
  const { data: timeline } = useTimeline(1)
  const { data: recent } = useRecentDecisions(10)

  const allowRate = stats && stats.total_events > 0
    ? Math.round(((stats.by_decision.allow ?? 0) / stats.total_events) * 100)
    : 0

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">Dashboard</h2>

      {/* Stats cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <StatsCard label="Total Events" value={stats?.total_events ?? 0} />
        <StatsCard label="Allow Rate" value={`${allowRate}%`} sub={`${stats?.by_decision.allow ?? 0} allowed`} />
        <StatsCard label="Denials" value={stats?.by_decision.deny ?? 0} />
        <StatsCard label="Critical Events" value={stats?.by_risk_class.critical ?? 0} />
      </div>

      {/* Timeline chart */}
      {timeline && timeline.length > 0 && (
        <div className="bg-white rounded-lg shadow-sm border border-gray-200 p-4 mb-6">
          <h3 className="text-sm font-medium text-gray-500 mb-3">Event Timeline</h3>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart data={timeline}>
              <XAxis dataKey="timestamp" tick={{ fontSize: 11 }} tickFormatter={(v) => new Date(v).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} />
              <YAxis tick={{ fontSize: 11 }} />
              <Tooltip labelFormatter={(v) => new Date(v as string).toLocaleString()} />
              <Area type="monotone" dataKey="allow" stackId="1" fill="#86efac" stroke="#22c55e" />
              <Area type="monotone" dataKey="deny" stackId="1" fill="#fca5a5" stroke="#ef4444" />
              <Area type="monotone" dataKey="require_approval" stackId="1" fill="#fcd34d" stroke="#f59e0b" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Recent decisions */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <div className="px-4 py-3 border-b border-gray-100">
          <h3 className="text-sm font-medium text-gray-500">Recent Decisions</h3>
        </div>
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
            <tr>
              <th className="px-4 py-2 text-left">Time</th>
              <th className="px-4 py-2 text-left">Action</th>
              <th className="px-4 py-2 text-left">Target</th>
              <th className="px-4 py-2 text-left">Decision</th>
              <th className="px-4 py-2 text-left">Risk</th>
            </tr>
          </thead>
          <tbody>
            {recent?.map((e) => (
              <tr key={e.event_id} className="border-t border-gray-50 hover:bg-gray-50">
                <td className="px-4 py-2 text-gray-500">{new Date(e.timestamp).toLocaleTimeString()}</td>
                <td className="px-4 py-2 font-mono text-xs">{e.action}</td>
                <td className="px-4 py-2 font-mono text-xs">{e.target}</td>
                <td className="px-4 py-2"><StatusBadge decision={e.decision} /></td>
                <td className="px-4 py-2"><RiskBadge risk={e.risk_class} /></td>
              </tr>
            ))}
            {(!recent || recent.length === 0) && (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-400">No events yet</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
