import { useState } from 'react'
import { useAuditEvents, type AuditEvent } from '../api/hooks'
import RiskBadge from '../components/RiskBadge'
import StatusBadge from '../components/StatusBadge'
import Pagination from '../components/Pagination'

export default function Audit() {
  const [page, setPage] = useState(1)
  const [eventType, setEventType] = useState('')
  const [decision, setDecision] = useState('')
  const [riskClass, setRiskClass] = useState('')

  const params: Record<string, string> = {
    page: String(page),
    page_size: '25',
  }
  if (eventType) params.event_type = eventType
  if (decision) params.decision = decision
  if (riskClass) params.risk_class = riskClass

  const { data, isLoading } = useAuditEvents(params)

  return (
    <div>
      <h2 className="text-xl font-semibold mb-4">Audit Log</h2>

      {/* Filters */}
      <div className="flex gap-3 mb-4">
        <select value={eventType} onChange={(e) => { setEventType(e.target.value); setPage(1) }} className="border rounded px-2 py-1 text-sm bg-white">
          <option value="">All types</option>
          <option value="decision">Decision</option>
          <option value="state_capture">State capture</option>
          <option value="execution">Execution</option>
        </select>
        <select value={decision} onChange={(e) => { setDecision(e.target.value); setPage(1) }} className="border rounded px-2 py-1 text-sm bg-white">
          <option value="">All decisions</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
          <option value="require_approval">Require approval</option>
        </select>
        <select value={riskClass} onChange={(e) => { setRiskClass(e.target.value); setPage(1) }} className="border rounded px-2 py-1 text-sm bg-white">
          <option value="">All risks</option>
          <option value="low">Low</option>
          <option value="medium">Medium</option>
          <option value="high">High</option>
          <option value="critical">Critical</option>
        </select>
      </div>

      {/* Table */}
      <div className="bg-white rounded-lg shadow-sm border border-gray-200">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 text-gray-500 text-xs uppercase">
            <tr>
              <th className="px-4 py-2 text-left">Time</th>
              <th className="px-4 py-2 text-left">Type</th>
              <th className="px-4 py-2 text-left">Action</th>
              <th className="px-4 py-2 text-left">Target</th>
              <th className="px-4 py-2 text-left">Caller</th>
              <th className="px-4 py-2 text-left">Decision</th>
              <th className="px-4 py-2 text-left">Risk</th>
            </tr>
          </thead>
          <tbody>
            {isLoading && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">Loading...</td></tr>
            )}
            {data?.items.map((e: AuditEvent) => (
              <tr key={e.event_id} className="border-t border-gray-50 hover:bg-gray-50">
                <td className="px-4 py-2 text-gray-500 whitespace-nowrap">{new Date(e.timestamp).toLocaleString()}</td>
                <td className="px-4 py-2">
                  <span className="inline-block px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600">{e.event_type}</span>
                </td>
                <td className="px-4 py-2 font-mono text-xs">{e.action}</td>
                <td className="px-4 py-2 font-mono text-xs">{e.target}</td>
                <td className="px-4 py-2 font-mono text-xs">{e.caller}</td>
                <td className="px-4 py-2"><StatusBadge decision={e.decision} /></td>
                <td className="px-4 py-2"><RiskBadge risk={e.risk_class} /></td>
              </tr>
            ))}
            {data && data.items.length === 0 && (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-gray-400">No events match your filters</td></tr>
            )}
          </tbody>
        </table>

        {data && (
          <div className="px-4 pb-3">
            <Pagination page={page} pageSize={25} total={data.total} onPageChange={setPage} />
          </div>
        )}
      </div>
    </div>
  )
}
