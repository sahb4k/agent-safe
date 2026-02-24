import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { useClusters, useClusterEvents, useRegisterCluster } from '../api/hooks'
import type { ClusterInfo, ClusterEvent } from '../api/hooks'

function formatDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

function decisionColor(d: string) {
  if (d === 'allow') return 'text-green-700 bg-green-50'
  if (d === 'deny') return 'text-red-700 bg-red-50'
  return 'text-yellow-700 bg-yellow-50'
}

function riskColor(r: string) {
  if (r === 'critical') return 'text-red-700 bg-red-50'
  if (r === 'high') return 'text-orange-700 bg-orange-50'
  if (r === 'medium') return 'text-yellow-700 bg-yellow-50'
  return 'text-gray-600 bg-gray-50'
}

export default function Clusters() {
  const queryClient = useQueryClient()
  const { data: clusters, isLoading } = useClusters()
  const registerMutation = useRegisterCluster()

  const [showForm, setShowForm] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [newApiKey, setNewApiKey] = useState<string | null>(null)
  const [selectedCluster, setSelectedCluster] = useState<string | undefined>(undefined)

  const { data: events } = useClusterEvents(selectedCluster)

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault()
    const result = await registerMutation.mutateAsync({ name, description })
    setNewApiKey(result.api_key)
    setName('')
    setDescription('')
    setShowForm(false)
    queryClient.invalidateQueries({ queryKey: ['clusters'] })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Clusters</h1>
          <p className="text-sm text-gray-500 mt-1">Manage registered clusters and view aggregated audit events</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-md hover:bg-blue-700"
        >
          Register Cluster
        </button>
      </div>

      {/* API Key Alert */}
      {newApiKey && (
        <div className="bg-yellow-50 border border-yellow-200 rounded-md p-4">
          <h3 className="text-sm font-medium text-yellow-800">Cluster API Key (shown once)</h3>
          <code className="block mt-2 text-xs bg-white p-2 rounded border font-mono break-all">{newApiKey}</code>
          <p className="text-xs text-yellow-700 mt-2">Copy this key now. It will not be shown again.</p>
          <button
            onClick={() => setNewApiKey(null)}
            className="mt-2 text-xs text-yellow-800 underline"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* Register Form */}
      {showForm && (
        <form onSubmit={handleRegister} className="bg-white rounded-lg shadow p-4 space-y-3">
          <div>
            <label className="block text-sm font-medium text-gray-700">Cluster Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              required
              className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              placeholder="prod-us-east-1"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700">Description</label>
            <input
              type="text"
              value={description}
              onChange={e => setDescription(e.target.value)}
              className="mt-1 block w-full border border-gray-300 rounded-md px-3 py-2 text-sm"
              placeholder="Production cluster in US East"
            />
          </div>
          <div className="flex gap-2">
            <button
              type="submit"
              disabled={registerMutation.isPending}
              className="px-4 py-2 bg-blue-600 text-white text-sm rounded-md hover:bg-blue-700 disabled:opacity-50"
            >
              {registerMutation.isPending ? 'Registering...' : 'Register'}
            </button>
            <button
              type="button"
              onClick={() => setShowForm(false)}
              className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded-md hover:bg-gray-200"
            >
              Cancel
            </button>
          </div>
          {registerMutation.isError && (
            <p className="text-sm text-red-600">{registerMutation.error.message}</p>
          )}
        </form>
      )}

      {/* Cluster List */}
      {isLoading ? (
        <p className="text-sm text-gray-500">Loading clusters...</p>
      ) : !clusters?.length ? (
        <div className="bg-white rounded-lg shadow p-8 text-center">
          <p className="text-gray-500">No clusters registered yet.</p>
          <p className="text-sm text-gray-400 mt-1">Register a cluster to start aggregating audit events.</p>
        </div>
      ) : (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Events</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Last Seen</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">API Key</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-200">
              {clusters.map((c: ClusterInfo) => (
                <tr key={c.cluster_id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="text-sm font-medium text-gray-900">{c.name}</div>
                    {c.description && <div className="text-xs text-gray-500">{c.description}</div>}
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex px-2 py-0.5 text-xs font-medium rounded-full ${c.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                      {c.is_active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-600">{c.event_count.toLocaleString()}</td>
                  <td className="px-4 py-3 text-sm text-gray-500">{formatDate(c.last_seen)}</td>
                  <td className="px-4 py-3 text-xs font-mono text-gray-400">{c.api_key_prefix}...</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => setSelectedCluster(selectedCluster === c.cluster_id ? undefined : c.cluster_id)}
                      className="text-xs text-blue-600 hover:text-blue-800"
                    >
                      {selectedCluster === c.cluster_id ? 'Hide Events' : 'View Events'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Cluster Events */}
      {selectedCluster && events && (
        <div className="bg-white rounded-lg shadow overflow-hidden">
          <div className="px-4 py-3 bg-gray-50 border-b">
            <h2 className="text-sm font-medium text-gray-700">
              Events for {clusters?.find(c => c.cluster_id === selectedCluster)?.name ?? selectedCluster}
            </h2>
          </div>
          {!events.items.length ? (
            <p className="p-4 text-sm text-gray-500">No events ingested yet.</p>
          ) : (
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Time</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Action</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Target</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Decision</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Risk</th>
                  <th className="px-3 py-2 text-left text-xs font-medium text-gray-500 uppercase">Caller</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {events.items.map((ev: ClusterEvent) => (
                  <tr key={ev.event_id} className="hover:bg-gray-50">
                    <td className="px-3 py-2 text-xs text-gray-500">{formatDate(ev.timestamp)}</td>
                    <td className="px-3 py-2 text-sm font-mono text-gray-900">{ev.action}</td>
                    <td className="px-3 py-2 text-sm text-gray-600">{ev.target}</td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex px-2 py-0.5 text-xs font-medium rounded ${decisionColor(ev.decision)}`}>
                        {ev.decision}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`inline-flex px-2 py-0.5 text-xs font-medium rounded ${riskColor(ev.risk_class)}`}>
                        {ev.risk_class}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-xs text-gray-500">{ev.caller}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="px-4 py-2 bg-gray-50 border-t text-xs text-gray-500">
            {events.total} total events
          </div>
        </div>
      )}
    </div>
  )
}
