import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  usePolicies, useMatchAnalysis,
  useManagedPolicies, useCreateManagedPolicy,
  useUpdateManagedPolicy, useDeleteManagedPolicy,
  usePublishPolicies, usePolicyRevisions, usePolicySyncStatus,
} from '../api/hooks'
import type { ManagedPolicy, ManagedPolicyCreateRequest } from '../api/hooks'
import StatusBadge from '../components/StatusBadge'
import PolicyEditor from '../components/PolicyEditor'

function formatDate(iso: string | null) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

type Tab = 'file' | 'managed'

export default function Policies() {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<Tab>('file')

  // File-based
  const { data: policies } = usePolicies()
  const { data: analysis } = useMatchAnalysis()
  const [showAnalysis, setShowAnalysis] = useState(false)
  const matchMap = new Map(analysis?.map((a) => [a.rule_name, a]) ?? [])

  // Managed
  const { data: managed, isError: managedError } = useManagedPolicies()
  const createMutation = useCreateManagedPolicy()
  const updateMutation = useUpdateManagedPolicy()
  const deleteMutation = useDeleteManagedPolicy()
  const publishMutation = usePublishPolicies()
  const { data: revisions } = usePolicyRevisions()
  const { data: syncStatus } = usePolicySyncStatus()

  const [showEditor, setShowEditor] = useState(false)
  const [editingPolicy, setEditingPolicy] = useState<ManagedPolicy | undefined>()
  const [publishNotes, setPublishNotes] = useState('')
  const [showPublishForm, setShowPublishForm] = useState(false)

  const hasManagedFeature = !managedError

  const handleCreate = async (data: ManagedPolicyCreateRequest) => {
    await createMutation.mutateAsync(data)
    setShowEditor(false)
    queryClient.invalidateQueries({ queryKey: ['managed-policies'] })
  }

  const handleUpdate = async (data: ManagedPolicyCreateRequest) => {
    if (!editingPolicy) return
    await updateMutation.mutateAsync({ id: editingPolicy.policy_id, body: data })
    setEditingPolicy(undefined)
    setShowEditor(false)
    queryClient.invalidateQueries({ queryKey: ['managed-policies'] })
  }

  const handleDelete = async (id: string) => {
    await deleteMutation.mutateAsync(id)
    queryClient.invalidateQueries({ queryKey: ['managed-policies'] })
  }

  const handlePublish = async (e: React.FormEvent) => {
    e.preventDefault()
    await publishMutation.mutateAsync({ notes: publishNotes })
    setPublishNotes('')
    setShowPublishForm(false)
    queryClient.invalidateQueries({ queryKey: ['policy-revisions'] })
    queryClient.invalidateQueries({ queryKey: ['policy-sync-status'] })
  }

  const startEdit = (p: ManagedPolicy) => {
    setEditingPolicy(p)
    setShowEditor(true)
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-gray-900">Policies</h1>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b">
        <button
          onClick={() => setTab('file')}
          className={`px-4 py-2 text-sm font-medium border-b-2 ${tab === 'file' ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
        >
          File-Based Rules
        </button>
        {hasManagedFeature && (
          <button
            onClick={() => setTab('managed')}
            className={`px-4 py-2 text-sm font-medium border-b-2 ${tab === 'managed' ? 'border-blue-600 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'}`}
          >
            Managed Rules
          </button>
        )}
      </div>

      {/* File-Based Tab */}
      {tab === 'file' && (
        <div>
          <div className="flex justify-end mb-3">
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
      )}

      {/* Managed Tab */}
      {tab === 'managed' && hasManagedFeature && (
        <div className="space-y-6">
          {/* Actions bar */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => { setEditingPolicy(undefined); setShowEditor(!showEditor) }}
              className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded hover:bg-blue-700"
            >
              {showEditor && !editingPolicy ? 'Cancel' : 'Create Rule'}
            </button>
            <button
              onClick={() => setShowPublishForm(!showPublishForm)}
              className="px-4 py-2 bg-green-600 text-white text-sm font-medium rounded hover:bg-green-700"
            >
              Publish
            </button>
          </div>

          {/* Publish form */}
          {showPublishForm && (
            <form onSubmit={handlePublish} className="bg-green-50 border border-green-200 rounded-md p-4 flex gap-3 items-end">
              <div className="flex-1">
                <label className="block text-xs font-medium text-green-800 mb-1">Publish Notes (optional)</label>
                <input
                  type="text" value={publishNotes} onChange={e => setPublishNotes(e.target.value)}
                  className="w-full border border-green-300 rounded px-3 py-1.5 text-sm"
                  placeholder="What changed in this revision?"
                />
              </div>
              <button
                type="submit" disabled={publishMutation.isPending}
                className="px-4 py-2 bg-green-600 text-white text-sm rounded hover:bg-green-700 disabled:opacity-50"
              >
                {publishMutation.isPending ? 'Publishing...' : 'Publish Now'}
              </button>
              <button
                type="button" onClick={() => setShowPublishForm(false)}
                className="px-4 py-2 bg-white text-gray-700 text-sm rounded border hover:bg-gray-50"
              >
                Cancel
              </button>
            </form>
          )}

          {/* Editor */}
          {showEditor && (
            <PolicyEditor
              initial={editingPolicy}
              onSubmit={editingPolicy ? handleUpdate : handleCreate}
              onCancel={() => { setShowEditor(false); setEditingPolicy(undefined) }}
              isPending={createMutation.isPending || updateMutation.isPending}
            />
          )}

          {/* Managed policies table */}
          {!managed?.length ? (
            <div className="bg-white rounded-lg shadow p-8 text-center">
              <p className="text-gray-500">No managed policies yet.</p>
              <p className="text-sm text-gray-400 mt-1">Create a policy rule to get started.</p>
            </div>
          ) : (
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Priority</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Decision</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Actions</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Reason</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Manage</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {managed.map((p: ManagedPolicy) => (
                    <tr key={p.policy_id} className="hover:bg-gray-50">
                      <td className="px-4 py-3 text-sm font-mono">{p.priority}</td>
                      <td className="px-4 py-3">
                        <div className="text-sm font-medium text-gray-900">{p.name}</div>
                        {p.description && <div className="text-xs text-gray-500">{p.description}</div>}
                      </td>
                      <td className="px-4 py-3"><StatusBadge decision={p.decision} /></td>
                      <td className="px-4 py-3 font-mono text-xs">
                        {p.match.actions.length > 2
                          ? `${p.match.actions.slice(0, 2).join(', ')} +${p.match.actions.length - 2}`
                          : p.match.actions.join(', ')}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex px-2 py-0.5 text-xs font-medium rounded-full ${p.is_active ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                          {p.is_active ? 'Active' : 'Inactive'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-500 max-w-xs truncate">{p.reason}</td>
                      <td className="px-4 py-3 space-x-2">
                        <button onClick={() => startEdit(p)} className="text-xs text-blue-600 hover:text-blue-800">Edit</button>
                        <button onClick={() => handleDelete(p.policy_id)} className="text-xs text-red-600 hover:text-red-800">Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Revision History */}
          {revisions && revisions.length > 0 && (
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <div className="px-4 py-3 bg-gray-50 border-b">
                <h2 className="text-sm font-medium text-gray-700">Revision History</h2>
              </div>
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Rev</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Rules</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Published By</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Published At</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Notes</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {revisions.map(rev => (
                    <tr key={rev.revision_id} className="hover:bg-gray-50">
                      <td className="px-4 py-2 text-sm font-mono">#{rev.revision_id}</td>
                      <td className="px-4 py-2 text-sm">{rev.rule_count}</td>
                      <td className="px-4 py-2 text-sm text-gray-600">{rev.published_by}</td>
                      <td className="px-4 py-2 text-sm text-gray-500">{formatDate(rev.published_at)}</td>
                      <td className="px-4 py-2 text-xs text-gray-500">{rev.notes || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Cluster Sync Status */}
          {syncStatus && syncStatus.length > 0 && (
            <div className="bg-white rounded-lg shadow overflow-hidden">
              <div className="px-4 py-3 bg-gray-50 border-b">
                <h2 className="text-sm font-medium text-gray-700">Cluster Sync Status</h2>
              </div>
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Cluster</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Synced Revision</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Synced At</th>
                    <th className="px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {syncStatus.map(s => (
                    <tr key={s.cluster_id} className="hover:bg-gray-50">
                      <td className="px-4 py-2 text-sm font-medium">{s.cluster_name}</td>
                      <td className="px-4 py-2 text-sm font-mono">
                        {s.revision_id != null ? `#${s.revision_id}` : '—'}
                      </td>
                      <td className="px-4 py-2 text-sm text-gray-500">{formatDate(s.synced_at)}</td>
                      <td className="px-4 py-2">
                        {s.revision_id == null ? (
                          <span className="inline-flex px-2 py-0.5 text-xs font-medium rounded-full bg-gray-100 text-gray-600">Never synced</span>
                        ) : s.is_current ? (
                          <span className="inline-flex px-2 py-0.5 text-xs font-medium rounded-full bg-green-100 text-green-800">Current</span>
                        ) : (
                          <span className="inline-flex px-2 py-0.5 text-xs font-medium rounded-full bg-yellow-100 text-yellow-800">Behind</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
