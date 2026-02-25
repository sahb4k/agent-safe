import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import {
  useAlertRules,
  useCreateAlertRule,
  useUpdateAlertRule,
  useDeleteAlertRule,
  useAlertHistory,
  type AlertRule,
  type AlertRuleCreateRequest,
} from '../api/hooks'
import AlertRuleEditor from '../components/AlertRuleEditor'

type Tab = 'rules' | 'history'

export default function Alerts() {
  const [tab, setTab] = useState<Tab>('rules')
  const [editing, setEditing] = useState<AlertRule | 'new' | null>(null)
  const queryClient = useQueryClient()

  const { data: rules, isLoading: rulesLoading } = useAlertRules()
  const { data: history, isLoading: historyLoading } = useAlertHistory()

  const createMut = useCreateAlertRule()
  const updateMut = useUpdateAlertRule()
  const deleteMut = useDeleteAlertRule()

  const invalidate = () => {
    queryClient.invalidateQueries({ queryKey: ['alert-rules'] })
    queryClient.invalidateQueries({ queryKey: ['alert-history'] })
  }

  const handleCreate = (data: AlertRuleCreateRequest) => {
    createMut.mutate(data, {
      onSuccess: () => { setEditing(null); invalidate() },
    })
  }

  const handleUpdate = (data: AlertRuleCreateRequest) => {
    if (editing && editing !== 'new') {
      updateMut.mutate({ id: editing.rule_id, body: data }, {
        onSuccess: () => { setEditing(null); invalidate() },
      })
    }
  }

  const handleDelete = (id: string) => {
    if (confirm('Delete this alert rule?')) {
      deleteMut.mutate(id, { onSuccess: invalidate })
    }
  }

  const handleToggle = (rule: AlertRule) => {
    updateMut.mutate(
      { id: rule.rule_id, body: { is_active: !rule.is_active } },
      { onSuccess: invalidate },
    )
  }

  const statusBadge = (status: string) => {
    const colors: Record<string, string> = {
      sent: 'bg-green-100 text-green-800',
      failed: 'bg-red-100 text-red-800',
      partial: 'bg-yellow-100 text-yellow-800',
      pending: 'bg-gray-100 text-gray-800',
    }
    return (
      <span className={`inline-block px-2 py-0.5 text-xs rounded-full font-medium ${colors[status] || colors.pending}`}>
        {status}
      </span>
    )
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
        {tab === 'rules' && !editing && (
          <button
            onClick={() => setEditing('new')}
            className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700"
          >New Rule</button>
        )}
      </div>

      {/* Tabs */}
      <div className="border-b border-gray-200 mb-6">
        <nav className="flex gap-4">
          {(['rules', 'history'] as Tab[]).map(t => (
            <button key={t}
              onClick={() => { setTab(t); setEditing(null) }}
              className={`pb-2 text-sm font-medium border-b-2 transition-colors ${
                tab === t ? 'border-blue-500 text-blue-600' : 'border-transparent text-gray-500 hover:text-gray-700'
              }`}
            >{t === 'rules' ? 'Rules' : 'History'}</button>
          ))}
        </nav>
      </div>

      {/* Rules Tab */}
      {tab === 'rules' && (
        <>
          {editing && (
            <div className="mb-6">
              <AlertRuleEditor
                initial={editing === 'new' ? undefined : {
                  name: editing.name,
                  description: editing.description,
                  conditions: editing.conditions,
                  threshold: editing.threshold,
                  window_seconds: editing.window_seconds,
                  channels: editing.channels,
                  cooldown_seconds: editing.cooldown_seconds,
                }}
                onSubmit={editing === 'new' ? handleCreate : handleUpdate}
                onCancel={() => setEditing(null)}
                loading={createMut.isPending || updateMut.isPending}
              />
            </div>
          )}

          {rulesLoading ? (
            <p className="text-sm text-gray-500">Loading rules...</p>
          ) : !rules?.length ? (
            <p className="text-sm text-gray-500">No alert rules configured.</p>
          ) : (
            <div className="bg-white shadow rounded-lg overflow-hidden">
              <table className="min-w-full divide-y divide-gray-200">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Conditions</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Threshold</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Channels</th>
                    <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                    <th className="px-4 py-3 text-right text-xs font-medium text-gray-500 uppercase">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-200">
                  {rules.map(rule => (
                    <tr key={rule.rule_id} className={!rule.is_active ? 'opacity-50' : ''}>
                      <td className="px-4 py-3">
                        <div className="text-sm font-medium text-gray-900">{rule.name}</div>
                        {rule.description && <div className="text-xs text-gray-500">{rule.description}</div>}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-600">
                        {rule.conditions.risk_classes?.length ? <div>Risk: {rule.conditions.risk_classes.join(', ')}</div> : null}
                        {rule.conditions.decisions?.length ? <div>Decision: {rule.conditions.decisions.join(', ')}</div> : null}
                        {rule.conditions.event_types?.length ? <div>Events: {rule.conditions.event_types.join(', ')}</div> : null}
                        {rule.conditions.action_patterns?.length ? <div>Actions: {rule.conditions.action_patterns.join(', ')}</div> : null}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-600">
                        {rule.threshold > 1 ? `${rule.threshold} in ${rule.window_seconds}s` : 'Every match'}
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-600">
                        {rule.channels.webhook_url && <div>Webhook</div>}
                        {rule.channels.slack_webhook_url && <div>Slack</div>}
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleToggle(rule)}
                          className={`text-xs px-2 py-1 rounded ${rule.is_active ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-600'}`}
                        >{rule.is_active ? 'Active' : 'Inactive'}</button>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button onClick={() => setEditing(rule)}
                          className="text-xs text-blue-600 hover:text-blue-800 mr-3"
                        >Edit</button>
                        <button onClick={() => handleDelete(rule.rule_id)}
                          className="text-xs text-red-600 hover:text-red-800"
                        >Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {/* History Tab */}
      {tab === 'history' && (
        historyLoading ? (
          <p className="text-sm text-gray-500">Loading alert history...</p>
        ) : !history?.length ? (
          <p className="text-sm text-gray-500">No alerts have been fired yet.</p>
        ) : (
          <div className="bg-white shadow rounded-lg overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Fired At</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Rule</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Cluster</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Events</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200">
                {history.map(item => (
                  <tr key={item.id}>
                    <td className="px-4 py-3 text-sm text-gray-900">
                      {new Date(item.fired_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-sm text-gray-700">{item.rule_name}</td>
                    <td className="px-4 py-3 text-sm text-gray-500 font-mono text-xs">{item.cluster_id.slice(0, 8)}</td>
                    <td className="px-4 py-3 text-sm text-gray-500">{item.trigger_event_ids.length}</td>
                    <td className="px-4 py-3">
                      {statusBadge(item.notification_status)}
                      {item.notification_error && (
                        <span className="ml-2 text-xs text-red-500" title={item.notification_error}>error</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </div>
  )
}
