import { useState, type FormEvent } from 'react'
import type { AlertRuleCreateRequest, AlertConditions, AlertChannels } from '../api/hooks'

interface Props {
  initial?: Partial<AlertRuleCreateRequest> & { name?: string }
  onSubmit: (data: AlertRuleCreateRequest) => void
  onCancel: () => void
  loading?: boolean
}

const RISK_CLASSES = ['critical', 'high', 'medium', 'low']
const DECISIONS = ['allow', 'deny', 'require_approval']
const EVENT_TYPES = ['action_request', 'action_executed', 'action_denied', 'approval_granted', 'approval_denied']

export default function AlertRuleEditor({ initial, onSubmit, onCancel, loading }: Props) {
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')

  // Conditions
  const [riskClasses, setRiskClasses] = useState<string[]>(initial?.conditions?.risk_classes ?? [])
  const [decisions, setDecisions] = useState<string[]>(initial?.conditions?.decisions ?? [])
  const [eventTypes, setEventTypes] = useState<string[]>(initial?.conditions?.event_types ?? [])
  const [actionPatterns, setActionPatterns] = useState(
    (initial?.conditions?.action_patterns ?? []).join(', ')
  )

  // Threshold
  const [threshold, setThreshold] = useState(initial?.threshold ?? 1)
  const [windowSeconds, setWindowSeconds] = useState(initial?.window_seconds ?? 0)
  const [cooldownSeconds, setCooldownSeconds] = useState(initial?.cooldown_seconds ?? 300)

  // Channels
  const [webhookUrl, setWebhookUrl] = useState(initial?.channels?.webhook_url ?? '')
  const [slackWebhookUrl, setSlackWebhookUrl] = useState(initial?.channels?.slack_webhook_url ?? '')
  const [slackChannel, setSlackChannel] = useState(initial?.channels?.slack_channel ?? '')

  const toggleItem = (list: string[], item: string, setter: (v: string[]) => void) => {
    setter(list.includes(item) ? list.filter(x => x !== item) : [...list, item])
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const conditions: AlertConditions = {}
    if (riskClasses.length) conditions.risk_classes = riskClasses
    if (decisions.length) conditions.decisions = decisions
    if (eventTypes.length) conditions.event_types = eventTypes
    const patterns = actionPatterns.split(',').map(s => s.trim()).filter(Boolean)
    if (patterns.length) conditions.action_patterns = patterns

    const channels: AlertChannels = {}
    if (webhookUrl) channels.webhook_url = webhookUrl
    if (slackWebhookUrl) channels.slack_webhook_url = slackWebhookUrl
    if (slackChannel) channels.slack_channel = slackChannel

    onSubmit({
      name,
      description,
      conditions,
      threshold,
      window_seconds: windowSeconds,
      channels,
      cooldown_seconds: cooldownSeconds,
    })
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6 bg-white p-6 rounded-lg shadow">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Rule Name</label>
          <input
            type="text" value={name} onChange={e => setName(e.target.value)} required
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
          <input
            type="text" value={description} onChange={e => setDescription(e.target.value)}
            className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:ring-blue-500 focus:border-blue-500"
          />
        </div>
      </div>

      {/* Conditions */}
      <fieldset className="border border-gray-200 rounded-md p-4">
        <legend className="text-sm font-medium text-gray-700 px-1">Conditions</legend>

        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Risk Classes</label>
            <div className="flex gap-2 flex-wrap">
              {RISK_CLASSES.map(rc => (
                <button key={rc} type="button"
                  onClick={() => toggleItem(riskClasses, rc, setRiskClasses)}
                  className={`px-2 py-1 text-xs rounded border ${
                    riskClasses.includes(rc) ? 'bg-blue-100 border-blue-400 text-blue-800' : 'bg-gray-50 border-gray-300 text-gray-600'
                  }`}
                >{rc}</button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Decisions</label>
            <div className="flex gap-2 flex-wrap">
              {DECISIONS.map(d => (
                <button key={d} type="button"
                  onClick={() => toggleItem(decisions, d, setDecisions)}
                  className={`px-2 py-1 text-xs rounded border ${
                    decisions.includes(d) ? 'bg-blue-100 border-blue-400 text-blue-800' : 'bg-gray-50 border-gray-300 text-gray-600'
                  }`}
                >{d}</button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Event Types</label>
            <div className="flex gap-2 flex-wrap">
              {EVENT_TYPES.map(et => (
                <button key={et} type="button"
                  onClick={() => toggleItem(eventTypes, et, setEventTypes)}
                  className={`px-2 py-1 text-xs rounded border ${
                    eventTypes.includes(et) ? 'bg-blue-100 border-blue-400 text-blue-800' : 'bg-gray-50 border-gray-300 text-gray-600'
                  }`}
                >{et}</button>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Action Patterns (comma-separated, supports glob *)</label>
            <input
              type="text" value={actionPatterns} onChange={e => setActionPatterns(e.target.value)}
              placeholder="e.g. deploy.*, db.drop_*"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm focus:ring-blue-500 focus:border-blue-500"
            />
          </div>
        </div>
      </fieldset>

      {/* Threshold */}
      <fieldset className="border border-gray-200 rounded-md p-4">
        <legend className="text-sm font-medium text-gray-700 px-1">Threshold &amp; Cooldown</legend>
        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Threshold (events)</label>
            <input
              type="number" min={1} value={threshold} onChange={e => setThreshold(Number(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Window (seconds, 0 = instant)</label>
            <input
              type="number" min={0} value={windowSeconds} onChange={e => setWindowSeconds(Number(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Cooldown (seconds)</label>
            <input
              type="number" min={0} value={cooldownSeconds} onChange={e => setCooldownSeconds(Number(e.target.value))}
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm"
            />
          </div>
        </div>
      </fieldset>

      {/* Channels */}
      <fieldset className="border border-gray-200 rounded-md p-4">
        <legend className="text-sm font-medium text-gray-700 px-1">Notification Channels</legend>
        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Webhook URL</label>
            <input
              type="url" value={webhookUrl} onChange={e => setWebhookUrl(e.target.value)}
              placeholder="https://example.com/webhook"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Slack Webhook URL</label>
            <input
              type="url" value={slackWebhookUrl} onChange={e => setSlackWebhookUrl(e.target.value)}
              placeholder="https://hooks.slack.com/services/..."
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Slack Channel</label>
            <input
              type="text" value={slackChannel} onChange={e => setSlackChannel(e.target.value)}
              placeholder="#alerts"
              className="w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm text-sm"
            />
          </div>
        </div>
      </fieldset>

      <div className="flex justify-end gap-3">
        <button type="button" onClick={onCancel}
          className="px-4 py-2 text-sm border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
        >Cancel</button>
        <button type="submit" disabled={loading}
          className="px-4 py-2 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
        >{loading ? 'Saving...' : 'Save Rule'}</button>
      </div>
    </form>
  )
}
