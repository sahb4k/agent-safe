import { useState } from 'react'
import type { ManagedPolicy, ManagedPolicyCreateRequest, MatchConditions } from '../api/hooks'

const DECISIONS = ['allow', 'deny', 'require_approval'] as const
const ENVIRONMENTS = ['dev', 'staging', 'prod'] as const
const SENSITIVITIES = ['public', 'internal', 'restricted', 'critical'] as const
const RISK_CLASSES = ['low', 'medium', 'high', 'critical'] as const

interface PolicyEditorProps {
  initial?: ManagedPolicy
  onSubmit: (data: ManagedPolicyCreateRequest) => void
  onCancel: () => void
  isPending?: boolean
}

export default function PolicyEditor({ initial, onSubmit, onCancel, isPending }: PolicyEditorProps) {
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [priority, setPriority] = useState(initial?.priority ?? 0)
  const [decision, setDecision] = useState(initial?.decision ?? 'allow')
  const [reason, setReason] = useState(initial?.reason ?? '')

  // Match conditions
  const [actionsText, setActionsText] = useState(
    initial?.match?.actions?.join(', ') ?? '*'
  )
  const [environments, setEnvironments] = useState<string[]>(
    initial?.match?.targets?.environments ?? []
  )
  const [sensitivities, setSensitivities] = useState<string[]>(
    initial?.match?.targets?.sensitivities ?? []
  )
  const [riskClasses, setRiskClasses] = useState<string[]>(
    initial?.match?.risk_classes ?? []
  )
  const [rolesText, setRolesText] = useState(
    initial?.match?.callers?.roles?.join(', ') ?? ''
  )

  const toggleItem = (
    list: string[],
    setList: (v: string[]) => void,
    item: string,
  ) => {
    setList(list.includes(item) ? list.filter(i => i !== item) : [...list, item])
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    const actions = actionsText.split(',').map(s => s.trim()).filter(Boolean)
    const roles = rolesText.split(',').map(s => s.trim()).filter(Boolean)

    const match: MatchConditions = {
      actions: actions.length > 0 ? actions : ['*'],
      targets: (environments.length > 0 || sensitivities.length > 0) ? {
        environments: environments.length > 0 ? environments : null,
        sensitivities: sensitivities.length > 0 ? sensitivities : null,
      } : null,
      callers: roles.length > 0 ? { roles } : null,
      risk_classes: riskClasses.length > 0 ? riskClasses : null,
    }

    onSubmit({ name, description, priority, decision, reason, match })
  }

  return (
    <form onSubmit={handleSubmit} className="bg-white rounded-lg shadow p-5 space-y-4">
      <h3 className="text-sm font-semibold text-gray-900">
        {initial ? 'Edit Policy Rule' : 'Create Policy Rule'}
      </h3>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Name</label>
          <input
            type="text" value={name} onChange={e => setName(e.target.value)} required
            className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
            placeholder="require-approval-prod"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Priority</label>
          <input
            type="number" value={priority} onChange={e => setPriority(Number(e.target.value))}
            className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
          />
        </div>
      </div>

      <div>
        <label className="block text-xs font-medium text-gray-700 mb-1">Description</label>
        <input
          type="text" value={description} onChange={e => setDescription(e.target.value)}
          className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
          placeholder="Optional description"
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Decision</label>
          <select
            value={decision} onChange={e => setDecision(e.target.value)}
            className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
          >
            {DECISIONS.map(d => <option key={d} value={d}>{d}</option>)}
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-gray-700 mb-1">Reason</label>
          <input
            type="text" value={reason} onChange={e => setReason(e.target.value)} required
            className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm"
            placeholder="Why this rule exists"
          />
        </div>
      </div>

      {/* Match conditions */}
      <div className="border-t pt-3">
        <h4 className="text-xs font-semibold text-gray-700 mb-2 uppercase">Match Conditions</h4>

        <div className="space-y-3">
          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Actions (comma-separated glob patterns)
            </label>
            <input
              type="text" value={actionsText} onChange={e => setActionsText(e.target.value)}
              className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm font-mono"
              placeholder="*, restart-deployment, get-*"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Environments</label>
            <div className="flex gap-3">
              {ENVIRONMENTS.map(env => (
                <label key={env} className="flex items-center gap-1 text-xs">
                  <input
                    type="checkbox"
                    checked={environments.includes(env)}
                    onChange={() => toggleItem(environments, setEnvironments, env)}
                  />
                  {env}
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Sensitivities</label>
            <div className="flex gap-3">
              {SENSITIVITIES.map(s => (
                <label key={s} className="flex items-center gap-1 text-xs">
                  <input
                    type="checkbox"
                    checked={sensitivities.includes(s)}
                    onChange={() => toggleItem(sensitivities, setSensitivities, s)}
                  />
                  {s}
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">Risk Classes</label>
            <div className="flex gap-3">
              {RISK_CLASSES.map(rc => (
                <label key={rc} className="flex items-center gap-1 text-xs">
                  <input
                    type="checkbox"
                    checked={riskClasses.includes(rc)}
                    onChange={() => toggleItem(riskClasses, setRiskClasses, rc)}
                  />
                  {rc}
                </label>
              ))}
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-600 mb-1">
              Caller Roles (comma-separated)
            </label>
            <input
              type="text" value={rolesText} onChange={e => setRolesText(e.target.value)}
              className="w-full border border-gray-300 rounded px-3 py-1.5 text-sm font-mono"
              placeholder="deployer, admin"
            />
          </div>
        </div>
      </div>

      <div className="flex gap-2 pt-2">
        <button
          type="submit" disabled={isPending}
          className="px-4 py-2 bg-blue-600 text-white text-sm rounded hover:bg-blue-700 disabled:opacity-50"
        >
          {isPending ? 'Saving...' : initial ? 'Update' : 'Create'}
        </button>
        <button
          type="button" onClick={onCancel}
          className="px-4 py-2 bg-gray-100 text-gray-700 text-sm rounded hover:bg-gray-200"
        >
          Cancel
        </button>
      </div>
    </form>
  )
}
