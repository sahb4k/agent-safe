const decisionColors: Record<string, string> = {
  allow: 'bg-green-100 text-green-800',
  deny: 'bg-red-100 text-red-800',
  require_approval: 'bg-amber-100 text-amber-800',
}

export default function StatusBadge({ decision }: { decision: string }) {
  const classes = decisionColors[decision] ?? 'bg-gray-100 text-gray-800'
  const label = decision.replace('_', ' ')
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${classes}`}>
      {label}
    </span>
  )
}
