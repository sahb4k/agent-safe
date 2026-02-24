import { useQuery } from '@tanstack/react-query'
import { fetchApi } from './client'

// --- Types ---

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface AuditEvent {
  event_id: string
  timestamp: string
  event_type: string
  action: string
  target: string
  caller: string
  decision: string
  reason: string
  risk_class: string
  effective_risk: string
  policy_matched: string | null
  correlation_id: string | null
  params: Record<string, unknown>
  context: Record<string, unknown> | null
}

export interface AuditStats {
  total_events: number
  by_decision: Record<string, number>
  by_risk_class: Record<string, number>
  by_event_type: Record<string, number>
}

export interface TimelineBucket {
  timestamp: string
  count: number
  allow: number
  deny: number
  require_approval: number
}

export interface ActionSummary {
  name: string
  description: string
  risk_class: string
  tags: string[]
  reversible: boolean
  target_types: string[]
}

export interface ActionDetail {
  name: string
  version: string
  description: string
  risk_class: string
  tags: string[]
  target_types: string[]
  reversible: boolean
  rollback_action: string | null
  parameters: { name: string; type: string; required: boolean; description: string; default: unknown }[]
  prechecks: { name: string; description: string }[]
  credentials: Record<string, unknown> | null
  state_fields: Record<string, unknown>[]
}

export interface PolicyRule {
  name: string
  description: string
  priority: number
  decision: string
  reason: string
  match_actions: string[]
  match_environments: string[] | null
  match_sensitivities: string[] | null
  match_risk_classes: string[] | null
}

export interface PolicyMatchAnalysis {
  rule_name: string
  priority: number
  decision: string
  matching_target_count: number
  matching_targets: string[]
}

export interface ActivityItem {
  event_id: string
  timestamp: string
  event_type: string
  action: string
  target: string
  caller: string
  decision: string
  risk_class: string
}

export interface HealthStatus {
  status: string
  version: string
  audit_events: number
  actions: number
  policies: number
}

// --- Hooks ---

export function useHealth() {
  return useQuery<HealthStatus>({
    queryKey: ['health'],
    queryFn: () => fetchApi('/health'),
  })
}

export function useAuditEvents(params: Record<string, string>) {
  return useQuery<PaginatedResponse<AuditEvent>>({
    queryKey: ['audit-events', params],
    queryFn: () => fetchApi('/audit/events', params),
  })
}

export function useAuditStats() {
  return useQuery<AuditStats>({
    queryKey: ['audit-stats'],
    queryFn: () => fetchApi('/audit/stats'),
  })
}

export function useTimeline(bucketHours = 1) {
  return useQuery<TimelineBucket[]>({
    queryKey: ['audit-timeline', bucketHours],
    queryFn: () => fetchApi('/audit/timeline', { bucket_hours: String(bucketHours) }),
  })
}

export function useActions(params?: Record<string, string>) {
  return useQuery<ActionSummary[]>({
    queryKey: ['actions', params],
    queryFn: () => fetchApi('/actions/', params),
  })
}

export function useActionDetail(name: string) {
  return useQuery<ActionDetail>({
    queryKey: ['action-detail', name],
    queryFn: () => fetchApi(`/actions/${name}`),
    enabled: !!name,
  })
}

export function usePolicies() {
  return useQuery<PolicyRule[]>({
    queryKey: ['policies'],
    queryFn: () => fetchApi('/policies/'),
  })
}

export function useMatchAnalysis() {
  return useQuery<PolicyMatchAnalysis[]>({
    queryKey: ['match-analysis'],
    queryFn: () => fetchApi('/policies/match-analysis'),
  })
}

export function useActivityFeed(limit = 50) {
  return useQuery<ActivityItem[]>({
    queryKey: ['activity-feed', limit],
    queryFn: () => fetchApi('/activity/feed', { limit: String(limit) }),
    refetchInterval: 5000,
  })
}

export function useRecentDecisions(limit = 10) {
  return useQuery<ActivityItem[]>({
    queryKey: ['recent-decisions', limit],
    queryFn: () => fetchApi('/activity/recent-decisions', { limit: String(limit) }),
    refetchInterval: 5000,
  })
}
