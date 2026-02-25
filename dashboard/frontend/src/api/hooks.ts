import { useQuery, useMutation } from '@tanstack/react-query'
import { fetchApi, postApi, putApi, deleteApi } from './client'

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

// --- Compliance Reports ---

export interface ReportSummary {
  total_decisions: number
  allowed: number
  denied: number
  approvals_required: number
  unique_agents: number
  unique_targets: number
  high_risk_actions: number
  denial_rate: number
  audit_chain_valid: boolean
}

export interface ReportSection {
  title: string
  description: string
  items: Record<string, unknown>[]
}

export interface ComplianceReport {
  report_type: string
  generated_at: string
  period: { start: string; end: string }
  summary: ReportSummary
  sections: ReportSection[]
}

export function useGenerateReport() {
  return useMutation<ComplianceReport, Error, { report_type: string; start_date: string; end_date: string }>({
    mutationFn: (body) => postApi('/reports/generate', body),
  })
}

// --- Users (admin) ---

export interface UserInfo {
  user_id: string
  username: string
  display_name: string
  role: string
}

export function useUsers() {
  return useQuery<UserInfo[]>({
    queryKey: ['users'],
    queryFn: () => fetchApi('/users/'),
  })
}

// --- Clusters ---

export interface ClusterInfo {
  cluster_id: string
  name: string
  description: string
  api_key_prefix: string
  is_active: boolean
  created_at: string
  last_seen: string | null
  event_count: number
}

export interface ClusterCreateResponse {
  cluster: ClusterInfo
  api_key: string
}

export interface ClusterEvent {
  event_id: string
  cluster_id: string
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
  ingested_at: string
}

export function useClusters() {
  return useQuery<ClusterInfo[]>({
    queryKey: ['clusters'],
    queryFn: () => fetchApi('/clusters/'),
  })
}

export function useClusterEvents(clusterId?: string, params?: Record<string, string>) {
  const path = clusterId ? `/clusters/${clusterId}/events` : '/clusters/events'
  return useQuery<PaginatedResponse<ClusterEvent>>({
    queryKey: ['cluster-events', clusterId, params],
    queryFn: () => fetchApi(path, params),
  })
}

export function useClusterStats(clusterId?: string) {
  const path = clusterId ? `/clusters/${clusterId}/stats` : '/clusters/stats'
  return useQuery<AuditStats>({
    queryKey: ['cluster-stats', clusterId],
    queryFn: () => fetchApi(path),
  })
}

export function useRegisterCluster() {
  return useMutation<ClusterCreateResponse, Error, { name: string; description?: string }>({
    mutationFn: (body) => postApi('/clusters/', body),
  })
}

// --- Managed Policies ---

export interface MatchTargets {
  environments?: string[] | null
  sensitivities?: string[] | null
  types?: string[] | null
  labels?: Record<string, string> | null
}

export interface MatchCallers {
  agent_ids?: string[] | null
  roles?: string[] | null
  groups?: string[] | null
}

export interface MatchConditions {
  actions: string[]
  targets?: MatchTargets | null
  callers?: MatchCallers | null
  risk_classes?: string[] | null
  require_ticket?: boolean | null
}

export interface ManagedPolicy {
  policy_id: string
  name: string
  description: string
  priority: number
  decision: string
  reason: string
  match: MatchConditions
  is_active: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface ManagedPolicyCreateRequest {
  name: string
  description?: string
  priority?: number
  decision: string
  reason: string
  match?: MatchConditions
}

export interface PolicyRevision {
  revision_id: number
  rule_count: number
  published_by: string
  published_at: string
  notes: string
}

export interface ClusterSyncStatus {
  cluster_id: string
  cluster_name: string
  revision_id: number | null
  synced_at: string | null
  is_current: boolean
}

export function useManagedPolicies() {
  return useQuery<ManagedPolicy[]>({
    queryKey: ['managed-policies'],
    queryFn: () => fetchApi('/policies/managed'),
  })
}

export function useCreateManagedPolicy() {
  return useMutation<ManagedPolicy, Error, ManagedPolicyCreateRequest>({
    mutationFn: (body) => postApi('/policies/managed', body),
  })
}

export function useUpdateManagedPolicy() {
  return useMutation<ManagedPolicy, Error, { id: string; body: Partial<ManagedPolicyCreateRequest> & { is_active?: boolean } }>({
    mutationFn: ({ id, body }) => putApi(`/policies/managed/${id}`, body),
  })
}

export function useDeleteManagedPolicy() {
  return useMutation<{ ok: boolean }, Error, string>({
    mutationFn: (id) => deleteApi(`/policies/managed/${id}`),
  })
}

export function usePublishPolicies() {
  return useMutation<{ revision: PolicyRevision; bundle_preview: Record<string, unknown>[] }, Error, { notes?: string }>({
    mutationFn: (body) => postApi('/policies/publish', body),
  })
}

export function usePolicyRevisions() {
  return useQuery<PolicyRevision[]>({
    queryKey: ['policy-revisions'],
    queryFn: () => fetchApi('/policies/revisions'),
  })
}

export function usePolicySyncStatus() {
  return useQuery<ClusterSyncStatus[]>({
    queryKey: ['policy-sync-status'],
    queryFn: () => fetchApi('/policies/sync-status'),
  })
}

// --- Alert Rules ---

export interface AlertConditions {
  risk_classes?: string[] | null
  decisions?: string[] | null
  action_patterns?: string[] | null
  event_types?: string[] | null
}

export interface AlertChannels {
  webhook_url?: string | null
  webhook_headers?: Record<string, string> | null
  slack_webhook_url?: string | null
  slack_channel?: string | null
}

export interface AlertRule {
  rule_id: string
  name: string
  description: string
  is_active: boolean
  conditions: AlertConditions
  cluster_ids: string[] | null
  threshold: number
  window_seconds: number
  channels: AlertChannels
  cooldown_seconds: number
  created_by: string
  created_at: string
  updated_at: string
}

export interface AlertRuleCreateRequest {
  name: string
  description?: string
  conditions?: AlertConditions
  cluster_ids?: string[] | null
  threshold?: number
  window_seconds?: number
  channels: AlertChannels
  cooldown_seconds?: number
}

export interface AlertHistoryItem {
  id: number
  rule_id: string
  rule_name: string
  cluster_id: string
  fired_at: string
  trigger_event_ids: string[]
  conditions_snapshot: AlertConditions
  notification_status: string
  notification_error: string | null
}

export function useAlertRules() {
  return useQuery<AlertRule[]>({
    queryKey: ['alert-rules'],
    queryFn: () => fetchApi('/alerts/rules'),
  })
}

export function useCreateAlertRule() {
  return useMutation<AlertRule, Error, AlertRuleCreateRequest>({
    mutationFn: (body) => postApi('/alerts/rules', body),
  })
}

export function useUpdateAlertRule() {
  return useMutation<AlertRule, Error, { id: string; body: Partial<AlertRuleCreateRequest> & { is_active?: boolean } }>({
    mutationFn: ({ id, body }) => putApi(`/alerts/rules/${id}`, body),
  })
}

export function useDeleteAlertRule() {
  return useMutation<{ ok: boolean }, Error, string>({
    mutationFn: (id) => deleteApi(`/alerts/rules/${id}`),
  })
}

export function useAlertHistory(params?: { limit?: string; rule_id?: string; cluster_id?: string }) {
  return useQuery<AlertHistoryItem[]>({
    queryKey: ['alert-history', params],
    queryFn: () => fetchApi('/alerts/history', params as Record<string, string>),
    refetchInterval: 15000,
  })
}
