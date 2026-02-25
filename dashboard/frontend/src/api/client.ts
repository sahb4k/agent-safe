const BASE_URL = '/api'
const TOKEN_KEY = 'agent-safe-token'

export async function fetchApi<T>(
  path: string,
  params?: Record<string, string>,
  options?: RequestInit,
): Promise<T> {
  const url = new URL(`${BASE_URL}${path}`, window.location.origin)
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v) url.searchParams.set(k, v)
    })
  }

  const headers: Record<string, string> = {
    ...(options?.headers as Record<string, string> || {}),
  }

  // Inject auth token if present
  const token = localStorage.getItem(TOKEN_KEY)
  if (token) {
    headers['Authorization'] = `Bearer ${token}`
  }

  const resp = await fetch(url.toString(), { ...options, headers })

  if (resp.status === 401) {
    localStorage.removeItem(TOKEN_KEY)
    localStorage.removeItem('agent-safe-user')
    window.location.href = '/login'
    throw new Error('Session expired')
  }

  if (!resp.ok) {
    throw new Error(`API error: ${resp.status} ${resp.statusText}`)
  }
  return resp.json()
}

export async function postApi<T>(
  path: string,
  body: unknown,
): Promise<T> {
  return fetchApi<T>(path, undefined, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function putApi<T>(
  path: string,
  body: unknown,
): Promise<T> {
  return fetchApi<T>(path, undefined, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

export async function deleteApi<T>(path: string): Promise<T> {
  return fetchApi<T>(path, undefined, { method: 'DELETE' })
}
