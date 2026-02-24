import { useState } from 'react'
import { useUsers, type UserInfo } from '../api/hooks'
import { postApi } from '../api/client'

export default function Users() {
  const { data: users, isLoading, refetch } = useUsers()
  const [showCreate, setShowCreate] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', role: 'viewer', display_name: '' })
  const [error, setError] = useState('')

  const handleCreate = async () => {
    setError('')
    try {
      await postApi('/users/', form)
      setShowCreate(false)
      setForm({ username: '', password: '', role: 'viewer', display_name: '' })
      refetch()
    } catch (err: any) {
      setError(err.message || 'Failed to create user')
    }
  }

  if (isLoading) return <p className="text-gray-500">Loading users...</p>

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-2xl font-bold text-gray-900">User Management</h2>
        <button
          onClick={() => setShowCreate(!showCreate)}
          className="px-4 py-2 bg-blue-600 text-white rounded-md text-sm font-medium hover:bg-blue-700 transition-colors"
        >
          {showCreate ? 'Cancel' : 'Add User'}
        </button>
      </div>

      {/* Create User Form */}
      {showCreate && (
        <div className="bg-white rounded-lg shadow p-6 mb-6">
          <h3 className="text-lg font-semibold mb-4">Create User</h3>
          {error && <p className="text-sm text-red-600 mb-3">{error}</p>}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <input
              placeholder="Username"
              value={form.username}
              onChange={e => setForm({ ...form, username: e.target.value })}
              className="px-3 py-2 border border-gray-300 rounded-md"
            />
            <input
              type="password"
              placeholder="Password"
              value={form.password}
              onChange={e => setForm({ ...form, password: e.target.value })}
              className="px-3 py-2 border border-gray-300 rounded-md"
            />
            <input
              placeholder="Display Name"
              value={form.display_name}
              onChange={e => setForm({ ...form, display_name: e.target.value })}
              className="px-3 py-2 border border-gray-300 rounded-md"
            />
            <select
              value={form.role}
              onChange={e => setForm({ ...form, role: e.target.value })}
              className="px-3 py-2 border border-gray-300 rounded-md"
            >
              <option value="viewer">Viewer</option>
              <option value="editor">Editor</option>
              <option value="admin">Admin</option>
            </select>
          </div>
          <button
            onClick={handleCreate}
            className="mt-4 px-4 py-2 bg-green-600 text-white rounded-md text-sm font-medium hover:bg-green-700 transition-colors"
          >
            Create
          </button>
        </div>
      )}

      {/* Users Table */}
      <div className="bg-white rounded-lg shadow overflow-hidden">
        <table className="min-w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Username</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Display Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Role</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200">
            {users?.map((user: UserInfo) => (
              <tr key={user.user_id}>
                <td className="px-6 py-4 text-sm font-medium text-gray-900">{user.username}</td>
                <td className="px-6 py-4 text-sm text-gray-500">{user.display_name || '—'}</td>
                <td className="px-6 py-4">
                  <span className={`inline-flex px-2 py-1 text-xs font-semibold rounded-full ${
                    user.role === 'admin' ? 'bg-purple-100 text-purple-800' :
                    user.role === 'editor' ? 'bg-blue-100 text-blue-800' :
                    'bg-gray-100 text-gray-800'
                  }`}>
                    {user.role}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {(!users || users.length === 0) && (
          <p className="text-center py-8 text-gray-400">No users found.</p>
        )}
      </div>
    </div>
  )
}
