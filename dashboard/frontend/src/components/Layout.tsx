import { NavLink } from 'react-router-dom'
import type { ReactNode } from 'react'
import { useAuth } from '../auth/AuthContext'

const coreNavItems = [
  { to: '/', label: 'Dashboard' },
  { to: '/audit', label: 'Audit Log' },
  { to: '/actions', label: 'Actions' },
  { to: '/policies', label: 'Policies' },
  { to: '/activity', label: 'Activity' },
]

const paidNavItems = [
  { to: '/clusters', label: 'Clusters' },
  { to: '/reports', label: 'Reports' },
]

const adminNavItems = [
  { to: '/users', label: 'Users' },
]

export default function Layout({ children }: { children: ReactNode }) {
  const { user, tier, logout } = useAuth()
  const isPaid = tier !== 'free'
  const isAdmin = user?.role === 'admin'

  const navItems = [
    ...coreNavItems,
    ...(isPaid ? paidNavItems : []),
    ...(isPaid && isAdmin ? adminNavItems : []),
  ]

  return (
    <div className="flex min-h-screen">
      {/* Sidebar */}
      <nav className="w-56 bg-gray-900 text-gray-100 flex flex-col">
        <div className="px-4 py-5 border-b border-gray-700">
          <h1 className="text-lg font-bold tracking-tight">Agent-Safe</h1>
          <p className="text-xs text-gray-400 mt-0.5">Governance Dashboard</p>
        </div>
        <ul className="flex-1 py-3">
          {navItems.map(({ to, label }) => (
            <li key={to}>
              <NavLink
                to={to}
                end={to === '/'}
                className={({ isActive }) =>
                  `block px-4 py-2 text-sm transition-colors ${
                    isActive
                      ? 'bg-gray-800 text-white font-medium border-l-2 border-blue-400'
                      : 'text-gray-300 hover:bg-gray-800 hover:text-white border-l-2 border-transparent'
                  }`
                }
              >
                {label}
              </NavLink>
            </li>
          ))}
        </ul>
        <div className="px-4 py-3 border-t border-gray-700">
          {isPaid && user ? (
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-gray-300 font-medium">{user.username}</p>
                <p className="text-xs text-gray-500">{user.role}</p>
              </div>
              <button
                onClick={logout}
                className="text-xs text-gray-400 hover:text-white transition-colors"
              >
                Logout
              </button>
            </div>
          ) : (
            <p className="text-xs text-gray-500">v0.14.0</p>
          )}
        </div>
      </nav>

      {/* Main content */}
      <main className="flex-1 p-6 overflow-auto bg-gray-50">
        {children}
      </main>
    </div>
  )
}
