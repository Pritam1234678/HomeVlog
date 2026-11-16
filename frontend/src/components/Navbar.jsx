import { Link, NavLink, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Navbar() {
  const { user, loading, logout } = useAuth()
  const navigate = useNavigate()

  const handleLogout = async () => {
    await logout()
    navigate('/')
  }

  const navLinkClass = ({ isActive }) =>
    `text-sm font-medium transition ${isActive ? 'text-clay' : 'text-ink-soft hover:text-clay'}`

  return (
    <header className="sticky top-0 z-50 border-b border-ink/10 bg-paper/85 backdrop-blur-lg">
      <nav className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link to="/" className="flex items-center gap-2">
          <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-forest font-serif text-lg text-paper">
            H
          </span>
          <span className="font-serif text-xl font-semibold tracking-tight text-ink">
            Home<span className="text-clay">Vlog</span>
          </span>
        </Link>

        <div className="hidden items-center gap-7 md:flex">
          <NavLink to="/feed" className={navLinkClass}>
            Feed
          </NavLink>
          {user && (
            <NavLink to="/dashboard" className={navLinkClass}>
              Dashboard
            </NavLink>
          )}
          <NavLink to="/admin/report" className={navLinkClass}>
            Threat Monitor
          </NavLink>
        </div>

        <div className="flex items-center gap-3">
          {user ? (
            <>
              <span className="hidden text-sm text-smoke sm:block">
                <span className="font-medium text-ink">{user.name.split(' ')[0]}</span>
              </span>
              <button
                onClick={handleLogout}
                className="rounded-full border border-ink/15 px-4 py-2 text-sm font-medium text-ink transition hover:border-clay hover:text-clay"
              >
                Logout
              </button>
            </>
          ) : loading ? (
            <span className="text-sm text-smoke">…</span>
          ) : (
            <>
              <Link
                to="/login"
                className="rounded-full px-4 py-2 text-sm font-medium text-ink-soft transition hover:text-clay"
              >
                Sign in
              </Link>
              <Link
                to="/signup"
                className="rounded-full bg-forest px-5 py-2 text-sm font-medium text-paper transition hover:bg-forest/90"
              >
                Get started
              </Link>
            </>
          )}
        </div>
      </nav>
    </header>
  )
}
