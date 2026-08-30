import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Login() {
  const { login } = useAuth()
  const navigate = useNavigate()
  const [form, setForm] = useState({ email: '', password: '' })
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      await login(form.email, form.password)
      navigate('/dashboard')
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex min-h-[calc(100vh-73px)]">
      {/* Left brand panel */}
      <div className="hidden flex-1 flex-col justify-between bg-forest p-12 text-paper lg:flex">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-paper/10 font-serif text-xl">
              H
            </span>
            <span className="font-serif text-xl font-semibold">Home<span className="text-clay">Vlog</span></span>
          </div>
        </div>
        <div>
          <h2 className="font-serif text-4xl font-medium leading-tight">
            Share your story.
            <br />
            Read the world.
          </h2>
          <p className="mt-4 max-w-sm text-paper/70">
            A calm space to write, publish, and discover vlogs from people like you.
          </p>
        </div>
        <p className="text-sm text-paper/50">© {new Date().getFullYear()} HomeVlog. All thoughts welcome.</p>
      </div>

      {/* Form panel */}
      <div className="flex flex-1 items-center justify-center px-6 py-16">
        <div className="w-full max-w-md">
          <p className="mb-3 text-xs font-medium uppercase tracking-[0.2em] text-clay">Welcome back</p>
          <h1 className="font-serif text-4xl font-medium tracking-tight text-ink">Sign in</h1>
          <p className="mt-3 text-sm text-smoke">Pick up right where you left off.</p>

          <form onSubmit={handleSubmit} className="mt-8 space-y-5">
            <div>
              <label htmlFor="email" className="mb-2 block text-sm font-medium text-ink">
                Email
              </label>
              <input
                id="email"
                type="email"
                required
                value={form.email}
                onChange={(e) => setForm({ ...form, email: e.target.value })}
                placeholder="you@example.com"
                className="w-full rounded-xl border border-ink/15 bg-paper px-4 py-3 text-ink placeholder:text-smoke/50 transition focus:border-forest focus:outline-none focus:ring-2 focus:ring-forest/20"
              />
            </div>
            <div>
              <label htmlFor="password" className="mb-2 block text-sm font-medium text-ink">
                Password
              </label>
              <input
                id="password"
                type="password"
                required
                value={form.password}
                onChange={(e) => setForm({ ...form, password: e.target.value })}
                placeholder="••••••••"
                className="w-full rounded-xl border border-ink/15 bg-paper px-4 py-3 text-ink placeholder:text-smoke/50 transition focus:border-forest focus:outline-none focus:ring-2 focus:ring-forest/20"
              />
            </div>

            {error && (
              <p className="rounded-xl border border-clay/20 bg-clay/5 px-4 py-3 text-sm text-clay">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full rounded-xl bg-forest py-3.5 text-sm font-medium text-paper transition hover:bg-forest/90 disabled:opacity-50"
            >
              {loading ? 'Signing in…' : 'Sign in'}
            </button>
          </form>

          <p className="mt-8 text-center text-sm text-smoke">
            New here?{' '}
            <Link to="/signup" className="font-medium text-clay transition hover:text-clay-dark">
              Create an account
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
