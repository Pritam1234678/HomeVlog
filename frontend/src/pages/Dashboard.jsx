import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'
import { API_URL } from '../api.js'

function readingTime(text) {
  const words = text.trim().split(/\s+/).length
  return Math.max(1, Math.round(words / 200))
}

export default function Dashboard() {
  const { user, loading } = useAuth()
  const [vlogs, setVlogs] = useState([])
  const [fetching, setFetching] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editing, setEditing] = useState(null)
  const [form, setForm] = useState({ title: '', content: '' })
  const [error, setError] = useState('')
  const [saving, setSaving] = useState(false)

  const fetchVlogs = async () => {
    const res = await fetch(`${API_URL}/vlogs`, { credentials: 'include' })
    if (!res.ok) return
    const data = await res.json()
    setVlogs(data.filter((v) => v.author.id === user.id))
    setFetching(false)
  }

  useEffect(() => {
    if (user) fetchVlogs()
  }, [user])

  const openCreate = () => {
    setEditing(null)
    setForm({ title: '', content: '' })
    setError('')
    setShowForm(true)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const openEdit = (vlog) => {
    setEditing(vlog)
    setForm({ title: vlog.title, content: vlog.content })
    setError('')
    setShowForm(true)
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  const closeForm = () => {
    setShowForm(false)
    setEditing(null)
    setForm({ title: '', content: '' })
    setError('')
  }

  const handleSave = async (e) => {
    e.preventDefault()
    setError('')
    if (form.content.trim().length < 10) {
      setError('Content must be at least 10 characters')
      return
    }
    setSaving(true)
    const url = editing ? `${API_URL}/vlogs/${editing.id}` : `${API_URL}/vlogs`
    const method = editing ? 'PUT' : 'POST'
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ title: form.title, content: form.content }),
    })
    if (!res.ok) {
      const data = await res.json().catch(() => ({}))
      setError(typeof data.detail === 'string' ? data.detail : 'Failed to save')
    } else {
      closeForm()
      fetchVlogs()
    }
    setSaving(false)
  }

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this vlog permanently?')) return
    await fetch(`${API_URL}/vlogs/${id}`, { method: 'DELETE', credentials: 'include' })
    fetchVlogs()
  }

  if (loading) {
    return <div className="flex min-h-[calc(100vh-73px)] items-center justify-center text-smoke">Loading…</div>
  }
  if (!user) return null

  const totalWords = vlogs.reduce((sum, v) => sum + v.content.trim().split(/\s+/).length, 0)

  return (
    <div className="min-h-[calc(100vh-73px)]">
      {/* Hero banner */}
      <section className="relative overflow-hidden bg-forest">
        <div className="pointer-events-none absolute -top-24 right-10 h-72 w-72 rounded-full bg-amber/10 blur-3xl" />
        <div className="pointer-events-none absolute bottom-0 -left-16 h-64 w-64 rounded-full bg-clay/20 blur-3xl" />

        <div className="relative mx-auto max-w-6xl px-6 py-14 md:py-20">
          <p className="mb-3 text-xs font-medium uppercase tracking-[0.25em] text-amber">
            Your dashboard
          </p>
          <h1 className="font-serif text-4xl font-medium leading-tight tracking-tight text-paper md:text-6xl">
            Namaste, <span className="text-amber">{user.name.split(' ')[0]}</span>
          </h1>
          <p className="mt-4 max-w-xl text-lg text-paper/70">
            This is your writing room. Craft, publish, and shape your vlogs — everything lives here.
          </p>

          <div className="mt-10 flex flex-wrap gap-4">
            <button
              onClick={openCreate}
              className="rounded-full bg-amber px-7 py-3.5 text-sm font-semibold text-ink transition hover:bg-amber/90"
            >
              + Write a new vlog
            </button>
            <Link
              to="/feed"
              className="rounded-full border border-paper/30 px-7 py-3.5 text-sm font-medium text-paper transition hover:border-amber hover:text-amber"
            >
              Browse the feed
            </Link>
          </div>
        </div>
      </section>

      {/* Stats strip */}
      <section className="border-b border-ink/10 bg-paper">
        <div className="mx-auto grid max-w-6xl grid-cols-3 divide-x divide-ink/10 px-6">
          {[
            [vlogs.length, 'Vlogs published'],
            [totalWords, 'Words written'],
            [readingTime(vlogs.map((v) => v.content).join('\n') || ' '), 'Min to read all'],
          ].map(([value, label]) => (
            <div key={label} className="px-4 py-8 text-center md:px-8">
              <p className="font-serif text-3xl font-medium text-forest md:text-4xl">{value}</p>
              <p className="mt-1 text-xs uppercase tracking-widest text-smoke">{label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Form */}
      {showForm && (
        <div className="mx-auto max-w-3xl px-6 py-10">
          <div className="overflow-hidden rounded-3xl border border-ink/10 bg-paper shadow-[0_20px_50px_-20px_rgba(26,22,19,0.2)]">
            <div className="flex items-center justify-between border-b border-ink/10 bg-cream/40 px-8 py-5">
              <div>
                <h2 className="font-serif text-2xl font-medium text-ink">
                  {editing ? 'Edit your vlog' : 'Start something new'}
                </h2>
                <p className="mt-1 text-xs text-smoke">
                  {editing ? 'Refine and update your story.' : 'Give your thoughts a title and let them flow.'}
                </p>
              </div>
              <button
                onClick={closeForm}
                className="rounded-full border border-ink/15 px-4 py-2 text-xs font-medium text-ink transition hover:border-clay hover:text-clay"
              >
                Close
              </button>
            </div>

            <form onSubmit={handleSave} className="space-y-6 p-8">
              <div>
                <label htmlFor="title" className="mb-2 block text-sm font-semibold text-ink">
                  Title
                </label>
                <input
                  id="title"
                  type="text"
                  required
                  minLength={3}
                  maxLength={200}
                  value={form.title}
                  onChange={(e) => setForm({ ...form, title: e.target.value })}
                  placeholder="A title worth reading"
                  className="w-full rounded-xl border border-ink/15 bg-paper px-4 py-3.5 font-serif text-lg text-ink placeholder:text-smoke/40 transition focus:border-forest focus:outline-none focus:ring-2 focus:ring-forest/20"
                />
              </div>
              <div>
                <label htmlFor="content" className="mb-2 block text-sm font-semibold text-ink">
                  Your story
                </label>
                <textarea
                  id="content"
                  required
                  minLength={10}
                  rows={12}
                  value={form.content}
                  onChange={(e) => setForm({ ...form, content: e.target.value })}
                  placeholder="Write freely. This is your space…"
                  className="w-full resize-y rounded-xl border border-ink/15 bg-paper px-4 py-4 text-[15px] leading-relaxed text-ink placeholder:text-smoke/40 transition focus:border-forest focus:outline-none focus:ring-2 focus:ring-forest/20"
                />
              </div>

              {error && (
                <p className="rounded-xl border border-clay/20 bg-clay/5 px-4 py-3 text-sm text-clay">
                  {error}
                </p>
              )}

              <div className="flex items-center gap-3">
                <button
                  type="submit"
                  disabled={saving}
                  className="rounded-full bg-forest px-8 py-3 text-sm font-semibold text-paper transition hover:bg-forest/90 disabled:opacity-50"
                >
                  {saving ? 'Saving…' : editing ? 'Update vlog' : 'Publish vlog'}
                </button>
                <button
                  type="button"
                  onClick={closeForm}
                  className="rounded-full px-5 py-3 text-sm font-medium text-smoke transition hover:text-clay"
                >
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Vlogs list */}
      <section className="mx-auto max-w-6xl px-6 py-14">
        <div className="mb-8 flex items-center justify-between">
          <h2 className="font-serif text-3xl font-medium tracking-tight text-ink">
            Your published vlogs
          </h2>
          {vlogs.length > 0 && (
            <span className="text-sm text-smoke">{vlogs.length} {vlogs.length === 1 ? 'story' : 'stories'}</span>
          )}
        </div>

        {fetching ? (
          <div className="grid gap-6 md:grid-cols-2">
            {[...Array(2)].map((_, i) => (
              <div key={i} className="h-52 animate-pulse rounded-3xl bg-cream/50" />
            ))}
          </div>
        ) : vlogs.length === 0 ? (
          <div className="rounded-3xl border border-dashed border-ink/15 bg-cream/20 px-8 py-20 text-center">
            <span className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-full bg-forest/10 text-2xl">
              ✎
            </span>
            <p className="font-serif text-3xl text-ink">Your page is a blank canvas</p>
            <p className="mt-3 text-sm text-smoke">
              The first line is the hardest — after that, the words find their way.
            </p>
            <button
              onClick={openCreate}
              className="mt-8 rounded-full bg-clay px-7 py-3 text-sm font-semibold text-paper transition hover:bg-clay-dark"
            >
              Write your first vlog
            </button>
          </div>
        ) : (
          <div className="grid gap-6 md:grid-cols-2">
            {vlogs.map((vlog) => (
              <article
                key={vlog.id}
                className="group flex flex-col overflow-hidden rounded-3xl border border-ink/10 bg-paper transition hover:-translate-y-1 hover:shadow-[0_25px_50px_-20px_rgba(26,22,19,0.3)]"
              >
                <div className="flex-1 p-7 md:p-8">
                  <div className="mb-4 flex items-center gap-2 text-xs text-smoke">
                    <span className="rounded-full bg-forest/10 px-3 py-1 font-medium text-forest">
                      {new Date(vlog.created_at).toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' })}
                    </span>
                    <span className="rounded-full bg-cream px-3 py-1">
                      {readingTime(vlog.content)} min read
                    </span>
                  </div>

                  <Link to={`/vlog/${vlog.id}`}>
                    <h3 className="font-serif text-2xl font-medium leading-snug text-ink transition group-hover:text-clay md:text-3xl">
                      {vlog.title}
                    </h3>
                  </Link>

                  <p className="mt-4 line-clamp-3 text-sm leading-relaxed text-ink-soft">
                    {vlog.content}
                  </p>
                </div>

                <div className="flex items-center justify-between border-t border-ink/10 bg-cream/20 px-7 py-4">
                  <span className="text-xs text-smoke">By {vlog.author.name}</span>
                  <div className="flex gap-2">
                    <button
                      onClick={() => openEdit(vlog)}
                      className="rounded-full border border-ink/15 px-4 py-1.5 text-xs font-medium text-ink transition hover:border-forest hover:text-forest"
                    >
                      Edit
                    </button>
                    <button
                      onClick={() => handleDelete(vlog.id)}
                      className="rounded-full border border-clay/30 px-4 py-1.5 text-xs font-medium text-clay transition hover:bg-clay hover:text-paper"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              </article>
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
