import { useEffect, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { API_URL } from '../api.js'

function readingTime(text) {
  const words = text.trim().split(/\s+/).length
  return Math.max(1, Math.round(words / 200))
}

export default function VlogDetail() {
  const { id } = useParams()
  const [vlog, setVlog] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`${API_URL}/vlogs/${id}`, { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => setVlog(data))
      .catch(() => setVlog(null))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return <div className="flex min-h-[calc(100vh-73px)] items-center justify-center text-smoke">Loading…</div>
  }

  if (!vlog) {
    return (
      <div className="mx-auto max-w-3xl px-6 py-24 text-center">
        <span className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-full bg-clay/10 text-2xl">✕</span>
        <p className="font-serif text-4xl text-ink">Story not found</p>
        <p className="mt-3 text-sm text-smoke">It may have been removed or never existed.</p>
        <Link to="/feed" className="mt-8 inline-block rounded-full bg-forest px-6 py-3 text-sm font-medium text-paper transition hover:bg-forest/90">
          ← Back to feed
        </Link>
      </div>
    )
  }

  return (
    <article className="min-h-[calc(100vh-73px)]">
      {/* Reading hero */}
      <header className="relative overflow-hidden border-b border-ink/10 bg-cream/30">
        <div className="pointer-events-none absolute -top-16 right-0 h-64 w-64 rounded-full bg-amber/10 blur-3xl" />
        <div className="relative mx-auto max-w-3xl px-6 py-14 md:py-20">
          <Link to="/feed" className="text-sm text-smoke transition hover:text-clay">
            ← Back to feed
          </Link>

          <p className="mt-8 text-xs font-medium uppercase tracking-[0.25em] text-clay">
            {new Date(vlog.created_at).toLocaleDateString('en-IN', {
              weekday: 'long',
              day: 'numeric',
              month: 'long',
              year: 'numeric',
            })}
          </p>
          <h1 className="mt-4 font-serif text-4xl font-medium leading-tight tracking-tight text-ink md:text-6xl">
            {vlog.title}
          </h1>

          <div className="mt-8 flex flex-wrap items-center justify-between gap-4 border-t border-ink/10 pt-6">
            <div className="flex items-center gap-3">
              <span className="flex h-11 w-11 items-center justify-center rounded-full bg-forest/10 font-serif text-lg text-forest">
                {vlog.author.name[0].toUpperCase()}
              </span>
              <div>
                <p className="font-medium text-ink">{vlog.author.name}</p>
                <p className="text-xs text-smoke">Author</p>
              </div>
            </div>
            <span className="rounded-full bg-cream px-4 py-1.5 text-xs text-smoke">
              {readingTime(vlog.content)} min read
            </span>
          </div>
        </div>
      </header>

      {/* Content */}
      <div className="mx-auto max-w-3xl px-6 py-12 md:py-16">
        <div className="prose-vlog">{vlog.content}</div>

        <div className="mt-16 border-t border-ink/10 pt-8 text-center">
          <p className="font-serif text-xl text-ink">Thanks for reading.</p>
          <Link
            to="/feed"
            className="mt-5 inline-block rounded-full bg-forest px-7 py-3 text-sm font-medium text-paper transition hover:bg-forest/90"
          >
            Discover more stories
          </Link>
        </div>
      </div>
    </article>
  )
}
