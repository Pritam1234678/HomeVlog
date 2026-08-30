import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { API_URL } from '../api.js'

function readingTime(text) {
  const words = text.trim().split(/\s+/).length
  return Math.max(1, Math.round(words / 200))
}

export default function Feed() {
  const [vlogs, setVlogs] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch(`${API_URL}/vlogs`, { credentials: 'include' })
      .then((res) => (res.ok ? res.json() : []))
      .then((data) => setVlogs(data))
      .catch(() => setVlogs([]))
      .finally(() => setLoading(false))
  }, [])

  const [featured, ...rest] = vlogs

  return (
    <div className="min-h-[calc(100vh-73px)]">
      {/* Feed header */}
      <section className="relative overflow-hidden border-b border-ink/10 bg-cream/30">
        <div className="pointer-events-none absolute -top-20 left-1/3 h-64 w-64 rounded-full bg-amber/10 blur-3xl" />
        <div className="relative mx-auto max-w-4xl px-6 py-16 text-center md:py-20">
          <p className="mb-3 text-xs font-medium uppercase tracking-[0.25em] text-clay">The community feed</p>
          <h1 className="font-serif text-5xl font-medium tracking-tight text-ink md:text-6xl">
            Stories worth your time
          </h1>
          <p className="mx-auto mt-4 max-w-lg text-sm text-smoke">
            Every vlog, from every writer. Take a slow scroll — something here will stay with you.
          </p>
        </div>
      </section>

      <div className="mx-auto max-w-4xl px-6 py-12">
        {loading ? (
          <div className="space-y-6">
            {[...Array(4)].map((_, i) => (
              <div key={i} className="h-40 animate-pulse rounded-3xl bg-cream/50" />
            ))}
          </div>
        ) : vlogs.length === 0 ? (
          <div className="rounded-3xl border border-dashed border-ink/15 bg-cream/20 px-8 py-20 text-center">
            <span className="mb-4 inline-flex h-14 w-14 items-center justify-center rounded-full bg-forest/10 text-2xl">
              ✦
            </span>
            <p className="font-serif text-3xl text-ink">The feed is quiet for now</p>
            <p className="mt-3 text-sm text-smoke">
              Be the first voice — <Link to="/signup" className="text-clay hover:underline">join and share your story</Link>.
            </p>
          </div>
        ) : (
          <>
            {/* Featured story */}
            {featured && (
              <article className="group mb-10 overflow-hidden rounded-3xl border border-ink/10 bg-forest text-paper transition hover:shadow-[0_30px_60px_-25px_rgba(46,74,62,0.6)]">
                <div className="p-8 md:p-12">
                  <div className="mb-5 flex items-center gap-3">
                    <span className="flex h-10 w-10 items-center justify-center rounded-full bg-amber/20 font-serif text-base text-amber">
                      {featured.author.name[0].toUpperCase()}
                    </span>
                    <div>
                      <p className="text-sm font-medium text-paper">{featured.author.name}</p>
                      <p className="text-xs text-paper/60">
                        {new Date(featured.created_at).toLocaleDateString('en-IN', {
                          day: 'numeric',
                          month: 'long',
                          year: 'numeric',
                        })}
                      </p>
                    </div>
                  </div>

                  <Link to={`/vlog/${featured.id}`}>
                    <h2 className="font-serif text-3xl font-medium leading-tight tracking-tight text-paper transition group-hover:text-amber md:text-5xl">
                      {featured.title}
                    </h2>
                  </Link>
                  <p className="mt-5 line-clamp-3 max-w-2xl leading-relaxed text-paper/70">
                    {featured.content}
                  </p>
                  <div className="mt-7 flex items-center gap-4">
                    <Link
                      to={`/vlog/${featured.id}`}
                      className="rounded-full bg-amber px-6 py-2.5 text-sm font-semibold text-ink transition hover:bg-amber/90"
                    >
                      Read the story
                    </Link>
                    <span className="text-xs text-paper/50">{readingTime(featured.content)} min read</span>
                  </div>
                </div>
              </article>
            )}

            {/* Rest of the stories */}
            <div className="space-y-5">
              {rest.map((vlog) => (
                <article
                  key={vlog.id}
                  className="group rounded-3xl border border-ink/10 bg-paper p-7 transition hover:-translate-y-0.5 hover:border-forest/30 hover:shadow-lg md:p-8"
                >
                  <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-3">
                      <span className="flex h-9 w-9 items-center justify-center rounded-full bg-forest/10 font-serif text-sm text-forest">
                        {vlog.author.name[0].toUpperCase()}
                      </span>
                      <div>
                        <p className="text-sm font-medium text-ink">{vlog.author.name}</p>
                        <p className="text-xs text-smoke">
                          {new Date(vlog.created_at).toLocaleDateString('en-IN', {
                            day: 'numeric',
                            month: 'long',
                            year: 'numeric',
                          })}
                        </p>
                      </div>
                    </div>
                    <span className="rounded-full bg-cream px-3 py-1 text-xs text-smoke">
                      {readingTime(vlog.content)} min
                    </span>
                  </div>

                  <Link to={`/vlog/${vlog.id}`}>
                    <h2 className="font-serif text-2xl font-medium leading-snug text-ink transition group-hover:text-clay md:text-3xl">
                      {vlog.title}
                    </h2>
                  </Link>
                  <p className="mt-3 line-clamp-3 leading-relaxed text-ink-soft">
                    {vlog.content}
                  </p>
                  <Link
                    to={`/vlog/${vlog.id}`}
                    className="mt-4 inline-block text-sm font-medium text-clay transition hover:text-clay-dark"
                  >
                    Read more →
                  </Link>
                </article>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
