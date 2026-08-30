import { Link } from 'react-router-dom'
import { useAuth } from '../context/AuthContext.jsx'

export default function Home() {
  const { user, loading } = useAuth()

  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="relative overflow-hidden bg-forest">
        <div className="pointer-events-none absolute -top-32 right-0 h-96 w-96 rounded-full bg-paper/5 blur-3xl" />
        <div className="pointer-events-none absolute bottom-0 -left-32 h-96 w-96 rounded-full bg-clay/20 blur-3xl" />

        <div className="relative mx-auto grid max-w-6xl gap-12 px-6 py-20 md:grid-cols-2 md:items-center md:py-32">
          <div>
            <p className="mb-6 inline-flex items-center gap-2 rounded-full border border-paper/20 bg-paper/5 px-4 py-1.5 text-xs font-medium uppercase tracking-widest text-amber">
              <span className="h-1.5 w-1.5 rounded-full bg-amber" />
              A home for your stories
            </p>
            <h1 className="font-serif text-5xl font-medium leading-[1.05] tracking-tight text-paper md:text-7xl">
              Write. Read.
              <br />
              <em className="not-italic text-amber">Belong.</em>
            </h1>
            <p className="mt-6 max-w-md text-lg leading-relaxed text-paper/70">
              HomeVlog is a calm, considered space to share your vlogs, read what others
              write, and feel part of something real.
            </p>
            <div className="mt-10 flex flex-wrap items-center gap-4">
              {user ? (
                <Link
                  to="/dashboard"
                  className="rounded-full bg-amber px-8 py-3.5 text-sm font-medium text-ink transition hover:bg-amber/90"
                >
                  Go to your dashboard
                </Link>
              ) : loading ? (
                <span className="text-sm text-paper/60">Loading…</span>
              ) : (
                <>
                  <Link
                    to="/signup"
                    className="rounded-full bg-amber px-8 py-3.5 text-sm font-medium text-ink transition hover:bg-amber/90"
                  >
                    Start writing
                  </Link>
                  <Link
                    to="/feed"
                    className="rounded-full border border-paper/30 px-8 py-3.5 text-sm font-medium text-paper transition hover:border-amber hover:text-amber"
                  >
                    Read the feed
                  </Link>
                </>
              )}
            </div>
          </div>

          {/* Editorial card */}
          <div className="relative">
            <div className="relative rounded-3xl border border-paper/10 bg-paper/5 p-8 backdrop-blur-sm md:p-10">
              <div className="mb-8 flex items-center justify-between">
                <span className="font-serif text-sm uppercase tracking-widest text-paper/60">
                  What is HomeVlog?
                </span>
                <span className="text-2xl text-amber">✳</span>
              </div>
              <ul className="space-y-5">
                {[
                  ['Write freely', 'Your vlogs, your voice. Publish with a click.'],
                  ['Read everyone', 'A shared feed of stories from real people.'],
                  ['Stay connected', 'See who wrote what — a community of words.'],
                ].map(([title, desc], i) => (
                  <li key={title} className="flex items-start gap-4 border-b border-paper/10 pb-5 last:border-0 last:pb-0">
                    <span className="mt-1 flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-amber/20 font-serif text-sm text-amber">
                      {i + 1}
                    </span>
                    <div>
                      <p className="font-medium text-paper">{title}</p>
                      <p className="mt-1 text-sm leading-relaxed text-paper/60">{desc}</p>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      </section>

      {/* Three pillars */}
      <section className="border-b border-ink/10 bg-paper">
        <div className="mx-auto grid max-w-6xl gap-px px-6 py-16 md:grid-cols-3 md:py-24">
          {[
            ['01', 'Write', 'A simple editor to capture your thoughts. No clutter, no distraction.'],
            ['02', 'Publish', 'Share your vlog to the feed for everyone to read.'],
            ['03', 'Discover', 'Read what others have written — find your people.'],
          ].map(([num, title, desc]) => (
            <div key={num} className="px-2 py-6 md:px-8">
              <span className="font-serif text-3xl text-clay">{num}</span>
              <h3 className="mt-4 font-serif text-2xl font-medium text-ink">{title}</h3>
              <p className="mt-3 text-sm leading-relaxed text-smoke">{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Footer CTA */}
      <section className="mx-auto max-w-6xl px-6 py-24 text-center">
        <p className="font-serif text-4xl font-medium tracking-tight text-ink md:text-5xl">
          Your story matters.
        </p>
        <p className="mt-4 text-smoke">Start writing today — it's free, and it's yours.</p>
        {!user && !loading && (
          <Link
            to="/signup"
            className="mt-8 inline-block rounded-full bg-forest px-8 py-3.5 text-sm font-medium text-paper transition hover:bg-forest/90"
          >
            Begin here
          </Link>
        )}
      </section>
    </div>
  )
}
