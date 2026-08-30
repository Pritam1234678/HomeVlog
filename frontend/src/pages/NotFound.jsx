import { Link } from 'react-router-dom'

export default function NotFound() {
  return (
    <div className="flex min-h-[calc(100vh-73px)] items-center justify-center px-6 py-24">
      <div className="text-center">
        <p className="font-serif text-7xl font-medium tracking-tight text-clay md:text-9xl">404</p>
        <p className="mt-6 font-serif text-3xl text-ink md:text-4xl">This page wandered off</p>
        <p className="mx-auto mt-3 max-w-sm text-sm leading-relaxed text-smoke">
          The page you're looking for doesn't exist, or it never did. Either way, you're safe here.
        </p>
        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <Link
            to="/"
            className="rounded-full bg-forest px-7 py-3 text-sm font-medium text-paper transition hover:bg-forest/90"
          >
            ← Back home
          </Link>
          <Link
            to="/feed"
            className="rounded-full border border-ink/15 px-7 py-3 text-sm font-medium text-ink transition hover:border-clay hover:text-clay"
          >
            Read the feed
          </Link>
        </div>
      </div>
    </div>
  )
}
