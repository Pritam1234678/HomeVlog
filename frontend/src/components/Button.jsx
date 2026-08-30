export default function Button({ children, variant = 'primary', className = '', ...props }) {
  const base =
    'inline-flex items-center justify-center rounded-full px-6 py-3 text-sm font-medium transition-all focus:outline-none focus:ring-2 focus:ring-forest focus:ring-offset-2 focus:ring-offset-paper disabled:opacity-50 disabled:cursor-not-allowed'
  const variants = {
    primary: 'bg-forest text-paper hover:bg-forest/90',
    clay: 'bg-clay text-paper hover:bg-clay-dark',
    secondary: 'border border-ink/15 text-ink hover:border-forest hover:text-forest',
    ghost: 'text-ink-soft hover:text-clay',
    danger: 'border border-clay/30 text-clay hover:bg-clay hover:text-paper',
  }
  return (
    <button className={`${base} ${variants[variant]} ${className}`} {...props}>
      {children}
    </button>
  )
}
