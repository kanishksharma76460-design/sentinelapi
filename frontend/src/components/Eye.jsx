import { useEffect, useRef } from 'react'

// Robotic overseer eye — blinks, tracks the cursor, sweeps while scanning,
// and glows green/red when the analysis completes.
export default function Eye({ scanning, done, grade }) {
  const ref = useRef(null)

  // Iris tracks the cursor
  useEffect(() => {
    const onMove = e => {
      const el = ref.current
      if (!el) return
      const r = el.getBoundingClientRect()
      const dx = (e.clientX - (r.left + r.width / 2)) / (r.width / 2)
      const dy = (e.clientY - (r.top + r.height / 2)) / (r.height / 2)
      el.style.setProperty('--px', Math.max(-1, Math.min(1, dx)).toFixed(3))
      el.style.setProperty('--py', Math.max(-1, Math.min(1, dy)).toFixed(3))
    }
    window.addEventListener('mousemove', onMove)
    return () => window.removeEventListener('mousemove', onMove)
  }, [])

  const cls = [
    'eye',
    scanning ? 'scanning' : '',
    done ? (grade && grade.grade === 'A' ? 'approved' : 'threat') : ''
  ].join(' ')

  return (
    <div className={cls} ref={ref} aria-label="scanning eye">
      <div className="eye-outer">
        <div className="eye-segments" />
        <div className="eye-sclera" />
        <div className="eye-iris">
          <div className="eye-pupil" />
          <div className="eye-ring-1" />
          <div className="eye-ring-2" />
        </div>
        <div className="eye-lid" />
        <div className="eye-sweep" />
        <div className="eye-glint" />
      </div>
    </div>
  )
}
