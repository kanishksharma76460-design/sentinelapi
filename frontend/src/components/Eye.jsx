import { useEffect, useRef, useState } from 'react'

// Robotic eye — closed during boot (glowing lid), then opens; blinks
// periodically, tracks the cursor, sweeps while scanning, and turns
// green (ACCESS GRANTED) or red (THREAT) on completion.
export default function Eye({ scanning, done, grade, open = true }) {
  const ref = useRef(null)
  const [blink, setBlink] = useState(false)

  // periodic blink
  useEffect(() => {
    const t = setInterval(() => {
      setBlink(true)
      setTimeout(() => setBlink(false), 150)
    }, 4200)
    return () => clearInterval(t)
  }, [])

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
    !open ? 'closed' : '',
    blink ? 'blink' : '',
    scanning ? 'scanning' : '',
    done ? (grade && grade.grade === 'A' ? 'approved' : 'threat') : ''
  ].filter(Boolean).join(' ')

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
