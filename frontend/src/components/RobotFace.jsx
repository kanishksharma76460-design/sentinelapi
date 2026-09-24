// AEGIS Core — a mathematically precise geometric gateway.
// A 12-fold (dodecagonal) lattice with a central hexagonal aperture iris,
// sized by the golden ratio (φ ≈ 1.618).
const CX = 170
const CY = 170
const PHI = 1.618034

function polar(r, deg) {
  const a = (deg * Math.PI) / 180
  return [CX + r * Math.cos(a), CY + r * Math.sin(a)].map(n => +n.toFixed(2))
}

function hexPts(r, rot = 0) {
  return Array.from({ length: 6 }, (_, i) => polar(r, rot + i * 60).map(String).join(',')).join(' ')
}

// radial tick marks every `step` degrees between r1 and r2
function Ticks({ r1, r2, step = 6, major = 30, className = '' }) {
  const els = []
  for (let d = 0; d < 360; d += step) {
    const [x1, y1] = polar(r1, d)
    const [x2, y2] = polar(r2, d)
    els.push(
      <line key={d} x1={x1} y1={y1} x2={x2} y2={y2}
        className={d % major === 0 ? 'tick major' : 'tick'} />
    )
  }
  return <g className={className}>{els}</g>
}

// A camera-shutter blade: a 60° sector slat from the outer ring to the pupil.
function bladePath(d) {
  const [xo1, yo1] = polar(94, d + 30)
  const [xo2, yo2] = polar(94, d - 30)
  const [xi1, yi1] = polar(26, d - 30)
  const [xi2, yi2] = polar(26, d + 30)
  return `M ${xo1} ${yo1} A 94 94 0 0 1 ${xo2} ${yo2} L ${xi1} ${yi1} A 26 26 0 0 0 ${xi2} ${yi2} Z`
}

export default function RobotFace({ powering = false, terminated = false }) {
  const cls = 'robot-face' + (powering ? ' power' : '') + (terminated ? ' off' : '')

  // φ-scaled ring radii
  const r1 = 150
  const r2 = r1 / PHI          // ≈ 92.7 — outer rotating hex ring
  const r3 = r2 / PHI          // ≈ 57.3 — inner hex ring
  const rGold = r3 / PHI       // ≈ 35.4 — gold ring
  const rPupil = 15

  return (
    <svg className={cls} viewBox="0 0 340 340" width="330" height="330" aria-hidden>
      <defs>
        <radialGradient id="rg-aura" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor="#39ff14" stopOpacity="0.5" />
          <stop offset="0.6" stopColor="#39ff14" stopOpacity="0.12" />
          <stop offset="1" stopColor="#39ff14" stopOpacity="0" />
        </radialGradient>
        <radialGradient id="rg-iris" cx="0.5" cy="0.42" r="0.72">
          <stop offset="0" stopColor="#eafff0" />
          <stop offset="0.45" stopColor="#39ff14" />
          <stop offset="0.82" stopColor="#0f7a1f" />
          <stop offset="1" stopColor="#03270a" />
        </radialGradient>
        <linearGradient id="rg-gold" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fde68a" />
          <stop offset="1" stopColor="#f59e0b" />
        </linearGradient>
      </defs>

      {/* aura */}
      <circle cx={CX} cy={CY} r={r1 + 8} fill="url(#rg-aura)" className="rg-aura" />

      {/* tick ring (static, 12-fold) */}
      <Ticks r1={r1 - 2} r2={r1 + 2} step={6} major={30} className="rg-ticks" />

      {/* outer hexagon (static, glowing) */}
      <polygon points={hexPts(r1, 0)} className="rg-hex1" />
      <polygon points={hexPts(r1, 30)} className="rg-hex1b" />

      {/* rotating dashed hex rings */}
      <g className="rg-spin">
        <polygon points={hexPts(r2, 0)} className="rg-hex2" />
      </g>
      <g className="rg-spin-rev">
        <polygon points={hexPts(r2 * 0.72, 30)} className="rg-hex3" />
      </g>

      {/* inner hex ring (static) */}
      <polygon points={hexPts(r3, 0)} className="rg-hex4" />

      {/* gold ring */}
      <circle cx={CX} cy={CY} r={rGold} className="rg-goldring" />

      {/* aperture iris — 6 shutter blades + pupil */}
      <g className="rg-iris">
        {[0, 60, 120, 180, 240, 300].map(d => (
          <path key={d} d={bladePath(d)} className="rg-blade" />
        ))}
        <circle cx={CX} cy={CY} r={rPupil} className="rg-pupil" />
        <circle cx={CX} cy={CY} r={rPupil * 0.45} className="rg-pupil-core" />
      </g>

      {/* gold vertex markers on outer hexagon */}
      {Array.from({ length: 6 }, (_, i) => {
        const [x, y] = polar(r1, i * 60)
        return <circle key={i} cx={x} cy={y} r="4" className="rg-vertex" />
      })}

      {/* antenna */}
      <line x1={CX} y1={CY - r1} x2={CX} y2={CY - r1 - 18} className="rg-antenna-line" />
      <circle cx={CX} cy={CY - r1 - 20} r="5" className="rg-antenna" />
    </svg>
  )
}
