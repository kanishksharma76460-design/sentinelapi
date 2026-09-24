// Precise HUD structure rendered behind the hero eyes — a coded, robotic
// reticle: crosshair, concentric rings, degree ticks, counter-rotating
// dashed hexagons, corner brackets and monospace telemetry labels.
const CX = 350
const CY = 150

function polar(r, deg) {
  const a = (deg * Math.PI) / 180
  return [CX + r * Math.cos(a), CY + r * Math.sin(a)].map(n => +n.toFixed(2))
}

function hexPts(r, rot = 0) {
  return Array.from({ length: 6 }, (_, i) => polar(r, rot + i * 60).map(String).join(',')).join(' ')
}

function ticks(r1, r2, step = 15) {
  const lines = []
  for (let d = 0; d < 360; d += step) {
    const [x1, y1] = polar(r1, d)
    const [x2, y2] = polar(r2, d)
    lines.push(<line key={d} x1={x1} y1={y1} x2={x2} y2={y2} className="hg-tick" />)
  }
  return lines
}

export default function HeroGrid() {
  return (
    <svg className="hero-grid" viewBox="0 0 700 300" aria-hidden>
      {/* crosshair */}
      <line x1="0" y1={CY} x2="700" y2={CY} className="hg-line" />
      <line x1={CX} y1="0" x2={CX} y2="300" className="hg-line v" />

      {/* target rings */}
      <circle cx={CX} cy={CY} r="132" className="hg-ring" />
      <circle cx={CX} cy={CY} r="102" className="hg-ring faint" />
      <circle cx={CX} cy={CY} r="72" className="hg-ring faint" />

      {/* degree ticks */}
      {ticks(130, 134, 15)}

      {/* counter-rotating dashed hexagons */}
      <g className="hg-spin"><polygon points={hexPts(102, 30)} className="hg-hex" /></g>
      <g className="hg-spin-rev"><polygon points={hexPts(72, 0)} className="hg-hex gold" /></g>

      {/* corner brackets */}
      <path d="M22 34 V14 H42" className="hg-bracket" />
      <path d="M658 14 H678 V34" className="hg-bracket" />
      <path d="M22 266 V286 H42" className="hg-bracket" />
      <path d="M658 286 H678 V266" className="hg-bracket" />

      {/* coded telemetry */}
      <text x="34" y="66" className="hg-code">SCAN VECTOR // θ = 60°</text>
      <text x="520" y="66" className="hg-code">φ 1.618034</text>
      <text x="34" y="252" className="hg-code">01101001 01110010 01101001 01110011</text>
      <text x="480" y="252" className="hg-code">LAT 37.7749 · LON -122.4194</text>
    </svg>
  )
}
