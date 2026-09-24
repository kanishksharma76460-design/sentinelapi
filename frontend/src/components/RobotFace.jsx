export default function RobotFace({ powering = false, terminated = false }) {
  const cls = 'robot-face' + (powering ? ' power' : '') + (terminated ? ' off' : '')
  return (
    <svg className={cls} viewBox="0 0 240 240" width="300" height="300" aria-hidden>
      <defs>
        <linearGradient id="rf-gold" x1="0" y1="0" x2="1" y2="1">
          <stop offset="0" stopColor="#fde68a" />
          <stop offset="1" stopColor="#fbbf24" />
        </linearGradient>
        <linearGradient id="rf-eye" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#eafff0" />
          <stop offset="0.45" stopColor="#39ff14" />
          <stop offset="1" stopColor="#0f7a1f" />
        </linearGradient>
        <radialGradient id="rf-aura" cx="0.5" cy="0.5" r="0.5">
          <stop offset="0" stopColor="#39ff14" stopOpacity="0.55" />
          <stop offset="1" stopColor="#39ff14" stopOpacity="0" />
        </radialGradient>
      </defs>

      {/* aura */}
      <circle cx="120" cy="120" r="112" fill="url(#rf-aura)" className="rf-aura" />

      {/* antenna */}
      <line x1="120" y1="16" x2="120" y2="5" stroke="#fbbf24" strokeWidth="2" />
      <circle cx="120" cy="5" r="4.5" fill="#39ff14" className="rf-antenna" />

      {/* outer helmet */}
      <path
        d="M120 14 L196 42 L214 120 L196 198 L120 226 L44 198 L26 120 L44 42 Z"
        fill="#0b1409" stroke="#39ff14" strokeWidth="3" strokeLinejoin="round"
        className="rf-helm"
      />
      {/* inner face plate */}
      <path
        d="M120 34 L178 56 L192 120 L178 184 L120 206 L62 184 L48 120 L62 56 Z"
        fill="#071006" stroke="rgba(57,255,20,0.35)" strokeWidth="1.5"
      />

      {/* brow crest (gold) */}
      <path d="M72 78 L120 62 L168 78 L160 92 L80 92 Z" fill="url(#rf-gold)" />

      {/* eyes — blink together */}
      <g className="rf-eye">
        <polygon points="78,112 112,103 119,112 112,125 78,120" fill="url(#rf-eye)" stroke="#39ff14" strokeWidth="1.5" />
        <polygon points="121,112 162,103 169,112 162,125 121,120" fill="url(#rf-eye)" stroke="#39ff14" strokeWidth="1.5" />
      </g>

      {/* nose ridge */}
      <rect x="116" y="112" width="8" height="34" fill="#39ff14" opacity="0.6" />

      {/* mouth grill */}
      <g className="rf-mouth">
        <rect x="82" y="152" width="76" height="5" fill="#39ff14" opacity="0.7" />
        <rect x="86" y="162" width="68" height="5" fill="#39ff14" opacity="0.5" />
        <rect x="90" y="172" width="60" height="5" fill="#39ff14" opacity="0.35" />
      </g>

      {/* cheek vents */}
      <g opacity="0.5" stroke="#39ff14" strokeWidth="2" fill="none">
        <line x1="54" y1="130" x2="72" y2="130" />
        <line x1="54" y1="138" x2="72" y2="138" />
        <line x1="168" y1="130" x2="186" y2="130" />
        <line x1="168" y1="138" x2="186" y2="138" />
      </g>

      {/* chin light (gold) */}
      <rect x="110" y="198" width="20" height="6" fill="#fbbf24" opacity="0.6" />
    </svg>
  )
}
