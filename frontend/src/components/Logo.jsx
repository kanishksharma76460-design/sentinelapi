// Athera Secure emblem — a hexagonal shield with a scanning robotic iris.
export default function Logo({ size = 30 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg" style={{ display: 'block' }}>
      <defs>
        <linearGradient id="lg-shield" x1="8" y1="2" x2="56" y2="62" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#fde68a" />
          <stop offset="0.5" stopColor="#fbbf24" />
          <stop offset="1" stopColor="#b45309" />
        </linearGradient>
        <radialGradient id="lg-iris" cx="45%" cy="40%" r="65%">
          <stop offset="0" stopColor="#eafff0" />
          <stop offset="0.4" stopColor="#39ff14" />
          <stop offset="0.75" stopColor="#0f7a1f" />
          <stop offset="1" stopColor="#03270a" />
        </radialGradient>
        <radialGradient id="lg-pupil" cx="50%" cy="50%" r="50%">
          <stop offset="0" stopColor="#000000" />
          <stop offset="1" stopColor="#0b1a20" />
        </radialGradient>
      </defs>

      {/* hexagonal shield */}
      <path d="M32 2 L58 10 V30 C58 45.5 46.5 55.5 32 62 C17.5 55.5 6 45.5 6 30 V10 Z"
        stroke="url(#lg-shield)" strokeWidth="3" fill="rgba(57,255,20,0.06)" strokeLinejoin="round" />
      <path d="M32 6.5 L53.5 12.8 V30 C53.5 43 43.5 52 32 57.8 C20.5 52 10.5 43 10.5 30 V12.8 Z"
        stroke="#39ff14" strokeWidth="0.75" opacity="0.4" fill="none" />

      {/* iris (hexagonal eye) */}
      <polygon points="16,32 24,14.5 40,14.5 48,32 40,49.5 24,49.5" fill="url(#lg-iris)" stroke="#39ff14" strokeWidth="1.5" strokeLinejoin="round" />

      {/* slit pupil */}
      <polygon points="23,32 27,28.5 37,28.5 41,32 37,35.5 27,35.5" fill="#020a03" stroke="#39ff14" strokeWidth="0.6" />

      {/* glint / specular highlight */}
      <circle cx="26" cy="24" r="3.4" fill="#f0fff0" opacity="0.95" />
      <circle cx="28.5" cy="26" r="1.4" fill="#ffffff" opacity="0.8" />

      {/* scan beam */}
      <line x1="15" y1="32" x2="49" y2="32" stroke="#c8ffd0" strokeWidth="1" opacity="0.65" />
      <line x1="32" y1="15" x2="32" y2="49" stroke="#c8ffd0" strokeWidth="1" opacity="0.25" />
    </svg>
  )
}
