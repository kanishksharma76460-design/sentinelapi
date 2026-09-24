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
          <stop offset="0" stopColor="#fef3c7" />
          <stop offset="0.4" stopColor="#fbbf24" />
          <stop offset="0.75" stopColor="#b45309" />
          <stop offset="1" stopColor="#451a03" />
        </radialGradient>
        <radialGradient id="lg-pupil" cx="50%" cy="50%" r="50%">
          <stop offset="0" stopColor="#000000" />
          <stop offset="1" stopColor="#0b1a20" />
        </radialGradient>
      </defs>

      {/* hexagonal shield */}
      <path d="M32 2 L58 10 V30 C58 45.5 46.5 55.5 32 62 C17.5 55.5 6 45.5 6 30 V10 Z"
        stroke="url(#lg-shield)" strokeWidth="3" fill="rgba(251,191,36,0.06)" strokeLinejoin="round" />
      <path d="M32 6.5 L53.5 12.8 V30 C53.5 43 43.5 52 32 57.8 C20.5 52 10.5 43 10.5 30 V12.8 Z"
        stroke="#fbbf24" strokeWidth="0.75" opacity="0.4" fill="none" />

      {/* iris (eye) */}
      <circle cx="32" cy="32" r="16.5" stroke="#fbbf24" strokeWidth="1.5" fill="url(#lg-iris)" />
      <circle cx="32" cy="32" r="11.5" stroke="rgba(0,0,0,0.35)" strokeWidth="0.8" fill="none" />
      <circle cx="32" cy="32" r="6.5" fill="url(#lg-pupil)" stroke="#fbbf24" strokeWidth="0.5" />

      {/* glint / specular highlight */}
      <circle cx="25" cy="24" r="3.4" fill="#fff8e7" opacity="0.95" />
      <circle cx="27.5" cy="26" r="1.4" fill="#ffffff" opacity="0.8" />

      {/* scan beam */}
      <line x1="15" y1="32" x2="49" y2="32" stroke="#fde68a" strokeWidth="1" opacity="0.65" />
      <line x1="32" y1="15" x2="32" y2="49" stroke="#fde68a" strokeWidth="1" opacity="0.25" />
    </svg>
  )
}
