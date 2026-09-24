import { useEffect, useRef } from 'react'
import * as THREE from 'three'

const SEV_COLORS = {
  CRITICAL: 0xf43f5e,
  HIGH: 0xfb923c,
  MEDIUM: 0xfacc15,
  LOW: 0x38bdf8
}
const SEV_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

// Rotating 3D hub-and-spoke graph of the vulnerable endpoints.
export default function AttackGraph({ findings }) {
  const ref = useRef(null)

  useEffect(() => {
    const el = ref.current
    if (!el || !findings || !findings.length) return

    const map = {}
    findings.forEach(f => {
      const k = f.endpoint || '?'
      if (!map[k]) map[k] = { endpoint: k, sev: f.severity || 'LOW', count: 0 }
      map[k].count++
      if (SEV_ORDER[f.severity] < SEV_ORDER[map[k].sev]) map[k].sev = f.severity
    })
    const nodes = Object.values(map)

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(45, el.clientWidth / el.clientHeight, 0.1, 100)
    camera.position.set(0, 1.4, 12)

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setSize(el.clientWidth, el.clientHeight)
    el.appendChild(renderer.domElement)

    const group = new THREE.Group()
    scene.add(group)

    // Hub
    const hub = new THREE.Mesh(
      new THREE.SphereGeometry(0.55, 32, 32),
      new THREE.MeshBasicMaterial({ color: 0x8b5cf6 })
    )
    const hubGlow = new THREE.Mesh(
      new THREE.SphereGeometry(0.85, 32, 32),
      new THREE.MeshBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.16 })
    )
    group.add(hub, hubGlow)

    const nodeMeshes = []
    nodes.forEach((n, i) => {
      const ang = (i / nodes.length) * Math.PI * 2
      const x = Math.cos(ang) * 4.4
      const z = Math.sin(ang) * 4.4
      const y = (Math.sin(ang * 2.3)) * 0.9
      const color = SEV_COLORS[n.sev] || 0x38bdf8
      const size = 0.32 + Math.min(n.count * 0.14, 0.45)

      const mesh = new THREE.Mesh(
        new THREE.SphereGeometry(size, 22, 22),
        new THREE.MeshBasicMaterial({ color })
      )
      mesh.position.set(x, y, z)
      group.add(mesh)
      nodeMeshes.push(mesh)

      const lineGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(0, 0, 0),
        new THREE.Vector3(x, y, z)
      ])
      const line = new THREE.Line(lineGeo, new THREE.LineBasicMaterial({
        color, transparent: true, opacity: 0.3
      }))
      group.add(line)
    })

    let raf
    const animate = () => {
      group.rotation.y += 0.0045
      nodeMeshes.forEach((m, i) => {
        const s = 1 + Math.sin(Date.now() * 0.004 + i * 0.9) * 0.1
        m.scale.setScalar(s)
      })
      renderer.render(scene, camera)
      raf = requestAnimationFrame(animate)
    }
    animate()

    const onResize = () => {
      camera.aspect = el.clientWidth / el.clientHeight
      camera.updateProjectionMatrix()
      renderer.setSize(el.clientWidth, el.clientHeight)
    }
    window.addEventListener('resize', onResize)

    return () => {
      cancelAnimationFrame(raf)
      window.removeEventListener('resize', onResize)
      renderer.dispose()
      if (renderer.domElement.parentNode === el) el.removeChild(renderer.domElement)
    }
  }, [findings])

  const legend = [
    ['#f43f5e', 'Critical'],
    ['#fb923c', 'High'],
    ['#facc15', 'Medium'],
    ['#38bdf8', 'Low']
  ]

  return (
    <div className="attack-wrap">
      <div ref={ref} style={{ width: '100%', height: '100%' }} />
      <div className="legend">
        {legend.map(([c, l]) => (
          <span key={l}><i style={{ background: c }} />{l}</span>
        ))}
      </div>
    </div>
  )
}
