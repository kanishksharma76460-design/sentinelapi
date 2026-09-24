import { useEffect, useRef } from 'react'
import * as THREE from 'three'

// Dark-luxury dot-matrix globe + orbiting ring, rendered behind the hero.
export default function Globe() {
  const ref = useRef(null)

  useEffect(() => {
    const el = ref.current
    if (!el) return

    const scene = new THREE.Scene()
    const camera = new THREE.PerspectiveCamera(50, el.clientWidth / el.clientHeight, 0.1, 100)
    camera.position.z = 7.5

    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true })
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2))
    renderer.setSize(el.clientWidth, el.clientHeight)
    el.appendChild(renderer.domElement)

    const group = new THREE.Group()
    scene.add(group)

    // Dot-matrix sphere
    const R = 2.3
    const count = 2600
    const pos = new Float32Array(count * 3)
    for (let i = 0; i < count; i++) {
      const lat = Math.acos(2 * Math.random() - 1) - Math.PI / 2
      const lon = Math.random() * Math.PI * 2
      pos[i * 3] = R * Math.cos(lat) * Math.cos(lon)
      pos[i * 3 + 1] = R * Math.sin(lat)
      pos[i * 3 + 2] = R * Math.cos(lat) * Math.sin(lon)
    }
    const geo = new THREE.BufferGeometry()
    geo.setAttribute('position', new THREE.BufferAttribute(pos, 3))
    const sphere = new THREE.Points(geo, new THREE.PointsMaterial({
      color: 0x8b8bd6, size: 0.02, transparent: true, opacity: 0.55, depthWrite: false
    }))
    group.add(sphere)

    // Faint wireframe shell
    const shell = new THREE.Mesh(
      new THREE.SphereGeometry(R + 0.02, 36, 36),
      new THREE.MeshBasicMaterial({ color: 0x6366f1, wireframe: true, transparent: true, opacity: 0.06 })
    )
    group.add(shell)

    // Two rings
    const ring1 = new THREE.Mesh(
      new THREE.TorusGeometry(R + 0.7, 0.006, 8, 160),
      new THREE.MeshBasicMaterial({ color: 0x22d3ee, transparent: true, opacity: 0.18 })
    )
    ring1.rotation.x = Math.PI / 2.6
    const ring2 = new THREE.Mesh(
      new THREE.TorusGeometry(R + 1.05, 0.005, 8, 160),
      new THREE.MeshBasicMaterial({ color: 0x8b5cf6, transparent: true, opacity: 0.12 })
    )
    ring2.rotation.x = Math.PI / 1.7
    group.add(ring1, ring2)

    let raf
    const animate = () => {
      group.rotation.y += 0.0016
      ring1.rotation.z += 0.0008
      ring2.rotation.z -= 0.0006
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
  }, [])

  return <div ref={ref} className="globe" />
}
