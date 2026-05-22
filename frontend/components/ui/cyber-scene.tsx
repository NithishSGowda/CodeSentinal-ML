'use client'

import { useEffect, useRef } from 'react'

/**
 * CyberScene — Cinematic 3D Holographic AI Security Assistant Robot
 * 
 * Features:
 *  - 3D Humanoid holographic robot centerpiece (head, collar/chest, neck)
 *  - Rotating cyber visor & animated breathing eyes
 *  - Tilted neural halo orbital ring with orbiting node indicators
 *  - Dynamic mouse tracking (robot looks towards cursor)
 *  - Floating cyber particles and glowing central reactor
 *  - Self-contained procedural geometry for 100% offline robustness
 */
export function CyberScene({ className }: { className?: string }) {
  const mountRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!mountRef.current) return
    let active = true
    let animId: number = 0
    let renderer: any = null
    let sceneRef: any = null
    let mouseMoveHandler: any = null
    let resizeHandler: any = null
    const mountElement = mountRef.current

    // Viewport visibility observer to pause rendering when off-screen
    let isVisible = true
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        isVisible = entry.isIntersecting
      })
    }, { threshold: 0.05 })
    observer.observe(mountElement)

    // ── Lazy import Three to ensure Next.js SSR compatibility ────────────────
    import('three').then((THREE) => {
      if (!active) return

      let currentW = mountElement.clientWidth  || 500
      let currentH = mountElement.clientHeight || 500
      let bounds = mountElement.getBoundingClientRect()

      // Renderer
      renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: 'high-performance' })
      renderer.setPixelRatio(1)
      renderer.setSize(currentW, currentH)
      renderer.setClearColor(0x000000, 0)
      mountElement.appendChild(renderer.domElement)

      // Scene & Camera
      const scene  = new THREE.Scene()
      sceneRef = scene
      const camera = new THREE.PerspectiveCamera(50, currentW / currentH, 0.1, 500)
      camera.position.set(0, 0.2, 6.2)

      // ── Ambient Lighting (Holographic style) ─────────────────────────────
      const lightsGroup = new THREE.Group()
      scene.add(lightsGroup)
      
      const light1 = new THREE.PointLight(0x00f0ff, 1.5, 50)
      light1.position.set(5, 5, 5)
      lightsGroup.add(light1)
      
      const light2 = new THREE.PointLight(0x8b5cf6, 1.5, 50)
      light2.position.set(-5, -5, 5)
      lightsGroup.add(light2)

      // ── 1. PROCEDURAL HOLOGRAPHIC AI ROBOT ───────────────────────────────
      const robotGroup = new THREE.Group()
      scene.add(robotGroup)

      // A. Robot Head Group (for local looking rotations)
      const headGroup = new THREE.Group()
      headGroup.position.set(0, 0.4, 0)
      robotGroup.add(headGroup)

      // Skull Geometry (holographic wireframe)
      const skullGeo = new THREE.SphereGeometry(0.85, 18, 18)
      const skullWireMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        wireframe: true,
        transparent: true,
        opacity: 0.38,
      })
      const skullSolidMat = new THREE.MeshBasicMaterial({
        color: 0x040614,
        transparent: true,
        opacity: 0.85,
      })
      const skullWire = new THREE.Mesh(skullGeo, skullWireMat)
      const skullSolid = new THREE.Mesh(skullGeo, skullSolidMat)
      headGroup.add(skullSolid)
      headGroup.add(skullWire)

      // Visor / Mask Plate
      const visorGeo = new THREE.CylinderGeometry(0.87, 0.87, 0.25, 18, 1, true, 0, Math.PI)
      const visorMat = new THREE.MeshBasicMaterial({
        color: 0xff007f,
        transparent: true,
        opacity: 0.75,
        side: THREE.DoubleSide
      })
      const visor = new THREE.Mesh(visorGeo, visorMat)
      visor.rotation.x = Math.PI / 2
      visor.position.set(0, 0, 0.06)
      headGroup.add(visor)

      // Glowing Eyes
      const eyeGeo = new THREE.SphereGeometry(0.07, 8, 8)
      const eyeMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        transparent: true,
        opacity: 0.95,
      })
      const leftEye = new THREE.Mesh(eyeGeo, eyeMat)
      leftEye.position.set(-0.25, 0.0, 0.8)
      const rightEye = new THREE.Mesh(eyeGeo, eyeMat)
      rightEye.position.set(0.25, 0.0, 0.8)
      headGroup.add(leftEye)
      headGroup.add(rightEye)

      // Rotating ear antennas
      const earGeo = new THREE.TorusGeometry(0.22, 0.015, 6, 24)
      const earMat = new THREE.MeshBasicMaterial({
        color: 0x8b5cf6,
        transparent: true,
        opacity: 0.55
      })
      const leftEar = new THREE.Mesh(earGeo, earMat)
      leftEar.position.set(-0.9, 0, 0)
      leftEar.rotation.y = Math.PI / 2
      const rightEar = new THREE.Mesh(earGeo, earMat)
      rightEar.position.set(0.9, 0, 0)
      rightEar.rotation.y = Math.PI / 2
      headGroup.add(leftEar)
      headGroup.add(rightEar)

      // Tilted Orbital Halo Ring around the Head
      const haloGeo = new THREE.TorusGeometry(1.4, 0.012, 6, 64)
      const haloMat = new THREE.MeshBasicMaterial({
        color: 0x8b5cf6,
        transparent: true,
        opacity: 0.45
      })
      const haloRing = new THREE.Mesh(haloGeo, haloMat)
      haloRing.rotation.x = Math.PI / 2.3
      headGroup.add(haloRing)

      // Halo data nodes (floating node modules)
      const haloNodeGeo = new THREE.SphereGeometry(0.045, 8, 8)
      const haloNodeMat = new THREE.MeshBasicMaterial({ color: 0x00f0ff })
      const haloNodes: any[] = []
      const HALO_NODES_COUNT = 5
      for (let i = 0; i < HALO_NODES_COUNT; i++) {
        const node = new THREE.Mesh(haloNodeGeo, haloNodeMat)
        headGroup.add(node)
        haloNodes.push(node)
      }

      // B. Neck (Cylinder connecting head and collar)
      const neckGeo = new THREE.CylinderGeometry(0.22, 0.28, 0.45, 16)
      const neckMat = new THREE.MeshBasicMaterial({
        color: 0x8b5cf6,
        wireframe: true,
        transparent: true,
        opacity: 0.4
      })
      const neck = new THREE.Mesh(neckGeo, neckMat)
      neck.position.set(0, -0.62, 0)
      robotGroup.add(neck)

      // C. Upper Chest / Collar Group (stabilized underneath)
      const chestGroup = new THREE.Group()
      chestGroup.position.set(0, -1.3, 0)
      robotGroup.add(chestGroup)

      const collarGeo = new THREE.CylinderGeometry(0.55, 1.15, 0.65, 16, 2, true)
      const collarMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff,
        wireframe: true,
        transparent: true,
        opacity: 0.25
      })
      const collar = new THREE.Mesh(collarGeo, collarMat)
      chestGroup.add(collar)

      // Central Reactor (pulsing chest core)
      const reactorGeo = new THREE.SphereGeometry(0.2, 16, 16)
      const reactorMat = new THREE.MeshBasicMaterial({
        color: 0xff007f,
        transparent: true,
        opacity: 0.95
      })
      const reactor = new THREE.Mesh(reactorGeo, reactorMat)
      reactor.position.set(0, 0, 0.65)
      chestGroup.add(reactor)

      // ── 2. OUTER DATA NODE PARTICLES ─────────────────────────────────────
      const ptCount    = 180
      const ptPositions = new Float32Array(ptCount * 3)
      const ptColors    = new Float32Array(ptCount * 3)
      const PALETTE = [
        new THREE.Color(0x00f0ff),
        new THREE.Color(0x8b5cf6),
        new THREE.Color(0xff007f),
      ]
      for (let i = 0; i < ptCount; i++) {
        const phi   = Math.acos(-1 + (2 * i) / ptCount)
        const theta = Math.sqrt(ptCount * Math.PI) * phi
        const r     = 3.2 + Math.random() * 1.3
        ptPositions[i * 3]     = r * Math.sin(phi) * Math.cos(theta)
        ptPositions[i * 3 + 1] = r * Math.sin(phi) * Math.sin(theta) + 0.4
        ptPositions[i * 3 + 2] = r * Math.cos(phi)
        const col = PALETTE[i % 3]
        ptColors[i * 3] = col.r; ptColors[i * 3 + 1] = col.g; ptColors[i * 3 + 2] = col.b
      }
      const ptGeo = new THREE.BufferGeometry()
      ptGeo.setAttribute('position', new THREE.BufferAttribute(ptPositions, 3))
      ptGeo.setAttribute('color',    new THREE.BufferAttribute(ptColors,    3))
      const ptMat = new THREE.PointsMaterial({
        size: 0.04, vertexColors: true, transparent: true, opacity: 0.65,
      })
      const points = new THREE.Points(ptGeo, ptMat)
      scene.add(points)

      // ── 3. SCAN LASER SWEEP (Procedural horizontal ring) ────────────────
      const scanRingGeo = new THREE.TorusGeometry(1.6, 0.008, 6, 64)
      const scanRingMat = new THREE.MeshBasicMaterial({
        color: 0x00f0ff, transparent: true, opacity: 0.6,
      })
      const scanRing = new THREE.Mesh(scanRingGeo, scanRingMat)
      scanRing.rotation.x = Math.PI / 2
      scene.add(scanRing)

      // ── 4. MOUSE FOLLOW EVENT LISTENER ──────────────────────────────────
      let mouseX = 0
      let mouseY = 0
      mouseMoveHandler = (e: MouseEvent) => {
        mouseX = ((e.clientX - bounds.left) / currentW) * 2 - 1
        mouseY = -((e.clientY - bounds.top) / currentH) * 2 + 1
      }
      window.addEventListener('mousemove', mouseMoveHandler)

      // ── ANIMATION LOOP (Targeted 60 FPS cap to prevent heat and CPU spikes) ──────
      let frame = 0
      let lastTime = performance.now()
      const interval = 1000 / 60 // 16.7ms for 60 FPS

      function animate(currentTime: number = performance.now()) {
        if (!active) return
        animId = requestAnimationFrame(animate)

        // Do not render or run calculations if the scene is scrolled out of view
        if (!isVisible) return

        const delta = currentTime - lastTime
        if (delta < interval) return

        lastTime = currentTime - (delta % interval)
        frame++
        const t = frame * 0.008

        // A. Floating motion (Sine translation)
        const floatY = Math.sin(t * 1.5) * 0.12
        robotGroup.position.y = floatY

        // B. Ears slow spin
        leftEar.rotation.z = t * 0.8
        rightEar.rotation.z = -t * 0.8

        // C. Halo orbital rotation
        haloRing.rotation.z = t * 0.35

        // D. Positioning nodes along tilted ring
        haloNodes.forEach((node, i) => {
          const angle = (i / HALO_NODES_COUNT) * Math.PI * 2 + t * 0.35
          const rx = Math.cos(angle) * 1.4
          const rz = Math.sin(angle) * 1.4
          // Project points on the tilted plane matching ring rotation
          node.position.set(rx, Math.sin(angle) * 0.3, rz)
        })

        // E. Reactor & eye blinking pulse
        const pulse = 1.0 + 0.22 * Math.sin(t * 4.5)
        reactor.scale.setScalar(pulse)
        leftEye.scale.y = 0.85 + 0.15 * Math.abs(Math.sin(t * 0.4))
        rightEye.scale.y = 0.85 + 0.15 * Math.abs(Math.sin(t * 0.4))

        // F. Interactive Mouse Rotation (Smooth LERP)
        const targetHeadX = mouseY * 0.22
        const targetHeadY = mouseX * 0.32
        headGroup.rotation.x += (targetHeadX - headGroup.rotation.x) * 0.075
        headGroup.rotation.y += (targetHeadY - headGroup.rotation.y) * 0.075

        // Collar moves slightly less to mimic a natural collar bone
        chestGroup.rotation.x += (targetHeadX * 0.35 - chestGroup.rotation.x) * 0.075
        chestGroup.rotation.y += (targetHeadY * 0.35 - chestGroup.rotation.y) * 0.075

        // G. Laser Sweep Sweep
        scanRing.position.y = Math.sin(t * 0.9) * 1.2
        ;(scanRing.material as any).opacity = 0.3 + 0.45 * Math.abs(Math.sin(t * 0.9))

        // H. Scanned particle clouds slow spin
        points.rotation.y = t * 0.04
        points.rotation.x = t * 0.02

        // I. Subtle camera drift
        camera.position.x = Math.sin(t * 0.08) * 0.4
        camera.lookAt(0, 0, 0)

        renderer.render(scene, camera)
      }
      animate()

      // Resize event
      resizeHandler = () => {
        if (!mountElement) return
        currentW = mountElement.clientWidth  || 500
        currentH = mountElement.clientHeight || 500
        bounds = mountElement.getBoundingClientRect()
        camera.aspect = currentW / currentH
        camera.updateProjectionMatrix()
        renderer.setSize(currentW, currentH)
      }
      window.addEventListener('resize', resizeHandler)
    })

    return () => {
      active = false
      if (animId) {
        cancelAnimationFrame(animId)
      }
      if (mouseMoveHandler) {
        window.removeEventListener('mousemove', mouseMoveHandler)
      }
      if (resizeHandler) {
        window.removeEventListener('resize', resizeHandler)
      }
      if (sceneRef) {
        sceneRef.traverse((object: any) => {
          if (!object.isMesh && !object.isPoints) return
          if (object.geometry) object.geometry.dispose()
          if (object.material) {
            if (Array.isArray(object.material)) {
              object.material.forEach((mat: any) => mat.dispose())
            } else {
              object.material.dispose()
            }
          }
        })
      }
      if (renderer) {
        renderer.dispose()
        if (mountElement && renderer.domElement && mountElement.contains(renderer.domElement)) {
          mountElement.removeChild(renderer.domElement)
        }
      }
      if (observer) {
        observer.disconnect()
      }
    }
  }, [])

  return (
    <div
      ref={mountRef}
      className={className}
      style={{ background: 'transparent' }}
    />
  )
}
