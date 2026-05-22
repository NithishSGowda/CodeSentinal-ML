/**
 * static/js/tunnel.js
 * Premium canvas animation: animated particle grid + morphing orbs
 * Inspired by UIverse.io & CTA.gallery aesthetics
 */
(function () {
  const canvas = document.getElementById('bg-canvas');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');

  let W = canvas.width  = window.innerWidth;
  let H = canvas.height = window.innerHeight;

  window.addEventListener('resize', () => {
    W = canvas.width  = window.innerWidth;
    H = canvas.height = window.innerHeight;
  });

  // ── Mouse tracking ────────────────────────────────────────────────────
  const mouse = { x: W / 2, y: H / 2 };
  window.addEventListener('mousemove', e => { mouse.x = e.clientX; mouse.y = e.clientY; });

  // ── Config ────────────────────────────────────────────────────────────
  const COLS    = Math.floor(W / 52) + 2;
  const ROWS    = Math.floor(H / 52) + 2;
  const SPACING = 52;

  // ── Dot Grid ──────────────────────────────────────────────────────────
  const dots = [];
  for (let r = 0; r < ROWS; r++) {
    for (let c = 0; c < COLS; c++) {
      dots.push({
        x: c * SPACING,
        y: r * SPACING,
        baseX: c * SPACING,
        baseY: r * SPACING,
        t: Math.random() * Math.PI * 2,
      });
    }
  }

  // ── Floating particles ────────────────────────────────────────────────
  const PARTICLE_COUNT = 90;
  const particles = Array.from({ length: PARTICLE_COUNT }, () => ({
    x: Math.random() * W,
    y: Math.random() * H,
    r: 0.8 + Math.random() * 1.8,
    vx: (Math.random() - 0.5) * 0.35,
    vy: (Math.random() - 0.5) * 0.35,
    alpha: 0.1 + Math.random() * 0.35,
    hue: Math.random() > 0.5 ? 195 : (Math.random() > 0.5 ? 320 : 265),
  }));

  // ── Orbs (morphing glows) ─────────────────────────────────────────────
  const orbs = [
    { cx: W * 0.15, cy: H * 0.2,  r: 320, hue: 265, alpha: 0.12, speed: 0.0006 },
    { cx: W * 0.85, cy: H * 0.75, r: 280, hue: 195, alpha: 0.10, speed: 0.0008 },
    { cx: W * 0.5,  cy: H * 0.55, r: 200, hue: 320, alpha: 0.08, speed: 0.0012 },
  ];

  // ── Connection lines between close particles ──────────────────────────
  function drawConnections() {
    const MAX_DIST = 110;
    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const d  = Math.sqrt(dx * dx + dy * dy);
        if (d < MAX_DIST) {
          const a = (1 - d / MAX_DIST) * 0.18;
          ctx.strokeStyle = `rgba(139,92,246,${a})`;
          ctx.lineWidth = 0.8;
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.stroke();
        }
      }
    }
  }

  let frame = 0;

  function tick() {
    requestAnimationFrame(tick);
    frame++;

    ctx.clearRect(0, 0, W, H);

    // Background gradient
    const bg = ctx.createRadialGradient(W/2, H/2, 0, W/2, H/2, Math.max(W,H)*0.8);
    bg.addColorStop(0, '#060915');
    bg.addColorStop(1, '#020308');
    ctx.fillStyle = bg;
    ctx.fillRect(0, 0, W, H);

    // Orb glows
    orbs.forEach((orb, i) => {
      const t = frame * orb.speed + i * 2.1;
      const px = orb.cx + Math.sin(t)         * W * 0.08;
      const py = orb.cy + Math.cos(t * 0.7)   * H * 0.06;
      const rr = orb.r  + Math.sin(t * 1.3)   * 40;

      const grad = ctx.createRadialGradient(px, py, 0, px, py, rr);
      grad.addColorStop(0, `hsla(${orb.hue},90%,65%,${orb.alpha})`);
      grad.addColorStop(1, `hsla(${orb.hue},90%,65%,0)`);
      ctx.fillStyle = grad;
      ctx.beginPath();
      ctx.arc(px, py, rr, 0, Math.PI * 2);
      ctx.fill();
    });

    // Dot grid — dots repel from mouse
    dots.forEach(d => {
      d.t += 0.012;
      const mx = mouse.x - d.baseX;
      const my = mouse.y - d.baseY;
      const dist = Math.sqrt(mx * mx + my * my);
      const repel = Math.max(0, 90 - dist) / 90;
      d.x = d.baseX - mx * repel * 0.18;
      d.y = d.baseY - my * repel * 0.18;

      const proximity = Math.max(0, 1 - dist / 200);
      const alpha = 0.08 + proximity * 0.55 + Math.sin(d.t) * 0.04;
      const hue   = proximity > 0.3 ? 195 : 265;
      const size  = 1.2 + proximity * 2.2;

      ctx.beginPath();
      ctx.arc(d.x, d.y, size, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${hue},90%,70%,${alpha})`;
      ctx.fill();
    });

    // Particle connections + movement
    drawConnections();
    particles.forEach(p => {
      p.x += p.vx;
      p.y += p.vy;
      if (p.x < 0) p.x = W;
      if (p.x > W) p.x = 0;
      if (p.y < 0) p.y = H;
      if (p.y > H) p.y = 0;

      ctx.beginPath();
      ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
      ctx.fillStyle = `hsla(${p.hue},90%,70%,${p.alpha})`;
      ctx.fill();
    });

    // Scan line sweep (SOC effect) — every 3s
    const scanY = ((frame * 0.6) % (H + 60)) - 30;
    const scanGrad = ctx.createLinearGradient(0, scanY - 30, 0, scanY + 30);
    scanGrad.addColorStop(0,   'transparent');
    scanGrad.addColorStop(0.5, 'rgba(0,240,255,0.03)');
    scanGrad.addColorStop(1,   'transparent');
    ctx.fillStyle = scanGrad;
    ctx.fillRect(0, scanY - 30, W, 60);
  }

  tick();
})();
