'use client'

import { useEffect, useState } from 'react'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Cpu, Activity, ChevronRight, Zap } from 'lucide-react'

export default function WelcomePage() {
  const router = useRouter()
  const [userName, setUserName]       = useState('Operator')
  const [countdown, setCountdown]     = useState(10)
  const [showContent, setShowContent] = useState(false)

  useEffect(() => {
    // Read user from localStorage
    try {
      const raw = localStorage.getItem('cs_user')
      if (raw) {
        const u = JSON.parse(raw)
        if (u?.name) setUserName(u.name.split(' ')[0])
      }
    } catch {}
    // Stagger the reveal
    const t = setTimeout(() => setShowContent(true), 300)
    return () => clearTimeout(t)
  }, [])

  // Countdown auto-redirect
  useEffect(() => {
    if (countdown <= 0) { router.replace('/'); return }
    const t = setTimeout(() => setCountdown(c => c - 1), 1000)
    return () => clearTimeout(t)
  }, [countdown, router])

  const pulsingRing = {
    scale:     [1, 1.15, 1] as number[],
    opacity:   [0.4, 0.1, 0.4] as number[],
    transition: {
      duration: 3,
      repeat: Infinity,
      ease: 'easeInOut' as const,
    },
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#020308] flex items-center justify-center">
      {/* ── Cyber Grid & Ambient ── */}
      <div className="fixed inset-0 grid-bg opacity-40 pointer-events-none z-0" />
      <div className="fixed top-[-10%] left-[-5%] w-[900px] h-[900px] rounded-full bg-[radial-gradient(circle_at_center,rgba(0,240,255,0.05)_0%,transparent_70%)] pulse-orb pointer-events-none z-0" />
      <div className="fixed bottom-[-10%] right-[-5%] w-[700px] h-[700px] rounded-full bg-[radial-gradient(circle_at_center,rgba(139,92,246,0.07)_0%,transparent_70%)] pulse-orb pointer-events-none z-0" />

      {/* ── Navbar ── */}
      <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4 border-b border-cyan-500/10 bg-[#020308]/75 backdrop-blur-xl">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Shield className="w-4 h-4 text-cyan-400 animate-pulse" />
          </div>
          <span className="text-sm font-black tracking-[4px] uppercase bg-gradient-to-r from-white via-cyan-300 to-purple-400 bg-clip-text text-transparent">
            CodeSentinel ML
          </span>
        </div>
        <div className="flex items-center gap-2 text-[10px] font-bold text-green-400 border border-green-500/20 rounded-xl px-4 py-2 bg-green-500/5">
          <Activity className="w-3 h-3" /> IDENTITY CONFIRMED
        </div>
      </nav>

      <AnimatePresence>
        {showContent && (
          <motion.div
            className="relative z-10 w-full max-w-2xl mx-4 flex flex-col items-center"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.6, ease: 'easeOut' }}
          >
            {/* Holographic agent orb */}
            <div className="relative w-36 h-36 mb-8 flex items-center justify-center">
              {/* Outer pulsing rings */}
              <motion.div
                className="absolute inset-[-24px] rounded-full border border-cyan-500/10"
                animate={pulsingRing}
              />
              <motion.div
                className="absolute inset-[-12px] rounded-full border border-cyan-500/15"
                animate={pulsingRing}
                style={{ animationDelay: '0.5s' }}
              />
              {/* Spinning orbit rings */}
              <div className="absolute inset-0 rounded-full border border-dashed border-cyan-500/20 animate-[spin-slow_20s_linear_infinite]" />
              <div className="absolute inset-3 rounded-full border border-dashed border-purple-500/15 animate-[spin-slow_14s_linear_infinite_reverse]" />
              <div className="absolute inset-6 rounded-full border border-dashed border-cyan-500/10 animate-[spin-slow_8s_linear_infinite]" />

              {/* Core orb */}
              <div className="relative w-20 h-20 rounded-full bg-gradient-to-tr from-cyan-500/15 to-purple-500/15 border border-cyan-500/25 flex items-center justify-center shadow-[0_0_40px_rgba(0,240,255,0.2)]">
                <div className="absolute inset-0 rounded-full bg-[radial-gradient(circle_at_center,rgba(0,240,255,0.08),transparent_70%)]" />
                <Cpu className="w-9 h-9 text-cyan-400 relative z-10" />
              </div>

              {/* Live status ping */}
              <span className="absolute top-2 right-2 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500 shadow-[0_0_8px_#22c55e]" />
              </span>
            </div>

            {/* SENTINEL AI badge */}
            <motion.div
              className="flex items-center gap-2 mb-5"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.2 }}
            >
              <div className="tag-badge border-green-500/30 text-green-400 bg-green-500/5">
                <Zap className="w-3 h-3 text-green-400" /> Identity Confirmed · Enrollment Successful
              </div>
            </motion.div>

            {/* Main welcome heading */}
            <motion.h1
              className="text-5xl md:text-6xl font-black tracking-tight text-center bg-gradient-to-r from-white via-cyan-200 to-purple-400 bg-clip-text text-transparent mb-3 leading-tight"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.3, duration: 0.5 }}
            >
              Welcome Aboard,<br />
              <span className="bg-gradient-to-r from-cyan-300 to-purple-400 bg-clip-text text-transparent">
                {userName}.
              </span>
            </motion.h1>

            {/* Sentinel AI dialogue card */}
            <motion.div
              className="w-full mt-6 p-6 rounded-2xl border border-cyan-500/20 bg-[#030611]/85 backdrop-blur-xl shadow-[0_0_40px_rgba(0,240,255,0.08)] relative overflow-hidden"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.45, duration: 0.5 }}
            >
              {/* Top scan laser */}
              <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-400/60 to-transparent animate-[scanLine_6s_linear_infinite]" />

              <div className="flex items-start gap-4">
                {/* Mini agent icon */}
                <div className="flex-shrink-0 w-10 h-10 rounded-full bg-cyan-500/10 border border-cyan-500/25 flex items-center justify-center animate-pulse">
                  <Cpu className="w-5 h-5 text-cyan-400" />
                </div>

                <div className="flex-1">
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-[9px] font-black text-cyan-400 tracking-[4px] uppercase font-mono">SENTINEL AI v1.0</span>
                    <div className="flex items-center gap-2">
                      <span className="text-[8px] font-bold text-green-400/70 tracking-widest uppercase font-mono">TELEMETRY ONLINE</span>
                      <span className="flex h-1.5 w-1.5">
                        <span className="animate-ping absolute inline-flex h-1.5 w-1.5 rounded-full bg-green-400 opacity-75" />
                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-green-500" />
                      </span>
                    </div>
                  </div>

                  <p className="mono text-sm text-neutral-200 leading-relaxed font-medium cursor">
                    "Welcome aboard, <strong className="text-cyan-300">{userName}</strong>. Identity confirmed. Your secure operations terminal is now active. Telemetry systems initialized. Proceed to the CodeSentinel ecosystem to begin your first threat assessment and attack chain vector mapping session."
                  </p>

                  <div className="mt-4 pt-4 border-t border-cyan-500/10 grid grid-cols-3 gap-4">
                    {[
                      ['STATUS',      'ACTIVE'],
                      ['CLEARANCE',   'OPERATOR'],
                      ['SESSION',     'INITIALIZED'],
                    ].map(([k, v]) => (
                      <div key={k}>
                        <div className="text-[8px] font-bold text-neutral-600 uppercase tracking-widest font-mono">{k}</div>
                        <div className="text-[10px] font-black text-cyan-400 tracking-wider font-mono mt-0.5">{v}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </motion.div>

            {/* CTA buttons */}
            <motion.div
              className="flex gap-4 mt-8 w-full"
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.6, duration: 0.4 }}
            >
              <button
                onClick={() => router.replace('/')}
                className="btn-scan flex-1 flex items-center justify-center gap-2 text-sm font-bold shadow-[0_0_30px_rgba(0,240,255,0.15)]"
              >
                <Shield className="w-4 h-4" />
                ENTER THE SYSTEM
                <ChevronRight className="w-4 h-4" />
              </button>
            </motion.div>

            {/* Countdown auto-redirect bar */}
            <motion.div
              className="mt-5 w-full"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ delay: 0.75 }}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="mono text-[9px] text-neutral-600 tracking-widest uppercase font-bold">
                  Auto-redirecting to command terminal
                </span>
                <span className="mono text-[9px] text-cyan-400/60 font-bold tracking-widest">
                  {countdown}s
                </span>
              </div>
              <div className="h-[2px] bg-white/[0.04] rounded-full overflow-hidden">
                <motion.div
                  className="h-full bg-gradient-to-r from-cyan-400 to-purple-500 rounded-full"
                  initial={{ width: '100%' }}
                  animate={{ width: '0%' }}
                  transition={{ duration: 10, ease: 'linear' }}
                />
              </div>
            </motion.div>

            <p className="text-center mono text-[9px] text-neutral-700 mt-5 tracking-widest uppercase font-bold">
              CodeSentinel ML · SOC Telemetry · Operator Authenticated
            </p>
          </motion.div>
        )}
      </AnimatePresence>
    </main>
  )
}
