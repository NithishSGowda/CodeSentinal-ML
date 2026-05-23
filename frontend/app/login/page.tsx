'use client'

import { useState, useRef, useEffect, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence } from 'framer-motion'
import { Shield, Cpu, AlertTriangle, ChevronRight, Activity, Mail, Lock, ArrowRight } from 'lucide-react'

const FLASK_API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:5000'

const fadeUp = {
  hidden: { opacity: 0, y: 24 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.4 } },
}

export default function LoginPage() {
  const router = useRouter()
  const [step, setStep]         = useState<'email' | 'otp'>('email')
  const [email, setEmail]       = useState('')
  const [otp, setOtp]           = useState(['', '', '', '', '', ''])
  const [loading, setLoading]   = useState(false)
  const [error, setError]       = useState('')
  const [resendCd, setResendCd] = useState(0)

  const otpRefs = useRef<(HTMLInputElement | null)[]>([])
  const emailRef = useRef<HTMLInputElement>(null)

  // Countdown timer for resend
  useEffect(() => {
    if (resendCd <= 0) return
    const t = setTimeout(() => setResendCd(r => r - 1), 1000)
    return () => clearTimeout(t)
  }, [resendCd])

  // Redirect if already logged in
  useEffect(() => {
    if (typeof window !== 'undefined' && localStorage.getItem('cs_token')) {
      router.replace('/')
    }
  }, [router])

  const handleSendOtp = useCallback(async () => {
    const e = email.trim().toLowerCase()
    if (!e || !e.includes('@')) { setError('Enter a valid email address.'); return }
    setLoading(true); setError('')
    try {
      const res  = await fetch(`${FLASK_API}/api/auth/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: e, mode: 'login' }),
      })
      const data = await res.json()
      if (!res.ok || data.error) { setError(data.error || 'Failed to send access code.'); return }
      setStep('otp')
      setResendCd(60)
      setTimeout(() => otpRefs.current[0]?.focus(), 200)
    } catch {
      setError('Cannot reach the CodeSentinel server. Ensure python server.py is running.')
    } finally {
      setLoading(false)
    }
  }, [email])

  const handleOtpChange = (index: number, val: string) => {
    if (!/^\d?$/.test(val)) return
    const next = [...otp]
    next[index] = val
    setOtp(next)
    if (val && index < 5) otpRefs.current[index + 1]?.focus()
  }

  const handleOtpKeyDown = (index: number, e: React.KeyboardEvent) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      otpRefs.current[index - 1]?.focus()
    }
  }

  const handleOtpPaste = (e: React.ClipboardEvent) => {
    const paste = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6)
    if (paste.length === 6) {
      setOtp(paste.split(''))
      otpRefs.current[5]?.focus()
    }
  }

  const handleVerify = useCallback(async () => {
    const code = otp.join('')
    if (code.length < 6) { setError('Enter all 6 digits of your access code.'); return }
    setLoading(true); setError('')
    try {
      const res  = await fetch(`${FLASK_API}/api/auth/verify-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim().toLowerCase(), otp: code, mode: 'login' }),
      })
      const data = await res.json()
      if (!res.ok || data.error) { setError(data.error || 'Verification failed.'); return }
      localStorage.setItem('cs_token', data.token)
      localStorage.setItem('cs_user',  JSON.stringify(data.user))
      router.replace('/')
    } catch {
      setError('Cannot reach the CodeSentinel server.')
    } finally {
      setLoading(false)
    }
  }, [email, otp, router])

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#020308] flex items-center justify-center">
      {/* ── Cyber Grid & Orbs ── */}
      <div className="fixed inset-0 grid-bg opacity-40 pointer-events-none z-0" />
      <div className="fixed inset-0 bg-radial-gradient pointer-events-none z-0" />
      <div className="fixed top-[-10%] left-[-5%] w-[700px] h-[700px] rounded-full bg-[radial-gradient(circle_at_center,rgba(147,51,234,0.07)_0%,transparent_70%)] pulse-orb pointer-events-none z-0" />
      <div className="fixed bottom-[-10%] right-[-5%] w-[600px] h-[600px] rounded-full bg-[radial-gradient(circle_at_center,rgba(6,182,212,0.05)_0%,transparent_70%)] pulse-orb pointer-events-none z-0" />

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
        <div className="flex items-center gap-2 text-[10px] font-bold text-cyan-400 border border-cyan-500/20 rounded-xl px-4 py-2 bg-cyan-500/5">
          <Activity className="w-3 h-3" /> SECURE ACCESS PORTAL
        </div>
      </nav>

      {/* ── Auth Card ── */}
      <motion.div
        className="relative z-10 w-full max-w-md mx-4"
        variants={fadeUp} initial="hidden" animate="show"
      >
        <div className="relative rounded-3xl border border-cyan-500/15 bg-[#03050c]/80 backdrop-blur-3xl shadow-[0_0_60px_rgba(0,240,255,0.06)] overflow-hidden p-8">
          {/* Laser sweep top border */}
          <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-[scanLine_4s_linear_infinite]" />

          {/* Agent identity badge */}
          <div className="flex flex-col items-center mb-8">
            <div className="relative w-16 h-16 mb-4">
              <div className="absolute inset-0 rounded-full border border-dashed border-cyan-500/25 animate-[spin-slow_20s_linear_infinite]" />
              <div className="absolute inset-2 rounded-full border border-dashed border-purple-500/20 animate-[spin-slow_12s_linear_infinite_reverse]" />
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-cyan-500/20 to-purple-500/20 border border-cyan-500/30 flex items-center justify-center shadow-[0_0_20px_rgba(0,240,255,0.15)]">
                  <Shield className="w-5 h-5 text-cyan-400" />
                </div>
              </div>
              <span className="absolute top-1 right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-green-500 shadow-[0_0_6px_#22c55e]" />
              </span>
            </div>
            <div className="text-[9px] font-bold text-cyan-400 tracking-[5px] uppercase font-mono mb-1">SENTINEL AI v1.0</div>
            <h1 className="text-2xl font-black tracking-tight bg-gradient-to-r from-white via-cyan-200 to-purple-400 bg-clip-text text-transparent">
              Operator Login
            </h1>
            <p className="text-neutral-500 text-xs mt-1.5 font-mono tracking-wider">
              {step === 'email' ? 'Enter your email to receive a secure access code' : `Code dispatched to ${email}`}
            </p>
          </div>

          {/* Step indicator */}
          <div className="flex items-center gap-3 mb-7">
            {['Email', 'Access Code'].map((label, i) => (
              <div key={label} className="flex items-center gap-2 flex-1">
                <div className={`w-6 h-6 rounded-full border flex items-center justify-center text-[10px] font-black font-mono transition-all duration-300 ${
                  (step === 'email' && i === 0) || (step === 'otp' && i === 1)
                    ? 'bg-cyan-500/10 border-cyan-500/50 text-cyan-400 shadow-[0_0_10px_rgba(0,240,255,0.2)]'
                    : i < (step === 'otp' ? 1 : 0)
                    ? 'bg-green-500/10 border-green-500/40 text-green-400'
                    : 'border-white/10 text-neutral-600'
                }`}>{i + 1}</div>
                <span className={`text-[10px] font-bold tracking-wider uppercase ${
                  (step === 'email' && i === 0) || (step === 'otp' && i === 1) ? 'text-cyan-400' : i < (step === 'otp' ? 1 : 0) ? 'text-green-400' : 'text-neutral-600'
                }`}>{label}</span>
                {i === 0 && <ChevronRight className="w-3 h-3 text-neutral-700 ml-auto" />}
              </div>
            ))}
          </div>

          <AnimatePresence mode="wait">
            {step === 'email' ? (
              <motion.div key="step-email"
                initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 16 }}
                transition={{ duration: 0.25 }}
              >
                <label className="mono text-[10px] text-cyan-400/70 tracking-[3px] uppercase block mb-2.5 font-bold">
                  Operator Email Address
                </label>
                <div className="relative mb-5">
                  <Mail className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" />
                  <input
                    ref={emailRef}
                    type="email"
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && !loading && handleSendOtp()}
                    className="cyber-input pl-11"
                    placeholder="operator@example.com"
                    autoFocus
                  />
                </div>
                <button
                  onClick={handleSendOtp}
                  disabled={loading}
                  className="btn-scan w-full flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  {loading ? (
                    <><span className="loader" style={{ width: 16, height: 16, borderWidth: 2 }} /> DISPATCHING CODE...</>
                  ) : (
                    <><Lock className="w-4 h-4" /> SEND ACCESS CODE <ArrowRight className="w-4 h-4 ml-1" /></>
                  )}
                </button>
              </motion.div>
            ) : (
              <motion.div key="step-otp"
                initial={{ opacity: 0, x: -16 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 16 }}
                transition={{ duration: 0.25 }}
              >
                <label className="mono text-[10px] text-cyan-400/70 tracking-[3px] uppercase block mb-3 font-bold">
                  6-Digit Access Code
                </label>

                {/* OTP boxes */}
                <div className="flex gap-2.5 mb-5 justify-center" onPaste={handleOtpPaste}>
                  {otp.map((digit, i) => (
                    <input
                      key={i}
                      ref={el => { otpRefs.current[i] = el }}
                      type="text"
                      inputMode="numeric"
                      maxLength={1}
                      value={digit}
                      onChange={e => handleOtpChange(i, e.target.value)}
                      onKeyDown={e => handleOtpKeyDown(i, e)}
                      className="w-12 h-14 text-center text-xl font-black font-mono rounded-xl border transition-all duration-200 outline-none bg-black/50 text-cyan-300"
                      style={{
                        borderColor: digit ? 'rgba(0,240,255,0.5)' : 'rgba(255,255,255,0.08)',
                        boxShadow: digit ? '0 0 12px rgba(0,240,255,0.12)' : 'none',
                      }}
                    />
                  ))}
                </div>

                <button
                  onClick={handleVerify}
                  disabled={loading || otp.join('').length < 6}
                  className="btn-scan w-full flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed mb-4"
                >
                  {loading ? (
                    <><span className="loader" style={{ width: 16, height: 16, borderWidth: 2 }} /> VERIFYING...</>
                  ) : (
                    <><Shield className="w-4 h-4" /> AUTHORIZE SESSION</>
                  )}
                </button>

                <div className="flex items-center justify-between">
                  <button
                    onClick={() => { setStep('email'); setOtp(['','','','','','']); setError('') }}
                    className="text-[10px] font-bold text-neutral-500 hover:text-neutral-300 transition-colors uppercase tracking-wider font-mono"
                  >
                    ← Change Email
                  </button>
                  <button
                    onClick={handleSendOtp}
                    disabled={resendCd > 0 || loading}
                    className="text-[10px] font-bold text-cyan-400/60 hover:text-cyan-400 disabled:text-neutral-600 disabled:cursor-not-allowed transition-colors uppercase tracking-wider font-mono"
                  >
                    {resendCd > 0 ? `Resend in ${resendCd}s` : 'Resend Code'}
                  </button>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Error display */}
          <AnimatePresence>
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                className="mt-5 flex items-start gap-2.5 p-3.5 bg-red-500/10 border border-red-500/25 rounded-xl text-red-400 text-xs font-semibold"
              >
                <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" /> {error}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Register link */}
          <div className="mt-7 pt-6 border-t border-white/[0.04] text-center">
            <span className="text-neutral-600 text-xs font-mono">No account?{' '}</span>
            <a href="/register" className="text-cyan-400 text-xs font-bold font-mono hover:text-cyan-300 transition-colors tracking-wider uppercase">
              Initialize Operator Profile →
            </a>
          </div>
        </div>

        <p className="text-center mono text-[9px] text-neutral-700 mt-5 tracking-widest uppercase font-bold">
          CodeSentinel ML · SOC Telemetry · OTP Auth
        </p>
      </motion.div>
    </main>
  )
}
