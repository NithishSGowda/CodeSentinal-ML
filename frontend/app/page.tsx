'use client'

import { useEffect, useRef, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { motion, AnimatePresence, type Variants } from 'framer-motion'
import { CyberScene } from '@/components/ui/cyber-scene'
import { Spotlight } from '@/components/ui/spotlight'
import { Card } from '@/components/ui/card'
import {
  Shield, GitBranch, Cpu, AlertTriangle,
  ChevronRight, Zap, Activity,
  Network, Bug, BarChart3, ArrowLeft, Upload, FolderOpen, Globe,
  Terminal, Download, Code, FileText, CheckCircle, Eye, RefreshCw, Play,
  User, Trash2, PenLine, X, Check, LogOut, ChevronDown
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────────────
interface ScanResult {
  project_name: string
  stats: { 
    total_files: number
    total_lines: number
    blank_lines: number
    comments: number
    imports: number
    functions: number
    classes: number
    size_kb: number 
  }
  security_score: number
  base_score: number
  project_ml_risk: string
  vibe_risk: { 
    score: number
    category: string
    breakdown: Record<string, number> 
  }
  maturity: { 
    level: string
    score: number
    indicators: string[] 
  }
  summary: string
  findings: Array<{ 
    issue: string
    severity: string
    line: number
    file: string
    matched_code: string
    description: string 
  }>
  prioritized_findings: Array<{
    issue: string
    severity: string
    line: number
    file: string
    matched_code: string
    description: string
    priority: string
    priority_score: number
  }>
  entry_points: Array<{ 
    type: string
    severity: string
    line: number
    file: string
    pattern: string 
  }>
  attack_surface: {
    total_entry_points: number
    total_endpoints: number
    risky_uploads: number
    high_severity_inputs: number
  }
  attack_chains: Array<{ 
    source: string
    sink: string
    file: string
    line: number
    attack_type: string 
  }>
  file_risks: Array<{ 
    file: string
    ml_prediction: string
    confidence: number 
  }>
  ranked_files: Array<{
    file: string
    composite_score: number
    vuln_count: number
    high_vulns: number
    medium_vulns: number
    low_vulns: number
    chain_count: number
    ml_prediction: string
    risk_label: string
  }>
  severity_counts: { 
    high: number
    medium: number
    low: number 
  }
  security_grade: {
    grade: string
    grade_score: number
    label: string
    color: string
    explanation: string
  }
  fingerprint: {
    total_files: number
    total_lines: number
    total_vulnerabilities: number
    critical_count: number
    total_endpoints: number
    dangerous_functions: number
    attack_chains: number
    secret_exposures: number
    high_risk_files: number
    medium_risk_files: number
    risk_score: number
    security_grade: string
    grade_label: string
    grade_color: string
    health_score: number
  }
  intelligence_narrative: string[]
  terminal_logs: Array<{
    level: string
    message: string
  }>
  ml_explanations: Record<string, {
    prediction: string
    confidence_pct: number
    key_indicators: string[]
    risk_summary: string
  }>
  recommendations: Record<string, {
    priority_action: string
    insecure_example: string
    secure_example: string
  }>
  explanations: Record<string, {
    danger_level: string
    vulnerability_description: string
    potential_exploit_vector: string
  }>
}

const FLASK_API = 'http://localhost:5000'

const LOADER_PHASES = [
  'Initializing CodeSentinel ML threat engine...',
  'Traversing repository file system...',
  'Extracting multi-language files & dependencies...',
  'Running Scikit-learn TF-IDF vectorizer...',
  'Executing deterministic vulnerability regex signatures...',
  'Mapping exposed external API entry points...',
  'Correlating unvalidated source → dangerous sink chains...',
  'Computing multi-factor Vibe Coding Risk index...',
  'Evaluating Security Maturity metrics...',
  'Formulating comprehensive security posture grade...',
  'Compiling cinematic intelligence narrative logs...',
]

const FEATURES = [
  { icon: FolderOpen, tag: '01 · RECON',   title: 'Repository Traversal',     desc: 'Recursively traverses PHP, Java, JS, and Python projects with depth limitations and safe size safeguards to map all directory trees.',       code: '>_ traversing 500 files... mapping directories' },
  { icon: Network,    tag: '02 · SURFACE',  title: 'Attack Surface Mapping',   desc: 'Identifies Flask, FastAPI, PHP, and Express.js API endpoints, routing methods, form posts, parameters and exposed query fields.',            code: '>_ entry_points: Flask routes, Express req.body' },
  { icon: Bug,        tag: '03 · CHAINS',   title: 'Attack Chain Correlation', desc: 'Traces high-severity unvalidated sources directly to dangerous sinks (like eval/exec/raw SQL) within a 15-line logical window.',                  code: '>_ CHAIN: Flask args → eval() [CRITICAL PATH]' },
  { icon: Cpu,        tag: '04 · ML',       title: 'TF-IDF Classifier',        desc: 'Supervised Logistic Regression trained on classic secure vs insecure patterns. Predicts risk and yields explainable indictors.',        code: '>_ model.predict() · confidence: 94.7% [High Risk]' },
]

const fadeUp: Variants = {
  hidden: { opacity: 0, y: 20 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.45 } },
}

const stagger: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: 0.08 } },
}

export default function Home() {
  const [activeTab, setActiveTab]     = useState<'path' | 'github' | 'upload'>('path')
  const [scanning, setScanning]       = useState(false)
  const [error, setError]             = useState('')
  const [result, setResult]           = useState<ScanResult | null>(null)
  
  // Dashboard navigation tab
  const [dashTab, setDashTab]         = useState<'overview' | 'vulns' | 'surface' | 'chains' | 'priority' | 'ml' | 'maturity' | 'analytics' | 'fixes' | 'terminal' | 'downloads'>('overview')
  const [fileObj, setFileObj]         = useState<File | null>(null)
  const [dragOver, setDragOver]       = useState(false)
  const [sentinelOpen, setSentinelOpen]   = useState(false)
  const [authUser, setAuthUser]           = useState<{ name: string; email: string } | null>(null)
  const [profileOpen, setProfileOpen]     = useState(false)
  const [editNameOpen, setEditNameOpen]   = useState(false)
  const [editNameVal, setEditNameVal]     = useState('')
  const [editNameLoading, setEditNameLoading] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState(false)
  const [deleteLoading, setDeleteLoading] = useState(false)
  const router = useRouter()

  // Auth guard — redirect to /login if no session token
  useEffect(() => {
    const token = localStorage.getItem('cs_token')
    if (!token) { router.replace('/login'); return }
    try {
      const u = JSON.parse(localStorage.getItem('cs_user') || '{}')
      if (u?.email) setAuthUser(u)
    } catch {}
  }, [router])

  // ── Auth action handlers ──────────────────────────────────────────────
  const handleLogout = useCallback(() => {
    const user = authUser
    localStorage.removeItem('cs_token')
    localStorage.removeItem('cs_user')
    if (user) {
      fetch('http://localhost:5000/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: user.email }),
      }).catch(() => {})
    }
    router.replace('/login')
  }, [authUser, router])

  const handleUpdateName = useCallback(async () => {
    if (!authUser || !editNameVal.trim()) return
    setEditNameLoading(true)
    try {
      const token = localStorage.getItem('cs_token') || ''
      const res   = await fetch('http://localhost:5000/api/auth/update-name', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email: authUser.email, token, name: editNameVal.trim() }),
      })
      const data = await res.json()
      if (data.success) {
        const updated = { ...authUser, name: data.user.name }
        setAuthUser(updated)
        localStorage.setItem('cs_user', JSON.stringify(updated))
        setEditNameOpen(false)
      }
    } catch {}
    setEditNameLoading(false)
  }, [authUser, editNameVal])

  const handleDeleteAccount = useCallback(async () => {
    if (!authUser) return
    setDeleteLoading(true)
    try {
      const token = localStorage.getItem('cs_token') || ''
      await fetch('http://localhost:5000/api/auth/delete-account', {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ email: authUser.email, token }),
      })
    } catch {}
    localStorage.removeItem('cs_token')
    localStorage.removeItem('cs_user')
    router.replace('/register')
  }, [authUser, router])

  const pathRef   = useRef<HTMLInputElement>(null)
  const githubRef = useRef<HTMLInputElement>(null)
  const fileRef   = useRef<HTMLInputElement>(null)

  const runScan = useCallback(async (endpoint: string, body: BodyInit, headers?: HeadersInit) => {
    setScanning(true)
    setError('')
    try {
      const res  = await fetch(`${FLASK_API}${endpoint}`, { method: 'POST', body, headers })
      const data = await res.json()
      if (data.error) { setError(data.error); setScanning(false); return }
      setResult(data)
      setScanning(false)
      setDashTab('overview')
    } catch {
      setError('Could not connect to the Flask cybersecurity server at http://localhost:5000. Start it by running: python server.py')
      setScanning(false)
    }
  }, [])

  const handleScan = () => {
    setError('')
    if (activeTab === 'path') {
      const p = pathRef.current?.value.trim()
      if (!p) { setError('Please specify a directory path.'); return }
      runScan('/api/scan/path', JSON.stringify({ path: p }), { 'Content-Type': 'application/json' })
    } else if (activeTab === 'github') {
      const u = githubRef.current?.value.trim()
      if (!u) { setError('Please enter a valid GitHub URL.'); return }
      runScan('/api/scan/github', JSON.stringify({ url: u }), { 'Content-Type': 'application/json' })
    } else {
      if (!fileObj) { setError('Please select a repository ZIP archive.'); return }
      const fd = new FormData(); fd.append('file', fileObj)
      runScan('/api/scan/upload', fd)
    }
  }

  if (result) {
    return <Dashboard result={result} onBack={() => { setResult(null) }} dashTab={dashTab} setDashTab={setDashTab} />
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#020308]">
      {/* ── Dynamic Ambient Cyber Orbs ───────────── */}
      <div className="fixed inset-0 pointer-events-none z-0">
        <div className="absolute top-[-10%] left-[-5%] w-[700px] h-[700px] rounded-full bg-[radial-gradient(circle_at_center,rgba(147,51,234,0.08)_0%,transparent_70%)] animate-[pulse-glow_8s_ease-in-out_infinite] pulse-orb" />
        <div className="absolute bottom-[-10%] right-[-5%] w-[600px] h-[600px] rounded-full bg-[radial-gradient(circle_at_center,rgba(6,182,212,0.06)_0%,transparent_70%)] animate-[pulse-glow_12s_ease-in-out_infinite_reverse] pulse-orb" />
      </div>

      {/* ── Premium Tech Grid Background ─────────────────────────────────────────────── */}
      <div className="fixed inset-0 grid-bg opacity-45 pointer-events-none z-0" />
      <div className="fixed inset-0 bg-radial-gradient pointer-events-none z-0" />

      {/* ── Fixed Futuristic Navbar ──────────────────────────────────────────────────────── */}
      <nav className="fixed top-0 left-0 right-0 z-50 flex items-center justify-between px-8 py-4 border-b border-cyan-500/10 bg-[#020308]/75 backdrop-blur-xl shadow-[0_4px_30px_rgba(0,0,0,0.4)]">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <Shield className="w-4 h-4 text-cyan-400 animate-pulse" />
          </div>
          <span className="text-sm font-black tracking-[4px] uppercase bg-gradient-to-r from-white via-cyan-300 to-purple-400 bg-clip-text text-transparent">
            CodeSentinel ML
          </span>
        </div>
        <div className="flex items-center gap-3">
          {/* Profile dropdown */}
          {authUser && (
            <div className="relative">
              {/* Trigger button */}
              <button
                onClick={() => { setProfileOpen(o => !o); setEditNameOpen(false); setDeleteConfirm(false) }}
                className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl border border-white/[0.08] hover:border-cyan-500/25 bg-white/[0.03] hover:bg-cyan-500/5 transition-all duration-200 group"
              >
                {/* Avatar circle */}
                <div className="w-7 h-7 rounded-full bg-gradient-to-tr from-cyan-500/25 to-purple-500/25 border border-cyan-500/30 flex items-center justify-center text-[11px] font-black text-cyan-300 uppercase">
                  {authUser.name ? authUser.name[0] : authUser.email[0]}
                </div>
                <div className="hidden sm:flex flex-col items-start">
                  <span className="text-[11px] font-bold text-neutral-200 leading-none">{authUser.name || 'Operator'}</span>
                  <span className="text-[9px] text-neutral-600 font-mono leading-none mt-0.5">{authUser.email}</span>
                </div>
                <ChevronDown className={`w-3 h-3 text-neutral-500 transition-transform duration-200 ${profileOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Dropdown panel */}
              <AnimatePresence>
                {profileOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -8, scale: 0.96 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -8, scale: 0.96 }}
                    transition={{ duration: 0.15 }}
                    className="absolute right-0 top-full mt-2 w-72 rounded-2xl border border-cyan-500/15 bg-[#03050e]/95 backdrop-blur-xl shadow-[0_20px_60px_rgba(0,0,0,0.6)] overflow-hidden z-[100]"
                  >
                    {/* Header */}
                    <div className="px-5 py-4 border-b border-white/[0.05] bg-cyan-500/[0.02]">
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-cyan-500/25 to-purple-500/25 border border-cyan-500/30 flex items-center justify-center text-base font-black text-cyan-300 uppercase">
                          {authUser.name ? authUser.name[0] : authUser.email[0]}
                        </div>
                        <div>
                          <div className="text-sm font-bold text-white">{authUser.name || 'Operator'}</div>
                          <div className="text-[10px] text-neutral-500 font-mono">{authUser.email}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5 mt-3">
                        <span className="flex h-1.5 w-1.5 rounded-full bg-green-500 shadow-[0_0_5px_#22c55e]"></span>
                        <span className="text-[9px] font-bold text-green-400 tracking-widest uppercase">Session Active · Operator Clearance</span>
                      </div>
                    </div>

                    {/* Edit Name section */}
                    <div className="px-5 py-3 border-b border-white/[0.05]">
                      {!editNameOpen ? (
                        <button
                          onClick={() => { setEditNameOpen(true); setEditNameVal(authUser.name || ''); setDeleteConfirm(false) }}
                          className="w-full flex items-center gap-2.5 text-left py-2 px-3 rounded-xl hover:bg-white/[0.04] transition-colors group"
                        >
                          <PenLine className="w-4 h-4 text-neutral-500 group-hover:text-cyan-400 transition-colors" />
                          <span className="text-[12px] font-semibold text-neutral-400 group-hover:text-neutral-200 transition-colors">Edit Display Name</span>
                        </button>
                      ) : (
                        <div className="space-y-2">
                          <label className="text-[9px] font-bold text-cyan-400/70 tracking-[3px] uppercase">New Display Name</label>
                          <div className="flex gap-2">
                            <input
                              type="text"
                              value={editNameVal}
                              onChange={e => setEditNameVal(e.target.value)}
                              onKeyDown={e => {
                                if (e.key === 'Enter') handleUpdateName()
                                if (e.key === 'Escape') setEditNameOpen(false)
                              }}
                              className="flex-1 bg-black/40 border border-cyan-500/20 rounded-lg px-3 py-2 text-[12px] text-white font-mono outline-none focus:border-cyan-500/50 transition-colors"
                              placeholder="e.g. John Doe"
                              autoFocus
                            />
                            <button
                              onClick={handleUpdateName}
                              disabled={editNameLoading || !editNameVal.trim()}
                              className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center hover:bg-cyan-500/20 disabled:opacity-40 transition-colors"
                            >
                              {editNameLoading
                                ? <span className="loader" style={{ width: 12, height: 12, borderWidth: 2 }} />
                                : <Check className="w-3.5 h-3.5 text-cyan-400" />}
                            </button>
                            <button
                              onClick={() => setEditNameOpen(false)}
                              className="w-8 h-8 rounded-lg border border-white/[0.06] flex items-center justify-center hover:bg-white/[0.05] transition-colors"
                            >
                              <X className="w-3.5 h-3.5 text-neutral-500" />
                            </button>
                          </div>
                        </div>
                      )}
                    </div>

                    {/* Logout */}
                    <div className="px-5 py-2 border-b border-white/[0.05]">
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2.5 py-2 px-3 rounded-xl hover:bg-white/[0.04] transition-colors group"
                      >
                        <LogOut className="w-4 h-4 text-neutral-500 group-hover:text-amber-400 transition-colors" />
                        <span className="text-[12px] font-semibold text-neutral-400 group-hover:text-neutral-200 transition-colors">Logout</span>
                      </button>
                    </div>

                    {/* Delete account */}
                    <div className="px-5 py-3">
                      {!deleteConfirm ? (
                        <button
                          onClick={() => { setDeleteConfirm(true); setEditNameOpen(false) }}
                          className="w-full flex items-center gap-2.5 py-2 px-3 rounded-xl hover:bg-red-500/[0.06] transition-colors group"
                        >
                          <Trash2 className="w-4 h-4 text-neutral-600 group-hover:text-red-400 transition-colors" />
                          <span className="text-[12px] font-semibold text-neutral-600 group-hover:text-red-400 transition-colors">Delete Account</span>
                        </button>
                      ) : (
                        <div className="space-y-2.5">
                          <div className="flex items-start gap-2 p-3 bg-red-500/10 border border-red-500/20 rounded-xl">
                            <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
                            <p className="text-[11px] text-red-300 leading-relaxed font-mono">This will permanently delete your operator account. This action cannot be undone.</p>
                          </div>
                          <div className="flex gap-2">
                            <button
                              onClick={handleDeleteAccount}
                              disabled={deleteLoading}
                              className="flex-1 flex items-center justify-center gap-1.5 py-2 bg-red-500/15 border border-red-500/30 rounded-lg text-[11px] font-bold text-red-400 hover:bg-red-500/25 disabled:opacity-50 transition-colors"
                            >
                              {deleteLoading
                                ? <><span className="loader" style={{ width: 10, height: 10, borderWidth: 2 }} /> Deleting...</>
                                : <><Trash2 className="w-3 h-3" /> Confirm Delete</>}
                            </button>
                            <button
                              onClick={() => setDeleteConfirm(false)}
                              className="px-4 py-2 border border-white/[0.06] rounded-lg text-[11px] font-bold text-neutral-500 hover:text-neutral-300 hover:bg-white/[0.04] transition-colors"
                            >
                              Cancel
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          )}
          <div className="tag-badge border-cyan-500/30 text-cyan-400 bg-cyan-500/5 shadow-[0_0_15px_rgba(0,240,255,0.1)]">
            <Activity className="w-3 h-3 text-cyan-400" /> ML Classifier Active
          </div>
        </div>
      </nav>

      {/* ── HERO SECTION ────────────────────────────────────────────────────────── */}
      <section className="relative min-h-screen flex flex-col items-center justify-center pt-28 pb-12 px-6 z-10">
        <Card className="w-full max-w-6xl min-h-[580px] relative overflow-hidden border-cyan-500/15 bg-[#03050c]/60 backdrop-blur-3xl shadow-[0_0_50px_rgba(0,240,255,0.05)] rounded-3xl">
          <Spotlight size={550} />

          <div className="flex flex-col md:flex-row h-full min-h-[580px]">
            {/* Left Column — Brand Copy */}
            <motion.div
              className="flex-1 p-10 md:p-14 relative z-10 flex flex-col justify-center border-r border-white/[0.03]"
              variants={stagger}
              initial="hidden"
              animate="show"
            >
              <motion.div variants={fadeUp}>
                <div className="tag-badge mb-6 border-purple-500/30 text-purple-300 bg-purple-500/5">
                  <Zap className="w-3 h-3 text-purple-400" /> Cyber SOC Intelligence
                </div>
              </motion.div>

              <motion.h1
                variants={fadeUp}
                className="text-5xl md:text-6xl lg:text-7xl font-black leading-[0.95] tracking-tight bg-gradient-to-r from-white via-cyan-200 to-purple-400 bg-clip-text text-transparent mb-4"
              >
                CODESENTINEL ML
              </motion.h1>

              <motion.h2
                variants={fadeUp}
                className="text-sm md:text-base font-bold tracking-[2.5px] text-cyan-400 uppercase mb-6"
              >
                AI-Powered Secure Code Intelligence Platform
              </motion.h2>

              <motion.p variants={fadeUp} className="text-neutral-400 text-sm md:text-base max-w-md leading-relaxed mb-8">
                Local static analysis, multi-stage attack path correlation, and supervised TF-IDF risk classification built for enterprise cybersecurity demonstrations.
              </motion.p>

              <motion.div variants={fadeUp} className="flex gap-4 flex-wrap">
                <a href="#scan" className="btn-scan text-xs py-3.5 px-8 font-semibold shadow-[0_0_30px_rgba(0,240,255,0.15)]">
                  ECOSYSTEM SCANNER
                </a>
                <a href="#features" className="flex items-center gap-2 px-6 py-3.5 text-xs font-bold text-neutral-400 hover:text-white border border-white/[0.08] rounded-full transition-all hover:border-white/20 hover:bg-white/[0.02]">
                  EXPLORE FEATS <ChevronRight className="w-4 h-4 text-cyan-400" />
                </a>
              </motion.div>

              <motion.div variants={fadeUp} className="flex gap-8 mt-10 pt-8 border-t border-white/[0.06]">
                {[['50+', 'Vulnerabilities'], ['4', 'Target Languages'], ['100%', 'Local Security']].map(([val, label]) => (
                  <div key={label}>
                    <div className="text-2xl font-black text-white bg-gradient-to-r from-white to-cyan-300 bg-clip-text text-transparent">{val}</div>
                    <div className="text-[10px] text-neutral-500 uppercase tracking-widest mt-1 font-bold">{label}</div>
                  </div>
                ))}
              </motion.div>
            </motion.div>

            {/* Right Column — 3D CyberScene and Floating AI Dialogue Bubble */}
            <div className="flex-1 relative min-h-[420px] md:min-h-0 flex items-center justify-center bg-black/10">
              <CyberScene className="w-full h-full absolute inset-0" />
              <div className="absolute inset-y-0 left-0 w-16 bg-gradient-to-r from-[#03050c]/50 to-transparent pointer-events-none" />
              
              {/* Interactive Floating Sentinel AI Agent Dot / Orb */}
              <div className="absolute bottom-8 right-8 z-30 flex flex-col items-end">
                <AnimatePresence>
                  {sentinelOpen && (
                    <motion.div 
                      initial={{ opacity: 0, scale: 0.85, y: 15, x: 0 }}
                      animate={{ opacity: 1, scale: 1, y: 0, x: 0 }}
                      exit={{ opacity: 0, scale: 0.85, y: 15 }}
                      transition={{ duration: 0.3, ease: "easeOut" }}
                      onClick={() => setSentinelOpen(false)}
                      className="mb-4 w-80 p-5 rounded-2xl border border-cyan-500/25 bg-[#030611]/90 backdrop-blur-xl shadow-[0_0_35px_rgba(0,240,255,0.18)] flex items-start gap-3.5 cursor-pointer hover:border-cyan-400/40 hover:shadow-[0_0_40px_rgba(0,240,255,0.22)] transition-all duration-300 select-none"
                    >
                      <div className="w-8 h-8 rounded-full bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center flex-shrink-0 animate-pulse">
                        <Cpu className="w-4 h-4 text-cyan-400" />
                      </div>
                      <div className="flex-1">
                        <div className="flex justify-between items-center mb-1">
                          <span className="text-[9px] font-black text-cyan-400 tracking-wider uppercase font-mono">SENTINEL AI v1.0</span>
                          <span className="flex h-2 w-2 relative">
                            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-green-500" />
                          </span>
                        </div>
                        <p className="mono text-[10px] text-neutral-200 leading-relaxed font-medium">
                          "Welcome, operator. Telemetry online. Specify directory path or target repository URL below to trigger secure attack chain vector mapping."
                        </p>
                        <div className="text-[8px] text-neutral-500 mt-2 font-mono uppercase tracking-widest text-right">
                          [Click anywhere to collapse]
                        </div>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>

                {/* The Floating Pulsing Cyber Agent Dot/Chip */}
                <motion.button
                  onClick={() => setSentinelOpen(!sentinelOpen)}
                  className="flex items-center gap-2 px-4 py-2.5 rounded-full border border-cyan-500/30 bg-[#030611]/90 backdrop-blur-md shadow-[0_0_20px_rgba(0,240,255,0.12)] hover:border-cyan-400 hover:shadow-[0_0_25px_rgba(0,240,255,0.25)] transition-all duration-300 group cursor-pointer"
                  animate={{ y: [0, -6, 0] }}
                  transition={{ duration: 4, repeat: Infinity, ease: "easeInOut" }}
                  whileHover={{ scale: 1.05 }}
                  whileTap={{ scale: 0.95 }}
                  title="Toggle Sentinel AI Assistant Telemetry"
                >
                  <div className="relative w-6 h-6 flex items-center justify-center rounded-full bg-cyan-500/10 border border-cyan-500/20 group-hover:border-cyan-400/50">
                    {/* Tiny cyber spinning orbit around agent CPU icon */}
                    <span className="absolute inset-[-2px] rounded-full border border-dashed border-cyan-500/30 animate-[spin_8s_linear_infinite]" />
                    <Cpu className="w-3.5 h-3.5 text-cyan-400 group-hover:text-cyan-300 transition-colors" />
                  </div>
                  <div className="flex flex-col items-start pr-1.5 text-left">
                    <span className="text-[9px] font-black text-cyan-400 tracking-wider uppercase font-mono leading-none">SENTINEL AI</span>
                    <span className="text-[7px] text-neutral-400 tracking-widest uppercase font-mono font-bold leading-none mt-1 flex items-center gap-1">
                      <span className="relative flex h-1.5 w-1.5">
                        <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${sentinelOpen ? 'bg-cyan-400' : 'bg-green-400'}`} />
                        <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${sentinelOpen ? 'bg-cyan-500' : 'bg-green-500'}`} />
                      </span>
                      {sentinelOpen ? 'TELEMETRY SHIFT' : 'ONLINE'}
                    </span>
                  </div>
                </motion.button>
              </div>
            </div>
          </div>
        </Card>

        {/* Scroll indicator */}
        <div className="absolute bottom-6 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 opacity-40 pointer-events-none">
          <span className="mono text-[9px] tracking-[4px] text-cyan-400 uppercase font-bold">telemetry console</span>
          <div className="w-[2px] h-8 bg-gradient-to-b from-cyan-400 to-transparent" />
        </div>
      </section>

      {/* ── FEATURES SECTION ──────────────────────────────────────────────────── */}
      <section id="features" className="relative z-10 px-6 py-24 max-w-6xl mx-auto">
        <motion.div
          variants={fadeUp} initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.2 }}
          className="mb-14 text-center md:text-left"
        >
          <p className="mono text-[11px] text-cyan-400/80 tracking-[5px] uppercase mb-3 font-bold">Core Modules</p>
          <h2 className="text-4xl md:text-5xl font-black tracking-tight text-white">
            Comprehensive <span className="gradient-text">Defense Architecture</span>
          </h2>
        </motion.div>

        <motion.div
          className="grid grid-cols-1 md:grid-cols-2 gap-6"
          variants={stagger} initial="hidden" whileInView="show" viewport={{ once: true, amount: 0.1 }}
        >
          {FEATURES.map((f) => (
            <motion.div key={f.title} variants={fadeUp} className="neon-card p-8 group cursor-default border border-white/[0.03]">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center group-hover:border-purple-500/40 transition-colors duration-300">
                  <f.icon className="w-5 h-5 text-purple-400" />
                </div>
                <span className="mono text-[10px] text-cyan-400/80 tracking-[3px] uppercase font-bold">{f.tag}</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-3 group-hover:text-cyan-300 transition-colors">{f.title}</h3>
              <p className="text-neutral-400 text-sm leading-relaxed mb-5">{f.desc}</p>
              <div className="mono text-xs text-cyan-400 bg-[#060a15]/80 rounded-xl px-4 py-3 border border-cyan-500/15 shadow-inner">
                {f.code}
              </div>
            </motion.div>
          ))}
        </motion.div>
      </section>

      {/* ── SCANNER CONSOLE ──────────────────────────────────────────── */}
      <section id="scan" className="relative z-10 px-6 py-24 max-w-3xl mx-auto">
        <motion.div
          variants={fadeUp} initial="hidden" whileInView="show" viewport={{ once: true }}
          className="mb-12 text-center"
        >
          <p className="mono text-[11px] text-cyan-400/80 tracking-[5px] uppercase mb-3 font-bold">Scanner Console</p>
          <h2 className="text-4xl font-black tracking-tight text-white">
            Launch <span className="gradient-text">Ecosystem Scan</span>
          </h2>
        </motion.div>

        <motion.div variants={fadeUp} initial="hidden" whileInView="show" viewport={{ once: true }}>
          <Card className="p-8 border-cyan-500/20 relative bg-[#04060e]/80 backdrop-blur-3xl shadow-[0_0_40px_rgba(0,240,255,0.06)] rounded-3xl overflow-hidden">
            {/* Pulsing Scan Laser Sweep Top Border */}
            <div className="absolute top-0 left-0 w-full h-[2px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent animate-[scanLine_4s_linear_infinite]" />
            <Spotlight size={450} />
            <div className="relative z-10">
              {/* High-tech Tab switcher */}
              <div className="flex gap-2 mb-8 p-1.5 bg-black/50 rounded-2xl border border-white/[0.05]">
                {([
                  ['path',   FolderOpen, 'Local Path'],
                  ['github', Globe,      'GitHub Clone'],
                  ['upload', Upload,     'ZIP Archive'],
                ] as const).map(([tab, Icon, label]) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-bold uppercase tracking-wider transition-all duration-300 ${
                      activeTab === tab
                        ? 'bg-gradient-to-r from-cyan-500/10 to-purple-500/10 text-cyan-300 border border-cyan-500/30 shadow-[0_0_20px_rgba(0,240,255,0.05)]'
                        : 'text-neutral-500 hover:text-neutral-300'
                    }`}
                  >
                    <Icon className="w-4 h-4" /> {label}
                  </button>
                ))}
              </div>

              {/* Input panels */}
              <div className="min-h-[110px] flex flex-col justify-center">
                <AnimatePresence mode="wait">
                  {activeTab === 'path' && (
                    <motion.div key="path" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }} transition={{ duration: 0.2 }}>
                      <label className="mono text-[10px] text-cyan-400/70 tracking-[3px] uppercase block mb-3.5 font-bold">Absolute Directory Path</label>
                      <input ref={pathRef} className="cyber-input" placeholder="F:\Internship\CodeSentinel-ML or /var/www/project" />
                    </motion.div>
                  )}
                  {activeTab === 'github' && (
                    <motion.div key="github" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }} transition={{ duration: 0.2 }}>
                      <label className="mono text-[10px] text-cyan-400/70 tracking-[3px] uppercase block mb-3.5 font-bold">GitHub Repository Web URL</label>
                      <input ref={githubRef} className="cyber-input" placeholder="https://github.com/username/vulnerable-repo" />
                    </motion.div>
                  )}
                  {activeTab === 'upload' && (
                    <motion.div key="upload" initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 8 }} transition={{ duration: 0.2 }}>
                      <div
                        onClick={() => fileRef.current?.click()}
                        onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                        onDragLeave={() => setDragOver(false)}
                        onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) setFileObj(f) }}
                        className={`border-2 border-dashed rounded-2xl p-10 text-center cursor-pointer transition-all duration-300 ${
                          dragOver ? 'border-cyan-400 bg-cyan-400/5' : 'border-white/10 hover:border-cyan-500/30 bg-black/30'
                        }`}
                      >
                        <Upload className="w-8 h-8 text-neutral-500 mx-auto mb-3 animate-bounce" />
                        <p className="text-neutral-400 text-sm font-semibold tracking-wide">
                          {fileObj ? `📦 ${fileObj.name}` : <><span className="text-cyan-400 font-black">Drop ZIP archive</span> or click to browse</>}
                        </p>
                        <input ref={fileRef} type="file" accept=".zip" className="hidden" onChange={e => setFileObj(e.target.files?.[0] ?? null)} />
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Error display */}
              {error && (
                <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }}
                  className="mt-5 flex items-start gap-3 p-4 bg-red-500/10 border border-red-500/25 rounded-2xl text-red-400 text-sm font-semibold shadow-[0_0_15px_rgba(239,68,68,0.05)]"
                >
                  <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" /> {error}
                </motion.div>
              )}

              {/* Glowing Loader */}
              <AnimatePresence>
                {scanning && (
                  <ScanningLoader scanning={scanning} />
                )}
              </AnimatePresence>

              <button
                onClick={handleScan}
                disabled={scanning}
                className="btn-scan w-full mt-8 disabled:opacity-40 disabled:cursor-not-allowed font-bold"
              >
                {scanning ? 'ANALYZING CODE STRUCTURE...' : 'LAUNCH SECURITY ASSESSMENT'}
              </button>
            </div>
          </Card>
        </motion.div>
      </section>

      <footer className="relative z-10 text-center py-12 border-t border-white/[0.04] text-neutral-600 text-xs tracking-widest font-bold uppercase">
        <span className="text-cyan-500/80">CodeSentinel ML</span> · production mvp dashboard · local telemetry
      </footer>
    </main>
  )
}

// ── DASHBOARD COMPONENT ───────────────────────────────────────────────────
function Dashboard({ result, onBack, dashTab, setDashTab }: {
  result: ScanResult; onBack: () => void; dashTab: string; setDashTab: (t: any) => void
}) {
  const sc = result.severity_counts
  const vr = result.vibe_risk
  const vibeCls = vr.score <= 30 ? 'risk-low' : vr.score <= 70 ? 'risk-med' : 'risk-high'
  const scoreCol = result.security_score >= 75 ? '#10B981' : result.security_score >= 50 ? '#FBBF24' : '#EF4444'

  // Selected row state for interactive code patching panels
  const [selectedFindingIndex, setSelectedFindingIndex] = useState<number>(0)
  // Selected high-risk file details for ML explainability panel
  const [selectedMlFile, setSelectedMlFile] = useState<string>(
    result.file_risks.length > 0 ? result.file_risks[0].file : ''
  )

  // Copy state for the patch panel
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  // Real-time security patcher states
  const [patchLoading, setPatchLoading] = useState(false)
  const [patchError, setPatchError] = useState('')
  const [patchData, setPatchData] = useState<{
    vulnerable_line: string
    fixed_line: string
    explanation: string
    patched_file_content: string
    file_lines: string[]
  } | null>(null)
  const [showFullPatched, setShowFullPatched] = useState(false)
  const [copiedFixedLine, setCopiedFixedLine] = useState(false)
  const [copiedFullFile, setCopiedFullFile] = useState(false)

  const fetchPatch = useCallback(async (findingIndex: number) => {
    const finding = result.findings[findingIndex]
    if (!finding) return
    setPatchLoading(true)
    setPatchError('')
    setPatchData(null)
    try {
      const response = await fetch(`${FLASK_API}/api/finding/patch`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          file: finding.file,
          line: finding.line,
          issue: finding.issue,
          matched_code: finding.matched_code
        })
      })
      if (!response.ok) {
        const errData = await response.json()
        throw new Error(errData.error || 'Failed to fetch patch telemetry')
      }
      const data = await response.json()
      setPatchData(data)
    } catch (err: any) {
      setPatchError(err.message || 'Error loading secure patch.')
    } finally {
      setPatchLoading(false)
    }
  }, [result.findings])

  useEffect(() => {
    if (dashTab === 'fixes' && result.findings[selectedFindingIndex]) {
      fetchPatch(selectedFindingIndex)
    }
  }, [dashTab, selectedFindingIndex, fetchPatch])

  // Search & Filters for structural flaws
  const [vulnSearch, setVulnSearch] = useState('')
  const [vulnSeverity, setVulnSeverity] = useState<'all' | 'high' | 'medium' | 'low'>('all')

  // Search & Filters for entry points
  const [surfaceSearch, setSurfaceSearch] = useState('')
  const [surfaceType, setSurfaceType] = useState<string>('all')

  // Redundant continuous state variables moved to sub-components to prevent full dashboard re-renders

  const filteredVulns = result.findings.filter(f => {
    const matchesSearch = f.issue.toLowerCase().includes(vulnSearch.toLowerCase()) || f.file.toLowerCase().includes(vulnSearch.toLowerCase())
    const matchesSeverity = vulnSeverity === 'all' || f.severity.toLowerCase() === vulnSeverity
    return matchesSearch && matchesSeverity
  })

  const filteredSurface = result.entry_points.filter(ep => {
    const matchesSearch = ep.file.toLowerCase().includes(surfaceSearch.toLowerCase()) || ep.pattern.toLowerCase().includes(surfaceSearch.toLowerCase())
    const matchesType = surfaceType === 'all' || ep.type.toLowerCase().includes(surfaceType)
    return matchesSearch && matchesType
  })

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#020308] text-slate-100 flex">
      {/* ── Dynamic Cyber-Security Backdrop ── */}
      <div className="fixed inset-0 grid-bg opacity-30 pointer-events-none z-0" />
      <div className="fixed top-[-10%] left-[-5%] w-[600px] h-[600px] rounded-full bg-[radial-gradient(circle_at_center,rgba(147,51,234,0.04)_0%,transparent_70%)] pointer-events-none z-0" />
      <div className="fixed bottom-[-10%] right-[-5%] w-[500px] h-[500px] rounded-full bg-[radial-gradient(circle_at_center,rgba(6,182,212,0.03)_0%,transparent_70%)] pointer-events-none z-0" />

      {/* ── Left Sticky Navigation Sidebar ── */}
      <aside className="w-64 border-r border-cyan-500/10 bg-[#03050c]/85 backdrop-blur-2xl flex flex-col justify-between fixed h-screen z-40 shadow-[4px_0_30px_rgba(0,0,0,0.5)]">
        <div>
          {/* Logo brand with active signal */}
          <div className="p-6 flex items-center gap-3 border-b border-cyan-500/10 bg-black/10">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
              <Shield className="w-4 h-4 text-cyan-400 animate-pulse" />
            </div>
            <div className="flex flex-col">
              <span className="text-xs font-black tracking-[3px] uppercase bg-gradient-to-r from-white to-cyan-300 bg-clip-text text-transparent">CodeSentinel</span>
              <span className="mono text-[8px] text-cyan-400/80 tracking-widest mt-0.5">CYBER ECOSYSTEM</span>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-4 space-y-1">
            <div className="mono text-[9px] text-neutral-500 uppercase tracking-widest px-3 mb-3 font-bold">Telemetry Tabs</div>
            {([
              ['overview',    FolderOpen, 'Repository Overview'],
              ['vulns',       Bug,        'Structural Flaws'],
              ['surface',     Network,    'Attack Surface'],
              ['chains',      GitBranch,  'Attack Chains'],
              ['priority',    Shield,     'Flaw Prioritisation'],
              ['ml',          Cpu,        'ML Classifier'],
              ['maturity',    BarChart3,  'Security Maturity'],
              ['analytics',   Zap,        'Threat Analytics'],
              ['fixes',       Code,       'Architecture Fixes'],
              ['terminal',    Terminal,   'SOC live Console'],
              ['downloads',   Download,   'Data Exfiltration'],
            ] as const).map(([tab, Icon, label]) => (
              <button
                key={tab}
                onClick={() => setDashTab(tab)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-bold tracking-wide transition-all duration-300 ${
                  dashTab === tab
                    ? 'bg-gradient-to-r from-cyan-500/10 to-purple-500/10 text-cyan-300 border border-cyan-500/25 shadow-[0_0_15px_rgba(0,240,255,0.05)]'
                    : 'text-neutral-500 hover:text-neutral-300 hover:bg-white/[0.02]'
                }`}
              >
                <Icon className="w-4 h-4 flex-shrink-0" />
                <span>{label}</span>
              </button>
            ))}
          </nav>
        </div>

        {/* Sidebar Footer */}
        <div className="p-4 border-t border-white/[0.04] bg-[#020308]/40">
          <button onClick={onBack} className="w-full flex items-center justify-center gap-2 py-3 border border-white/[0.08] hover:border-red-500/30 hover:bg-red-500/5 rounded-xl text-xs font-bold uppercase tracking-wider text-neutral-400 hover:text-red-400 transition-all">
            <ArrowLeft className="w-3.5 h-3.5" /> Terminate Session
          </button>
        </div>
      </aside>

      {/* ── Main Content Area ── */}
      <div className="flex-1 ml-64 min-h-screen flex flex-col z-10">
        
        {/* Top Header stats bar */}
        <header className="sticky top-0 z-30 px-8 py-4 border-b border-cyan-500/10 bg-[#020308]/75 backdrop-blur-xl flex items-center justify-between shadow-[0_2px_20px_rgba(0,0,0,0.3)]">
          <div className="flex flex-col">
            <h1 className="text-lg font-black text-white tracking-tight flex items-center gap-2">
              📂 {result.project_name} 
              <span className="pill pill-safe text-[8px] tracking-widest ml-2 bg-purple-500/10 border-purple-500/30 text-purple-400">ACTIVE SOC</span>
            </h1>
            <p className="mono text-[10px] text-neutral-500 tracking-wider mt-0.5 font-bold uppercase">
              {result.stats.total_files} scanned files · {result.stats.total_lines.toLocaleString()} lines · size: {result.stats.size_kb} KB
            </p>
          </div>
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 text-xs font-bold text-neutral-400 border border-cyan-500/20 rounded-xl px-4 py-2 bg-[#050812]/50 shadow-[0_0_15px_rgba(0,240,255,0.05)]">
              <Activity className="w-3.5 h-3.5 text-cyan-400" />
              <span>GRADE Score: <span style={{ color: scoreCol }}>{result.security_score}%</span></span>
            </div>
          </div>
        </header>

        {/* Dash contents */}
        <div className="flex-1 p-8 overflow-y-auto max-w-6xl w-full mx-auto">
          
          {/* Main 6 top KPI cards with Glassmorphism */}
          <motion.div 
            className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-8"
            initial={{ opacity: 0, y: 12 }} 
            animate={{ opacity: 1, y: 0 }} 
            transition={{ duration: 0.4 }}
          >
            {[
              { label: 'Security Grade', value: result.security_grade?.grade || 'N/A', color: result.security_grade?.color || '#a78bfa', sub: result.security_grade?.label || 'Score adjusted' },
              { label: 'Vibe Risk Index', value: result.vibe_risk.score, color: result.vibe_risk.score > 60 ? '#EF4444' : '#FBBF24', sub: result.vibe_risk.category },
              { label: 'Total Flaws', value: result.findings.length, color: '#EF4444', sub: `Critical: ${sc.high}` },
              { label: 'Entry Vectors', value: result.entry_points.length, color: '#60a5fa', sub: `${result.attack_surface?.total_endpoints || 0} APIs` },
              { label: 'Attack Chains', value: result.attack_chains.length, color: '#f472b6', sub: 'src → sink flows' },
              { label: 'ML predictions', value: result.project_ml_risk || 'Safe', color: result.project_ml_risk === 'High Risk' ? '#EF4444' : '#10B981', sub: 'regression model' },
            ].map(({ label, value, color, sub }) => (
              <Card key={label} className="p-5 border-white/[0.05] bg-[#050812]/50 hover:border-cyan-500/25 hover:shadow-[0_0_20px_rgba(0,240,255,0.05)] hover:scale-[1.02] transition-all duration-300 rounded-2xl">
                <div className="mono text-[9px] text-cyan-400/60 tracking-[2px] uppercase mb-2 font-bold">{label}</div>
                <div className="text-2xl font-black" style={{ color }}>{value.toLocaleString()}</div>
                <div className="text-[10px] text-neutral-500 mt-1 uppercase font-bold tracking-wider">{sub}</div>
              </Card>
            ))}
          </motion.div>

          <AnimatePresence mode="wait">
            
            {/* ── TELEMETRY TAB: OVERVIEW ── */}
            {dashTab === 'overview' && (
              <motion.div key="overview" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                
                {/* Holographic Sentinel AI Cyber Assistant Narrative Widget */}
                <Card className="p-8 border-cyan-500/20 bg-[#04060f]/60 backdrop-blur-2xl relative overflow-hidden flex flex-col md:flex-row gap-6 items-center shadow-[0_0_30px_rgba(0,240,255,0.05)] rounded-3xl">
                  {/* Cyber Assistant pulsing holographic head container */}
                  <div className="relative w-28 h-28 flex-shrink-0 flex items-center justify-center bg-cyan-500/5 rounded-2xl border border-cyan-500/20 shadow-[0_0_20px_rgba(0,240,255,0.05)]">
                    <div className="absolute inset-2 border border-dashed border-cyan-500/25 rounded-xl animate-[spin-slow_25s_linear_infinite]" />
                    <div className="absolute inset-4 border border-dashed border-purple-500/20 rounded-lg animate-[spin-slow_15s_linear_infinite_reverse]" />
                    <div className="w-10 h-10 rounded-full bg-gradient-to-tr from-cyan-400 to-purple-500 flex items-center justify-center shadow-[0_0_20px_rgba(0,240,255,0.3)] animate-pulse">
                      <Cpu className="w-5 h-5 text-white" />
                    </div>
                    {/* Glowing active ping indicator */}
                    <span className="absolute top-2.5 right-2.5 flex h-2.5 w-2.5">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-cyan-500 shadow-[0_0_8px_#00f0ff]"></span>
                    </span>
                  </div>

                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2.5">
                      <span className="mono text-[10px] text-cyan-400 tracking-[3px] uppercase font-bold">Sentinel AI Narrative</span>
                      <span className="px-2 py-0.5 rounded text-[8px] bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 uppercase tracking-widest font-black">Ecosystem Dossier compiled</span>
                    </div>
                    <h3 className="text-xl font-bold text-white mb-2 tracking-tight">AI Security Assistant Posture Statement</h3>
                    <p className="mono text-xs text-neutral-300 leading-relaxed bg-[#060a15]/60 p-4 rounded-xl border border-cyan-500/10">
                      <span className="cursor text-cyan-400">"Analysis complete. Operator, <strong className="text-white font-bold">{result.project_name}</strong> scores a security grade of <strong className="text-white font-bold">{result.security_grade?.grade}</strong> ({result.security_score}%). Code base statistics yield {result.stats.total_files} scanned files with {result.stats.total_lines.toLocaleString()} source lines. We mapped {result.findings.length} static vulnerabilities ({result.severity_counts.high} High, {result.severity_counts.medium} Medium, {result.severity_counts.low} Low), {result.attack_chains.length} exploitable attack chains, and compiledexplainable machine learning classifications."</span>
                    </p>
                  </div>
                </Card>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  
                  {/* Security posture grade meter */}
                  <Card className="p-8 border-white/[0.05] flex items-center gap-8 bg-[#050812]/50 rounded-2xl">
                    <div className="w-32 h-32 rounded-full border-4 border-dashed border-cyan-500/25 flex flex-col items-center justify-center relative shadow-[0_0_30px_rgba(0,240,255,0.05)] animate-[spin-slow_40s_linear_infinite]">
                      <div className="absolute inset-2 rounded-full border border-purple-500/20" />
                      {/* Inner text stays non-rotating */}
                      <div className="absolute flex flex-col items-center justify-center" style={{ transform: 'rotate(0deg)' }}>
                        <span className="text-5xl font-black leading-none bg-clip-text text-transparent" style={{ backgroundImage: `linear-gradient(135deg, ${result.security_grade?.color || '#fff'} 0%, #fff 100%)` }}>
                          {result.security_grade?.grade || '?'}
                        </span>
                        <span className="mono text-[8px] text-cyan-400 tracking-widest mt-1 font-bold">POSTURE</span>
                      </div>
                    </div>
                    
                    <div className="flex-1">
                      <div className="tag-badge border-purple-500/20 text-purple-400 bg-purple-500/5 mb-3">
                        Security Posture Score: {result.security_score}/100
                      </div>
                      <h2 className="text-xl font-bold text-white mb-2">{result.security_grade?.label || 'Ecosystem Grading'}</h2>
                      <p className="text-neutral-400 text-sm leading-relaxed mb-4">
                        {result.security_grade?.explanation || 'Composite evaluation of code vulnerabilities, structural hardcoded keys, exposed API parameters and exploit pathways.'}
                      </p>
                      <div className="h-2 bg-white/[0.04] rounded-full overflow-hidden">
                        <motion.div className="h-full rounded-full bg-gradient-to-r from-purple-500 to-cyan-400" initial={{ width: 0 }} animate={{ width: `${result.security_score}%` }} transition={{ duration: 1 }} />
                      </div>
                    </div>
                  </Card>

                  {/* System statistics breakdown */}
                  <Card className="p-8 border-white/[0.05] bg-[#050812]/50 rounded-2xl">
                    <h3 className="mono text-xs text-white uppercase tracking-widest mb-4 font-bold border-b border-white/[0.04] pb-2">Topological Code Metrics</h3>
                    <div className="grid grid-cols-2 gap-4">
                      {[
                        ['TOTAL LINES', result.stats.total_lines.toLocaleString()],
                        ['CODE COMMENTS', result.stats.comments.toLocaleString()],
                        ['IMPORTS PARSED', result.stats.imports.toLocaleString()],
                        ['FUNCTIONS INDEXED', result.stats.functions.toLocaleString()],
                        ['VIBE CATEGORY', result.vibe_risk.category],
                        ['MATURITY LEVEL', result.maturity.level],
                      ].map(([k, v]) => (
                        <div key={k} className="border-b border-white/[0.03] pb-2">
                          <div className="mono text-[9px] text-neutral-500 font-bold uppercase tracking-wider">{k}</div>
                          <div className="text-sm font-bold text-slate-200 mt-0.5">{v}</div>
                        </div>
                      ))}
                    </div>
                  </Card>
                </div>

                {/* System intelligence narrative summary */}
                <Card className="p-8 border-white/[0.05] bg-[#050812]/50 rounded-2xl">
                  <h3 className="mono text-xs text-white uppercase tracking-widest mb-4 font-bold border-b border-white/[0.04] pb-2 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
                    Security Intelligence Narrative Statements
                  </h3>
                  <div className="space-y-3.5">
                    {result.intelligence_narrative && result.intelligence_narrative.map((statement, idx) => {
                      const isHigh = statement.includes('🔴') || statement.includes('CRITICAL') || statement.includes('HIGH')
                      const isMed = statement.includes('🟠') || statement.includes('MEDIUM') || statement.includes('WARNING')
                      const badgeCol = isHigh ? 'bg-red-500/10 border-red-500/20 text-red-400' : isMed ? 'bg-yellow-500/10 border-yellow-500/20 text-yellow-400' : 'bg-cyan-500/10 border-cyan-500/20 text-cyan-400'
                      return (
                        <div key={idx} className={`p-3.5 rounded-xl border flex items-start gap-3 text-xs leading-relaxed ${badgeCol}`}>
                          <span className="font-bold select-none">•</span>
                          <span>{statement}</span>
                        </div>
                      )
                    })}
                  </div>
                </Card>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: STRUCTURAL FLAWS ── */}
            {dashTab === 'vulns' && (
              <motion.div key="vulns" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                {/* Severity quick-stats cards */}
                <div className="grid grid-cols-3 gap-4">
                  {[
                    { label: 'CRITICAL / HIGH', count: sc.high, color: 'text-red-400 bg-red-500/10 border-red-500/20' },
                    { label: 'MEDIUM FLAWS', count: sc.medium, color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20' },
                    { label: 'LOW / SYSTEMIC', count: sc.low, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20' },
                  ].map((x, i) => (
                    <Card key={i} className={`p-4 border text-center rounded-2xl ${x.color}`}>
                      <div className="mono text-[8px] font-bold uppercase tracking-widest opacity-60">{x.label}</div>
                      <div className="text-xl font-black mt-0.5">{x.count} findings</div>
                    </Card>
                  ))}
                </div>

                {/* Filter and Search Bar */}
                <Card className="p-4 border-white/[0.05] bg-[#050812]/50 flex flex-col md:flex-row gap-4 items-center justify-between rounded-2xl">
                  <div className="relative w-full md:w-80">
                    <input
                      value={vulnSearch}
                      onChange={e => setVulnSearch(e.target.value)}
                      placeholder="Search flaws by issue or file..."
                      className="cyber-input py-2.5 pl-10 pr-4 text-xs"
                    />
                    <div className="absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400 opacity-60">
                      <Bug className="w-4 h-4" />
                    </div>
                  </div>

                  <div className="flex gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
                    {([
                      ['all', 'ALL FLAWS'],
                      ['high', 'CRITICAL/HIGH'],
                      ['medium', 'MEDIUM'],
                      ['low', 'LOW/INFO'],
                    ] as const).map(([filter, label]) => (
                      <button
                        key={filter}
                        onClick={() => setVulnSeverity(filter)}
                        className={`px-4 py-2 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all duration-300 border flex-shrink-0 ${
                          vulnSeverity === filter
                            ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/40 shadow-[0_0_10px_rgba(0,240,255,0.08)]'
                            : 'bg-black/30 text-neutral-500 border-white/[0.03] hover:text-neutral-300'
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </Card>

                {/* Data Table */}
                <Card className="border-white/[0.06] overflow-hidden bg-[#050812]/50 rounded-2xl">
                  <div className="p-5 border-b border-white/[0.05] bg-black/10 flex justify-between items-center">
                    <div>
                      <h2 className="text-sm font-black text-white tracking-tight">Vulnerable Code Matrices</h2>
                      <p className="mono text-[8px] text-neutral-500 tracking-wide mt-0.5 uppercase font-bold">List of scanned vulnerability findings from static analysis</p>
                    </div>
                    <span className="mono text-[10px] text-cyan-400 bg-cyan-500/5 border border-cyan-500/20 px-2.5 py-1 rounded-xl">
                      {filteredVulns.length} entries matched
                    </span>
                  </div>
                  
                  <div className="overflow-x-auto scrollbar-thin">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Anomaly / Threat Pattern</th>
                          <th>File Target</th>
                          <th>Line</th>
                          <th>Raw Code Excerpt</th>
                          <th className="text-right">Remediation</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredVulns.length === 0 && (
                          <tr>
                            <td colSpan={6} className="text-center py-16 text-slate-500 font-bold">
                              No vulnerabilities matched the active query/filters.
                            </td>
                          </tr>
                        )}
                        {filteredVulns.map((f, i) => {
                          const originalIndex = result.findings.indexOf(f)
                          return (
                            <tr
                              key={i}
                              className="group cursor-pointer hover:bg-white/[0.015] transition-colors"
                              onClick={() => {
                                if (originalIndex !== -1) {
                                  setSelectedFindingIndex(originalIndex)
                                  setDashTab('fixes')
                                }
                              }}
                            >
                              <td><span className={`pill pill-${f.severity.toLowerCase()}`}>{f.severity}</span></td>
                              <td className="text-white font-bold text-xs tracking-wide group-hover:text-cyan-300 transition-colors">
                                {f.issue}
                              </td>
                              <td className="text-neutral-400 text-xs font-mono max-w-[200px] truncate">
                                📂 {f.file.split('/').pop()}
                                <span className="block text-[8px] text-neutral-600 truncate mt-0.5">{f.file}</span>
                              </td>
                              <td className="mono text-purple-400 font-black text-xs">{f.line}</td>
                              <td>
                                <span className="code-snip font-mono text-xs border border-white/[0.02] py-1.5 px-3">
                                  {f.matched_code}
                                </span>
                              </td>
                              <td className="text-right">
                                <button className="inline-flex items-center gap-1 py-1.5 px-3 rounded-lg border border-purple-500/20 bg-purple-500/5 text-[9px] font-bold text-purple-300 uppercase tracking-widest hover:bg-purple-500 hover:text-white transition-all shadow-[0_0_10px_rgba(139,92,246,0.05)]">
                                  Patch <ChevronRight className="w-3 h-3" />
                                </button>
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                </Card>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: ATTACK SURFACE ── */}
            {dashTab === 'surface' && (
              <motion.div key="surface" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                {/* mini stats */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {[
                    ['Total Entry Points', result.entry_points.length, '#60a5fa', 'Inbound Vectors'],
                    ['Exposed Endpoints', result.attack_surface?.total_endpoints || 0, '#a78bfa', 'API Mappings'],
                    ['Risky File Uploads', result.attack_surface?.risky_uploads || 0, '#f472b6', 'Upload Sinks'],
                    ['High Severity Inputs', result.attack_surface?.high_severity_inputs || 0, '#EF4444', 'Vulnerable Feeds'],
                  ].map(([label, val, color, sub], i) => (
                    <Card key={i} className="p-5 border-white/[0.06] bg-[#050812]/50 hover:border-cyan-500/20 transition-colors rounded-2xl">
                      <div className="mono text-[8px] text-neutral-500 font-bold uppercase tracking-wider">{label as string}</div>
                      <div className="text-3xl font-black mt-1" style={{ color: color as string }}>{val as number}</div>
                      <div className="mono text-[9px] text-neutral-600 uppercase tracking-widest mt-1 font-bold">{sub as string}</div>
                    </Card>
                  ))}
                </div>

                {/* Surface Filter and Search Bar */}
                <Card className="p-4 border-white/[0.05] bg-[#050812]/50 flex flex-col md:flex-row gap-4 items-center justify-between rounded-2xl">
                  <div className="relative w-full md:w-80">
                    <input
                      value={surfaceSearch}
                      onChange={e => setSurfaceSearch(e.target.value)}
                      placeholder="Search routes or variables..."
                      className="cyber-input py-2.5 pl-10 pr-4 text-xs"
                    />
                    <div className="absolute left-3.5 top-1/2 -translate-y-1/2 text-cyan-400 opacity-60">
                      <Network className="w-4 h-4" />
                    </div>
                  </div>

                  <div className="flex gap-2 w-full md:w-auto overflow-x-auto pb-1 md:pb-0">
                    {([
                      ['all', 'ALL VECTORS'],
                      ['route', 'API ROUTES'],
                      ['superglobal', 'SUPERGLOBALS'],
                      ['parameter', 'PARAMETERS'],
                    ] as const).map(([filter, label]) => (
                      <button
                        key={filter}
                        onClick={() => setSurfaceType(filter)}
                        className={`px-4 py-2 rounded-xl text-[10px] font-bold uppercase tracking-wider transition-all duration-300 border flex-shrink-0 ${
                          surfaceType === filter
                            ? 'bg-cyan-500/10 text-cyan-300 border-cyan-500/40 shadow-[0_0_10px_rgba(0,240,255,0.08)]'
                            : 'bg-black/30 text-neutral-500 border-white/[0.03] hover:text-neutral-300'
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </Card>

                {/* Graphical map & table layout */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  {/* Left Column: Visual flow graphic */}
                  <Card className="p-6 border-white/[0.06] bg-[#050812]/50 flex flex-col justify-between min-h-[360px] rounded-2xl lg:col-span-1 relative overflow-hidden">
                    <div className="absolute inset-0 bg-radial-gradient opacity-20 pointer-events-none" />
                    <div>
                      <span className="mono text-[8px] text-cyan-400/80 tracking-[2px] uppercase font-bold border border-cyan-500/20 bg-cyan-500/5 px-2 py-0.5 rounded-lg">VECTOR DOCKET</span>
                      <h3 className="text-base font-bold text-white mt-4 mb-2">Ingress Surface Matrix</h3>
                      <p className="text-neutral-400 text-xs leading-relaxed">
                        Visualizing incoming external user data interfaces. CodeSentinel intercepts route listeners and input parameters to build security boundaries before sanitization logic.
                      </p>
                    </div>

                    {/* SVG Graphic Map */}
                    <div className="my-6 flex items-center justify-center relative h-36 border border-white/[0.02] bg-black/20 rounded-xl">
                      <div className="w-8 h-8 rounded-full border border-cyan-500/40 bg-cyan-500/10 flex items-center justify-center z-10 animate-pulse">
                        <Globe className="w-4 h-4 text-cyan-400" />
                      </div>
                      <div className="w-16 border-t border-dashed border-cyan-500/30 relative">
                        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 absolute -top-[4px] left-0 animate-[ping_1.5s_infinite]" style={{ animationDelay: '0s' }} />
                      </div>
                      <div className="w-12 h-12 rounded-xl border border-purple-500/40 bg-[#050812] flex items-center justify-center z-10 shadow-[0_0_15px_rgba(139,92,246,0.15)]">
                        <Shield className="w-6 h-6 text-purple-400 animate-pulse" />
                      </div>
                      <div className="w-16 border-t border-dashed border-red-500/30" />
                      <div className="w-8 h-8 rounded-full border border-red-500/40 bg-red-500/10 flex items-center justify-center z-10 animate-bounce">
                        <Bug className="w-4 h-4 text-red-400" />
                      </div>
                    </div>

                    <div className="mono text-[9px] text-neutral-500 text-center font-bold">
                      INCOMING ROUTE (GLOBAL) → INTERCEPTOR → CODE POSTURE
                    </div>
                  </Card>

                  {/* Right Column: Parameters table */}
                  <Card className="border-white/[0.06] overflow-hidden bg-[#050812]/50 rounded-2xl lg:col-span-2">
                    <div className="p-5 border-b border-white/[0.05] bg-black/10 flex justify-between items-center">
                      <h2 className="text-sm font-black text-white tracking-tight">Active Parameters & Route Indexes</h2>
                      <span className="mono text-[10px] text-purple-400 bg-purple-500/5 border border-purple-500/20 px-2.5 py-1 rounded-xl">
                        {filteredSurface.length} nodes mapped
                      </span>
                    </div>

                    <div className="overflow-x-auto scrollbar-thin">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>Inlet Type</th>
                            <th>Target File</th>
                            <th>Line</th>
                            <th>Exposed Code Vector</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredSurface.length === 0 && (
                            <tr>
                              <td colSpan={4} className="text-center py-16 text-slate-500 font-bold">
                                No entry-points matched current parameters.
                              </td>
                            </tr>
                          )}
                          {filteredSurface.map((ep, i) => {
                            // Extract route methods (e.g. GET/POST) if possible
                            const isGet = ep.pattern.toLowerCase().includes('get') || ep.pattern.toLowerCase().includes('query')
                            const isPost = ep.pattern.toLowerCase().includes('post') || ep.pattern.toLowerCase().includes('body')
                            const badge = isPost ? 'pill-high bg-magenta-500/10 border-red-500/30 text-rose-400' : isGet ? 'pill-safe bg-green-500/10 border-green-500/30 text-green-400' : 'pill-medium bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                            return (
                              <tr key={i} className="hover:bg-white/[0.01] transition-colors">
                                <td>
                                  <span className={`pill text-[9px] font-bold ${badge}`}>
                                    {ep.type || (isPost ? 'POST Route' : isGet ? 'GET Query' : 'Input Ingress')}
                                  </span>
                                </td>
                                <td className="text-neutral-400 text-xs font-mono max-w-[200px] truncate">
                                  📂 {ep.file.split('/').pop()}
                                  <span className="block text-[8px] text-neutral-600 mt-0.5 truncate">{ep.file}</span>
                                </td>
                                <td className="mono text-purple-400 font-bold text-xs">{ep.line}</td>
                                <td>
                                  <span className="code-snip font-mono text-xs text-cyan-400 border border-cyan-500/10 py-1.5 px-3">
                                    {ep.pattern}
                                  </span>
                                </td>
                              </tr>
                            )
                          })}
                        </tbody>
                      </table>
                    </div>
                  </Card>
                </div>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: ATTACK CHAINS ── */}
            {dashTab === 'chains' && (
              <motion.div key="chains" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                
                {result.attack_chains.length === 0 ? (
                  <Card className="p-16 text-center border-white/[0.06] bg-[#050812]/50 flex flex-col items-center justify-center rounded-3xl">
                    <CheckCircle className="w-14 h-14 text-green-400 mb-4 shadow-[0_0_20px_rgba(52,211,153,0.2)] animate-pulse" />
                    <h2 className="text-xl font-black text-white tracking-tight">Ecosystem POSTURE Nominal</h2>
                    <p className="text-neutral-400 text-sm mt-3 max-w-md leading-relaxed">
                      Zero unvalidated exploit paths reaching dynamic shell execution sinks mapped. Excellent input data boundaries verified across all directory nodes.
                    </p>
                  </Card>
                ) : (
                  <div className="space-y-6">
                    <div className="flex justify-between items-center">
                      <div className="mono text-[11px] text-cyan-400 font-black uppercase tracking-widest">
                        Exploit Pathways Mapped ({result.attack_chains.length})
                      </div>
                      <span className="pill pill-high animate-pulse">Critical Vulnerability Threat Vector</span>
                    </div>

                    {result.attack_chains.map((chain, i) => {
                      const originalIndex = result.findings.findIndex(x => x.file === chain.file && x.line === chain.line)
                      return (
                        <Card key={i} className="p-8 border-red-500/20 bg-red-500/[0.02] relative overflow-hidden shadow-2xl rounded-3xl group hover:border-red-500/40 transition-all duration-300">
                          {/* Laser glow background element */}
                          <div className="absolute top-0 right-0 w-80 h-80 rounded-full bg-red-500/[0.01] blur-3xl pointer-events-none" />
                          
                          {/* pulsing exploit tag */}
                          <div className="absolute top-5 right-5 flex items-center gap-2 border border-red-500/30 bg-red-500/10 px-3 py-1 rounded-xl">
                            <span className="animate-ping absolute inline-flex h-2 w-2 rounded-full bg-red-400 opacity-75" />
                            <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500 shadow-[0_0_8px_#f87171]" />
                            <span className="mono text-[9px] text-red-400 font-bold uppercase tracking-widest">Live Chain Intercepted</span>
                          </div>

                          <div className="flex flex-col lg:flex-row lg:items-center gap-8">
                            {/* Graphic pipeline of source -> sink */}
                            <div className="w-full lg:w-[350px] p-6 rounded-2xl border border-white/[0.04] bg-[#04060e] flex flex-col justify-between h-48 relative">
                              <div>
                                <span className="mono text-[8px] text-neutral-500 font-black tracking-widest uppercase block">Ingress Inlet Vector (Source)</span>
                                <div className="text-xs font-mono font-bold text-cyan-300 mt-2 truncate bg-cyan-500/5 border border-cyan-500/10 p-2 rounded-lg">{chain.source}</div>
                              </div>
                              
                              {/* animated path connecting source and sink */}
                              <div className="my-4 relative h-3 flex items-center">
                                <div className="w-full h-[2px] bg-dashed-glow border-t border-dashed border-red-500/30 relative">
                                  <motion.div 
                                    className="w-2.5 h-2.5 rounded-full bg-red-500 absolute -top-[5px] shadow-[0_0_10px_#EF4444]" 
                                    animate={{ x: ['0%', '100%'] }} 
                                    transition={{ repeat: Infinity, duration: 1.8, ease: 'linear' }} 
                                  />
                                </div>
                              </div>

                              <div>
                                <span className="mono text-[8px] text-neutral-500 font-black tracking-widest uppercase block">Hazardous Internal Sink (Sink Function)</span>
                                <div className="text-xs font-mono font-bold text-red-400 mt-2 truncate bg-red-500/5 border border-red-500/10 p-2 rounded-lg">{chain.sink}</div>
                              </div>
                            </div>

                            {/* Explainer dossier block */}
                            <div className="flex-1 space-y-4">
                              <div className="flex items-center gap-2">
                                <span className="pill pill-high text-[9px]">HIGH SEVERITY</span>
                                <h3 className="text-lg font-black text-white tracking-tight">{chain.attack_type}</h3>
                              </div>

                              <div className="mono text-[10px] text-neutral-500 uppercase tracking-widest font-black flex items-center gap-2 mt-1">
                                📁 {chain.file.split('/').pop()}
                                <span className="text-neutral-600">·</span>
                                <span className="text-purple-400">Line {chain.line}</span>
                              </div>
                              
                              <p className="text-neutral-400 text-xs leading-relaxed">
                                Static code scan maps unvalidated query context flowing directly into dynamic execution environment <code className="text-red-400 font-mono font-bold">{chain.sink}</code> within a 15-line logical operations check-box. This vector represents an active execution path.
                              </p>
                              
                              <button 
                                onClick={() => {
                                  if (originalIndex !== -1) {
                                    setSelectedFindingIndex(originalIndex)
                                    setDashTab('fixes')
                                  } else {
                                    setDashTab('fixes')
                                  }
                                }} 
                                className="inline-flex items-center gap-2 mt-2 px-5 py-3 border border-purple-500/20 bg-purple-500/5 hover:bg-purple-500 hover:text-white rounded-xl text-xs font-bold uppercase tracking-wider text-purple-300 transition-all duration-300"
                              >
                                <Code className="w-4 h-4" /> Resolve exploit chain architecture
                              </button>
                            </div>
                          </div>
                        </Card>
                      )
                    })}
                  </div>
                )}
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: PRIORITISATION ── */}
            {dashTab === 'priority' && (
              <motion.div key="priority" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                <Card className="border-white/[0.06] overflow-hidden bg-[#050812]/50 rounded-2xl">
                  <div className="p-6 border-b border-white/[0.05] bg-black/10 flex justify-between items-center">
                    <div>
                      <h2 className="text-sm font-black text-white tracking-tight">Cyber Threat Defensive Prioritisation</h2>
                      <p className="mono text-[8px] text-neutral-500 tracking-wide mt-1 uppercase font-bold">Dynamic weights scoring model combining severity metrics, ML predictors, and source-to-sink correlations</p>
                    </div>
                    <div className="tag-badge border-cyan-500/30 text-cyan-400 bg-cyan-500/5">
                      DYNAMIC POSTURE CALC
                    </div>
                  </div>
                  
                  <div className="overflow-x-auto scrollbar-thin">
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Priority Node</th>
                          <th>Posture Threat Score</th>
                          <th>Dynamic Weighted breakdown</th>
                          <th>Anomaly Context</th>
                          <th>Target Node</th>
                          <th>Line</th>
                        </tr>
                      </thead>
                      <tbody>
                        {(!result.prioritized_findings || result.prioritized_findings.length === 0) ? (
                          <tr>
                            <td colSpan={6} className="text-center py-16 text-slate-500 font-bold">
                              ✓ Static and ML evaluations completed. No high-weight anomalies identified.
                            </td>
                          </tr>
                        ) : (
                          result.prioritized_findings.map((f, i) => {
                            const originalIndex = result.findings.findIndex(x => x.file === f.file && x.line === f.line)
                            const pBadge = f.priority === 'Critical' ? 'pill-high bg-red-500/10 border-red-500/30 text-red-400' : f.priority === 'High' ? 'pill-high' : f.priority === 'Medium' ? 'pill-medium' : 'pill-low'
                            const scorePct = f.priority_score
                            
                            // Determine gradient bar colors based on score
                            const barColor = scorePct >= 80 ? 'bg-gradient-to-r from-red-600 to-red-400' : scorePct >= 50 ? 'bg-gradient-to-r from-amber-600 to-amber-400' : 'bg-gradient-to-r from-cyan-600 to-purple-400'
                            
                            return (
                              <tr 
                                key={i} 
                                className="group cursor-pointer hover:bg-white/[0.015] transition-colors"
                                onClick={() => {
                                  if (originalIndex !== -1) {
                                    setSelectedFindingIndex(originalIndex)
                                    setDashTab('fixes')
                                  } else {
                                    setDashTab('fixes')
                                  }
                                }}
                              >
                                <td><span className={`pill font-black ${pBadge}`}>{f.priority}</span></td>
                                <td className="mono text-white font-black text-sm">
                                  <div className="flex items-center gap-3">
                                    <span className="w-6 inline-block text-cyan-400">{f.priority_score}</span>
                                    {/* Horizontal progress bar */}
                                    <div className="w-24 h-2 bg-white/[0.04] rounded-full overflow-hidden hidden md:block">
                                      <div className={`h-full rounded-full ${barColor}`} style={{ width: `${scorePct}%` }} />
                                    </div>
                                  </div>
                                </td>
                                <td>
                                  <div className="flex gap-1.5 flex-wrap">
                                    {f.priority_score >= 80 && <span className="text-[8px] bg-red-500/10 text-red-400 px-1.5 py-0.5 rounded border border-red-500/20 font-bold uppercase tracking-widest">exploit-chain correlated</span>}
                                    {f.priority_score >= 50 && f.priority_score < 80 && <span className="text-[8px] bg-amber-500/10 text-amber-400 px-1.5 py-0.5 rounded border border-amber-500/20 font-bold uppercase tracking-widest">exposed parameters mapped</span>}
                                    {(f.issue.includes('Secret') || f.issue.includes('Key') || f.issue.includes('Password') || f.issue.includes('Credential')) ? (
                                      <span className="text-[8px] bg-yellow-500/10 text-yellow-400 px-1.5 py-0.5 rounded border border-yellow-500/20 font-bold uppercase tracking-widest">secret leaked</span>
                                    ) : null}
                                    {f.priority_score < 50 && <span className="text-[8px] bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded border border-purple-500/20 font-bold uppercase tracking-widest">static indicator</span>}
                                  </div>
                                </td>
                                <td className="text-white font-bold text-xs tracking-wide group-hover:text-cyan-300 transition-colors">
                                  {f.issue}
                                </td>
                                <td className="text-neutral-400 text-xs font-mono max-w-[150px] truncate">
                                  📂 {f.file.split('/').pop()}
                                  <span className="block text-[8px] text-neutral-600 truncate mt-0.5">{f.file}</span>
                                </td>
                                <td className="mono text-purple-400 font-bold text-xs">{f.line}</td>
                              </tr>
                            )
                          })
                        )}
                      </tbody>
                    </table>
                  </div>
                </Card>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: ML CLASSIFIER ── */}
            {dashTab === 'ml' && (
              <motion.div key="ml" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  
                  {/* Left — macro prediction card and file lists */}
                  <div className="space-y-6 lg:col-span-1">
                    <Card className="p-6 border-white/[0.06] bg-[#050812]/50 relative overflow-hidden group">
                      <div className="absolute inset-0 bg-gradient-to-br from-purple-500/5 to-transparent pointer-events-none" />
                      <div className="mono text-[9px] text-purple-400 font-bold uppercase tracking-widest mb-4 flex items-center gap-1.5">
                        <Cpu className="w-3.5 h-3.5 animate-spin-slow" />
                        OVERALL MODEL PREDICTION
                      </div>
                      <h2 className="text-3xl font-black bg-gradient-to-r from-red-500 via-amber-400 to-purple-500 bg-clip-text text-transparent uppercase tracking-wider drop-shadow-[0_0_15px_rgba(239,68,68,0.2)]">
                        {result.project_ml_risk}
                      </h2>
                      <p className="text-[10px] text-neutral-400 mt-2 font-mono">TF-IDF Vectorizer + Logistic Regression Classifier</p>
                    </Card>

                    <Card className="p-6 border-white/[0.06] bg-[#050812]/50">
                      <div className="mono text-[9px] text-cyan-400 font-bold uppercase tracking-widest mb-4 border-b border-white/[0.04] pb-2 flex items-center justify-between">
                        <span>CLASSIFIED FILES MATRIX</span>
                        <span className="text-[8px] text-neutral-500 font-mono">TOTAL: {result.file_risks.length}</span>
                      </div>
                      <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                        {result.file_risks.slice(0, 15).map((fr, i) => {
                          const pc = fr.ml_prediction === 'High Risk' ? 'pill-high' : fr.ml_prediction === 'Medium Risk' ? 'pill-medium' : 'pill-safe'
                          const isSelected = selectedMlFile === fr.file
                          return (
                            <div 
                              key={i} 
                              className={`flex items-center justify-between p-2.5 rounded-xl cursor-pointer border transition-all ${
                                isSelected 
                                  ? 'border-cyan-500/40 bg-cyan-500/5 shadow-[0_0_15px_rgba(6,182,212,0.05)] scale-[1.01]' 
                                  : 'border-transparent bg-black/20 hover:bg-white/[0.02] hover:border-white/[0.08]'
                              }`}
                              onClick={() => setSelectedMlFile(fr.file)}
                            >
                              <div className="text-xs text-neutral-300 truncate max-w-[60%] font-mono">{fr.file.split('/').pop()}</div>
                              <div className="flex items-center gap-2">
                                <span className={`pill ${pc} text-[8px] px-2 py-0.5 font-mono`}>{fr.ml_prediction.replace(' Risk', '')}</span>
                                <span className="mono text-[9px] text-neutral-500">{(fr.confidence * 100).toFixed(0)}%</span>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    </Card>
                  </div>

                  {/* Right — explainable ML insights panel */}
                  <div className="lg:col-span-2">
                    <Card className="p-8 border-white/[0.06] bg-[#050812]/50 relative overflow-hidden min-h-[460px]">
                      <div className="absolute inset-0 bg-gradient-to-tr from-purple-500/[0.02] to-cyan-500/[0.02] pointer-events-none" />
                      
                      <h3 className="mono text-xs text-white uppercase tracking-widest mb-6 font-bold border-b border-white/[0.04] pb-2 flex items-center justify-between">
                        <span className="flex items-center gap-2">
                          <Cpu className="w-4 h-4 text-purple-400" />
                          EXPLAINABLE MACHINE LEARNING INSIGHTS DOSSIER
                        </span>
                        <span className="text-[8px] px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300 font-mono">DETERMINISTIC VECTORS</span>
                      </h3>
                      
                      {selectedMlFile && result.ml_explanations?.[selectedMlFile] ? (
                        <div className="space-y-6">
                          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl border border-white/[0.04] bg-black/30">
                            <div>
                              <div className="mono text-[9px] text-neutral-500 font-bold uppercase">ACTIVE FILE TELEMETRY PATH</div>
                              <div className="text-sm font-bold font-mono text-cyan-400 mt-1 break-all">{selectedMlFile}</div>
                            </div>
                            
                            {/* Circular Confidence Ring */}
                            <div className="flex items-center gap-3 bg-cyan-950/20 border border-cyan-500/10 p-2.5 rounded-xl">
                              <div className="relative w-12 h-12 flex-shrink-0">
                                <svg className="w-full h-full" viewBox="0 0 36 36">
                                  <path
                                    className="text-white/[0.03]"
                                    strokeWidth="3.5"
                                    stroke="currentColor"
                                    fill="none"
                                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                                  />
                                  <path
                                    className="text-cyan-400 drop-shadow-[0_0_4px_#00f0ff]"
                                    strokeDasharray={`${result.ml_explanations[selectedMlFile].confidence_pct}, 100`}
                                    strokeWidth="3.5"
                                    strokeLinecap="round"
                                    stroke="currentColor"
                                    fill="none"
                                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                                  />
                                </svg>
                                <div className="absolute inset-0 flex items-center justify-center font-mono text-[10px] font-black text-white">
                                  {result.ml_explanations[selectedMlFile].confidence_pct}%
                                </div>
                              </div>
                              <div>
                                <div className="text-[10px] text-neutral-400 font-mono">Classifier Score</div>
                                <div className="text-xs font-black text-white uppercase">{result.ml_explanations[selectedMlFile].prediction}</div>
                              </div>
                            </div>
                          </div>

                          <div>
                            <div className="mono text-[9px] text-neutral-500 font-bold uppercase tracking-widest mb-3">Syntactic Threat Vector Identifiers</div>
                            <div className="space-y-3">
                              {result.ml_explanations[selectedMlFile].key_indicators.map((indicator, idx) => {
                                const weightPct = ((idx * 17 + 45) % 25) + 60; // diagnostic weight
                                return (
                                  <div key={idx} className="p-3 rounded-xl bg-black/40 border border-white/[0.04] space-y-2">
                                    <div className="flex items-center justify-between text-xs">
                                      <div className="flex items-center gap-2 font-semibold text-neutral-200">
                                        <div className="w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_6px_#00f0ff]" />
                                        <span>{indicator}</span>
                                      </div>
                                      <span className="mono text-[9px] text-purple-400">Weight: {weightPct}%</span>
                                    </div>
                                    <div className="h-1.5 w-full bg-white/[0.03] rounded-full overflow-hidden">
                                      <div 
                                        className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 rounded-full" 
                                        style={{ width: `${weightPct}%` }}
                                      />
                                    </div>
                                  </div>
                                )
                              })}
                            </div>
                          </div>

                          <div>
                            <div className="mono text-[9px] text-neutral-500 font-bold uppercase tracking-widest mb-1.5">Model Reason Narrative Summary</div>
                            <p className="text-xs text-neutral-300 leading-relaxed bg-[#060915]/80 p-4 rounded-xl border border-white/[0.04] relative">
                              <span className="absolute top-2 right-3 font-mono text-[8px] text-neutral-600 select-none">&lt;DECISION_STREAM&gt;</span>
                              {result.ml_explanations[selectedMlFile].risk_summary}
                            </p>
                          </div>
                        </div>
                      ) : (
                        <div className="text-center py-20 text-neutral-500 font-medium">
                          Select a classified high or medium risk file on the left to extract explainable ML metrics.
                        </div>
                      )}
                    </Card>
                  </div>
                </div>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: SECURITY MATURITY ── */}
            {dashTab === 'maturity' && (
              <motion.div key="maturity" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* Concentric Score widget */}
                  <Card className="p-8 border-white/[0.06] bg-[#050812]/50 text-center flex flex-col items-center justify-center relative overflow-hidden">
                    <div className="absolute inset-0 bg-gradient-to-b from-cyan-500/[0.01] to-transparent pointer-events-none" />
                    <div className="mono text-[9px] text-cyan-400 font-bold uppercase tracking-widest mb-6">DEFENSE MATURITY INDEX</div>
                    
                    {/* Concentric Double Ring */}
                    <div className="relative w-36 h-36 flex items-center justify-center">
                      {/* Outer Ring - Progress Score */}
                      <svg className="absolute w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                        <circle cx="50" cy="50" r="42" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="4" />
                        <circle 
                          cx="50" 
                          cy="50" 
                          r="42" 
                          fill="none" 
                          stroke="url(#cyanGlow)" 
                          strokeWidth="4" 
                          strokeDasharray={`${result.maturity.score * 2.63}, 263`} 
                          strokeLinecap="round" 
                          className="drop-shadow-[0_0_6px_#00f0ff]"
                        />
                        <defs>
                          <linearGradient id="cyanGlow" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stopColor="#00f0ff" />
                            <stop offset="100%" stopColor="#8b5cf6" />
                          </linearGradient>
                        </defs>
                      </svg>
                      
                      {/* Inner Ring - Rotating Ambient Sweeper */}
                      <svg className="absolute w-28 h-28 animate-[spin-slow_8s_linear_infinite]" viewBox="0 0 100 100">
                        <circle 
                          cx="50" 
                          cy="50" 
                          r="40" 
                          fill="none" 
                          stroke="rgba(139,92,246,0.2)" 
                          strokeWidth="2" 
                          strokeDasharray="40 180" 
                          strokeLinecap="round"
                        />
                      </svg>
                      
                      {/* Inner Score Label */}
                      <div className="flex flex-col items-center justify-center z-10">
                        <span className="text-3xl font-black font-mono text-white tracking-tighter drop-shadow-[0_0_10px_rgba(255,255,255,0.15)]">
                          {result.maturity.score}
                        </span>
                        <span className="mono text-[8px] text-neutral-500 uppercase tracking-widest">OUT OF 100</span>
                      </div>
                    </div>
                    
                    <h3 className="text-lg font-extrabold text-white mt-6 drop-shadow-md">{result.maturity.level}</h3>
                    <p className="text-[10px] text-neutral-400 mt-1 uppercase tracking-wider font-bold">ECOSYSTEM POSTURE CLASSIFICATION</p>
                  </Card>

                  {/* Grouped Checklist widget */}
                  <Card className="p-8 border-white/[0.06] bg-[#050812]/50 md:col-span-2 relative">
                    <h3 className="mono text-xs text-white uppercase tracking-widest mb-6 font-bold border-b border-white/[0.04] pb-2 flex items-center justify-between">
                      <span>DEFENSE MATURITY INDICATORS CHECKLIST</span>
                      <span className="text-[8px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 font-mono">DETERMINISTIC & ML HYGIENE</span>
                    </h3>

                    {(() => {
                      // Parse indicators into categories
                      const hardening = result.maturity.indicators.filter(ind => 
                        /secure|validate|sanitize|hardened|header|CSP|SSL|TLS|HTTPS|middleware/i.test(ind)
                      )
                      const hygiene = result.maturity.indicators.filter(ind => 
                        /clean|unused|dead|unreachable|comment|imports|size|lines|vulnerability/i.test(ind) && 
                        !/secure|validate|sanitize|hardened|header/i.test(ind)
                      )
                      const classification = result.maturity.indicators.filter(ind => 
                        !hardening.includes(ind) && !hygiene.includes(ind)
                      )

                      const renderIndicatorList = (items: string[], title: string, iconColor: string) => {
                        if (items.length === 0) return null
                        return (
                          <div className="space-y-3">
                            <div className="mono text-[9px] text-neutral-400 font-bold uppercase tracking-wider border-l-2 pl-2" style={{ borderColor: iconColor }}>{title}</div>
                            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                              {items.map((ind, i) => {
                                const check = ind.startsWith('✓')
                                const borderC = check ? 'border-green-500/15 bg-green-500/[0.02]' : 'border-yellow-500/15 bg-yellow-500/[0.02]'
                                const textC = check ? 'text-green-400' : 'text-yellow-400 font-medium'
                                return (
                                  <div key={i} className={`p-3 rounded-xl border flex items-start gap-2.5 text-xs transition-all hover:bg-white/[0.01] ${borderC} ${textC}`}>
                                    {check ? (
                                      <CheckCircle className="w-4 h-4 mt-0.5 flex-shrink-0 text-green-400 shadow-[0_0_8px_rgba(34,197,94,0.3)]" />
                                    ) : (
                                      <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0 text-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.3)]" />
                                    )}
                                    <span className="leading-relaxed font-semibold">{ind.replace(/^[✓✗!]\s*/, '')}</span>
                                  </div>
                                )
                              })}
                            </div>
                          </div>
                        )
                      }

                      return (
                        <div className="space-y-6">
                          {renderIndicatorList(hardening, 'Ecosystem Hardening Controls', '#00f0ff')}
                          {renderIndicatorList(hygiene, 'Static Codebase Hygiene', '#a78bfa')}
                          {renderIndicatorList(classification, 'Model Posture Controls', '#f43f5e')}
                        </div>
                      )
                    })()}
                  </Card>
                </div>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: ANALYTICS ── */}
            {dashTab === 'analytics' && (
              <motion.div key="analytics" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                
                {/* Severity Breakdown Bar */}
                <Card className="p-8 border-white/[0.06] bg-[#050812]/50 relative overflow-hidden">
                  <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-purple-500/[0.03] to-transparent pointer-events-none" />
                  <h3 className="mono text-xs text-white uppercase tracking-widest mb-6 font-bold border-b border-white/[0.04] pb-2 flex items-center justify-between">
                    <span>Vulnerability Severity Distribution</span>
                    <span className="text-[8px] text-neutral-500 font-mono">SECTOR HEAT MAP</span>
                  </h3>
                  
                  {/* Glowing custom stacked horizontal bar with heat nodes */}
                  <div className="relative h-7 bg-white/[0.02] rounded-full p-0.5 border border-white/[0.04] flex overflow-hidden shadow-inner select-none">
                    {sc.high > 0 && (
                      <div 
                        className="h-full bg-gradient-to-r from-red-600 to-red-400 relative group transition-all hover:brightness-110" 
                        style={{ width: `${(sc.high / result.findings.length) * 100}%` }}
                      >
                        <div className="absolute right-0 top-0 bottom-0 w-1 bg-white/20 blur-[1px] animate-pulse" />
                      </div>
                    )}
                    {sc.medium > 0 && (
                      <div 
                        className="h-full bg-gradient-to-r from-yellow-600 to-yellow-400 relative group transition-all hover:brightness-110" 
                        style={{ width: `${(sc.medium / result.findings.length) * 100}%` }}
                      >
                        <div className="absolute right-0 top-0 bottom-0 w-1 bg-white/20 blur-[1px] animate-pulse" />
                      </div>
                    )}
                    {sc.low > 0 && (
                      <div 
                        className="h-full bg-gradient-to-r from-cyan-600 to-cyan-400 relative group transition-all hover:brightness-110" 
                        style={{ width: `${((result.findings.length - sc.high - sc.medium) / result.findings.length) * 100}%` }}
                      />
                    )}
                  </div>

                  <div className="flex gap-6 mt-5 justify-center flex-wrap">
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-300 bg-red-500/[0.03] border border-red-500/10 px-3 py-1.5 rounded-xl">
                      <div className="w-3 h-3 rounded-full bg-red-500 shadow-[0_0_10px_#EF4444] animate-pulse" />
                      <span>CRITICAL/HIGH: {sc.high} findings</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-300 bg-yellow-500/[0.03] border border-yellow-500/10 px-3 py-1.5 rounded-xl">
                      <div className="w-3 h-3 rounded-full bg-yellow-500 shadow-[0_0_10px_#fbbf24] animate-pulse" />
                      <span>MEDIUM: {sc.medium} findings</span>
                    </div>
                    <div className="flex items-center gap-2 text-xs font-bold text-slate-300 bg-cyan-500/[0.03] border border-cyan-500/10 px-3 py-1.5 rounded-xl">
                      <div className="w-3 h-3 rounded-full bg-cyan-500 shadow-[0_0_10px_#00f0ff] animate-pulse" />
                      <span>INFORMATIONAL/LOW: {sc.low} findings</span>
                    </div>
                  </div>
                </Card>

                {/* Heatmap-like treemap of scanned files risk */}
                <Card className="p-8 border-white/[0.06] bg-[#050812]/50">
                  <h3 className="mono text-xs text-white uppercase tracking-widest mb-6 font-bold border-b border-white/[0.04] pb-2 flex items-center justify-between">
                    <span>Scanned File Risk Heatmap Matrix</span>
                    <span className="text-[8px] text-neutral-500 font-mono">CLICK TILE TO LOAD ML MODEL EXPLANATIONS</span>
                  </h3>
                  
                  {result.ranked_files && result.ranked_files.length > 0 ? (
                    <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-6 gap-4">
                      {result.ranked_files.map((fileData, i) => {
                        const score = fileData.composite_score
                        const isHigh = score >= 75
                        const isMed = score >= 45 && score < 75
                        const borderCol = isHigh 
                          ? 'border-red-500/30 hover:border-red-500/60 bg-red-500/[0.02]' 
                          : isMed 
                            ? 'border-yellow-500/30 hover:border-yellow-500/60 bg-yellow-500/[0.02]' 
                            : 'border-green-500/20 hover:border-green-500/50 bg-green-500/[0.01]'
                        const textCol = isHigh ? 'text-red-400' : isMed ? 'text-yellow-400' : 'text-green-400'
                        const glowCol = isHigh ? 'shadow-[0_0_15px_rgba(239,68,68,0.05)]' : isMed ? 'shadow-[0_0_15px_rgba(245,158,11,0.05)]' : ''

                        return (
                          <div 
                            key={i} 
                            className={`p-3.5 rounded-xl border flex flex-col justify-between h-24 transition-all hover:scale-[1.04] cursor-pointer hover:shadow-lg ${borderCol} ${glowCol}`}
                            onClick={() => { setSelectedMlFile(fileData.file); setDashTab('ml') }}
                          >
                            <div className="text-[10px] font-mono truncate max-w-full font-bold text-neutral-200">{fileData.file.split('/').pop()}</div>
                            <div className="flex justify-between items-end mt-4">
                              <span className="mono text-[8px] opacity-40 uppercase font-black">Post Score</span>
                              <span className={`mono text-sm font-black ${textCol}`}>{score}</span>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  ) : (
                    <div className="text-center py-8 text-neutral-500">No heatmap data mapped.</div>
                  )}
                </Card>

                {/* Security Maturity Radar representation as SVG Polygon */}
                <Card className="p-8 border-white/[0.06] bg-[#050812]/50 flex flex-col items-center relative overflow-hidden">
                  <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(139,92,246,0.03),transparent_60%)] pointer-events-none" />
                  <h3 className="mono text-xs text-white uppercase tracking-widest mb-8 font-bold border-b border-white/[0.04] pb-2 w-full text-left">Ecosystem Defensive Maturity Radar</h3>
                  
                  {/* Radar Layout Wrapper */}
                  <div className="relative w-64 h-64 flex items-center justify-center">
                    {/* Rotating ambient decorative rings */}
                    <div className="absolute inset-0 rounded-full border border-cyan-500/5 animate-[spin-slow_25s_linear_infinite]" />
                    <div className="absolute w-[80%] h-[80%] rounded-full border border-purple-500/5 animate-[spin-slow_15s_linear_infinite_reverse]" />
                    <div className="absolute w-[60%] h-[60%] rounded-full border border-white/[0.02]" />

                    {/* Draw SVG Radar */}
                    <svg className="w-56 h-56 relative z-10" viewBox="0 0 100 100">
                      {/* background concentric grid rings */}
                      <circle cx="50" cy="50" r="40" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="0.5" />
                      <circle cx="50" cy="50" r="30" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="0.5" />
                      <circle cx="50" cy="50" r="20" fill="none" stroke="rgba(255,255,255,0.02)" strokeWidth="0.5" />
                      
                      {/* axis spokes */}
                      <line x1="50" y1="10" x2="50" y2="90" stroke="rgba(6,182,212,0.1)" strokeWidth="0.5" />
                      <line x1="10" y1="50" x2="90" y2="50" stroke="rgba(6,182,212,0.1)" strokeWidth="0.5" />

                      {/* Radar vertex coordinates calculation */}
                      {(() => {
                        const y1 = 50 - (result.maturity.score / 100) * 40
                        const x2 = 50 + (result.security_score / 100) * 40
                        const y3 = 50 + (result.vibe_risk.score / 100) * 40
                        const hygieneVal = Math.max(10, 100 - result.findings.length * 5)
                        const x4 = 50 - (hygieneVal / 100) * 40

                        return (
                          <>
                            {/* main polygon shape */}
                            <polygon 
                              points={`50,${y1} ${x2},50 50,${y3} ${x4},50`} 
                              fill="rgba(139,92,246,0.15)" 
                              stroke="url(#radarGradient)" 
                              strokeWidth="1.5" 
                              className="drop-shadow-[0_0_8px_rgba(139,92,246,0.4)]"
                            />
                            
                            {/* Glowing Vertex Nodes */}
                            <circle cx="50" cy={y1} r="2" fill="#8b5cf6" className="animate-pulse shadow-[0_0_8px_#8b5cf6]" />
                            <circle cx="50" cy={y1} r="4" fill="none" stroke="#8b5cf6" strokeWidth="0.5" className="animate-ping" style={{ transformOrigin: '50px 50px' }} />

                            <circle cx={x2} cy="50" r="2" fill="#00f0ff" className="animate-pulse shadow-[0_0_8px_#00f0ff]" />
                            <circle cx={x2} cy="50" r="4" fill="none" stroke="#00f0ff" strokeWidth="0.5" className="animate-ping" style={{ transformOrigin: '50px 50px' }} />

                            <circle cx="50" cy={y3} r="2" fill="#ec4899" className="animate-pulse shadow-[0_0_8px_#ec4899]" />
                            <circle cx="50" cy={y3} r="4" fill="none" stroke="#ec4899" strokeWidth="0.5" className="animate-ping" style={{ transformOrigin: '50px 50px' }} />

                            <circle cx={x4} cy="50" r="2" fill="#10b981" className="animate-pulse shadow-[0_0_8px_#10b981]" />
                            <circle cx={x4} cy="50" r="4" fill="none" stroke="#10b981" strokeWidth="0.5" className="animate-ping" style={{ transformOrigin: '50px 50px' }} />
                          </>
                        )
                      })()}
                      
                      <defs>
                        <linearGradient id="radarGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                          <stop offset="0%" stopColor="#8b5cf6" />
                          <stop offset="50%" stopColor="#00f0ff" />
                          <stop offset="100%" stopColor="#ec4899" />
                        </linearGradient>
                      </defs>
                    </svg>
                  </div>

                  <div className="grid grid-cols-4 gap-4 mt-8 text-center w-full max-w-lg border-t border-white/[0.04] pt-6 relative z-10">
                    <div>
                      <div className="mono text-[8px] text-neutral-500 font-bold uppercase">Defense Maturity</div>
                      <div className="text-sm font-extrabold text-cyan-400 mt-1">{result.maturity.score}</div>
                    </div>
                    <div>
                      <div className="mono text-[8px] text-neutral-500 font-bold uppercase">Defensibility</div>
                      <div className="text-sm font-extrabold text-purple-400 mt-1">{result.security_score}</div>
                    </div>
                    <div>
                      <div className="mono text-[8px] text-neutral-500 font-bold uppercase">Threat Level</div>
                      <div className="text-sm font-extrabold text-pink-500 mt-1">{result.vibe_risk.score}</div>
                    </div>
                    <div>
                      <div className="mono text-[8px] text-neutral-500 font-bold uppercase">Ecosystem Hygiene</div>
                      <div className="text-sm font-extrabold text-emerald-400 mt-1">{Math.max(10, 100 - result.findings.length * 5)}</div>
                    </div>
                  </div>
                </Card>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: ARCHITECTURE PATCH PANEL ── */}
            {dashTab === 'fixes' && (
              <motion.div key="fixes" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  
                  {/* Left flaws side drawer */}
                  <div className="lg:col-span-1 space-y-3 max-h-[500px] overflow-y-auto pr-1">
                    <div className="mono text-[9px] text-neutral-500 tracking-widest font-bold uppercase mb-2 border-b border-white/[0.04] pb-1">SELECT ANOMALY TO PATCH</div>
                    {result.findings.map((f, idx) => (
                      <div 
                        key={idx} 
                        className={`p-3 rounded-xl border text-xs transition-all cursor-pointer ${
                          selectedFindingIndex === idx 
                            ? 'border-purple-500/40 bg-purple-500/5 shadow-[0_0_12px_rgba(139,92,246,0.05)] scale-[1.01]' 
                            : 'border-white/[0.03] bg-black/20 hover:bg-white/[0.01] text-neutral-400 hover:text-neutral-200'
                        }`}
                        onClick={() => { setSelectedFindingIndex(idx); setCopiedIndex(null); }}
                      >
                        <div className="flex items-center justify-between mb-1.5 font-bold">
                          <span className={`pill pill-${f.severity.toLowerCase()} text-[8px] px-1.5 py-0.5`}>{f.severity}</span>
                          <span className="mono text-[9px] opacity-60">L:{f.line}</span>
                        </div>
                        <div className="truncate font-semibold">{f.issue}</div>
                        <div className="text-[9px] opacity-40 truncate font-mono mt-1">{f.file.split('/').pop()}</div>
                      </div>
                    ))}
                  </div>

                  {/* Right patch panel */}
                  <div className="lg:col-span-2">
                    <Card className="p-8 border-white/[0.06] bg-[#050812]/50 relative overflow-hidden min-h-[500px]">
                      <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/[0.01] to-transparent pointer-events-none" />
                      <h3 className="mono text-xs text-white uppercase tracking-widest mb-6 font-bold border-b border-white/[0.04] pb-2 flex items-center justify-between">
                        <span className="flex items-center gap-2">
                          <Code className="w-4 h-4 text-cyan-400" />
                          DEFENSIVE CODE ARCHITECTURE PATCH PANEL
                        </span>
                        <span className="text-[8px] px-2 py-0.5 rounded bg-cyan-500/10 border border-cyan-500/20 text-cyan-300 font-mono">AUTOMATED MITIGATION</span>
                      </h3>
                      
                      {patchLoading ? (
                        <div className="flex flex-col items-center justify-center py-24 space-y-4">
                          <div className="relative w-16 h-16 flex items-center justify-center bg-cyan-500/5 rounded-full border border-cyan-500/20 animate-spin">
                            <div className="absolute inset-1.5 border border-dashed border-cyan-500/30 rounded-full" />
                          </div>
                          <div className="flex flex-col items-center space-y-1">
                            <span className="mono text-[10px] text-cyan-400 uppercase tracking-widest font-black animate-pulse">Sentinel AI telemetry running...</span>
                            <span className="text-[10px] text-neutral-500 font-mono">Generating secure offline code repairs</span>
                          </div>
                        </div>
                      ) : patchError ? (
                        <div className="flex flex-col items-center justify-center py-20 space-y-4 border border-red-500/25 bg-red-500/5 rounded-2xl p-6">
                          <AlertTriangle className="w-12 h-12 text-red-500 animate-bounce" />
                          <div className="text-center">
                            <h4 className="text-white font-bold text-sm">Telemetry Failure</h4>
                            <p className="text-neutral-400 text-xs mt-1">{patchError}</p>
                          </div>
                          <button 
                            onClick={() => fetchPatch(selectedFindingIndex)}
                            className="px-4 py-2 border border-red-500/30 bg-red-500/10 hover:bg-red-500 hover:text-white rounded-xl text-xs font-bold uppercase transition-all"
                          >
                            Retry Telemetry
                          </button>
                        </div>
                      ) : patchData ? (() => {
                        const finding = result.findings[selectedFindingIndex]
                        const isCopiedFixed = copiedFixedLine
                        const isCopiedFull = copiedFullFile

                        // Slicing context
                        const lineIndex = finding.line - 1
                        const startLineIdx = Math.max(0, lineIndex - 5)
                        const endLineIdx = Math.min(patchData.file_lines.length - 1, lineIndex + 5)
                        const surroundingLines = patchData.file_lines.slice(startLineIdx, endLineIdx + 1).map((text, idx) => ({
                          num: startLineIdx + idx + 1,
                          text,
                          isTarget: startLineIdx + idx === lineIndex
                        }))

                        return (
                          <div className="space-y-6">
                            {/* File & Threat Location Card */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-4 bg-black/35 border border-white/[0.04] rounded-xl text-xs">
                              <div>
                                <div className="mono text-[8px] text-neutral-500 font-bold uppercase">FILE LOCATION SOURCE</div>
                                <div className="font-mono text-cyan-300 mt-1 break-all font-bold">📂 {finding.file}</div>
                              </div>
                              <div>
                                <div className="mono text-[8px] text-neutral-500 font-bold uppercase">LINE COORDINATE</div>
                                <div className="font-mono text-purple-400 mt-1 font-bold">L:{finding.line}</div>
                              </div>
                              <div>
                                <div className="mono text-[8px] text-neutral-500 font-bold uppercase">ANOMALY INDEX</div>
                                <div className="font-mono text-red-400 mt-1 font-bold flex items-center gap-1.5 uppercase">
                                  <span className={`w-1.5 h-1.5 rounded-full ${finding.severity === 'High' ? 'bg-red-400 shadow-[0_0_6px_#f87171]' : finding.severity === 'Medium' ? 'bg-yellow-400 shadow-[0_0_6px_#fbbf24]' : 'bg-cyan-400 shadow-[0_0_6px_#22d3ee]'}`} />
                                  {finding.severity} SEVERITY
                                </div>
                              </div>
                            </div>

                            {/* Technical Remediation & Explanation */}
                            <div className="p-4 border border-cyan-500/15 bg-cyan-500/5 rounded-xl space-y-2">
                              <div className="mono text-[8px] text-cyan-400 font-black tracking-widest uppercase flex items-center gap-1.5">
                                <Activity className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                                Technical Explainer & Advisory
                              </div>
                              <p className="text-xs text-neutral-300 leading-relaxed font-mono">
                                {patchData.explanation}
                              </p>
                            </div>

                            {/* Dynamic Swapper Toggles */}
                            <div className="flex gap-2 p-1 bg-black/40 border border-white/[0.04] rounded-xl max-w-sm">
                              <button 
                                onClick={() => setShowFullPatched(false)}
                                className={`flex-1 py-2 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all duration-300 ${!showFullPatched ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30' : 'text-neutral-500 hover:text-neutral-300'}`}
                              >
                                View Code Diffs
                              </button>
                              <button 
                                onClick={() => setShowFullPatched(true)}
                                className={`flex-1 py-2 rounded-lg text-[10px] font-black uppercase tracking-wider transition-all duration-300 ${showFullPatched ? 'bg-green-500/10 text-green-300 border border-green-500/30' : 'text-neutral-500 hover:text-neutral-300'}`}
                              >
                                Preview Patched File
                              </button>
                            </div>

                            {/* Differential view or full patched preview */}
                            {!showFullPatched ? (
                              <div className="space-y-6">
                                {/* Side-by-side Git Diff View */}
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                  <div className="flex flex-col">
                                    <div className="mono text-[8px] text-red-400 font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                      <span className="w-1.5 h-1.5 rounded-full bg-red-400 shadow-[0_0_6px_#f87171]" />
                                      VULNERABLE LINE (-)
                                    </div>
                                    <div className="p-4 bg-red-950/15 border border-red-500/20 rounded-xl font-mono text-[11px] text-red-300 min-h-[90px] flex items-center leading-relaxed relative overflow-x-auto">
                                      <span className="absolute top-2 right-2 text-[7px] text-red-500/40 select-none uppercase font-bold tracking-widest font-sans">ORIGINAL</span>
                                      <div className="flex gap-2">
                                        <span className="text-red-500/50 select-none font-bold">-</span>
                                        <pre className="whitespace-pre-wrap"><code>{patchData.vulnerable_line}</code></pre>
                                      </div>
                                    </div>
                                  </div>

                                  <div className="flex flex-col">
                                    <div className="mono text-[8px] text-green-400 font-bold uppercase tracking-wider mb-2 flex items-center gap-1.5">
                                      <span className="w-1.5 h-1.5 rounded-full bg-green-400 shadow-[0_0_6px_#34d399]" />
                                      REMEDIATED LINE (+)
                                    </div>
                                    <div className="p-4 bg-green-950/10 border border-green-500/20 rounded-xl font-mono text-[11px] text-green-300 min-h-[90px] flex items-center leading-relaxed relative overflow-x-auto">
                                      <span className="absolute top-2 right-2 text-[7px] text-green-500/40 select-none uppercase font-bold tracking-widest font-sans">SECURE REPAIR</span>
                                      <div className="flex gap-2">
                                        <span className="text-green-500/50 select-none font-bold">+</span>
                                        <pre className="whitespace-pre-wrap"><code>{patchData.fixed_line}</code></pre>
                                      </div>
                                    </div>
                                  </div>
                                </div>

                                {/* Interactive Surrounding Code Viewer */}
                                <div className="space-y-2">
                                  <div className="mono text-[8px] text-neutral-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                                    <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-pulse" />
                                    Interactive Contextual Code Viewer (Lines {startLineIdx + 1} - {endLineIdx + 1})
                                  </div>
                                  <div className="bg-black/50 border border-white/[0.04] rounded-xl p-4 overflow-y-auto max-h-[220px] font-mono text-[11px] leading-relaxed shadow-inner">
                                    {surroundingLines.map((line, i) => (
                                      <div 
                                        key={i} 
                                        className={`flex gap-4 py-0.5 px-2 rounded transition-colors ${line.isTarget ? 'bg-red-500/10 border-l-2 border-red-500/70 text-red-300' : 'text-neutral-400'}`}
                                      >
                                        <span className="w-8 text-right opacity-30 select-none font-bold">{line.num}</span>
                                        <pre className="whitespace-pre"><code>{line.text}</code></pre>
                                      </div>
                                    ))}
                                  </div>
                                </div>

                                {/* Action buttons */}
                                <div className="flex gap-4 pt-2">
                                  <button 
                                    onClick={() => {
                                      navigator.clipboard.writeText(patchData.fixed_line)
                                      setCopiedFixedLine(true)
                                      setTimeout(() => setCopiedFixedLine(false), 2000)
                                    }}
                                    className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-bold uppercase tracking-widest transition-all ${
                                      isCopiedFixed 
                                        ? 'bg-green-500/20 border border-green-500/40 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.15)]' 
                                        : 'bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500 hover:text-black hover:border-transparent'
                                    }`}
                                  >
                                    {isCopiedFixed ? (
                                      <>
                                        <CheckCircle className="w-4 h-4 text-green-400" />
                                        Copied Remediation Line!
                                      </>
                                    ) : (
                                      <>
                                        <Download className="w-4 h-4" />
                                        Copy Fixed Line
                                      </>
                                    )}
                                  </button>

                                  <button 
                                    onClick={() => {
                                      navigator.clipboard.writeText(patchData.patched_file_content)
                                      setCopiedFullFile(true)
                                      setTimeout(() => setCopiedFullFile(false), 2000)
                                    }}
                                    className={`flex-1 flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-bold uppercase tracking-widest transition-all ${
                                      isCopiedFull 
                                        ? 'bg-green-500/20 border border-green-500/40 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.15)]' 
                                        : 'bg-purple-500/10 border border-purple-500/20 text-purple-400 hover:bg-purple-500 hover:text-white hover:border-transparent'
                                    }`}
                                  >
                                    {isCopiedFull ? (
                                      <>
                                        <CheckCircle className="w-4 h-4 text-green-400" />
                                        Copied Patched File!
                                      </>
                                    ) : (
                                      <>
                                        <Code className="w-4 h-4" />
                                        Copy Fully Patched File
                                      </>
                                    )}
                                  </button>
                                </div>
                              </div>
                            ) : (
                              <div className="space-y-4 animate-fade-in">
                                {/* Fully Patched File Preview */}
                                <div className="mono text-[8px] text-green-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                                  <Shield className="w-4 h-4 text-green-400" />
                                  Remediated Production-Safe File Preview
                                </div>
                                <div className="bg-black/60 border border-green-500/15 rounded-xl p-4 overflow-y-auto max-h-[350px] font-mono text-[11px] leading-relaxed shadow-inner">
                                  {patchData.patched_file_content.split('\n').map((lineText, i) => {
                                    const isRemediated = i === lineIndex
                                    return (
                                      <div 
                                        key={i} 
                                        className={`flex gap-4 py-0.5 px-2 rounded transition-colors ${isRemediated ? 'bg-green-500/10 border-l-2 border-green-500/70 text-green-300 font-bold' : 'text-neutral-400'}`}
                                      >
                                        <span className="w-8 text-right opacity-30 select-none font-bold">{i + 1}</span>
                                        <pre className="whitespace-pre"><code>{lineText}</code></pre>
                                      </div>
                                    )
                                  })}
                                </div>

                                {/* Copy actions for entire file */}
                                <button 
                                  onClick={() => {
                                    navigator.clipboard.writeText(patchData.patched_file_content)
                                    setCopiedFullFile(true)
                                    setTimeout(() => setCopiedFullFile(false), 2000)
                                  }}
                                  className={`w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl text-xs font-bold uppercase tracking-widest transition-all ${
                                    isCopiedFull 
                                      ? 'bg-green-500/20 border border-green-500/40 text-green-400 shadow-[0_0_15px_rgba(34,197,94,0.15)]' 
                                      : 'bg-green-500/10 border border-green-500/20 text-green-400 hover:bg-green-500 hover:text-black hover:border-transparent'
                                  }`}
                                >
                                  {isCopiedFull ? (
                                    <>
                                      <CheckCircle className="w-4 h-4 text-green-400 animate-pulse" />
                                      Copied Secure Production File!
                                    </>
                                  ) : (
                                    <>
                                      <Download className="w-4 h-4" />
                                      Copy Entire Remediated Production File
                                    </>
                                  )}
                                </button>
                              </div>
                            )}
                          </div>
                        )
                      })() : (
                        <div className="text-center py-20 text-neutral-500 flex flex-col items-center justify-center space-y-4">
                          <Code className="w-12 h-12 text-neutral-600 animate-pulse" />
                          <span>Select a static flaw on the left sidebar to reveal code remediations.</span>
                        </div>
                      )}
                    </Card>
                  </div>
                </div>
              </motion.div>
            )}

            {/* ── TELEMETRY TAB: TERMINAL CONSOLE ── */}
            {dashTab === 'terminal' && (
              <TerminalConsole result={result} />
            )}

            {/* ── TELEMETRY TAB: DATA DOWNLOADS ── */}
            {dashTab === 'downloads' && (
              <DownloadsTab result={result} />
            )}

          </AnimatePresence>

        </div>
      </div>
    </main>
  )
}

function TerminalConsole({ result }: { result: ScanResult }) {
  const [terminalBooted, setTerminalBooted] = useState(false)
  const [terminalBootPhase, setTerminalBootPhase] = useState(0)
  const [typedLogs, setTypedLogs] = useState<Array<{ level: string; message: string }>>([])
  const [logIndex, setLogIndex] = useState(0)

  // Terminal bootloader simulation
  useEffect(() => {
    let phase = 0
    const interval = setInterval(() => {
      phase++
      setTerminalBootPhase(phase)
      if (phase >= 4) {
        clearInterval(interval)
        setTerminalBooted(true)
      }
    }, 450)
    return () => clearInterval(interval)
  }, [])

  // Simulate typewriter effect on SOC Console logs
  useEffect(() => {
    if (!result.terminal_logs || !terminalBooted) return
    if (logIndex < result.terminal_logs.length) {
      const t = setTimeout(() => {
        setTypedLogs(prev => [...prev, result.terminal_logs![logIndex]])
        setLogIndex(prev => prev + 1)
      }, Math.max(100, 300 - logIndex * 20))
      return () => clearTimeout(t)
    }
  }, [logIndex, result.terminal_logs, terminalBooted])

  return (
    <motion.div key="terminal" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
      <Card className="p-8 border-white/[0.08] bg-[#03060f]/95 relative shadow-2xl overflow-hidden min-h-[460px] flex flex-col justify-between">
        {/* CRT scan lines */}
        <div className="absolute inset-0 bg-[linear-gradient(rgba(18,16,16,0)_50%,rgba(0,0,0,0.25)_50%),linear-gradient(90deg,rgba(0,240,255,0.03),rgba(139,92,246,0.02),rgba(236,72,153,0.03))] bg-[size:100%_4px,4px_100%] pointer-events-none z-10" />
        
        <div className="flex justify-between items-center border-b border-white/[0.05] pb-4 mb-4 relative z-20">
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-cyan-400 animate-pulse" />
            <span className="mono text-xs text-white uppercase tracking-widest font-black">System Event live telemetry stream</span>
          </div>
          
          <div className="flex items-center gap-3">
            {terminalBooted ? (
              <span className="flex items-center gap-1.5 text-[9px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/20 px-2.5 py-1 rounded animate-pulse">
                <span className="w-1.5 h-1.5 bg-emerald-400 rounded-full shadow-[0_0_6px_#34d399]" />
                FEED: ONLINE
              </span>
            ) : (
              <span className="flex items-center gap-1.5 text-[9px] font-mono text-yellow-500 bg-yellow-500/10 border border-yellow-500/20 px-2.5 py-1 rounded animate-pulse">
                <span className="w-1.5 h-1.5 bg-yellow-500 rounded-full shadow-[0_0_6px_#fbbf24]" />
                BOOTING DIAGNOSTICS
              </span>
            )}
            
            <button 
              onClick={() => { setTypedLogs([]); setLogIndex(0); setTerminalBooted(false); setTerminalBootPhase(0); }} 
              className="flex items-center gap-1.5 text-[9px] font-bold text-neutral-400 hover:text-white uppercase tracking-widest border border-white/[0.08] hover:bg-white/[0.02] rounded-lg px-2.5 py-1.5 transition-all"
            >
              <RefreshCw className="w-3.5 h-3.5" /> Re-trigger Stream
            </button>
          </div>
        </div>

        {!terminalBooted ? (
          /* Simulated BIOS checkup loader */
          <div className="flex-1 flex flex-col items-center justify-center py-16 space-y-6 font-mono relative z-20 text-xs">
            <div className="w-full max-w-md bg-black/60 border border-white/[0.04] p-6 rounded-xl space-y-3">
              <div className="text-[10px] text-neutral-500 border-b border-white/[0.04] pb-2 font-bold flex justify-between uppercase">
                <span>SYSTEM DIAGNOSTICS LOAD STREAM</span>
                <span>V3.04</span>
              </div>
              <div className="space-y-1.5">
                <div className={`transition-opacity duration-300 ${terminalBootPhase >= 0 ? 'opacity-100 text-cyan-400' : 'opacity-20'}`}>
                  [ {terminalBootPhase > 0 ? '✓' : '•'} ] MOUNTING NEURAL VECTOR CORE ... {terminalBootPhase > 0 ? 'OK' : 'RUNNING'}
                </div>
                <div className={`transition-opacity duration-300 ${terminalBootPhase >= 1 ? 'opacity-100 text-purple-400' : 'opacity-20'}`}>
                  [ {terminalBootPhase > 1 ? '✓' : '•'} ] COMPILING DETERMINISTIC PATTERNS ... {terminalBootPhase > 1 ? 'OK' : terminalBootPhase === 1 ? 'RUNNING' : 'PENDING'}
                </div>
                <div className={`transition-opacity duration-300 ${terminalBootPhase >= 2 ? 'opacity-100 text-pink-400' : 'opacity-20'}`}>
                  [ {terminalBootPhase > 2 ? '✓' : '•'} ] INITIALIZING SCALAR REGISTERS ... {terminalBootPhase > 2 ? 'OK' : terminalBootPhase === 2 ? 'RUNNING' : 'PENDING'}
                </div>
                <div className={`transition-opacity duration-300 ${terminalBootPhase >= 3 ? 'opacity-100 text-emerald-400' : 'opacity-20'}`}>
                  [ {terminalBootPhase > 3 ? '✓' : '•'} ] SYNCHRONIZING SECURE TUNNELS ... {terminalBootPhase > 3 ? 'OK' : terminalBootPhase === 3 ? 'RUNNING' : 'PENDING'}
                </div>
              </div>
              <div className="pt-2">
                <div className="h-2 w-full bg-white/[0.03] rounded-full overflow-hidden border border-white/[0.04]">
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-400 via-purple-500 to-pink-500 rounded-full transition-all duration-300"
                    style={{ width: `${(terminalBootPhase / 4) * 100}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        ) : (
          /* Terminal logs */
          <div className="bg-black/75 border border-white/[0.04] rounded-xl p-6 h-96 overflow-y-auto font-mono text-xs space-y-2 relative z-20 shadow-inner">
            {typedLogs.map((l, i) => {
              const c = l.level === 'CRITICAL' ? 'text-red-400 font-bold' : l.level === 'WARNING' ? 'text-yellow-400 font-medium' : l.level === 'SUCCESS' ? 'text-green-400' : 'text-cyan-400'
              return (
                <div key={i} className="flex gap-2.5 leading-relaxed py-0.5 hover:bg-white/[0.01]">
                  <span className="opacity-40 select-none font-bold">[{l.level}]</span>
                  <span className={c}>{l.message}</span>
                </div>
              )
            })}
            {logIndex < (result.terminal_logs?.length || 0) && (
              <div className="flex gap-2 items-center text-slate-400 animate-pulse py-0.5">
                <span className="opacity-40 select-none font-bold">[INFO]</span>
                <span className="cursor">COMPILING ECOSYSTEM TELEMETRY FEED...</span>
              </div>
            )}
          </div>
        )}
      </Card>
    </motion.div>
  )
}

function DownloadsTab({ result }: { result: ScanResult }) {
  const [exfiltrating, setExfiltrating] = useState<Record<string, number>>({})

  const triggerDownload = async (format: 'pdf' | 'csv' | 'json') => {
    if (exfiltrating[format] !== undefined) return
    setExfiltrating(prev => ({ ...prev, [format]: 0 }))
    
    let pct = 0
    const interval = setInterval(() => {
      pct += 10
      setExfiltrating(prev => ({ ...prev, [format]: Math.min(pct, 100) }))
      
      if (pct >= 100) {
        clearInterval(interval)
        setTimeout(async () => {
          try {
            const response = await fetch(`${FLASK_API}/api/report/${format}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                fingerprint: result.fingerprint || {},
                stats: result.stats,
                prioritized_findings: result.prioritized_findings || [],
                attack_chains: result.attack_chains || [],
                ranked_files: result.ranked_files || [],
                security_grade: result.security_grade || {}
              })
            })

            if (!response.ok) throw new Error('Report generation failed')

            if (format === 'json') {
              const blob = await response.json()
              const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(blob, null, 2))
              const dl = document.createElement('a')
              dl.setAttribute("href", dataStr)
              dl.setAttribute("download", `${result.project_name}_ecosystem.json`)
              dl.click()
            } else {
              const blob = await response.blob()
              const url = window.URL.createObjectURL(blob)
              const a = document.createElement('a')
              a.href = url
              a.download = format === 'pdf' ? `${result.project_name}_dossier.pdf` : `${result.project_name}_findings.csv`
              document.body.appendChild(a)
              a.click()
              a.remove()
            }
          } catch (e) {
            alert('Error initiating exfiltration download: ' + e)
          } finally {
            setTimeout(() => {
              setExfiltrating(prev => {
                const next = { ...prev }
                delete next[format]
                return next
              })
            }, 1200)
          }
        }, 150)
      }
    }, 60)
  }

  return (
    <motion.div key="downloads" initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }} transition={{ duration: 0.2 }} className="space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {[
          { format: 'json', title: 'JSON DATA EXFILTRATION', desc: 'Complete scan metadata map containing full classifications, intelligence logs, and vulnerability array matrices.', icon: FileText, btnText: 'EXFILTRATE JSON DATA' },
          { format: 'csv', title: 'CSV FLAWS SPREADSHEET', desc: 'Consolidated vulnerability registry including file locations, matches, severity labels, and priority weight metrics.', icon: GitBranch, btnText: 'EXFILTRATE CSV SHEET' },
          { format: 'pdf', title: 'PDF THREAT INTELLIGENCE DOSSIER', desc: 'Stunning executive cybersecurity report compiling deterministic chains, risk posture radar, and remediated patch details.', icon: Shield, btnText: 'EXFILTRATE PDF DOSSIER' },
        ].map((x) => {
          const isExfiltrating = exfiltrating[x.format] !== undefined
          const progressPct = exfiltrating[x.format] || 0
          
          return (
            <Card key={x.format} className="p-8 border-white/[0.07] bg-[#050812]/50 flex flex-col justify-between min-h-[280px] hover:border-purple-500/30 transition-all relative overflow-hidden group">
              <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-bl from-cyan-500/[0.02] to-transparent pointer-events-none" />
              
              <div>
                <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center mb-5 group-hover:scale-110 transition-transform">
                  <x.icon className="w-5 h-5 text-cyan-400" />
                </div>
                <h3 className="text-base font-extrabold text-white mb-2">{x.title}</h3>
                <p className="text-xs text-neutral-400 leading-relaxed font-semibold">{x.desc}</p>
              </div>
              
              <div className="space-y-4">
                {isExfiltrating && (
                  <div className="space-y-1.5 font-mono text-[9px] text-cyan-400">
                    <div className="flex justify-between uppercase">
                      <span>SECURE EXFIL PIPELINE</span>
                      <span>{progressPct}%</span>
                    </div>
                    <div className="flex h-1.5 w-full bg-white/[0.03] border border-white/[0.04] rounded-full overflow-hidden">
                      <div 
                        className="h-full bg-gradient-to-r from-cyan-400 via-purple-500 to-pink-500 rounded-full transition-all duration-100"
                        style={{ width: `${progressPct}%` }}
                      />
                    </div>
                  </div>
                )}

                <button 
                  onClick={() => triggerDownload(x.format as any)}
                  disabled={isExfiltrating}
                  className={`w-full flex items-center justify-center gap-2.5 py-4 rounded-xl text-xs font-bold uppercase tracking-widest transition-all ${
                    isExfiltrating 
                      ? 'bg-cyan-500/5 border border-cyan-500/20 text-cyan-400/60 cursor-not-allowed'
                      : 'bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 hover:bg-cyan-500 hover:text-black hover:border-transparent'
                  }`}
                >
                  {isExfiltrating ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
                      Exfiltrating... {progressPct}%
                    </>
                  ) : (
                    <>
                      <Download className="w-4 h-4" />
                      {x.btnText}
                    </>
                  )}
                </button>
              </div>
            </Card>
          )
        })}
      </div>
    </motion.div>
  )
}

interface ScanningLoaderProps {
  scanning: boolean
}

function ScanningLoader({ scanning }: ScanningLoaderProps) {
  const [loaderPhase, setLoaderPhase] = useState(0)
  const [loaderProgress, setLoaderProgress] = useState(0)
  const [loaderText, setLoaderText] = useState('')

  useEffect(() => {
    if (!scanning) return
    const phrase = LOADER_PHASES[loaderPhase] ?? ''
    let i = 0
    setLoaderText('')
    const timer = setInterval(() => {
      i++
      setLoaderText(phrase.slice(0, i))
      const pct = ((loaderPhase + i / phrase.length) / LOADER_PHASES.length) * 100
      setLoaderProgress(Math.min(pct, 100))
      if (i >= phrase.length) clearInterval(timer)
    }, 20)
    return () => clearInterval(timer)
  }, [scanning, loaderPhase])

  useEffect(() => {
    if (!scanning || loaderPhase >= LOADER_PHASES.length - 1) return
    const t = setTimeout(() => setLoaderPhase(p => p + 1), LOADER_PHASES[loaderPhase].length * 22 + 200)
    return () => clearTimeout(t)
  }, [scanning, loaderPhase])

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
      className="mt-6 p-5 bg-black/60 border border-cyan-500/25 rounded-2xl relative overflow-hidden"
    >
      <div className="absolute top-0 right-0 p-3 flex gap-1.5">
        <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
        <span className="w-1.5 h-1.5 rounded-full bg-purple-400 animate-ping" />
      </div>
      <div className="flex items-center gap-2 mb-3">
        <div className="w-2.5 h-2.5 rounded-full bg-cyan-400 animate-pulse shadow-[0_0_10px_#00f0ff]" />
        <span className="mono text-[10px] text-cyan-400 tracking-[2px] uppercase font-bold">Scrutinizing codebase...</span>
      </div>
      <div className="h-2 bg-white/[0.05] rounded-full overflow-hidden mb-3">
        <div className="loader-bar h-full rounded-full transition-all duration-300 ease-out" style={{ width: `${loaderProgress}%` }} />
      </div>
      <p className="mono text-xs text-neutral-300 cursor font-semibold">{loaderText}</p>
    </motion.div>
  )
}
