'use client'
import React, { useRef, useState, useCallback, useEffect } from 'react'
import { motion, useSpring, useTransform, type SpringOptions } from 'framer-motion'
import { cn } from '@/lib/utils'

type SpotlightProps = {
  className?: string
  size?: number
  springOptions?: SpringOptions
}

// Reduced spring stiffness for smoother, less CPU-intensive tracking
export function Spotlight({
  className,
  size = 400,
  springOptions = { stiffness: 80, damping: 20, mass: 1 },
}: SpotlightProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [isHovered, setIsHovered] = useState(false)
  const [parentElement, setParentElement] = useState<HTMLElement | null>(null)

  const mouseX = useSpring(0, springOptions)
  const mouseY = useSpring(0, springOptions)

  const spotlightLeft = useTransform(mouseX, (x) => `${x - size / 2}px`)
  const spotlightTop  = useTransform(mouseY, (y) => `${y - size / 2}px`)

  useEffect(() => {
    if (containerRef.current) {
      const parent = containerRef.current.parentElement
      if (parent) {
        parent.style.position = 'relative'
        parent.style.overflow = 'hidden'
        setParentElement(parent)
      }
    }
  }, [])

  const handleMouseMove = useCallback(
    (event: MouseEvent) => {
      if (!parentElement) return
      const { left, top } = parentElement.getBoundingClientRect()
      mouseX.set(event.clientX - left)
      mouseY.set(event.clientY - top)
    },
    [mouseX, mouseY, parentElement]
  )

  useEffect(() => {
    if (!parentElement) return
    const onEnter = () => setIsHovered(true)
    const onLeave = () => setIsHovered(false)
    parentElement.addEventListener('mousemove', handleMouseMove)
    parentElement.addEventListener('mouseenter', onEnter)
    parentElement.addEventListener('mouseleave', onLeave)
    return () => {
      parentElement.removeEventListener('mousemove', handleMouseMove)
      parentElement.removeEventListener('mouseenter', onEnter)
      parentElement.removeEventListener('mouseleave', onLeave)
    }
  }, [parentElement, handleMouseMove])

  return (
    <motion.div
      ref={containerRef}
      className={cn(
        'pointer-events-none absolute rounded-full blur-3xl transition-opacity duration-500 will-change-transform',
        'bg-[radial-gradient(circle_at_center,rgba(139,92,246,0.35),rgba(0,240,255,0.1),transparent_70%)]',
        isHovered ? 'opacity-100' : 'opacity-0',
        className
      )}
      style={{
        width: size,
        height: size,
        left: spotlightLeft,
        top: spotlightTop,
        // Force GPU layer so blur doesn't repaint on CPU
        transform: 'translateZ(0)',
      }}
    />
  )
}
