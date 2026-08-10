# AI Phishing Attack Detector - PRD

## Problem statement
Localhost web app: user pastes an SMS/email/message, gets AI-powered phishing risk analysis (0-100), risk level, verdict, indicators, URL analysis, explainable reasoning, recommendation, and history dashboard.

## User choices
- Detection: Hybrid rule-based scoring + Claude Sonnet 4.6 explainable AI reasoning
- History: Browser localStorage only (privacy-first, no server-side storage)
- UI: Dark cybersecurity dashboard (navy/black + cyan accents + risk color coding)

## Architecture
- **Backend (FastAPI)**: `/api/analyze` (POST), `/api/samples` (GET), `/api/` (health)
  - `detector.py`: 5 pattern categories (Urgency, Credentials, Financial, Impersonation, Language), weighted scoring, cross-signal boost
  - `url_analyzer.py`: URL extraction + per-URL analysis (HTTPS, IP, shortener, TLD, brand impersonation, obfuscation)
  - `scoring.py`: score -> level + verdict + context-aware recommendation
  - LLM: Claude Sonnet 4.6 via emergentintegrations (Emergent LLM key) for the "why was this flagged" explanation ONLY. Deterministic fallback if LLM fails.
- **Frontend (React + Shadcn + Tailwind)**: Single-page dashboard
  - `PhishingDashboard.jsx`: stats row, input card, result card w/ gauge, indicators, URL cards, explainable reasons, recommendation, history table
  - `RiskGauge.jsx`: animated SVG half-circle gauge
  - LocalStorage persistence for history + stats

## Implemented (2026-02-10)
- Rule-based deterministic scoring (0-100), 5 categories + URL analysis + cross-signal boost
- Explainable AI reasoning via Claude Sonnet + fallback
- URL analyzer with 8+ signals per URL
- Sample messages endpoint (5 labeled samples)
- Dark cyber-themed dashboard, fully responsive, animated gauge
- LocalStorage history + stats dashboard (total/phishing/safe/avg)
- Sonner toast notifications, error handling, input validation

## Backlog
- P1: Bulk analysis (upload CSV of messages)
- P1: Export history to CSV/JSON
- P2: Real ML model integration (sklearn pkl) alongside rules
- P2: Multi-language support (Hindi, Spanish, etc.)
- P2: Copy-shareable analysis report URL
