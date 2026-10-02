import React from 'react';
import { BookOpen, Target, Brain, Shield, AlertOctagon } from 'lucide-react';

const fingerprints = [
  {
    label: 'THREAT_VECTOR',
    desc: 'Account suspension · Service disconnection · Legal action · SIM deactivation · Financial loss · Delivery hold',
    icon: AlertOctagon,
    color: '#ff616f',
  },
  {
    label: 'URGENCY_LEVEL',
    desc: 'HIGH: immediate verification · MEDIUM: within 24h · LOW: last chance / gentle reminder',
    icon: Target,
    color: '#ffd166',
  },
  {
    label: 'REQUESTED_ACTION',
    desc: 'Verify identity · Share credential · Pay · Click link · Call number · Approve transaction · Reply',
    icon: Brain,
    color: '#00f0ff',
  },
  {
    label: 'DEMANDED_ASSET',
    desc: 'Credential · Payment · Both · None — the asset class the attacker ultimately targets',
    icon: Shield,
    color: '#00ff9d',
  },
];

const modelLineage = [
  {
    id: 'MODEL_A',
    title: 'Model A (Baseline)',
    tag: 'LEXICAL',
    tagColor: 'badge-blue',
    desc: 'Word TF-IDF + Logistic Regression — establishes standard lexical performance upper-bound.',
  },
  {
    id: 'MODEL_A2',
    title: 'Model A2 (Robust Lexical)',
    tag: 'SUB-WORD',
    tagColor: 'badge-blue',
    desc: 'Word + Character n-gram TF-IDF — captures sub-word invariants in inconsistent Romanized spellings (karein vs karen vs kariye).',
  },
  {
    id: 'MODEL_B',
    title: 'Model B (Semantic)',
    tag: 'EMBEDDING',
    tagColor: 'badge-pink',
    desc: 'Multilingual MiniLM-L12-v2 sentence embeddings + LR — captures semantic intent beyond surface vocabulary across languages.',
  },
  {
    id: 'MODEL_C',
    title: 'Model C (Proposed ★)',
    tag: 'PROPOSED',
    tagColor: 'badge-green',
    desc: 'Multilingual semantic embeddings augmented with out-of-fold predicted 4D intent fingerprints — the main research contribution.',
    highlight: true,
  },
];

export default function MethodologyTab() {
  return (
    <div style={{ maxWidth: '920px', margin: '0 auto' }}>

      {/* Hero Banner */}
      <div className="card" style={{ marginBottom: '1.5rem', background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.08), rgba(139, 92, 246, 0.10))' }}>
        <div className="card-title">
          <BookOpen size={20} color="#00f0ff" />
          PHISHGUARD AI // RESEARCH METHODOLOGY
        </div>
        <p style={{ color: 'var(--text-secondary)', marginBottom: '0', fontSize: '0.9rem', lineHeight: 1.7, fontFamily: 'var(--font-mono)' }}>
          PhishGuard AI investigates <span style={{ color: 'var(--cyber-cyan)' }}>explainable and robust phishing detection</span> for email and SMS. The primary research focus is evaluating detector resilience when underlying phishing attempts are paraphrased or expressed in <span style={{ color: 'var(--violet-bright)' }}>code-mixed languages</span> such as Romanized Hinglish or Kanglish.
        </p>
      </div>

      {/* Research Question */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '0.85rem', color: 'var(--cyber-cyan)', marginBottom: '0.85rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          [01] Primary Research Question
        </h3>
        <div style={{
          background: 'rgba(0, 240, 255, 0.06)',
          border: '1px solid rgba(0, 240, 255, 0.28)',
          borderLeft: '4px solid var(--cyber-cyan)',
          borderRadius: '0 var(--r-md) var(--r-md) 0',
          padding: '1rem 1.25rem',
          fontFamily: 'var(--font-mono)',
          fontSize: '0.88rem',
          color: '#e2e8f0',
          lineHeight: 1.65,
          fontStyle: 'italic',
        }}>
          "Can a phishing detector maintain reliable predictions when the same underlying phishing message is paraphrased by humans or AI, or expressed using code-mixed language such as Romanized Hinglish and Kanglish?"
        </div>
      </div>

      {/* Intent Fingerprint Grid */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '0.85rem', color: 'var(--cyber-cyan)', marginBottom: '0.85rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          [02] 4-Dimensional Phishing Intent Fingerprint
        </h3>
        <p style={{ fontSize: '0.84rem', color: 'var(--text-secondary)', marginBottom: '1.25rem', fontFamily: 'var(--font-mono)' }}>
          // Phishing attacks rely on core social-engineering dimensions regardless of surface phrasing. PhishGuard AI models an explicit 4D intent fingerprint per message.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: '0.85rem' }}>
          {fingerprints.map((fp) => {
            const Icon = fp.icon;
            return (
              <div key={fp.label} style={{
                background: 'var(--bg-input)',
                padding: '1rem 1.1rem',
                borderRadius: 'var(--r-md)',
                border: `1px solid ${fp.color}30`,
                boxShadow: `0 0 16px ${fp.color}15`,
                borderTop: `2px solid ${fp.color}`,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                  <Icon size={15} color={fp.color} />
                  <strong style={{ color: fp.color, fontSize: '0.75rem', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }}>
                    {fp.label}
                  </strong>
                </div>
                <p style={{ fontSize: '0.775rem', color: 'var(--text-muted)', lineHeight: 1.55 }}>{fp.desc}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Model Lineage */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '0.85rem', color: 'var(--cyber-cyan)', marginBottom: '0.85rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          [03] Four-Tier Model Lineage
        </h3>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem' }}>
          {modelLineage.map((m, i) => (
            <div key={m.id} style={{
              display: 'flex',
              gap: '1rem',
              padding: '1rem 1.15rem',
              background: m.highlight ? 'rgba(0, 255, 157, 0.05)' : 'var(--bg-input)',
              border: m.highlight ? '1px solid rgba(0, 255, 157, 0.35)' : '1px solid var(--border-dim)',
              borderRadius: 'var(--r-md)',
              alignItems: 'flex-start',
            }}>
              <div style={{
                width: 32, height: 32, borderRadius: 'var(--r-sm)',
                background: m.highlight ? 'rgba(0, 255, 157, 0.18)' : 'rgba(0, 240, 255, 0.10)',
                border: m.highlight ? '1px solid rgba(0, 255, 157, 0.5)' : '1px solid var(--border-dim)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexShrink: 0, fontFamily: 'var(--font-mono)', fontWeight: 700,
                fontSize: '0.72rem', color: m.highlight ? 'var(--lime-bright)' : 'var(--cyber-cyan)',
              }}>
                0{i + 1}
              </div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', marginBottom: '0.3rem' }}>
                  <strong style={{ fontFamily: 'var(--font-mono)', fontSize: '0.85rem', color: m.highlight ? 'var(--lime-bright)' : 'var(--text-primary)' }}>
                    {m.title}
                  </strong>
                  <span className={`badge-tag ${m.tagColor}`}>{m.tag}</span>
                </div>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.6 }}>{m.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Hard Negatives */}
      <div className="card">
        <h3 style={{ fontFamily: 'var(--font-display)', fontSize: '0.85rem', color: 'var(--cyber-cyan)', marginBottom: '0.85rem', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
          [04] Hard Negatives &amp; Near-Miss Benchmark Pairs
        </h3>
        <div style={{ background: 'rgba(255, 23, 68, 0.06)', border: '1px solid rgba(255, 23, 68, 0.22)', borderRadius: 'var(--r-md)', padding: '1rem 1.15rem', fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.7 }}>
          To avoid the spurious shortcut that <code style={{ color: 'var(--cyber-cyan)', background: 'rgba(0, 240, 255, 0.1)', padding: '0.1rem 0.35rem', borderRadius: '4px' }}>urgency = phishing</code>, the evaluation suite incorporates critical <strong style={{ color: '#ffd166' }}>hard negatives</strong>: legitimate transactional OTPs ("Do not share this OTP with anyone") and urgent utility reminders ("Service may be disconnected if unpaid — pay via official app"). Adversarial near-miss pairs test fine-grained boundary discrimination at the phishing / genuine frontier.
        </div>
      </div>
    </div>
  );
}
