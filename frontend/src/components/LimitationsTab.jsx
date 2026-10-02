import React from 'react';
import { AlertTriangle, Target, Brain, Globe, RefreshCw, Info } from 'lucide-react';

const Section = ({ icon: Icon, color, code, title, children }) => (
  <div className="card" style={{ marginBottom: '1.25rem' }}>
    <div className="card-title">
      <Icon size={18} color={color || '#ffb703'} />
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: color || '#ffd166', opacity: 0.75 }}>[{code}]</span>
      {title}
    </div>
    {children}
  </div>
);

const LimitItem = ({ id, title, desc }) => (
  <div style={{
    padding: '0.9rem 1.1rem',
    background: 'rgba(255, 23, 68, 0.06)',
    border: '1px solid rgba(255, 23, 68, 0.22)',
    borderLeft: '3px solid var(--crimson)',
    borderRadius: '0 var(--r-md) var(--r-md) 0',
    marginBottom: '0.75rem',
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', marginBottom: '0.3rem' }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--crimson-bright)', letterSpacing: '0.06em' }}>{id}</span>
      <strong style={{ fontWeight: 700, fontSize: '0.875rem', color: '#fca5a5' }}>{title}</strong>
    </div>
    <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.65 }}>{desc}</div>
  </div>
);

const MitigationItem = ({ id, title, desc }) => (
  <div style={{
    padding: '0.9rem 1.1rem',
    background: 'rgba(0, 255, 157, 0.06)',
    border: '1px solid rgba(0, 255, 157, 0.22)',
    borderLeft: '3px solid var(--lime)',
    borderRadius: '0 var(--r-md) var(--r-md) 0',
    marginBottom: '0.75rem',
  }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.55rem', marginBottom: '0.3rem' }}>
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.68rem', color: 'var(--lime-bright)', letterSpacing: '0.06em' }}>{id}</span>
      <strong style={{ fontWeight: 700, fontSize: '0.875rem', color: 'var(--lime-bright)' }}>{title}</strong>
    </div>
    <div style={{ fontSize: '0.825rem', color: 'var(--text-secondary)', lineHeight: 1.65 }}>{desc}</div>
  </div>
);

export default function LimitationsTab() {
  return (
    <div style={{ maxWidth: '860px', margin: '0 auto' }}>

      {/* Disclaimer Hazard Banner */}
      <div style={{
        background: 'rgba(255, 183, 3, 0.08)',
        border: '1px solid rgba(255, 183, 3, 0.32)',
        borderTop: '2px solid var(--amber)',
        borderRadius: 'var(--r-lg)',
        padding: '1.25rem 1.5rem',
        marginBottom: '1.75rem',
        display: 'flex',
        gap: '1rem',
        alignItems: 'flex-start',
        boxShadow: '0 0 24px rgba(255, 183, 3, 0.10)',
      }}>
        <AlertTriangle size={22} color="#ffd166" style={{ flexShrink: 0, marginTop: '2px', filter: 'drop-shadow(0 0 6px #ffb703)' }} />
        <div style={{ fontSize: '0.88rem', color: '#fcd34d', lineHeight: 1.65, fontFamily: 'var(--font-mono)' }}>
          <strong style={{ color: 'var(--amber-bright)', letterSpacing: '0.04em' }}>⚠ IMPORTANT DISCLAIMER:</strong>
          <span style={{ color: 'var(--text-secondary)' }}> PhishGuard AI is a research prototype. Its predictions are probabilistic and </span>
          <em style={{ color: '#ffd166' }}>should never be the sole basis for high-stakes security decisions</em>
          <span style={{ color: 'var(--text-secondary)' }}>. Always apply human judgement and consult official sources when in doubt.</span>
        </div>
      </div>

      {/* Known Limitations */}
      <Section icon={Target} color="#ff616f" code="LIMITS" title="KNOWN MODEL LIMITATIONS">
        <LimitItem
          id="LIMIT_01"
          title="Dataset Distribution Shift"
          desc="The model was trained on English-language phishing datasets from 2020–2024. Campaigns in other languages, or novel post-training campaigns, may not be detected accurately."
        />
        <LimitItem
          id="LIMIT_02"
          title="Adversarial Text Manipulation"
          desc="A determined attacker can insert benign-looking tokens, use lookalike Unicode characters, or fragment URLs across lines to evade the TF-IDF features the model relies on."
        />
        <LimitItem
          id="LIMIT_03"
          title="Image-Based Phishing (Blind Spot)"
          desc="The system analyses text only. Phishing messages that embed the malicious call-to-action inside an image attachment will receive a low risk score and may be missed entirely."
        />
        <LimitItem
          id="LIMIT_04"
          title="Short / Context-Free Messages"
          desc="Very short messages (e.g., one-word OTPs or terse alerts) offer little lexical signal. Predictions on messages under ~15 words carry higher uncertainty."
        />
        <LimitItem
          id="LIMIT_05"
          title="False Positives on Legitimate Alerts"
          desc="Genuine urgency-bearing messages from banks, utilities, and government services may occasionally be flagged as suspicious because they share surface-level vocabulary with phishing."
        />
      </Section>

      {/* Model Scope */}
      <Section icon={Brain} color="#b49aff" code="SCOPE" title="MODEL SCOPE &amp; COVERAGE">
        <div className="extracted-details">
          <div className="extracted-row">
            <span className="extracted-key">supported_channels</span>
            <span className="extracted-val" style={{ color: 'var(--cyber-cyan)' }}>Email, SMS</span>
          </div>
          <div className="extracted-row">
            <span className="extracted-key">supported_languages</span>
            <span className="extracted-val" style={{ color: 'var(--cyber-cyan)' }}>English (primary)</span>
          </div>
          <div className="extracted-row">
            <span className="extracted-key">training_data_horizon</span>
            <span className="extracted-val">2020–2024</span>
          </div>
          <div className="extracted-row">
            <span className="extracted-key">max_text_length</span>
            <span className="extracted-val">~2,000 tokens (truncated beyond)</span>
          </div>
          <div className="extracted-row">
            <span className="extracted-key">image_attachment_analysis</span>
            <span className="extracted-val" style={{ color: '#ff616f' }}>NOT SUPPORTED</span>
          </div>
          <div className="extracted-row">
            <span className="extracted-key">realtime_url_reputation</span>
            <span className="extracted-val" style={{ color: '#ffd166' }}>NOT SUPPORTED (offline inference)</span>
          </div>
        </div>
      </Section>

      {/* Geo-linguistic Coverage */}
      <Section icon={Globe} color="#00f0ff" code="GEO" title="GEO-LINGUISTIC COVERAGE GAPS">
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.65, marginBottom: '0.85rem', fontFamily: 'var(--font-mono)' }}>
          // Training samples are heavily skewed towards phishing targeting US, UK, and Indian users. Known coverage gaps:
        </p>
        <ul style={{ paddingLeft: '1.35rem', fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 2.1 }}>
          <li>Non-Latin scripts (Arabic, Devanagari, CJK, Cyrillic)</li>
          <li>Regional Indian language SMS</li>
          <li>WhatsApp-style forwarded chain messages</li>
          <li>Voice-phishing (vishing) transcripts</li>
        </ul>
      </Section>

      {/* Implemented Mitigations */}
      <Section icon={RefreshCw} color="#00ff9d" code="MITIGATION" title="IMPLEMENTED MITIGATIONS">
        <MitigationItem
          id="MIT_01"
          title="Rule-Engine Cue Extraction"
          desc="Deterministic regex-based checks for spoofed senders, OTP-share requests, urgency triggers, and suspicious URL patterns act as a safety net independent of the ML model."
        />
        <MitigationItem
          id="MIT_02"
          title="Repeat-Message Detection"
          desc="If the same message is submitted multiple times (mass-blast campaign), the repeat counter increases and is surfaced in the UI as an additional risk signal."
        />
        <MitigationItem
          id="MIT_03"
          title="Confidence Score Transparency"
          desc="The UI always displays the raw probability score alongside the label so users can gauge prediction uncertainty rather than treating the output as binary."
        />
        <MitigationItem
          id="MIT_04"
          title="Anti-Leakage Training Protocol"
          desc="All dataset variants sharing the same template_id are strictly confined to either the training or test split, preventing inflated benchmark scores."
        />
      </Section>

      {/* Responsible Use */}
      <div className="card" style={{ background: 'rgba(139, 92, 246, 0.07)', borderColor: 'rgba(139, 92, 246, 0.30)' }}>
        <div className="card-title">
          <Info size={18} color="#b49aff" />
          <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: '#b49aff', opacity: 0.75 }}>[RESPONSIBLE_USE]</span>
          RESPONSIBLE USE GUIDELINES
        </div>
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.7, marginBottom: '0.75rem', fontFamily: 'var(--font-mono)' }}>
          PhishGuard AI is intended as a <strong style={{ color: 'var(--violet-bright)' }}>supplementary tool</strong> to assist users in identifying potentially malicious messages. It is not a replacement for:
        </p>
        <ul style={{ paddingLeft: '1.35rem', fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 2 }}>
          <li>Official anti-phishing services provided by your email or mobile provider</li>
          <li>Domain reputation databases (e.g., Google Safe Browsing, VirusTotal)</li>
          <li>Security-trained human review for high-value targets</li>
          <li>Organisational incident-response procedures and SOC teams</li>
        </ul>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.95rem', fontFamily: 'var(--font-mono)' }}>
          // If you receive a message believed to be part of an active phishing campaign, report it to your national cybersecurity authority (CERT-In, NCSC, CISA).
        </p>
      </div>

    </div>
  );
}
