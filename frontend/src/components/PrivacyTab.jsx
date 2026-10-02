import React from 'react';
import { Lock, ShieldCheck, Eye, Server, Trash2, Globe } from 'lucide-react';

const Section = ({ icon: Icon, color, code, title, children }) => (
  <div className="card" style={{ marginBottom: '1.25rem' }}>
    <div className="card-title">
      <Icon size={18} color={color || '#00f0ff'} />
      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.72rem', color: color || 'var(--cyber-cyan)', opacity: 0.75 }}>[{code}]</span>
      {title}
    </div>
    {children}
  </div>
);

const Row = ({ label, value, valueColor }) => (
  <div className="extracted-row">
    <span className="extracted-key">{label}</span>
    <span className="extracted-val" style={valueColor ? { color: valueColor } : undefined}>{value}</span>
  </div>
);

export default function PrivacyTab() {
  return (
    <div style={{ maxWidth: '860px', margin: '0 auto' }}>

      {/* Cyber Hero Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.10), rgba(139, 92, 246, 0.10))',
        border: '1px solid rgba(0, 240, 255, 0.30)',
        borderTop: '2px solid var(--cyber-cyan)',
        borderRadius: 'var(--r-lg)',
        padding: '1.5rem',
        marginBottom: '1.75rem',
        display: 'flex',
        gap: '1.25rem',
        alignItems: 'center',
        boxShadow: '0 0 28px rgba(0, 240, 255, 0.08)',
      }}>
        <div style={{
          background: 'linear-gradient(135deg, rgba(0, 240, 255, 0.25), rgba(139, 92, 246, 0.30))',
          border: '1px solid var(--cyber-cyan)',
          borderRadius: 'var(--r-md)',
          width: 52, height: 52,
          display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
          boxShadow: '0 0 20px rgba(0, 240, 255, 0.3)',
        }}>
          <Lock size={24} color="#00f0ff" style={{ filter: 'drop-shadow(0 0 6px #00f0ff)' }} />
        </div>
        <div>
          <div style={{ fontFamily: 'var(--font-display)', fontSize: '1.15rem', fontWeight: 800, color: 'var(--cyber-cyan)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: '0.3rem' }}>
            Privacy-First by Design // Secure Local Enclave
          </div>
          <div style={{ fontSize: '0.88rem', color: 'var(--text-secondary)', lineHeight: 1.65, fontFamily: 'var(--font-mono)' }}>
            PhishGuard AI performs all analysis entirely on-device using a local ML pipeline.
            No message content is transmitted to external servers or third-party APIs.
          </div>
        </div>
      </div>

      {/* Data Collection */}
      <Section icon={ShieldCheck} color="#00ff9d" code="COLLECT" title="DATA COLLECTION MANIFEST">
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem', fontFamily: 'var(--font-mono)' }}>
          // PhishGuard AI is designed to collect <strong style={{ color: 'var(--lime-bright)' }}>as little data as possible</strong>. Transparent breakdown:
        </p>
        <div className="extracted-details">
          <Row label="message_text" value="Processed in-memory · never persisted" valueColor="var(--lime-bright)" />
          <Row label="sender / subject" value="Processed in-memory · never persisted" valueColor="var(--lime-bright)" />
          <Row label="repeat_check_hash" value="SHA-256 fingerprint in session RAM only" valueColor="var(--cyber-cyan)" />
          <Row label="session_logs" value="None — cleared on app restart" valueColor="var(--lime-bright)" />
          <Row label="cookies / tracking" value="None" valueColor="var(--lime-bright)" />
          <Row label="external_api_calls" value="None — fully offline inference" valueColor="var(--lime-bright)" />
        </div>
      </Section>

      {/* Local Inference Architecture */}
      <Section icon={Server} color="#b49aff" code="ARCH" title="LOCAL INFERENCE ARCHITECTURE">
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: 1.65, fontFamily: 'var(--font-mono)' }}>
          // Detection pipeline runs entirely inside the FastAPI backend on your machine. Sequence of operations:
        </p>
        <ol style={{ paddingLeft: '1.35rem', fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 2.1 }}>
          <li>Text is <strong style={{ color: 'var(--cyber-cyan)' }}>vectorised</strong> using a TF-IDF + domain-feature extractor.</li>
          <li>A <strong style={{ color: 'var(--cyber-cyan)' }}>trained scikit-learn classifier</strong> (or ensemble) returns a probability score.</li>
          <li>Deterministic <strong style={{ color: 'var(--cyber-cyan)' }}>rule-engine cues</strong> are extracted via regex matching and domain heuristics.</li>
          <li>Results are returned to the browser — the raw text is <strong style={{ color: 'var(--lime-bright)' }}>discarded from RAM</strong>.</li>
        </ol>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.85rem', fontFamily: 'var(--font-mono)' }}>
          // No GPU cloud services, no LLM API calls, no data leaves the local network.
        </p>
      </Section>

      {/* Repeat-Check */}
      <Section icon={Eye} color="#ffd166" code="HASH" title="REPEAT-CHECK MECHANISM">
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.7, fontFamily: 'var(--font-mono)' }}>
          The repeat-check service stores a <strong style={{ color: 'var(--amber-bright)' }}>one-way SHA-256 hash</strong> of the message text in a Python{' '}
          <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--cyber-cyan)', background: 'rgba(0, 240, 255, 0.1)', padding: '0.1rem 0.35rem', borderRadius: '4px' }}>defaultdict</code>
          {' '}held in process memory. It is computationally infeasible to reconstruct the original message from this hash. All hashes are purged when the backend process terminates.
        </p>
      </Section>

      {/* Data Retention */}
      <Section icon={Trash2} color="#ff616f" code="RETAIN" title="DATA RETENTION POLICY">
        <p style={{ fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 1.65, marginBottom: '0.75rem', fontFamily: 'var(--font-mono)' }}>
          PhishGuard AI retains <strong style={{ color: 'var(--lime-bright)' }}>zero persistent data</strong> about submitted messages.
        </p>
        <ul style={{ paddingLeft: '1.35rem', fontSize: '0.875rem', color: 'var(--text-secondary)', lineHeight: 2 }}>
          <li>No database, no file logs, no cloud storage of any kind.</li>
          <li>Restarting the backend resets all in-memory counters to zero.</li>
          <li>The frontend stores no data in <code style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', color: 'var(--cyber-cyan)', background: 'rgba(0, 240, 255, 0.1)', padding: '0.1rem 0.3rem', borderRadius: '4px' }}>localStorage</code> or cookies.</li>
        </ul>
      </Section>

      {/* Third-Party Services */}
      <Section icon={Globe} color="#b49aff" code="3P" title="THIRD-PARTY SERVICES AUDIT">
        <div className="extracted-details">
          <Row label="analytics_trackers" value="None" valueColor="var(--lime-bright)" />
          <Row label="cdn_fonts" value="Google Fonts (CSS only · no JS execution)" valueColor="var(--cyber-cyan)" />
          <Row label="external_ml_apis" value="None" valueColor="var(--lime-bright)" />
          <Row label="crash_reporting" value="None" valueColor="var(--lime-bright)" />
          <Row label="advertising_networks" value="None" valueColor="var(--lime-bright)" />
        </div>
        <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.95rem', fontFamily: 'var(--font-mono)' }}>
          // Google Fonts loads stylesheet data via your browser; no message content is included in font requests.
        </p>
      </Section>

    </div>
  );
}
