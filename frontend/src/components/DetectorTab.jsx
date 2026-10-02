import React, { useState, useRef, useCallback } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertCircle, Mail, MessageSquare, 
  Send, RefreshCw, AlertTriangle, Fingerprint, 
  HelpCircle, CheckCircle2, UserCheck, Link2, Info, Zap, Shield,
  Paperclip, FileWarning, File, FileText, Archive, UploadCloud,
  XCircle, BarChart2, Globe, ExternalLink, Radio, Rss, Search
} from 'lucide-react';

// ── Web Intelligence Panel Component ────────────────────────────────────────
function WebIntelPanel({ webIntel }) {
  if (!webIntel) return null;

  const isScam = webIntel.is_known_scam;
  const isVerified = webIntel.is_verified_entity && !isScam;
  const hasSocialSignals = webIntel.social_media_signals?.length > 0;
  const hasUrlhausFindings = webIntel.urlhaus_findings?.length > 0;
  const hasImpersonation = webIntel.impersonation_alerts?.length > 0;
  const hasScamBulletins = webIntel.scam_bulletins?.length > 0;
  const hasFindings = webIntel.findings?.some(f => f.verdict !== 'VERIFIED_OFFICIAL');

  const panelBorder = isScam ? 'rgba(255,23,68,0.45)' : isVerified ? 'rgba(0,255,157,0.35)' : 'var(--border-dim)';
  const panelBg = isScam ? 'rgba(255,23,68,0.04)' : isVerified ? 'rgba(0,255,157,0.04)' : 'rgba(7,9,24,0.85)';
  const scoreColor = webIntel.reputation_score >= 75 ? '#ff616f' : webIntel.reputation_score >= 45 ? '#ffd166' : '#5affbf';

  return (
    <div style={{ marginBottom: '1.25rem' }}>
      <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--cyber-cyan)', marginBottom: '0.55rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-display)', letterSpacing: '0.06em' }}>
        <Globe size={15} />
        <span>WEB INTELLIGENCE // OSINT THREAT CORRELATION</span>
        {isScam && <span className="badge-tag badge-red" style={{ fontSize: '0.62rem', padding: '0.1rem 0.35rem' }}>THREAT CONFIRMED</span>}
        {isVerified && <span className="badge-tag badge-green" style={{ fontSize: '0.62rem', padding: '0.1rem 0.35rem' }}>ENTITY VERIFIED</span>}
      </div>

      <div style={{ background: panelBg, border: `1px solid ${panelBorder}`, borderRadius: 'var(--r-md)', padding: '0.9rem 1rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>

        {/* Reputation Status Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
          <div>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }}>REPUTATION STATUS</div>
            <div style={{ fontSize: '0.88rem', fontWeight: 700, color: isScam ? '#ff616f' : isVerified ? '#5affbf' : '#ffd166', fontFamily: 'var(--font-display)' }}>
              {webIntel.reputation_status}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>THREAT SCORE</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 800, color: scoreColor, fontFamily: 'var(--font-display)' }}>
              {webIntel.reputation_score}<span style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>/100</span>
            </div>
          </div>
        </div>

        {/* Summary */}
        {webIntel.summary && (
          <div style={{ fontSize: '0.82rem', lineHeight: '1.5', color: 'var(--text-secondary)', borderTop: '1px solid var(--border-dim)', paddingTop: '0.6rem', fontStyle: 'italic' }}>
            {webIntel.summary}
          </div>
        )}

        {/* Brand Impersonation Alerts */}
        {hasImpersonation && (
          <div>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#ff616f', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
              <ShieldAlert size={13} />
              <span>BRAND IMPERSONATION DETECTED ({webIntel.impersonation_alerts.length})</span>
            </div>
            {webIntel.impersonation_alerts.slice(0, 3).map((alert, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.3rem', fontSize: '0.8rem', lineHeight: '1.4' }}>
                <span style={{ color: '#ff616f', flexShrink: 0 }}>⚠</span>
                <span style={{ color: 'var(--text-primary)' }}>{alert}</span>
              </div>
            ))}
          </div>
        )}

        {/* Public Scam Bulletins */}
        {hasScamBulletins && (
          <div>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: '#ffd166', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
              <AlertTriangle size={13} />
              <span>SCAM ADVISORY BULLETINS ({webIntel.scam_bulletins.length})</span>
            </div>
            {webIntel.scam_bulletins.slice(0, 3).map((bulletin, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.3rem', fontSize: '0.78rem', lineHeight: '1.4' }}>
                <span style={{ color: '#ffd166', flexShrink: 0 }}>▸</span>
                <span style={{ color: 'var(--text-secondary)' }}>{bulletin}</span>
              </div>
            ))}
          </div>
        )}

        {/* Social Media Scam Signals */}
        {hasSocialSignals && (
          <div style={{ background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.22)', borderRadius: '6px', padding: '0.65rem 0.8rem' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--violet-bright)', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
              <Rss size={13} />
              <span>SOCIAL MEDIA / NEWS INTELLIGENCE ({webIntel.social_media_signals.length})</span>
            </div>
            {webIntel.social_media_signals.slice(0, 3).map((sig, i) => (
              <div key={i} style={{ marginBottom: '0.45rem', padding: '0.4rem 0.55rem', background: 'rgba(0,0,0,0.3)', borderRadius: '4px', borderLeft: '2px solid rgba(139,92,246,0.5)' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--violet-bright)', fontFamily: 'var(--font-mono)', marginBottom: '0.15rem' }}>
                  📡 {sig.platform}
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', lineHeight: '1.4' }}>{sig.signal}</div>
                {sig.report_volume && (
                  <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.15rem', fontFamily: 'var(--font-mono)' }}>📊 {sig.report_volume}</div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* URLhaus / Threat Feed Hits */}
        {hasUrlhausFindings && (
          <div style={{ background: 'rgba(255,0,127,0.05)', border: '1px solid rgba(255,0,127,0.25)', borderRadius: '6px', padding: '0.65rem 0.8rem' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--fuchsia-bright)', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
              <Search size={13} />
              <span>THREAT FEED INTELLIGENCE ({webIntel.urlhaus_findings.length})</span>
            </div>
            {webIntel.urlhaus_findings.slice(0, 4).map((uf, i) => (
              <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', marginBottom: '0.3rem', fontSize: '0.78rem', lineHeight: '1.4' }}>
                <span style={{ color: 'var(--fuchsia-bright)', flexShrink: 0 }}>⚡</span>
                <div>
                  {uf.detail && <div style={{ color: 'var(--text-secondary)' }}>{uf.detail}</div>}
                  {uf.feed && <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginTop: '0.1rem' }}>Feed: {uf.feed}</div>}
                  {uf.verdict && <span className="badge-tag badge-red" style={{ fontSize: '0.62rem', padding: '0.05rem 0.3rem', marginTop: '0.15rem', display: 'inline-block' }}>{uf.verdict}</span>}
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Verified Entity Badge */}
        {isVerified && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.45rem 0.7rem', background: 'rgba(0,255,157,0.06)', border: '1px solid rgba(0,255,157,0.25)', borderRadius: '6px', fontSize: '0.8rem' }}>
            <CheckCircle2 size={14} color="#5affbf" />
            <span style={{ color: '#5affbf' }}>Verified official institution — domain registered under canonical authority.</span>
          </div>
        )}

        {/* Sources Queried */}
        {webIntel.sources_queried?.length > 0 && (
          <div style={{ borderTop: '1px solid var(--border-dim)', paddingTop: '0.5rem' }}>
            <div style={{ fontSize: '0.67rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '0.25rem' }}>// INTELLIGENCE SOURCES QUERIED:</div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.3rem' }}>
              {webIntel.sources_queried.map((src, i) => (
                <span key={i} style={{ fontSize: '0.62rem', color: 'var(--text-muted)', background: 'rgba(255,255,255,0.03)', border: '1px solid var(--border-dim)', borderRadius: '3px', padding: '0.1rem 0.35rem', fontFamily: 'var(--font-mono)' }}>
                  {src}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

const MAX_FILE_SIZE_MB = 25;

function formatBytes(bytes) {
  if (bytes == null || isNaN(bytes)) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function getFileIcon(name) {
  const ext = name?.split('.').pop()?.toLowerCase();
  if (['pdf'].includes(ext)) return <FileText size={20} color="#ff94a2" />;
  if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].includes(ext)) return <FileText size={20} color="#ffd166" />;
  if (['zip', 'rar', '7z'].includes(ext)) return <Archive size={20} color="#a78bfa" />;
  if (['exe', 'dll', 'bat', 'ps1'].includes(ext)) return <FileWarning size={20} color="#ff616f" />;
  return <File size={20} color="var(--cyber-cyan)" />;
}

function getRiskSeverityColor(level) {
  if (!level) return 'var(--text-muted)';
  const l = level.toLowerCase();
  if (l === 'critical' || l === 'high' || l === 'high-risk') return '#ff616f';
  if (l === 'medium' || l === 'low' || l === 'suspicious') return '#ffd166';
  return '#5affbf';
}

const SMS_DEMO_SAMPLES = [
  {
    label: 'High-risk SMS',
    tier: 'danger',
    tag: 'CRITICAL',
    channel: 'SMS',
    sender: 'HDFCBK',
    subject: '',
    text: 'Your HDFC account will be suspended today. Verify KYC immediately: https://hdfc-netbanking-kyc.com/login'
  },
  {
    label: 'Suspicious SMS',
    tier: 'warning',
    tag: 'SUSPICIOUS',
    channel: 'SMS',
    sender: 'INFO',
    subject: '',
    text: 'Your account requires urgent verification. View details at http://bit.ly/bank-verify-urgent'
  },
  {
    label: 'Genuine SMS',
    tier: 'safe',
    tag: 'CLEAN',
    channel: 'SMS',
    sender: 'DHBVN',
    subject: '',
    text: 'Your electricity bill of Rs 850 for September is due on 10 October. Pay through official biller app or dhbvn.org.in.'
  }
];

const EMAIL_DEMO_SAMPLES = [
  {
    label: 'High-risk Email',
    tier: 'danger',
    tag: 'CRITICAL',
    channel: 'Email',
    sender: 'security@chase-identity-resolution.net',
    subject: 'Urgent: Unusual sign-in activity on your Chase Online account',
    text: 'Subject: Urgent: Unusual sign-in activity on your Chase Online account\n\nDear Chase Customer,\n\nWe detected a sign-in attempt from an unrecognized IP address. For your security, your account access has been temporarily restricted.\n\nTo restore full account access, verify your identity immediately at:\nhttp://paypa1-resolution-case.biz/login\n\nFailure to verify within 24 hours will result in permanent suspension.\n\nChase Security Operations'
  },
  {
    label: 'Genuine Email',
    tier: 'safe',
    tag: 'CLEAN',
    channel: 'Email',
    sender: 'billing@aws.amazon.com',
    subject: 'Your AWS Monthly Billing Invoice is now available',
    text: 'Subject: Your AWS Monthly Billing Invoice is now available\n\nGreetings from Amazon Web Services,\n\nYour billing statement for the month of September is now available. Your card ending in 4102 has been charged $18.42.\n\nTo view your detailed itemized usage breakdown, log in to the official AWS Management Console at https://console.aws.amazon.com/billing\n\nThank you for choosing AWS.'
  }
];

const URL_DEMO_SAMPLES = [
  {
    label: 'Typosquatting Spoof',
    tier: 'danger',
    tag: 'CRITICAL',
    url: 'http://paypa1-resolution-case.biz/login'
  },
  {
    label: 'IP-based KYC Portal',
    tier: 'danger',
    tag: 'CRITICAL',
    url: 'http://192.168.1.1/login/verify-hdfc-kyc'
  },
  {
    label: 'Shortened Redirect',
    tier: 'warning',
    tag: 'SUSPICIOUS',
    url: 'http://bit.ly/bank-verify-urgent'
  },
  {
    label: 'Brand Subdomain Injection',
    tier: 'warning',
    tag: 'SUSPICIOUS',
    url: 'http://hdfc.security-verify-alerts.info/auth'
  },
  {
    label: 'Official Bank Portal',
    tier: 'safe',
    tag: 'CLEAN',
    url: 'https://www.hdfcbank.com'
  },
  {
    label: 'AWS Management Console',
    tier: 'safe',
    tag: 'CLEAN',
    url: 'https://console.aws.amazon.com/billing'
  }
];

export default function DetectorTab() {
  // Active Channel: 'SMS' | 'Email' | 'URL' | 'Attachment'
  const [channel, setChannel] = useState('SMS');
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');

  // Attachment state
  const [attachedFile, setAttachedFile] = useState(null);
  const [attachResult, setAttachResult] = useState(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef(null);

  // Standalone URL analysis state
  const [urlInput, setUrlInput] = useState('');
  const [urlResult, setUrlResult] = useState(null);
  const [urlLoading, setUrlLoading] = useState(false);

  const handleSelectDemo = (demo) => {
    if (demo.channel) {
      setChannel(demo.channel);
      setSender(demo.sender || '');
      setSubject(demo.subject || '');
      setText(demo.text || '');
      setError('');
    }
  };

  const handleSelectUrlDemo = (demo) => {
    setUrlInput(demo.url);
    setError('');
    handleUrlAnalyze(demo.url);
  };

  const handleAnalyze = async (e) => {
    e?.preventDefault();
    if (!text.trim()) {
      setError('Please enter a message payload to analyze.');
      return;
    }
    setError('');
    setLoading(true);

    try {
      const response = await fetch('/predict', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          channel,
          sender: sender.trim(),
          subject: channel === 'Email' ? subject.trim() : '',
          text: text.trim()
        })
      });

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || 'Analysis request failed.');
      }

      const data = await response.json();
      setResult(data);
    } catch (err) {
      setError(err.message || 'Failed to connect to PhishGuard AI service.');
    } finally {
      setLoading(false);
    }
  };

  // ── Attachment handlers ───────────────────────────────────────────────────

  const validateFile = (file) => {
    if (file.size > MAX_FILE_SIZE_MB * 1024 * 1024) {
      return `File exceeds maximum allowed upload size of ${MAX_FILE_SIZE_MB}MB.`;
    }
    return null;
  };

  const handleFileSelect = useCallback((file) => {
    if (!file) return;
    const err = validateFile(file);
    if (err) { setError(err); return; }
    setAttachedFile(file);
    setAttachResult(null);
    setError('');
  }, []);

  const handleDrop = useCallback((e) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files[0];
    if (file) handleFileSelect(file);
  }, [handleFileSelect]);

  const handleDragOver = useCallback((e) => { e.preventDefault(); setIsDragOver(true); }, []);
  const handleDragLeave = useCallback((e) => { e.preventDefault(); setIsDragOver(false); }, []);

  const clearAttachment = () => {
    setAttachedFile(null);
    setAttachResult(null);
    setError('');
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleAttachmentAnalyze = async () => {
    if (!attachedFile) { setError('Please select a file to analyze.'); return; }
    setError('');
    setLoading(true);
    setAttachResult(null);
    try {
      const formData = new FormData();
      formData.append('file', attachedFile);
      const response = await fetch('/api/attachment/analyze-attachment', {
        method: 'POST',
        body: formData,
      });
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || 'Attachment analysis failed.');
      }
      setAttachResult(await response.json());
    } catch (err) {
      setError(err.message || 'Failed to connect to PhishGuard AI service.');
    } finally {
      setLoading(false);
    }
  };

  // ── Standalone URL handler ────────────────────────────────────────────────

  const handleUrlAnalyze = async (overrideUrl) => {
    const target = (typeof overrideUrl === 'string' ? overrideUrl : urlInput).trim();
    if (!target) { 
      setError('Please enter a target URL to analyze.'); 
      return; 
    }
    setError('');
    setUrlLoading(true);
    setUrlResult(null);
    try {
      let response;
      try {
        response = await fetch('/api/attachment/analyze-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: target }),
        });
      } catch (networkErr) {
        response = await fetch('/analyze-url', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: target }),
        });
      }

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}));
        throw new Error(errData.detail || 'URL analysis request failed.');
      }
      const data = await response.json();
      setUrlResult(data);
    } catch (err) {
      setError(err.message || 'Failed to analyze URL.');
    } finally {
      setUrlLoading(false);
    }
  };

  const getRiskClass = (risk) => {
    if (risk === 'High-risk') return 'high-risk';
    if (risk === 'Suspicious') return 'suspicious';
    return 'genuine';
  };

  const getRiskIcon = (risk) => {
    if (risk === 'High-risk') return <ShieldAlert size={28} />;
    if (risk === 'Suspicious') return <AlertTriangle size={28} />;
    return <ShieldCheck size={28} />;
  };

  return (
    <div>
      {/* Tactical Privacy Enclave Banner */}
      <div className="privacy-banner">
        <Info className="privacy-banner-icon" size={20} />
        <div>
          <span>SECURE LOCAL ENCLAVE: </span>Your payload is evaluated by <strong>PhishGuard AI</strong>. Messages, attachments, and URLs are analyzed strictly on-device without third-party cloud LLM transmission.
        </div>
      </div>

      <div className="grid-layout">
        {/* Left Column: Input Form Console */}
        <div className="card">
          <div className="card-title">
            <Send size={18} color="#00f0ff" />
            <span>PAYLOAD INGESTION // INTERCEPT CONSOLE</span>
          </div>

          {/* 4-Channel Selector: SMS · EMAIL · URL · ATTACHMENT */}
          <div className="channel-selector">
            <button
              type="button"
              className={`channel-btn ${channel === 'SMS' ? 'active' : ''}`}
              onClick={() => { setChannel('SMS'); setSubject(''); setError(''); }}
            >
              <span className="channel-led" />
              <MessageSquare size={16} />
              <span>SMS</span>
              <span className="channel-badge">PORT_01</span>
            </button>

            <button
              type="button"
              className={`channel-btn ${channel === 'Email' ? 'active' : ''}`}
              onClick={() => { setChannel('Email'); setError(''); }}
            >
              <span className="channel-led" />
              <Mail size={16} />
              <span>EMAIL</span>
              <span className="channel-badge">PORT_02</span>
            </button>

            <button
              type="button"
              className={`channel-btn ${channel === 'URL' ? 'active' : ''}`}
              onClick={() => { setChannel('URL'); setError(''); }}
            >
              <span className="channel-led" />
              <Link2 size={16} />
              <span>URL</span>
              <span className="channel-badge">PORT_03</span>
            </button>

            <button
              type="button"
              className={`channel-btn ${channel === 'Attachment' ? 'active' : ''}`}
              onClick={() => { setChannel('Attachment'); setError(''); }}
            >
              <span className="channel-led" />
              <Paperclip size={16} />
              <span>ATTACHMENT</span>
              <span className="channel-badge">PORT_04</span>
            </button>
          </div>

          {/* ── Mode 1 & 2: Email & SMS Form ── */}
          {(channel === 'SMS' || channel === 'Email') && (
            <form onSubmit={handleAnalyze}>
              {channel === 'Email' && (
                <div className="form-group">
                  <label className="form-label" htmlFor="email-subject">// EMAIL HEADER [SUBJECT]</label>
                  <input
                    id="email-subject"
                    className="form-input"
                    placeholder="e.g. Urgent: Account Verification Required"
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                  />
                </div>
              )}

              <div className="form-group">
                <label className="form-label" htmlFor="message-sender">
                  // {channel === 'Email' ? 'ORIGINATOR [SENDER EMAIL]' : 'ORIGINATOR [SENDER ID / MSISDN]'} (OPTIONAL)
                </label>
                <input
                  id="message-sender"
                  className="form-input"
                  placeholder={channel === 'Email' ? 'e.g. security@chase-verify.net' : 'e.g. HDFCBK or +919876543210'}
                  value={sender}
                  onChange={(e) => setSender(e.target.value)}
                />
              </div>

              <div className="form-group">
                <label className="form-label" htmlFor="message-body">
                  // {channel === 'Email' ? 'MESSAGE CONTENT PAYLOAD [BODY]' : 'SMS TEXT PAYLOAD [BODY]'}
                </label>
                <textarea
                  id="message-body"
                  className="form-textarea"
                  placeholder={channel === 'Email' ? 'Paste raw email headers, subject, and text body here...' : 'Paste raw SMS message text here...'}
                  value={text}
                  onChange={(e) => setText(e.target.value)}
                  rows={5}
                  required
                />
              </div>

              {error && (
                <div style={{ color: '#ff616f', fontSize: '0.85rem', marginBottom: '0.95rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                  <AlertCircle size={16} /><span>ERROR: {error}</span>
                </div>
              )}

              <button type="submit" className="submit-btn" disabled={loading}>
                {loading ? (
                  <>
                    <div className="spinner" />
                    <span>EXECUTING NEURAL SCAN PROTOCOL...</span>
                  </>
                ) : (
                  <>
                    <Zap size={18} />
                    <span>INITIATE THREAT SCAN [{channel}]</span>
                  </>
                )}
              </button>
            </form>
          )}

          {/* ── Mode 3: Standalone URL Scanner ── */}
          {channel === 'URL' && (
            <div>
              <div className="form-group">
                <label className="form-label" htmlFor="url-input-console">
                  // TARGET DESTINATION URL [HTTPS / HTTP PAYLOAD]
                </label>
                <div style={{ position: 'relative' }}>
                  <input
                    id="url-input-console"
                    className="form-input"
                    style={{ paddingRight: urlInput ? '2.5rem' : '1rem' }}
                    placeholder="https://suspicious-domain-kyc.in/login"
                    value={urlInput}
                    onChange={(e) => setUrlInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        handleUrlAnalyze();
                      }
                    }}
                  />
                  {urlInput && (
                    <button
                      type="button"
                      onClick={() => { setUrlInput(''); setUrlResult(null); setError(''); }}
                      style={{
                        position: 'absolute',
                        right: '10px',
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'none',
                        border: 'none',
                        color: 'var(--text-muted)',
                        cursor: 'pointer',
                        padding: 0
                      }}
                      aria-label="Clear URL"
                    >
                      <XCircle size={16} />
                    </button>
                  )}
                </div>
              </div>

              <div style={{
                background: 'rgba(7, 9, 24, 0.7)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--r-md)',
                padding: '0.75rem 0.95rem',
                marginBottom: '1.1rem',
                fontSize: '0.78rem',
                color: 'var(--text-secondary)',
                lineHeight: '1.5',
                fontFamily: 'var(--font-mono)'
              }}>
                <div style={{ color: 'var(--cyber-cyan)', fontWeight: 700, marginBottom: '0.3rem' }}>
                  // HEURISTIC INSPECTION SUITE:
                </div>
                <div>• IP-based hostnames & Punycode look-alike domains</div>
                <div>• Shortener resolution, suspicious TLDs & subdomain hijacking</div>
                <div>• Unencrypted HTTP transport & deceptive banking path keywords</div>
                <div>• Local trusted-domain verification (supporting evidence)</div>
              </div>

              {error && (
                <div style={{ color: '#ff616f', fontSize: '0.85rem', marginBottom: '0.95rem', display: 'flex', alignItems: 'center', gap: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                  <AlertCircle size={16} /><span>ERROR: {error}</span>
                </div>
              )}

              <button
                type="button"
                className="submit-btn"
                onClick={() => handleUrlAnalyze()}
                disabled={urlLoading || !urlInput.trim()}
              >
                {urlLoading ? (
                  <>
                    <div className="spinner" />
                    <span>EXECUTING HEURISTIC URL SCAN...</span>
                  </>
                ) : (
                  <>
                    <Zap size={18} />
                    <span>INITIATE DEEP URL SCAN [URL]</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* ── Mode 4: Attachment Mode UI ── */}
          {channel === 'Attachment' && (
            <div>
              {/* Dropzone */}
              <div
                className={`file-dropzone${isDragOver ? ' drag-over' : ''}`}
                onDrop={handleDrop}
                onDragOver={handleDragOver}
                onDragLeave={handleDragLeave}
                onClick={() => !attachedFile && fileInputRef.current?.click()}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => e.key === 'Enter' && !attachedFile && fileInputRef.current?.click()}
                aria-label="File upload dropzone"
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  style={{ display: 'none' }}
                  accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip,.rar,.exe,.dll,.bat,.ps1"
                  onChange={(e) => handleFileSelect(e.target.files[0])}
                />
                {!attachedFile ? (
                  <div className="dropzone-idle">
                    <UploadCloud size={36} className="dropzone-icon" />
                    <div className="dropzone-title">DROP FILE HERE OR CLICK TO BROWSE</div>
                    <div className="dropzone-subtitle">PDF · DOC/DOCX · XLS/XLSX · PPT · ZIP · EXE · DLL · PS1</div>
                    <div className="dropzone-limit">MAX {MAX_FILE_SIZE_MB}MB · STATIC ANALYSIS · NO CODE EXECUTION</div>
                  </div>
                ) : (
                  <div className="dropzone-file-preview" onClick={(e) => e.stopPropagation()}>
                    {getFileIcon(attachedFile.name)}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.84rem', color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                        {attachedFile.name}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                        {formatBytes(attachedFile.size)}
                      </div>
                    </div>
                    <button
                      type="button"
                      onClick={clearAttachment}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#ff616f', padding: '4px', display: 'flex', alignItems: 'center' }}
                      aria-label="Remove file"
                    >
                      <XCircle size={18} />
                    </button>
                  </div>
                )}
              </div>

              {error && (
                <div style={{ color: '#ff616f', fontSize: '0.85rem', margin: '0.8rem 0', display: 'flex', alignItems: 'center', gap: '0.5rem', fontFamily: 'var(--font-mono)' }}>
                  <AlertCircle size={16} /><span>ERROR: {error}</span>
                </div>
              )}

              <button
                type="button"
                className="submit-btn"
                style={{ marginTop: '1.15rem' }}
                onClick={handleAttachmentAnalyze}
                disabled={loading || !attachedFile}
              >
                {loading ? (
                  <>
                    <div className="spinner" />
                    <span>SCANNING FILE PAYLOAD...</span>
                  </>
                ) : (
                  <>
                    <BarChart2 size={18} />
                    <span>INITIATE STATIC FILE SCAN</span>
                  </>
                )}
              </button>
            </div>
          )}

          {/* Preset Test Vectors */}
          {channel === 'SMS' && (
            <div className="demo-section">
              <div className="demo-title">// LOAD TEST VECTORS / SMS PRESETS</div>
              <div className="demo-chips">
                {SMS_DEMO_SAMPLES.map((demo, idx) => (
                  <button key={idx} type="button" className="demo-chip" onClick={() => handleSelectDemo(demo)}>
                    <span className={`badge-tag ${demo.tier === 'danger' ? 'badge-red' : demo.tier === 'warning' ? 'badge-yellow' : 'badge-green'}`} style={{ padding: '0.1rem 0.35rem', fontSize: '0.62rem' }}>{demo.tag}</span>
                    <span>{demo.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {channel === 'Email' && (
            <div className="demo-section">
              <div className="demo-title">// LOAD TEST VECTORS / EMAIL PRESETS</div>
              <div className="demo-chips">
                {EMAIL_DEMO_SAMPLES.map((demo, idx) => (
                  <button key={idx} type="button" className="demo-chip" onClick={() => handleSelectDemo(demo)}>
                    <span className={`badge-tag ${demo.tier === 'danger' ? 'badge-red' : demo.tier === 'warning' ? 'badge-yellow' : 'badge-green'}`} style={{ padding: '0.1rem 0.35rem', fontSize: '0.62rem' }}>{demo.tag}</span>
                    <span>{demo.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          {channel === 'URL' && (
            <div className="demo-section">
              <div className="demo-title">// LOAD TEST VECTORS / URL PRESETS</div>
              <div className="demo-chips">
                {URL_DEMO_SAMPLES.map((demo, idx) => (
                  <button key={idx} type="button" className="demo-chip" onClick={() => handleSelectUrlDemo(demo)}>
                    <span className={`badge-tag ${demo.tier === 'danger' ? 'badge-red' : demo.tier === 'warning' ? 'badge-yellow' : 'badge-green'}`} style={{ padding: '0.1rem 0.35rem', fontSize: '0.62rem' }}>{demo.tag}</span>
                    <span>{demo.label}</span>
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Result Output & Evidence Console */}
        <div className="card">
          <div className="card-title">
            <ShieldAlert size={18} color="#00f0ff" />
            <span>DIAGNOSTIC READOUT // EVIDENCE TELEMETRY</span>
          </div>

          {/* ════════════════════════════════════════════════════════════════════
              STANDALONE URL SCANNER READOUT
             ════════════════════════════════════════════════════════════════════ */}
          {channel === 'URL' && !urlResult && !urlLoading && (
            <div className="empty-state">
              <div className="cyber-radar-scanner">
                <div className="radar-sweep" /><div className="radar-circle" /><div className="radar-circle circle-2" />
                <div className="radar-crosshair-h" /><div className="radar-crosshair-v" /><div className="radar-blip" />
              </div>
              <h3 className="empty-state-heading">STANDALONE URL SCANNER ACTIVE</h3>
              <p className="empty-state-desc">
                Awaiting target URL. Enter an HTTP/HTTPS address on the left console or select a test vector to inspect deceptive look-alikes, IP hosts, suspicious TLDs, and path-embedded lures.
              </p>
              <div className="empty-state-telemetry">
                <span>[HEURISTIC: ACTIVE]</span>
                <span>[TYPOSQUAT: MONITORED]</span>
                <span>[TLS_CHECK: ONLINE]</span>
              </div>
            </div>
          )}

          {channel === 'URL' && urlLoading && (
            <div className="empty-state">
              <div className="cyber-radar-scanner" style={{ animation: 'spin 3s linear infinite' }}>
                <div className="radar-sweep" /><div className="radar-circle" />
                <div className="radar-crosshair-h" /><div className="radar-crosshair-v" />
              </div>
              <h3 className="empty-state-heading" style={{ color: 'var(--cyber-cyan)' }}>ANALYZING TARGET URL HEURISTICS...</h3>
              <p className="empty-state-desc" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                Decomposing domain hierarchy · Inspecting Punycode / IDN · Verifying TLS posture · Querying local trusted registries
              </p>
            </div>
          )}

          {channel === 'URL' && urlResult && !urlLoading && (() => {
            const r = urlResult;
            const isHigh = r.risk === 'High-risk';
            const isSusp = r.risk === 'Suspicious';
            const riskClass = isHigh ? 'high-risk' : isSusp ? 'suspicious' : 'genuine';
            const riskColor = isHigh ? '#ff616f' : isSusp ? '#ffd166' : '#5affbf';

            return (
              <div>
                {/* Result Header Card */}
                <div className={`result-header ${riskClass}`}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                    {getRiskIcon(r.risk)}
                    <div>
                      <div className="result-badge">{r.risk}</div>
                      <div style={{ fontSize: '0.8rem', opacity: 0.9, fontFamily: 'var(--font-mono)' }}>
                        ESTIMATED URL RISK: {r.risk.toUpperCase()}
                      </div>
                    </div>
                  </div>

                  <div style={{ textAlign: 'right' }}>
                    <div className="result-confidence" style={{ fontSize: '0.82rem', fontFamily: 'var(--font-mono)', color: riskColor }}>
                      {r.is_suspicious ? 'ANOMALIES DETECTED' : 'CLEAN PROTOCOL'}
                    </div>
                    <div style={{ fontSize: '0.7rem', opacity: 0.85, marginTop: '4px', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.5rem' }}>
                      <span>ENGINE: URL HEURISTICS</span>
                      {typeof r.latency_ms === 'number' && (
                        <span style={{ color: 'var(--cyber-cyan)', fontWeight: 600 }}>[{r.latency_ms}ms]</span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Mandatory Disclaimer */}
                <div className="result-disclaimer">
                  * {r.disclaimer || 'This is a heuristic URL assessment, not a guarantee of site safety.'}
                </div>

                {/* Explainable AI (XAI) Guardrail Rationale */}
                {r.explanation && (
                  <div style={{
                    marginTop: '1rem',
                    marginBottom: '1rem',
                    background: 'rgba(10, 14, 35, 0.85)',
                    borderLeft: `3px solid ${isHigh ? 'var(--crimson)' : isSusp ? 'var(--amber)' : 'var(--lime)'}`,
                    borderTop: '1px solid var(--border-dim)',
                    borderRight: '1px solid var(--border-dim)',
                    borderBottom: '1px solid var(--border-dim)',
                    borderRadius: 'var(--r-md)',
                    padding: '0.85rem 1rem',
                  }}>
                    <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--cyber-cyan)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-mono)' }}>
                      <Zap size={14} />
                      <span>EXPLAINABLE AI // REASONING MATRIX (URL HEURISTICS)</span>
                    </div>
                    <div style={{ fontSize: '0.84rem', lineHeight: '1.55', color: 'var(--text-primary)' }}>
                      {r.explanation}
                    </div>
                  </div>
                )}

                {/* URL Technical Telemetry Card */}
                <div style={{
                  background: 'rgba(7, 9, 24, 0.85)',
                  border: `1px solid ${r.is_suspicious ? 'rgba(255, 23, 68, 0.35)' : 'var(--border-dim)'}`,
                  borderRadius: 'var(--r-md)',
                  padding: '0.9rem 1rem',
                  marginBottom: '1rem'
                }}>
                  <div style={{ fontSize: '0.73rem', fontWeight: 700, color: 'var(--cyber-cyan)', fontFamily: 'var(--font-mono)', letterSpacing: '0.07em', marginBottom: '0.55rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                    <Link2 size={14} />
                    <span>INSPECTED URL TARGET</span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.65rem' }}>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.84rem', wordBreak: 'break-all', color: r.is_suspicious ? '#ff94a2' : 'var(--cyber-cyan)', background: 'rgba(0,0,0,0.3)', padding: '0.35rem 0.6rem', borderRadius: '4px', flex: 1, minWidth: '220px' }}>
                      {r.url}
                    </div>
                    <div style={{ display: 'flex', gap: '0.4rem', flexShrink: 0 }}>
                      <span className={`badge-tag ${r.https ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '0.72rem' }}>
                        {r.https ? 'HTTPS ENCRYPTED' : 'HTTP UNENCRYPTED'}
                      </span>
                      <span className={`badge-tag ${r.is_suspicious ? 'badge-red' : 'badge-green'}`} style={{ fontSize: '0.72rem' }}>
                        {r.is_suspicious ? 'FLAGGED' : 'CLEAN'}
                      </span>
                    </div>
                  </div>

                  {/* Trust notes */}
                  {r.trust_notes?.length > 0 && (
                    <div style={{ marginTop: '0.4rem', display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                      {r.trust_notes.map((tn, i) => (
                        <span key={i} className="badge-tag badge-green" style={{ fontSize: '0.72rem' }}>✓ {tn}</span>
                      ))}
                    </div>
                  )}

                  {/* Flag tags */}
                  {r.flags?.length > 0 && (
                    <div style={{ marginTop: '0.5rem', display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                      {r.flags.map((flag, i) => (
                        <span key={i} className="badge-tag badge-red" style={{ fontSize: '0.72rem' }}>{flag}</span>
                      ))}
                    </div>
                  )}
                </div>

                {/* Detected Threat Indicators */}
                {r.flags && r.flags.length > 0 && (
                  <div style={{ marginBottom: '1rem' }}>
                    <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ff616f', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-display)', letterSpacing: '0.06em' }}>
                      <HelpCircle size={15} />
                      <span>DETECTED THREAT INDICATORS ({r.flags.length})</span>
                    </div>
                    <ul className="evidence-list">
                      {r.flags.map((flag, idx) => (
                        <li key={idx} className="evidence-item">
                          <AlertTriangle className="evidence-icon" size={15} />
                          <span>{flag}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Contextual Tactical Safety Advice */}
                {r.safety_advice && (
                  <div className="safety-box">
                    <div className="safety-box-title">
                      <CheckCircle2 size={16} />
                      <span>TACTICAL DEFENSE PROTOCOL (BEFORE YOU NAVIGATE)</span>
                    </div>
                    {Array.isArray(r.safety_advice) ? (
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginTop: '0.4rem' }}>
                        {r.safety_advice.map((item, idx) => (
                          <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.84rem' }}>
                            <span style={{ color: 'var(--lime-bright)', fontWeight: 'bold' }}>▸</span>
                            <span>{item}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div>{r.safety_advice}</div>
                    )}
                  </div>
                )}

                {/* Web Intelligence Panel — URL Scan */}
                <WebIntelPanel webIntel={r.web_intel} />
              </div>
            );
          })()}

          {/* ════════════════════════════════════════════════════════════════════
              ATTACHMENT SCANNER READOUT
             ════════════════════════════════════════════════════════════════════ */}
          {channel === 'Attachment' && !attachResult && !loading && (
            <div className="empty-state">
              <div className="cyber-radar-scanner">
                <div className="radar-sweep" /><div className="radar-circle" /><div className="radar-circle circle-2" />
                <div className="radar-crosshair-h" /><div className="radar-crosshair-v" /><div className="radar-blip" />
              </div>
              <h3 className="empty-state-heading">ATTACHMENT SCANNER READY</h3>
              <p className="empty-state-desc">
                Drop a file into the left console for isolated static analysis — inspects file headers, entropy, macros, embedded URLs, and binary characteristics without executing any code.
              </p>
              <div className="empty-state-telemetry">
                <span>[STATIC ONLY: ENABLED]</span>
                <span>[NO EXECUTION: ENFORCED]</span>
                <span>[SANDBOXED: READY]</span>
              </div>
            </div>
          )}

          {channel === 'Attachment' && loading && (
            <div className="empty-state">
              <div className="cyber-radar-scanner" style={{ animation: 'spin 3s linear infinite' }}>
                <div className="radar-sweep" /><div className="radar-circle" />
                <div className="radar-crosshair-h" /><div className="radar-crosshair-v" />
              </div>
              <h3 className="empty-state-heading" style={{ color: 'var(--cyber-cyan)' }}>SCANNING FILE PAYLOAD...</h3>
              <p className="empty-state-desc" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                Detecting true file type · Computing entropy · Extracting embedded URLs · Parsing structural blocks
              </p>
            </div>
          )}

          {channel === 'Attachment' && attachResult && !loading && (() => {
            const r = attachResult;
            const isMal = r.verdict === 'MALICIOUS';
            const isSus = r.verdict === 'SUSPICIOUS';
            const vc = isMal ? '#ff616f' : isSus ? '#ffd166' : '#5affbf';
            const vb = isMal ? 'rgba(255,97,111,0.3)' : isSus ? 'rgba(255,209,102,0.3)' : 'rgba(90,255,191,0.18)';

            return (
              <div>
                {/* Verdict Header */}
                <div style={{
                  background: isMal ? 'rgba(255,23,68,0.08)' : isSus ? 'rgba(255,183,3,0.07)' : 'rgba(0,255,157,0.06)',
                  border: `1px solid ${vb}`,
                  borderRadius: 'var(--r-md)',
                  padding: '0.95rem 1.1rem',
                  marginBottom: '1rem',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  flexWrap: 'wrap',
                  gap: '0.65rem'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.7rem' }}>
                    {isMal ? <ShieldAlert size={26} color="#ff616f" /> : isSus ? <AlertTriangle size={26} color="#ffd166" /> : <ShieldCheck size={26} color="#5affbf" />}
                    <div>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }}>STATIC ANALYSIS VERDICT</div>
                      <div style={{ fontSize: '1.05rem', fontWeight: 800, color: vc, fontFamily: 'var(--font-display)', letterSpacing: '0.08em' }}>{r.verdict}</div>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>RISK SEVERITY</div>
                    <div style={{ fontSize: '0.88rem', fontWeight: 700, color: getRiskSeverityColor(r.risk_level), fontFamily: 'var(--font-display)' }}>{r.risk_level || 'N/A'}</div>
                  </div>
                </div>

                {/* File Metadata */}
                <div style={{ background: 'rgba(7,9,24,0.85)', border: '1px solid var(--border-dim)', borderRadius: 'var(--r-md)', padding: '0.7rem 0.9rem', marginBottom: '0.8rem' }}>
                  <div style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--cyber-cyan)', fontFamily: 'var(--font-mono)', letterSpacing: '0.07em', marginBottom: '0.45rem' }}>// FILE METADATA</div>
                  <div className="extracted-details">
                    <div className="extracted-row"><span className="extracted-key">Filename:</span><span className="extracted-val" style={{ fontFamily: 'var(--font-mono)', wordBreak: 'break-all' }}>{r.filename}</span></div>
                    <div className="extracted-row"><span className="extracted-key">Detected Type:</span><span className="extracted-val" style={{ color: 'var(--cyber-cyan)' }}>{r.detected_type || r.file_type || 'Unknown'}</span></div>
                    {r.file_size_bytes != null && <div className="extracted-row"><span className="extracted-key">File Size:</span><span className="extracted-val">{formatBytes(r.file_size_bytes)}</span></div>}
                    {r.entropy != null && <div className="extracted-row"><span className="extracted-key">Entropy:</span><span className="extracted-val" style={{ color: r.entropy > 7 ? '#ff616f' : r.entropy > 6 ? '#ffd166' : '#5affbf' }}>{r.entropy.toFixed(3)}{r.entropy > 7 ? ' ⚠ HIGH (packed?)' : ''}</span></div>}
                    {r.page_count != null && <div className="extracted-row"><span className="extracted-key">Pages:</span><span className="extracted-val">{r.page_count}</span></div>}
                  </div>
                </div>

                {/* Threat Indicators */}
                {r.threat_indicators?.length > 0 && (
                  <div style={{ marginBottom: '0.8rem' }}>
                    <div style={{ fontSize: '0.73rem', fontWeight: 700, color: '#ff616f', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
                      <AlertTriangle size={13} />
                      <span>THREAT INDICATORS ({r.threat_indicators.length})</span>
                    </div>
                    <ul className="evidence-list">{r.threat_indicators.map((ti, i) => <li key={i} className="evidence-item"><AlertTriangle className="evidence-icon" size={13} /><span>{ti}</span></li>)}</ul>
                  </div>
                )}

                {/* Macro / Script Flags */}
                {(r.has_macros || r.suspicious_macros || r.has_scripts || r.has_javascript || r.is_encrypted || r.is_packed) && (
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem', marginBottom: '0.7rem' }}>
                    {r.has_macros && <span className="badge-tag badge-red">⚠ MACRO DETECTED</span>}
                    {r.suspicious_macros && <span className="badge-tag badge-red">🚨 SUSPICIOUS MACRO</span>}
                    {r.has_scripts && <span className="badge-tag badge-yellow">SCRIPT CONTENT</span>}
                    {r.has_javascript && <span className="badge-tag badge-red">EMBEDDED JS</span>}
                    {r.is_encrypted && <span className="badge-tag badge-yellow">ENCRYPTED</span>}
                    {r.is_packed && <span className="badge-tag badge-red">PACKED EXECUTABLE</span>}
                  </div>
                )}

                {/* Extracted URLs */}
                {r.extracted_urls?.length > 0 && (
                  <div style={{ marginBottom: '0.8rem' }}>
                    <div style={{ fontSize: '0.73rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem', fontFamily: 'var(--font-mono)' }}>
                      <Link2 size={13} />
                      <span>EXTRACTED URLS IN FILE ({r.extracted_urls.length})</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.3rem' }}>
                      {r.extracted_urls.slice(0, 8).map((u, i) => (
                        <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.77rem', color: 'var(--cyber-cyan)', background: 'rgba(0,240,255,0.04)', border: '1px solid rgba(0,240,255,0.12)', borderRadius: '4px', padding: '0.28rem 0.55rem', wordBreak: 'break-all', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <span>{u}</span>
                          <button
                            type="button"
                            onClick={() => {
                              setChannel('URL');
                              setUrlInput(u);
                              handleUrlAnalyze(u);
                            }}
                            style={{
                              background: 'none',
                              border: 'none',
                              color: 'var(--lime-bright)',
                              cursor: 'pointer',
                              fontSize: '0.7rem',
                              fontFamily: 'var(--font-mono)',
                              textDecoration: 'underline'
                            }}
                          >
                            Scan Alone →
                          </button>
                        </div>
                      ))}
                      {r.extracted_urls.length > 8 && <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>...and {r.extracted_urls.length - 8} more</div>}
                    </div>
                  </div>
                )}

                {/* Archive contents */}
                {r.archive_contents?.length > 0 && (
                  <div style={{ marginBottom: '0.8rem' }}>
                    <div style={{ fontSize: '0.73rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.4rem', fontFamily: 'var(--font-mono)' }}>// ARCHIVE CONTENTS</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.28rem' }}>
                      {r.archive_contents.slice(0, 10).map((item, i) => (
                        <div key={i} style={{ fontFamily: 'var(--font-mono)', fontSize: '0.76rem', color: 'var(--text-primary)', display: 'flex', justifyContent: 'space-between', gap: '0.5rem' }}>
                          <span style={{ wordBreak: 'break-all' }}>{item.name || item}</span>
                          {item.size != null && <span style={{ color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{formatBytes(item.size)}</span>}
                        </div>
                      ))}
                      {r.archive_contents.length > 10 && <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>...and {r.archive_contents.length - 10} more</div>}
                    </div>
                  </div>
                )}

                {r.summary && (
                  <div style={{ marginTop: '0.5rem', fontSize: '0.83rem', lineHeight: '1.55', color: 'var(--text-secondary)', fontStyle: 'italic', borderTop: '1px solid var(--border-dim)', paddingTop: '0.6rem' }}>
                    {r.summary}
                  </div>
                )}
              </div>
            );
          })()}

          {/* ════════════════════════════════════════════════════════════════════
              MESSAGE SCANNER READOUT (SMS & EMAIL)
             ════════════════════════════════════════════════════════════════════ */}
          {(channel === 'SMS' || channel === 'Email') && !result && !loading && (
            <div className="empty-state">
              <div className="cyber-radar-scanner">
                <div className="radar-sweep" />
                <div className="radar-circle" />
                <div className="radar-circle circle-2" />
                <div className="radar-crosshair-h" />
                <div className="radar-crosshair-v" />
                <div className="radar-blip" />
              </div>
              <h3 className="empty-state-heading">TACTICAL SENSORS ACTIVE</h3>
              <p className="empty-state-desc">
                Awaiting payload ingestion. Enter an Email or SMS message on the left console or select a test vector to compute multi-dimensional social engineering fingerprints, sub-word lexical cues, and URL heuristics.
              </p>
              <div className="empty-state-telemetry">
                <span>[MONITORING: ENABLED]</span>
                <span>[CODE_MIXED: READY]</span>
                <span>[URL_VERIFY: ONLINE]</span>
              </div>
            </div>
          )}

          {(channel === 'SMS' || channel === 'Email') && loading && (
            <div className="empty-state">
              <div className="cyber-radar-scanner" style={{ animation: 'spin 3s linear infinite' }}>
                <div className="radar-sweep" />
                <div className="radar-circle" />
                <div className="radar-crosshair-h" />
                <div className="radar-crosshair-v" />
              </div>
              <h3 className="empty-state-heading" style={{ color: 'var(--cyber-cyan)' }}>
                EXECUTING PIPELINE CLASSIFIER...
              </h3>
              <p className="empty-state-desc" style={{ fontFamily: 'var(--font-mono)', fontSize: '0.78rem' }}>
                Computing TF-IDF lexical vectors · Generating sentence embeddings · Parsing URL patterns · Matching out-of-fold intent models
              </p>
            </div>
          )}

          {(channel === 'SMS' || channel === 'Email') && result && !loading && (
            <div>
              {/* Repeat Check Badge */}
              {result.repeat_check?.check_count > 1 && (
                <div className="repeat-badge">
                  <RefreshCw size={14} />
                  <span>{result.repeat_check.message || `MESSAGE OBSERVED ${result.repeat_check.check_count} TIMES IN SECURITY CACHE.`}</span>
                </div>
              )}

              {/* Result Header Card */}
              <div className={`result-header ${getRiskClass(result.risk)}`}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
                  {getRiskIcon(result.risk)}
                  <div>
                    <div className="result-badge">{result.risk}</div>
                    <div style={{ fontSize: '0.8rem', opacity: 0.9, fontFamily: 'var(--font-mono)' }}>
                      ESTIMATED RISK LEVEL: {result.risk.toUpperCase()}
                    </div>
                  </div>
                </div>

                <div style={{ textAlign: 'right' }}>
                  {typeof result.confidence === 'number' && (
                    <div className="result-confidence">
                      {Math.round(result.confidence * 100)}% CONFIDENCE
                    </div>
                  )}
                  <div style={{ fontSize: '0.7rem', opacity: 0.85, marginTop: '4px', fontFamily: 'var(--font-mono)', display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.5rem' }}>
                    <span>ENGINE: {result.model_used}</span>
                    {typeof result.latency_ms === 'number' && (
                      <span style={{ color: 'var(--cyber-cyan)', fontWeight: 600 }}>[{result.latency_ms}ms]</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Mandatory Disclaimer */}
              <div className="result-disclaimer">
                * {result.disclaimer}
              </div>

              {/* Explainable AI (XAI) Guardrail Rationale */}
              {result.explanation && (
                <div style={{
                  marginTop: '1rem',
                  marginBottom: '1rem',
                  background: 'rgba(10, 14, 35, 0.85)',
                  borderLeft: `3px solid ${result.risk === 'High-risk' ? 'var(--crimson)' : result.risk === 'Suspicious' ? 'var(--amber)' : 'var(--lime)'}`,
                  borderTop: '1px solid var(--border-dim)',
                  borderRight: '1px solid var(--border-dim)',
                  borderBottom: '1px solid var(--border-dim)',
                  borderRadius: 'var(--r-md)',
                  padding: '0.85rem 1rem',
                }}>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--cyber-cyan)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-mono)' }}>
                    <Zap size={14} />
                    <span>EXPLAINABLE AI // REASONING MATRIX (LOCAL XAI)</span>
                  </div>
                  <div style={{ fontSize: '0.84rem', lineHeight: '1.55', color: 'var(--text-primary)' }}>
                    {result.explanation}
                  </div>
                </div>
              )}

              {/* Phishing Intent Fingerprint */}
              <div style={{ marginTop: '1.2rem' }}>
                <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--cyber-cyan)', marginBottom: '0.65rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-display)', letterSpacing: '0.06em' }}>
                  <Fingerprint size={16} />
                  <span>PHISHING INTENT FINGERPRINT [4D SOCIAL-ENGINEERING]</span>
                </div>
                <div className="fingerprint-grid">
                  <div className="fingerprint-cell">
                    <div className="fingerprint-cell-label">Threat Vector</div>
                    <div className="fingerprint-cell-value">{result.fingerprint?.threat || 'None'}</div>
                  </div>
                  <div className="fingerprint-cell">
                    <div className="fingerprint-cell-label">Urgency Indicator</div>
                    <div className="fingerprint-cell-value" style={{ 
                      color: result.fingerprint?.urgency === 'High' ? '#ff616f' : 
                             result.fingerprint?.urgency === 'Medium' ? '#ffd166' : '#5affbf' 
                    }}>
                      {result.fingerprint?.urgency || 'Low'}
                    </div>
                  </div>
                  <div className="fingerprint-cell">
                    <div className="fingerprint-cell-label">Requested Action</div>
                    <div className="fingerprint-cell-value">{result.fingerprint?.requested_action || 'None'}</div>
                  </div>
                  <div className="fingerprint-cell">
                    <div className="fingerprint-cell-label">Credential / Asset Target</div>
                    <div className="fingerprint-cell-value">{result.fingerprint?.credential_payment_request || 'None'}</div>
                  </div>
                </div>
              </div>

              {/* Cognitive Social Engineering Vectors */}
              {result.cues && (
                <div style={{ marginTop: '0.9rem', marginBottom: '0.9rem' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: '0.4rem', letterSpacing: '0.05em' }}>
                    // COGNITIVE SOCIAL ENGINEERING VECTORS
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                    {result.cues.otp_share && (
                      <span className="badge-tag badge-red" style={{ fontWeight: 700 }}>
                        🚨 CRITICAL: OTP / PIN HARVESTING
                      </span>
                    )}
                    {result.cues.credential_request && (
                      <span className="badge-tag badge-red">CREDENTIAL TARGETED</span>
                    )}
                    {result.cues.payment_request && (
                      <span className="badge-tag badge-red">PAYMENT DEMAND</span>
                    )}
                    {result.cues.fear && (
                      <span className="badge-tag badge-yellow">FEAR / PENALTY TACTIC</span>
                    )}
                    {result.cues.authority && (
                      <span className="badge-tag badge-blue">AUTHORITY IMPERSONATION</span>
                    )}
                    {result.cues.pressure && (
                      <span className="badge-tag badge-yellow">PRESSURE / ARTIFICIAL DEADLINE</span>
                    )}
                    {result.cues.reward && (
                      <span className="badge-tag badge-yellow">REWARD / LOTTERY LURE</span>
                    )}
                    {result.cues.detected_action && result.cues.detected_action !== 'None' && (
                      <span className="badge-tag badge-blue">ACTION: {result.cues.detected_action}</span>
                    )}
                  </div>
                </div>
              )}

              {/* Evidence Section */}
              {result.evidence && result.evidence.length > 0 && (
                <div style={{ marginTop: '0.75rem' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: '#ff616f', marginBottom: '0.55rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-display)', letterSpacing: '0.06em' }}>
                    <HelpCircle size={15} />
                    <span>DETECTED THREAT INDICATORS ({result.evidence.length})</span>
                  </div>
                  <ul className="evidence-list">
                    {result.evidence.map((ev, i) => (
                      <li key={i} className="evidence-item">
                        <AlertTriangle className="evidence-icon" size={15} />
                        <span>{ev}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              {/* Contextual Tactical Safety Advice */}
              {result.safety_advice && (
                <div className="safety-box">
                  <div className="safety-box-title">
                    <CheckCircle2 size={16} />
                    <span>TACTICAL DEFENSE PROTOCOL (BEFORE YOU ACT)</span>
                  </div>
                  {Array.isArray(result.safety_advice) ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.45rem', marginTop: '0.4rem' }}>
                      {result.safety_advice.map((item, idx) => (
                        <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem', fontSize: '0.84rem' }}>
                          <span style={{ color: 'var(--lime-bright)', fontWeight: 'bold' }}>▸</span>
                          <span>{item}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div>{result.safety_advice}</div>
                  )}
                </div>
              )}

              {/* URL Analysis with one-click standalone scan bridge */}
              {((result.url_analysis && result.url_analysis.length > 0) || (result.url_checks && result.url_checks.length > 0)) && (
                (() => {
                  const urls = result.url_analysis || result.url_checks;
                  return (
                    <div style={{ marginBottom: '1.25rem' }}>
                      <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.55rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-display)', letterSpacing: '0.06em' }}>
                        <Link2 size={15} />
                        <span>INSPECTED URL TARGETS ({urls.length})</span>
                      </div>
                      {urls.map((uc, i) => (
                        <div key={i} style={{ 
                          background: 'rgba(7, 9, 24, 0.85)', 
                          border: `1px solid ${uc.is_suspicious ? 'rgba(255, 23, 68, 0.45)' : 'var(--border-dim)'}`,
                          borderRadius: 'var(--r-md)', 
                          padding: '0.75rem 0.95rem',
                          marginBottom: '0.55rem'
                        }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.5rem', flexWrap: 'wrap' }}>
                            <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.82rem', wordBreak: 'break-all', color: uc.is_suspicious ? '#ff94a2' : 'var(--cyber-cyan)' }}>
                              {uc.url}
                            </div>
                            <div style={{ display: 'flex', gap: '0.4rem', alignItems: 'center' }}>
                              <span className={`badge-tag ${uc.https ? 'badge-green' : 'badge-red'}`} style={{ fontSize: '0.68rem', padding: '0.1rem 0.4rem' }}>
                                {uc.https ? 'HTTPS SECURE' : 'HTTP INSECURE'}
                              </span>
                              <button
                                type="button"
                                onClick={() => {
                                  setChannel('URL');
                                  setUrlInput(uc.url);
                                  handleUrlAnalyze(uc.url);
                                }}
                                style={{
                                  background: 'rgba(0,240,255,0.1)',
                                  border: '1px solid rgba(0,240,255,0.3)',
                                  color: 'var(--cyber-cyan)',
                                  cursor: 'pointer',
                                  fontSize: '0.68rem',
                                  fontFamily: 'var(--font-mono)',
                                  padding: '0.1rem 0.4rem',
                                  borderRadius: '4px'
                                }}
                              >
                                Scan Alone →
                              </button>
                            </div>
                          </div>
                          {uc.flags && uc.flags.length > 0 && (
                            <div style={{ marginTop: '0.45rem', display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                              {uc.flags.map((f, fi) => (
                                <span key={fi} className="badge-tag badge-red">{f}</span>
                              ))}
                            </div>
                          )}
                          {uc.trust_notes && uc.trust_notes.length > 0 && (
                            <div style={{ marginTop: '0.4rem', display: 'flex', flexWrap: 'wrap', gap: '0.4rem' }}>
                              {uc.trust_notes.map((tn, tni) => (
                                <span key={tni} className="badge-tag badge-green" style={{ fontSize: '0.7rem' }}>✓ {tn}</span>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  );
                })()
              )}

              {/* Sender Analysis */}
              {result.sender_check?.provided && (
                <div style={{ marginBottom: '1.25rem' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.55rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-display)', letterSpacing: '0.06em' }}>
                    <UserCheck size={15} />
                    <span>ORIGINATOR ANALYSIS</span>
                  </div>
                  <div style={{ 
                    background: 'rgba(7, 9, 24, 0.85)', 
                    border: `1px solid ${result.sender_check.is_suspicious ? 'rgba(255, 183, 3, 0.45)' : 'var(--border-dim)'}`,
                    borderRadius: 'var(--r-md)', 
                    padding: '0.75rem 0.95rem'
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem', marginBottom: '0.4rem' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Identifier:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{result.sender_check.sender}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.82rem' }}>
                      <span style={{ color: 'var(--text-muted)' }}>Format Classification:</span>
                      <span className="badge-tag badge-blue">{result.sender_check.format_type}</span>
                    </div>
                    {result.sender_check.indicators?.map((ind, idx) => (
                      <div key={idx} style={{ fontSize: '0.775rem', color: '#ffd166', marginTop: '0.4rem', fontFamily: 'var(--font-mono)' }}>
                        ▸ {ind}
                      </div>
                    ))}
                    <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.5rem', fontStyle: 'italic', fontFamily: 'var(--font-mono)' }}>
                      {result.sender_check.disclaimer}
                    </div>
                  </div>
                </div>
              )}

              {/* Extracted Entities & Privacy Enclave Metrics */}
              {result.entities && (
                <div style={{ marginBottom: '1.25rem' }}>
                  <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.55rem', display: 'flex', alignItems: 'center', gap: '0.45rem', fontFamily: 'var(--font-display)', letterSpacing: '0.06em' }}>
                    <Shield size={15} color="var(--lime)" />
                    <span>EXTRACTED ENTITIES & PRIVACY ENCLAVE</span>
                  </div>

                  {/* Privacy Masking Telemetry */}
                  {result.entities.pii_detected && (
                    <div style={{ 
                      background: 'rgba(0, 255, 157, 0.05)', 
                      border: '1px solid rgba(0, 255, 157, 0.22)', 
                      borderRadius: 'var(--r-md)', 
                      padding: '0.55rem 0.85rem', 
                      marginBottom: '0.65rem',
                      fontSize: '0.78rem',
                      fontFamily: 'var(--font-mono)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      flexWrap: 'wrap',
                      gap: '0.4rem'
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--lime-bright)' }}>
                        <CheckCircle2 size={14} />
                        <span>PRIVACY ENCLAVE: {result.entities.pii_detected.has_pii ? 'PII MASKED BEFORE ML INFERENCE' : 'CLEAN PAYLOAD (NO SENSITIVE PII DETECTED)'}</span>
                      </div>
                      {result.entities.pii_detected.has_pii && (
                        <div style={{ display: 'flex', gap: '0.4rem', color: 'var(--text-muted)' }}>
                          {result.entities.pii_detected.masked_phone_count > 0 && <span>[{result.entities.pii_detected.masked_phone_count} Phone]</span>}
                          {result.entities.pii_detected.masked_email_count > 0 && <span>[{result.entities.pii_detected.masked_email_count} Email]</span>}
                          {result.entities.pii_detected.masked_card_count > 0 && <span>[{result.entities.pii_detected.masked_card_count} Card]</span>}
                          {result.entities.pii_detected.masked_account_count > 0 && <span>[{result.entities.pii_detected.masked_account_count} Acct]</span>}
                          {result.entities.pii_detected.masked_txn_count > 0 && <span>[{result.entities.pii_detected.masked_txn_count} TxnRef]</span>}
                        </div>
                      )}
                    </div>
                  )}

                  {/* Entity Values */}
                  <div style={{ 
                    background: 'rgba(7, 9, 24, 0.85)', 
                    border: '1px solid var(--border-dim)', 
                    borderRadius: 'var(--r-md)', 
                    padding: '0.75rem 0.95rem' 
                  }}>
                    <div className="extracted-details">
                      <div className="extracted-row">
                        <span className="extracted-key">Channel:</span>
                        <span className="extracted-val">{result.channel}</span>
                      </div>

                      {result.entities.banks_financial?.length > 0 && (
                        <div className="extracted-row">
                          <span className="extracted-key">Financial Org / Bank:</span>
                          <span className="extracted-val" style={{ color: 'var(--cyber-cyan)' }}>
                            {result.entities.banks_financial.join(', ')}
                          </span>
                        </div>
                      )}

                      {result.entities.government_bodies?.length > 0 && (
                        <div className="extracted-row">
                          <span className="extracted-key">Government / Regulatory:</span>
                          <span className="extracted-val" style={{ color: '#ffd166' }}>
                            {result.entities.government_bodies.join(', ')}
                          </span>
                        </div>
                      )}

                      {result.entities.organizations?.length > 0 && (
                        <div className="extracted-row">
                          <span className="extracted-key">Organizations / Brands:</span>
                          <span className="extracted-val">{result.entities.organizations.join(', ')}</span>
                        </div>
                      )}

                      {result.entities.monetary_amounts?.length > 0 && (
                        <div className="extracted-row">
                          <span className="extracted-key">Monetary Values:</span>
                          <span className="extracted-val" style={{ color: 'var(--lime-bright)' }}>
                            {result.entities.monetary_amounts.join(', ')}
                          </span>
                        </div>
                      )}

                      {result.entities.dates_deadlines?.length > 0 && (
                        <div className="extracted-row">
                          <span className="extracted-key">Deadlines / Time Horizons:</span>
                          <span className="extracted-val">{result.entities.dates_deadlines.join(', ')}</span>
                        </div>
                      )}

                      {result.entities.phone_numbers?.length > 0 && (
                        <div className="extracted-row">
                          <span className="extracted-key">Telephone / MSISDN:</span>
                          <span className="extracted-val">{result.entities.phone_numbers.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Web Intelligence Panel — SMS/Email Scan */}
              <WebIntelPanel webIntel={result.web_intel} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
