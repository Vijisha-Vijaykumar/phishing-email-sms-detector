import React from 'react';
import { Shield, BarChart3, BookOpen, Lock, AlertTriangle, Terminal, Cpu, Activity, Radio } from 'lucide-react';

export default function Header({ activeTab, setActiveTab }) {
  const tabs = [
    { id: 'detector',    label: 'Detector',    code: '01', icon: Shield },
    { id: 'research',    label: 'Research',    code: '02', icon: BarChart3 },
    { id: 'methodology', label: 'Methodology', code: '03', icon: BookOpen },
    { id: 'privacy',     label: 'Privacy',     code: '04', icon: Lock },
    { id: 'limitations', label: 'Limitations', code: '05', icon: AlertTriangle },
  ];

  return (
    <header className="app-header">
      {/* Top Cyber Telemetry Ribbon */}
      <div className="cyber-hud-ribbon">
        <div className="hud-segment">
          <Terminal size={11} className="hud-icon" />
          <span className="hud-key">SYS_OP:</span>
          <span className="hud-val text-neon-green">NOMINAL</span>
        </div>
        <div className="hud-segment">
          <Cpu size={11} className="hud-icon" />
          <span className="hud-key">INFERENCE_CORE:</span>
          <span className="hud-val text-neon-cyan">MiniLM-L12 + OOF_INTENT</span>
        </div>
        <div className="hud-segment hud-hide-mobile">
          <Activity size={11} className="hud-icon" />
          <span className="hud-key">RUNTIME_LEAK:</span>
          <span className="hud-val text-neon-purple">0.00% (ZERO EXTERNAL LLM)</span>
        </div>
        <div className="hud-segment hud-segment-right">
          <Radio size={11} className="hud-icon hud-pulse" />
          <span className="hud-key">ENCLAVE:</span>
          <span className="hud-val text-neon-green">ACTIVE</span>
        </div>
      </div>

      <div className="app-header-main">
        {/* Brand section */}
        <div className="brand-wrapper">
          <div className="brand-logo-container">
            <div className="brand-logo">
              <Shield size={24} color="#00f0ff" className="brand-shield-icon" />
              <div className="brand-radar-ring" />
            </div>
            <span className="brand-status-dot" />
          </div>

          <div className="brand-meta">
            <div className="brand-title-row">
              <h1 className="brand-title">PhishGuard AI</h1>
              <span className="brand-version-badge">v2.4-CYBER</span>
            </div>
            <div className="brand-subtitle">Explainable Phishing Defense · Email &amp; SMS Intercept</div>
            <div className="brand-prompt">
              <span className="prompt-cursor">▸</span> root@phishguard-sec:~# ./threat-eval --realtime
            </div>
          </div>
        </div>

        {/* Tactical status beacon */}
        <div className="tactical-status-beacon">
          <span className="beacon-ping">
            <span className="beacon-ping-core" />
            <span className="beacon-ping-wave" />
          </span>
          <div className="beacon-text">
            <span className="beacon-primary">OFFLINE SANDBOX</span>
            <span className="beacon-secondary">100% LOCAL PROCESSING</span>
          </div>
        </div>
      </div>

      {/* Futuristic Cockpit Nav Tabs */}
      <nav className="nav-tabs" aria-label="Main Navigation">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              id={`tab-${tab.id}`}
              className={`nav-tab${isActive ? ' active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
              aria-selected={isActive}
            >
              <span className="nav-tab-code">[{tab.code}]</span>
              <Icon size={14} className="nav-tab-icon" />
              <span className="nav-tab-label">{tab.label}</span>
              {isActive && <span className="nav-tab-laser" />}
            </button>
          );
        })}
      </nav>
    </header>
  );
}
