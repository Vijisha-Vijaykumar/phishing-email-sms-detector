import { useState } from 'react';
import './index.css';

import Header from './components/Header';
import DetectorTab from './components/DetectorTab';
import ResearchTab from './components/ResearchTab';
import MethodologyTab from './components/MethodologyTab';
import PrivacyTab from './components/PrivacyTab';
import LimitationsTab from './components/LimitationsTab';

function App() {
  const [activeTab, setActiveTab] = useState('detector');

  const renderTab = () => {
    switch (activeTab) {
      case 'detector':    return <DetectorTab />;
      case 'research':    return <ResearchTab />;
      case 'methodology': return <MethodologyTab />;
      case 'privacy':     return <PrivacyTab />;
      case 'limitations': return <LimitationsTab />;
      default:            return <DetectorTab />;
    }
  };

  return (
    <div className="cyber-universe">
      {/* Background Cyber Atmosphere */}
      <div className="cyber-grid-perspective" aria-hidden="true" />
      <div className="cyber-laser-scanner" aria-hidden="true" />
      <div className="cyber-ambient-glow glow-cyan" aria-hidden="true" />
      <div className="cyber-ambient-glow glow-violet" aria-hidden="true" />
      <div className="cyber-ambient-glow glow-magenta" aria-hidden="true" />
      <div className="cyber-scanlines-fx" aria-hidden="true" />

      {/* Decorative Cyber Viewport Crosshairs */}
      <div className="cyber-view-corner corner-tl" aria-hidden="true">+</div>
      <div className="cyber-view-corner corner-tr" aria-hidden="true">+</div>
      <div className="cyber-view-corner corner-bl" aria-hidden="true">+</div>
      <div className="cyber-view-corner corner-br" aria-hidden="true">+</div>

      <div className="app-container">
        <Header activeTab={activeTab} setActiveTab={setActiveTab} />
        <main className="tab-viewport">{renderTab()}</main>

        <footer className="cyber-footer">
          <div className="cyber-footer-container">
            <div className="cyber-footer-section">
              <span className="cyber-bracket">[</span>
              <span className="cyber-footer-tag">SYS_STATUS</span>
              <span className="cyber-footer-val text-neon-green">ACTIVE_SHIELD_ONLINE</span>
              <span className="cyber-bracket">]</span>
            </div>
            <div className="cyber-footer-section">
              <span className="cyber-bracket">[</span>
              <span className="cyber-footer-tag">ARCHITECTURE</span>
              <span className="cyber-footer-val">INTENT FINGERPRINTING + MINI_LM EMBEDDINGS</span>
              <span className="cyber-bracket">]</span>
            </div>
            <div className="cyber-footer-section hud-hide-mobile">
              <span className="cyber-bracket">[</span>
              <span className="cyber-footer-tag">PRIVACY_ENGINE</span>
              <span className="cyber-footer-val text-neon-cyan">ZERO CLOUD LLM TRANSMISSION</span>
              <span className="cyber-bracket">]</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}

export default App;
