import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import {
  LayoutDashboard, ShieldAlert, Activity, Shield,
  Search, Sun, Moon, Bell, Menu, ActivitySquare, Server, Lock
} from 'lucide-react';

import Dashboard from './pages/Dashboard';
import Incidents from './pages/Incidents';

function Sidebar() {
  const location = useLocation();
  const navItems = [
    { path: '/', label: 'Executive Overview', icon: LayoutDashboard },
    { path: '/incidents', label: 'Live Incidents', icon: ShieldAlert },
    { path: '/threats', label: 'Threat Intelligence', icon: Activity },
    { path: '/response', label: 'Active Response', icon: Shield },
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <h1><ActivitySquare size={24} /> AI SOC Engine</h1>
      </div>
      <div className="nav-links">
        {navItems.map((item) => {
          const Icon = item.icon;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={`nav-item ${location.pathname === item.path ? 'active' : ''}`}
            >
              <Icon size={20} />
              {item.label}
            </Link>
          );
        })}
      </div>
    </div>
  );
}

function Topbar({ toggleTheme, isDark }: { toggleTheme: () => void, isDark: boolean }) {
  return (
    <div className="header">
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <button className="theme-toggle" style={{ display: 'none' }}><Menu size={20} /></button>
        <div style={{ position: 'relative' }}>
          <Search size={18} style={{ position: 'absolute', left: '0.75rem', top: '50%', transform: 'translateY(-50%)', color: 'var(--text-secondary)' }} />
          <input
            type="text"
            placeholder="Search alerts, IPs..."
            style={{
              padding: '0.5rem 1rem 0.5rem 2.5rem',
              borderRadius: '9999px',
              border: '1px solid var(--border-color)',
              backgroundColor: 'var(--bg-color)',
              color: 'var(--text-primary)',
              width: '300px'
            }}
          />
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
        <button className="theme-toggle" onClick={toggleTheme}>
          {isDark ? <Sun size={20} /> : <Moon size={20} />}
        </button>
        <button className="theme-toggle">
          <Bell size={20} />
        </button>
        <div style={{ width: '32px', height: '32px', borderRadius: '50%', backgroundColor: 'var(--accent-blue)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', fontWeight: 'bold' }}>
          A
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [isDark, setIsDark] = useState(true);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
  }, [isDark]);

  const toggleTheme = () => setIsDark(!isDark);

  return (
    <Router>
      <div className="dashboard-container">
        <Sidebar />
        <div className="main-content">
          <Topbar toggleTheme={toggleTheme} isDark={isDark} />
          <div className="page-content">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/incidents" element={<Incidents />} />
              <Route path="*" element={<div><h2>Coming Soon</h2><p>This module is currently under development.</p></div>} />
            </Routes>
          </div>
        </div>
      </div>
    </Router>
  );
}
