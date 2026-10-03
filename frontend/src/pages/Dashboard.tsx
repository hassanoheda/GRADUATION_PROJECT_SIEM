import React, { useState, useEffect } from 'react';
import { 
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip as RechartsTooltip, 
  ResponsiveContainer, BarChart, Bar, Legend
} from 'recharts';

export default function Dashboard() {
  const [metrics, setMetrics] = useState({
    total_alerts: 0, isolated_vectors: 0, active_decoys: 0, ai_status: 'OFFLINE'
  });
  const [history, setHistory] = useState([]);
  
  useEffect(() => {
    // Polling function for metrics
    const fetchMetrics = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/metrics/latest');
        if (res.ok) setMetrics(await res.json());
      } catch (e) {
        console.error("API not reachable");
      }
    };
    
    const fetchHistory = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/metrics/history');
        if (res.ok) setHistory(await res.json());
      } catch (e) {
        console.error("API not reachable");
      }
    };

    fetchMetrics();
    fetchHistory();
    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <h2 className="page-title">Executive Overview</h2>
      
      <div className="grid-cards">
        <div className="metric-card">
          <h3>Total Processed Alerts</h3>
          <div className="value">{metrics.total_alerts}</div>
        </div>
        <div className="metric-card">
          <h3>Isolated Threats</h3>
          <div className="value" style={{ color: 'var(--accent-red)' }}>{metrics.isolated_vectors}</div>
        </div>
        <div className="metric-card">
          <h3>Active Decoys / Honeypots</h3>
          <div className="value" style={{ color: 'var(--accent-green)' }}>{metrics.active_decoys}</div>
        </div>
        <div className="metric-card">
          <h3>AI Analysis Core</h3>
          <div className="value">
            <span className={`badge ${metrics.ai_status === 'ONLINE' ? 'info' : 'warning'}`}>
              {metrics.ai_status}
            </span>
          </div>
        </div>
      </div>

      <div className="charts-grid">
        <div className="chart-panel">
          <h3 style={{ marginBottom: '1.5rem', fontWeight: 600 }}>Threat Detection Trend</h3>
          <div style={{ height: '300px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={history.length > 0 ? history : [{ hour: 'Now', total_alerts: metrics.total_alerts, isolated_vectors: metrics.isolated_vectors }]}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="hour" stroke="var(--text-secondary)" fontSize={12} tickFormatter={(tick) => {
                  if(tick === 'Now') return tick;
                  return new Date(tick).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                }} />
                <YAxis stroke="var(--text-secondary)" fontSize={12} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: 'var(--panel-bg)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                />
                <Legend />
                <Line type="monotone" dataKey="total_alerts" name="Total Alerts" stroke="var(--accent-blue)" strokeWidth={2} dot={false} />
                <Line type="monotone" dataKey="isolated_vectors" name="Isolated" stroke="var(--accent-red)" strokeWidth={2} dot={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>
        
        <div className="chart-panel">
          <h3 style={{ marginBottom: '1.5rem', fontWeight: 600 }}>Active Responses</h3>
          <div style={{ height: '300px' }}>
             <ResponsiveContainer width="100%" height="100%">
              <BarChart data={history.length > 0 ? history.slice(-5) : [{ hour: 'Now', active_decoys: metrics.active_decoys }]}>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border-color)" />
                <XAxis dataKey="hour" stroke="var(--text-secondary)" fontSize={12} tickFormatter={(tick) => {
                  if(tick === 'Now') return tick;
                  return new Date(tick).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                }} />
                <YAxis stroke="var(--text-secondary)" fontSize={12} />
                <RechartsTooltip 
                  contentStyle={{ backgroundColor: 'var(--panel-bg)', borderColor: 'var(--border-color)', color: 'var(--text-primary)' }}
                />
                <Bar dataKey="active_decoys" name="Active Decoys" fill="var(--accent-green)" radius={[4,4,0,0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
}
