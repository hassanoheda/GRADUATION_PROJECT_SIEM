import React, { useState, useEffect } from 'react';

export default function Incidents() {
  const [incidents, setIncidents] = useState([]);
  
  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        const res = await fetch('http://localhost:8000/api/incidents');
        if (res.ok) setIncidents(await res.json());
      } catch (e) {
        console.error("API not reachable");
      }
    };
    
    fetchIncidents();
    const interval = setInterval(fetchIncidents, 5000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityBadge = (level: number) => {
    if (level >= 12) return <span className="badge critical">Critical ({level})</span>;
    if (level >= 8) return <span className="badge warning">High ({level})</span>;
    return <span className="badge info">Medium ({level})</span>;
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2 className="page-title" style={{ marginBottom: 0 }}>Live Incident Feed</h2>
        <button style={{ 
          padding: '0.5rem 1rem', 
          backgroundColor: 'var(--accent-blue)', 
          color: 'white', 
          border: 'none', 
          borderRadius: '0.375rem',
          cursor: 'pointer',
          fontWeight: 500
        }}>
          Export CSV
        </button>
      </div>
      
      <div className="data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Time</th>
              <th>Severity</th>
              <th>Category</th>
              <th>Source IP</th>
              <th>Target</th>
              <th>Action Taken</th>
            </tr>
          </thead>
          <tbody>
            {incidents.length > 0 ? (
              incidents.map((inc: any) => (
                <tr key={inc.id}>
                  <td>{new Date(inc.timestamp).toLocaleString()}</td>
                  <td>{getSeverityBadge(inc.max_severity)}</td>
                  <td>{inc.category}</td>
                  <td style={{ fontFamily: 'monospace' }}>
                    {inc.attacker_ip}
                    {inc.country && <span style={{ marginLeft: '0.5rem', color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{inc.country}</span>}
                  </td>
                  <td>{inc.target_asset}</td>
                  <td>
                    <div style={{ fontSize: '0.875rem', maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {inc.action}
                    </div>
                  </td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan={6} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                  No incidents recorded yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
