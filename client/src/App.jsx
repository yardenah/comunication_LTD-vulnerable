import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Login from './pages/Login';
import Register from './pages/Register';
import Dashboard from './pages/Dashboard';
import ChangePassword from './pages/ChangePassword';
import ForgotPassword from './pages/ForgotPassword';
import './App.css';

function App() {
  const [apiStatus, setApiStatus] = useState('Checking...');

  useEffect(() => {
    // Test API connection
    fetch('/api/clients')
      .then(response => {
        if (response.ok) {
          setApiStatus('Connected to Backend ✅');
        } else {
          setApiStatus('Backend Error ❌');
        }
      })
      .catch(error => {
        setApiStatus('Cannot connect to Backend ❌');
        console.error('API connection error:', error);
      });
  }, []);

  return (
    <Router>
      <div className="App">
        <div style={{ 
          position: 'fixed', 
          top: '10px', 
          right: '10px', 
          background: '#f0f0f0', 
          padding: '8px 12px', 
          borderRadius: '4px', 
          fontSize: '12px',
          zIndex: 1000
        }}>
          {apiStatus}
        </div>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/register" element={<Register />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/change-password" element={<ChangePassword />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/" element={<Navigate to="/login" />} />
        </Routes>
      </div>
    </Router>
  );
}

export default App;
