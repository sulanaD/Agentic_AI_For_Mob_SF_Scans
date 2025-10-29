import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

// Types for our API responses
interface ScanResponse {
  scan_id: string;
  status: string;
  message: string;
}

interface ScanStatus {
  scan_id: string;
  status: string;
  progress?: number;
  message?: string;
  results?: any;
  error?: string;
  filename?: string;
  app_name?: string;
}

interface HealthResponse {
  status: string;
  components: Record<string, string>;
  version: string;
}

interface ConfigResponse {
  api_version: string;
  supported_formats: string[];
  max_file_size: string;
  features: {
    mobsf_scanning: boolean;
    ai_analysis: boolean;
    report_generation: boolean;
  };
}

const API_BASE_URL = 'http://localhost:8081';

function App() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [appName, setAppName] = useState<string>('');
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [scans, setScans] = useState<ScanStatus[]>([]);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [activeTab, setActiveTab] = useState<'upload' | 'scans' | 'status'>('upload');

  // Fetch health and config on component mount
  useEffect(() => {
    fetchHealth();
    fetchConfig();
    fetchScans();
  }, []);

  // Poll for scan updates every 5 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      if (scans.length > 0) {
        fetchScans();
      }
    }, 5000);

    return () => clearInterval(interval);
  }, [scans.length]);

  const fetchHealth = async () => {
    try {
      const response = await axios.get<HealthResponse>(`${API_BASE_URL}/health`);
      setHealth(response.data);
    } catch (error) {
      console.error('Error fetching health:', error);
    }
  };

  const fetchConfig = async () => {
    try {
      const response = await axios.get<ConfigResponse>(`${API_BASE_URL}/config`);
      setConfig(response.data);
    } catch (error) {
      console.error('Error fetching config:', error);
    }
  };

  const fetchScans = async () => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scans`);
      setScans(response.data.scans || []);
    } catch (error) {
      console.error('Error fetching scans:', error);
    }
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      if (!appName) {
        setAppName(file.name.replace(/\.[^/.]+$/, "")); // Remove extension
      }
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      alert('Please select a file first');
      return;
    }

    setIsUploading(true);
    
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);
      if (appName) {
        formData.append('app_name', appName);
      }

      const response = await axios.post<ScanResponse>(`${API_BASE_URL}/scan`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      alert(`Scan initiated successfully! Scan ID: ${response.data.scan_id}`);
      
      // Reset form
      setSelectedFile(null);
      setAppName('');
      
      // Refresh scans list
      setTimeout(fetchScans, 1000);
      
      // Switch to scans tab
      setActiveTab('scans');
      
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Error uploading file. Please check your backend connection.');
    } finally {
      setIsUploading(false);
    }
  };

  const viewScanResults = async (scanId: string) => {
    try {
      const response = await axios.get(`${API_BASE_URL}/scan/${scanId}/results`);
      
      // Open results in a new window or modal
      const resultsWindow = window.open('', '_blank');
      if (resultsWindow) {
        resultsWindow.document.write(`
          <html>
            <head><title>Scan Results - ${scanId}</title></head>
            <body>
              <h1>Scan Results</h1>
              <pre>${JSON.stringify(response.data, null, 2)}</pre>
            </body>
          </html>
        `);
      }
    } catch (error) {
      console.error('Error fetching scan results:', error);
      alert('Error fetching scan results');
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#28a745';
      case 'processing': return '#ffc107';
      case 'failed': return '#dc3545';
      case 'initiated': return '#17a2b8';
      default: return '#6c757d';
    }
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>🔒 Mobile Security Analysis</h1>
        <p>Upload APK/IPA files for comprehensive security scanning</p>
      </header>

      <div className="container">
        {/* Status Bar */}
        <div className="status-bar">
          <div className="status-item">
            <span className="status-label">Backend:</span>
            <span 
              className={`status-value ${health?.status === 'healthy' ? 'healthy' : 'unhealthy'}`}
            >
              {health?.status || 'Unknown'} {health?.status === 'healthy' ? '✅' : '❌'}
            </span>
          </div>
          <div className="status-item">
            <span className="status-label">Version:</span>
            <span className="status-value">{config?.api_version || 'Unknown'}</span>
          </div>
          <div className="status-item">
            <span className="status-label">Active Scans:</span>
            <span className="status-value">{scans.length}</span>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="nav-tabs">
          <button 
            className={`tab ${activeTab === 'upload' ? 'active' : ''}`}
            onClick={() => setActiveTab('upload')}
          >
            📁 Upload File
          </button>
          <button 
            className={`tab ${activeTab === 'scans' ? 'active' : ''}`}
            onClick={() => setActiveTab('scans')}
          >
            📊 Scans ({scans.length})
          </button>
          <button 
            className={`tab ${activeTab === 'status' ? 'active' : ''}`}
            onClick={() => setActiveTab('status')}
          >
            ⚙️ System Status
          </button>
        </div>

        {/* Tab Content */}
        <div className="tab-content">
          {activeTab === 'upload' && (
            <div className="upload-section">
              <h2>📱 Upload Mobile App</h2>
              
              <div className="upload-form">
                <div className="form-group">
                  <label htmlFor="file-input">Select APK or IPA file:</label>
                  <input
                    id="file-input"
                    type="file"
                    accept=".apk,.ipa"
                    onChange={handleFileChange}
                    disabled={isUploading}
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="app-name">App Name (optional):</label>
                  <input
                    id="app-name"
                    type="text"
                    value={appName}
                    onChange={(e) => setAppName(e.target.value)}
                    placeholder="Enter app name..."
                    disabled={isUploading}
                  />
                </div>

                <div className="file-info">
                  {selectedFile && (
                    <div>
                      <p><strong>Selected file:</strong> {selectedFile.name}</p>
                      <p><strong>Size:</strong> {(selectedFile.size / 1024 / 1024).toFixed(2)} MB</p>
                    </div>
                  )}
                </div>

                <button 
                  className="upload-btn"
                  onClick={handleUpload}
                  disabled={!selectedFile || isUploading}
                >
                  {isUploading ? '⏳ Uploading...' : '🚀 Start Scan'}
                </button>
              </div>

              <div className="supported-formats">
                <h3>Supported Formats:</h3>
                <p>{config?.supported_formats.join(', ') || 'APK, IPA'}</p>
                <p><strong>Max file size:</strong> {config?.max_file_size || '100MB'}</p>
              </div>
            </div>
          )}

          {activeTab === 'scans' && (
            <div className="scans-section">
              <h2>📊 Scan History</h2>
              
              <button className="refresh-btn" onClick={fetchScans}>
                🔄 Refresh
              </button>

              <div className="scans-list">
                {scans.length === 0 ? (
                  <p className="no-scans">No scans yet. Upload a file to get started!</p>
                ) : (
                  scans.map((scan) => (
                    <div key={scan.scan_id} className="scan-item">
                      <div className="scan-header">
                        <h3>{scan.app_name || scan.filename}</h3>
                        <span 
                          className="scan-status"
                          style={{ backgroundColor: getStatusColor(scan.status) }}
                        >
                          {scan.status.toUpperCase()}
                        </span>
                      </div>
                      
                      <div className="scan-details">
                        <p><strong>Scan ID:</strong> {scan.scan_id}</p>
                        <p><strong>Message:</strong> {scan.message}</p>
                        {scan.progress !== undefined && (
                          <div className="progress-bar">
                            <div 
                              className="progress-fill"
                              style={{ width: `${scan.progress}%` }}
                            ></div>
                            <span className="progress-text">{scan.progress}%</span>
                          </div>
                        )}
                      </div>

                      {scan.status === 'completed' && (
                        <button 
                          className="view-results-btn"
                          onClick={() => viewScanResults(scan.scan_id)}
                        >
                          📋 View Results
                        </button>
                      )}

                      {scan.error && (
                        <div className="error-message">
                          <strong>Error:</strong> {scan.error}
                        </div>
                      )}
                    </div>
                  ))
                )}
              </div>
            </div>
          )}

          {activeTab === 'status' && (
            <div className="status-section">
              <h2>⚙️ System Status</h2>
              
              <div className="status-cards">
                <div className="status-card">
                  <h3>🔧 Backend Health</h3>
                  {health ? (
                    <div>
                      <p><strong>Overall Status:</strong> 
                        <span className={health.status === 'healthy' ? 'healthy' : 'unhealthy'}>
                          {health.status}
                        </span>
                      </p>
                      <div className="components">
                        <h4>Components:</h4>
                        {Object.entries(health.components).map(([component, status]) => (
                          <div key={component} className="component-status">
                            <span className="component-name">{component}:</span>
                            <span className={`component-value ${status === 'healthy' ? 'healthy' : 'unhealthy'}`}>
                              {status}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <p>Loading health status...</p>
                  )}
                </div>

                <div className="status-card">
                  <h3>⚡ Configuration</h3>
                  {config ? (
                    <div>
                      <p><strong>API Version:</strong> {config.api_version}</p>
                      <p><strong>Supported Formats:</strong> {config.supported_formats.join(', ')}</p>
                      <p><strong>Max File Size:</strong> {config.max_file_size}</p>
                      
                      <div className="features">
                        <h4>Features:</h4>
                        <div className="feature-list">
                          <div className="feature-item">
                            <span>MobSF Scanning:</span>
                            <span className={config.features.mobsf_scanning ? 'enabled' : 'disabled'}>
                              {config.features.mobsf_scanning ? '✅' : '❌'}
                            </span>
                          </div>
                          <div className="feature-item">
                            <span>AI Analysis:</span>
                            <span className={config.features.ai_analysis ? 'enabled' : 'disabled'}>
                              {config.features.ai_analysis ? '✅' : '❌'}
                            </span>
                          </div>
                          <div className="feature-item">
                            <span>Report Generation:</span>
                            <span className={config.features.report_generation ? 'enabled' : 'disabled'}>
                              {config.features.report_generation ? '✅' : '❌'}
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>
                  ) : (
                    <p>Loading configuration...</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
