import React, { useState, useEffect } from 'react';
import axios from 'axios';
import './App.css';

// Types for our API responses
interface ScanResponse {
  scan_id: string;
  status: string;
  message: string;
}

interface VulnerabilityPriority {
  severity: string;
  priority_score: number;
  confidence: number;
  reasoning: string;
  category: string;
  exploitability: string;
  business_impact: string;
}

interface TechnicalDetails {
  title: string;
  description: string;
  severity: string;
  section: string;
  type: string;
}

interface AIAnalysis {
  vulnerability_id: string;
  title: string;
  description: string;
  priority: VulnerabilityPriority;
  impact_assessment: string;
  remediation_steps: string[];
  references: string[];
  cwe_mapping: string | null;
  owasp_mapping: string | null;
  technical_details: TechnicalDetails;
}

interface ScanResults {
  scan_id: string;
  status: string;
  progress?: number;
  message?: string;
  filename?: string;
  app_name?: string;
  data?: any;
  ai_analysis?: AIAnalysis[];
  security_score?: number;
  file_hash?: string;
  scan_timestamp?: string;
  error?: string;
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
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [currentScan, setCurrentScan] = useState<ScanResults | null>(null);
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [scanProgress, setScanProgress] = useState<number>(0);
  const [scanStatus, setScanStatus] = useState<string>('');

  // Fetch health and config on component mount
  useEffect(() => {
    fetchHealth();
    fetchConfig();
  }, []);

  // Poll scan status when scanning
  useEffect(() => {
    let interval: NodeJS.Timeout;
    
    if (isScanning && currentScan?.scan_id) {
      interval = setInterval(async () => {
        try {
          const statusResponse = await axios.get(`${API_BASE_URL}/scan/${currentScan.scan_id}/status`);
          const status = statusResponse.data;
          
          setScanStatus(status.status || 'scanning');
          
          if (status.progress !== undefined) {
            setScanProgress(status.progress);
          }
          
          // Check if scan is complete
          if (status.status === 'completed') {
            // Fetch full results
            const resultsResponse = await axios.get(`${API_BASE_URL}/scan/${currentScan.scan_id}/results`);
            setCurrentScan(resultsResponse.data);
            setIsScanning(false);
            setScanProgress(100);
            setScanStatus('completed');
          } else if (status.status === 'failed' || status.status === 'error') {
            setCurrentScan(prev => prev ? { ...prev, error: status.message || 'Scan failed' } : null);
            setIsScanning(false);
            setScanStatus('failed');
          }
        } catch (error) {
          console.error('Error fetching scan status:', error);
        }
      }, 2000); // Poll every 2 seconds
    }

    return () => {
      if (interval) clearInterval(interval);
    };
  }, [isScanning, currentScan?.scan_id]);

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

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      if (!appName) {
        setAppName(file.name.replace(/\.[^/.]+$/, "")); // Remove extension
      }
    }
  };

  const handleStartNewScan = () => {
    setCurrentScan(null);
    setSelectedFile(null);
    setAppName('');
    setIsScanning(false);
    setScanProgress(0);
    setScanStatus('');
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      alert('Please select a file first');
      return;
    }

    setIsScanning(true);
    setScanProgress(0);
    setScanStatus('uploading');
    
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

      // Set initial scan data
      setCurrentScan({
        scan_id: response.data.scan_id,
        status: response.data.status,
        message: response.data.message,
        filename: selectedFile.name,
        app_name: appName || selectedFile.name.replace(/\.[^/.]+$/, "")
      });
      
      setScanProgress(10);
      setScanStatus('scanning');
      
    } catch (error) {
      console.error('Error uploading file:', error);
      alert('Error uploading file. Please check your backend connection.');
      setIsScanning(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': case 'critical': return '#dc3545';
      case 'medium': return '#ffc107';
      case 'low': return '#28a745';
      default: return '#6c757d';
    }
  };

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'high': case 'critical': return '🔴';
      case 'medium': return '🟡';
      case 'low': return '🟢';
      default: return '⚪';
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return '#28a745';
      case 'failed': case 'error': return '#dc3545';
      case 'scanning': case 'in_progress': return '#007bff';
      default: return '#6c757d';
    }
  };

  return (
    <div className="App">
      <div className="container">
        <header className="header">
          <h1>🛡️ Mobile Security Analyzer</h1>
          <p>AI-Powered Security Analysis for Mobile Applications</p>
          
          {/* Health Status */}
          <div className="status-bar">
            <div className="status-item">
              <span>Backend:</span>
              <span className={health?.status === 'healthy' ? 'status-healthy' : 'status-error'}>
                {health?.status === 'healthy' ? '✅ Online' : '❌ Offline'}
              </span>
            </div>
            {config && (
              <>
                <div className="status-item">
                  <span>MobSF:</span>
                  <span className={config.features.mobsf_scanning ? 'status-healthy' : 'status-error'}>
                    {config.features.mobsf_scanning ? '✅ Ready' : '❌ Unavailable'}
                  </span>
                </div>
                <div className="status-item">
                  <span>AI Analysis:</span>
                  <span className={config.features.ai_analysis ? 'status-healthy' : 'status-error'}>
                    {config.features.ai_analysis ? '✅ Ready' : '❌ Unavailable'}
                  </span>
                </div>
              </>
            )}
          </div>
        </header>

        <main className="main-content">
          {/* Upload Section or New Scan Button */}
          {!currentScan ? (
            <div className="upload-section">
              <div className="upload-card">
                <h2>📱 Upload Mobile App</h2>
                
                <div className="form-group">
                  <label htmlFor="file-input">Select APK or IPA file:</label>
                  <input
                    id="file-input"
                    type="file"
                    accept=".apk,.ipa"
                    onChange={handleFileChange}
                    disabled={isScanning}
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
                    disabled={isScanning}
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
                  disabled={!selectedFile || isScanning}
                >
                  {isScanning ? '⏳ Starting Scan...' : '🚀 Start Security Analysis'}
                </button>

                <div className="supported-formats">
                  <h3>Supported Formats:</h3>
                  <p>{config?.supported_formats.join(', ') || 'APK, IPA'}</p>
                  <p><strong>Max file size:</strong> {config?.max_file_size || '100MB'}</p>
                </div>
              </div>
            </div>
          ) : (
            <div className="results-section">
              {/* Scan Status */}
              <div className="scan-status-card">
                <div className="scan-header">
                  <h2>🔍 Security Analysis</h2>
                  <button className="new-scan-btn" onClick={handleStartNewScan}>
                    📱 New Scan
                  </button>
                </div>
                
                <div className="app-info">
                  <h3>{currentScan.app_name || currentScan.filename}</h3>
                  <p><strong>Scan ID:</strong> {currentScan.scan_id}</p>
                  {currentScan.file_hash && (
                    <p><strong>File Hash:</strong> {currentScan.file_hash}</p>
                  )}
                </div>

                {/* Progress Bar */}
                <div className="progress-section">
                  <div className="progress-header">
                    <span className="progress-label">
                      Status: <span 
                        className="status-badge"
                        style={{ backgroundColor: getStatusColor(scanStatus) }}
                      >
                        {scanStatus.replace('_', ' ').toUpperCase()}
                      </span>
                    </span>
                    <span className="progress-percentage">{scanProgress}%</span>
                  </div>
                  <div className="progress-bar">
                    <div 
                      className="progress-fill"
                      style={{ width: `${scanProgress}%` }}
                    ></div>
                  </div>
                  {isScanning && (
                    <p className="progress-message">
                      {scanProgress < 20 ? '📤 Uploading file...' :
                       scanProgress < 50 ? '🔍 Analyzing with MobSF...' :
                       scanProgress < 80 ? '🤖 Running AI analysis...' :
                       scanProgress < 100 ? '📊 Generating report...' :
                       '✅ Analysis complete!'}
                    </p>
                  )}
                </div>

                {/* Error Display */}
                {currentScan.error && (
                  <div className="error-card">
                    <h3>❌ Error</h3>
                    <p>{currentScan.error}</p>
                  </div>
                )}
              </div>

              {/* Security Score */}
              {currentScan.data?.security_score !== undefined && (
                <div className="security-score-card">
                  <h3>🛡️ Security Score</h3>
                  <div className="score-display">
                    <span className="score-number">{currentScan.data.security_score}</span>
                    <span className="score-total">/100</span>
                  </div>
                  <div className="score-bar">
                    <div 
                      className="score-fill"
                      style={{ 
                        width: `${currentScan.data.security_score}%`,
                        backgroundColor: currentScan.data.security_score > 70 ? '#28a745' : 
                                       currentScan.data.security_score > 40 ? '#ffc107' : '#dc3545'
                      }}
                    ></div>
                  </div>
                  <p className="score-description">
                    {currentScan.data.security_score > 70 ? 'Good security posture' :
                     currentScan.data.security_score > 40 ? 'Moderate security concerns' :
                     'Significant security risks detected'}
                  </p>
                </div>
              )}

              {/* AI Analysis Results */}
              {currentScan.ai_analysis && currentScan.ai_analysis.length > 0 && (
                <div className="ai-analysis-card">
                  <h3>🤖 AI Security Analysis</h3>
                  <p className="analysis-intro">
                    Our AI has analyzed <strong>{currentScan.ai_analysis.length}</strong> security vulnerabilities 
                    and provided detailed assessments and remediation steps.
                  </p>
                  
                  <div className="vulnerabilities-grid">
                    {currentScan.ai_analysis.map((vulnerability: AIAnalysis, index: number) => (
                      <div key={index} className="vulnerability-card">
                        <div className="vulnerability-header">
                          <div className="vulnerability-title">
                            <span className="severity-icon">
                              {getSeverityIcon(vulnerability.priority.severity)}
                            </span>
                            <h4>{vulnerability.title}</h4>
                            <span 
                              className="severity-badge"
                              style={{ backgroundColor: getSeverityColor(vulnerability.priority.severity) }}
                            >
                              {vulnerability.priority.severity.toUpperCase()}
                            </span>
                          </div>
                        </div>

                        <div className="vulnerability-content">
                          <div className="vulnerability-description">
                            <h5>📋 Description</h5>
                            <p>{vulnerability.description}</p>
                          </div>

                          <div className="vulnerability-metrics">
                            <div className="metric">
                              <span className="metric-label">Priority Score:</span>
                              <span className="metric-value">
                                {(vulnerability.priority.priority_score * 100).toFixed(0)}%
                              </span>
                            </div>
                            <div className="metric">
                              <span className="metric-label">Category:</span>
                              <span className="metric-value">{vulnerability.priority.category}</span>
                            </div>
                            <div className="metric">
                              <span className="metric-label">Exploitability:</span>
                              <span className="metric-value">{vulnerability.priority.exploitability}</span>
                            </div>
                          </div>

                          <div className="remediation-section">
                            <h5>🛠️ Remediation Steps</h5>
                            {vulnerability.remediation_steps && vulnerability.remediation_steps.length > 0 ? (
                              <ol className="remediation-list">
                                {vulnerability.remediation_steps.map((step: string, stepIndex: number) => (
                                  <li key={stepIndex}>{step}</li>
                                ))}
                              </ol>
                            ) : (
                              <p className="no-remediation">Manual security review required</p>
                            )}
                          </div>

                          <div className="impact-assessment">
                            <h5>📊 Impact Assessment</h5>
                            <p>{vulnerability.impact_assessment}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* No AI Analysis Message */}
              {!isScanning && (!currentScan.ai_analysis || currentScan.ai_analysis.length === 0) && (
                <div className="no-ai-analysis-card">
                  <h3>🤖 AI Analysis</h3>
                  <p>AI analysis is not available for this scan. This could be due to:</p>
                  <ul>
                    <li>Scan still in progress</li>
                    <li>AI service temporarily unavailable</li>
                    <li>No vulnerabilities detected for AI analysis</li>
                  </ul>
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;