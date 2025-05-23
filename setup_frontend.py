#!/usr/bin/env python3
"""
Script to create the frontend directory and files for the Security Log Analysis Toolkit
"""

import os
from pathlib import Path

def create_frontend():
    """Create the frontend directory and index.html file"""
    
    # Create frontend directory
    frontend_dir = Path("frontend")
    frontend_dir.mkdir(exist_ok=True)
    
    # HTML content for the frontend
    html_content = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Log Analysis Toolkit</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; color: white; margin-bottom: 30px; }
        .header h1 { font-size: 2.5rem; margin-bottom: 10px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .card {
            background: white; border-radius: 15px; padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.1); margin: 20px 0;
        }
        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white; border: none; padding: 12px 25px; border-radius: 8px;
            cursor: pointer; font-size: 1rem; margin: 5px;
        }
        .btn:hover { transform: translateY(-2px); }
        .upload-area {
            border: 3px dashed #cbd5e0; border-radius: 10px; padding: 40px 20px;
            text-align: center; cursor: pointer; background: #f7fafc;
        }
        .upload-area:hover { border-color: #667eea; background: #edf2f7; }
        .alert { padding: 15px; margin: 10px 0; border-radius: 8px; border-left: 4px solid; }
        .alert-success { background: #f0fff4; border-color: #38a169; color: #22543d; }
        .alert-error { background: #fff5f5; border-color: #e53e3e; color: #742a2a; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 5px; font-weight: 600; }
        .form-group input, .form-group select {
            width: 100%; padding: 10px; border: 2px solid #e2e8f0; border-radius: 8px;
        }
        .logs-table {
            width: 100%; border-collapse: collapse; background: white;
            border-radius: 10px; overflow: hidden; margin-top: 15px;
        }
        .logs-table th, .logs-table td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #e2e8f0; }
        .logs-table th { background: #f7fafc; font-weight: 600; color: #4a5568; }
        .status-badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }
        .status-success { background: #c6f6d5; color: #22543d; }
        .status-failed { background: #fed7d7; color: #742a2a; }
        .loading { display: inline-block; width: 20px; height: 20px; border: 3px solid #f3f3f3;
                  border-top: 3px solid #667eea; border-radius: 50%; animation: spin 1s linear infinite; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Log Analysis Toolkit</h1>
            <p>Advanced Authentication Log Analysis & Threat Detection</p>
        </div>

        <!-- Status Display -->
        <div class="card">
            <h3>📊 System Status</h3>
            <div id="statusDisplay">Checking system status...</div>
        </div>

        <!-- File Upload -->
        <div class="card">
            <h3>📁 Upload Log Files</h3>
            <div class="upload-area" id="uploadArea">
                <div style="font-size: 3rem; margin-bottom: 15px;">📤</div>
                <p><strong>Drop your log files here</strong></p>
                <p>or click to browse</p>
                <p style="font-size: 0.9rem; color: #718096; margin-top: 10px;">
                    Supports: Windows Event Logs, Linux auth.log, .zip files
                </p>
                <input type="file" id="fileInput" style="display: none;" multiple accept=".log,.txt,.evtx,.zip">
            </div>
            <div id="uploadStatus"></div>
        </div>

        <!-- Analysis Controls -->
        <div class="card">
            <h3>⚡ Quick Analysis</h3>
            <div class="form-group">
                <label for="analysisType">Analysis Type:</label>
                <select id="analysisType">
                    <option value="suspicious_activity">Suspicious Activity</option>
                    <option value="incident_summary">Executive Summary</option>
                    <option value="technical_analysis">Technical Analysis</option>
                </select>
            </div>
            <div class="form-group">
                <label for="llmApiKey">LLM API Key (Optional):</label>
                <input type="password" id="llmApiKey" placeholder="Enter your OpenAI/Claude API key">
            </div>
            <button class="btn" onclick="runAnalysis()" id="analyzeBtn">🔍 Analyze Selected Logs</button>
            <button class="btn" onclick="generateReport()" id="reportBtn" disabled>📊 Generate Report</button>
        </div>

        <!-- Log Entries -->
        <div class="card">
            <h3>📋 Log Entries</h3>
            <div id="logsContainer">
                <table class="logs-table" id="logsTable">
                    <thead>
                        <tr>
                            <th><input type="checkbox" id="selectAll" onchange="toggleSelectAll()"></th>
                            <th>Timestamp</th>
                            <th>Event Type</th>
                            <th>Username</th>
                            <th>Source IP</th>
                            <th>Result</th>
                        </tr>
                    </thead>
                    <tbody id="logsTableBody">
                        <tr><td colspan="6" style="text-align: center; padding: 40px;">No logs loaded. Upload some files to get started!</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- Analysis Results -->
        <div class="card" id="analysisSection" style="display: none;">
            <h3>🔬 Analysis Results</h3>
            <div id="analysisResults"></div>
        </div>

        <!-- Reports -->
        <div class="card">
            <h3>📄 Reports</h3>
            <div id="reportsList">
                <p style="text-align: center; padding: 20px; color: #718096;">No reports generated yet.</p>
            </div>
        </div>
    </div>

    <script>
        const API_BASE = '/api';  // Use relative URL for Docker setup
        const AUTH_TOKEN = 'demo-token-123';
        let currentLogs = [];
        let selectedLogIds = [];
        let lastAnalysisResults = null;

        const getHeaders = () => ({
            'Authorization': `Bearer ${AUTH_TOKEN}`,
            'Content-Type': 'application/json'
        });

        // Initialize
        document.addEventListener('DOMContentLoaded', function() {
            checkSystemStatus();
            setupFileUpload();
            loadLogs();
            loadReports();
        });

        async function checkSystemStatus() {
            try {
                const response = await fetch('/health');
                const data = await response.json();
                document.getElementById('statusDisplay').innerHTML = `
                    <div class="alert alert-success">
                        ✅ System Status: ${data.api}<br>
                        📊 Storage: ${data.storage_type}<br>
                        🕐 Last Check: ${new Date().toLocaleTimeString()}
                    </div>
                `;
            } catch (error) {
                document.getElementById('statusDisplay').innerHTML = `
                    <div class="alert alert-error">❌ System offline or unreachable</div>
                `;
            }
        }

        function setupFileUpload() {
            const uploadArea = document.getElementById('uploadArea');
            const fileInput = document.getElementById('fileInput');

            uploadArea.addEventListener('click', () => fileInput.click());
            uploadArea.addEventListener('dragover', (e) => {
                e.preventDefault();
                uploadArea.style.borderColor = '#667eea';
            });
            uploadArea.addEventListener('dragleave', (e) => {
                e.preventDefault();
                uploadArea.style.borderColor = '#cbd5e0';
            });
            uploadArea.addEventListener('drop', (e) => {
                e.preventDefault();
                uploadArea.style.borderColor = '#cbd5e0';
                uploadFiles(e.dataTransfer.files);
            });
            fileInput.addEventListener('change', (e) => uploadFiles(e.target.files));
        }

        async function uploadFiles(files) {
            const statusDiv = document.getElementById('uploadStatus');
            statusDiv.innerHTML = '';

            for (let file of files) {
                const formData = new FormData();
                formData.append('file', file);

                try {
                    statusDiv.innerHTML += `<div class="alert alert-warning">
                        <span class="loading"></span> Uploading ${file.name}...
                    </div>`;

                    const response = await fetch(`${API_BASE}/upload-logs`, {
                        method: 'POST',
                        headers: { 'Authorization': `Bearer ${AUTH_TOKEN}` },
                        body: formData
                    });

                    const result = await response.json();

                    if (response.ok) {
                        statusDiv.innerHTML += `<div class="alert alert-success">
                            ✅ ${file.name}: ${result.message}
                        </div>`;
                        loadLogs();
                    } else {
                        statusDiv.innerHTML += `<div class="alert alert-error">
                            ❌ ${file.name}: ${result.detail || 'Upload failed'}
                        </div>`;
                    }
                } catch (error) {
                    statusDiv.innerHTML += `<div class="alert alert-error">
                        ❌ ${file.name}: ${error.message}
                    </div>`;
                }
            }
            document.getElementById('fileInput').value = '';
        }

        async function loadLogs() {
            try {
                const response = await fetch(`${API_BASE}/logs`, { headers: getHeaders() });
                if (response.ok) {
                    const logs = await response.json();
                    currentLogs = logs;
                    updateLogsTable(logs);
                }
            } catch (error) {
                console.error('Error loading logs:', error);
            }
        }

        function updateLogsTable(logs) {
            const tbody = document.getElementById('logsTableBody');
            if (logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 40px;">No logs loaded. Upload some files to get started!</td></tr>';
                return;
            }

            tbody.innerHTML = logs.map(log => `
                <tr>
                    <td><input type="checkbox" value="${log.id}" onchange="updateSelectedLogs()"></td>
                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                    <td>${log.event_type}</td>
                    <td>${log.username}</td>
                    <td>${log.source_ip}</td>
                    <td><span class="status-badge ${log.result.toLowerCase() === 'failed' ? 'status-failed' : 'status-success'}">${log.result}</span></td>
                </tr>
            `).join('');
        }

        function toggleSelectAll() {
            const selectAll = document.getElementById('selectAll');
            const checkboxes = document.querySelectorAll('#logsTableBody input[type="checkbox"]');
            checkboxes.forEach(cb => cb.checked = selectAll.checked);
            updateSelectedLogs();
        }

        function updateSelectedLogs() {
            const checkboxes = document.querySelectorAll('#logsTableBody input[type="checkbox"]:checked');
            selectedLogIds = Array.from(checkboxes).map(cb => parseInt(cb.value));
            document.getElementById('reportBtn').disabled = selectedLogIds.length === 0;
        }

        async function runAnalysis() {
            if (selectedLogIds.length === 0) {
                alert('Please select some log entries to analyze');
                return;
            }

            const analyzeBtn = document.getElementById('analyzeBtn');
            analyzeBtn.innerHTML = '<span class="loading"></span> Analyzing...';
            analyzeBtn.disabled = true;

            try {
                const requestData = {
                    log_entries: selectedLogIds,
                    analysis_type: document.getElementById('analysisType').value,
                    api_key: document.getElementById('llmApiKey').value || null
                };

                const response = await fetch(`${API_BASE}/analyze`, {
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify(requestData)
                });

                const results = await response.json();
                if (response.ok) {
                    lastAnalysisResults = results;
                    displayAnalysisResults(results);
                    document.getElementById('reportBtn').disabled = false;
                } else {
                    throw new Error(results.detail || 'Analysis failed');
                }
            } catch (error) {
                alert(`Analysis failed: ${error.message}`);
            } finally {
                analyzeBtn.innerHTML = '🔍 Analyze Selected Logs';
                analyzeBtn.disabled = false;
            }
        }

        function displayAnalysisResults(results) {
            const section = document.getElementById('analysisSection');
            const resultsDiv = document.getElementById('analysisResults');
            
            let html = '<h4>📊 Analysis Summary</h4>';
            
            if (results.failed_logins) {
                html += `<div class="alert ${results.failed_logins.total_failed > 5 ? 'alert-error' : 'alert-success'}">
                    <strong>Failed Logins:</strong> ${results.failed_logins.total_failed} total attempts<br>
                    <strong>Security Alerts:</strong> ${results.failed_logins.alerts.length} detected
                </div>`;
            }
            
            if (results.time_patterns) {
                html += `<div class="alert ${results.time_patterns.off_hours_count > 0 ? 'alert-error' : 'alert-success'}">
                    <strong>Off-Hours Activity:</strong> ${results.time_patterns.off_hours_count} events detected
                </div>`;
            }
            
            if (results.threat_intelligence) {
                html += '<h4>🔍 Threat Intelligence</h4>';
                Object.entries(results.threat_intelligence).forEach(([ip, intel]) => {
                    const rep = intel.abuseipdb?.reputation || 'unknown';
                    const alertClass = rep === 'malicious' ? 'alert-error' : rep === 'suspicious' ? 'alert-warning' : 'alert-success';
                    html += `<div class="alert ${alertClass}">
                        <strong>IP ${ip}:</strong> ${rep.toUpperCase()} reputation
                    </div>`;
                });
            }
            
            if (results.llm_analysis) {
                html += `<h4>🤖 AI Analysis</h4><div class="alert alert-success">${results.llm_analysis.replace(/\\n/g, '<br>')}</div>`;
            }

            resultsDiv.innerHTML = html;
            section.style.display = 'block';
        }

        async function generateReport() {
            if (!lastAnalysisResults || selectedLogIds.length === 0) {
                alert('Please run analysis first');
                return;
            }

            const reportBtn = document.getElementById('reportBtn');
            reportBtn.innerHTML = '<span class="loading"></span> Generating...';
            reportBtn.disabled = true;

            try {
                const requestData = {
                    analysis_type: document.getElementById('analysisType').value,
                    log_ids: selectedLogIds
                };

                const response = await fetch(`${API_BASE}/generate-report`, {
                    method: 'POST',
                    headers: getHeaders(),
                    body: JSON.stringify(requestData)
                });

                const result = await response.json();
                if (response.ok) {
                    alert('Report generated successfully!');
                    loadReports();
                } else {
                    throw new Error(result.detail || 'Report generation failed');
                }
            } catch (error) {
                alert(`Report generation failed: ${error.message}`);
            } finally {
                reportBtn.innerHTML = '📊 Generate Report';
                reportBtn.disabled = false;
            }
        }

        async function loadReports() {
            try {
                const response = await fetch(`${API_BASE}/reports`, { headers: getHeaders() });
                if (response.ok) {
                    const reports = await response.json();
                    updateReportsList(reports);
                }
            } catch (error) {
                console.error('Error loading reports:', error);
            }
        }

        function updateReportsList(reports) {
            const reportsDiv = document.getElementById('reportsList');
            if (reports.length === 0) {
                reportsDiv.innerHTML = '<p style="text-align: center; padding: 20px; color: #718096;">No reports generated yet.</p>';
                return;
            }

            reportsDiv.innerHTML = reports.map(report => `
                <div class="alert alert-success" style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>${report.title}</strong><br>
                        <small>Type: ${report.report_type} | Created: ${new Date(report.created_at).toLocaleString()}</small>
                    </div>
                    <button class="btn" onclick="viewReport(${report.id})">👁️ View</button>
                </div>
            `).join('');
        }

        async function viewReport(reportId) {
            try {
                const response = await fetch(`${API_BASE}/reports/${reportId}`, { headers: getHeaders() });
                if (response.ok) {
                    const report = await response.json();
                    const newWindow = window.open('', '_blank');
                    newWindow.document.write(`
                        <html>
                            <head><title>${report.title}</title>
                            <style>body { font-family: Arial, sans-serif; padding: 20px; line-height: 1.6; }
                            h1 { color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }
                            pre { background: #f4f4f4; padding: 15px; border-radius: 5px; white-space: pre-wrap; }</style>
                            </head>
                            <body>
                                <h1>${report.title}</h1>
                                <p><strong>Generated:</strong> ${new Date(report.created_at).toLocaleString()}</p>
                                <hr><pre>${report.content}</pre>
                            </body>
                        </html>
                    `);
                } else {
                    alert('Failed to load report');
                }
            } catch (error) {
                alert(`Error loading report: ${error.message}`);
            }
        }

        // Auto-refresh every 30 seconds
        setInterval(() => {
            checkSystemStatus();
            if (currentLogs.length > 0) loadLogs();
        }, 30000);
    </script>
</body>
</html>'''
    
    # Write the HTML file
    index_file = frontend_dir / "index.html"
    with open(index_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"✅ Created frontend files:")
    print(f"   📄 {index_file.absolute()}")
    print(f"\n📋 Next steps:")
    print(f"   1. Make sure Docker containers are running: docker-compose ps")
    print(f"   2. Access the frontend at: http://localhost")
    print(f"   3. API documentation at: http://localhost:8000/docs")

if __name__ == "__main__":
    create_frontend()