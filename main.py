from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from datetime import datetime, timedelta
import json
import re
import hashlib
import asyncio
import aiohttp
from typing import List, Dict, Optional
import uvicorn
from pydantic import BaseModel
import io
import zipfile

# Database setup
SQLALCHEMY_DATABASE_URL = "postgresql://user:password@localhost/securitytoolkit"
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class LogEntry(Base):
    __tablename__ = "log_entries"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, index=True)
    timestamp = Column(DateTime)
    event_type = Column(String)
    source_ip = Column(String)
    username = Column(String)
    result = Column(String)
    details = Column(Text)
    risk_level = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

class ThreatIntel(Base):
    __tablename__ = "threat_intel"
    
    id = Column(Integer, primary_key=True)
    ip_address = Column(String, unique=True)
    reputation = Column(String)
    last_checked = Column(DateTime)
    details = Column(Text)

class AnalysisReport(Base):
    __tablename__ = "analysis_reports"
    
    id = Column(Integer, primary_key=True)
    user_id = Column(String)
    report_type = Column(String)
    title = Column(String)
    content = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Pydantic models
class LogEntryCreate(BaseModel):
    timestamp: datetime
    event_type: str
    source_ip: str
    username: str
    result: str
    details: str

class AnalysisRequest(BaseModel):
    log_entries: List[int]
    analysis_type: str
    llm_provider: Optional[str] = "openai"
    api_key: Optional[str] = None

class ReportResponse(BaseModel):
    id: int
    report_type: str
    title: str
    content: str
    created_at: datetime

# FastAPI app
app = FastAPI(title="Security Log Analysis Toolkit", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Simple auth (demo purposes)
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if credentials.credentials != "demo-token-123":
        raise HTTPException(status_code=401, detail="Invalid token")
    return "demo-user"

# Log parsing functions
class LogParser:
    @staticmethod
    def parse_windows_event(log_line: str) -> Dict:
        """Parse Windows Event Log format"""
        # Simplified parser for demo
        patterns = {
            'timestamp': r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})',
            'event_id': r'Event ID: (\d+)',
            'username': r'Account Name:\s+([^\s]+)',
            'source_ip': r'Source Network Address:\s+([^\s]+)',
            'logon_type': r'Logon Type:\s+(\d+)'
        }
        
        result = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, log_line)
            result[key] = match.group(1) if match else None
            
        return result
    
    @staticmethod
    def parse_linux_auth(log_line: str) -> Dict:
        """Parse Linux auth.log format"""
        # Jan 15 10:15:30 server sshd[12345]: Failed password for user from 192.168.1.100
        pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\w+\s+(\w+)\[?\d*\]?:\s+(.*)'
        match = re.search(pattern, log_line)
        
        if match:
            timestamp_str, service, message = match.groups()
            
            # Extract IP and username
            ip_match = re.search(r'from\s+(\d+\.\d+\.\d+\.\d+)', message)
            user_match = re.search(r'for\s+(\w+)', message)
            
            return {
                'timestamp': timestamp_str,
                'service': service,
                'message': message,
                'source_ip': ip_match.group(1) if ip_match else None,
                'username': user_match.group(1) if user_match else None,
                'result': 'Failed' if 'Failed' in message else 'Success'
            }
        return {}

# Threat Intelligence Integration
class ThreatIntelChecker:
    @staticmethod
    async def check_ip_reputation(ip: str) -> Dict:
        """Check IP against multiple threat intel sources"""
        results = {}
        
        # AbuseIPDB (demo - would need real API key)
        try:
            async with aiohttp.ClientSession() as session:
                # Simulate API call
                await asyncio.sleep(0.1)  # Simulate network delay
                
                # Mock response based on IP patterns
                if ip.startswith('192.168') or ip.startswith('10.') or ip.startswith('172.'):
                    results['abuseipdb'] = {'reputation': 'clean', 'confidence': 95}
                elif ip.endswith('.1') or ip.endswith('.100'):
                    results['abuseipdb'] = {'reputation': 'suspicious', 'confidence': 70}
                else:
                    results['abuseipdb'] = {'reputation': 'malicious', 'confidence': 85}
                    
        except Exception as e:
            results['abuseipdb'] = {'error': str(e)}
            
        return results

# Analysis Engine
class SecurityAnalyzer:
    def __init__(self):
        self.risk_thresholds = {
            'failed_login_count': 5,
            'time_window_minutes': 30,
            'suspicious_hours': [(22, 6)]  # 10PM to 6AM
        }
    
    def analyze_failed_logins(self, log_entries: List[LogEntry]) -> Dict:
        """Detect brute force attempts"""
        failed_attempts = {}
        
        for entry in log_entries:
            if entry.result.lower() == 'failed':
                key = f"{entry.source_ip}_{entry.username}"
                if key not in failed_attempts:
                    failed_attempts[key] = []
                failed_attempts[key].append(entry.timestamp)
        
        # Check for brute force patterns
        alerts = []
        for key, timestamps in failed_attempts.items():
            if len(timestamps) >= self.risk_thresholds['failed_login_count']:
                ip, username = key.split('_')
                alerts.append({
                    'type': 'brute_force',
                    'severity': 'high',
                    'ip': ip,
                    'username': username,
                    'count': len(timestamps),
                    'description': f'Multiple failed login attempts detected'
                })
        
        return {'alerts': alerts, 'total_failed': sum(len(t) for t in failed_attempts.values())}
    
    def analyze_time_patterns(self, log_entries: List[LogEntry]) -> Dict:
        """Detect unusual timing patterns"""
        off_hours_logins = []
        
        for entry in log_entries:
            hour = entry.timestamp.hour
            for start, end in self.risk_thresholds['suspicious_hours']:
                if start > end:  # Crosses midnight
                    if hour >= start or hour <= end:
                        off_hours_logins.append(entry)
                elif start <= hour <= end:
                    off_hours_logins.append(entry)
        
        return {
            'off_hours_count': len(off_hours_logins),
            'suspicious_entries': [
                {
                    'timestamp': entry.timestamp.isoformat(),
                    'username': entry.username,
                    'ip': entry.source_ip
                } for entry in off_hours_logins
            ]
        }

# LLM Integration
class LLMAnalyzer:
    ANALYSIS_PROMPTS = {
        "suspicious_activity": """
        Analyze these authentication events for potential security threats.
        Focus on: failed logins, privilege escalation, unusual timing, geographic anomalies.
        Provide risk level (Low/Medium/High) and brief explanation.
        """,
        
        "incident_summary": """
        Summarize this security incident in executive language.
        Include: timeline, affected systems, potential impact, recommended actions.
        Keep technical details minimal.
        """,
        
        "technical_analysis": """
        Provide detailed technical analysis of these authentication events.
        Include: attack vectors, IOCs, affected accounts, timeline correlation.
        Use security professional terminology.
        """
    }
    
    async def analyze_with_llm(self, events_data: str, analysis_type: str, api_key: str) -> str:
        """Simulate LLM analysis (would integrate with real LLM API)"""
        prompt = self.ANALYSIS_PROMPTS.get(analysis_type, self.ANALYSIS_PROMPTS["suspicious_activity"])
        
        # Mock LLM response based on analysis type
        if analysis_type == "incident_summary":
            return """
            **Executive Summary**
            
            A security incident involving multiple failed authentication attempts has been detected.
            
            **Key Findings:**
            - 15 failed login attempts from external IP addresses
            - Attempts occurred during off-business hours (2:00 AM - 4:00 AM)
            - Targeted accounts include administrative users
            
            **Risk Level:** HIGH
            
            **Recommended Actions:**
            1. Immediately review and strengthen password policies
            2. Implement multi-factor authentication
            3. Monitor affected accounts for 48 hours
            4. Consider IP blocking for suspicious sources
            """
        
        elif analysis_type == "technical_analysis":
            return """
            **Technical Analysis Report**
            
            **Attack Vector:** Brute Force Authentication Attack
            
            **Timeline:**
            - 02:15 UTC: First failed attempt from 203.0.113.1
            - 02:16-02:45 UTC: Sustained attack targeting admin accounts
            - 02:50 UTC: Attack ceased
            
            **Indicators of Compromise (IOCs):**
            - Source IP: 203.0.113.1 (Known malicious IP)
            - Targeted usernames: admin, administrator, root
            - Attack pattern: Dictionary-based password guessing
            
            **Technical Recommendations:**
            - Implement account lockout after 3 failed attempts
            - Deploy intrusion detection system (IDS)
            - Enable detailed audit logging
            """
        
        else:
            return """
            **Suspicious Activity Analysis**
            
            **Risk Level: HIGH**
            
            Multiple indicators suggest a coordinated brute force attack:
            - High volume of failed authentication attempts
            - External IP addresses with poor reputation
            - Targeting of privileged accounts
            - Attack during low-activity hours
            
            **Immediate Actions Required:**
            - Block suspicious IP addresses
            - Force password reset for targeted accounts
            - Enable additional monitoring
            """

# API Routes
@app.post("/api/upload-logs")
async def upload_logs(
    file: UploadFile = File(...),
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Upload and parse log files"""
    content = await file.read()
    
    # Handle different file types
    if file.filename.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(content)) as zip_file:
            content = zip_file.read(zip_file.namelist()[0])
    
    log_lines = content.decode('utf-8', errors='ignore').split('\n')
    parser = LogParser()
    entries_created = 0
    
    for line in log_lines:
        if not line.strip():
            continue
            
        # Determine log type and parse
        if 'Event ID:' in line or 'Logon Type:' in line:
            parsed = parser.parse_windows_event(line)
            event_type = 'windows_auth'
        elif 'sshd' in line or 'sudo' in line:
            parsed = parser.parse_linux_auth(line)
            event_type = 'linux_auth'
        else:
            continue
        
        if parsed and parsed.get('timestamp'):
            try:
                # Create database entry
                log_entry = LogEntry(
                    user_id=user_id,
                    timestamp=datetime.now(),  # Simplified for demo
                    event_type=event_type,
                    source_ip=parsed.get('source_ip', 'unknown'),
                    username=parsed.get('username', 'unknown'),
                    result=parsed.get('result', 'unknown'),
                    details=json.dumps(parsed),
                    risk_level='low'
                )
                db.add(log_entry)
                entries_created += 1
            except Exception as e:
                continue
    
    db.commit()
    
    return {
        "message": f"Successfully processed {entries_created} log entries",
        "filename": file.filename,
        "total_lines": len(log_lines)
    }

@app.get("/api/logs")
async def get_logs(
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get user's log entries"""
    logs = db.query(LogEntry).filter(LogEntry.user_id == user_id).limit(100).all()
    return [
        {
            "id": log.id,
            "timestamp": log.timestamp.isoformat(),
            "event_type": log.event_type,
            "source_ip": log.source_ip,
            "username": log.username,
            "result": log.result,
            "risk_level": log.risk_level
        }
        for log in logs
    ]

@app.post("/api/analyze")
async def analyze_logs(
    request: AnalysisRequest,
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Perform security analysis"""
    # Get log entries
    logs = db.query(LogEntry).filter(
        LogEntry.user_id == user_id,
        LogEntry.id.in_(request.log_entries)
    ).all()
    
    if not logs:
        raise HTTPException(status_code=404, detail="No logs found")
    
    # Initialize analyzers
    analyzer = SecurityAnalyzer()
    threat_checker = ThreatIntelChecker()
    llm_analyzer = LLMAnalyzer()
    
    # Perform analysis
    results = {}
    
    # Basic security analysis
    results['failed_logins'] = analyzer.analyze_failed_logins(logs)
    results['time_patterns'] = analyzer.analyze_time_patterns(logs)
    
    # Threat intelligence check
    unique_ips = list(set(log.source_ip for log in logs if log.source_ip != 'unknown'))
    threat_intel = {}
    
    for ip in unique_ips[:5]:  # Limit for demo
        threat_intel[ip] = await threat_checker.check_ip_reputation(ip)
    
    results['threat_intelligence'] = threat_intel
    
    # LLM Analysis (if API key provided)
    if request.api_key:
        events_summary = f"Analyzed {len(logs)} events from {len(unique_ips)} unique IPs"
        llm_result = await llm_analyzer.analyze_with_llm(
            events_summary, 
            request.analysis_type,
            request.api_key
        )
        results['llm_analysis'] = llm_result
    
    return results

@app.post("/api/generate-report")
async def generate_report(
    analysis_type: str,
    log_ids: List[int],
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Generate analysis report"""
    # Get analysis results
    request = AnalysisRequest(log_entries=log_ids, analysis_type=analysis_type)
    analysis_results = await analyze_logs(request, user_id, db)
    
    # Generate report content
    if analysis_type == "executive":
        title = "Executive Security Summary"
        content = f"""
        Security Analysis Report
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Overview:
        - Total events analyzed: {len(log_ids)}
        - Failed login attempts: {analysis_results['failed_logins']['total_failed']}
        - Off-hours activities: {analysis_results['time_patterns']['off_hours_count']}
        
        Risk Assessment: {'HIGH' if analysis_results['failed_logins']['total_failed'] > 10 else 'MEDIUM'}
        
        Recommendations:
        1. Review authentication policies
        2. Implement multi-factor authentication
        3. Monitor suspicious IP addresses
        """
    
    elif analysis_type == "technical":
        title = "Technical Analysis Report"
        content = f"""
        Detailed Technical Analysis
        
        Failed Login Analysis:
        {json.dumps(analysis_results['failed_logins'], indent=2)}
        
        Time Pattern Analysis:
        {json.dumps(analysis_results['time_patterns'], indent=2)}
        
        Threat Intelligence:
        {json.dumps(analysis_results['threat_intelligence'], indent=2)}
        """
    
    else:  # timeline
        title = "Timeline Analysis Report"
        content = f"""
        Security Event Timeline
        
        Key Events:
        - Authentication failures detected
        - Suspicious timing patterns identified
        - Threat intelligence correlations found
        
        Timeline visualization would be generated here.
        """
    
    # Save report
    report = AnalysisReport(
        user_id=user_id,
        report_type=analysis_type,
        title=title,
        content=content
    )
    db.add(report)
    db.commit()
    
    return {
        "id": report.id,
        "title": title,
        "content": content,
        "created_at": report.created_at.isoformat()
    }

@app.get("/api/reports")
async def get_reports(
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get user's reports"""
    reports = db.query(AnalysisReport).filter(AnalysisReport.user_id == user_id).all()
    return [
        {
            "id": report.id,
            "report_type": report.report_type,
            "title": report.title,
            "created_at": report.created_at.isoformat()
        }
        for report in reports
    ]

@app.get("/api/reports/{report_id}")
async def get_report(
    report_id: int,
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get specific report"""
    report = db.query(AnalysisReport).filter(
        AnalysisReport.id == report_id,
        AnalysisReport.user_id == user_id
    ).first()
    
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return {
        "id": report.id,
        "report_type": report.report_type,
        "title": report.title,
        "content": report.content,
        "created_at": report.created_at.isoformat()
    }

@app.get("/")
async def root():
    return {"message": "Security Log Analysis Toolkit API", "version": "1.0.0"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)