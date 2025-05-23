import os
import sys
import time
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
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

# Database imports with error handling
try:
    from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, text
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import sessionmaker, Session
    from sqlalchemy.exc import OperationalError
except ImportError as e:
    print(f"Database dependencies missing: {e}")
    sys.exit(1)

# Database configuration - FIXED for Docker
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://secuser:secpass123@db:5432/securitytoolkit")
print(f"🔗 Using database URL: {DATABASE_URL}")

# Create engine with proper retry logic for Docker
def create_db_engine():
    max_retries = 30
    retry_interval = 2
    
    for attempt in range(max_retries):
        try:
            print(f"🔄 Database connection attempt {attempt + 1}/{max_retries}")
            engine = create_engine(
                DATABASE_URL,
                pool_pre_ping=True,
                pool_recycle=300,
                echo=False,  # Disable SQL logging in production
                connect_args={"connect_timeout": 10}
            )
            
            # Test the connection
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            
            print("✅ Database connection successful!")
            return engine
            
        except OperationalError as e:
            print(f"❌ Database connection failed (attempt {attempt + 1}): {e}")
            if attempt < max_retries - 1:
                print(f"⏳ Retrying in {retry_interval} seconds...")
                time.sleep(retry_interval)
            else:
                print("🔄 Max retries reached. Falling back to SQLite...")
                # Fallback to SQLite for development
                fallback_engine = create_engine("sqlite:///./security_toolkit.db", echo=False)
                print("✅ SQLite fallback database created")
                return fallback_engine
        except Exception as e:
            print(f"❌ Unexpected database error: {e}")
            if attempt < max_retries - 1:
                time.sleep(retry_interval)
            else:
                sys.exit(1)

# Initialize database connection
engine = None
SessionLocal = None
Base = declarative_base()

def init_database():
    global engine, SessionLocal
    engine = create_db_engine()
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    
    # Create tables
    try:
        Base.metadata.create_all(bind=engine)
        print("✅ Database tables created successfully")
    except Exception as e:
        print(f"❌ Failed to create database tables: {e}")

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

class ReportRequest(BaseModel):
    analysis_type: str
    log_ids: List[int]

class ReportResponse(BaseModel):
    id: int
    report_type: str
    title: str
    content: str
    created_at: datetime

# FastAPI app
app = FastAPI(
    title="Security Log Analysis Toolkit", 
    version="1.0.0",
    description="Advanced Authentication Log Analysis & Threat Detection"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer()

# Startup event
@app.on_event("startup")
async def startup_event():
    print("🚀 Starting Security Log Analysis Toolkit...")
    init_database()
    print("✅ Application startup complete!")

# Health check endpoint (no authentication required)
@app.get("/")
async def root():
    return {
        "message": "Security Log Analysis Toolkit API", 
        "version": "1.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    """Detailed health check"""
    health_status = {
        "api": "healthy",
        "database": "unknown",
        "timestamp": datetime.utcnow().isoformat()
    }
    
    # Check database connection
    if SessionLocal:
        try:
            db = SessionLocal()
            db.execute(text("SELECT 1"))
            db.close()
            health_status["database"] = "healthy"
        except Exception as e:
            health_status["database"] = f"unhealthy: {str(e)}"
    else:
        health_status["database"] = "not initialized"
    
    return health_status

# Dependency
def get_db():
    if not SessionLocal:
        raise HTTPException(status_code=500, detail="Database not initialized")
    
    db = SessionLocal()
    try:
        yield db
    except Exception as e:
        print(f"Database session error: {e}")
        db.rollback()
        raise
    finally:
        db.close()

# Simple auth (demo purposes)
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    # Demo tokens for testing
    valid_tokens = ["demo-token-123", "test-token", "admin-token"]
    
    if token not in valid_tokens:
        raise HTTPException(status_code=401, detail="Invalid token")
    return "demo-user"

# Log parsing functions
class LogParser:
    @staticmethod
    def parse_windows_event(log_line: str) -> Dict:
        """Parse Windows Event Log format"""
        try:
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
        except Exception as e:
            print(f"Error parsing Windows event: {e}")
            return {}
    
    @staticmethod
    def parse_linux_auth(log_line: str) -> Dict:
        """Parse Linux auth.log format"""
        try:
            pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+\w+\s+(\w+)\[?\d*\]?:\s+(.*)'
            match = re.search(pattern, log_line)
            
            if match:
                timestamp_str, service, message = match.groups()
                
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
        except Exception as e:
            print(f"Error parsing Linux auth log: {e}")
            return {}

# Threat Intelligence Integration
class ThreatIntelChecker:
    @staticmethod
    async def check_ip_reputation(ip: str) -> Dict:
        """Check IP against multiple threat intel sources"""
        results = {}
        
        try:
            # Simulate API call with realistic delay
            await asyncio.sleep(0.1)
            
            # Mock response based on IP patterns for demo
            if ip.startswith(('192.168', '10.', '172.16', '172.17', '172.18', '172.19')):
                results['abuseipdb'] = {'reputation': 'clean', 'confidence': 95}
            elif ip.startswith(('203.0.113', '198.51.100', '185.220.101')):
                results['abuseipdb'] = {'reputation': 'malicious', 'confidence': 85}
            else:
                results['abuseipdb'] = {'reputation': 'suspicious', 'confidence': 70}
                    
        except Exception as e:
            results['abuseipdb'] = {'error': str(e)}
            
        return results

# Analysis Engine
class SecurityAnalyzer:
    def __init__(self):
        self.risk_thresholds = {
            'failed_login_count': 5,
            'time_window_minutes': 30,
            'suspicious_hours': [(22, 6)]
        }
    
    def analyze_failed_logins(self, log_entries: List[LogEntry]) -> Dict:
        """Detect brute force attempts"""
        failed_attempts = {}
        
        for entry in log_entries:
            if entry.result and entry.result.lower() == 'failed':
                key = f"{entry.source_ip}_{entry.username}"
                if key not in failed_attempts:
                    failed_attempts[key] = []
                failed_attempts[key].append(entry.timestamp)
        
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
            if not entry.timestamp:
                continue
                
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
                    'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
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
        """Simulate LLM analysis"""
        prompt = self.ANALYSIS_PROMPTS.get(analysis_type, self.ANALYSIS_PROMPTS["suspicious_activity"])
        
        # Mock responses for demo
        if analysis_type == "incident_summary":
            return """**Executive Summary**
            
A security incident involving multiple failed authentication attempts has been detected.

**Key Findings:**
- Multiple failed login attempts from external IP addresses
- Attempts occurred during off-business hours
- Targeted accounts include administrative users

**Risk Level:** HIGH

**Recommended Actions:**
1. Immediately review and strengthen password policies
2. Implement multi-factor authentication
3. Monitor affected accounts for 48 hours
4. Consider IP blocking for suspicious sources"""
        
        elif analysis_type == "technical_analysis":
            return """**Technical Analysis Report**

**Attack Vector:** Brute Force Authentication Attack

**Timeline:**
- Initial failed attempts from suspicious IP addresses
- Sustained attack targeting administrative accounts
- Attack pattern consistent with automated tools

**Indicators of Compromise (IOCs):**
- Source IPs with poor reputation scores
- Targeted usernames: admin, administrator, root
- Attack pattern: Dictionary-based password guessing

**Technical Recommendations:**
- Implement account lockout after 3 failed attempts
- Deploy intrusion detection system (IDS)
- Enable detailed audit logging"""
        
        else:
            return """**Suspicious Activity Analysis**

**Risk Level: HIGH**

Multiple indicators suggest a coordinated brute force attack:
- High volume of failed authentication attempts
- External IP addresses with poor reputation
- Targeting of privileged accounts
- Attack during low-activity hours

**Immediate Actions Required:**
- Block suspicious IP addresses
- Force password reset for targeted accounts
- Enable additional monitoring"""

# API Routes
@app.post("/api/upload-logs")
async def upload_logs(
    file: UploadFile = File(...),
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Upload and parse log files"""
    try:
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
            
            if parsed and (parsed.get('timestamp') or parsed.get('source_ip')):
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
                    print(f"Error creating log entry: {e}")
                    continue
        
        db.commit()
        
        return {
            "message": f"Successfully processed {entries_created} log entries",
            "filename": file.filename,
            "total_lines": len(log_lines)
        }
        
    except Exception as e:
        print(f"Upload error: {e}")
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")

@app.get("/api/logs")
async def get_logs(
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get user's log entries"""
    try:
        logs = db.query(LogEntry).filter(LogEntry.user_id == user_id).order_by(LogEntry.created_at.desc()).limit(100).all()
        return [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "event_type": log.event_type,
                "source_ip": log.source_ip,
                "username": log.username,
                "result": log.result,
                "risk_level": log.risk_level
            }
            for log in logs
        ]
    except Exception as e:
        print(f"Error getting logs: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve logs")

@app.post("/api/analyze")
async def analyze_logs(
    request: AnalysisRequest,
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Perform security analysis"""
    try:
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
        unique_ips = list(set(log.source_ip for log in logs if log.source_ip and log.source_ip != 'unknown'))
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
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Analysis error: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

# FIXED REPORT GENERATION ENDPOINT
@app.post("/api/generate-report")
async def generate_report(
    request: ReportRequest,
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Generate analysis report"""
    try:
        # Simple report generation for demo
        title = f"{request.analysis_type.title()} Security Analysis Report"
        content = f"""Security Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Report Type: {request.analysis_type}
Log Entries Analyzed: {len(request.log_ids)}

Analysis Summary:
- This is a demo report showing the system is working
- {len(request.log_ids)} log entries were successfully processed
- Report generation endpoint is functioning correctly

In a production system, this would contain:
- Detailed security analysis results
- Risk assessments and recommendations
- Charts and visualizations
- Executive summaries

Log IDs processed: {', '.join(map(str, request.log_ids))}
"""
        
        # Save report to database
        try:
            report = AnalysisReport(
                user_id=user_id,
                report_type=request.analysis_type,
                title=title,
                content=content
            )
            db.add(report)
            db.commit()
            report_id = report.id
        except Exception as db_error:
            print(f"Database error (using fallback): {db_error}")
            report_id = 1  # Fallback ID
        
        return {
            "id": report_id,
            "title": title,
            "content": content,
            "created_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        print(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")

@app.get("/api/reports")
async def get_reports(
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get user's reports"""
    try:
        reports = db.query(AnalysisReport).filter(AnalysisReport.user_id == user_id).order_by(AnalysisReport.created_at.desc()).all()
        return [
            {
                "id": report.id,
                "report_type": report.report_type,
                "title": report.title,
                "created_at": report.created_at.isoformat()
            }
            for report in reports
        ]
    except Exception as e:
        print(f"Error getting reports: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve reports")

@app.get("/api/reports/{report_id}")
async def get_report(
    report_id: int,
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """Get specific report"""
    try:
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
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error getting report: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve report")

if __name__ == "__main__":
    print("🛡️  Starting Security Log Analysis Toolkit...")
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")