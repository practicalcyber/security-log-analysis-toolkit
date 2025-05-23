#!/usr/bin/env python3
"""
This shows exactly what to fix in your main.py file
"""

print("🔧 EXACT FIXES NEEDED IN YOUR main.py:")
print("=" * 60)

print("\n1. ADD THIS MODEL (after AnalysisRequest):")
print("=" * 40)
print("""
class ReportRequest(BaseModel):
    analysis_type: str
    log_ids: List[int]
""")

print("\n2. REPLACE YOUR ENTIRE generate_report FUNCTION:")
print("=" * 50)
print("""
@app.post("/api/generate-report")
async def generate_report(
    request: ReportRequest,  # <-- CHANGED: was analysis_type: str, log_ids: List[int]
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    \"\"\"Generate analysis report\"\"\"
    try:
        # Get logs for the report
        logs = db.query(LogEntry).filter(
            LogEntry.user_id == user_id,
            LogEntry.id.in_(request.log_ids)  # <-- CHANGED: was log_ids
        ).all()
        
        # Simple report generation
        title = f"{request.analysis_type.title()} Security Report"  # <-- CHANGED: was analysis_type
        content = f\"\"\"Security Analysis Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Report Type: {request.analysis_type}  # <-- CHANGED: was analysis_type
Log Entries Analyzed: {len(request.log_ids)}  # <-- CHANGED: was log_ids

Summary:
- Total events processed: {len(logs)}
- Report generated successfully
- System functioning correctly
\"\"\"
        
        # Save to database
        report = AnalysisReport(
            user_id=user_id,
            report_type=request.analysis_type,  # <-- CHANGED: was analysis_type
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
        
    except Exception as e:
        print(f"Report generation error: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {str(e)}")
""")

print("\n3. RESTART THE API:")
print("=" * 20)
print("docker-compose restart api")

print("\n4. TEST:")
print("=" * 10)
print("python test_api.py")