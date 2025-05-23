#!/usr/bin/env python3
"""
Quick fix script to update the report endpoint in main.py
Run this script to add the missing ReportRequest model
"""

import re

def fix_main_py():
    """Fix the main.py file to include ReportRequest model and updated endpoint"""
    
    try:
        # Read the current main.py file
        with open('main.py', 'r', encoding='utf-8') as f:
            content = f.read()
        
        print("📖 Reading main.py...")
        
        # Check if ReportRequest already exists
        if 'class ReportRequest' in content:
            print("✅ ReportRequest model already exists!")
        else:
            print("🔧 Adding ReportRequest model...")
            
            # Find where to insert the ReportRequest model (after AnalysisRequest)
            analysis_request_pattern = r'(class AnalysisRequest\(BaseModel\):.*?\n(?:    .*\n)*)'
            
            if re.search(analysis_request_pattern, content, re.DOTALL):
                # Add ReportRequest after AnalysisRequest
                report_request_model = '''
class ReportRequest(BaseModel):
    analysis_type: str
    log_ids: List[int]
'''
                content = re.sub(
                    analysis_request_pattern,
                    r'\1' + report_request_model,
                    content,
                    flags=re.DOTALL
                )
                print("✅ Added ReportRequest model")
            else:
                print("⚠️  Could not find AnalysisRequest model to insert after")
        
        # Check if the report endpoint uses ReportRequest
        if 'request: ReportRequest' in content:
            print("✅ Report endpoint already uses ReportRequest!")
        else:
            print("🔧 Updating report endpoint...")
            
            # Find and replace the report endpoint signature
            old_signature_pattern = r'async def generate_report\(\s*analysis_type: str,\s*log_ids: List\[int\],\s*user_id: str = Depends\(verify_token\),\s*db: Session = Depends\(get_db\)\s*\):'
            new_signature = '''async def generate_report(
    request: ReportRequest,
    user_id: str = Depends(verify_token),
    db: Session = Depends(get_db)
):'''
            
            if re.search(old_signature_pattern, content, re.DOTALL):
                content = re.sub(old_signature_pattern, new_signature, content, flags=re.DOTALL)
                
                # Also need to update references to analysis_type and log_ids
                content = content.replace('analysis_type', 'request.analysis_type')
                content = content.replace('log_ids', 'request.log_ids')
                
                print("✅ Updated report endpoint signature")
            else:
                print("⚠️  Could not find old report endpoint signature")
        
        # Write the updated content back
        with open('main.py', 'w', encoding='utf-8') as f:
            f.write(content)
        
        print("💾 Saved updated main.py")
        print("\n🚀 Next steps:")
        print("   1. Restart your API: docker-compose restart api")
        print("   2. Run the test again: python test_api.py")
        
        return True
        
    except FileNotFoundError:
        print("❌ main.py file not found. Make sure you're in the correct directory.")
        return False
    except Exception as e:
        print(f"❌ Error updating main.py: {e}")
        return False

if __name__ == "__main__":
    print("🔧 Fixing Report Endpoint in main.py")
    print("=" * 50)
    
    if fix_main_py():
        print("\n✅ Fix completed successfully!")
    else:
        print("\n❌ Fix failed. You may need to manually update main.py")
        print("\nManual fix:")
        print("1. Add this model after AnalysisRequest:")
        print("""
class ReportRequest(BaseModel):
    analysis_type: str
    log_ids: List[int]
""")
        print("2. Change the generate_report function signature to:")
        print("   async def generate_report(request: ReportRequest, ...)")
        print("3. Use request.analysis_type and request.log_ids in the function")