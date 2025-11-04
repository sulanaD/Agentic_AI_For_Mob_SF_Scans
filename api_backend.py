"""
FastAPI Mobile Security Analysis Backend

Integrates with the proven src/ components to provide a REST API for mobile app security scanning.
Updated: Added debug logging to MobSF requests
"""

import os
import sys
import asyncio
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Ensure Kubernetes environment variables take precedence
if 'MOBSF_API_URL' not in os.environ:
    os.environ['MOBSF_API_URL'] = 'http://mobsf-service:8000'

# Force reload environment variables but don't override existing ones
load_dotenv(override=False)  # Don't override env vars with .env file

# Force reload from .env files again to pick up any missing vars
load_dotenv('./.env', override=False)
load_dotenv('../.env', override=False)

# Load environment variables at module level - prioritize K8s env vars
MOBSF_API_URL = os.getenv('MOBSF_API_URL', 'http://localhost:8000')
# Note: MOBSF_API_KEY is read dynamically to support env changes
GROQ_API_KEY = os.getenv('GROQ_API_KEY')

# Add src directory to Python path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import our proven components from src/
try:
    from mobile_security_agent import MobileSecurityAgent
except ImportError as e:
    print(f"❌ Failed to import MobileSecurityAgent: {e}")
    print("Make sure you're running from the project root directory")
    sys.exit(1)


# Pydantic Models for API
class ScanRequest(BaseModel):
    """Request model for scanning parameters"""
    app_name: Optional[str] = Field(None, description="Optional app name")
    include_ai_analysis: bool = Field(True, description="Include AI vulnerability analysis")


class ScanResponse(BaseModel):
    """Response model for scan initiation"""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: str = Field(..., description="Scan status")
    message: str = Field(..., description="Status message")


class ScanStatus(BaseModel):
    """Response model for scan status"""
    scan_id: str
    status: str  # initiated, processing, completed, failed
    progress: Optional[int] = None
    message: str
    results: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    components: Dict[str, str]
    version: str = "1.0.0"


# Global state for tracking scans
active_scans: Dict[str, Dict[str, Any]] = {}
security_agent: Optional[MobileSecurityAgent] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager - startup and shutdown"""
    global security_agent
    
    print("🚀 Starting Mobile Security FastAPI Backend...")
    
    # Initialize the proven MobileSecurityAgent
    try:
        # Change to src directory context for proper initialization
        original_cwd = os.getcwd()
        src_dir = os.path.join(os.path.dirname(__file__), 'src')
        os.chdir(src_dir)
        
        security_agent = MobileSecurityAgent()
        print("✅ MobileSecurityAgent initialized successfully")
        
        # Return to original directory
        os.chdir(original_cwd)
        
    except Exception as e:
        print(f"❌ Failed to initialize MobileSecurityAgent: {e}")
        print("Please check your configuration and MobSF connection")
        # Don't exit - allow API to start in degraded mode
    
    yield
    
    print("🛑 Shutting down Mobile Security FastAPI Backend...")


# Initialize FastAPI app
app = FastAPI(
    title="Mobile Security Analysis API",
    description="FastAPI backend for automated mobile security scanning using proven src/ components",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health Check Endpoint
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint to verify all components"""
    global security_agent
    
    components = {
        "api": "healthy",
        "security_agent": "healthy" if security_agent else "not_initialized",
        "mobsf_client": "unknown",
        "ai_analyzer": "unknown"
    }
    
    # Check individual components if agent is available
    if security_agent:
        try:
            # Check if MobSF client is accessible
            if hasattr(security_agent, 'mobsf_client'):
                components["mobsf_client"] = "healthy"
            
            # Check if AI analyzer is available
            if hasattr(security_agent, 'ai_analyzer'):
                components["ai_analyzer"] = "healthy"
                
        except Exception as e:
            components["error"] = str(e)
    
    overall_status = "healthy" if security_agent else "degraded"
    
    return HealthResponse(
        status=overall_status,
        components=components
    )


# File Upload and Scan Endpoint
@app.post("/scan", response_model=ScanResponse)
async def scan_mobile_app(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    app_name: Optional[str] = None,
    include_ai_analysis: bool = True
):
    """
    Upload and scan a mobile application file (APK/IPA)
    """
    global security_agent
    
    # Force correct API key from file before any MobSF operations
    correct_api_key = None
    try:
        # Try to read the API key directly from .env file
        env_paths = ['.env', 'src/.env', '../.env']
        for env_path in env_paths:
            try:
                with open(env_path, 'r') as f:
                    for line in f:
                        if line.startswith('MOBSF_API_KEY='):
                            correct_api_key = line.split('=', 1)[1].strip()
                            break
                if correct_api_key:
                    break
            except FileNotFoundError:
                continue
        
        if correct_api_key:
            os.environ['MOBSF_API_KEY'] = correct_api_key
            # Update the client's API key directly
            if security_agent and hasattr(security_agent, 'mobsf_client'):
                security_agent.mobsf_client.update_api_key(correct_api_key)
                print(f"🔑 Updated MobSF API key: {correct_api_key[:10]}...")
    except Exception as e:
        print(f"⚠️ Warning: Could not update API key: {e}")
    
    if not security_agent:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security agent not initialized. Check health endpoint for details."
        )
    
    # Ensure we're using the current API key from environment
    load_dotenv(override=False)
    
    # Force read from .env file and update environment
    env_key = None
    try:
        with open('.env', 'r') as f:
            for line in f:
                if line.startswith('MOBSF_API_KEY='):
                    env_key = line.split('=', 1)[1].strip()
                    break
    except Exception:
        pass
    
    if env_key:
        os.environ['MOBSF_API_KEY'] = env_key
        current_api_key = env_key
    else:
        current_api_key = os.getenv('MOBSF_API_KEY')
    
    if current_api_key and security_agent.mobsf_client.api_key != current_api_key:
        print(f"🔄 Updating MobSF API key: {current_api_key[:10]}...")
        security_agent.mobsf_client.update_api_key(current_api_key)
    
    # Validate file type
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No file provided"
        )
    
    file_ext = Path(file.filename).suffix.lower()
    if file_ext not in ['.apk', '.ipa']:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only APK and IPA files are supported"
        )
    
    # First, upload to MobSF to get the hash (which will be our scan_id)
    # Create temporary file for initial upload
    with tempfile.NamedTemporaryFile(delete=False, suffix=file_ext) as temp_file:
        content = await file.read()
        temp_file.write(content)
        temp_file_path = temp_file.name
    
    try:
        # Step 1: Upload to MobSF to get hash
        mobsf_client = security_agent.mobsf_client
        upload_result = mobsf_client.upload_file(temp_file_path)
        mobsf_hash = upload_result.get('hash')
        
        if not mobsf_hash:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Failed to upload file to MobSF - no hash returned"
            )
        
        print(f"✅ File uploaded to MobSF, hash: {mobsf_hash}")
        
        # Step 2: Start scan with the hash
        scan_type = 'apk' if file_ext == '.apk' else 'ipa'
        scan_result = mobsf_client.start_scan(mobsf_hash, scan_type)
        print(f"✅ Scan initiated for hash: {mobsf_hash}")
        
        # Use MobSF hash as scan_id for easier management
        scan_id = mobsf_hash
        
    except Exception as e:
        # Clean up temp file
        Path(temp_file_path).unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to initiate scan: {str(e)}"
        )
    finally:
        # Clean up temp file
        Path(temp_file_path).unlink(missing_ok=True)
    
    # Initialize scan tracking
    active_scans[scan_id] = {
        "scan_id": scan_id,
        "status": "initiated",
        "progress": 0,
        "message": "Scan initiated",
        "filename": file.filename,
        "app_name": app_name or file.filename,
        "include_ai_analysis": include_ai_analysis,
        "results": None,
        "error": None
    }
    
    # Start background scan processing (file already uploaded, hash is scan_id)
    background_tasks.add_task(
        process_scan_background,
        scan_id,  # This is now the MobSF hash
        file.filename,
        app_name or file.filename,
        include_ai_analysis
    )
    
    return ScanResponse(
        scan_id=scan_id,
        status="initiated",
        message=f"Scan initiated for {file.filename}"
    )


# Scan Status Endpoint
@app.get("/scan/{scan_id}/status", response_model=ScanStatus)
async def get_scan_status(scan_id: str):
    """Get the current status of a scan"""
    if scan_id not in active_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan_data = active_scans[scan_id]
    return ScanStatus(**scan_data)


# Get Scan Results
@app.get("/scan/{scan_id}/results")
async def get_scan_results(scan_id: str):
    """Get detailed results of a completed scan"""
    if scan_id not in active_scans:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    scan_data = active_scans[scan_id]
    
    if scan_data["status"] != "completed":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Scan is not completed. Current status: {scan_data['status']}"
        )
    
    return scan_data["results"]


# List Active Scans
@app.get("/scans")
async def list_scans():
    """List all scans with their current status"""
    return {
        "total_scans": len(active_scans),
        "scans": [
            {
                "scan_id": scan_id,
                "status": data["status"],
                "filename": data["filename"],
                "app_name": data["app_name"],
                "progress": data.get("progress", 0),
                "message": data.get("message", "")
            }
            for scan_id, data in active_scans.items()
        ]
    }


# Get Individual Scan Results
@app.get("/scans/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get detailed results for a specific scan"""
    if scan_id not in active_scans:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_data = active_scans[scan_id]
    
    return {
        "scan_id": scan_id,
        "status": scan_data["status"],
        "progress": scan_data.get("progress", 0),
        "message": scan_data.get("message", ""),
        "filename": scan_data.get("filename", ""),
        "app_name": scan_data.get("app_name", ""),
        "results": scan_data.get("results", None),
        "error": scan_data.get("error", None)
    }


# Debug Endpoint
@app.get("/debug-env")
async def debug_environment():
    """Debug endpoint to check environment variables"""
    # Force reload environment but don't override K8s env vars
    from dotenv import load_dotenv
    load_dotenv(override=False)
    
    # Read current values dynamically
    current_mobsf_key = os.getenv('MOBSF_API_KEY')
    
    # Also read directly from .env file
    env_file_content = ""
    try:
        with open('.env', 'r') as f:
            for line in f:
                if 'MOBSF_API_KEY' in line:
                    env_file_content = line.strip()
                    break
    except Exception as e:
        env_file_content = f"Error reading .env: {e}"
    
    return {
        "mobsf_api_key_from_os": current_mobsf_key[:10] + "..." if current_mobsf_key else "NOT_SET",
        "mobsf_api_key_from_file": env_file_content,
        "mobsf_api_url": MOBSF_API_URL,
        "groq_api_key": "SET" if GROQ_API_KEY else "NOT_SET"
    }


# Reload Security Agent Endpoint
@app.post("/reload-agent")
async def reload_security_agent():
    """Reload the security agent with fresh environment variables"""
    global security_agent, MOBSF_API_KEY, MOBSF_API_URL, GROQ_API_KEY
    
    try:
        # Get correct API key from environment
        correct_api_key = os.getenv('MOBSF_API_KEY_OVERRIDE') or os.getenv('MOBSF_API_KEY')
        if correct_api_key:
            os.environ['MOBSF_API_KEY'] = correct_api_key
        
        # Force reload environment variables at all levels but don't override K8s env vars
        from dotenv import load_dotenv
        load_dotenv('.env', override=False)
        
        # Update our module-level variables directly
        MOBSF_API_KEY = correct_api_key
        MOBSF_API_URL = os.getenv('MOBSF_API_URL', 'http://localhost:8000')
        GROQ_API_KEY = os.getenv('GROQ_API_KEY')
        
        # Force reload in all related modules
        from mobsf_client import reload_mobsf_environment
        reload_mobsf_environment()
        
        # Recreate security agent 
        security_agent = MobileSecurityAgent()
        
        return {
            "status": "success", 
            "message": "Security agent forcefully reloaded with correct API key",
            "mobsf_api_key": (correct_api_key[:10] + "...") if correct_api_key else "NOT_SET"
        }
    except Exception as e:
        print(f"[DEBUG] Error reloading agent: {e}")
        import traceback
        traceback.print_exc()
        return {
            "status": "error",
            "message": f"Failed to reload agent: {str(e)}"
        }


# Configuration Endpoint
@app.get("/config")
async def get_configuration():
    """Get current API configuration"""
    config = {
        "api_version": "1.0.0",
        "supported_formats": [".apk", ".ipa"],
        "max_file_size": "100MB",
        "features": {
            "mobsf_scanning": bool(MOBSF_API_URL),
            "ai_analysis": bool(GROQ_API_KEY or os.getenv("OPENAI_API_KEY")),
            "report_generation": True
        }
    }
    
    return config


# Background Processing Function
async def process_scan_background(
    scan_id: str,  # This is now the MobSF hash 
    filename: str,
    app_name: str, 
    include_ai_analysis: bool = True
):
    """
    Background task to process mobile app scan using MobSF hash
    Since upload already happened, just poll for results and run AI analysis
    """
    try:
        # Add overall timeout to prevent infinite hanging
        await asyncio.wait_for(
            _perform_scan_with_timeout(scan_id, filename, app_name, include_ai_analysis),
            timeout=300.0  # 5 minute total timeout
        )
    except asyncio.TimeoutError:
        print(f"❌ Overall scan timeout after 5 minutes for {scan_id}")
        active_scans[scan_id].update({
            "status": "failed",
            "progress": 0,
            "message": "Scan timed out after 5 minutes",
            "error": "Overall scan timeout"
        })
    except Exception as e:
        print(f"❌ Scan {scan_id} failed: {e}")
        active_scans[scan_id].update({
            "status": "failed",
            "progress": 0,
            "message": f"Scan failed: {str(e)}",
            "error": str(e)
        })


async def _perform_scan_with_timeout(
    scan_id: str,  # This is now the MobSF hash
    filename: str,
    app_name: str, 
    include_ai_analysis: bool = True
):
    try:
        # Update status to processing 
        active_scans[scan_id].update({
            "status": "processing",
            "progress": 50,
            "message": f"File already uploaded to MobSF (hash: {scan_id[:8]}...)"
        })
        
        # File is already uploaded to MobSF, scan_id IS the MobSF hash
        file_hash = scan_id
        print(f"✅ Using MobSF hash as scan ID: {file_hash}")
        
        # Step 1: Get scan results from MobSF report_json endpoint
        print(f"📊 Step 1: Retrieving scan results from MobSF...")
        active_scans[scan_id].update({
            "progress": 70,
            "message": "Retrieving scan results from MobSF"
        })
        
        # Poll for results with retry logic
        mobsf_client = security_agent.mobsf_client
        max_attempts = 20
        attempt = 0
        
        while attempt < max_attempts:
            attempt += 1
            scan_results = mobsf_client.get_scan_results(file_hash)
            
            if scan_results.get('report') == 'Report not Found':
                if attempt < max_attempts:
                    wait_time = min(5 + attempt, 15)  # Start at 5s, max 15s
                    print(f"⏳ MobSF still processing, waiting {wait_time} seconds... (attempt {attempt}/{max_attempts})")
                    active_scans[scan_id].update({
                        "progress": 70 + (attempt * 2),  # Gradually increase progress
                        "message": f"Waiting for MobSF scan completion (attempt {attempt}/{max_attempts})"
                    })
                    await asyncio.sleep(wait_time)
                    continue
                else:
                    print("⚠️ MobSF scan timed out or failed")
                    active_scans[scan_id].update({
                        "status": "completed",
                        "progress": 90,
                        "message": "MobSF scan completed but report not available",
                        "results": {"error": "Report not found", "mobsf_response": scan_results}
                    })
                    return
            
            print(f"✅ Retrieved scan results from MobSF ({len(str(scan_results))} bytes)")
            
            # Step 3: Parse through AI (if requested)
            if include_ai_analysis and 'error' not in scan_results:
                active_scans[scan_id].update({
                    "progress": 85,
                    "message": "Analyzing results with AI for countermeasures"
                })
                
                print(f"🤖 Step 3: Analyzing with AI...")
                try:
                    # Extract vulnerabilities from MobSF scan results
                    vulnerabilities = []
                    
                    # Extract high severity findings
                    if 'appsec' in scan_results and 'high' in scan_results['appsec']:
                        for vuln in scan_results['appsec']['high']:
                            vulnerabilities.append({
                                'title': vuln.get('title', 'High Severity Finding'),
                                'description': vuln.get('description', ''),
                                'severity': 'High',
                                'section': vuln.get('section', ''),
                                'type': 'security'
                            })
                    
                    # Extract warning level findings
                    if 'appsec' in scan_results and 'warning' in scan_results['appsec']:
                        for vuln in scan_results['appsec']['warning']:
                            vulnerabilities.append({
                                'title': vuln.get('title', 'Warning Level Finding'),
                                'description': vuln.get('description', ''),
                                'severity': 'Medium',
                                'section': vuln.get('section', ''),
                                'type': 'warning'
                            })
                    
                    # If we have vulnerabilities, analyze them
                    if vulnerabilities:
                        ai_analysis = await asyncio.wait_for(
                            asyncio.get_event_loop().run_in_executor(
                                None,
                                security_agent.ai_analyzer.analyze_vulnerability_batch,
                                vulnerabilities[:5]  # Limit to first 5 for performance
                            ),
                            timeout=60.0  # 60 second timeout for AI analysis
                        )
                    else:
                        ai_analysis = {"message": "No significant vulnerabilities found for AI analysis"}
                    
                    # Combine MobSF results with AI analysis
                    final_results = {
                        "mobsf_scan": scan_results,
                        "ai_analysis": ai_analysis,
                        "file_hash": file_hash,
                        "app_name": app_name,
                        "scan_timestamp": datetime.now().isoformat()
                    }
                    print(f"✅ AI analysis completed")
                    
                except asyncio.TimeoutError:
                    print(f"⚠️ AI analysis timed out after 60 seconds")
                    # Return MobSF results even if AI times out
                    final_results = {
                        "mobsf_scan": scan_results,
                        "ai_analysis_error": "AI analysis timed out after 60 seconds",
                        "file_hash": file_hash,
                        "app_name": app_name,
                        "scan_timestamp": datetime.now().isoformat()
                    }
                except Exception as ai_error:
                    print(f"⚠️ AI analysis failed: {ai_error}")
                    # Return MobSF results even if AI fails
                    final_results = {
                        "mobsf_scan": scan_results,
                        "ai_analysis_error": str(ai_error),
                        "file_hash": file_hash,
                        "app_name": app_name,
                        "scan_timestamp": datetime.now().isoformat()
                    }
            else:
                print(f"⏭️ Skipping AI analysis (include_ai_analysis={include_ai_analysis})")
                # Return just MobSF results
                final_results = {
                    "mobsf_scan": scan_results,
                    "file_hash": file_hash,
                    "app_name": app_name,
                    "scan_timestamp": datetime.now().isoformat()
                }
            
            # Update status with successful results
            active_scans[scan_id].update({
                "status": "completed",
                "progress": 100,
                "message": "Scan completed successfully",
                "results": final_results
            })
            
            print(f"🎉 Scan completed successfully for {app_name}")
                
    except Exception as e:
        # Handle errors
        active_scans[scan_id].update({
            "status": "failed",
            "progress": 0,
            "message": f"Scan failed: {str(e)}",
            "error": str(e)
        })
        print(f"❌ Scan {scan_id} failed: {e}")


# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "Mobile Security Analysis API",
        "version": "1.0.0",
        "description": "FastAPI backend integrated with proven src/ components",
        "endpoints": {
            "health": "/health",
            "scan": "/scan",
            "status": "/scan/{scan_id}/status",
            "results": "/scan/{scan_id}/results",
            "scans": "/scans",
            "config": "/config",
            "docs": "/docs"
        },
        "docs_url": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    
    # Run the development server
    uvicorn.run(
        "api_backend:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )