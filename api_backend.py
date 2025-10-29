"""
FastAPI Mobile Security Analysis Backend

Integrates with the proven src/ components to provide a REST API for mobile app security scanning.
"""

import os
import sys
import asyncio
import tempfile
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from pydantic import BaseModel, Field

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
            if hasattr(security_agent, 'vulnerability_analyzer'):
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
    
    if not security_agent:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Security agent not initialized. Check health endpoint for details."
        )
    
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
    
    # Generate unique scan ID
    scan_id = str(uuid.uuid4())
    
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
    
    # Start background scan processing
    background_tasks.add_task(
        process_scan_background,
        scan_id,
        file,
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
                "progress": data.get("progress", 0)
            }
            for scan_id, data in active_scans.items()
        ]
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
            "mobsf_scanning": bool(os.getenv("MOBSF_API_URL")),
            "ai_analysis": bool(os.getenv("GROQ_API_KEY") or os.getenv("OPENAI_API_KEY")),
            "report_generation": True
        }
    }
    
    return config


# Background Processing Function
async def process_scan_background(
    scan_id: str, 
    file: UploadFile, 
    app_name: str, 
    include_ai_analysis: bool = True
):
    """
    Background task to process mobile app scan using the proven MobileSecurityAgent
    """
    try:
        # Update status to processing
        active_scans[scan_id].update({
            "status": "processing",
            "progress": 10,
            "message": "Saving uploaded file"
        })
        
        # Create temporary file for processing
        with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as temp_file:
            # Reset file pointer and read content
            await file.seek(0)
            content = await file.read()
            temp_file.write(content)
            temp_file_path = temp_file.name
        
        try:
            # Update status
            active_scans[scan_id].update({
                "progress": 30,
                "message": "Starting security analysis with MobileSecurityAgent"
            })
            
            # Change to src directory context for the scan
            original_cwd = os.getcwd()
            src_dir = os.path.join(os.path.dirname(__file__), 'src')
            os.chdir(src_dir)
            
            try:
                # Use the proven MobileSecurityAgent to perform the scan
                scan_results = await asyncio.get_event_loop().run_in_executor(
                    None,
                    security_agent.scan_mobile_app,
                    temp_file_path,
                    app_name
                )
                
                # Update status with successful results
                active_scans[scan_id].update({
                    "status": "completed",
                    "progress": 100,
                    "message": "Scan completed successfully",
                    "results": scan_results
                })
                
            finally:
                # Always return to original directory
                os.chdir(original_cwd)
                
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_file_path)
            except OSError:
                pass
                
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