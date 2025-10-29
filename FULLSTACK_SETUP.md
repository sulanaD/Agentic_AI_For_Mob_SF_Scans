# Mobile Security Analysis - Full Stack Setup Guide

## Overview
This guide explains how to run the complete mobile security analysis platform with both the FastAPI backend and React frontend components.

## Architecture
- **Backend**: FastAPI server on port 8080
- **Frontend**: React TypeScript application on port 3000
- **Integration**: RESTful API communication with axios HTTP client

## Prerequisites
- Python 3.11+ with conda environment
- Node.js 24.3.0+ with npm 11.4.2+
- Git for version control

## Quick Start

### 1. Backend Setup (Terminal 1)
```bash
# Navigate to project root
cd /Users/sulanadulwan/Desktop/Agentic_AI_For_Mob_SF_Scans

# Activate conda environment
conda activate ai

# Start FastAPI server
python api_backend.py
```

The backend will be available at:
- Main API: http://localhost:8080
- Interactive Docs: http://localhost:8080/docs
- Health Check: http://localhost:8080/health

### 2. Frontend Setup (Terminal 2)
```bash
# Navigate to frontend directory
cd /Users/sulanadulwan/Desktop/Agentic_AI_For_Mob_SF_Scans/frontend

# Start React development server
npm start
```

The frontend will be available at:
- Main Application: http://localhost:3000

## API Endpoints

### Core Endpoints
- `GET /health` - System health and component status
- `POST /scan` - Upload file and initiate security scan
- `GET /scans` - List all scan results
- `GET /scans/{scan_id}` - Get specific scan details
- `GET /config` - Get system configuration

### Health Check Response
```json
{
  "status": "healthy",
  "components": {
    "api": "healthy",
    "security_agent": "healthy",
    "mobsf_client": "healthy",
    "ai_analyzer": "unknown"
  },
  "version": "1.0.0"
}
```

## Frontend Features

### 1. File Upload Tab
- Drag & drop APK/IPA file upload
- File validation and size checking
- Real-time upload progress
- Supported formats: APK, IPA

### 2. Scan History Tab
- List all completed and in-progress scans
- Real-time status updates
- Scan result viewing
- Auto-refresh capabilities

### 3. System Status Tab
- Backend component health monitoring
- API endpoint status
- System configuration display
- Feature availability checking

## Component Integration

### MobileSecurityAgent Integration
The FastAPI backend integrates with the proven `src/` components:
- `MobileSecurityAgent` - Main orchestration
- `vulnerability_extractor` - Security analysis
- `ai_analyzer` - AI-powered insights
- `mobsf_client` - MobSF integration

### React-FastAPI Communication
- RESTful API calls using axios
- FormData for file uploads
- JSON responses for scan data
- WebSocket-style polling for real-time updates

## Development Workflow

### Current Git Structure
```
main
└── dev
    ├── feature/backend_integration (merged)
    └── feature/frontend_initial (current)
```

### Making Changes
1. Create feature branch from `dev`
2. Implement changes
3. Test full stack integration
4. Merge to `dev` branch

## Testing the Integration

### 1. Upload Test
1. Open http://localhost:3000
2. Go to "Upload File" tab
3. Select an APK/IPA file
4. Monitor upload progress
5. Check scan initiation

### 2. Status Monitoring
1. Go to "System Status" tab
2. Verify all components show "healthy"
3. Check API endpoint accessibility

### 3. Scan History
1. Go to "Scan History" tab
2. View uploaded scan results
3. Test real-time updates

## Troubleshooting

### Backend Issues
- **Port 8080 in use**: Kill existing processes or change port
- **Import errors**: Ensure conda `ai` environment is activated
- **MobSF connection**: Check MobSF server availability

### Frontend Issues
- **Port 3000 in use**: React will automatically suggest alternative port
- **API connection**: Verify backend is running on port 8080
- **CORS errors**: Backend includes CORS middleware for development

### Common Solutions
```bash
# Check running processes
lsof -i :8080  # Backend
lsof -i :3000  # Frontend

# Restart services
# Backend: Ctrl+C then python api_backend.py
# Frontend: Ctrl+C then npm start
```

## File Structure
```
/Users/sulanadulwan/Desktop/Agentic_AI_For_Mob_SF_Scans/
├── api_backend.py              # FastAPI server
├── src/                        # Core analysis components
│   ├── mobile_security_agent.py
│   ├── vulnerability_extractor.py
│   ├── ai_analyzer.py
│   └── mobsf_client.py
├── frontend/                   # React application
│   ├── src/
│   │   ├── App.tsx            # Main React component
│   │   └── App.css            # Styling
│   ├── package.json           # Dependencies
│   └── public/                # Static assets
└── templates/                  # Report templates
```

## Next Steps
1. Deploy to production environment
2. Add authentication/authorization
3. Implement WebSocket for real-time updates
4. Add more comprehensive error handling
5. Create automated testing suite

## Support
For issues or questions:
1. Check logs in the respective terminal windows
2. Verify both services are running
3. Test API endpoints individually with curl
4. Check browser developer tools for frontend errors