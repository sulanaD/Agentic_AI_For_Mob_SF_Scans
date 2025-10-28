#!/usr/bin/env python3
"""
Mobile Security Agent API Server

Flask API server for the Mobile Security Agent that provides
HTTP endpoints for mobile application security scanning.
"""

import os
import sys
import logging
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename
import tempfile
import traceback

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from mobile_security_agent import create_mobile_security_agent, MobileSecurityAgentError
from langchain_config import create_config_manager, ConfigurationError

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Global configuration
config_manager = None
agent = None

def init_agent():
    """Initialize the mobile security agent"""
    global config_manager, agent
    try:
        config_manager = create_config_manager()
        config = config_manager.get_config()
        agent = create_mobile_security_agent(config)
        logging.info("Mobile Security Agent initialized successfully")
    except Exception as e:
        logging.error(f"Failed to initialize agent: {e}")
        raise

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'mobile-security-agent',
        'version': '1.0.0'
    })

@app.route('/scan', methods=['POST'])
def scan_apk():
    """
    Scan an APK file for security vulnerabilities
    
    Expects:
    - file: APK file in multipart/form-data
    - analysis_type: 'basic' or 'full' (optional, default: 'full')
    
    Returns:
    - JSON with scan results and analysis
    """
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not file.filename.lower().endswith('.apk'):
            return jsonify({'error': 'File must be an APK'}), 400
        
        # Get analysis type
        analysis_type = request.form.get('analysis_type', 'full')
        if analysis_type not in ['basic', 'full']:
            analysis_type = 'full'
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Perform scan
            logging.info(f"Starting scan for {file.filename}")
            
            if analysis_type == 'full':
                # Full scan with AI analysis
                result = agent.scan_with_ai_analysis(temp_path)
            else:
                # Basic scan only
                result = agent.scan_apk(temp_path)
            
            logging.info(f"Scan completed for {file.filename}")
            
            return jsonify({
                'status': 'success',
                'filename': file.filename,
                'analysis_type': analysis_type,
                'results': result
            })
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
                
    except MobileSecurityAgentError as e:
        logging.error(f"Agent error: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        logging.error(traceback.format_exc())
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/scan/status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    """Get status of a scan by ID"""
    # This would be implemented with a proper job queue in production
    return jsonify({'error': 'Not implemented yet'}), 501

@app.route('/reports/<report_id>', methods=['GET'])
def get_report(report_id):
    """Download a generated report"""
    # This would be implemented with proper report storage in production
    return jsonify({'error': 'Not implemented yet'}), 501

@app.route('/config', methods=['GET'])
def get_config():
    """Get current configuration (sanitized)"""
    try:
        config = config_manager.get_config()
        
        # Return sanitized config (remove sensitive data)
        sanitized_config = {
            'mobsf': {
                'url': config.get('mobsf', {}).get('url', 'Not configured'),
                'connected': bool(config.get('mobsf', {}).get('api_key'))
            },
            'ai': {
                'provider': config.get('ai', {}).get('provider', 'Not configured'),
                'model': config.get('ai', {}).get('model', 'Not configured'),
                'configured': bool(config.get('ai', {}).get('api_key'))
            }
        }
        
        return jsonify(sanitized_config)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large'}), 413

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Initialize agent
    try:
        init_agent()
    except Exception as e:
        logging.error(f"Failed to start server: {e}")
        sys.exit(1)
    
    # Get configuration
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    
    logging.info(f"Starting Mobile Security Agent API server on {host}:{port}")
    app.run(host=host, port=port, debug=debug)