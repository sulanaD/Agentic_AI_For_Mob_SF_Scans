#!/usr/bin/env python3
"""
Simple Mobile Security Agent API Server

Basic Flask API server for the Mobile Security Agent that provides
HTTP endpoints for mobile application security scanning using just MobSF.
"""

import os
import sys
import logging
import tempfile
import json
import requests
from pathlib import Path
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Configuration
MOBSF_URL = os.environ.get('MOBSF_URL', 'http://localhost:8000')
MOBSF_API_KEY = os.environ.get('MOBSF_API_KEY', '')

def get_mobsf_url():
    """Get the MobSF URL with proper formatting"""
    url = MOBSF_URL.rstrip('/')
    return url

def scan_apk_with_mobsf(apk_path):
    """
    Scan APK using MobSF API
    """
    try:
        # Upload file to MobSF
        url = f"{get_mobsf_url()}/api/v1/upload"
        
        with open(apk_path, 'rb') as f:
            files = {'file': (os.path.basename(apk_path), f, 'application/vnd.android.package-archive')}
            data = {}
            if MOBSF_API_KEY:
                data['apikey'] = MOBSF_API_KEY
            
            response = requests.post(url, files=files, data=data, timeout=300)
            response.raise_for_status()
            
            upload_result = response.json()
            
        # Start scan
        scan_url = f"{get_mobsf_url()}/api/v1/scan"
        scan_data = {
            'file_name': upload_result['file_name'],
            'hash': upload_result['hash'],
            'scan_type': upload_result['scan_type']
        }
        if MOBSF_API_KEY:
            scan_data['apikey'] = MOBSF_API_KEY
            
        scan_response = requests.post(scan_url, data=scan_data, timeout=600)
        scan_response.raise_for_status()
        
        return scan_response.json()
        
    except requests.exceptions.RequestException as e:
        raise Exception(f"MobSF API error: {e}")
    except Exception as e:
        raise Exception(f"Scan error: {e}")

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check MobSF connectivity
        response = requests.get(f"{get_mobsf_url()}/api_docs", timeout=10)
        mobsf_status = "connected" if response.status_code == 200 else "disconnected"
    except:
        mobsf_status = "disconnected"
    
    return jsonify({
        'status': 'healthy',
        'service': 'mobile-security-agent',
        'version': '1.0.0',
        'mobsf_status': mobsf_status
    })

@app.route('/scan', methods=['POST'])
def scan_apk():
    """
    Scan an APK file for security vulnerabilities
    
    Expects:
    - file: APK file in multipart/form-data
    
    Returns:
    - JSON with scan results
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
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Perform scan
            logging.info(f"Starting scan for {file.filename}")
            result = scan_apk_with_mobsf(temp_path)
            logging.info(f"Scan completed for {file.filename}")
            
            return jsonify({
                'status': 'success',
                'filename': file.filename,
                'results': result
            })
            
        finally:
            # Clean up temporary file
            try:
                os.unlink(temp_path)
            except:
                pass
                
    except Exception as e:
        logging.error(f"Scan error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/config', methods=['GET'])
def get_config():
    """Get current configuration (sanitized)"""
    try:
        # Test MobSF connectivity
        try:
            response = requests.get(f"{get_mobsf_url()}/api_docs", timeout=10)
            mobsf_connected = response.status_code == 200
        except:
            mobsf_connected = False
        
        config = {
            'mobsf': {
                'url': get_mobsf_url(),
                'connected': mobsf_connected,
                'has_api_key': bool(MOBSF_API_KEY and MOBSF_API_KEY != 'placeholder')
            }
        }
        
        return jsonify(config)
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
    
    # Get configuration
    port = int(os.environ.get('PORT', 8000))
    host = os.environ.get('HOST', '0.0.0.0')
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'
    
    logging.info(f"Starting Simple Mobile Security Agent API server on {host}:{port}")
    logging.info(f"MobSF URL: {get_mobsf_url()}")
    
    app.run(host=host, port=port, debug=debug)