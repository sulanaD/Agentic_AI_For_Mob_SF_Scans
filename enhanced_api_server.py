#!/usr/bin/env python3
"""
Enhanced Mobile Security Agent API Server

Flask API server with AI analysis capabilities using Groq.
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
import groq

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Configuration
MOBSF_URL = os.environ.get('MOBSF_URL', 'http://localhost:8000')
MOBSF_API_KEY = os.environ.get('MOBSF_API_KEY', '')
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
AI_MODEL = os.environ.get('AI_MODEL', 'llama-3.3-70b-versatile')

# Initialize Groq client
groq_client = None
if GROQ_API_KEY and GROQ_API_KEY != 'placeholder':
    try:
        groq_client = groq.Groq(api_key=GROQ_API_KEY)
    except Exception as e:
        logging.warning(f"Failed to initialize Groq client: {e}")

def get_mobsf_url():
    """Get the MobSF URL with proper formatting"""
    url = MOBSF_URL.rstrip('/')
    return url

def scan_apk_with_mobsf(apk_path):
    """Scan APK using MobSF API"""
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

def analyze_with_ai(vulnerabilities, app_info):
    """Analyze vulnerabilities using Groq AI"""
    if not groq_client:
        return {"error": "AI analysis not available - Groq API key not configured"}
    
    try:
        # Prepare the prompt
        vuln_summary = []
        for vuln in vulnerabilities[:10]:  # Limit to top 10 vulnerabilities
            vuln_summary.append({
                'title': vuln.get('title', 'Unknown'),
                'severity': vuln.get('severity', 'Unknown'),
                'description': vuln.get('description', '')[:200]  # Truncate description
            })
        
        prompt = f"""
        As a mobile security expert, analyze the following Android application security scan results and provide:

        Application Info:
        - Package: {app_info.get('package_name', 'Unknown')}
        - Version: {app_info.get('version_name', 'Unknown')}
        - Target SDK: {app_info.get('target_sdk', 'Unknown')}

        Top Vulnerabilities Found:
        {json.dumps(vuln_summary, indent=2)}

        Please provide:
        1. Executive Summary (2-3 sentences)
        2. Risk Assessment (High/Medium/Low)
        3. Top 3 Critical Issues to Address
        4. Recommended Actions

        Respond in JSON format:
        {{
            "executive_summary": "...",
            "risk_level": "High|Medium|Low",
            "critical_issues": ["issue1", "issue2", "issue3"],
            "recommendations": ["rec1", "rec2", "rec3"]
        }}
        """
        
        response = groq_client.chat.completions.create(
            model=AI_MODEL,
            messages=[
                {"role": "system", "content": "You are a mobile security expert analyzing Android app vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.1,
            max_tokens=1000
        )
        
        # Parse AI response
        ai_content = response.choices[0].message.content
        
        # Try to extract JSON from the response
        try:
            # Find JSON content in the response
            start_idx = ai_content.find('{')
            end_idx = ai_content.rfind('}') + 1
            if start_idx >= 0 and end_idx > start_idx:
                json_content = ai_content[start_idx:end_idx]
                return json.loads(json_content)
            else:
                return {"raw_analysis": ai_content}
        except json.JSONDecodeError:
            return {"raw_analysis": ai_content}
            
    except Exception as e:
        logging.error(f"AI analysis error: {e}")
        return {"error": f"AI analysis failed: {str(e)}"}

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        # Check MobSF connectivity
        response = requests.get(f"{get_mobsf_url()}/api_docs", timeout=10)
        mobsf_status = "connected" if response.status_code == 200 else "disconnected"
    except:
        mobsf_status = "disconnected"
    
    # Check AI status
    ai_status = "available" if groq_client else "unavailable"
    
    return jsonify({
        'status': 'healthy',
        'service': 'mobile-security-agent-enhanced',
        'version': '2.0.0',
        'mobsf_status': mobsf_status,
        'ai_status': ai_status
    })

@app.route('/scan', methods=['POST'])
def scan_apk():
    """Scan an APK file with optional AI analysis"""
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
        
        # Get analysis options
        include_ai = request.form.get('include_ai', 'true').lower() == 'true'
        
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as temp_file:
            file.save(temp_file.name)
            temp_path = temp_file.name
        
        try:
            # Perform MobSF scan
            logging.info(f"Starting MobSF scan for {file.filename}")
            scan_result = scan_apk_with_mobsf(temp_path)
            logging.info(f"MobSF scan completed for {file.filename}")
            
            result = {
                'status': 'success',
                'filename': file.filename,
                'mobsf_results': scan_result
            }
            
            # Add AI analysis if requested and available
            if include_ai and groq_client:
                logging.info(f"Starting AI analysis for {file.filename}")
                
                # Extract vulnerabilities and app info from MobSF results
                vulnerabilities = []
                app_info = {}
                
                if 'findings' in scan_result:
                    vulnerabilities = scan_result['findings']
                elif isinstance(scan_result, list):
                    vulnerabilities = scan_result
                
                if 'app_info' in scan_result:
                    app_info = scan_result['app_info']
                
                ai_analysis = analyze_with_ai(vulnerabilities, app_info)
                result['ai_analysis'] = ai_analysis
                logging.info(f"AI analysis completed for {file.filename}")
            
            return jsonify(result)
            
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
            },
            'ai': {
                'provider': 'groq',
                'model': AI_MODEL,
                'available': bool(groq_client),
                'has_api_key': bool(GROQ_API_KEY and GROQ_API_KEY != 'placeholder')
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
    
    logging.info(f"Starting Enhanced Mobile Security Agent API server on {host}:{port}")
    logging.info(f"MobSF URL: {get_mobsf_url()}")
    logging.info(f"AI Model: {AI_MODEL}")
    logging.info(f"Groq Client: {'Available' if groq_client else 'Not Available'}")
    
    app.run(host=host, port=port, debug=debug)