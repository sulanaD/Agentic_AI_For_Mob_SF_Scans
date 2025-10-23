#!/usr/bin/env python3
"""Test complete MobSF workflow with explicit scan call"""

import os
from dotenv import load_dotenv
from src.mobsf_client import MobSFClient

load_dotenv()

# Initialize client
api_url = os.getenv('MOBSF_API_URL', 'http://localhost:8000')
api_key = os.getenv('MOBSF_API_KEY')
client = MobSFClient(api_url, api_key)

print('=== Complete MobSF Workflow Test ===\n')

# Step 1: Upload
print('Step 1: Uploading APK...')
file_hash = client.upload_file('iecc-care-release-170.apk')
print(f'✓ Uploaded successfully! Hash: {file_hash}\n')

# Step 2: Explicit scan call
print('Step 2: Triggering scan explicitly...')
response = client.session.post(
    f'{client.api_url}/api/v1/scan',
    data={'hash': file_hash, 'scan_type': 'apk'}
)
scan_result = response.json()
if 'error' in scan_result:
    print(f'✗ Scan error: {scan_result["error"]}')
elif 'file_name' in scan_result:
    print(f'✓ Scan started for: {scan_result["file_name"]}\n')
else:
    print(f'Response: {scan_result}\n')

# Step 3: Wait for completion
print('Step 3: Waiting for scan to complete (up to 5 minutes)...')
if client.wait_for_scan_completion(file_hash, timeout=300, poll_interval=10):
    print('✓ Scan completed successfully!\n')
    
    # Step 4: Get results
    print('Step 4: Retrieving results...')
    results = client.get_scan_results(file_hash)
    print(f'✓ Results retrieved!')
    print(f'  - App Name: {results.get("app_name")}')
    print(f'  - Package: {results.get("package_name")}')
    print(f'  - Security Score: {results.get("security_score")}')
else:
    print('✗ Scan timed out after 5 minutes')
