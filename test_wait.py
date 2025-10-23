#!/usr/bin/env python3
"""Test the wait logic for MobSF scan completion"""

import sys
import os
from dotenv import load_dotenv
from src.mobsf_client import create_mobsf_client
from src.langchain_config import get_quick_config

def main():
    # Load .env file
    load_dotenv()
    
    print("=== Testing MobSF Wait Logic ===\n")
    
    # Load config
    config = get_quick_config()
    
    # Create client
    client = create_mobsf_client(
        api_url=config.mobsf.api_url,
        api_key=config.mobsf.api_key
    )
    
    # Upload a new file to trigger a fresh scan
    print("Step 1: Uploading file to trigger new scan...")
    upload_result = client.upload_file("iecc-care-release-170.apk")
    file_hash = upload_result.get('hash')
    print(f"✓ Upload successful! Hash: {file_hash}\n")
    
    # Now test if wait_for_scan_completion properly waits
    print("Step 2: Waiting for scan to complete (this should take ~30-60 seconds)...")
    if client.wait_for_scan_completion(file_hash, timeout=180, poll_interval=5):
        print("✓ Scan completed successfully!\n")
        
        # Get final results
        print("Step 3: Retrieving final results...")
        results = client.get_scan_results(file_hash)
        print(f"✓ Results retrieved!")
        print(f"  - App Name: {results.get('app_name', 'N/A')}")
        print(f"  - Package: {results.get('package_name', 'N/A')}")
        print(f"  - Security Score: {results.get('appsec', {}).get('security_score', 'N/A')}")
        return 0
    else:
        print("✗ Scan timed out!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
