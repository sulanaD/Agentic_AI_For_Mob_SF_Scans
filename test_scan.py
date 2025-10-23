#!/usr/bin/env python3
"""Quick test of MobSF scan workflow"""

import sys
import os
from dotenv import load_dotenv
from src.mobsf_client import create_mobsf_client
from src.langchain_config import get_quick_config

def main():
    # Load .env file
    load_dotenv()
    
    print("=== Testing MobSF Scan Workflow ===\n")
    
    # Load config
    config = get_quick_config()
    print(f"Using MobSF at: {config.mobsf.api_url}")
    print(f"API Key: {config.mobsf.api_key[:10]}...\n")
    
    # Create client
    client = create_mobsf_client(
        api_url=config.mobsf.api_url,
        api_key=config.mobsf.api_key
    )
    
    print("Step 1: Uploading file...")
    upload_result = client.upload_file("iecc-care-release-170.apk")
    file_hash = upload_result.get('hash')
    print(f"✓ Upload successful! Hash: {file_hash}\n")
    
    print("Step 2: Getting scan results...")
    try:
        results = client.get_scan_results(file_hash)
        print(f"✓ Results retrieved!")
        print(f"  - App Name: {results.get('app_name', 'N/A')}")
        print(f"  - Package: {results.get('package_name', 'N/A')}")
        print(f"  - Security Score: {results.get('appsec', {}).get('security_score', 'N/A')}")
        return 0
    except Exception as e:
        print(f"✗ Failed to get results: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
