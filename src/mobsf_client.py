"""
MobSF API Integration Module

This module provides a comprehensive interface to the Mobile Security Framework (MobSF) API
for automated mobile application security scanning.
"""

import requests
import json
import time
import os
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
import logging

logger = logging.getLogger(__name__)


class MobSFAPIError(Exception):
    """Custom exception for MobSF API related errors"""
    pass


class MobSFClient:
    """
    Client class for interacting with MobSF API
    """
    
    def __init__(self, api_url: str, api_key: str):
        """
        Initialize MobSF client
        
        Args:
            api_url (str): MobSF server URL (e.g., http://localhost:8000)
            api_key (str): MobSF API key for authentication
        """
        self.api_url = api_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'X-Mobsf-Api-Key': api_key
        })
        
    def _make_request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """
        Make HTTP request to MobSF API with error handling
        
        Args:
            method (str): HTTP method
            endpoint (str): API endpoint
            **kwargs: Additional request parameters
            
        Returns:
            requests.Response: API response
            
        Raises:
            MobSFAPIError: If API request fails
        """
        url = f"{self.api_url}{endpoint}"
        
        # Set timeout for large file uploads if not specified
        if 'timeout' not in kwargs:
            kwargs['timeout'] = (30, 300)  # (connection timeout, read timeout)
        
        try:
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            logger.error(f"MobSF API request failed: {e}")
            raise MobSFAPIError(f"API request failed: {e}")
    
    def upload_file(self, file_path: str) -> Dict[str, Any]:
        """
        Upload mobile application file to MobSF
        
        Args:
            file_path (str): Path to APK/IPA file
            
        Returns:
            Dict[str, Any]: Upload response containing file hash and metadata
            
        Raises:
            MobSFAPIError: If upload fails
        """
        if not os.path.exists(file_path):
            raise MobSFAPIError(f"File not found: {file_path}")
        
        file_path_obj = Path(file_path)
        if file_path_obj.suffix.lower() not in ['.apk', '.ipa']:
            raise MobSFAPIError(f"Unsupported file type: {file_path_obj.suffix}")
        
        logger.info(f"Uploading file: {file_path}")
        
        with open(file_path, 'rb') as f:
            files = {'file': (file_path_obj.name, f, 'application/octet-stream')}
            response = self._make_request('POST', '/api/v1/upload', files=files)
        
        result = response.json()
        logger.info(f"File uploaded successfully. Hash: {result.get('hash', 'N/A')}")
        return result
    
    def start_scan(self, file_hash: str, scan_type: str = 'apk') -> Dict[str, Any]:
        """
        Start security scan for uploaded file
        
        Args:
            file_hash (str): Hash of uploaded file
            scan_type (str): Type of scan ('apk' or 'ipa')
            
        Returns:
            Dict[str, Any]: Scan initiation response
            
        Raises:
            MobSFAPIError: If scan initiation fails
        """
        logger.info(f"Starting {scan_type} scan for hash: {file_hash}")
        
        data = {
            'hash': file_hash,
            'scan_type': scan_type
        }
        
        response = self._make_request('POST', '/api/v1/scan', data=data)
        result = response.json()
        
        logger.info(f"Scan started successfully for hash: {file_hash}")
        return result
    
    def wait_for_scan_completion(self, file_hash: str, timeout: int = 1800, 
                               poll_interval: int = 5) -> bool:
        """
        Wait for scan to complete by trying to fetch results
        
        Args:
            file_hash (str): Hash of the file being scanned
            timeout (int): Maximum wait time in seconds (default: 30 minutes)
            poll_interval (int): Polling interval in seconds (default: 5 seconds)
            
        Returns:
            bool: True if scan completed successfully, False if timeout
        """
        logger.info(f"Waiting for scan completion (timeout: {timeout}s)")
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                # Try to get scan results - if successful, scan is complete
                result = self.get_scan_results(file_hash)
                
                # Check if this is a valid report (not just "Report not Found")
                if result and isinstance(result, dict):
                    # If we get "Report not Found" or similar error message, scan is not ready
                    if result.get('report') == 'Report not Found' or 'error' in result:
                        logger.debug(f"Scan still in progress, waiting {poll_interval}s...")
                        time.sleep(poll_interval)
                        continue
                    
                    # If we have file_name or other scan data, scan is complete
                    if 'file_name' in result or 'app_name' in result:
                        logger.info("Scan completed successfully")
                        return True
                    
            except Exception as e:
                logger.debug(f"Scan still in progress: {e}")
                time.sleep(poll_interval)
                continue
        
        logger.error(f"Scan timeout after {timeout} seconds")
        return False
    
    def get_scan_results(self, file_hash: str, report_type: str = 'json') -> Dict[str, Any]:
        """
        Retrieve scan results
        
        Args:
            file_hash (str): Hash of the scanned file
            report_type (str): Report format ('json', 'pdf', 'xml')
            
        Returns:
            Dict[str, Any]: Complete scan results or {"report": "Report not Found"} if scan in progress
            
        Raises:
            MobSFAPIError: If results retrieval fails
        """
        logger.info(f"Retrieving scan results for hash: {file_hash}")
        
        data = {
            'hash': file_hash
        }
        
        url = f"{self.api_url}/api/v1/report_json"
        
        try:
            response = self.session.post(url, data=data)
            result = response.json()
            
            # If report is not found, return the message without raising error
            if result.get('report') == 'Report not Found':
                logger.debug("Report not found - scan may still be in progress")
                return result
            
            # For other errors, raise
            response.raise_for_status()
            
            logger.info(f"Retrieved scan results ({len(str(result))} bytes)")
            return result
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to retrieve scan results: {e}")
            raise MobSFAPIError(f"Failed to retrieve scan results: {e}")
    
    def delete_scan(self, file_hash: str) -> Dict[str, Any]:
        """
        Delete scan and associated files
        
        Args:
            file_hash (str): Hash of the file to delete
            
        Returns:
            Dict[str, Any]: Deletion response
        """
        logger.info(f"Deleting scan for hash: {file_hash}")
        
        data = {'hash': file_hash}
        response = self._make_request('POST', '/api/v1/delete_scan', data=data)
        
        logger.info(f"Scan deleted for hash: {file_hash}")
        return response.json()
    
    def get_recent_scans(self, limit: int = 10) -> Dict[str, Any]:
        """
        Get list of recent scans
        
        Args:
            limit (int): Maximum number of scans to retrieve
            
        Returns:
            Dict[str, Any]: List of recent scans
        """
        params = {'limit': limit}
        response = self._make_request('GET', '/api/v1/scans', params=params)
        return response.json()
    
    def perform_complete_scan(self, file_path: str, scan_type: str = None, 
                            timeout: int = 1800) -> Tuple[str, Dict[str, Any]]:
        """
        Perform complete scan workflow: upload, scan, wait, and retrieve results
        
        Args:
            file_path (str): Path to mobile app file
            scan_type (str): Scan type ('apk' or 'ipa'), auto-detected if None
            timeout (int): Maximum wait time for scan completion
            
        Returns:
            Tuple[str, Dict[str, Any]]: File hash and complete scan results
            
        Raises:
            MobSFAPIError: If any step of the scan process fails
        """
        # Auto-detect scan type if not provided
        if scan_type is None:
            ext = Path(file_path).suffix.lower()
            scan_type = 'apk' if ext == '.apk' else 'ipa' if ext == '.ipa' else 'apk'
        
        logger.info(f"Starting complete scan workflow for: {file_path}")
        
        # Step 1: Upload file (this automatically starts the scan in MobSF)
        upload_result = self.upload_file(file_path)
        file_hash = upload_result.get('hash')
        
        if not file_hash:
            raise MobSFAPIError("Failed to get file hash from upload response")
        
        logger.info("Upload successful, scan started automatically by MobSF")
        
        # Step 2: Wait for scan completion
        if not self.wait_for_scan_completion(file_hash, timeout):
            raise MobSFAPIError("Scan did not complete within timeout period")
        
        # Step 3: Get results
        results = self.get_scan_results(file_hash)
        
        logger.info("Complete scan workflow finished successfully")
        return file_hash, results


def create_mobsf_client(api_url: str = None, api_key: str = None) -> MobSFClient:
    """
    Factory function to create MobSF client with environment variable fallback
    
    Args:
        api_url (str): MobSF API URL (uses MOBSF_API_URL env var if None)
        api_key (str): MobSF API key (uses MOBSF_API_KEY env var if None)
        
    Returns:
        MobSFClient: Configured MobSF client instance
        
    Raises:
        MobSFAPIError: If required configuration is missing
    """
    api_url = api_url or os.getenv('MOBSF_API_URL')
    api_key = api_key or os.getenv('MOBSF_API_KEY')
    
    if not api_url:
        raise MobSFAPIError("MobSF API URL not provided (set MOBSF_API_URL environment variable)")
    
    if not api_key:
        raise MobSFAPIError("MobSF API key not provided (set MOBSF_API_KEY environment variable)")
    
    return MobSFClient(api_url, api_key)