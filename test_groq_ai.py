#!/usr/bin/env python3
"""Test Groq AI analysis with mock vulnerability data"""

import os
import sys
from dotenv import load_dotenv
from src.langchain_analyzer import create_langchain_analyzer, VulnerabilityAnalysis, SeverityLevel, VulnerabilityCategory

def main():
    load_dotenv()
    
    print("=== Testing Groq AI Analysis ===\n")
    
    # Create analyzer
    print("Step 1: Creating Groq analyzer...")
    analyzer = create_langchain_analyzer(
        provider='groq',
        model_name='llama-3.3-70b-versatile',
        api_key=os.getenv('GROQ_API_KEY')
    )
    print("✓ Analyzer created successfully\n")
    
    # Create mock vulnerability data
    print("Step 2: Creating mock vulnerability data...")
    vulnerabilities = [
        {
            "title": "Insecure HTTP Communication",
            "description": "Application communicates over HTTP without encryption",
            "severity": "HIGH",
            "file": "MainActivity.java",
            "line": 45,
            "category": "NETWORK",
            "type": "cleartext_communication"
        },
        {
            "title": "Weak Cryptography", 
            "description": "Application uses MD5 hashing algorithm",
            "severity": "MEDIUM",
            "file": "CryptoUtils.java", 
            "line": 23,
            "category": "CRYPTO",
            "type": "weak_hash"
        }
    ]
    print(f"✓ Created {len(vulnerabilities)} mock vulnerabilities\n")
    
    # Test AI analysis
    print("Step 3: Testing AI vulnerability analysis...")
    try:
        results = analyzer.analyze_vulnerability_batch(vulnerabilities)
        print("✓ AI analysis completed successfully!")
        print(f"✓ Analyzed {len(results)} vulnerabilities")
        
        for i, result in enumerate(results, 1):
            print(f"\nVulnerability {i}:")
            print(f"  - Title: {result.title}")
            print(f"  - Severity: {result.severity.value}")
            print(f"  - Category: {result.category.value}")
            print(f"  - Confidence: {result.confidence_score}")
            print(f"  - Business Impact: {result.business_impact}")
            if result.remediation_steps:
                print(f"  - Remediation Steps: {len(result.remediation_steps)} steps")
        
    except Exception as e:
        print(f"❌ AI analysis failed: {e}")
        return 1
    
    print("\n=== Test Summary ===")
    print("✅ Groq API: Working")
    print("✅ LangChain Integration: Working") 
    print("✅ Vulnerability Analysis: Working")
    print("✅ All tests passed!")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())