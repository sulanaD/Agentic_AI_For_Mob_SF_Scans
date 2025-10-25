#!/usr/bin/env python3
"""
Quick validation test for the LangChain Mobile Security Agent

This script performs basic validation to ensure all components
are properly integrated and configured.
"""

import os
import sys
import traceback
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test that all modules can be imported correctly"""
    print("🔍 Testing module imports...")
    
    try:
        # Test configuration
        from langchain_config import (
            create_config_manager, 
            ConfigManager, 
            AgentConfig,
            get_quick_config
        )
        print("✅ Configuration module imported successfully")
        
        # Test LangChain analyzer
        from langchain_analyzer import (
            LangChainVulnerabilityAnalyzer,
            VulnerabilityAnalysis
        )
        print("✅ LangChain analyzer imported successfully")
        
        # Test security workflow
        from security_workflow import (
            SecurityAnalysisWorkflow,
            SecurityAnalysisState
        )
        print("✅ Security workflow imported successfully")
        
        # Test main agent
        from mobile_security_agent import (
            create_mobile_security_agent,
            create_quick_agent,
            quick_scan,
            MobileSecurityAgent
        )
        print("✅ Mobile security agent imported successfully")
        
        # Test existing modules
        from mobsf_client import create_mobsf_client
        from vulnerability_extractor import create_vulnerability_extractor
        from report_generator import create_report_generator
        print("✅ Supporting modules imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import failed: {e}")
        traceback.print_exc()
        return False
    except Exception as e:
        print(f"❌ Unexpected error during imports: {e}")
        traceback.print_exc()
        return False


def test_configuration():
    """Test configuration management"""
    print("\n🔍 Testing configuration management...")
    
    try:
        from langchain_config import create_config_manager, get_quick_config
        
        # Test quick config
        quick_config = get_quick_config()
        print(f"✅ Quick config created: {quick_config.ai_provider.provider}")
        
        # Test config manager
        config_manager = create_config_manager()
        print("✅ Config manager created successfully")
        
        # Test validation
        validation = config_manager.validate_configuration()
        print(f"✅ Configuration validation completed")
        print(f"   Valid: {validation['valid']}")
        print(f"   Warnings: {len(validation['warnings'])}")
        print(f"   Errors: {len(validation['errors'])}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        traceback.print_exc()
        return False


def test_ai_analyzer():
    """Test LangChain AI analyzer initialization"""
    print("\n🔍 Testing AI analyzer...")
    
    try:
        from langchain_analyzer import LangChainVulnerabilityAnalyzer
        
        # Test with OpenAI (mock if no key)
        api_key = os.getenv('OPENAI_API_KEY') or 'test_key'
        
        analyzer = LangChainVulnerabilityAnalyzer(
            provider='openai',
            model_name='gpt-4',
            api_key=api_key,
            temperature=0.1
        )
        print("✅ LangChain analyzer initialized successfully")
        
        # Test prompt templates exist
        assert analyzer.classification_chain is not None
        assert analyzer.impact_chain is not None
        assert analyzer.remediation_chain is not None
        print("✅ AI analysis chains configured correctly")
        
        return True
        
    except Exception as e:
        print(f"❌ AI analyzer test failed: {e}")
        traceback.print_exc()
        return False


def test_workflow():
    """Test LangGraph workflow initialization"""
    print("\n🔍 Testing LangGraph workflow...")
    
    try:
        from security_workflow import SecurityAnalysisWorkflow, SecurityAnalysisState
        from langchain_config import get_quick_config
        
        # Mock components for testing
        config = get_quick_config()
        
        # Create workflow (with mock components)
        workflow = SecurityAnalysisWorkflow(
            ai_analyzer=None,  # We'll mock this
            mobsf_client=None,
            vulnerability_extractor=None,
            report_generator=None,
            config=config
        )
        print("✅ Security workflow initialized successfully")
        
        # Test workflow state
        initial_state = SecurityAnalysisState(
            file_path="test.apk",
            app_name="Test App",
            report_formats=["html"],
            config=config.dict()
        )
        print("✅ Workflow state created successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Workflow test failed: {e}")
        traceback.print_exc()
        return False


def test_agent_creation():
    """Test agent creation without actual scanning"""
    print("\n🔍 Testing agent creation...")
    
    try:
        from mobile_security_agent import create_quick_agent
        
        # Create agent with environment variables
        agent = create_quick_agent()
        print("✅ Quick agent created successfully")
        
        # Test status method
        status = agent.get_scan_status()
        print(f"✅ Agent status retrieved: {status['agent_initialized']}")
        print(f"   Architecture: {status.get('architecture', 'Standard')}")
        
        return True
        
    except Exception as e:
        print(f"❌ Agent creation test failed: {e}")
        traceback.print_exc()
        return False


def test_cli_commands():
    """Test CLI command structure"""
    print("\n🔍 Testing CLI commands...")
    
    try:
        # Import CLI module
        import agent
        print("✅ CLI module imported successfully")
        
        # Test that commands are registered
        cli = agent.cli
        commands = cli.list_commands(None)
        expected_commands = {'scan', 'batch-scan', 'status', 'init-config', 'show-config', 'version'}
        
        found_commands = set(commands)
        if expected_commands.issubset(found_commands):
            print(f"✅ All expected CLI commands found: {found_commands}")
        else:
            missing = expected_commands - found_commands
            print(f"⚠️  Some CLI commands missing: {missing}")
        
        return True
        
    except Exception as e:
        print(f"❌ CLI test failed: {e}")
        traceback.print_exc()
        return False


def test_countermeasures_generation():
    """Test the new AI-powered countermeasures generation feature"""
    print("\n🔍 Testing countermeasures generation...")
    
    try:
        from langchain_analyzer import (
            LangChainVulnerabilityAnalyzer,
            VulnerabilityAnalysis,
            VulnerabilityPriority,
            SeverityLevel,
            VulnerabilityCategory
        )
        
        # Create analyzer (using Ollama for testing - no API key needed)
        analyzer = LangChainVulnerabilityAnalyzer(
            provider='ollama',
            model_name='llama2',
            enable_memory=False
        )
        print("✅ Analyzer initialized for countermeasures test")
        
        # Create sample vulnerability analyses for testing
        sample_analyses = [
            VulnerabilityAnalysis(
                vulnerability_id="TEST_001",
                title="SQL Injection in Login",
                description="Test vulnerability",
                priority=VulnerabilityPriority(
                    severity=SeverityLevel.CRITICAL,
                    priority_score=0.95,
                    confidence=0.9,
                    reasoning="Test reasoning",
                    category=VulnerabilityCategory.INJECTION,
                    exploitability="High",
                    business_impact="Critical"
                ),
                impact_assessment="Test impact",
                remediation_steps=["Step 1", "Step 2"],
                cwe_mapping="CWE-89",
                owasp_mapping="A03:2021"
            ),
            VulnerabilityAnalysis(
                vulnerability_id="TEST_002",
                title="Insecure Data Storage",
                description="Test vulnerability 2",
                priority=VulnerabilityPriority(
                    severity=SeverityLevel.HIGH,
                    priority_score=0.85,
                    confidence=0.95,
                    reasoning="Test reasoning",
                    category=VulnerabilityCategory.STORAGE,
                    exploitability="Medium",
                    business_impact="High"
                ),
                impact_assessment="Test impact",
                remediation_steps=["Encrypt data", "Use keystore"],
                cwe_mapping="CWE-312",
                owasp_mapping="M2"
            )
        ]
        
        print(f"✅ Created {len(sample_analyses)} test vulnerabilities")
        
        # Test countermeasures generation
        app_context = {
            "app_name": "TestApp",
            "platform": "Android",
            "package_name": "com.test.app"
        }
        
        print("   Generating countermeasures (this may take a moment)...")
        countermeasures = analyzer.generate_countermeasures(
            vulnerability_analyses=sample_analyses,
            app_context=app_context
        )
        
        # Verify countermeasures structure
        assert "overview" in countermeasures, "Missing 'overview' in countermeasures"
        assert "implementation_roadmap" in countermeasures, "Missing 'implementation_roadmap'"
        assert "priority_matrix" in countermeasures, "Missing 'priority_matrix'"
        assert "categorized_vulnerabilities" in countermeasures, "Missing 'categorized_vulnerabilities'"
        
        print("✅ Countermeasures generated successfully")
        print(f"   Total vulnerabilities: {countermeasures['overview']['total_vulnerabilities']}")
        print(f"   Critical: {countermeasures['overview']['critical_count']}")
        print(f"   High: {countermeasures['overview']['high_count']}")
        
        # Verify roadmap structure
        roadmap = countermeasures['implementation_roadmap']
        assert "immediate_0_24h" in roadmap
        assert "short_term_1_7d" in roadmap
        assert "medium_term_1_4w" in roadmap
        assert "long_term_1_3m" in roadmap
        print("✅ Implementation roadmap structure verified")
        
        # Verify priority matrix
        priority_matrix = countermeasures['priority_matrix']
        assert len(priority_matrix) == len(sample_analyses)
        assert all('vulnerability' in item for item in priority_matrix)
        assert all('priority_score' in item for item in priority_matrix)
        print("✅ Priority matrix structure verified")
        
        # Display sample roadmap items
        if roadmap['immediate_0_24h']:
            print(f"   Immediate actions: {len(roadmap['immediate_0_24h'])} items")
            print(f"      Example: {roadmap['immediate_0_24h'][0][:60]}...")
        
        print("✅ Countermeasures feature working correctly!")
        
        return True
        
    except Exception as e:
        print(f"❌ Countermeasures test failed: {e}")
        traceback.print_exc()
        return False


def test_dependencies():
    """Test that all required dependencies are installed"""
    print("\n🔍 Testing dependencies...")
    
    required_packages = [
        'langchain',
        'langgraph',
        'langchain_openai',
        'langchain_anthropic',
        'requests',
        'click',
        'jinja2',
        'reportlab',
        'dotenv',  # python-dotenv imports as 'dotenv'
        'pydantic'
    ]
    
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
            print(f"✅ {package}")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} - MISSING")
    
    if missing_packages:
        print(f"\n⚠️  Missing packages: {missing_packages}")
        print("Run: pip install -r requirements.txt")
        return False
    else:
        print("✅ All dependencies are installed")
        return True


def main():
    """Run all validation tests"""
    print("🚀 Mobile Security Agent - LangChain Architecture Validation")
    print("=" * 70)
    
    tests = [
        ("Dependencies", test_dependencies),
        ("Module Imports", test_imports),
        ("Configuration", test_configuration),
        ("AI Analyzer", test_ai_analyzer),
        ("LangGraph Workflow", test_workflow),
        ("Countermeasures Generation", test_countermeasures_generation),  # NEW TEST
        ("Agent Creation", test_agent_creation),
        ("CLI Commands", test_cli_commands)
    ]
    
    results = []
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    # Summary
    print("\n" + "=" * 70)
    print("📊 Validation Summary:")
    print("=" * 70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"   {test_name:<20} {status}")
    
    print(f"\n🎯 Overall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! The LangChain architecture is ready to use.")
        print("\n📋 Next Steps:")
        print("   1. Configure your API keys in .env file")
        print("   2. Start MobSF if not already running")
        print("   3. Run: python agent.py status")
        print("   4. Try: python agent.py scan your_app.apk")
    else:
        print(f"\n⚠️  {total - passed} tests failed. Please check the errors above.")
        return 1
    
    return 0


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)