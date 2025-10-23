#!/usr/bin/env python3
"""
LangChain Mobile Security Agent Examples

This script demonstrates how to use the Mobile Security Agent
with the new LangChain and LangGraph architecture.
"""

import os
import sys
import asyncio
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from mobile_security_agent import (
    create_mobile_security_agent, 
    create_quick_agent,
    quick_scan,
    quick_scan_async,
    MobileSecurityAgentError
)
from langchain_config import create_config_manager, get_quick_config


def example_basic_usage():
    """
    Example 1: Basic usage with environment variables
    """
    print("🚀 Example 1: Basic Usage with Environment Variables")
    print("=" * 60)
    
    # Make sure you have these environment variables set:
    # - MOBSF_API_URL
    # - MOBSF_API_KEY  
    # - OPENAI_API_KEY or ANTHROPIC_API_KEY
    
    try:
        # Create agent with environment-based config
        agent = create_quick_agent()
        
        # Get status
        status = agent.get_scan_status()
        print(f"✅ Agent initialized successfully")
        print(f"🤖 AI Provider: {status['configuration']['ai_provider']}")
        print(f"🧠 AI Model: {status['configuration']['ai_model']}")
        print(f"⚡ Parallel Scanning: {status['configuration']['parallel_scanning_enabled']}")
        
    except Exception as e:
        print(f"❌ Failed to initialize agent: {e}")
        print("Make sure your environment variables are set properly")


def example_config_file_usage():
    """
    Example 2: Using configuration files
    """
    print("\n🚀 Example 2: Configuration File Usage")
    print("=" * 60)
    
    try:
        # Create configuration manager
        config_manager = create_config_manager('./config.json', './.env')
        
        # Create default config if it doesn't exist
        if not Path('./config.json').exists():
            config_path = config_manager.create_default_config_file('./config.json')
            print(f"📝 Created default config: {config_path}")
            print("Edit the config file with your API keys before running scans")
            return
        
        # Create agent with config file
        agent = create_mobile_security_agent('./config.json', './.env')
        
        # Validate configuration
        validation = config_manager.validate_configuration()
        if validation['valid']:
            print("✅ Configuration is valid")
        else:
            print("❌ Configuration has issues:")
            for error in validation['errors']:
                print(f"   - {error}")
            
    except Exception as e:
        print(f"❌ Configuration example failed: {e}")


async def example_async_scanning():
    """
    Example 3: Asynchronous scanning with LangGraph workflows
    """
    print("\n🚀 Example 3: Async Scanning with LangGraph")
    print("=" * 60)
    
    # Example APK file path (you need to provide a real APK file)
    apk_file = "./sample_app.apk"
    
    if not Path(apk_file).exists():
        print(f"⚠️  Sample APK file not found: {apk_file}")
        print("Place an APK file at that location to run this example")
        return
    
    try:
        agent = create_quick_agent()
        
        print(f"📱 Starting async scan of: {apk_file}")
        
        # Perform async scan
        result = await agent.scan_mobile_app_async(
            file_path=apk_file,
            app_name="Sample App",
            report_formats=['html', 'json']
        )
        
        # Display results
        summary = result.get_summary()
        print(f"✅ Scan completed!")
        print(f"📊 Found {summary.get('total_vulnerabilities', 0)} vulnerabilities")
        print(f"🚨 Critical: {summary.get('critical_count', 0)}")
        print(f"⚠️  High: {summary.get('high_count', 0)}")
        
        # Show generated reports
        print("\n📄 Generated Reports:")
        if hasattr(result, 'reports'):
            for format_type, path in result.reports.items():
                print(f"   {format_type.upper()}: {path}")
        
    except FileNotFoundError:
        print(f"❌ APK file not found: {apk_file}")
    except MobileSecurityAgentError as e:
        print(f"❌ Scan failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")


async def example_batch_scanning():
    """
    Example 4: Batch scanning with parallel processing
    """
    print("\n🚀 Example 4: Batch Scanning with Parallel Processing")
    print("=" * 60)
    
    # Example directory with APK files
    apk_directory = "./test_apps"
    
    if not Path(apk_directory).exists():
        print(f"⚠️  Test apps directory not found: {apk_directory}")
        print("Create the directory and add some APK files to run this example")
        return
    
    # Find APK files
    apk_files = list(Path(apk_directory).glob("*.apk"))
    
    if not apk_files:
        print(f"⚠️  No APK files found in: {apk_directory}")
        return
    
    try:
        agent = create_quick_agent()
        
        print(f"📱 Starting batch scan of {len(apk_files)} APK files")
        print(f"⚡ Parallel processing enabled")
        
        # Perform batch scan with parallel processing
        results = await agent.scan_multiple_apps_async(
            file_paths=[str(f) for f in apk_files],
            report_formats=['html', 'json'],
            parallel=True
        )
        
        print(f"\n✅ Batch scan completed: {len(results)}/{len(apk_files)} successful")
        
        # Summary statistics
        total_vulns = sum(r.get_summary().get('total_vulnerabilities', 0) for r in results)
        total_critical = sum(r.get_summary().get('critical_count', 0) for r in results)
        
        print(f"📊 Total vulnerabilities found: {total_vulns}")
        print(f"🚨 Total critical vulnerabilities: {total_critical}")
        
    except Exception as e:
        print(f"❌ Batch scan failed: {e}")


def example_workflow_persistence():
    """
    Example 5: Workflow persistence and resumption
    """
    print("\n🚀 Example 5: Workflow Persistence and Resumption")
    print("=" * 60)
    
    try:
        agent = create_quick_agent()
        
        # Check if there are any persisted workflows
        # Note: This would require implementing workflow listing in the agent
        print("🔍 Checking for persisted workflows...")
        
        # In a real scenario, you might have interrupted workflows that can be resumed
        # workflow_id = "interrupted_workflow_123"
        # result = agent.resume_workflow(workflow_id)
        
        print("💡 Workflow persistence allows you to:")
        print("   - Resume interrupted scans")
        print("   - Save processing state between steps")
        print("   - Handle system crashes gracefully")
        print("   - Implement checkpoint recovery")
        
    except Exception as e:
        print(f"❌ Workflow persistence example failed: {e}")


def example_quick_scan():
    """
    Example 6: Quick scan utility function
    """
    print("\n🚀 Example 6: Quick Scan Utility")
    print("=" * 60)
    
    apk_file = "./sample_app.apk"
    
    if not Path(apk_file).exists():
        print(f"⚠️  Sample APK file not found: {apk_file}")
        print("This is just a demonstration of the quick scan API")
        return
    
    try:
        print(f"📱 Quick scanning: {apk_file}")
        
        # Use the quick scan utility function
        # result = quick_scan(apk_file, output_formats=['html', 'json'])
        
        print("💡 The quick_scan() function provides:")
        print("   - Minimal setup required")
        print("   - Environment-based configuration")
        print("   - Standard report formats")
        print("   - Ideal for scripts and automation")
        
    except Exception as e:
        print(f"❌ Quick scan example failed: {e}")


def example_ai_configuration():
    """
    Example 7: AI Provider Configuration
    """
    print("\n🚀 Example 7: AI Provider Configuration")
    print("=" * 60)
    
    try:
        # Show different AI provider configurations
        print("🤖 Supported AI Providers:")
        print("   1. OpenAI (GPT-4, GPT-3.5-turbo)")
        print("   2. Anthropic (Claude-3, Claude-2)")
        
        print("\n📝 Configuration Examples:")
        
        print("\n🔹 OpenAI Configuration:")
        openai_config = {
            "ai_provider": {
                "provider": "openai",
                "model_name": "gpt-4",
                "api_key": "your_openai_api_key",
                "temperature": 0.1,
                "max_tokens": 2000
            }
        }
        print(f"   {openai_config}")
        
        print("\n🔹 Anthropic Configuration:")
        anthropic_config = {
            "ai_provider": {
                "provider": "anthropic", 
                "model_name": "claude-3-sonnet-20240229",
                "api_key": "your_anthropic_api_key",
                "temperature": 0.1,
                "max_tokens": 2000
            }
        }
        print(f"   {anthropic_config}")
        
    except Exception as e:
        print(f"❌ AI configuration example failed: {e}")


async def main():
    """
    Run all examples
    """
    print("🔍 Mobile Security Agent - LangChain Architecture Examples")
    print("=" * 80)
    
    # Run all examples
    example_basic_usage()
    example_config_file_usage()
    await example_async_scanning()
    await example_batch_scanning()
    example_workflow_persistence()
    example_quick_scan()
    example_ai_configuration()
    
    print("\n🎉 Examples completed!")
    print("\n📚 Additional Resources:")
    print("   - Run 'python agent.py --help' for CLI usage")
    print("   - Edit config.json for custom configuration")
    print("   - Check README.md for detailed setup instructions")


if __name__ == "__main__":
    asyncio.run(main())