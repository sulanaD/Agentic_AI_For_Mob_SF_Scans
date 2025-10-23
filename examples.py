"""
Example usage script for the Mobile Security Agent

This script demonstrates how to use the agent programmatically
for scanning mobile applications and generating reports.
"""

import os
import sys
import logging
from pathlib import Path

# Add src directory to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from mobile_security_agent import create_mobile_security_agent, quick_scan
from config import create_config_manager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def example_single_scan():
    """Example: Scan a single mobile application"""
    print("🚀 Example: Single Application Scan")
    print("=" * 50)
    
    # NOTE: Replace with actual APK/IPA file path
    app_file = "path/to/your/app.apk"
    
    if not os.path.exists(app_file):
        print(f"❌ Example file not found: {app_file}")
        print("📝 Please update the 'app_file' variable with a valid APK/IPA path")
        return
    
    try:
        # Quick scan using environment variables
        result = quick_scan(
            file_path=app_file,
            output_formats=["html", "json"]
        )
        
        # Display results
        summary = result.get_summary()
        print(f"✅ Scan completed for: {summary['app_name']}")
        print(f"📊 Total vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"🚨 Critical: {summary['critical_count']}")
        print(f"⚠️  High: {summary['high_count']}")
        print(f"🔶 Medium: {summary['medium_count']}")
        print(f"🔷 Low: {summary['low_count']}")
        
        print("\n📄 Generated reports:")
        for format_type, path in result.generated_reports.items():
            print(f"  {format_type.upper()}: {path}")
        
    except Exception as e:
        print(f"❌ Scan failed: {e}")


def example_batch_scan():
    """Example: Batch scan multiple applications"""
    print("\n🚀 Example: Batch Application Scan")
    print("=" * 50)
    
    # NOTE: Replace with actual directory containing APK/IPA files
    apps_directory = "path/to/apps/directory"
    
    if not os.path.exists(apps_directory):
        print(f"❌ Example directory not found: {apps_directory}")
        print("📝 Please update the 'apps_directory' variable with a valid directory path")
        return
    
    try:
        # Find APK files in directory
        app_files = list(Path(apps_directory).glob("*.apk"))
        app_files.extend(list(Path(apps_directory).glob("*.ipa")))
        
        if not app_files:
            print(f"❌ No APK/IPA files found in: {apps_directory}")
            return
        
        print(f"📱 Found {len(app_files)} applications to scan")
        
        # Create agent with configuration
        agent = create_mobile_security_agent()
        
        # Perform batch scan
        results = agent.scan_multiple_apps(
            file_paths=[str(f) for f in app_files],
            report_formats=["html", "json"]
        )
        
        print(f"✅ Batch scan completed: {len(results)}/{len(app_files)} successful")
        
        # Summary statistics
        total_vulns = sum(len(r.ai_analyses) for r in results)
        total_critical = sum(len(r.categorized_vulnerabilities.get('Critical', [])) for r in results)
        
        print(f"📊 Total vulnerabilities found: {total_vulns}")
        print(f"🚨 Total critical vulnerabilities: {total_critical}")
        
    except Exception as e:
        print(f"❌ Batch scan failed: {e}")


def example_custom_agent():
    """Example: Create agent with custom configuration"""
    print("\n🚀 Example: Custom Agent Configuration")
    print("=" * 50)
    
    try:
        # Create agent with custom settings
        agent = create_mobile_security_agent(
            mobsf_api_url="http://localhost:8000",
            mobsf_api_key="your_custom_api_key",
            huggingface_token="your_huggingface_token",
            huggingface_model="microsoft/DialoGPT-medium",
            template_dir="./templates",
            output_dir="./custom_reports"
        )
        
        # Get agent status
        status = agent.get_scan_status()
        print("🔍 Agent Status:")
        print(f"  Components initialized: {status['components']}")
        print(f"  Scan timeout: {status['configuration']['scan_timeout']}s")
        print(f"  AI batch size: {status['configuration']['ai_batch_size']}")
        print(f"  Min severity filter: {status['configuration']['min_severity_filter']}")
        print(f"  Scan history: {status['scan_history_count']} scans")
        
    except Exception as e:
        print(f"❌ Custom agent creation failed: {e}")


def example_config_management():
    """Example: Configuration management"""
    print("\n🚀 Example: Configuration Management")
    print("=" * 50)
    
    try:
        # Create configuration manager
        config_manager = create_config_manager()
        
        # Get configuration
        config = config_manager.get_config()
        print("⚙️  Configuration loaded successfully")
        
        # Validate configuration
        validation = config_manager.validate_configuration()
        if validation['valid']:
            print("✅ Configuration is valid")
        else:
            print("❌ Configuration validation failed:")
            for error in validation['errors']:
                print(f"  Error: {error}")
            for missing in validation['missing_required']:
                print(f"  Missing: {missing}")
        
        # Show warnings
        for warning in validation['warnings']:
            print(f"⚠️  Warning: {warning}")
        
        # Display key configuration values
        print(f"🔗 MobSF URL: {config.mobsf.api_url}")
        print(f"🤖 AI Model: {config.huggingface.model_name}")
        print(f"📊 Report formats: {config.reports.default_formats}")
        print(f"📁 Output directory: {config.reports.output_dir}")
        
    except Exception as e:
        print(f"❌ Configuration management failed: {e}")


def example_report_analysis():
    """Example: Analyze generated reports"""
    print("\n🚀 Example: Report Analysis")
    print("=" * 50)
    
    # Check for existing reports
    reports_dir = Path("./reports")
    if not reports_dir.exists():
        print("❌ Reports directory not found. Run a scan first.")
        return
    
    # Find report files
    html_reports = list(reports_dir.glob("*.html"))
    json_reports = list(reports_dir.glob("*.json"))
    pdf_reports = list(reports_dir.glob("*.pdf"))
    
    print(f"📄 Found reports:")
    print(f"  HTML: {len(html_reports)}")
    print(f"  JSON: {len(json_reports)}")
    print(f"  PDF: {len(pdf_reports)}")
    
    # Analyze JSON reports
    if json_reports:
        import json
        print("\n📊 Report Analysis:")
        
        total_apps = 0
        total_vulns = 0
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        
        for json_report in json_reports[:5]:  # Analyze first 5 reports
            try:
                with open(json_report, 'r', encoding='utf-8') as f:
                    report_data = json.load(f)
                
                total_apps += 1
                app_vulns = sum(len(vulns) for vulns in report_data.get('vulnerabilities', {}).values())
                total_vulns += app_vulns
                
                for severity in severity_counts:
                    severity_counts[severity] += len(report_data.get('vulnerabilities', {}).get(severity, []))
                
                print(f"  📱 {report_data.get('app_name', 'Unknown')}: {app_vulns} vulnerabilities")
                
            except Exception as e:
                print(f"  ❌ Failed to analyze {json_report}: {e}")
        
        print(f"\n📈 Summary ({total_apps} apps):")
        print(f"  Total vulnerabilities: {total_vulns}")
        for severity, count in severity_counts.items():
            print(f"  {severity}: {count}")


def main():
    """Main example function"""
    print("🎯 Mobile Security Agent - Usage Examples")
    print("=" * 60)
    
    # Check if environment is set up
    if not os.path.exists('.env') and not os.path.exists('config.json'):
        print("⚠️  No configuration found!")
        print("📝 Please run: python agent.py init-config")
        print("📝 Then edit config.json with your API keys")
        return
    
    # Run examples
    try:
        example_config_management()
        example_custom_agent()
        example_single_scan()
        example_batch_scan()
        example_report_analysis()
        
        print("\n🎉 Examples completed!")
        print("📚 Check the README.md for more detailed usage instructions")
        
    except KeyboardInterrupt:
        print("\n⚠️  Examples interrupted by user")
    except Exception as e:
        print(f"\n❌ Examples failed: {e}")
        logger.error(f"Examples failed: {e}", exc_info=True)


if __name__ == "__main__":
    main()