#!/usr/bin/env python3
"""
Mobile Security Agent CLI

Command-line interface for the Mobile Security Agent that automates
mobile application security scanning using MobSF API and AI analysis.
"""

import sys
import os
import click
import json
import logging
from pathlib import Path
from typing import List, Dict, Any

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from mobile_security_agent import create_mobile_security_agent, MobileSecurityAgentError
from langchain_config import create_config_manager, ConfigurationError


@click.group()
@click.option('--config', '-c', default=None, help='Configuration file path')
@click.option('--env-file', '-e', default=None, help='Environment file path')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose logging')
@click.pass_context
def cli(ctx, config, env_file, verbose):
    """
    Mobile Security Agent - Automated mobile app security scanning with AI analysis
    
    This tool integrates MobSF for security scanning and Hugging Face AI for
    intelligent vulnerability analysis and prioritization.
    """
    # Ensure context object exists
    ctx.ensure_object(dict)
    
    # Set up logging level
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Load configuration
    try:
        config_manager = create_config_manager(config, env_file)
        config_manager.setup_logging()
        ctx.obj['config'] = config_manager.get_config()
        ctx.obj['config_manager'] = config_manager
        
        # Validate configuration
        validation = config_manager.validate_configuration()
        if not validation['valid']:
            click.echo("⚠️  Configuration validation failed:", err=True)
            for error in validation['errors']:
                click.echo(f"   Error: {error}", err=True)
            for missing in validation['missing_required']:
                click.echo(f"   Missing: {missing}", err=True)
            if validation['errors'] or validation['missing_required']:
                sys.exit(1)
        
        # Show warnings
        for warning in validation['warnings']:
            click.echo(f"⚠️  Warning: {warning}", err=True)
            
    except ConfigurationError as e:
        click.echo(f"❌ Configuration error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('file_path', type=click.Path(exists=True))
@click.option('--output-formats', '-f', multiple=True, 
              type=click.Choice(['html', 'pdf', 'json'], case_sensitive=False),
              default=['html', 'json'], help='Report formats to generate')
@click.option('--app-name', '-n', help='Application name (auto-detected if not provided)')
@click.option('--no-cleanup', is_flag=True, help='Keep scan data in MobSF after completion')
@click.option('--output-dir', '-o', help='Output directory for reports')
@click.pass_context
def scan(ctx, file_path, output_formats, app_name, no_cleanup, output_dir):
    """
    Scan a mobile application file (APK/IPA) for security vulnerabilities using LangChain AI
    
    FILE_PATH: Path to the APK or IPA file to scan
    
    Example:
        agent scan app.apk -f html -f pdf -n "My App"
    """
    config_manager = ctx.obj['config_manager']
    config = ctx.obj['config']
    
    # Override output directory if provided
    if output_dir:
        config.reports.output_dir = output_dir
    
    click.echo("🚀 Starting mobile application security scan with LangChain AI...")
    click.echo(f"📱 File: {file_path}")
    click.echo(f"🤖 AI Model: {config.ai_provider.model_name} ({config.ai_provider.provider})")
    click.echo(f"📊 Report formats: {', '.join(output_formats)}")
    
    try:
        # Create agent with new architecture
        agent = create_mobile_security_agent(
            config_file=config_manager.config_file,
            env_file=config_manager.env_file
        )
        
        # Perform scan using LangGraph workflow
        result = agent.scan_mobile_app(
            file_path=file_path,
            app_name=app_name,
            report_formats=list(output_formats),
            cleanup_scan=not no_cleanup
        )
        
        # Display results summary
        summary = result.get_summary()
        click.echo("\n✅ Scan completed successfully!")
        click.echo("📈 Vulnerability Summary:")
        click.echo(f"   📱 Application: {summary.get('app_name', 'Unknown')}")
        click.echo(f"   🔍 Total vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        click.echo(f"   🚨 Critical: {summary.get('critical_count', 0)}")
        click.echo(f"   ⚠️  High: {summary.get('high_count', 0)}")
        click.echo(f"   🔶 Medium: {summary.get('medium_count', 0)}")
        click.echo(f"   🔷 Low: {summary.get('low_count', 0)}")
        
        # Show AI analysis insights
        click.echo(f"\n🤖 AI Analysis:")
        click.echo(f"   📊 Model: {config.ai_provider.model_name}")
        click.echo(f"   ⏱️  Processing time: {summary.get('workflow_duration', 'Unknown')}")
        
        click.echo("\n📄 Generated Reports:")
        if hasattr(result, 'reports') and result.reports:
            for format_type, report_path in result.reports.items():
                click.echo(f"   {format_type.upper()}: {report_path}")
        else:
            click.echo("   No reports available in result")
        
    except MobileSecurityAgentError as e:
        click.echo(f"❌ Scan failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.argument('directory', type=click.Path(exists=True, file_okay=False, dir_okay=True))
@click.option('--output-formats', '-f', multiple=True,
              type=click.Choice(['html', 'pdf', 'json'], case_sensitive=False),
              default=['html', 'json'], help='Report formats to generate')
@click.option('--pattern', '-p', default='*.apk,*.ipa', help='File patterns to match')
@click.option('--output-dir', '-o', help='Output directory for reports')
@click.option('--parallel', is_flag=True, help='Enable parallel scanning with LangChain')
@click.pass_context
def batch_scan(ctx, directory, output_formats, pattern, output_dir, parallel):
    """
    Scan multiple mobile application files in a directory using LangChain workflows
    
    DIRECTORY: Directory containing APK/IPA files to scan
    
    Example:
        agent batch-scan ./apps --pattern "*.apk" -f html --parallel
    """
    config_manager = ctx.obj['config_manager']
    config = ctx.obj['config']
    
    # Override output directory if provided
    if output_dir:
        config.reports.output_dir = output_dir
    
    # Find files matching patterns
    directory_path = Path(directory)
    patterns = [p.strip() for p in pattern.split(',')]
    
    files_to_scan = []
    for pat in patterns:
        files_to_scan.extend(list(directory_path.glob(pat)))
    
    if not files_to_scan:
        click.echo(f"❌ No files found matching patterns: {pattern}")
        sys.exit(1)
    
    click.echo(f"🚀 Starting LangChain batch scan of {len(files_to_scan)} files...")
    click.echo(f"📁 Directory: {directory}")
    click.echo(f"🔍 Patterns: {pattern}")
    click.echo(f"🤖 AI Model: {config.ai_provider.model_name} ({config.ai_provider.provider})")
    click.echo(f"📊 Report formats: {', '.join(output_formats)}")
    click.echo(f"⚡ Parallel processing: {'Enabled' if parallel else 'Disabled'}")
    
    try:
        # Create agent with new architecture
        agent = create_mobile_security_agent(
            config_file=config_manager.config_file,
            env_file=config_manager.env_file
        )
        
        # Perform batch scan with LangGraph workflows
        results = agent.scan_multiple_apps(
            file_paths=[str(f) for f in files_to_scan],
            report_formats=list(output_formats),
            parallel=parallel
        )
        
        # Display results summary
        click.echo(f"\n✅ Batch scan completed: {len(results)}/{len(files_to_scan)} successful")
        
        total_vulns = 0
        total_critical = 0
        total_high = 0
        
        click.echo("\n📈 Results Summary:")
        for i, result in enumerate(results, 1):
            summary = result.get_summary()
            total_vulns += summary.get('total_vulnerabilities', 0)
            total_critical += summary.get('critical_count', 0)
            total_high += summary.get('high_count', 0)
            
            click.echo(f"   {i}. {summary.get('app_name', 'Unknown')}: "
                      f"{summary.get('total_vulnerabilities', 0)} vulns "
                      f"(🚨{summary.get('critical_count', 0)} critical, "
                      f"⚠️{summary.get('high_count', 0)} high)")
        
        click.echo(f"\n🎯 Overall Summary:")
        click.echo(f"   Total vulnerabilities: {total_vulns}")
        click.echo(f"   Critical vulnerabilities: {total_critical}")
        click.echo(f"   High vulnerabilities: {total_high}")
        
    except MobileSecurityAgentError as e:
        click.echo(f"❌ Batch scan failed: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Unexpected error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.pass_context
def status(ctx):
    """
    Check agent status and LangChain configuration
    """
    config = ctx.obj['config']
    config_manager = ctx.obj['config_manager']
    
    click.echo("🔍 Mobile Security Agent Status (LangChain Architecture)")
    click.echo("=" * 60)
    
    # Configuration validation
    validation = config_manager.validate_configuration()
    if validation['valid']:
        click.echo("✅ Configuration: Valid")
    else:
        click.echo("❌ Configuration: Invalid")
        for error in validation['errors']:
            click.echo(f"   Error: {error}")
    
    # Show warnings
    for warning in validation['warnings']:
        click.echo(f"⚠️  Warning: {warning}")
    
    # MobSF connection
    click.echo(f"🔗 MobSF API: {config.mobsf.api_url}")
    try:
        from mobsf_client import create_mobsf_client
        client = create_mobsf_client(config.mobsf.api_url, config.mobsf.api_key)
        # Try to get recent scans to test connection
        client.get_recent_scans(limit=1)
        click.echo("✅ MobSF Connection: OK")
    except Exception as e:
        click.echo(f"❌ MobSF Connection: Failed ({e})")
    
    # AI Provider configuration
    click.echo(f"🤖 AI Provider: {config.ai_provider.provider.upper()}")
    click.echo(f"🧠 AI Model: {config.ai_provider.model_name}")
    if config.ai_provider.api_key:
        click.echo("✅ AI API Key: Configured")
    else:
        click.echo("❌ AI API Key: Missing")
    
    # LangGraph workflow configuration
    click.echo(f"🔄 Workflow Persistence: {'Enabled' if config.workflow.enable_persistence else 'Disabled'}")
    click.echo(f"📊 Max Concurrent Workflows: {config.workflow.max_concurrent_workflows}")
    click.echo(f"⚡ Parallel Scanning: {'Enabled' if config.parallel_scanning else 'Disabled'}")
    
    # Directories
    click.echo(f"📁 Template Directory: {config.reports.template_dir}")
    click.echo(f"📁 Output Directory: {config.reports.output_dir}")
    click.echo(f"📁 Log File: {config.logging.log_file}")
    click.echo(f"🗃️  Checkpoint Path: {config.workflow.checkpoint_path}")
    
    # Check directory existence
    for name, path in [
        ("Templates", config.reports.template_dir),
        ("Reports", config.reports.output_dir),
        ("Logs", Path(config.logging.log_file).parent),
        ("Checkpoints", Path(config.workflow.checkpoint_path).parent)
    ]:
        if os.path.exists(path):
            click.echo(f"✅ {name} directory exists")
        else:
            click.echo(f"⚠️  {name} directory missing: {path}")
    
    # Try to create agent to test initialization
    try:
        from mobile_security_agent import create_mobile_security_agent
        agent = create_mobile_security_agent(
            config_file=config_manager.config_file,
            env_file=config_manager.env_file
        )
        agent_status = agent.get_scan_status()
        click.echo("✅ Agent Initialization: OK")
        click.echo(f"📈 Scan History: {agent_status['scan_history_count']} scans")
    except Exception as e:
        click.echo(f"❌ Agent Initialization: Failed ({e})")


@cli.command()
@click.option('--file', '-f', help='Output file path', default='./config.json')
@click.option('--force', is_flag=True, help='Overwrite existing file')
def init_config(file, force):
    """
    Create a default LangChain configuration file
    """
    config_path = Path(file)
    
    if config_path.exists() and not force:
        click.echo(f"❌ Configuration file already exists: {file}")
        click.echo("Use --force to overwrite")
        sys.exit(1)
    
    try:
        from langchain_config import create_config_manager
        manager = create_config_manager()
        created_path = manager.create_default_config_file(file)
        
        click.echo(f"✅ Created default LangChain configuration file: {created_path}")
        click.echo("\n📝 Next steps:")
        click.echo("1. Edit the configuration file with your API keys:")
        click.echo(f"   - MobSF API URL and key")
        click.echo(f"   - OpenAI or Anthropic API key (ai_provider section)")
        click.echo("2. Set environment variables:")
        click.echo(f"   - MOBSF_API_URL and MOBSF_API_KEY")
        click.echo(f"   - OPENAI_API_KEY or ANTHROPIC_API_KEY")
        click.echo("3. Choose your AI provider: 'openai' or 'anthropic'")
        click.echo("4. Run 'agent status' to verify configuration")
        
    except Exception as e:
        click.echo(f"❌ Failed to create configuration file: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--format', 'output_format', type=click.Choice(['json', 'yaml'], case_sensitive=False),
              default='json', help='Output format')
@click.pass_context
def show_config(ctx, output_format):
    """
    Display current configuration
    """
    config = ctx.obj['config']
    
    try:
        if output_format.lower() == 'json':
            # Convert to dictionary and display as JSON
            config_dict = config.dict()
            click.echo(json.dumps(config_dict, indent=2))
        else:
            # YAML output would require PyYAML
            click.echo("YAML output not implemented. Use JSON format.")
            
    except Exception as e:
        click.echo(f"❌ Failed to display configuration: {e}", err=True)
        sys.exit(1)


@cli.command()
def version():
    """
    Show version information
    """
    click.echo("Mobile Security Agent v2.0.0 (LangChain Architecture)")
    click.echo("Automated mobile application security scanning with advanced AI analysis")
    click.echo("")
    click.echo("🏗️  Architecture:")
    click.echo("  - LangChain: AI workflow orchestration")
    click.echo("  - LangGraph: State-based processing workflows")
    click.echo("  - MobSF API: Mobile security scanning")
    click.echo("  - OpenAI/Anthropic: Advanced AI analysis")
    click.echo("  - Multi-format reports: HTML, PDF, JSON")
    click.echo("")
    click.echo("🚀 Key Features:")
    click.echo("  - Intelligent vulnerability categorization")
    click.echo("  - AI-powered risk assessment")
    click.echo("  - Workflow persistence and resumption")
    click.echo("  - Parallel processing support")
    click.echo("  - Executive summary generation")
    click.echo("")
    click.echo("For more information, visit: https://github.com/your-repo/mobile-security-agent")


if __name__ == '__main__':
    # Handle SIGINT gracefully
    import signal
    
    def signal_handler(sig, frame):
        click.echo("\n\n⚠️  Interrupted by user")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    # Run CLI
    cli()