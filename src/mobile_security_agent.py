"""
Mobile Security Agent

Main orchestrator class that coordinates the entire workflow:
1. Upload mobile app to MobSF
2. Perform security scan
3. Extract vulnerabilities
4. Analyze with AI
5. Generate comprehensive reports
"""

import os
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

from mobsf_client import create_mobsf_client, MobSFClient, MobSFAPIError
from langchain_analyzer import LangChainVulnerabilityAnalyzer, VulnerabilityAnalysis
from vulnerability_extractor import create_vulnerability_extractor, VulnerabilityExtractor
from report_generator import create_report_generator, SecurityReportGenerator, ReportGenerationError
from security_workflow import SecurityAnalysisWorkflow, SecurityAnalysisState
from langchain_config import ConfigManager, AgentConfig, create_config_manager

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/agent.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


class MobileSecurityAgentError(Exception):
    """Custom exception for Mobile Security Agent errors"""
    pass


class ScanResult:
    """Container for scan results and metadata"""
    
    def __init__(self, 
                 app_info: Dict[str, Any],
                 raw_scan_data: Dict[str, Any],
                 vulnerabilities: List[Dict[str, Any]],
                 ai_analyses: List[VulnerabilityAnalysis],
                 categorized_vulnerabilities: Dict[str, List[VulnerabilityAnalysis]],
                 executive_summary: str,
                 statistics: Dict[str, Any],
                 generated_reports: Dict[str, str]):
        
        self.app_info = app_info
        self.raw_scan_data = raw_scan_data
        self.vulnerabilities = vulnerabilities
        self.ai_analyses = ai_analyses
        self.categorized_vulnerabilities = categorized_vulnerabilities
        self.executive_summary = executive_summary
        self.statistics = statistics
        self.generated_reports = generated_reports
        self.scan_completed_at = datetime.now()
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of the scan results"""
        return {
            'app_name': self.app_info.get('app_name', 'Unknown'),
            'total_vulnerabilities': len(self.ai_analyses),
            'critical_count': len(self.categorized_vulnerabilities.get('Critical', [])),
            'high_count': len(self.categorized_vulnerabilities.get('High', [])),
            'medium_count': len(self.categorized_vulnerabilities.get('Medium', [])),
            'low_count': len(self.categorized_vulnerabilities.get('Low', [])),
            'scan_completed_at': self.scan_completed_at.isoformat(),
            'reports_generated': list(self.generated_reports.keys())
        }


class MobileSecurityAgent:
    """
    Main agent class that orchestrates the complete mobile security scanning workflow
    using LangChain and LangGraph for AI-powered analysis
    """
    
    def __init__(self, 
                 config_file: str = None,
                 env_file: str = None):
        """
        Initialize the Mobile Security Agent with LangChain architecture
        
        Args:
            config_file (str): Path to configuration file
            env_file (str): Path to environment file
        """
        logger.info("Initializing Mobile Security Agent with LangChain architecture")
        
        # Load configuration
        try:
            self.config_manager = create_config_manager(config_file, env_file)
            self.config = self.config_manager.get_config()
            
            # Force correct API key if needed
            correct_api_key = os.getenv('MOBSF_API_KEY_OVERRIDE') or os.getenv('MOBSF_API_KEY')
            if not self.config.mobsf.api_key or (correct_api_key and self.config.mobsf.api_key != correct_api_key):
                logger.info(f"[DEBUG] Overriding API key from environment variable")
                self.config.mobsf.api_key = correct_api_key
            
            # Setup logging
            self.config_manager.setup_logging()
            
            # Validate configuration
            validation_results = self.config_manager.validate_configuration()
            if not validation_results['valid']:
                logger.error(f"Configuration validation failed: {validation_results['errors']}")
                raise MobileSecurityAgentError(f"Invalid configuration: {validation_results['errors']}")
            
            if validation_results['warnings']:
                for warning in validation_results['warnings']:
                    logger.warning(warning)
            
            logger.info("Configuration loaded and validated successfully")
            
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise MobileSecurityAgentError(f"Configuration loading failed: {e}")
        
        # Initialize components with new architecture
        try:
            # Debug output for MobSF config
            logger.info(f"[DEBUG] MobSF API URL: {self.config.mobsf.api_url}")
            logger.info(f"[DEBUG] MobSF API Key: {self.config.mobsf.api_key[:10]}...")
            
            # MobSF client
            self.mobsf_client = create_mobsf_client(
                self.config.mobsf.api_url, 
                self.config.mobsf.api_key
            )
            
            # LangChain AI analyzer
            self.ai_analyzer = LangChainVulnerabilityAnalyzer(
                provider=self.config.ai_provider.provider,
                model_name=self.config.ai_provider.model_name,
                api_key=self.config.ai_provider.api_key,
                temperature=self.config.ai_provider.temperature,
                max_tokens=self.config.ai_provider.max_tokens,
                ollama_base_url=getattr(self.config.ai_provider, 'ollama_base_url', 'http://localhost:11434')
            )
            
            # Vulnerability extractor
            self.vulnerability_extractor = create_vulnerability_extractor()
            
            # Report generator
            self.report_generator = create_report_generator(
                self.config.reports.template_dir, 
                self.config.reports.output_dir
            )
            
            # Security workflow using LangGraph
            self.workflow = SecurityAnalysisWorkflow(
                ai_analyzer=self.ai_analyzer,
                mobsf_client=self.mobsf_client,
                vulnerability_extractor=self.vulnerability_extractor,
                report_generator=self.report_generator,
                config=self.config
            )
            
            logger.info("All agent components initialized successfully with LangChain architecture")
            
        except Exception as e:
            logger.error(f"Failed to initialize agent components: {e}")
            raise MobileSecurityAgentError(f"Agent initialization failed: {e}")
        
        # State tracking
        self.current_scan = None
        self.scan_history = []
    
    async def scan_mobile_app_async(self, 
                                  file_path: str,
                                  app_name: str = None,
                                  report_formats: List[str] = None,
                                  cleanup_scan: bool = True) -> ScanResult:
        """
        Perform complete mobile application security scan using LangGraph workflow
        
        Args:
            file_path (str): Path to APK/IPA file
            app_name (str): Application name (auto-detected if None)
            report_formats (List[str]): Report formats to generate
            cleanup_scan (bool): Whether to delete scan from MobSF after completion
            
        Returns:
            ScanResult: Complete scan results and reports
            
        Raises:
            MobileSecurityAgentError: If scan process fails
        """
        if report_formats is None:
            report_formats = self.config.reports.default_formats
        
        try:
            logger.info(f"Starting LangGraph-based security scan for: {file_path}")
            
            # Execute the complete workflow using LangGraph
            # Generate a unique thread_id for this analysis
            import uuid
            thread_id = f"scan_{uuid.uuid4().hex[:8]}"
            
            final_state = self.workflow.analyze_mobile_app(
                app_file_path=file_path,
                config=self.config.dict() if hasattr(self.config, 'dict') else {},
                thread_id=thread_id
            )
            
            # Check for errors (final_state is a dict)
            if final_state.get("status") == "error" or final_state.get("current_step") == "failed":
                error_msg = final_state.get("errors", ["Unknown workflow error"])[0] if final_state.get("errors") else "Unknown workflow error"
                logger.error(f"Workflow failed: {error_msg}")
                raise MobileSecurityAgentError(f"Scan workflow failed: {error_msg}")
            
            # Create scan result object (final_state is a dict)
            scan_result = ScanResult(
                app_info=final_state.get("app_info", {}),
                raw_scan_data=final_state.get("raw_scan_results", {}),
                vulnerabilities=final_state.get("filtered_vulnerabilities", []),
                ai_analyses=final_state.get("vulnerability_analyses", []),
                categorized_vulnerabilities=final_state.get("categorized_vulnerabilities", {}),
                executive_summary=final_state.get("executive_summary", ""),
                statistics={
                    'scan_id': final_state.get("metadata", {}).get("workflow_id", "unknown"),
                    'timestamp': final_state.get("metadata", {}).get("start_time", datetime.now().isoformat()),
                    'file_path': file_path,
                    'app_name': final_state.get("app_info", {}).get("app_name", app_name or Path(file_path).stem),
                    'workflow_duration': 0,
                    'total_vulnerabilities': len(final_state.get("vulnerability_analyses", [])),
                    'ai_model_used': self.config.ai_provider.model_name,
                    'ai_provider': self.config.ai_provider.provider
                },
                generated_reports=final_state.get("generated_reports", {})
            )
            
            # Store in scan history
            self.current_scan = scan_result
            self.scan_history.append(scan_result)
            
            app_name_log = final_state.get("app_info", {}).get("app_name", "Unknown")
            logger.info(f"LangGraph workflow completed successfully for {app_name_log}")
            logger.info(f"Found {len(final_state.get('vulnerability_analyses', []))} vulnerabilities")
            logger.info(f"Generated {len(final_state.get('generated_reports', {}))} reports")
            
            return scan_result
            
        except Exception as e:
            logger.error(f"Mobile app scan failed: {e}")
            raise MobileSecurityAgentError(f"Scan failed: {e}")
    
    def scan_mobile_app(self, 
                       file_path: str,
                       app_name: str = None,
                       report_formats: List[str] = None,
                       cleanup_scan: bool = True) -> ScanResult:
        """
        Synchronous wrapper for async scan method
        
        Args:
            file_path (str): Path to APK/IPA file
            app_name (str): Application name (auto-detected if None)
            report_formats (List[str]): Report formats to generate
            cleanup_scan (bool): Whether to delete scan from MobSF after completion
            
        Returns:
            ScanResult: Complete scan results and reports
        """
        return asyncio.run(self.scan_mobile_app_async(
            file_path, app_name, report_formats, cleanup_scan
        ))
    
    async def scan_multiple_apps_async(self, 
                                     file_paths: List[str],
                                     report_formats: List[str] = None,
                                     parallel: bool = False) -> List[ScanResult]:
        """
        Scan multiple mobile applications using LangGraph workflows
        
        Args:
            file_paths (List[str]): List of APK/IPA file paths
            report_formats (List[str]): Report formats to generate
            parallel (bool): Whether to run scans in parallel
            
        Returns:
            List[ScanResult]: List of scan results
        """
        logger.info(f"Starting batch scan of {len(file_paths)} applications")
        
        if report_formats is None:
            report_formats = self.config.reports.default_formats
        
        results = []
        
        if parallel and self.config.parallel_scanning:
            # Parallel scanning with concurrency limits
            max_concurrent = min(
                self.config.max_concurrent_scans, 
                self.config.workflow.max_concurrent_workflows
            )
            
            semaphore = asyncio.Semaphore(max_concurrent)
            
            async def scan_with_semaphore(file_path: str) -> Optional[ScanResult]:
                async with semaphore:
                    try:
                        return await self.scan_mobile_app_async(
                            file_path, report_formats=report_formats
                        )
                    except Exception as e:
                        logger.error(f"Failed to scan {file_path}: {e}")
                        return None
            
            # Execute parallel scans
            scan_tasks = [scan_with_semaphore(fp) for fp in file_paths]
            scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Filter successful results
            for result in scan_results:
                if isinstance(result, ScanResult):
                    results.append(result)
        else:
            # Sequential scanning
            for i, file_path in enumerate(file_paths, 1):
                logger.info(f"Scanning application {i}/{len(file_paths)}: {file_path}")
                try:
                    result = await self.scan_mobile_app_async(
                        file_path, report_formats=report_formats
                    )
                    results.append(result)
                except Exception as e:
                    logger.error(f"Failed to scan {file_path}: {e}")
                    continue
        
        logger.info(f"Batch scan completed: {len(results)}/{len(file_paths)} successful")
        return results
    
    def scan_multiple_apps(self, 
                          file_paths: List[str],
                          report_formats: List[str] = None,
                          parallel: bool = False) -> List[ScanResult]:
        """
        Synchronous wrapper for batch scanning
        
        Args:
            file_paths (List[str]): List of APK/IPA file paths
            report_formats (List[str]): Report formats to generate
            parallel (bool): Whether to run scans in parallel
            
        Returns:
            List[ScanResult]: List of scan results
        """
        return asyncio.run(self.scan_multiple_apps_async(
            file_paths, report_formats, parallel
        ))
    
    def get_scan_status(self) -> Dict[str, Any]:
        """
        Get current agent status and scan information
        
        Returns:
            Dict[str, Any]: Agent status information
        """
        status = {
            'agent_initialized': True,
            'architecture': 'LangChain + LangGraph',
            'components': {
                'mobsf_client': self.mobsf_client is not None,
                'ai_analyzer': self.ai_analyzer is not None,
                'vulnerability_extractor': self.vulnerability_extractor is not None,
                'report_generator': self.report_generator is not None,
                'workflow': self.workflow is not None
            },
            'configuration': {
                'ai_provider': self.config.ai_provider.provider,
                'ai_model': self.config.ai_provider.model_name,
                'scan_timeout': self.config.mobsf.scan_timeout,
                'ai_batch_size': self.config.ai_provider.batch_size,
                'min_severity_filter': self.config.vulnerabilities.min_severity,
                'parallel_scanning_enabled': self.config.parallel_scanning,
                'workflow_persistence': self.config.workflow.enable_persistence
            },
            'scan_history_count': len(self.scan_history),
            'last_scan': None
        }
        
        if self.current_scan:
            status['last_scan'] = self.current_scan.get_summary()
        
        return status
    
    def generate_additional_report(self, 
                                 scan_result: ScanResult,
                                 format_type: str,
                                 custom_template: str = None) -> str:
        """
        Generate additional report for existing scan result
        
        Args:
            scan_result (ScanResult): Existing scan result
            format_type (str): Report format ('html', 'pdf', 'json')
            custom_template (str): Custom template name (for HTML reports)
            
        Returns:
            str: Path to generated report
        """
        logger.info(f"Generating additional {format_type} report")
        
        try:
            if format_type.lower() == 'html':
                template_name = custom_template or 'report_template.html'
                report_data = self.report_generator.generate_report_data(
                    scan_result.app_info,
                    scan_result.categorized_vulnerabilities,
                    scan_result.executive_summary,
                    scan_result.statistics
                )
                return self.report_generator.generate_html_report(report_data, template_name)
            
            elif format_type.lower() == 'pdf':
                report_data = self.report_generator.generate_report_data(
                    scan_result.app_info,
                    scan_result.categorized_vulnerabilities,
                    scan_result.executive_summary,
                    scan_result.statistics
                )
                return self.report_generator.generate_pdf_report(report_data)
            
            elif format_type.lower() == 'json':
                report_data = self.report_generator.generate_report_data(
                    scan_result.app_info,
                    scan_result.categorized_vulnerabilities,
                    scan_result.executive_summary,
                    scan_result.statistics
                )
                return self.report_generator.generate_json_report(report_data)
            
            else:
                raise ValueError(f"Unsupported report format: {format_type}")
                
        except Exception as e:
            logger.error(f"Failed to generate additional report: {e}")
            raise MobileSecurityAgentError(f"Report generation failed: {e}")
    
    def get_workflow_state(self, workflow_id: str = None) -> Optional[Dict[str, Any]]:
        """
        Get current or specific workflow state
        
        Args:
            workflow_id (str): Specific workflow ID (None for current)
            
        Returns:
            Optional[Dict[str, Any]]: Workflow state information
        """
        try:
            return self.workflow.get_workflow_state(workflow_id)
        except Exception as e:
            logger.error(f"Failed to get workflow state: {e}")
            return None
    
    def resume_workflow(self, workflow_id: str) -> ScanResult:
        """
        Resume a previously interrupted workflow
        
        Args:
            workflow_id (str): Workflow ID to resume
            
        Returns:
            ScanResult: Completed scan result
        """
        logger.info(f"Resuming workflow: {workflow_id}")
        
        try:
            final_state = asyncio.run(self.workflow.resume_workflow(workflow_id))
            
            if final_state.get("status") == "error" or final_state.get("current_step") == "failed":
                error_msg = final_state.get("errors", ["Unknown workflow error"])[0] if final_state.get("errors") else "Unknown workflow error"
                raise MobileSecurityAgentError(f"Resumed workflow failed: {error_msg}")
            
            # Create scan result from resumed workflow
            scan_result = ScanResult(
                app_info=final_state.get("app_info", {}),
                raw_scan_data=final_state.get("raw_scan_results", {}),
                vulnerabilities=final_state.get("filtered_vulnerabilities", []),
                ai_analyses=final_state.get("vulnerability_analyses", []),
                categorized_vulnerabilities=final_state.get("categorized_vulnerabilities", {}),
                executive_summary=final_state.get("executive_summary", ""),
                statistics={
                    'scan_id': final_state.get("metadata", {}).get("workflow_id", "unknown"),
                    'timestamp': final_state.get("metadata", {}).get("start_time", datetime.now().isoformat()),
                    'file_path': final_state.get("app_file_path", ""),
                    'app_name': final_state.get("app_info", {}).get("app_name", "Unknown"),
                    'workflow_duration': 0,
                    'total_vulnerabilities': len(final_state.get("vulnerability_analyses", [])),
                    'ai_model_used': self.config.ai_provider.model_name,
                    'ai_provider': self.config.ai_provider.provider,
                    'resumed_from': workflow_id
                },
                generated_reports=final_state.get("generated_reports", {})
            )
            
            # Store in scan history
            self.current_scan = scan_result
            self.scan_history.append(scan_result)
            
            logger.info(f"Successfully resumed and completed workflow: {workflow_id}")
            return scan_result
            
        except Exception as e:
            logger.error(f"Failed to resume workflow {workflow_id}: {e}")
            raise MobileSecurityAgentError(f"Workflow resume failed: {e}")
    
    def _validate_input_file(self, file_path: str) -> None:
        """Validate input mobile app file"""
        if not os.path.exists(file_path):
            raise MobileSecurityAgentError(f"File not found: {file_path}")
        
        file_ext = Path(file_path).suffix.lower()
        if file_ext not in ['.apk', '.ipa']:
            raise MobileSecurityAgentError(f"Unsupported file format: {file_ext}")
        
        file_size = os.path.getsize(file_path)
        max_size = self.config.reports.max_report_size_mb * 1024 * 1024
        if file_size > max_size:
            raise MobileSecurityAgentError(f"File too large: {file_size} bytes (max: {max_size})")
    
    def _log_scan_summary(self, scan_result: ScanResult) -> None:
        """Log scan summary information"""
        summary = scan_result.get_summary()
        
        logger.info("=== LANGCHAIN SCAN SUMMARY ===")
        logger.info(f"Application: {summary.get('app_name', 'Unknown')}")
        logger.info(f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        logger.info(f"Critical: {summary.get('critical_count', 0)}")
        logger.info(f"High: {summary.get('high_count', 0)}")
        logger.info(f"Medium: {summary.get('medium_count', 0)}")
        logger.info(f"Low: {summary.get('low_count', 0)}")
        logger.info(f"AI Model Used: {self.config.ai_provider.model_name}")
        logger.info(f"Reports Generated: {', '.join(summary.get('reports_generated', []))}")
        logger.info("==============================")


def create_mobile_security_agent(config_file: str = None, env_file: str = None, **kwargs) -> MobileSecurityAgent:
    """
    Factory function to create Mobile Security Agent with LangChain architecture
    
    Args:
        config_file (str): Path to configuration file
        env_file (str): Path to environment file
        **kwargs: Additional configuration parameters (deprecated)
        
    Returns:
        MobileSecurityAgent: Configured agent instance
        
    Raises:
        MobileSecurityAgentError: If agent creation fails
    """
    if kwargs:
        logger.warning("Keyword arguments are deprecated. Use configuration files instead.")
    
    return MobileSecurityAgent(config_file, env_file)


def create_quick_agent() -> MobileSecurityAgent:
    """
    Create agent with quick configuration from environment variables
    
    Returns:
        MobileSecurityAgent: Agent with environment-based configuration
    """
    return MobileSecurityAgent()


# Convenience function for quick scanning
def quick_scan(file_path: str, 
               output_formats: List[str] = None,
               config_file: str = None) -> ScanResult:
    """
    Quick scan function for immediate use with LangChain architecture
    
    Args:
        file_path (str): Path to mobile app file
        output_formats (List[str]): Report formats to generate
        config_file (str): Configuration file path
        
    Returns:
        ScanResult: Scan results
    """
    if output_formats is None:
        output_formats = ['html', 'json']
    
    agent = create_mobile_security_agent(config_file)
    return agent.scan_mobile_app(file_path, report_formats=output_formats)


async def quick_scan_async(file_path: str, 
                          output_formats: List[str] = None,
                          config_file: str = None) -> ScanResult:
    """
    Quick async scan function for immediate use
    
    Args:
        file_path (str): Path to mobile app file
        output_formats (List[str]): Report formats to generate
        config_file (str): Configuration file path
        
    Returns:
        ScanResult: Scan results
    """
    if output_formats is None:
        output_formats = ['html', 'json']
    
    agent = create_mobile_security_agent(config_file)
    return await agent.scan_mobile_app_async(file_path, report_formats=output_formats)