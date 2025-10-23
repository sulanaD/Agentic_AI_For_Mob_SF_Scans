"""
LangGraph Security Analysis Workflow

This module implements a comprehensive graph-based workflow for mobile security analysis
using LangGraph to orchestrate the entire process from vulnerability extraction to report generation.
"""

import logging
from typing import Dict, List, Any, Optional, TypedDict, Annotated
from datetime import datetime
import json
from pathlib import Path

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.runnables import RunnablePassthrough

from langchain_analyzer import LangChainVulnerabilityAnalyzer, VulnerabilityAnalysis
from vulnerability_extractor import VulnerabilityExtractor
from mobsf_client import MobSFClient
from report_generator import SecurityReportGenerator

logger = logging.getLogger(__name__)


class SecurityAnalysisState(TypedDict):
    """Complete state for security analysis workflow"""
    # Input data
    app_file_path: str
    app_info: Dict[str, Any]
    
    # MobSF scan data
    mobsf_file_hash: Optional[str] 
    raw_scan_results: Optional[Dict[str, Any]]
    
    # Vulnerability processing
    extracted_vulnerabilities: List[Dict[str, Any]]
    filtered_vulnerabilities: List[Dict[str, Any]]
    
    # AI Analysis results
    vulnerability_analyses: List[VulnerabilityAnalysis]
    categorized_vulnerabilities: Dict[str, List[VulnerabilityAnalysis]]
    executive_summary: Optional[str]
    
    # Report generation
    generated_reports: Dict[str, str]
    report_data: Optional[Dict[str, Any]]
    
    # Workflow control
    current_step: str
    errors: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]
    
    # Configuration
    config: Dict[str, Any]


class SecurityAnalysisWorkflow:
    """
    Comprehensive security analysis workflow using LangGraph
    """
    
    def __init__(self,
                 mobsf_client: MobSFClient,
                 ai_analyzer: LangChainVulnerabilityAnalyzer,
                 vulnerability_extractor: VulnerabilityExtractor,
                 report_generator: SecurityReportGenerator,
                 config: Optional[Dict[str, Any]] = None,
                 enable_persistence: bool = True,
                 checkpoint_path: str = "./checkpoints/security_analysis.db"):
        """
        Initialize the security analysis workflow
        
        Args:
            mobsf_client: MobSF API client
            ai_analyzer: LangChain-based AI analyzer
            vulnerability_extractor: Vulnerability extraction engine
            report_generator: Report generation system
            config: Optional configuration dictionary
            enable_persistence: Enable workflow state persistence
            checkpoint_path: Path for checkpoint database
        """
        self.mobsf_client = mobsf_client
        self.ai_analyzer = ai_analyzer
        self.vulnerability_extractor = vulnerability_extractor
        self.report_generator = report_generator
        self.config = config or {}
        
        self.enable_persistence = enable_persistence
        self.checkpoint_path = checkpoint_path
        
        # Initialize checkpointer if persistence enabled
        self.checkpointer = None
        if enable_persistence:
            Path(checkpoint_path).parent.mkdir(parents=True, exist_ok=True)
            self.checkpointer = MemorySaver()
        
        # Build workflow
        self._build_workflow()
        
        logger.info("Security analysis workflow initialized")
    
    def _build_workflow(self):
        """Build the complete LangGraph workflow"""
        
        # Define workflow nodes
        def initialize_analysis(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Initialize the analysis workflow"""
            logger.info(f"Initializing analysis for: {state['app_file_path']}")
            
            state["current_step"] = "initialize"
            state["metadata"]["start_time"] = datetime.now().isoformat()
            state["metadata"]["workflow_version"] = "2.0.0"
            
            # Validate input file
            if not Path(state["app_file_path"]).exists():
                state["errors"].append(f"File not found: {state['app_file_path']}")
                return state
            
            # Extract basic app info
            file_path = Path(state["app_file_path"])
            state["app_info"] = {
                "file_name": file_path.name,
                "file_size": file_path.stat().st_size,
                "file_type": file_path.suffix.lower(),
                "scan_date": datetime.now().isoformat()
            }
            
            logger.info("Analysis initialized successfully")
            return state
        
        def perform_mobsf_scan(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Perform MobSF security scan"""
            logger.info("Starting MobSF scan")
            state["current_step"] = "mobsf_scan"
            
            try:
                # Perform complete scan
                file_hash, scan_results = self.mobsf_client.perform_complete_scan(
                    state["app_file_path"],
                    timeout=state["config"].get("scan_timeout", 1800)
                )
                
                state["mobsf_file_hash"] = file_hash
                state["raw_scan_results"] = scan_results
                
                # Update app info with scan results
                state["app_info"].update({
                    "app_name": scan_results.get("app_name", "Unknown App"),
                    "package_name": scan_results.get("packagename", "Unknown Package"),
                    "version": scan_results.get("version", "Unknown Version"),
                    "platform": "Android" if state["app_info"]["file_type"] == ".apk" else "iOS"
                })
                
                logger.info(f"MobSF scan completed for: {state['app_info']['app_name']}")
                
            except Exception as e:
                error_msg = f"MobSF scan failed: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
            
            return state
        
        def extract_vulnerabilities(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Extract vulnerabilities from scan results"""
            logger.info("Extracting vulnerabilities")
            state["current_step"] = "extract_vulnerabilities"
            
            if not state.get("raw_scan_results"):
                state["errors"].append("No scan results available for vulnerability extraction")
                return state
            
            try:
                # Extract vulnerabilities
                vulnerabilities = self.vulnerability_extractor.extract_vulnerabilities_from_mobsf(
                    state["raw_scan_results"]
                )
                
                state["extracted_vulnerabilities"] = vulnerabilities
                logger.info(f"Extracted {len(vulnerabilities)} vulnerabilities")
                
            except Exception as e:
                error_msg = f"Vulnerability extraction failed: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["extracted_vulnerabilities"] = []
            
            return state
        
        def filter_and_deduplicate(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Filter and deduplicate vulnerabilities"""
            logger.info("Filtering and deduplicating vulnerabilities")
            state["current_step"] = "filter_vulnerabilities"
            
            vulnerabilities = state.get("extracted_vulnerabilities", [])
            
            try:
                # Apply filters
                filtered = self.vulnerability_extractor.filter_vulnerabilities(
                    vulnerabilities,
                    min_severity=state["config"].get("min_severity", "low")
                )
                
                # Deduplicate
                if state["config"].get("enable_deduplication", True):
                    filtered = self.vulnerability_extractor.deduplicate_vulnerabilities(filtered)
                
                state["filtered_vulnerabilities"] = filtered
                logger.info(f"Filtered to {len(filtered)} unique vulnerabilities")
                
            except Exception as e:
                error_msg = f"Vulnerability filtering failed: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["filtered_vulnerabilities"] = state.get("extracted_vulnerabilities", [])
            
            return state
        
        def analyze_with_ai(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Analyze vulnerabilities using AI"""
            logger.info("Starting AI analysis of vulnerabilities")
            state["current_step"] = "ai_analysis"
            
            vulnerabilities = state.get("filtered_vulnerabilities", [])
            
            if not vulnerabilities:
                state["warnings"].append("No vulnerabilities to analyze")
                state["vulnerability_analyses"] = []
                return state
            
            try:
                # Prepare context for AI analysis
                context = {
                    "app_info": state["app_info"],
                    "scan_metadata": {
                        "total_vulnerabilities": len(vulnerabilities),
                        "scan_date": state["app_info"].get("scan_date"),
                        "platform": state["app_info"].get("platform")
                    }
                }
                
                # Perform batch AI analysis
                analyses = self.ai_analyzer.analyze_vulnerability_batch(
                    vulnerabilities, 
                    context=context
                )
                
                state["vulnerability_analyses"] = analyses
                logger.info(f"AI analysis completed for {len(analyses)} vulnerabilities")
                
            except Exception as e:
                error_msg = f"AI analysis failed: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["vulnerability_analyses"] = []
            
            return state
        
        def categorize_vulnerabilities(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Categorize vulnerabilities by severity"""
            logger.info("Categorizing vulnerabilities")
            state["current_step"] = "categorize"
            
            analyses = state.get("vulnerability_analyses", [])
            
            try:
                categorized = self.ai_analyzer.categorize_vulnerabilities(analyses)
                state["categorized_vulnerabilities"] = categorized
                
                # Log statistics
                for severity, vulns in categorized.items():
                    logger.info(f"{severity}: {len(vulns)} vulnerabilities")
                
            except Exception as e:
                error_msg = f"Vulnerability categorization failed: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["categorized_vulnerabilities"] = {}
            
            return state
        
        def generate_executive_summary(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Generate executive summary"""
            logger.info("Generating executive summary")
            state["current_step"] = "executive_summary"
            
            categorized = state.get("categorized_vulnerabilities", {})
            
            try:
                summary = self.ai_analyzer.generate_executive_summary(
                    categorized,
                    app_context=state["app_info"]
                )
                
                state["executive_summary"] = summary
                logger.info("Executive summary generated")
                
            except Exception as e:
                error_msg = f"Executive summary generation failed: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["executive_summary"] = "Executive summary generation failed"
            
            return state
        
        def generate_reports(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Generate security reports"""
            logger.info("Generating security reports")
            state["current_step"] = "generate_reports"
            
            try:
                # Prepare report data
                statistics = self.vulnerability_extractor.get_vulnerability_statistics(
                    state.get("filtered_vulnerabilities", [])
                )
                
                # Generate reports
                reports = self.report_generator.generate_all_reports(
                    app_info=state["app_info"],
                    categorized_vulnerabilities=state.get("categorized_vulnerabilities", {}),
                    executive_summary=state.get("executive_summary", ""),
                    scan_stats=statistics,
                    formats=state["config"].get("report_formats", ["html", "json"])
                )
                
                state["generated_reports"] = reports
                state["report_data"] = {
                    "app_info": state["app_info"],
                    "statistics": statistics,
                    "executive_summary": state.get("executive_summary", "")
                }
                
                logger.info(f"Generated {len(reports)} reports")
                
            except Exception as e:
                error_msg = f"Report generation failed: {str(e)}"
                logger.error(error_msg)
                state["errors"].append(error_msg)
                state["generated_reports"] = {}
            
            return state
        
        def cleanup_and_finalize(state: SecurityAnalysisState) -> SecurityAnalysisState:
            """Cleanup and finalize workflow"""
            logger.info("Finalizing analysis workflow")
            state["current_step"] = "finalize"
            
            # Cleanup MobSF scan if configured
            if (state["config"].get("cleanup_mobsf", True) and 
                state.get("mobsf_file_hash")):
                try:
                    self.mobsf_client.delete_scan(state["mobsf_file_hash"])
                    logger.info("MobSF scan data cleaned up")
                except Exception as e:
                    state["warnings"].append(f"MobSF cleanup failed: {str(e)}")
            
            # Add completion metadata
            state["metadata"]["end_time"] = datetime.now().isoformat()
            state["metadata"]["completed"] = True
            state["metadata"]["success"] = len(state["errors"]) == 0
            
            # Log final summary
            total_vulns = len(state.get("vulnerability_analyses", []))
            critical_count = len(state.get("categorized_vulnerabilities", {}).get("Critical", []))
            
            logger.info("=== WORKFLOW COMPLETED ===")
            logger.info(f"App: {state['app_info'].get('app_name', 'Unknown')}")
            logger.info(f"Total vulnerabilities: {total_vulns}")
            logger.info(f"Critical vulnerabilities: {critical_count}")
            logger.info(f"Reports generated: {len(state.get('generated_reports', {}))}")
            logger.info(f"Errors: {len(state['errors'])}")
            logger.info(f"Warnings: {len(state['warnings'])}")
            
            return state
        
        # Define conditional logic
        def should_continue_after_scan(state: SecurityAnalysisState) -> str:
            """Decide whether to continue after MobSF scan"""
            if state["errors"]:
                return "finalize"
            return "extract_vulnerabilities"
        
        def should_continue_after_extraction(state: SecurityAnalysisState) -> str:
            """Decide whether to continue after vulnerability extraction"""
            if state["errors"] or not state.get("extracted_vulnerabilities"):
                return "finalize"
            return "filter_and_deduplicate"
        
        def should_continue_after_filtering(state: SecurityAnalysisState) -> str:
            """Decide whether to continue after filtering"""
            if state["errors"]:
                return "generate_reports"  # Generate report even with errors
            if not state.get("filtered_vulnerabilities"):
                return "generate_reports"  # No vulnerabilities to analyze
            return "analyze_with_ai"
        
        # Build the workflow graph
        workflow = StateGraph(SecurityAnalysisState)
        
        # Add nodes
        workflow.add_node("initialize", initialize_analysis)
        workflow.add_node("mobsf_scan", perform_mobsf_scan)
        workflow.add_node("extract_vulnerabilities", extract_vulnerabilities)
        workflow.add_node("filter_and_deduplicate", filter_and_deduplicate)
        workflow.add_node("analyze_with_ai", analyze_with_ai)
        workflow.add_node("categorize", categorize_vulnerabilities)
        workflow.add_node("executive_summary", generate_executive_summary)
        workflow.add_node("generate_reports", generate_reports)
        workflow.add_node("finalize", cleanup_and_finalize)
        
        # Add edges with conditional logic
        workflow.add_edge("initialize", "mobsf_scan")
        workflow.add_conditional_edges(
            "mobsf_scan",
            should_continue_after_scan,
            {
                "extract_vulnerabilities": "extract_vulnerabilities",
                "finalize": "finalize"
            }
        )
        workflow.add_conditional_edges(
            "extract_vulnerabilities",
            should_continue_after_extraction,
            {
                "filter_and_deduplicate": "filter_and_deduplicate",
                "finalize": "finalize"
            }
        )
        workflow.add_conditional_edges(
            "filter_and_deduplicate",
            should_continue_after_filtering,
            {
                "analyze_with_ai": "analyze_with_ai",
                "generate_reports": "generate_reports"
            }
        )
        workflow.add_edge("analyze_with_ai", "categorize")
        workflow.add_edge("categorize", "executive_summary")
        workflow.add_edge("executive_summary", "generate_reports")
        workflow.add_edge("generate_reports", "finalize")
        workflow.add_edge("finalize", END)
        
        # Set entry point
        workflow.set_entry_point("initialize")
        
        # Compile workflow with checkpointer
        compile_config = {}
        if self.checkpointer:
            compile_config["checkpointer"] = self.checkpointer
        
        self.workflow = workflow.compile(**compile_config)
        
        logger.info("Security analysis workflow built successfully")
    
    def analyze_mobile_app(self,
                          app_file_path: str,
                          config: Dict[str, Any] = None,
                          thread_id: str = None) -> SecurityAnalysisState:
        """
        Run complete security analysis workflow
        
        Args:
            app_file_path: Path to mobile app file
            config: Analysis configuration
            thread_id: Thread ID for persistence (optional)
            
        Returns:
            SecurityAnalysisState: Final workflow state
        """
        logger.info(f"Starting security analysis workflow for: {app_file_path}")
        
        # Prepare initial state
        initial_state: SecurityAnalysisState = {
            "app_file_path": app_file_path,
            "app_info": {},
            "mobsf_file_hash": None,
            "raw_scan_results": None,
            "extracted_vulnerabilities": [],
            "filtered_vulnerabilities": [],
            "vulnerability_analyses": [],
            "categorized_vulnerabilities": {},
            "executive_summary": None,
            "generated_reports": {},
            "report_data": None,
            "current_step": "start",
            "errors": [],
            "warnings": [],
            "metadata": {
                "workflow_id": thread_id or f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                "start_time": datetime.now().isoformat()
            },
            "config": config or {}
        }
        
        # Run workflow
        run_config = {}
        if thread_id and self.checkpointer:
            run_config["thread_id"] = thread_id
        
        try:
            final_state = self.workflow.invoke(initial_state, config=run_config)
            logger.info("Security analysis workflow completed successfully")
            return final_state
            
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            initial_state["errors"].append(f"Workflow execution failed: {str(e)}")
            initial_state["current_step"] = "failed"
            return initial_state
    
    def get_workflow_state(self, thread_id: str) -> Optional[SecurityAnalysisState]:
        """
        Get current workflow state for a thread
        
        Args:
            thread_id: Thread identifier
            
        Returns:
            SecurityAnalysisState: Current state or None
        """
        if not self.checkpointer:
            logger.warning("Persistence not enabled - cannot retrieve workflow state")
            return None
        
        try:
            # Get latest checkpoint for thread
            checkpoints = list(self.checkpointer.list({"thread_id": thread_id}))
            if checkpoints:
                latest = checkpoints[0]
                return latest.state
            return None
            
        except Exception as e:
            logger.error(f"Failed to retrieve workflow state: {e}")
            return None
    
    def list_workflow_runs(self) -> List[Dict[str, Any]]:
        """
        List all workflow runs
        
        Returns:
            List[Dict[str, Any]]: List of workflow run information
        """
        if not self.checkpointer:
            return []
        
        try:
            runs = []
            checkpoints = list(self.checkpointer.list({}))
            
            for checkpoint in checkpoints:
                state = checkpoint.state
                runs.append({
                    "thread_id": checkpoint.config.get("thread_id"),
                    "app_name": state.get("app_info", {}).get("app_name", "Unknown"),
                    "current_step": state.get("current_step", "unknown"),
                    "start_time": state.get("metadata", {}).get("start_time"),
                    "completed": state.get("metadata", {}).get("completed", False),
                    "success": state.get("metadata", {}).get("success", False),
                    "error_count": len(state.get("errors", [])),
                    "vulnerability_count": len(state.get("vulnerability_analyses", []))
                })
            
            return runs
            
        except Exception as e:
            logger.error(f"Failed to list workflow runs: {e}")
            return []


def create_security_workflow(mobsf_client: MobSFClient,
                           ai_analyzer: LangChainVulnerabilityAnalyzer,
                           vulnerability_extractor: VulnerabilityExtractor,
                           report_generator: SecurityReportGenerator,
                           **kwargs) -> SecurityAnalysisWorkflow:
    """
    Factory function to create security analysis workflow
    
    Args:
        mobsf_client: MobSF API client
        ai_analyzer: AI analyzer instance
        vulnerability_extractor: Vulnerability extractor
        report_generator: Report generator
        **kwargs: Additional configuration
        
    Returns:
        SecurityAnalysisWorkflow: Configured workflow instance
    """
    return SecurityAnalysisWorkflow(
        mobsf_client=mobsf_client,
        ai_analyzer=ai_analyzer,
        vulnerability_extractor=vulnerability_extractor,
        report_generator=report_generator,
        **kwargs
    )