"""
LangChain-based AI Vulnerability Analyzer

This module uses LangChain and LangGraph to create sophisticated AI workflows
for vulnerability analysis, classification, and prioritization.
"""

import json
import logging
from typing import Dict, List, Any, Optional, TypedDict, Annotated
from datetime import datetime
from enum import Enum

from langchain_core.prompts import ChatPromptTemplate, PromptTemplate
from langchain_core.output_parsers import PydanticOutputParser, JsonOutputParser
from langchain_core.runnables import RunnablePassthrough, RunnableLambda
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_ollama import ChatOllama
from langchain_core.prompts import ChatPromptTemplate
from langchain_community.chat_message_histories import ChatMessageHistory

from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class VulnerabilityCategory(str, Enum):
    """Vulnerability categories"""
    AUTHENTICATION = "Authentication"
    ENCRYPTION = "Encryption"
    STORAGE = "Storage"
    NETWORK = "Network"
    PERMISSIONS = "Permissions"
    CODE_QUALITY = "Code Quality"
    CONFIGURATION = "Configuration"
    INJECTION = "Injection"
    BUSINESS_LOGIC = "Business Logic"
    OTHER = "Other"


class VulnerabilityPriority(BaseModel):
    """Structured vulnerability priority assessment"""
    severity: SeverityLevel = Field(description="Vulnerability severity level")
    priority_score: float = Field(ge=0.0, le=1.0, description="Priority score from 0.0 to 1.0")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence in the assessment")
    reasoning: str = Field(description="Detailed reasoning for the assessment")
    category: VulnerabilityCategory = Field(description="Vulnerability category")
    exploitability: str = Field(description="How easily this vulnerability can be exploited")
    business_impact: str = Field(description="Potential business impact")


class VulnerabilityAnalysis(BaseModel):
    """Complete vulnerability analysis result"""
    vulnerability_id: str
    title: str
    description: str
    priority: VulnerabilityPriority
    impact_assessment: str = Field(description="Detailed impact assessment")
    remediation_steps: List[str] = Field(description="Step-by-step remediation")
    references: List[str] = Field(default=[], description="External references")
    cwe_mapping: Optional[str] = Field(default=None, description="CWE identifier if applicable")
    owasp_mapping: Optional[str] = Field(default=None, description="OWASP category if applicable")
    technical_details: Dict[str, Any] = Field(default={}, description="Original technical details")


class AnalysisState(TypedDict):
    """State for the vulnerability analysis workflow"""
    vulnerabilities: List[Dict[str, Any]]
    current_vulnerability: Dict[str, Any]
    analysis_result: Optional[VulnerabilityAnalysis]
    context: Dict[str, Any]
    errors: List[str]
    completed_analyses: List[VulnerabilityAnalysis]
    executive_summary: Optional[str]


class LangChainVulnerabilityAnalyzer:
    """
    Advanced vulnerability analyzer using LangChain and LangGraph
    """
    
    def __init__(self, 
                 provider: str = "openai",
                 model_name: str = "gpt-4",
                 api_key: str = None,
                 temperature: float = 0.1,
                 max_tokens: int = 2000,
                 enable_memory: bool = True,
                 ollama_base_url: str = "http://localhost:11434"):
        """
        Initialize the LangChain vulnerability analyzer
        
        Args:
            provider: AI provider ("openai", "anthropic", "xai", "ollama")
            model_name: Model name to use
            api_key: API key for the provider
            temperature: Model temperature for consistency
            max_tokens: Maximum tokens per request
            enable_memory: Enable conversation memory
            ollama_base_url: Base URL for Ollama server
        """
        self.provider = provider
        self.model_name = model_name
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.enable_memory = enable_memory
        self.ollama_base_url = ollama_base_url
        
        # Initialize LLM
        self.llm = self._initialize_llm(provider, model_name, api_key, temperature, max_tokens, ollama_base_url)
        
        # Initialize memory if enabled
        self.memory = ChatMessageHistory() if enable_memory else None
        
        # Create chains
        self._create_analysis_chains()
        
        # Create LangGraph workflow
        self._create_workflow()
        
        logger.info(f"Initialized LangChain analyzer with {provider}:{model_name}")
    
    def _initialize_llm(self, provider: str, model_name: str, api_key: str, temperature: float, max_tokens: int, ollama_base_url: str):
        """Initialize the language model based on provider"""
        if provider.lower() == "openai":
            return ChatOpenAI(
                model=model_name,
                temperature=temperature,
                openai_api_key=api_key,
                max_tokens=max_tokens
            )
        elif provider.lower() == "anthropic":
            return ChatAnthropic(
                model=model_name,
                temperature=temperature,
                anthropic_api_key=api_key,
                max_tokens=max_tokens
            )
        elif provider.lower() == "xai":
            # xAI Grok uses OpenAI-compatible API
            return ChatOpenAI(
                model=model_name,
                temperature=temperature,
                openai_api_key=api_key,
                openai_api_base="https://api.x.ai/v1",
                max_tokens=max_tokens
            )
        elif provider.lower() == "groq":
            # Groq uses OpenAI-compatible API
            return ChatOpenAI(
                model=model_name,
                temperature=temperature,
                openai_api_key=api_key,
                openai_api_base="https://api.groq.com/openai/v1",
                max_tokens=max_tokens
            )
        elif provider.lower() == "ollama":
            chat_ollama_params = {
                "model": model_name,
                "temperature": temperature,
                "base_url": ollama_base_url,
            }
            # Add API key if provided (for hosted Ollama instances)
            if api_key:
                chat_ollama_params["api_key"] = api_key
            
            return ChatOllama(**chat_ollama_params)
        else:
            raise ValueError(f"Unsupported provider: {provider}. Supported: openai, anthropic, xai, groq, ollama")
    
    def _create_analysis_chains(self):
        """Create specialized LangChain chains for different analysis tasks"""
        
        # Vulnerability classification chain
        classification_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a mobile application security expert. Analyze the given vulnerability and classify it accurately.
            
Consider these factors:
- Exploitability (how easy is it to exploit?)
- Impact (what damage could it cause?)
- Scope (how many users/systems affected?)
- Detectability (how hard is it to detect?)

Provide structured output with severity, category, and detailed reasoning."""),
            ("human", """Analyze this mobile app vulnerability:

Title: {title}
Description: {description}
Type: {vuln_type}
Context: {context}

Classify this vulnerability and provide detailed analysis.""")
        ])
        
        classification_parser = PydanticOutputParser(pydantic_object=VulnerabilityPriority)
        self.classification_chain = classification_prompt | self.llm | classification_parser
        
        # Impact assessment chain
        impact_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity risk analyst. Assess the potential impact of mobile app vulnerabilities.
            
Consider:
- Data confidentiality risks
- System integrity threats  
- Service availability impacts
- Compliance implications
- Business consequences
            
Provide detailed impact analysis in clear, actionable language."""),
            ("human", """Assess the impact of this vulnerability:

Title: {title}
Description: {description}
Severity: {severity}
Category: {category}

Provide comprehensive impact assessment.""")
        ])
        
        self.impact_chain = impact_prompt | self.llm
        
        # Remediation chain
        remediation_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a mobile app security consultant. Provide specific, actionable remediation steps.
            
Your recommendations should be:
- Specific and technical
- Prioritized by importance
- Implementable by developers
- Include verification steps
- Consider different skill levels

Format as a numbered list of clear action items."""),
            ("human", """Provide remediation steps for this vulnerability:

Title: {title}
Description: {description}
Severity: {severity}
Category: {category}
Technical Details: {technical_details}

Provide step-by-step remediation guidance.""")
        ])
        
        self.remediation_chain = remediation_prompt | self.llm
        
        # Executive summary chain
        summary_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a cybersecurity executive advisor. Create executive summaries for technical audiences.
            
Your summary should:
- Start with overall risk assessment
- Highlight critical findings
- Provide business context
- Include recommended actions
- Be concise but comprehensive
- Use business language, not just technical jargon"""),
            ("human", """Create an executive summary for this mobile app security analysis:

Total Vulnerabilities: {total_count}
Critical: {critical_count}
High: {high_count}  
Medium: {medium_count}
Low: {low_count}

Key Findings:
{key_findings}

App Context: {app_context}

Create a professional executive summary (200-300 words).""")
        ])
        
        self.summary_chain = summary_prompt | self.llm
    
    def _create_workflow(self):
        """Create LangGraph workflow for vulnerability analysis"""
        
        # Define workflow nodes
        def classify_vulnerability(state: AnalysisState) -> AnalysisState:
            """Classify vulnerability using AI"""
            vuln = state["current_vulnerability"]
            
            try:
                priority = self.classification_chain.invoke({
                    "title": vuln.get("title", ""),
                    "description": vuln.get("description", ""),
                    "vuln_type": vuln.get("type", ""),
                    "context": json.dumps(state.get("context", {}))
                })
                
                # Create partial analysis result
                state["analysis_result"] = VulnerabilityAnalysis(
                    vulnerability_id=vuln.get("id", "unknown"),
                    title=vuln.get("title", "Unknown Vulnerability"),
                    description=vuln.get("description", ""),
                    priority=priority,
                    impact_assessment="",
                    remediation_steps=[],
                    technical_details=vuln
                )
                
            except Exception as e:
                logger.error(f"Classification failed: {e}")
                state["errors"].append(f"Classification failed: {str(e)}")
            
            return state
        
        def assess_impact(state: AnalysisState) -> AnalysisState:
            """Assess vulnerability impact"""
            if not state.get("analysis_result"):
                return state
            
            analysis = state["analysis_result"]
            
            try:
                impact_response = self.impact_chain.invoke({
                    "title": analysis.title,
                    "description": analysis.description,
                    "severity": analysis.priority.severity.value,
                    "category": analysis.priority.category.value
                })
                
                # Update analysis with impact assessment
                analysis.impact_assessment = impact_response.content if hasattr(impact_response, 'content') else str(impact_response)
                state["analysis_result"] = analysis
                
            except Exception as e:
                logger.error(f"Impact assessment failed: {e}")
                state["errors"].append(f"Impact assessment failed: {str(e)}")
            
            return state
        
        def generate_remediation(state: AnalysisState) -> AnalysisState:
            """Generate remediation steps"""
            if not state.get("analysis_result"):
                return state
            
            analysis = state["analysis_result"]
            
            try:
                remediation_response = self.remediation_chain.invoke({
                    "title": analysis.title,
                    "description": analysis.description,
                    "severity": analysis.priority.severity.value,
                    "category": analysis.priority.category.value,
                    "technical_details": json.dumps(analysis.technical_details)
                })
                
                # Parse remediation steps from response
                remediation_text = remediation_response.content if hasattr(remediation_response, 'content') else str(remediation_response)
                steps = self._parse_remediation_steps(remediation_text)
                
                analysis.remediation_steps = steps
                state["analysis_result"] = analysis
                
            except Exception as e:
                logger.error(f"Remediation generation failed: {e}")
                state["errors"].append(f"Remediation generation failed: {str(e)}")
            
            return state
        
        def finalize_analysis(state: AnalysisState) -> AnalysisState:
            """Finalize and store analysis result"""
            if state.get("analysis_result"):
                state["completed_analyses"].append(state["analysis_result"])
                logger.info(f"Completed analysis for: {state['analysis_result'].title}")
            
            return state
        
        # Create the workflow graph
        workflow = StateGraph(AnalysisState)
        
        # Add nodes
        workflow.add_node("classify", classify_vulnerability)
        workflow.add_node("assess_impact", assess_impact)
        workflow.add_node("generate_remediation", generate_remediation)
        workflow.add_node("finalize", finalize_analysis)
        
        # Add edges
        workflow.add_edge("classify", "assess_impact")
        workflow.add_edge("assess_impact", "generate_remediation")
        workflow.add_edge("generate_remediation", "finalize")
        workflow.add_edge("finalize", END)
        
        # Set entry point
        workflow.set_entry_point("classify")
        
        # Compile workflow
        self.workflow = workflow.compile()
        
        logger.info("LangGraph workflow created successfully")
    
    def _parse_remediation_steps(self, remediation_text: str) -> List[str]:
        """Parse remediation steps from AI response"""
        steps = []
        lines = remediation_text.split('\n')
        
        for line in lines:
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')):
                # Clean up numbered/bulleted items
                cleaned = line.lstrip('0123456789.-* ').strip()
                if cleaned:
                    steps.append(cleaned)
        
        return steps if steps else [remediation_text]
    
    def analyze_vulnerability(self, vulnerability: Dict[str, Any], context: Dict[str, Any] = None) -> VulnerabilityAnalysis:
        """
        Analyze a single vulnerability using the LangGraph workflow
        
        Args:
            vulnerability: Vulnerability data
            context: Additional context for analysis
            
        Returns:
            VulnerabilityAnalysis: Complete analysis result
        """
        logger.info(f"Analyzing vulnerability: {vulnerability.get('title', 'Unknown')}")
        
        # Initialize state
        initial_state: AnalysisState = {
            "vulnerabilities": [vulnerability],
            "current_vulnerability": vulnerability,
            "analysis_result": None,
            "context": context or {},
            "errors": [],
            "completed_analyses": [],
            "executive_summary": None
        }
        
        try:
            # Run workflow
            final_state = self.workflow.invoke(initial_state)
            
            if final_state["completed_analyses"]:
                return final_state["completed_analyses"][0]
            else:
                # Create fallback analysis if workflow failed
                return self._create_fallback_analysis(vulnerability, final_state["errors"])
                
        except Exception as e:
            logger.error(f"Workflow execution failed: {e}")
            return self._create_fallback_analysis(vulnerability, [str(e)])
    
    def analyze_vulnerability_batch(self, vulnerabilities: List[Dict[str, Any]], 
                                  context: Dict[str, Any] = None) -> List[VulnerabilityAnalysis]:
        """
        Analyze multiple vulnerabilities in batch
        
        Args:
            vulnerabilities: List of vulnerability data
            context: Shared context for all analyses
            
        Returns:
            List[VulnerabilityAnalysis]: List of analysis results
        """
        logger.info(f"Starting batch analysis of {len(vulnerabilities)} vulnerabilities")
        
        analyses = []
        for i, vuln in enumerate(vulnerabilities):
            try:
                analysis = self.analyze_vulnerability(vuln, context)
                analyses.append(analysis)
                logger.debug(f"Completed {i+1}/{len(vulnerabilities)}: {analysis.title}")
            except Exception as e:
                logger.error(f"Failed to analyze vulnerability {i+1}: {e}")
                continue
        
        logger.info(f"Batch analysis completed: {len(analyses)}/{len(vulnerabilities)} successful")
        return analyses
    
    def categorize_vulnerabilities(self, analyses: List[VulnerabilityAnalysis]) -> Dict[str, List[VulnerabilityAnalysis]]:
        """
        Categorize vulnerabilities by severity level
        
        Args:
            analyses: List of vulnerability analyses
            
        Returns:
            Dict[str, List[VulnerabilityAnalysis]]: Categorized vulnerabilities
        """
        categories = {
            "Critical": [],
            "High": [],
            "Medium": [],
            "Low": []
        }
        
        for analysis in analyses:
            severity = analysis.priority.severity.value
            if severity in categories:
                categories[severity].append(analysis)
        
        # Sort each category by priority score (highest first)
        for category in categories:
            categories[category].sort(key=lambda x: x.priority.priority_score, reverse=True)
        
        logger.info(f"Vulnerabilities categorized: "
                   f"Critical: {len(categories['Critical'])}, "
                   f"High: {len(categories['High'])}, "
                   f"Medium: {len(categories['Medium'])}, "
                   f"Low: {len(categories['Low'])}")
        
        return categories
    
    def generate_executive_summary(self, categorized_vulns: Dict[str, List[VulnerabilityAnalysis]], 
                                 app_context: Dict[str, Any] = None) -> str:
        """
        Generate executive summary using AI
        
        Args:
            categorized_vulns: Categorized vulnerabilities
            app_context: Application context information
            
        Returns:
            str: Executive summary text
        """
        total_count = sum(len(vulns) for vulns in categorized_vulns.values())
        counts = {
            "total_count": total_count,
            "critical_count": len(categorized_vulns.get("Critical", [])),
            "high_count": len(categorized_vulns.get("High", [])),
            "medium_count": len(categorized_vulns.get("Medium", [])),
            "low_count": len(categorized_vulns.get("Low", []))
        }
        
        # Extract key findings
        key_findings = []
        for severity, vulns in categorized_vulns.items():
            if vulns and severity in ["Critical", "High"]:
                for vuln in vulns[:3]:  # Top 3 per severity
                    key_findings.append(f"{severity}: {vuln.title}")
        
        try:
            response = self.summary_chain.invoke({
                **counts,
                "key_findings": "\n".join(key_findings),
                "app_context": json.dumps(app_context or {})
            })
            
            return response.content if hasattr(response, 'content') else str(response)
            
        except Exception as e:
            logger.error(f"Executive summary generation failed: {e}")
            return self._create_fallback_summary(counts, key_findings)
    
    def _create_fallback_analysis(self, vulnerability: Dict[str, Any], errors: List[str]) -> VulnerabilityAnalysis:
        """Create fallback analysis when AI processing fails"""
        priority = VulnerabilityPriority(
            severity=SeverityLevel.MEDIUM,
            priority_score=0.5,
            confidence=0.1,
            reasoning=f"AI analysis failed. Errors: {'; '.join(errors)}",
            category=VulnerabilityCategory.OTHER,
            exploitability="Unknown - requires manual analysis",
            business_impact="Unknown - requires manual assessment"
        )
        
        return VulnerabilityAnalysis(
            vulnerability_id=vulnerability.get("id", "unknown"),
            title=vulnerability.get("title", "Unknown Vulnerability"),
            description=vulnerability.get("description", "No description available"),
            priority=priority,
            impact_assessment="Impact assessment failed - manual review required",
            remediation_steps=["Manual security review required", "Consult security expert"],
            technical_details=vulnerability
        )
    
    def _create_fallback_summary(self, counts: Dict[str, int], key_findings: List[str]) -> str:
        """Create fallback executive summary"""
        return f"""
EXECUTIVE SUMMARY

The mobile application security scan identified {counts['total_count']} vulnerabilities requiring attention.

CRITICAL FINDINGS:
- {counts['critical_count']} Critical vulnerabilities requiring immediate action
- {counts['high_count']} High-priority vulnerabilities needing prompt resolution  
- {counts['medium_count']} Medium-priority issues for planned remediation
- {counts['low_count']} Low-priority items for future consideration

IMMEDIATE ACTIONS REQUIRED:
1. Address all critical vulnerabilities before deployment
2. Implement fixes for high-priority security issues
3. Conduct security code review
4. Update security testing procedures

This automated analysis provides initial risk assessment. Manual security review is recommended for comprehensive evaluation.
"""
    
    def generate_countermeasures(self, 
                                vulnerability_analyses: List[VulnerabilityAnalysis],
                                app_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate comprehensive countermeasures and action plan based on vulnerability analyses
        
        Args:
            vulnerability_analyses: List of analyzed vulnerabilities
            app_context: Application context (name, type, platform, etc.)
            
        Returns:
            Dict containing countermeasures, priority matrix, implementation roadmap
        """
        if not vulnerability_analyses:
            return {
                "countermeasures": [],
                "priority_matrix": [],
                "implementation_roadmap": {},
                "generated_at": datetime.now().isoformat()
            }
        
        # Categorize vulnerabilities
        categorized = {}
        for analysis in vulnerability_analyses:
            category = analysis.category.value
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(analysis)
        
        # Build prompt for AI countermeasures generation
        prompt_template = PromptTemplate(
            input_variables=["vulnerabilities", "app_context"],
            template="""You are a cybersecurity expert providing actionable countermeasures.

Application Context: {app_context}

Identified Vulnerabilities:
{vulnerabilities}

Generate a comprehensive remediation plan with:
1. Immediate Actions (critical/high priority)
2. Short-term Actions (next 1-3 months)
3. Long-term Actions (3-6 months)
4. Preventive Measures

For each action provide:
- Specific technical steps
- Estimated effort (hours/days)
- Required skills/tools
- Success criteria
- Compliance standards addressed (OWASP, CWE, etc.)

Format as structured JSON."""
        )
        
        # Prepare vulnerability summary
        vuln_summary = []
        for category, vulns in categorized.items():
            vuln_summary.append(f"\n{category.upper()}:")
            for vuln in vulns[:5]:  # Limit to top 5 per category
                vuln_summary.append(
                    f"  - {vuln.title} (Severity: {vuln.severity.value}, "
                    f"Confidence: {vuln.confidence_score:.2f})"
                )
        
        context_str = str(app_context) if app_context else "Mobile Application"
        
        try:
            # Generate AI countermeasures
            chain = prompt_template | self.llm
            response = chain.invoke({
                "vulnerabilities": "\n".join(vuln_summary),
                "app_context": context_str
            })
            
            # Parse AI response
            if hasattr(response, 'content'):
                content = response.content
            else:
                content = str(response)
            
            # Try to extract JSON from response
            import json
            import re
            
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                countermeasures_data = json.loads(json_match.group())
            else:
                # Fallback to structured text parsing
                countermeasures_data = {
                    "immediate_actions": content.split("Immediate Actions")[1].split("\n\n")[0] if "Immediate Actions" in content else "",
                    "short_term_actions": content.split("Short-term Actions")[1].split("\n\n")[0] if "Short-term Actions" in content else "",
                    "long_term_actions": content.split("Long-term Actions")[1].split("\n\n")[0] if "Long-term Actions" in content else "",
                    "preventive_measures": content.split("Preventive Measures")[1] if "Preventive Measures" in content else ""
                }
            
        except Exception as e:
            logger.warning(f"AI countermeasures generation failed: {e}, using fallback")
            countermeasures_data = self._create_fallback_countermeasures(
                vulnerability_analyses, categorized
            )
        
        return {
            "countermeasures": countermeasures_data,
            "categorized_vulnerabilities": categorized,
            "priority_matrix": self._create_priority_matrix(vulnerability_analyses),
            "implementation_roadmap": self._create_implementation_roadmap(categorized),
            "generated_at": datetime.now().isoformat()
        }
    
    def _create_priority_matrix(self, analyses: List[VulnerabilityAnalysis]) -> List[Dict[str, Any]]:
        """Create priority matrix for vulnerability remediation"""
        matrix = []
        for analysis in analyses:
            matrix.append({
                "vulnerability": analysis.title,
                "severity": analysis.severity.value,
                "confidence": analysis.confidence_score,
                "priority_score": self._calculate_priority_score(analysis),
                "estimated_effort": self._estimate_effort(analysis),
                "business_impact": analysis.business_impact
            })
        
        # Sort by priority score descending
        return sorted(matrix, key=lambda x: x['priority_score'], reverse=True)
    
    def _calculate_priority_score(self, analysis: VulnerabilityAnalysis) -> float:
        """Calculate priority score based on severity, confidence, and exploitability"""
        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}
        base_score = severity_weights.get(analysis.severity.value, 1)
        return base_score * analysis.confidence_score * analysis.exploitability_score
    
    def _estimate_effort(self, analysis: VulnerabilityAnalysis) -> str:
        """Estimate remediation effort"""
        # Simple heuristic based on severity and remediation steps
        step_count = len(analysis.remediation_steps)
        if analysis.severity.value in ["CRITICAL", "HIGH"] and step_count > 5:
            return "3-5 days"
        elif step_count > 3:
            return "1-2 days"
        else:
            return "4-8 hours"
    
    def _create_implementation_roadmap(self, categorized: Dict[str, List]) -> Dict[str, List[str]]:
        """Create timeline-based implementation roadmap"""
        roadmap = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        # Immediate: Critical and High
        for category in ["authentication", "encryption", "code_quality"]:
            if category in categorized:
                for vuln in categorized[category]:
                    if vuln.severity.value in ["CRITICAL", "HIGH"]:
                        roadmap["immediate"].append(
                            f"{vuln.title} - {vuln.remediation_steps[0] if vuln.remediation_steps else 'Review required'}"
                        )
        
        # Short-term: Medium severity
        for vulns in categorized.values():
            for vuln in vulns:
                if vuln.severity.value == "MEDIUM":
                    roadmap["short_term"].append(f"{vuln.title}")
        
        # Long-term: Low severity and preventive
        for vulns in categorized.values():
            for vuln in vulns:
                if vuln.severity.value in ["LOW", "INFO"]:
                    roadmap["long_term"].append(f"{vuln.title}")
        
        return roadmap
    
    def _create_fallback_countermeasures(self, analyses: List[VulnerabilityAnalysis], 
                                        categorized: Dict[str, List]) -> Dict[str, Any]:
        """Create fallback countermeasures when AI generation fails"""
        immediate = []
        short_term = []
        long_term = []
        
        for analysis in analyses:
            action = {
                "title": analysis.title,
                "steps": analysis.remediation_steps[:3],
                "severity": analysis.severity.value,
                "category": analysis.category.value
            }
            
            if analysis.severity.value in ["CRITICAL", "HIGH"]:
                immediate.append(action)
            elif analysis.severity.value == "MEDIUM":
                short_term.append(action)
            else:
                long_term.append(action)
        
        return {
            "immediate_actions": immediate,
            "short_term_actions": short_term,
            "long_term_actions": long_term,
            "preventive_measures": [
                "Implement security code review process",
                "Enable static analysis in CI/CD pipeline",
                "Conduct regular security training",
                "Establish secure coding guidelines"
            ]
        }


def create_langchain_analyzer(provider: str = "openai",
"""
    
    def generate_countermeasures(self, 
                                vulnerability_analyses: List[VulnerabilityAnalysis],
                                app_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate comprehensive countermeasures and action plan based on vulnerability analyses
        
        Args:
            vulnerability_analyses: List of analyzed vulnerabilities
            app_context: Application context (name, type, platform, etc.)
            
        Returns:
            Dict containing countermeasures, priority matrix, implementation roadmap
        """
        if not vulnerability_analyses:
            return {
                "countermeasures": [],
                "priority_matrix": [],
                "implementation_roadmap": {},
                "generated_at": datetime.now().isoformat()
            }
        
        # Categorize vulnerabilities
        categorized = {}
        for analysis in vulnerability_analyses:
            category = analysis.category.value
            if category not in categorized:
                categorized[category] = []
            categorized[category].append(analysis)
        
        # Build prompt for AI countermeasures generation
        prompt_template = PromptTemplate(
            input_variables=["vulnerabilities", "app_context"],
            template="""You are a cybersecurity expert providing actionable countermeasures.

Application Context: {app_context}

Identified Vulnerabilities:
{vulnerabilities}

Generate a comprehensive remediation plan with:
1. Immediate Actions (critical/high priority)
2. Short-term Actions (next 1-3 months)
3. Long-term Actions (3-6 months)
4. Preventive Measures

For each action provide:
- Specific technical steps
- Estimated effort (hours/days)
- Required skills/tools
- Success criteria
- Compliance standards addressed (OWASP, CWE, etc.)

Format as structured JSON."""
        )
        
        # Prepare vulnerability summary
        vuln_summary = []
        for category, vulns in categorized.items():
            vuln_summary.append(f"\n{category.upper()}:")
            for vuln in vulns[:5]:  # Limit to top 5 per category
                vuln_summary.append(
                    f"  - {vuln.title} (Severity: {vuln.severity.value}, "
                    f"Confidence: {vuln.confidence_score:.2f})"
                )
        
        context_str = str(app_context) if app_context else "Mobile Application"
        
        try:
            # Generate AI countermeasures
            chain = prompt_template | self.llm
            response = chain.invoke({
                "vulnerabilities": "\n".join(vuln_summary),
                "app_context": context_str
            })
            
            # Parse AI response
            if hasattr(response, 'content'):
                content = response.content
            else:
                content = str(response)
            
            # Try to extract JSON from response
            import json
            import re
            
            json_match = re.search(r'\{.*\}', content, re.DOTALL)
            if json_match:
                countermeasures_data = json.loads(json_match.group())
            else:
                # Fallback to structured text parsing
                countermeasures_data = {
                    "immediate_actions": content.split("Immediate Actions")[1].split("\n\n")[0] if "Immediate Actions" in content else "",
                    "short_term_actions": content.split("Short-term Actions")[1].split("\n\n")[0] if "Short-term Actions" in content else "",
                    "long_term_actions": content.split("Long-term Actions")[1].split("\n\n")[0] if "Long-term Actions" in content else "",
                    "preventive_measures": content.split("Preventive Measures")[1] if "Preventive Measures" in content else ""
                }
            
        except Exception as e:
            logger.warning(f"AI countermeasures generation failed: {e}, using fallback")
            countermeasures_data = self._create_fallback_countermeasures(
                vulnerability_analyses, categorized
            )
        
        return {
            "countermeasures": countermeasures_data,
            "categorized_vulnerabilities": categorized,
            "priority_matrix": self._create_priority_matrix(vulnerability_analyses),
            "implementation_roadmap": self._create_implementation_roadmap(categorized),
            "generated_at": datetime.now().isoformat()
        }
    
    def _create_priority_matrix(self, analyses: List[VulnerabilityAnalysis]) -> List[Dict[str, Any]]:
        """Create priority matrix for vulnerability remediation"""
        matrix = []
        for analysis in analyses:
            matrix.append({
                "vulnerability": analysis.title,
                "severity": analysis.severity.value,
                "confidence": analysis.confidence_score,
                "priority_score": self._calculate_priority_score(analysis),
                "estimated_effort": self._estimate_effort(analysis),
                "business_impact": analysis.business_impact
            })
        
        # Sort by priority score descending
        return sorted(matrix, key=lambda x: x['priority_score'], reverse=True)
    
    def _calculate_priority_score(self, analysis: VulnerabilityAnalysis) -> float:
        """Calculate priority score based on severity, confidence, and exploitability"""
        severity_weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 1}
        base_score = severity_weights.get(analysis.severity.value, 1)
        return base_score * analysis.confidence_score * analysis.exploitability_score
    
    def _estimate_effort(self, analysis: VulnerabilityAnalysis) -> str:
        """Estimate remediation effort"""
        # Simple heuristic based on severity and remediation steps
        step_count = len(analysis.remediation_steps)
        if analysis.severity.value in ["CRITICAL", "HIGH"] and step_count > 5:
            return "3-5 days"
        elif step_count > 3:
            return "1-2 days"
        else:
            return "4-8 hours"
    
    def _create_implementation_roadmap(self, categorized: Dict[str, List]) -> Dict[str, List[str]]:
        """Create timeline-based implementation roadmap"""
        roadmap = {
            "immediate": [],
            "short_term": [],
            "long_term": []
        }
        
        # Immediate: Critical and High
        for category in ["authentication", "encryption", "code_quality"]:
            if category in categorized:
                for vuln in categorized[category]:
                    if vuln.severity.value in ["CRITICAL", "HIGH"]:
                        roadmap["immediate"].append(
                            f"{vuln.title} - {vuln.remediation_steps[0] if vuln.remediation_steps else 'Review required'}"
                        )
        
        # Short-term: Medium severity
        for vulns in categorized.values():
            for vuln in vulns:
                if vuln.severity.value == "MEDIUM":
                    roadmap["short_term"].append(f"{vuln.title}")
        
        # Long-term: Low severity and preventive
        for vulns in categorized.values():
            for vuln in vulns:
                if vuln.severity.value in ["LOW", "INFO"]:
                    roadmap["long_term"].append(f"{vuln.title}")
        
        return roadmap
    
    def _create_fallback_countermeasures(self, analyses: List[VulnerabilityAnalysis], 
                                        categorized: Dict[str, List]) -> Dict[str, Any]:
        """Create fallback countermeasures when AI generation fails"""
        immediate = []
        short_term = []
        long_term = []
        
        for analysis in analyses:
            action = {
                "title": analysis.title,
                "steps": analysis.remediation_steps[:3],
                "severity": analysis.severity.value,
                "category": analysis.category.value
            }
            
            if analysis.severity.value in ["CRITICAL", "HIGH"]:
                immediate.append(action)
            elif analysis.severity.value == "MEDIUM":
                short_term.append(action)
            else:
                long_term.append(action)
        
        return {
            "immediate_actions": immediate,
            "short_term_actions": short_term,
            "long_term_actions": long_term,
            "preventive_measures": [
                "Implement security code review process",
                "Enable static analysis in CI/CD pipeline",
                "Conduct regular security training",
                "Establish secure coding guidelines"
            ]
        }


def create_langchain_analyzer(provider: str = "openai",
"""
    
    def generate_countermeasures(self, 
                                vulnerability_analyses: List[VulnerabilityAnalysis],
                                app_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate comprehensive countermeasures and action plan based on vulnerability analyses
        
        Args:
            vulnerability_analyses: List of analyzed vulnerabilities
            app_context: Application context (name, type, platform, etc.)
            
        Returns:
            Dict containing structured countermeasures, timeline, and action plan
        """
        logger.info(f"Generating countermeasures for {len(vulnerability_analyses)} vulnerabilities")
        
        # Create countermeasures prompt
        countermeasures_prompt = ChatPromptTemplate.from_messages([
            ("system", """You are a senior security architect creating a comprehensive security remediation plan.
            
Your task is to analyze all vulnerabilities and create a strategic, actionable countermeasures plan that includes:

1. IMMEDIATE ACTIONS (0-24 hours): Emergency fixes and mitigations
2. SHORT-TERM ACTIONS (1-7 days): Critical patches and security improvements
3. MEDIUM-TERM ACTIONS (1-4 weeks): Systematic security enhancements
4. LONG-TERM ACTIONS (1-3 months): Strategic security improvements and prevention

For each action:
- Provide specific, technical steps
- Estimate effort and complexity
- Identify required expertise
- Note dependencies and prerequisites
- Include code examples where helpful
- Consider business context and constraints

Format your response as a structured action plan with priorities, timelines, and implementation details."""),
            ("user", """Application Context:
{app_info}

Vulnerabilities Summary:
{vulnerability_summary}

Categorized Vulnerabilities:
{categorized_vulnerabilities}

Generate a comprehensive countermeasures and remediation action plan.""")
        ])
        
        # Prepare vulnerability summary
        categorized = {}
        for analysis in vulnerability_analyses:
            severity = analysis.priority.severity.value
            if severity not in categorized:
                categorized[severity] = []
            categorized[severity].append({
                'title': analysis.title,
                'description': analysis.description,
                'category': analysis.priority.category.value,
                'exploitability': analysis.priority.exploitability,
                'business_impact': analysis.priority.business_impact,
                'remediation_steps': analysis.remediation_steps,
                'cwe': analysis.cwe_mapping,
                'owasp': analysis.owasp_mapping
            })
        
        # Create summary text
        summary_lines = [
            f"Total Vulnerabilities: {len(vulnerability_analyses)}",
            f"Critical: {len(categorized.get('Critical', []))}",
            f"High: {len(categorized.get('High', []))}",
            f"Medium: {len(categorized.get('Medium', []))}",
            f"Low: {len(categorized.get('Low', []))}"
        ]
        
        app_info_text = f"""
App Name: {app_context.get('app_name', 'Unknown') if app_context else 'Unknown'}
Platform: {app_context.get('platform', 'Unknown') if app_context else 'Unknown'}
Package: {app_context.get('package_name', 'Unknown') if app_context else 'Unknown'}
"""
        
        try:
            # Create chain
            countermeasures_chain = countermeasures_prompt | self.llm
            
            # Generate countermeasures
            response = countermeasures_chain.invoke({
                "app_info": app_info_text,
                "vulnerability_summary": "\n".join(summary_lines),
                "categorized_vulnerabilities": json.dumps(categorized, indent=2)
            })
            
            countermeasures_text = response.content if hasattr(response, 'content') else str(response)
            
            # Structure the response
            countermeasures_plan = {
                "overview": {
                    "total_vulnerabilities": len(vulnerability_analyses),
                    "critical_count": len(categorized.get('Critical', [])),
                    "high_count": len(categorized.get('High', [])),
                    "medium_count": len(categorized.get('Medium', [])),
                    "low_count": len(categorized.get('Low', [])),
                    "app_context": app_context or {}
                },
                "detailed_plan": countermeasures_text,
                "categorized_vulnerabilities": categorized,
                "priority_matrix": self._create_priority_matrix(vulnerability_analyses),
                "implementation_roadmap": self._create_implementation_roadmap(categorized),
                "generated_at": datetime.now().isoformat()
            }
            
            logger.info("Countermeasures plan generated successfully")
            return countermeasures_plan
            
        except Exception as e:
            logger.error(f"Failed to generate countermeasures: {e}")
            return self._create_fallback_countermeasures(vulnerability_analyses, categorized)
    
    def _create_priority_matrix(self, analyses: List[VulnerabilityAnalysis]) -> List[Dict[str, Any]]:
        """Create a priority matrix for visualization"""
        matrix = []
        for analysis in analyses:
            matrix.append({
                "vulnerability": analysis.title,
                "severity": analysis.priority.severity.value,
                "priority_score": analysis.priority.priority_score,
                "category": analysis.priority.category.value,
                "exploitability": analysis.priority.exploitability,
                "business_impact": analysis.priority.business_impact,
                "effort_estimate": "Low" if len(analysis.remediation_steps) <= 3 else "High"
            })
        
        # Sort by priority score descending
        matrix.sort(key=lambda x: x['priority_score'], reverse=True)
        return matrix
    
    def _create_implementation_roadmap(self, categorized: Dict[str, List]) -> Dict[str, List[str]]:
        """Create a timeline-based implementation roadmap"""
        roadmap = {
            "immediate_0_24h": [],
            "short_term_1_7d": [],
            "medium_term_1_4w": [],
            "long_term_1_3m": []
        }
        
        # Critical issues - immediate action
        for vuln in categorized.get('Critical', []):
            roadmap["immediate_0_24h"].append(
                f"🔴 {vuln['title']}: {vuln['remediation_steps'][0] if vuln['remediation_steps'] else 'Security review required'}"
            )
        
        # High priority - short term
        for vuln in categorized.get('High', []):
            roadmap["short_term_1_7d"].append(
                f"🟠 {vuln['title']}: {vuln['remediation_steps'][0] if vuln['remediation_steps'] else 'Security patch required'}"
            )
        
        # Medium priority - medium term
        for vuln in categorized.get('Medium', []):
            roadmap["medium_term_1_4w"].append(
                f"🟡 {vuln['title']}: {vuln['remediation_steps'][0] if vuln['remediation_steps'] else 'Security improvement needed'}"
            )
        
        # Low priority - long term
        for vuln in categorized.get('Low', []):
            roadmap["long_term_1_3m"].append(
                f"🟢 {vuln['title']}: {vuln['remediation_steps'][0] if vuln['remediation_steps'] else 'Security enhancement recommended'}"
            )
        
        return roadmap
    
    def _create_fallback_countermeasures(self, analyses: List[VulnerabilityAnalysis], 
                                        categorized: Dict[str, List]) -> Dict[str, Any]:
        """Create fallback countermeasures if AI generation fails"""
        return {
            "overview": {
                "total_vulnerabilities": len(analyses),
                "critical_count": len(categorized.get('Critical', [])),
                "high_count": len(categorized.get('High', [])),
                "medium_count": len(categorized.get('Medium', [])),
                "low_count": len(categorized.get('Low', []))
            },
            "detailed_plan": """
SECURITY REMEDIATION PLAN

IMMEDIATE ACTIONS (0-24 hours):
- Review and address all CRITICAL vulnerabilities
- Implement emergency security patches
- Notify security team of critical findings

SHORT-TERM ACTIONS (1-7 days):
- Fix all HIGH severity vulnerabilities
- Conduct security code review
- Update security configurations

MEDIUM-TERM ACTIONS (1-4 weeks):
- Address MEDIUM severity issues
- Implement security best practices
- Enhance security testing

LONG-TERM ACTIONS (1-3 months):
- Resolve LOW severity findings
- Establish security training program
- Implement automated security scanning
""",
            "categorized_vulnerabilities": categorized,
            "priority_matrix": self._create_priority_matrix(analyses),
            "implementation_roadmap": self._create_implementation_roadmap(categorized),
            "generated_at": datetime.now().isoformat()
        }


def create_langchain_analyzer(provider: str = "openai", 
                            model_name: str = "gpt-4",
                            api_key: str = None,
                            **kwargs) -> LangChainVulnerabilityAnalyzer:
    """
    Factory function to create LangChain vulnerability analyzer
    
    Args:
        provider: AI provider ("openai", "anthropic")
        model_name: Model name to use
        api_key: API key for the provider
        **kwargs: Additional configuration options
        
    Returns:
        LangChainVulnerabilityAnalyzer: Configured analyzer instance
    """
    return LangChainVulnerabilityAnalyzer(
        provider=provider,
        model_name=model_name,
        api_key=api_key,
        **kwargs
    )