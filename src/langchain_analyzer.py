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
            provider: AI provider ("openai", "anthropic", "ollama")
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
            raise ValueError(f"Unsupported provider: {provider}. Supported: openai, anthropic, groq, ollama")
    
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
    
    def generate_countermeasures(self, categorized_vulns: Dict[str, List[VulnerabilityAnalysis]], 
                                app_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Generate comprehensive countermeasures and action plan using AI
        
        Args:
            categorized_vulns: Categorized vulnerabilities
            app_context: Application context information
            
        Returns:
            Dict containing countermeasures, action plan, and implementation timeline
        """
        logger.info("Generating AI-powered countermeasures and action plan")
        
        try:
            # Count vulnerabilities by severity
            counts = {
                'critical': len(categorized_vulns.get('Critical', [])),
                'high': len(categorized_vulns.get('High', [])),
                'medium': len(categorized_vulns.get('Medium', [])),
                'low': len(categorized_vulns.get('Low', []))
            }
            
            # Prepare vulnerability summaries for AI analysis
            vulnerability_summaries = []
            for severity, vulns in categorized_vulns.items():
                for vuln in vulns[:5]:  # Top 5 per category to avoid token limits
                    vulnerability_summaries.append({
                        'severity': severity,
                        'title': vuln.title,
                        'category': vuln.priority.category.value,
                        'description': vuln.description[:200],  # Truncate for token efficiency
                        'remediation_steps': vuln.remediation_steps[:3]  # Top 3 steps
                    })
            
            # Create countermeasures prompt
            countermeasures_prompt = ChatPromptTemplate.from_template(
                """You are a senior mobile application security expert tasked with creating comprehensive countermeasures and an action plan for identified vulnerabilities.

VULNERABILITY ANALYSIS:
Security Score: Based on {critical} critical, {high} high, {medium} medium, and {low} low severity vulnerabilities.

APP CONTEXT:
- App Name: {app_name}
- Platform: {platform}
- File: {file_name}

TOP VULNERABILITIES:
{vulnerability_details}

Your task is to create a comprehensive response including:

1. **IMMEDIATE ACTIONS** (0-7 days): Critical fixes that must be implemented immediately
2. **SHORT-TERM ACTIONS** (1-4 weeks): High-priority security improvements  
3. **MEDIUM-TERM ACTIONS** (1-3 months): Medium-priority security enhancements
4. **LONG-TERM ACTIONS** (3-6 months): Low-priority improvements and security hardening
5. **SECURITY BEST PRACTICES**: General recommendations for ongoing security
6. **IMPLEMENTATION PRIORITIES**: Risk-based prioritization of all countermeasures
7. **COMPLIANCE CONSIDERATIONS**: Relevant security standards and regulations
8. **MONITORING & VALIDATION**: How to verify fixes and monitor for new threats

For each action item, provide:
- Specific technical steps
- Estimated effort (hours/days)  
- Required resources/skills
- Risk reduction impact
- Implementation complexity (Low/Medium/High)

Return the response as a well-structured JSON object with the following structure:
{{
    "immediate_actions": [
        {{
            "title": "Action title",
            "description": "Detailed description",
            "steps": ["Step 1", "Step 2"],
            "effort_estimate": "X hours/days",
            "complexity": "Low/Medium/High",
            "risk_reduction": "High/Medium/Low",
            "priority": 1
        }}
    ],
    "short_term_actions": [...],
    "medium_term_actions": [...], 
    "long_term_actions": [...],
    "security_best_practices": [
        {{
            "category": "Category name",
            "recommendations": ["Recommendation 1", "Recommendation 2"]
        }}
    ],
    "implementation_timeline": {{
        "week_1": ["Immediate action 1", "Immediate action 2"],
        "month_1": ["Short-term action 1"],
        "month_3": ["Medium-term action 1"],
        "month_6": ["Long-term action 1"]
    }},
    "compliance_notes": [
        "OWASP Mobile Top 10 compliance note",
        "GDPR/privacy consideration",
        "Platform-specific security requirement"
    ],
    "monitoring_validation": [
        "Validation step 1",
        "Monitoring recommendation 1"
    ]
}}"""
            )
            
            # Format vulnerability details
            vuln_details = []
            for vuln in vulnerability_summaries:
                steps_text = ", ".join(vuln['remediation_steps']) if vuln['remediation_steps'] else "No specific steps provided"
                vuln_details.append(
                    f"- [{vuln['severity']}] {vuln['title']} ({vuln['category']}): {vuln['description']}... "
                    f"Remediation: {steps_text}"
                )
            
            vulnerability_details_text = "\n".join(vuln_details) if vuln_details else "No specific vulnerabilities detailed"
            
            # Get app context
            app_name = app_context.get('app_name', 'Unknown App') if app_context else 'Unknown App'
            platform = app_context.get('platform', 'Mobile') if app_context else 'Mobile'
            file_name = app_context.get('file_name', 'Unknown') if app_context else 'Unknown'
            
            # Generate countermeasures using AI
            chain = countermeasures_prompt | self.llm | JsonOutputParser()
            
            result = chain.invoke({
                "critical": counts['critical'],
                "high": counts['high'],
                "medium": counts['medium'],
                "low": counts['low'],
                "app_name": app_name,
                "platform": platform,
                "file_name": file_name,
                "vulnerability_details": vulnerability_details_text
            })
            
            # Add metadata
            result["generation_metadata"] = {
                "timestamp": datetime.now().isoformat(),
                "total_vulnerabilities_analyzed": sum(counts.values()),
                "ai_model": str(self.llm),
                "analysis_scope": "Comprehensive countermeasures and action plan"
            }
            
            logger.info(f"Generated countermeasures with {len(result.get('immediate_actions', []))} immediate actions")
            return result
            
        except Exception as e:
            logger.error(f"Countermeasures generation failed: {e}")
            # Return fallback countermeasures
            return self._create_fallback_countermeasures(counts, app_context)
    
    def _create_fallback_countermeasures(self, counts: Dict[str, int], app_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create fallback countermeasures when AI processing fails"""
        return {
            "immediate_actions": [
                {
                    "title": "Manual Security Review Required",
                    "description": "AI countermeasures generation failed. Conduct immediate manual security review.",
                    "steps": [
                        "Review all critical vulnerabilities manually",
                        "Consult security expert",
                        "Implement critical fixes immediately"
                    ],
                    "effort_estimate": "2-5 days",
                    "complexity": "High",
                    "risk_reduction": "High",
                    "priority": 1
                }
            ],
            "short_term_actions": [
                {
                    "title": "Comprehensive Security Assessment",
                    "description": "Conduct thorough security assessment to identify all vulnerabilities",
                    "steps": [
                        "Perform penetration testing",
                        "Code security review",
                        "Update security policies"
                    ],
                    "effort_estimate": "1-2 weeks",
                    "complexity": "Medium",
                    "risk_reduction": "High",
                    "priority": 2
                }
            ],
            "medium_term_actions": [],
            "long_term_actions": [],
            "security_best_practices": [
                {
                    "category": "General Security",
                    "recommendations": [
                        "Implement secure coding practices",
                        "Regular security assessments",
                        "Keep dependencies updated"
                    ]
                }
            ],
            "implementation_timeline": {
                "week_1": ["Manual Security Review Required"],
                "month_1": ["Comprehensive Security Assessment"],
                "month_3": [],
                "month_6": []
            },
            "compliance_notes": [
                "Follow OWASP Mobile Top 10 guidelines",
                "Ensure compliance with relevant data protection regulations"
            ],
            "monitoring_validation": [
                "Regular security scans",
                "Penetration testing",
                "Code review processes"
            ],
            "generation_metadata": {
                "timestamp": datetime.now().isoformat(),
                "total_vulnerabilities_analyzed": sum(counts.values()),
                "fallback_reason": "AI generation failed",
                "analysis_scope": "Fallback countermeasures"
            }
        }
    
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