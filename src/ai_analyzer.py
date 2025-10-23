"""
Hugging Face AI Integration Module

This module provides AI-powered vulnerability analysis using Hugging Face's Inference API
to categorize and prioritize security findings from MobSF scans.
"""

import json
import os
import re
from typing import Dict, List, Any, Optional, Tuple
import logging
from huggingface_hub import InferenceClient, login
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class VulnerabilityPriority(BaseModel):
    """Model for vulnerability priority classification"""
    severity: str = Field(..., description="Severity level: Critical, High, Medium, Low")
    priority_score: float = Field(..., description="Priority score from 0.0 to 1.0")
    reasoning: str = Field(..., description="AI reasoning for the classification")
    category: str = Field(..., description="Vulnerability category")


class VulnerabilityAnalysis(BaseModel):
    """Model for complete vulnerability analysis"""
    vulnerability_id: str
    title: str
    description: str
    priority: VulnerabilityPriority
    impact: str
    recommendation: str
    technical_details: Dict[str, Any]


class HuggingFaceAIError(Exception):
    """Custom exception for Hugging Face AI related errors"""
    pass


class VulnerabilityAnalyzer:
    """
    AI-powered vulnerability analyzer using Hugging Face models
    """
    
    def __init__(self, api_token: str, model_name: str = "microsoft/DialoGPT-medium"):
        """
        Initialize the vulnerability analyzer
        
        Args:
            api_token (str): Hugging Face API token
            model_name (str): Model to use for analysis
        """
        self.api_token = api_token
        self.model_name = model_name
        self.client = None
        
        # Initialize client
        try:
            if api_token:
                login(token=api_token)
            self.client = InferenceClient(model=model_name, token=api_token)
            logger.info(f"Initialized Hugging Face client with model: {model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize Hugging Face client: {e}")
            raise HuggingFaceAIError(f"Client initialization failed: {e}")
    
    def _create_vulnerability_prompt(self, vulnerability: Dict[str, Any]) -> str:
        """
        Create a structured prompt for vulnerability analysis
        
        Args:
            vulnerability (Dict[str, Any]): Vulnerability data from MobSF
            
        Returns:
            str: Formatted prompt for AI analysis
        """
        title = vulnerability.get('title', 'Unknown Vulnerability')
        description = vulnerability.get('description', 'No description available')
        severity = vulnerability.get('severity', 'Unknown')
        type_info = vulnerability.get('type', 'Unknown')
        
        prompt = f"""
Analyze the following mobile application security vulnerability and provide a detailed assessment:

VULNERABILITY DETAILS:
Title: {title}
Type: {type_info}
Current Severity: {severity}
Description: {description}

ANALYSIS REQUIRED:
1. Classify the severity as Critical, High, Medium, or Low
2. Provide a priority score from 0.0 (lowest) to 1.0 (highest)
3. Explain the reasoning for this classification
4. Identify the vulnerability category
5. Assess the potential impact
6. Provide specific remediation recommendations

Please respond in JSON format with the following structure:
{{
    "severity": "Critical|High|Medium|Low",
    "priority_score": 0.0-1.0,
    "reasoning": "Detailed explanation",
    "category": "Vulnerability category",
    "impact": "Impact assessment",
    "recommendation": "Remediation steps"
}}
"""
        return prompt
    
    def _extract_json_from_response(self, response: str) -> Dict[str, Any]:
        """
        Extract JSON from AI response, handling various formats
        
        Args:
            response (str): AI response text
            
        Returns:
            Dict[str, Any]: Parsed JSON data
        """
        try:
            # First try to parse the entire response as JSON
            return json.loads(response.strip())
        except json.JSONDecodeError:
            # Try to find JSON within the response
            json_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', response, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass
            
            # Fallback: create structured response from text
            return self._create_fallback_analysis(response)
    
    def _create_fallback_analysis(self, response: str) -> Dict[str, Any]:
        """
        Create fallback analysis when JSON parsing fails
        
        Args:
            response (str): AI response text
            
        Returns:
            Dict[str, Any]: Structured analysis data
        """
        # Extract severity keywords
        severity = "Medium"  # default
        if any(word in response.lower() for word in ["critical", "severe", "dangerous"]):
            severity = "Critical"
        elif any(word in response.lower() for word in ["high", "important", "serious"]):
            severity = "High"
        elif any(word in response.lower() for word in ["low", "minor", "negligible"]):
            severity = "Low"
        
        # Calculate priority score based on severity
        priority_scores = {"Critical": 0.9, "High": 0.7, "Medium": 0.5, "Low": 0.3}
        priority_score = priority_scores.get(severity, 0.5)
        
        return {
            "severity": severity,
            "priority_score": priority_score,
            "reasoning": response[:500] + "..." if len(response) > 500 else response,
            "category": "Security Vulnerability",
            "impact": "Potential security risk identified",
            "recommendation": "Review and address this vulnerability according to best practices"
        }
    
    def analyze_vulnerability(self, vulnerability: Dict[str, Any]) -> VulnerabilityAnalysis:
        """
        Analyze a single vulnerability using AI
        
        Args:
            vulnerability (Dict[str, Any]): Vulnerability data from MobSF
            
        Returns:
            VulnerabilityAnalysis: Complete analysis with AI insights
        """
        if not self.client:
            raise HuggingFaceAIError("Client not initialized")
        
        vuln_id = vulnerability.get('id', f"vuln_{hash(str(vulnerability))}")
        title = vulnerability.get('title', 'Unknown Vulnerability')
        description = vulnerability.get('description', 'No description available')
        
        logger.info(f"Analyzing vulnerability: {title}")
        
        try:
            # Create analysis prompt
            prompt = self._create_vulnerability_prompt(vulnerability)
            
            # Get AI response
            response = self.client.text_generation(
                prompt,
                max_new_tokens=500,
                temperature=0.3,
                do_sample=True,
                top_p=0.9
            )
            
            # Parse response
            analysis_data = self._extract_json_from_response(response)
            
            # Create priority object
            priority = VulnerabilityPriority(
                severity=analysis_data.get('severity', 'Medium'),
                priority_score=float(analysis_data.get('priority_score', 0.5)),
                reasoning=analysis_data.get('reasoning', 'AI analysis completed'),
                category=analysis_data.get('category', 'Security Vulnerability')
            )
            
            # Create complete analysis
            analysis = VulnerabilityAnalysis(
                vulnerability_id=vuln_id,
                title=title,
                description=description,
                priority=priority,
                impact=analysis_data.get('impact', 'Impact assessment pending'),
                recommendation=analysis_data.get('recommendation', 'Review required'),
                technical_details=vulnerability
            )
            
            logger.info(f"Analysis completed for {title}: {priority.severity} ({priority.priority_score:.2f})")
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing vulnerability {title}: {e}")
            # Create fallback analysis
            priority = VulnerabilityPriority(
                severity="Medium",
                priority_score=0.5,
                reasoning=f"Analysis failed: {str(e)}",
                category="Security Vulnerability"
            )
            
            return VulnerabilityAnalysis(
                vulnerability_id=vuln_id,
                title=title,
                description=description,
                priority=priority,
                impact="Impact assessment failed",
                recommendation="Manual review required",
                technical_details=vulnerability
            )
    
    def analyze_vulnerability_batch(self, vulnerabilities: List[Dict[str, Any]], 
                                  batch_size: int = 5) -> List[VulnerabilityAnalysis]:
        """
        Analyze multiple vulnerabilities in batches
        
        Args:
            vulnerabilities (List[Dict[str, Any]]): List of vulnerabilities
            batch_size (int): Number of vulnerabilities to process at once
            
        Returns:
            List[VulnerabilityAnalysis]: List of analyzed vulnerabilities
        """
        logger.info(f"Starting batch analysis of {len(vulnerabilities)} vulnerabilities")
        analyses = []
        
        for i in range(0, len(vulnerabilities), batch_size):
            batch = vulnerabilities[i:i + batch_size]
            logger.info(f"Processing batch {i//batch_size + 1}/{(len(vulnerabilities) + batch_size - 1)//batch_size}")
            
            for vuln in batch:
                try:
                    analysis = self.analyze_vulnerability(vuln)
                    analyses.append(analysis)
                except Exception as e:
                    logger.error(f"Failed to analyze vulnerability in batch: {e}")
                    continue
        
        logger.info(f"Batch analysis completed: {len(analyses)} vulnerabilities analyzed")
        return analyses
    
    def categorize_vulnerabilities(self, analyses: List[VulnerabilityAnalysis]) -> Dict[str, List[VulnerabilityAnalysis]]:
        """
        Categorize vulnerabilities by priority level
        
        Args:
            analyses (List[VulnerabilityAnalysis]): List of vulnerability analyses
            
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
            severity = analysis.priority.severity
            if severity in categories:
                categories[severity].append(analysis)
            else:
                categories["Medium"].append(analysis)  # Default fallback
        
        # Sort each category by priority score (highest first)
        for category in categories:
            categories[category].sort(key=lambda x: x.priority.priority_score, reverse=True)
        
        logger.info(f"Vulnerabilities categorized: "
                   f"Critical: {len(categories['Critical'])}, "
                   f"High: {len(categories['High'])}, "
                   f"Medium: {len(categories['Medium'])}, "
                   f"Low: {len(categories['Low'])}")
        
        return categories
    
    def generate_executive_summary(self, categorized_vulns: Dict[str, List[VulnerabilityAnalysis]]) -> str:
        """
        Generate an executive summary of the vulnerability analysis
        
        Args:
            categorized_vulns (Dict[str, List[VulnerabilityAnalysis]]): Categorized vulnerabilities
            
        Returns:
            str: Executive summary text
        """
        total_vulns = sum(len(vulns) for vulns in categorized_vulns.values())
        critical_count = len(categorized_vulns.get("Critical", []))
        high_count = len(categorized_vulns.get("High", []))
        
        summary_prompt = f"""
Generate an executive summary for a mobile application security scan with the following results:

VULNERABILITY COUNTS:
- Total Vulnerabilities: {total_vulns}
- Critical: {critical_count}
- High: {high_count}
- Medium: {len(categorized_vulns.get("Medium", []))}
- Low: {len(categorized_vulns.get("Low", []))}

TOP CRITICAL VULNERABILITIES:
"""
        
        # Add top 3 critical vulnerabilities
        for i, vuln in enumerate(categorized_vulns.get("Critical", [])[:3]):
            summary_prompt += f"\n{i+1}. {vuln.title}: {vuln.priority.reasoning[:100]}..."
        
        summary_prompt += """

Please provide a concise executive summary (200-300 words) that includes:
1. Overall security posture assessment
2. Key risk areas
3. Priority recommendations
4. Business impact considerations
"""
        
        try:
            response = self.client.text_generation(
                summary_prompt,
                max_new_tokens=400,
                temperature=0.5,
                do_sample=True
            )
            return response.strip()
        except Exception as e:
            logger.error(f"Failed to generate executive summary: {e}")
            return f"""
EXECUTIVE SUMMARY

The mobile application security scan identified {total_vulns} vulnerabilities across different severity levels. 
Of particular concern are {critical_count} critical vulnerabilities and {high_count} high-severity issues that 
require immediate attention.

The application shows significant security risks that could impact user data protection and application integrity. 
Priority should be given to addressing critical and high-severity vulnerabilities before deployment.

Recommended immediate actions:
1. Address all critical vulnerabilities
2. Implement security controls for high-priority issues
3. Conduct additional security testing
4. Review and update security practices
"""


def create_vulnerability_analyzer(api_token: str = None, model_name: str = None) -> VulnerabilityAnalyzer:
    """
    Factory function to create vulnerability analyzer with environment variable fallback
    
    Args:
        api_token (str): Hugging Face API token (uses HUGGINGFACE_API_TOKEN env var if None)
        model_name (str): Model name (uses HUGGINGFACE_MODEL env var if None)
        
    Returns:
        VulnerabilityAnalyzer: Configured analyzer instance
        
    Raises:
        HuggingFaceAIError: If required configuration is missing
    """
    api_token = api_token or os.getenv('HUGGINGFACE_API_TOKEN')
    model_name = model_name or os.getenv('HUGGINGFACE_MODEL', 'microsoft/DialoGPT-medium')
    
    if not api_token:
        logger.warning("Hugging Face API token not provided - some features may be limited")
    
    return VulnerabilityAnalyzer(api_token, model_name)