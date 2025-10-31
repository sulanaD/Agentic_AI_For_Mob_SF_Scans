"""
Configuration Management for LangChain-based Mobile Security Agent

This module handles configuration loading, validation, and environment setup
for the Mobile Security Agent using LangChain and LangGraph.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional
from dotenv import load_dotenv
from pydantic import BaseModel, Field, validator, ValidationError

# Load environment variables at module level
# Try to load .env from current directory first, then parent directory
current_dir = Path(__file__).parent
root_dir = current_dir.parent

env_paths = [
    current_dir / ".env",
    root_dir / ".env"
]

for env_path in env_paths:
    if env_path.exists():
        load_dotenv(env_path, override=True)
        break
else:
    # If no .env file found, just use environment variables
    load_dotenv(override=True)
MOBSF_API_URL = os.getenv('MOBSF_API_URL', 'http://localhost:8000')
MOBSF_API_KEY = os.getenv('MOBSF_API_KEY')
MOBSF_SCAN_TIMEOUT = int(os.getenv('MOBSF_SCAN_TIMEOUT', '1800'))
AI_PROVIDER = os.getenv('AI_PROVIDER', 'openai')
AI_MODEL_NAME = os.getenv('AI_MODEL_NAME', 'gpt-4')
OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
XAI_API_KEY = os.getenv('XAI_API_KEY')
AI_TEMPERATURE = float(os.getenv('AI_TEMPERATURE', '0.1'))
AI_MAX_TOKENS = int(os.getenv('AI_MAX_TOKENS', '4000'))

logger = logging.getLogger(__name__)


class MobSFConfig(BaseModel):
    """MobSF API configuration"""
    api_url: str = Field(..., description="MobSF API URL")
    api_key: str = Field(..., description="MobSF API key")
    scan_timeout: int = Field(default=1800, description="Scan timeout in seconds")
    
    @validator('api_url')
    def validate_api_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('API URL must start with http:// or https://')
        return v.rstrip('/')
    
    @validator('scan_timeout')
    def validate_timeout(cls, v):
        if v < 60 or v > 7200:  # 1 minute to 2 hours
            raise ValueError('Scan timeout must be between 60 and 7200 seconds')
        return v


class AIProviderConfig(BaseModel):
    """AI Provider configuration for LangChain integration"""
    provider: str = Field(default="openai", description="AI provider (openai, anthropic, ollama)")
    model_name: str = Field(default="gpt-4", description="Model name to use")
    api_key: Optional[str] = Field(None, description="API key for the provider")
    temperature: float = Field(default=0.1, description="Model temperature for consistency")
    max_tokens: int = Field(default=2000, description="Maximum tokens per request")
    batch_size: int = Field(default=5, description="Batch size for processing")
    enable_memory: bool = Field(default=True, description="Enable conversation memory")
    
    # Provider-specific settings
    openai_organization: Optional[str] = Field(None, description="OpenAI organization ID")
    anthropic_model_version: Optional[str] = Field(None, description="Anthropic model version")
    ollama_base_url: Optional[str] = Field("http://localhost:11434", description="Ollama base URL")
    
    @validator('provider')
    def validate_provider(cls, v):
        valid_providers = {'openai', 'anthropic', 'xai', 'groq', 'ollama'}
        if v.lower() not in valid_providers:
            raise ValueError(f'Provider must be one of {valid_providers}')
        return v.lower()
    
    @validator('batch_size')
    def validate_batch_size(cls, v):
        if v < 1 or v > 20:
            raise ValueError('Batch size must be between 1 and 20')
        return v
    
    @validator('temperature')
    def validate_temperature(cls, v):
        if v < 0.0 or v > 2.0:
            raise ValueError('Temperature must be between 0.0 and 2.0')
        return v


class ReportConfig(BaseModel):
    """Report generation configuration"""
    template_dir: str = Field(default="./templates", description="Template directory")
    output_dir: str = Field(default="./reports", description="Output directory")
    default_formats: list = Field(default=["html", "json"], description="Default report formats")
    auto_cleanup: bool = Field(default=True, description="Auto cleanup temporary files")
    max_report_size_mb: int = Field(default=100, description="Maximum report size in MB")
    
    @validator('default_formats')
    def validate_formats(cls, v):
        valid_formats = {'html', 'pdf', 'json'}
        for fmt in v:
            if fmt not in valid_formats:
                raise ValueError(f'Invalid format: {fmt}. Must be one of {valid_formats}')
        return v


class VulnerabilityConfig(BaseModel):
    """Vulnerability analysis configuration"""
    min_severity: str = Field(default="low", description="Minimum severity level")
    enable_deduplication: bool = Field(default=True, description="Enable vulnerability deduplication")
    category_filters: list = Field(default=[], description="Category filters to apply")
    exclude_types: list = Field(default=[], description="Vulnerability types to exclude")
    
    @validator('min_severity')
    def validate_severity(cls, v):
        valid_severities = {'low', 'medium', 'high', 'critical'}
        if v.lower() not in valid_severities:
            raise ValueError(f'Invalid severity: {v}. Must be one of {valid_severities}')
        return v.lower()


class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = Field(default="INFO", description="Logging level")
    log_file: str = Field(default="./logs/agent.log", description="Log file path")
    max_file_size_mb: int = Field(default=10, description="Maximum log file size in MB")
    backup_count: int = Field(default=5, description="Number of backup log files")
    console_output: bool = Field(default=True, description="Enable console output")
    
    @validator('level')
    def validate_level(cls, v):
        valid_levels = {'DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'}
        if v.upper() not in valid_levels:
            raise ValueError(f'Invalid log level: {v}. Must be one of {valid_levels}')
        return v.upper()


class WorkflowConfig(BaseModel):
    """LangGraph workflow configuration"""
    enable_persistence: bool = Field(default=True, description="Enable workflow state persistence")
    checkpoint_path: str = Field(default="./checkpoints/security_analysis.db", description="Checkpoint database path")
    max_concurrent_workflows: int = Field(default=3, description="Maximum concurrent workflows")
    retry_attempts: int = Field(default=2, description="Number of retry attempts for failed steps")
    
    @validator('max_concurrent_workflows')
    def validate_concurrent(cls, v):
        if v < 1 or v > 10:
            raise ValueError('Max concurrent workflows must be between 1 and 10')
        return v


class AgentConfig(BaseModel):
    """Complete agent configuration"""
    mobsf: MobSFConfig
    ai_provider: AIProviderConfig = Field(default_factory=AIProviderConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    vulnerabilities: VulnerabilityConfig = Field(default_factory=VulnerabilityConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    workflow: WorkflowConfig = Field(default_factory=WorkflowConfig)
    
    # Agent-specific settings
    parallel_scanning: bool = Field(default=False, description="Enable parallel scanning")
    max_concurrent_scans: int = Field(default=3, description="Maximum concurrent scans")
    cache_scan_results: bool = Field(default=True, description="Cache scan results")
    cache_duration_hours: int = Field(default=24, description="Cache duration in hours")
    
    @validator('max_concurrent_scans')
    def validate_concurrent_scans(cls, v):
        if v < 1 or v > 10:
            raise ValueError('Max concurrent scans must be between 1 and 10')
        return v


class ConfigurationError(Exception):
    """Custom exception for configuration errors"""
    pass


class ConfigManager:
    """
    Configuration manager for the LangChain-based Mobile Security Agent
    """
    
    def __init__(self, config_file: str = None, env_file: str = None):
        """
        Initialize configuration manager
        
        Args:
            config_file (str): Path to configuration file
            env_file (str): Path to environment file
        """
        self.config_file = config_file or os.getenv('AGENT_CONFIG_FILE', './config.json')
        self.env_file = env_file or os.getenv('AGENT_ENV_FILE', './.env')
        self.config = None
        
        # Load configuration
        self._load_environment()
        self._load_configuration()
    
    def _load_environment(self) -> None:
        """Load environment variables from .env file"""
        if os.path.exists(self.env_file):
            load_dotenv(self.env_file, override=True)
            logger.info(f"Loaded environment variables from: {self.env_file}")
        else:
            logger.warning(f"Environment file not found: {self.env_file}")
    
    def reload_environment_variables(self) -> None:
        """Force reload of all environment variables and update module globals"""
        global MOBSF_API_URL, MOBSF_API_KEY, MOBSF_SCAN_TIMEOUT, AI_PROVIDER, AI_MODEL_NAME
        global OPENAI_API_KEY, ANTHROPIC_API_KEY, GROQ_API_KEY, XAI_API_KEY, AI_TEMPERATURE, AI_MAX_TOKENS
        
        # Force reload multiple .env file locations
        load_dotenv('./.env', override=True)
        load_dotenv(self.env_file, override=True)
        
        # Update module-level variables
        MOBSF_API_URL = os.getenv('MOBSF_API_URL', 'http://localhost:8000')
        MOBSF_API_KEY = os.getenv('MOBSF_API_KEY')
        
        # Force correct API key if needed from environment
        correct_api_key = os.getenv('MOBSF_API_KEY_OVERRIDE') or os.getenv('MOBSF_API_KEY')
        if correct_api_key and (not MOBSF_API_KEY or MOBSF_API_KEY != correct_api_key):
            MOBSF_API_KEY = correct_api_key
            os.environ['MOBSF_API_KEY'] = MOBSF_API_KEY
        
        MOBSF_SCAN_TIMEOUT = int(os.getenv('MOBSF_SCAN_TIMEOUT', '1800'))
        AI_PROVIDER = os.getenv('AI_PROVIDER', 'openai')
        AI_MODEL_NAME = os.getenv('AI_MODEL_NAME', 'gpt-4')
        OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
        ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY')
        GROQ_API_KEY = os.getenv('GROQ_API_KEY')
        XAI_API_KEY = os.getenv('XAI_API_KEY')
        AI_TEMPERATURE = float(os.getenv('AI_TEMPERATURE', '0.1'))
        AI_MAX_TOKENS = int(os.getenv('AI_MAX_TOKENS', '4000'))
        
        logger.info(f"Reloaded environment variables: MOBSF_API_KEY = {MOBSF_API_KEY[:10] + '...' if MOBSF_API_KEY else 'NOT_SET'}")
        
        # Reload configuration
        self._load_configuration()
    
    def _load_configuration(self) -> None:
        """Load and validate configuration"""
        try:
            # Try to load from config file first
            if os.path.exists(self.config_file):
                config_data = self._load_config_file()
                logger.info(f"Loaded configuration from: {self.config_file}")
            else:
                config_data = {}
                logger.info("Using environment-based configuration")
            
            # Override with environment variables
            config_data = self._merge_with_environment(config_data)
            
            # Validate configuration
            self.config = AgentConfig(**config_data)
            logger.info("Configuration validated successfully")
            
        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e}")
            raise ConfigurationError(f"Invalid configuration: {e}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise ConfigurationError(f"Configuration loading failed: {e}")
    
    def _load_config_file(self) -> Dict[str, Any]:
        """Load configuration from JSON file"""
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in config file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Failed to read config file: {e}")
    
    def _merge_with_environment(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configuration with environment variables"""
        
        # MobSF configuration
        mobsf_config = config_data.get('mobsf', {})
        mobsf_config.update({
            'api_url': MOBSF_API_URL or mobsf_config.get('api_url'),
            'api_key': MOBSF_API_KEY or mobsf_config.get('api_key'),
            'scan_timeout': MOBSF_SCAN_TIMEOUT or mobsf_config.get('scan_timeout', 1800)
        })
        config_data['mobsf'] = mobsf_config
        
        # AI Provider configuration
        ai_config = config_data.get('ai_provider', {})
        ai_config.update({
            'provider': AI_PROVIDER or ai_config.get('provider', 'openai'),
            'model_name': AI_MODEL_NAME or ai_config.get('model_name', 'gpt-4'),
            'api_key': (OPENAI_API_KEY or 
                       ANTHROPIC_API_KEY or 
                       XAI_API_KEY or 
                       GROQ_API_KEY or 
                       os.getenv('OLLAMA_API_KEY') or 
                       ai_config.get('api_key')),
            'temperature': AI_TEMPERATURE or ai_config.get('temperature', 0.1),
            'max_tokens': AI_MAX_TOKENS or ai_config.get('max_tokens', 4000),
            'batch_size': int(os.getenv('AI_BATCH_SIZE', str(ai_config.get('batch_size', 5)))),
            'enable_memory': os.getenv('AI_ENABLE_MEMORY', str(ai_config.get('enable_memory', True))).lower() == 'true',
            'ollama_base_url': os.getenv('OLLAMA_BASE_URL') or ai_config.get('ollama_base_url', 'http://localhost:11434')
        })
        config_data['ai_provider'] = ai_config
        
        # Report configuration
        report_config = config_data.get('reports', {})
        report_config.update({
            'template_dir': os.getenv('REPORT_TEMPLATE_DIR') or report_config.get('template_dir', './templates'),
            'output_dir': os.getenv('REPORT_OUTPUT_DIR') or report_config.get('output_dir', './reports'),
            'auto_cleanup': os.getenv('REPORT_AUTO_CLEANUP', str(report_config.get('auto_cleanup', True))).lower() == 'true'
        })
        config_data['reports'] = report_config
        
        # Vulnerability configuration
        vuln_config = config_data.get('vulnerabilities', {})
        vuln_config.update({
            'min_severity': os.getenv('MIN_SEVERITY_FILTER') or vuln_config.get('min_severity', 'low'),
            'enable_deduplication': os.getenv('ENABLE_DEDUPLICATION', str(vuln_config.get('enable_deduplication', True))).lower() == 'true'
        })
        config_data['vulnerabilities'] = vuln_config
        
        # Logging configuration
        log_config = config_data.get('logging', {})
        log_config.update({
            'level': os.getenv('LOG_LEVEL') or log_config.get('level', 'INFO'),
            'log_file': os.getenv('LOG_FILE') or log_config.get('log_file', './logs/agent.log'),
            'console_output': os.getenv('LOG_CONSOLE', str(log_config.get('console_output', True))).lower() == 'true'
        })
        config_data['logging'] = log_config
        
        # Workflow configuration
        workflow_config = config_data.get('workflow', {})
        workflow_config.update({
            'enable_persistence': os.getenv('WORKFLOW_PERSISTENCE', str(workflow_config.get('enable_persistence', True))).lower() == 'true',
            'checkpoint_path': os.getenv('WORKFLOW_CHECKPOINT_PATH') or workflow_config.get('checkpoint_path', './checkpoints/security_analysis.db')
        })
        config_data['workflow'] = workflow_config
        
        return config_data
    
    def get_config(self) -> AgentConfig:
        """
        Get the validated configuration
        
        Returns:
            AgentConfig: Validated configuration object
        """
        if not self.config:
            raise ConfigurationError("Configuration not loaded")
        return self.config
    
    def create_default_config_file(self, file_path: str = None) -> str:
        """
        Create a default configuration file for LangChain-based agent
        
        Args:
            file_path (str): Path for the config file
            
        Returns:
            str: Path to created config file
        """
        file_path = file_path or self.config_file
        
        default_config = {
            "mobsf": {
                "api_url": "http://localhost:8000",
                "api_key": "your_mobsf_api_key_here",
                "scan_timeout": 1800
            },
            "ai_provider": {
                "provider": "openai",
                "model_name": "gpt-4",
                "api_key": "your_openai_or_anthropic_or_ollama_api_key_here",
                "temperature": 0.1,
                "max_tokens": 2000,
                "batch_size": 5,
                "enable_memory": True,
                "ollama_base_url": "http://localhost:11434"
            },
            "reports": {
                "template_dir": "./templates",
                "output_dir": "./reports",
                "default_formats": ["html", "json"],
                "auto_cleanup": True,
                "max_report_size_mb": 100
            },
            "vulnerabilities": {
                "min_severity": "low",
                "enable_deduplication": True,
                "category_filters": [],
                "exclude_types": []
            },
            "logging": {
                "level": "INFO",
                "log_file": "./logs/agent.log",
                "max_file_size_mb": 10,
                "backup_count": 5,
                "console_output": True
            },
            "workflow": {
                "enable_persistence": True,
                "checkpoint_path": "./checkpoints/security_analysis.db",
                "max_concurrent_workflows": 3,
                "retry_attempts": 2
            },
            "parallel_scanning": False,
            "max_concurrent_scans": 3,
            "cache_scan_results": True,
            "cache_duration_hours": 24
        }
        
        # Ensure directory exists
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        
        # Write config file
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=2)
        
        logger.info(f"Created default configuration file: {file_path}")
        return file_path
    
    def validate_configuration(self) -> Dict[str, Any]:
        """
        Validate current configuration and return validation results
        
        Returns:
            Dict[str, Any]: Validation results
        """
        validation_results = {
            'valid': True,
            'errors': [],
            'warnings': [],
            'missing_required': []
        }
        
        try:
            config = self.get_config()
            
            # Check required fields
            if not config.mobsf.api_url:
                validation_results['missing_required'].append('MobSF API URL')
            if not config.mobsf.api_key:
                validation_results['missing_required'].append('MobSF API Key')
            
            # Check AI provider configuration
            if not config.ai_provider.api_key:
                validation_results['warnings'].append('AI provider API key not provided - AI features may be limited')
            
            # Validate AI provider specific requirements
            if config.ai_provider.provider == 'openai' and not os.getenv('OPENAI_API_KEY'):
                validation_results['warnings'].append('OpenAI API key not found in environment')
            elif config.ai_provider.provider == 'anthropic' and not os.getenv('ANTHROPIC_API_KEY'):
                validation_results['warnings'].append('Anthropic API key not found in environment')
            elif config.ai_provider.provider == 'xai' and not os.getenv('XAI_API_KEY'):
                validation_results['warnings'].append('xAI API key not found in environment')
            elif config.ai_provider.provider == 'groq' and not os.getenv('GROQ_API_KEY'):
                validation_results['warnings'].append('Groq API key not found in environment')
            elif config.ai_provider.provider == 'ollama':
                # For Ollama, check if the service is accessible
                validation_results['warnings'].append('Ollama configured - ensure Ollama server is running')
                if not os.getenv('OLLAMA_API_KEY') and config.ai_provider.api_key:
                    validation_results['warnings'].append('Ollama API key provided - this may be for a hosted instance')
            
            # Check directories
            for dir_path in [config.reports.template_dir, config.reports.output_dir]:
                if not os.path.exists(dir_path):
                    validation_results['warnings'].append(f'Directory does not exist: {dir_path}')
            
            # Update overall validity
            if validation_results['missing_required'] or validation_results['errors']:
                validation_results['valid'] = False
            
        except Exception as e:
            validation_results['valid'] = False
            validation_results['errors'].append(str(e))
        
        return validation_results
    
    def setup_logging(self) -> None:
        """Setup logging based on configuration"""
        if not self.config:
            return
        
        log_config = self.config.logging
        
        # Create logs directory
        log_file_path = Path(log_config.log_file)
        log_file_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure logging
        handlers = []
        
        # File handler
        file_handler = logging.FileHandler(log_config.log_file, encoding='utf-8')
        file_handler.setLevel(getattr(logging, log_config.level))
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        handlers.append(file_handler)
        
        # Console handler
        if log_config.console_output:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, log_config.level))
            console_formatter = logging.Formatter(
                '%(levelname)s - %(name)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            handlers.append(console_handler)
        
        # Configure root logger
        logging.basicConfig(
            level=getattr(logging, log_config.level),
            handlers=handlers,
            force=True
        )
        
        logger.info(f"Logging configured: level={log_config.level}, file={log_config.log_file}")


def create_config_manager(config_file: str = None, env_file: str = None) -> ConfigManager:
    """
    Factory function to create configuration manager
    
    Args:
        config_file (str): Path to configuration file
        env_file (str): Path to environment file
        
    Returns:
        ConfigManager: Configured manager instance
    """
    return ConfigManager(config_file, env_file)


def setup_agent_directories(config: AgentConfig) -> None:
    """
    Setup required directories for the agent
    
    Args:
        config (AgentConfig): Agent configuration
    """
    directories = [
        config.reports.template_dir,
        config.reports.output_dir,
        Path(config.logging.log_file).parent,
        Path(config.workflow.checkpoint_path).parent
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured directory exists: {directory}")


def get_quick_config() -> AgentConfig:
    """
    Get a quick configuration for testing/development
    
    Returns:
        AgentConfig: Basic configuration with environment variables
    """
    return AgentConfig(
        mobsf=MobSFConfig(
            api_url=MOBSF_API_URL,
            api_key=MOBSF_API_KEY or 'test_key'
        ),
        ai_provider=AIProviderConfig(
            provider=AI_PROVIDER,
            api_key=OPENAI_API_KEY or ANTHROPIC_API_KEY or XAI_API_KEY or GROQ_API_KEY
        )
    )