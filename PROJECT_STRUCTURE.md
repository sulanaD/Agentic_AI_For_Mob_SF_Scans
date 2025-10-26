# Project Structure

## Core Files

### Main Application
- `agent.py` - CLI entry point for the Mobile Security Agent
- `requirements.txt` - Python dependencies

### Examples & Validation
- `examples.py` - Basic usage examples
- `langchain_examples.py` - LangChain-specific examples
- `validate_langchain.py` - Configuration validation script

### Documentation
- `README.md` - Main project documentation
- `README_LANGCHAIN.md` - LangChain architecture documentation

### Configuration
- `.env` - Environment variables (not committed)
- `.env.example` - Example environment configuration
- `.gitignore` - Git ignore rules

## Source Code (`src/`)
- `mobile_security_agent.py` - Main orchestrator agent
- `security_workflow.py` - LangGraph-based workflow
- `langchain_analyzer.py` - AI vulnerability analyzer using LangChain
- `langchain_config.py` - Configuration management
- `mobsf_client.py` - MobSF API client
- `vulnerability_extractor.py` - Vulnerability extraction from MobSF results
- `report_generator.py` - Report generation (HTML/JSON/PDF)
- `ai_analyzer.py` - Legacy HuggingFace analyzer (deprecated)

## Directories
- `logs/` - Application logs
- `reports/` - Generated security reports
- `templates/` - HTML report templates

## Test APK
- `iecc-care-release-170.apk` - Sample APK for testing

## Cleaned Files
Removed test files:
- test_*.py (all test scripts)
- scan_*.log (test logs)
- Temporary PR/deployment documentation

## Usage

### Basic Scan
\`\`\`bash
python agent.py scan /path/to/app.apk -f html -f json
\`\`\`

### Check Status
\`\`\`bash
python agent.py status
\`\`\`

### Configuration
Edit `.env` file with your:
- MobSF API URL and key
- AI provider (Groq/OpenAI/Anthropic)
- AI model name and API key
