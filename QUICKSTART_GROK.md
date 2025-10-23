# 🚀 Quick Start - Grok Integration

## ✅ Status: OPERATIONAL (All Tests Passed 7/7)

## Configuration (.env)
```properties
XAI_API_KEY=your_xai_api_key_here
AI_PROVIDER=xai
AI_MODEL=grok-beta
```

## Quick Commands

### Validate System
```bash
conda run -n ai python validate_langchain.py
```

### Scan an APK
```bash
conda run -n ai python agent.py scan your_app.apk
```

### Check Status
```bash
conda run -n ai python agent.py status
```

### Show Configuration
```bash
conda run -n ai python agent.py show-config
```

## Python Quick Start
```python
from dotenv import load_dotenv
import os
load_dotenv()

# Option 1: Use the analyzer directly
from src.langchain_analyzer import LangChainVulnerabilityAnalyzer

analyzer = LangChainVulnerabilityAnalyzer(
    provider="xai",
    model_name="grok-beta", 
    api_key=os.getenv("XAI_API_KEY")
)

# Option 2: Use the full agent (recommended)
from src.mobile_security_agent import create_quick_agent

agent = create_quick_agent()  # Auto-loads Grok from .env
results = agent.scan_apk("app.apk")
```

## What Changed

✅ Added xAI/Grok support to:
- `src/langchain_analyzer.py` - AI provider initialization
- `src/langchain_config.py` - Configuration validation
- `.env` - API key and provider settings

## Test Results
```
Dependencies         ✅ PASS
Module Imports       ✅ PASS  
Configuration        ✅ PASS
AI Analyzer          ✅ PASS
LangGraph Workflow   ✅ PASS
Agent Creation       ✅ PASS
CLI Commands         ✅ PASS

Overall: 7/7 tests passed ✅
```

## Documentation
- Full Guide: `GROK_INTEGRATION.md`
- Test Results: `GROK_TEST_RESULTS.md`
- Original README: `README_LANGCHAIN.md`

## Support
- xAI Console: https://console.x.ai
- API Docs: https://docs.x.ai

---
**Ready to use!** 🎉
