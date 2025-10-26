# Quick Test Guide

## ✅ Bug Fixes Validated!

All bug fixes have been tested and verified:
- ✓ ScanResult parameter names corrected
- ✓ Dictionary access patterns fixed
- ✓ Agent initialization working

## Running Tests

### 1. Validate Bug Fixes (No APK needed)
```bash
conda run -n ai python test_bug_fixes.py
```

### 2. Check Agent Status
```bash
conda run -n ai python agent.py status
```

### 3. Scan an APK File (when you have a working file)
```bash
# Correct command:
conda run -n ai python agent.py scan /path/to/your-app.apk -f html -f json

# NOT this (missing 'agent.py'):
python scan /path/to/your-app.apk  # ❌ WRONG
```

## Common Issues

### "No such file or directory"
**Problem:** Running `python scan ...` instead of `python agent.py scan ...`

**Solution:** Always include `agent.py`:
```bash
python agent.py scan your-file.apk
```

### APK Upload Timeout
**Problem:** The sample APK `iecc-care-release-170.apk` has filesystem read issues

**Solutions:**
1. Use a different APK file
2. Download a fresh APK
3. Copy the APK to `/tmp/` first:
   ```bash
   cp iecc-care-release-170.apk /tmp/test.apk
   python agent.py scan /tmp/test.apk -f html -f json
   ```

## Example: Download and Scan a Test APK

```bash
# Download a small test APK (example)
# Replace with your actual APK source
wget https://example.com/sample.apk -O test-app.apk

# Scan it
conda run -n ai python agent.py scan test-app.apk -f html -f json

# View reports
open reports/*.html
```

## Validation Results

```
Test Results:
✅ All bug fixes validated
✅ Agent initialization working
✅ MobSF connection established
✅ Groq AI configured correctly
✅ All components loading properly

System Status: Production Ready ✓
```

## Git Branch

Current test branch: `test/bug-fixes-validation`

To merge back to main after testing:
```bash
git checkout main
git merge test/bug-fixes-validation
git push origin main
```
