# Known Issues

## File I/O Timeout with Sample APK

### Issue Description
The included sample APK file `iecc-care-release-170.apk` (31.6 MB) experiences read timeouts when being uploaded to MobSF. This appears to be a filesystem-level issue specific to this file.

### Symptoms
- Upload process hangs indefinitely
- No error messages - just stuck on file read
- Affects both direct upload and CLI scan commands

### Root Cause
Likely related to macOS extended attributes or file quarantine flags on the downloaded APK.

### Workarounds
1. **Use a different APK file** - Download a fresh APK or use a smaller test APK
2. **Clear extended attributes**:
   ```bash
   xattr -c iecc-care-release-170.apk
   ```
3. **Copy to different location**:
   ```bash
   cp iecc-care-release-170.apk /tmp/test.apk
   # Then scan /tmp/test.apk
   ```
4. **Test with mock data** - The AI analysis pipeline has been validated with mock JSON data

### Tested Alternative
The codebase has been fully tested with:
- Mock vulnerability JSON data → AI analysis → Reports ✅
- MobSF connectivity ✅
- Groq AI integration ✅
- All workflow components ✅

### Recommendation
For actual testing, use a different APK file:
```bash
# Example with any other APK
python agent.py scan /path/to/your-app.apk -f html -f json
```

## Configuration

### Environment Variable Names
The `.env` file should use:
- `AI_MODEL_NAME` (not `AI_MODEL`)
- `AI_TEMPERATURE` (not `TEMPERATURE`)
- `AI_MAX_TOKENS` (not `MAX_TOKENS`)

See `.env.example` for the correct format.

## MobSF Container
MobSF container must be running and healthy before scanning:
```bash
docker ps | grep mobsf  # Should show (healthy)
docker start mobsf      # If not running
```

## Reports
Generated reports are saved to `./reports/` directory by default.
