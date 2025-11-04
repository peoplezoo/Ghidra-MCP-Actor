# Deployment Checklist - Ghidra MCP Actor

Use this checklist to ensure smooth deployment and testing.

## Pre-Deployment

### ✅ Code Review
- [ ] All files are present (run `git status` to verify)
- [ ] No sensitive data in code (API keys, credentials)
- [ ] `.gitignore` properly configured
- [ ] README.md has correct repository URLs

### ✅ Configuration Files
- [ ] `apify.json` - Actor name and version correct
- [ ] `input_schema.json` - All inputs properly defined
- [ ] `Dockerfile` - Ghidra version correct (11.0.1)
- [ ] `requirements.txt` - All dependencies listed

### ✅ Documentation
- [ ] README.md complete
- [ ] USAGE.md complete
- [ ] QUICKSTART.md available
- [ ] Examples directory populated

## Deployment Steps

### Step 1: Initialize Git Repository (if not done)
```bash
cd E:\ghira\hydra
git init
git add .
git commit -m "Initial commit: Ghidra MCP Actor"
```

### Step 2: Create GitHub Repository (Optional but Recommended)
1. Go to https://github.com/new
2. Create repository: `ghidra-mcp-actor`
3. Push code:
```bash
git remote add origin https://github.com/YOUR_USERNAME/ghidra-mcp-actor.git
git branch -M main
git push -u origin main
```

### Step 3: Install Apify CLI
```bash
# Check if already installed
apify --version

# If not installed (Windows PowerShell):
irm https://apify.com/install-cli.ps1 | iex

# Or via NPM:
npm install -g apify-cli
```

### Step 4: Login to Apify
```bash
apify login
```
- [ ] Successfully logged in
- [ ] Free tier account active (or paid plan)

### Step 5: Deploy Actor
```bash
cd E:\ghira\hydra
apify push
```

Expected output:
```
✔ Deploying actor...
✔ Building Docker image...
✔ Actor deployed successfully!
```

**Note**: First build takes 10-15 minutes (downloads Ghidra).

- [ ] Build completed successfully
- [ ] No error messages in build log
- [ ] Actor appears in Apify Console

## Post-Deployment Testing

### Test 1: Basic Analysis
**Input:**
```json
{
  "binaryUrl": "https://github.com/corkami/pocs/raw/master/PE/tiny.exe",
  "binaryName": "tiny.exe",
  "generateReport": true,
  "analysisOptions": {
    "timeout": 300
  }
}
```

**Expected Results:**
- [ ] Run completes in 2-5 minutes
- [ ] Status shows "SUCCEEDED"
- [ ] Dataset contains findings
- [ ] Key-Value Store has `REPORT.html`
- [ ] Key-Value Store has `SUMMARY.md`
- [ ] Key-Value Store has `ghidra_analysis.json`

**Verification:**
- [ ] HTML report opens and displays correctly
- [ ] Summary contains threat level
- [ ] JSON has functions array
- [ ] No error messages in logs

### Test 2: YARA Scanning
**Input:**
```json
{
  "binaryUrl": "https://github.com/corkami/pocs/raw/master/PE/tiny.exe",
  "binaryName": "tiny.exe",
  "yaraRules": "rule Test { strings: $a = \"MZ\" condition: $a }",
  "generateReport": true
}
```

**Expected Results:**
- [ ] YARA rule matches successfully
- [ ] Report shows YARA findings
- [ ] No YARA compilation errors

### Test 3: MCP Server Mode (Optional)
**Input:**
```json
{
  "binaryUrl": "https://github.com/corkami/pocs/raw/master/PE/tiny.exe",
  "binaryName": "tiny.exe",
  "mcpMode": true
}
```

**Expected Results:**
- [ ] Actor enters standby mode
- [ ] Logs show "Starting Ghidra MCP Server"
- [ ] MCP server is accessible
- [ ] Can connect AI client

### Test 4: Error Handling
**Input (Invalid URL):**
```json
{
  "binaryUrl": "https://invalid-url.com/notfound.exe",
  "binaryName": "test.exe"
}
```

**Expected Results:**
- [ ] Actor fails gracefully
- [ ] Error message is clear
- [ ] No stack traces exposed

## CI/CD Setup (Optional)

### GitHub Actions Configuration
- [ ] `.github/workflows/deploy.yml` exists
- [ ] Repository secrets configured:
  - `APIFY_TOKEN` - Your Apify API token
- [ ] Test push triggers workflow
- [ ] Workflow completes successfully

### Enable Auto-Deployment
1. Go to GitHub repo → Settings → Secrets
2. Add secret: `APIFY_TOKEN`
3. Push to main branch
4. Verify workflow runs in Actions tab

- [ ] CI/CD pipeline working
- [ ] Auto-deploy on push to main

## Production Readiness

### Performance
- [ ] Test with small binary (< 1MB) - completes in 1-3 min
- [ ] Test with medium binary (5-10MB) - completes in 5-10 min
- [ ] Memory usage acceptable (< 4GB)
- [ ] Timeout settings appropriate

### Security
- [ ] No credentials in code
- [ ] No sensitive data in logs
- [ ] Input validation working
- [ ] Error messages don't leak paths

### Monitoring
- [ ] Apify Console notifications enabled
- [ ] Understand Actor metrics
- [ ] Know how to access logs
- [ ] Understand Dataset/KV Store costs

## Documentation Updates

Before going live:
- [ ] Update repository URL in README.md
- [ ] Update actor ID in examples
- [ ] Add your contact information
- [ ] Update LICENSE file if needed
- [ ] Add any custom YARA rules to docs

## Final Checks

### Actor Settings (in Apify Console)
- [ ] Name: `ghidra-mcp-actor`
- [ ] Description filled
- [ ] Categories set: "SECURITY"
- [ ] Memory: 2048 MB minimum (4096 for large binaries)
- [ ] Timeout: 600 seconds default
- [ ] Standby enabled (for MCP mode)

### Testing Checklist
- [ ] ✅ Basic analysis works
- [ ] ✅ Reports generate correctly
- [ ] ✅ YARA scanning works
- [ ] ✅ Error handling graceful
- [ ] ✅ MCP mode accessible (if using)
- [ ] ✅ Batch processing tested (optional)

## Go Live! 🚀

Once all checks pass:

1. **Mark as Ready:**
   ```bash
   git tag -a v1.0.0 -m "Production release"
   git push origin v1.0.0
   ```

2. **Share with Team:**
   - Send Apify actor link
   - Share documentation
   - Provide example inputs

3. **Monitor First Runs:**
   - Watch logs for errors
   - Check resource usage
   - Gather user feedback

## Troubleshooting Common Issues

### Build Fails
**Problem:** Docker build times out or fails

**Solutions:**
- Check Dockerfile syntax
- Verify Ghidra download URL is accessible
- Increase build timeout in Apify settings
- Check Apify service status

### Analysis Timeouts
**Problem:** Actor times out during analysis

**Solutions:**
- Increase timeout in input: `"timeout": 1800`
- Increase actor memory: 4096 MB
- Try with smaller binary first
- Check if binary is corrupted

### MCP Server Not Accessible
**Problem:** Can't connect to MCP server

**Solutions:**
- Verify actor is in STANDBY mode
- Check `mcpMode: true` in input
- Look for "Starting Ghidra MCP Server" in logs
- Ensure standby is enabled in actor settings

### Empty Reports
**Problem:** Reports generated but contain no data

**Solutions:**
- Check Ghidra analysis logs
- Verify binary is valid PE/ELF format
- Try with known-good binary
- Check `ghidra_analysis.json` exists

## Support Resources

- **Apify Documentation**: https://docs.apify.com
- **Apify Discord**: https://discord.com/invite/jyEM2PRvMU
- **GitHub Issues**: https://github.com/YOUR_USERNAME/ghidra-mcp-actor/issues
- **Ghidra Documentation**: https://ghidra-sre.org

## Success Metrics

Track these after deployment:
- [ ] Number of successful runs
- [ ] Average execution time
- [ ] Error rate < 5%
- [ ] User satisfaction
- [ ] Cost per analysis

---

## 🎉 Deployment Complete!

Once all items are checked, your Ghidra MCP Actor is production-ready!

**Remember:**
- Start with small binaries for testing
- Monitor costs and resource usage
- Keep Ghidra and dependencies updated
- Gather user feedback for improvements

**Next Steps:**
- Read [USAGE.md](USAGE.md) for advanced features
- Explore [examples/](examples/) for inspiration
- Join Apify community for support
- Consider contributing improvements back

Good luck with your malware analysis! 🔐🤖
