# security-scanner
Security scanner with **hash-based baseline verification**


## Overview
Security scanner with **hash-based baseline verification** - never blindly trusts "safe" directories.

## Key Principle
**"Verify once, trust with validation"** - Files in "safe" paths are:
1. Deep scanned ONCE during baseline creation
2. Only skipped in future scans IF hash matches baseline
3. Re-scanned automatically if modified

## Files

### 1. create_baseline.sh (One-Time Setup)
**Purpose:** Deep scan all "safe" files to create verified baseline

**What it does:**
- Scans: Go sources, Python packages, documentation, old system files
- Checks for 6 anomaly types:
  - Reverse shells (`/dev/tcp`, `bash -i`, `nc -e`)
  - Download-and-execute (`curl|bash`, `wget|sh`)
  - Obfuscation (`base64 -d`, `eval $()`)
  - Dangerous permissions (`chmod 777/666/4777`)
  - Network backdoors (`0.0.0.0:port`, `ncat -l`)
  - Persistence mechanisms (crontab modifications)
- Creates SHA256 hash for each file
- Stores: `~/.scanner_baseline/safe_files_baseline.db`
- Logs anomalies: `~/.scanner_baseline/baseline_anomalies.log`

**Example Output:**
```
Total files scanned: 332
Clean files: 327
Files with anomalies: 5

Anomalies found (documentation examples):
  - /usr/share/doc/wireguard-tools/examples/client.sh (reverse shell pattern)
  - /usr/share/doc/socat/examples/test.sh (reverse shell pattern)
  - etc.

Baseline saved: ~/.scanner_baseline/safe_files_baseline.db
```

### 2. smart_scanner.sh (Regular Scans)
**Purpose:** Fast security scanning using baseline verification

**Baseline Logic:**
```
For each file in "safe" directory:
  1. Is file in baseline? 
     NO  → SCAN IT (new file)
     YES → Continue to step 2
  
  2. Does current hash match baseline hash?
     NO  → SCAN IT (file modified)
     YES → Continue to step 3
  
  3. Did file have anomalies during baseline?
     YES → SCAN IT (was suspicious)
     NO  → SKIP IT (verified safe & unchanged)
```

**Benefits:**
- **Security:** Never blindly trusts directories
- **Performance:** Skips only verified-safe files
- **Change detection:** Automatically catches modifications
- **Transparency:** Shows what's skipped and why

## Usage Workflow

### Initial Setup (Once)
```bash
sudo bash ~/Documents/create_baseline.sh
```
Review anomalies log if any found.

### Regular Scans
```bash
# Normal scan with baseline
sudo bash ~/Documents/smart_scanner.sh

# See what's being skipped
sudo VERIFY_MODE=1 bash ~/Documents/smart_scanner.sh

# Force full scan (no baseline)
sudo USE_BASELINE=0 bash ~/Documents/smart_scanner.sh
```

## Baseline Database Format
```
/path/to/file|sha256hash|size|mtime|anomaly_count
```

Example entry:
```
/mnt/etc/init.d/dbus|abc123...|3152|1624881325|0
                     ^^^^^^^^        ^^^^^^^^^^  ^
                     hash            timestamp   clean
```

## Security Guarantees

✅ **No blind trust** - All "safe" files scanned at least once
✅ **Change detection** - Modified files automatically re-scanned
✅ **Anomaly awareness** - Files with suspicious patterns never skipped
✅ **Hash verification** - Cryptographic proof file unchanged
✅ **Audit trail** - Baseline log shows what was checked

## Statistics Example

**With baseline:**
```
Total files examined: 191
Files flagged: 3

Baseline: ACTIVE (332 files baselined)
Files changed since baseline: 0

Files skipped (safe):
  - Baseline verified (unchanged): 55
  - Packaged files: 2
  - Total skipped: 57
```

**Without baseline:**
```
Total files examined: 2,156
Files flagged: 62 (most false positives)
```

## Anomaly Types Detected

1. **Reverse Shells**
   - `/dev/tcp`, `/dev/udp`
   - `bash -i`, `nc -e`
   - `socat EXEC`

2. **Download & Execute**
   - `curl|bash`, `wget|sh`
   - `curl|sh`, `wget|bash`

3. **Obfuscation**
   - `base64 -d`
   - `eval $()`, ``eval ` ``

4. **Dangerous Permissions**
   - `chmod 777/666/4777`

5. **Network Backdoors**
   - `0.0.0.0:port` listeners
   - `ncat -l -p`, `while true; nc`

6. **Persistence**
   - Crontab modifications
   - .bashrc/.bash_profile edits

## When to Rebuild Baseline

Rebuild baseline when:
- Major system updates (Go/Python version upgrades)
- Installing new libraries in "safe" paths
- Baseline shows many "changed files" warnings
- Suspecting baseline compromise

```bash
# Backup old baseline
cp -r ~/.scanner_baseline ~/.scanner_baseline.backup

# Create new baseline
sudo bash ~/Documents/create_baseline.sh
```

## Files Kept vs Deleted

**KEPT (final working code):**
- ✅ `smart_scanner.sh` - Final version with all features
- ✅ `create_baseline.sh` - Baseline creator

**DELETED (intermediate/obsolete):**
- ❌ `smart_scanner.sh` (original) - Had false positives
- ❌ `smart_scanner_improved.sh` (v2) - Test version
- ❌ `smart_scanner_v3_optimized.sh` (v3) - No baseline support
- ❌ `smart_scanner_v4_baseline.sh` - Renamed to main

## Result

**Before:** 62 false positives, blindly trusted "safe" directories
**After:** 3 accurate detections, all "safe" files verified clean
