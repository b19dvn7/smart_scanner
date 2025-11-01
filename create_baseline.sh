#!/bin/bash

# Baseline Creation Script for Smart Scanner
# This script performs ONE-TIME deep scan of "safe" directories
# to verify they're actually clean before trusting them in future scans

# Configuration
SCAN_TARGET="/mnt"
ROOT_PARTITION="/dev/nvme0n1p3"
ESP_PARTITION="/dev/nvme0n1p1"
BASELINE_DIR="$HOME/.scanner_baseline"
BASELINE_FILE="$BASELINE_DIR/safe_files_baseline.db"
ANOMALIES_LOG="$BASELINE_DIR/baseline_anomalies.log"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Statistics
TOTAL_FILES=0
CLEAN_FILES=0
ANOMALIES_FOUND=0

# Mount target system
mount_system() {
    log "Mounting target system..."
    sudo umount -lf $SCAN_TARGET/boot/efi 2>/dev/null
    sudo umount -lf $SCAN_TARGET 2>/dev/null
    sudo mkdir -p $SCAN_TARGET

    if sudo mount $ROOT_PARTITION $SCAN_TARGET; then
        if sudo mount $ESP_PARTITION $SCAN_TARGET/boot/efi 2>/dev/null; then
            log "System mounted successfully"
            return 0
        else
            warn "ESP mount failed (might not exist)"
            return 0
        fi
    else
        error "Failed to mount root partition"
        return 1
    fi
}

# Unmount system
unmount_system() {
    sudo umount -lf $SCAN_TARGET/boot/efi 2>/dev/null
    sudo umount -lf $SCAN_TARGET 2>/dev/null
    log "System unmounted"
}

# Check file for anomalies
check_file_for_anomalies() {
    local file="$1"
    local issues=0

    # Check 1: Reverse shell patterns
    if sudo grep -qE "/dev/tcp|/dev/udp|bash\s+-[a-z]*i|nc\s+-[a-z]*e|socat.*EXEC" "$file" 2>/dev/null; then
        warn "ANOMALY: Reverse shell pattern in $file"
        echo "REVERSE_SHELL: $file" >> "$ANOMALIES_LOG"
        ((issues++))
    fi

    # Check 2: Suspicious download and execute
    if sudo grep -qE "curl.*\|.*bash|wget.*\|.*sh|curl.*\|.*sh|wget.*\|.*bash" "$file" 2>/dev/null; then
        warn "ANOMALY: Download-and-execute pattern in $file"
        echo "DOWNLOAD_EXEC: $file" >> "$ANOMALIES_LOG"
        ((issues++))
    fi

    # Check 3: Obfuscation (base64, eval with variables)
    if sudo grep -qE "base64\s+-d|eval.*\$\(|eval.*\`" "$file" 2>/dev/null; then
        warn "ANOMALY: Obfuscation detected in $file"
        echo "OBFUSCATION: $file" >> "$ANOMALIES_LOG"
        ((issues++))
    fi

    # Check 4: Suspicious chmod patterns
    if sudo grep -qE "chmod\s+(777|666|4777)" "$file" 2>/dev/null; then
        warn "ANOMALY: Dangerous permissions in $file"
        echo "DANGEROUS_CHMOD: $file" >> "$ANOMALIES_LOG"
        ((issues++))
    fi

    # Check 5: Network backdoor patterns
    if sudo grep -qE "0\.0\.0\.0:[0-9]{4,5}|while.*true.*nc|ncat.*-l.*-p" "$file" 2>/dev/null; then
        warn "ANOMALY: Network backdoor pattern in $file"
        echo "NETWORK_BACKDOOR: $file" >> "$ANOMALIES_LOG"
        ((issues++))
    fi

    # Check 6: Cron/persistence patterns in unexpected files
    if sudo grep -qE "crontab.*-|echo.*>>.*cron|\.bashrc|\.bash_profile" "$file" 2>/dev/null; then
        if [[ ! "$file" =~ (setup|install|config) ]]; then
            warn "ANOMALY: Persistence mechanism in $file"
            echo "PERSISTENCE: $file" >> "$ANOMALIES_LOG"
            ((issues++))
        fi
    fi

    return $issues
}

# Scan and baseline a directory
baseline_directory() {
    local scan_path="$1"
    local description="$2"

    info "Scanning $description: $scan_path"

    # Find all script files in this directory
    local file_count=0
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            ((TOTAL_FILES++))
            ((file_count++))

            # Check for anomalies
            local anomaly_count=0
            check_file_for_anomalies "$file"
            anomaly_count=$?

            if [ $anomaly_count -gt 0 ]; then
                ((ANOMALIES_FOUND++))
            else
                ((CLEAN_FILES++))
            fi

            # Calculate hash
            local hash=$(sudo sha256sum "$file" 2>/dev/null | awk '{print $1}')
            local size=$(sudo stat -c%s "$file" 2>/dev/null)
            local mtime=$(sudo stat -c%Y "$file" 2>/dev/null)

            # Store in baseline
            echo "$file|$hash|$size|$mtime|$anomaly_count" >> "$BASELINE_FILE"

            # Progress indicator
            if [ $((file_count % 100)) -eq 0 ]; then
                echo -n "."
            fi
        fi
    done < <(sudo find "$scan_path" -type f \( -name "*.sh" -o -name "*.py" \) 2>/dev/null)

    echo "" # newline after progress dots
    log "Scanned $file_count files in $description"
}

# Main baseline creation
main() {
    log "=== BASELINE CREATION FOR SMART SCANNER ==="
    log "This is a ONE-TIME deep scan to verify 'safe' directories"
    echo ""

    # Create baseline directory
    mkdir -p "$BASELINE_DIR"

    # Clear previous baseline
    > "$BASELINE_FILE"
    > "$ANOMALIES_LOG"

    # Mount system
    if ! mount_system; then
        error "Failed to mount system"
        exit 1
    fi

    log "Starting deep scan of 'safe' directories..."
    echo ""

    # Scan each "safe" directory
    baseline_directory "$SCAN_TARGET/usr/local/go/src" "Go source code"
    baseline_directory "$SCAN_TARGET/usr/local/lib/python*/dist-packages" "Python dist-packages"
    baseline_directory "$SCAN_TARGET/usr/local/lib/python*/site-packages" "Python site-packages"
    baseline_directory "$SCAN_TARGET/usr/share/doc" "Documentation"
    baseline_directory "$SCAN_TARGET/usr/src" "System sources"

    # Also baseline old system files
    log "Baselineining old system files (>90 days)..."
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            local mod_time=$(sudo stat -c %Y "$file" 2>/dev/null || echo 0)
            local current_time=$(date +%s)
            local age_days=$(( (current_time - mod_time) / 86400 ))

            if [ $age_days -ge 90 ]; then
                ((TOTAL_FILES++))

                # Check for anomalies
                check_file_for_anomalies "$file"
                local anomaly_count=$?

                if [ $anomaly_count -gt 0 ]; then
                    ((ANOMALIES_FOUND++))
                else
                    ((CLEAN_FILES++))
                fi

                # Calculate hash and store
                local hash=$(sudo sha256sum "$file" 2>/dev/null | awk '{print $1}')
                local size=$(sudo stat -c%s "$file" 2>/dev/null)
                local mtime=$(sudo stat -c%Y "$file" 2>/dev/null)
                echo "$file|$hash|$size|$mtime|$anomaly_count" >> "$BASELINE_FILE"
            fi
        fi
    done < <(sudo find $SCAN_TARGET/etc/init.d -type f 2>/dev/null)

    # Unmount
    unmount_system

    # Generate report
    echo ""
    echo "=== BASELINE CREATION SUMMARY ==="
    echo "Total files scanned: $TOTAL_FILES"
    echo "Clean files: $CLEAN_FILES"
    echo "Files with anomalies: $ANOMALIES_FOUND"
    echo ""
    echo "Baseline saved to: $BASELINE_FILE"

    if [ $ANOMALIES_FOUND -gt 0 ]; then
        error "⚠️  ANOMALIES DETECTED!"
        echo ""
        echo "Files with potential issues were found in 'safe' directories."
        echo "Review the anomalies log: $ANOMALIES_LOG"
        echo ""
        echo "Recommendation:"
        echo "  1. Review each anomaly manually"
        echo "  2. Investigate suspicious files"
        echo "  3. Only proceed if anomalies are false positives"
        echo ""
        warn "Baseline created but contains $ANOMALIES_FOUND suspicious files"
    else
        log "✅ All files are clean! Baseline is safe to use."
        echo ""
        echo "The scanner will now skip these files on future scans"
        echo "IF AND ONLY IF they haven't been modified."
    fi

    echo ""
    log "Baseline database: $(wc -l < "$BASELINE_FILE") entries"
    log "Next step: Use smart_scanner_v4_baseline.sh for future scans"
}

# Run main
main "$@"
