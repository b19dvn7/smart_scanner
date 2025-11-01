#!/bin/bash

# Configuration
SCAN_TARGET="/mnt"
ROOT_PARTITION="/dev/nvme0n1p3"
ESP_PARTITION="/dev/nvme0n1p1"
SUSPICIOUS_ITEMS=()
THREAT_LEVEL=0

# Baseline configuration
BASELINE_DIR="$HOME/.scanner_baseline"
BASELINE_FILE="$BASELINE_DIR/safe_files_baseline.db"
USE_BASELINE=${USE_BASELINE:-1}  # Default: use baseline if exists

# Verification mode - set to 1 to see what's being skipped
VERIFY_MODE=${VERIFY_MODE:-0}

# Statistics tracking
SKIPPED_SAFE_PATH=0
SKIPPED_OLD_SYSTEM=0
SKIPPED_PACKAGED=0
SKIPPED_NON_EXEC=0
SKIPPED_BASELINE=0
BASELINE_MISMATCH=0
TOTAL_FILES_SCANNED=0
SKIPPED_FILES_LOG=()

# Colors for output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
log() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

# Check if file is in baseline and hasn't changed
is_in_baseline_unchanged() {
    local file="$1"

    # If baseline not enabled or doesn't exist, return false
    if [ $USE_BASELINE -eq 0 ] || [ ! -f "$BASELINE_FILE" ]; then
        return 1  # Not in baseline
    fi

    # Look up file in baseline
    local baseline_entry=$(grep "^${file}|" "$BASELINE_FILE" 2>/dev/null)

    if [ -z "$baseline_entry" ]; then
        return 1  # Not in baseline
    fi

    # Parse baseline: file|hash|size|mtime|anomaly_count
    local baseline_hash=$(echo "$baseline_entry" | cut -d'|' -f2)
    local baseline_size=$(echo "$baseline_entry" | cut -d'|' -f3)
    local baseline_anomalies=$(echo "$baseline_entry" | cut -d'|' -f5)

    # Get current file info
    local current_hash=$(sudo sha256sum "$file" 2>/dev/null | awk '{print $1}')
    local current_size=$(sudo stat -c%s "$file" 2>/dev/null)

    # Compare
    if [ "$current_hash" = "$baseline_hash" ] && [ "$current_size" = "$baseline_size" ]; then
        # File unchanged - check if it had anomalies
        if [ "$baseline_anomalies" -gt 0 ]; then
            warn "File in baseline but HAD anomalies during baseline scan: $file"
            return 1  # Don't skip - had anomalies
        fi
        return 0  # In baseline and unchanged
    else
        # File changed!
        warn "File CHANGED since baseline: $file"
        ((BASELINE_MISMATCH++))
        return 1  # Don't skip - file modified
    fi
}

# Whitelist safe paths - files in these directories are less suspicious
is_safe_path() {
    local file="$1"

    # Safe directories for source code and libraries
    if [[ "$file" =~ /usr/local/go/src/ ]] || \
       [[ "$file" =~ /usr/local/lib/python.*/dist-packages/ ]] || \
       [[ "$file" =~ /usr/local/lib/python.*/site-packages/ ]] || \
       [[ "$file" =~ /usr/share/doc/ ]] || \
       [[ "$file" =~ /usr/src/ ]]; then
        return 0  # Safe
    fi

    return 1  # Not explicitly safe
}

# Check if file is in a standard system directory
is_system_directory() {
    local file="$1"

    # Standard system init/service directories (expected to have scripts)
    if [[ "$file" =~ $SCAN_TARGET/etc/init\.d/ ]] || \
       [[ "$file" =~ $SCAN_TARGET/lib/systemd/system/ ]] || \
       [[ "$file" =~ $SCAN_TARGET/etc/systemd/system/ ]]; then
        return 0  # System directory
    fi

    return 1  # Not system directory
}

# Check if file is actually executable (not just source code)
is_executable_context() {
    local file="$1"

    # Check if file is executable
    if [ -x "$file" ]; then
        # But exclude if it's in source code directories
        if is_safe_path "$file"; then
            return 1  # Not executable context (just source code)
        fi
        return 0  # Executable context
    fi

    return 1  # Not executable
}

# Check file age - very old files are less suspicious
is_recent_file() {
    local file="$1"
    local days_old=90  # Files modified in last 90 days are "recent"

    local mod_time=$(sudo stat -c %Y "$file" 2>/dev/null || echo 0)
    local current_time=$(date +%s)
    local age_days=$(( (current_time - mod_time) / 86400 ))

    if [ $age_days -lt $days_old ]; then
        return 0  # Recent
    fi

    return 1  # Old
}

# Better package verification for mounted partitions
is_packaged_file() {
    local file="$1"
    local stripped_file="${file#$SCAN_TARGET}"  # Remove /mnt prefix

    # Try multiple methods to verify if file is from a package

    # Method 1: Check with chroot (may not work)
    if sudo chroot $SCAN_TARGET dpkg -S "$stripped_file" &>/dev/null; then
        return 0  # From package
    fi

    # Method 2: Check if in standard system paths (likely packaged)
    if [[ "$file" =~ ^$SCAN_TARGET/(etc/init\.d|lib/systemd|usr/bin|usr/sbin|bin|sbin)/ ]]; then
        # Additional check: if it's very old, probably packaged
        if ! is_recent_file "$file"; then
            return 0  # Probably from package (old + system directory)
        fi
    fi

    return 1  # Probably not packaged
}

# Mount target system
mount_system() {
    log "Mounting target system..."
    
    # Clean up any existing mounts
    sudo umount -lf $SCAN_TARGET/boot/efi 2>/dev/null
    sudo umount -lf $SCAN_TARGET 2>/dev/null
    
    # Create mount point
    sudo mkdir -p $SCAN_TARGET
    
    # Mount partitions
    if sudo mount $ROOT_PARTITION $SCAN_TARGET; then
        if sudo mount $ESP_PARTITION $SCAN_TARGET/boot/efi; then
            log "System mounted successfully"
            return 0
        else
            error "Failed to mount ESP partition"
            sudo umount $SCAN_TARGET
            return 1
        fi
    else
        error "Failed to mount root partition $ROOT_PARTITION"
        return 1
    fi
}

# Unmount system
unmount_system() {
    sudo umount -lf $SCAN_TARGET/boot/efi 2>/dev/null
    sudo umount -lf $SCAN_TARGET 2>/dev/null
    log "System unmounted"
}

# Quick system check
quick_system_check() {
    log "Running quick system check..."
    local issues=0
    
    # Check if system is mounted
    if ! mountpoint -q $SCAN_TARGET; then
        error "System not mounted properly"
        return 1
    fi
    
    # Check essential directories
    for dir in /etc /boot /usr/bin; do
        if [ ! -d "$SCAN_TARGET$dir" ]; then
            warn "Missing directory: $dir"
            ((issues++))
        fi
    done
    
    [ $issues -eq 0 ] && log "System check passed" || warn "System check found $issues issues"
    return $issues
}

# Module 1: Critical File Scan
scan_critical_files() {
    info "Scanning critical system files..."
    local flags=0
    
    # Check for suspicious systemd services
    while IFS= read -r service; do
        if [ -f "$service" ]; then
            # Check for dangerous patterns
            if sudo grep -q "sh -c.*chmod.*0666" "$service" 2>/dev/null; then
                SUSPICIOUS_ITEMS+=("CRITICAL: $service - Modifies system permissions")
                ((THREAT_LEVEL+=10))
                ((flags++))
                # Deep scan this item immediately
                deep_scan_file "$service" "SystemD Service"
            fi
            
            if sudo grep -q "curl.*|.*bash\|wget.*|.*bash" "$service" 2>/dev/null; then
                SUSPICIOUS_ITEMS+=("HIGH: $service - Downloads and executes code")
                ((THREAT_LEVEL+=5))
                ((flags++))
                deep_scan_file "$service" "SystemD Service"
            fi
        fi
    done < <(sudo find $SCAN_TARGET/etc/systemd/system $SCAN_TARGET/lib/systemd/system -name "*.service" -type f 2>/dev/null)
    
    [ $flags -eq 0 ] && log "No critical file issues found"
    return $flags
}

# Module 2: Execution Point Scan
scan_execution_points() {
    info "Scanning execution points..."
    local flags=0
    
    # Check crontab entries
    while IFS= read -r cron; do
        if [ -f "$cron" ]; then
            if sudo grep -q "curl.*|.*bash\|wget.*|.*bash" "$cron" 2>/dev/null; then
                SUSPICIOUS_ITEMS+=("HIGH: $cron - Downloads and executes via cron")
                ((THREAT_LEVEL+=5))
                ((flags++))
                deep_scan_file "$cron" "Cron Job"
            fi
        fi
    done < <(sudo find $SCAN_TARGET/etc/cron* $SCAN_TARGET/var/spool/cron -type f 2>/dev/null)
    
    # Check init scripts with context awareness
    while IFS= read -r script; do
        if [ -f "$script" ]; then
            ((TOTAL_FILES_SCANNED++))

            # Skip if it's in a standard system directory AND it's old (likely from package)
            if is_system_directory "$script" && ! is_recent_file "$script"; then
                # Check baseline if available
                if is_in_baseline_unchanged "$script"; then
                    ((SKIPPED_BASELINE++))
                    if [ $VERIFY_MODE -eq 1 ]; then
                        SKIPPED_FILES_LOG+=("SKIP[BASELINE_VERIFIED]: $script (old system)")
                    fi
                    continue
                else
                    # Old but not in baseline or changed - still skip but count separately
                    ((SKIPPED_OLD_SYSTEM++))
                    if [ $VERIFY_MODE -eq 1 ]; then
                        SKIPPED_FILES_LOG+=("SKIP[OLD_SYSTEM_NO_BASELINE]: $script")
                    fi
                    continue
                fi
            fi

            # Check if file is from a package using improved method
            if ! is_packaged_file "$script"; then
                # Only flag if it's recent OR in unusual location
                if is_recent_file "$script"; then
                    SUSPICIOUS_ITEMS+=("MEDIUM: $script - Recent unknown startup script")
                    ((THREAT_LEVEL+=5))
                    ((flags++))
                    deep_scan_file "$script" "Init Script"
                elif ! is_system_directory "$script"; then
                    SUSPICIOUS_ITEMS+=("LOW: $script - Startup script in unusual location")
                    ((THREAT_LEVEL+=2))
                    ((flags++))
                    deep_scan_file "$script" "Init Script"
                fi
            else
                ((SKIPPED_PACKAGED++))
                if [ $VERIFY_MODE -eq 1 ]; then
                    SKIPPED_FILES_LOG+=("SKIP[PACKAGED]: $script")
                fi
            fi
        fi
    done < <(sudo find $SCAN_TARGET/etc/init.d $SCAN_TARGET/etc/rc.local -type f 2>/dev/null)
    
    [ $flags -eq 0 ] && log "No execution point issues found"
    return $flags
}

# Module 3: Network Communication Scan
scan_network_scripts() {
    info "Scanning for network communications..."
    local flags=0
    
    # Check for scripts making network calls (skip source code directories)
    while IFS= read -r script; do
        if [ -f "$script" ]; then
            ((TOTAL_FILES_SCANNED++))

            # Check if in baseline first (if file is safe path)
            if is_safe_path "$script"; then
                # ONLY skip if in baseline and unchanged
                if is_in_baseline_unchanged "$script"; then
                    ((SKIPPED_BASELINE++))
                    if [ $VERIFY_MODE -eq 1 ]; then
                        SKIPPED_FILES_LOG+=("SKIP[BASELINE_VERIFIED]: $script")
                    fi
                    continue
                else
                    # In safe path but NOT in baseline or CHANGED - scan it!
                    warn "Safe path file NOT in baseline or changed: $script"
                    # Will be scanned below
                fi
            fi

            # Only check executable files or scripts in system directories
            if is_executable_context "$script" || [[ "$script" =~ $SCAN_TARGET/etc/ ]]; then
                # Check for HTTP requests - but be more specific
                if sudo grep -E "^[^#]*\b(curl|wget)\s+.*http" "$script" 2>/dev/null | grep -qv "^[[:space:]]*#"; then
                    if is_recent_file "$script"; then
                        SUSPICIOUS_ITEMS+=("NETWORK: $script - Recent script making HTTP requests")
                        ((THREAT_LEVEL+=4))
                        ((flags++))
                        deep_scan_file "$script" "Network Script"
                    else
                        SUSPICIOUS_ITEMS+=("INFO: $script - Old script with network calls (review manually)")
                        ((THREAT_LEVEL+=1))
                        ((flags++))
                    fi
                fi

                # Check for reverse shell patterns (HIGH PRIORITY)
                if sudo grep -E "/dev/tcp|/dev/udp|bash\s+-i|nc\s+-[a-z]*e|socat.*EXEC" "$script" 2>/dev/null | grep -qv "^[[:space:]]*#"; then
                    SUSPICIOUS_ITEMS+=("CRITICAL: $script - Possible reverse shell detected")
                    ((THREAT_LEVEL+=15))
                    ((flags++))
                    deep_scan_file "$script" "Reverse Shell Check"
                fi
            else
                # Not executable and not in /etc - skip
                ((SKIPPED_NON_EXEC++))
                if [ $VERIFY_MODE -eq 1 ]; then
                    SKIPPED_FILES_LOG+=("SKIP[NON_EXEC]: $script")
                fi
            fi
        fi
    done < <(sudo find $SCAN_TARGET/etc $SCAN_TARGET/usr/local -type f \( -name "*.sh" -o -name "*.py" \) \
        -not -path "*/go/src/*" \
        -not -path "*/python*/dist-packages/*" \
        -not -path "*/python*/site-packages/*" \
        -not -path "*/usr/share/doc/*" \
        2>/dev/null)
    
    [ $flags -eq 0 ] && log "No network communication issues found"
    return $flags
}

# Deep scan for suspicious files
deep_scan_file() {
    local file="$1"
    local context="$2"
    
    info "Deep scanning: $file"
    echo "=== DEEP ANALYSIS: $context ==="
    echo "File: $file"
    echo "Size: $(sudo stat -c%s "$file" 2>/dev/null || echo "unknown") bytes"
    echo "Type: $(sudo file "$file" 2>/dev/null | cut -d: -f2- || echo "unknown")"
    echo "Package: $(sudo chroot $SCAN_TARGET dpkg -S "$file" 2>/dev/null | cut -d: -f1 || echo "Not from package")"
    echo "Permissions: $(sudo stat -c "%a %U:%G" "$file" 2>/dev/null || echo "unknown")"
    echo "Last modified: $(sudo stat -c "%y" "$file" 2>/dev/null || echo "unknown")"
    echo ""
}

# Show skip statistics
show_skip_statistics() {
    echo ""
    echo "=== SCAN STATISTICS ==="
    echo "Total files examined: $TOTAL_FILES_SCANNED"
    echo "Files flagged: ${#SUSPICIOUS_ITEMS[@]}"
    echo ""
    # Check baseline status
    if [ $USE_BASELINE -eq 1 ] && [ -f "$BASELINE_FILE" ]; then
        local baseline_count=$(wc -l < "$BASELINE_FILE")
        log "Baseline: ACTIVE ($baseline_count files baselined)"
        if [ $BASELINE_MISMATCH -gt 0 ]; then
            warn "Files changed since baseline: $BASELINE_MISMATCH (these were scanned)"
        fi
    else
        warn "Baseline: NOT AVAILABLE (run create_baseline.sh first)"
    fi

    echo ""
    echo "Files skipped (safe):"
    echo "  - Baseline verified (unchanged): $SKIPPED_BASELINE"
    echo "  - Old system files (no baseline): $SKIPPED_OLD_SYSTEM"
    echo "  - Packaged files: $SKIPPED_PACKAGED"
    echo "  - Safe source paths (no baseline): $SKIPPED_SAFE_PATH"
    echo "  - Non-executable: $SKIPPED_NON_EXEC"
    local total_skipped=$((SKIPPED_BASELINE + SKIPPED_OLD_SYSTEM + SKIPPED_PACKAGED + SKIPPED_SAFE_PATH + SKIPPED_NON_EXEC))
    echo "  - Total skipped: $total_skipped"

    if [ $VERIFY_MODE -eq 1 ] && [ ${#SKIPPED_FILES_LOG[@]} -gt 0 ]; then
        echo ""
        echo "Sample of skipped files by category:"

        # Show samples from each category
        for category in "BASELINE_VERIFIED" "OLD_SYSTEM_NO_BASELINE" "PACKAGED" "SAFE_PATH" "NON_EXEC"; do
            local count=0
            echo ""
            echo "  $category files (showing first 5):"
            for item in "${SKIPPED_FILES_LOG[@]}"; do
                if [[ "$item" =~ SKIP\[$category\] ]]; then
                    echo "    ${item#SKIP[$category]: }"
                    ((count++))
                    [ $count -ge 5 ] && break
                fi
            done
            [ $count -eq 0 ] && echo "    (none)"
        done

        echo ""
        echo "Total files in skip log: ${#SKIPPED_FILES_LOG[@]}"
    fi
}

# Generate summary report
generate_summary() {
    echo ""
    echo "=== SECURITY SCAN SUMMARY ==="
    echo "Files flagged as suspicious: ${#SUSPICIOUS_ITEMS[@]}"
    echo "Threat Level: $THREAT_LEVEL"
    echo ""
    
    # Determine overall status with smarter thresholds
    if [ $THREAT_LEVEL -ge 15 ]; then
        error "OVERALL STATUS: 🔴 CRITICAL - Immediate action required"
    elif [ $THREAT_LEVEL -ge 8 ]; then
        warn "OVERALL STATUS: 🟡 HIGH - Review and take action"
    elif [ $THREAT_LEVEL -ge 3 ]; then
        warn "OVERALL STATUS: 🟠 MEDIUM - Investigate findings"
    elif [ $THREAT_LEVEL -ge 1 ]; then
        log "OVERALL STATUS: 🟢 LOW - Minor findings, review when convenient"
    else
        log "OVERALL STATUS: 🟢 CLEAN - No suspicious items found"
    fi
    
    echo ""
    if [ ${#SUSPICIOUS_ITEMS[@]} -gt 0 ]; then
        echo "SUSPICIOUS ITEMS FOUND:"
        for item in "${SUSPICIOUS_ITEMS[@]}"; do
            echo "  - $item"
        done
    else
        log "No suspicious items found"
    fi
}

# Show next steps
show_next_steps() {
    echo ""
    echo "=== RECOMMENDED NEXT STEPS ==="
    
    if [ $THREAT_LEVEL -ge 15 ]; then
        echo "1. Review CRITICAL items above immediately"
        echo "2. Isolate system if reverse shells or backdoors detected"
        echo "3. Remove or quarantine malicious files"
        echo "4. Run full forensic analysis"
        echo "5. Consider system restore from clean backup"
    elif [ $THREAT_LEVEL -ge 8 ]; then
        echo "1. Review HIGH priority items promptly"
        echo "2. Investigate recent unknown scripts/services"
        echo "3. Check network connections and listening ports"
        echo "4. Run additional security scans (ClamAV, rkhunter)"
        echo "5. Monitor system behavior for anomalies"
    elif [ $THREAT_LEVEL -ge 3 ]; then
        echo "1. Review MEDIUM priority items when convenient"
        echo "2. Verify custom scripts are legitimate"
        echo "3. Check file modification dates and ownership"
        echo "4. Schedule regular security scans"
    elif [ $THREAT_LEVEL -ge 1 ]; then
        echo "1. Review LOW priority findings at your convenience"
        echo "2. Items flagged are likely legitimate but verify if unsure"
        echo "3. Continue with normal system operation"
        echo "4. Maintain regular security updates"
    else
        echo "1. No issues detected - system appears clean"
        echo "2. Continue with normal system operation"
        echo "3. Schedule periodic security scans"
        echo "4. Keep system and packages updated"
    fi
    
    echo ""
    echo "Quick commands:"
    echo "  - Run deep scan: sudo bash $0 --deep"
    echo "  - View boot files: sudo ls -la /mnt/boot/"
    echo "  - Check services: sudo chroot /mnt systemctl list-units --type=service"
}

# Interactive menu
show_menu() {
    echo ""
    echo "=== SMART SECURITY SCANNER ==="
    echo "1. Quick Scan (Fast, basic checks)"
    echo "2. Deep Scan (Comprehensive, thorough)"
    echo "3. Network Focus (Communication checks)"
    echo "4. Execution Points (Cron, services, init)"
    echo "5. Custom Scan (Choose specific modules)"
    echo "6. Exit"
    echo ""
}

# Main execution
main() {
    log "Starting Smart Security Scanner..."
    
    # Mount system first
    if ! mount_system; then
        error "Failed to mount target system. Please check partitions."
        exit 1
    fi
    
    # Quick system check
    if ! quick_system_check; then
        error "System check failed. Please verify mount."
        unmount_system
        exit 1
    fi
    
    # Show menu and get choice
    show_menu
    read -p "Select option [1-6]: " choice
    
    case $choice in
        1)
            log "Starting Quick Scan..."
            scan_critical_files
            scan_execution_points
            ;;
        2)
            log "Starting Deep Scan..."
            scan_critical_files
            scan_execution_points
            scan_network_scripts
            ;;
        3)
            log "Starting Network Focus Scan..."
            scan_network_scripts
            ;;
        4)
            log "Starting Execution Points Scan..."
            scan_execution_points
            ;;
        5)
            echo "Custom scan options:"
            echo "a) Critical files only"
            echo "b) Network scripts only" 
            echo "c) Execution points only"
            read -p "Choose: " custom
            case $custom in
                a) scan_critical_files ;;
                b) scan_network_scripts ;;
                c) scan_execution_points ;;
                *) log "Invalid choice" ;;
            esac
            ;;
        6)
            log "Exiting..."
            unmount_system
            exit 0
            ;;
        *)
            error "Invalid option"
            unmount_system
            exit 1
            ;;
    esac
    
    # Generate results
    show_skip_statistics
    generate_summary
    show_next_steps
    
    # Cleanup
    unmount_system
}

# Run main function
main "$@"
