/opt/security-scanner/
├── scanner_core.sh           # Main orchestrator
├── config/
│   ├── main.conf            # Global configuration
│   ├── modules.conf         # Module settings
│   └── patterns/            # Detection patterns
├── modules/
│   ├── base/                # Core modules
│   │   ├── file_integrity.sh
│   │   ├── package_verify.sh
│   │   └── baseline_manager.sh
│   ├── detection/           # Detection modules
│   │   ├── yara_scanner.sh
│   │   ├── signature_detection.sh
│   │   ├── behavioral_analysis.sh
│   │   └── heuristic_detection.sh
│   ├── network/
│   │   ├── config_scanner.sh
│   │   ├── port_analyzer.sh
│   │   └── traffic_monitor.sh
│   └── analysis/
│       ├── forensics.sh
│       ├── timeline_analyzer.sh
│       └── report_generator.sh
├── data/
│   ├── baselines/           # System baselines
│   ├── signatures/          # Malware signatures
│   ├── yara_rules/          # YARA rules
│   └── logs/               # Scan logs
└── lib/
    ├── utils.sh            # Common utilities
    ├── logging.sh          # Logging functions
    └── output_formats.sh   # Output formatting
