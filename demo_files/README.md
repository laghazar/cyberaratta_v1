# CyberAratta Demo Files

This directory contains all the files created specifically for the demo presentation.

## Directory Structure

```
demo_files/
├── README.md                    # This file
├── api/
│   └── demo_api_views.py       # Demo API endpoints
├── templates/
│   └── demo_dashboard.html     # Demo dashboard template
├── scripts/
│   └── populate_demo_data.py   # Demo data population script
└── docs/
    └── DEMO_README.md          # Comprehensive demo documentation
```

## Files Description

### API Files
- **demo_api_views.py**: Enhanced API endpoints for live demonstration with real-time statistics

### Templates
- **demo_dashboard.html**: Comprehensive demo dashboard with live updates and animated counters

### Scripts
- **populate_demo_data.py**: Script to populate comprehensive demo data across all modules (150+ records per module)

### Documentation
- **DEMO_README.md**: Complete demo documentation with setup guide, demo script, and technical features

## Usage

1. First, populate demo data:
   ```bash
   python demo_files/scripts/populate_demo_data.py
   ```

2. Access demo dashboard:
   ```
   http://localhost:8000/demo-dashboard/
   ```

3. Use demo APIs for live presentation:
   ```
   http://localhost:8000/api/live-demo-stats/
   http://localhost:8000/api/demo-threat-feed/
   ```

## Integration Notes

- These files are designed to work with the main CyberAratta application
- Demo API views need to be properly imported in main URL configuration
- Demo dashboard template requires the main base template
- All demo functionality preserves production data integrity

For detailed setup and usage instructions, see `docs/DEMO_README.md`
