# Ollama Network Service Scanner

## Project Description
This tool is designed to automatically scan and detect the availability of Ollama services on hosts specified in an IP list. It supports concurrent scanning and custom service port configuration.

## Key Features
- Concurrent scanning
- Custom port configuration
- Real-time response status detection
- Concise result output

## File Structure
```
├── scan        # Main executable
├── config.yaml # Configuration file
└── ip.txt      # Target IP list (supports CIDR notation)
```

## Quick Start
### Environment Setup
1. Download latest release from [Releases](https://github.com/xxx/scan/releases) (scan-linux-amd64.zip)
2. Unzip and grant execution permission: `chmod +x scan`
3. Copy config template: `cp config.example.yaml config.yaml`

### Run Scan
```bash
./scan
```

## Important Notes
• Requires root privileges to run
• For educational and research purposes only