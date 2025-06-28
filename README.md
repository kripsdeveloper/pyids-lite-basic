# Simple IDS (Intrusion Detection)

A lightweight, Python-based Intrusion Detection System that monitors network traffic in real-time and detects suspicious activities based on predefined rules.
 
## Features

- **Real-time Network Monitoring**: Captures and analyzes network packets in real-time
- **Multiple Attack Detection**:
  - SQL Injection attempts
  - Cross-Site Scripting (XSS) attacks
  - Directory traversal attacks
  - Code injection attempts
  - Command injection
  - Port scanning detection
  - Suspicious port access monitoring
- **IP Blacklisting**: Automatic blocking of malicious IP addresses
- **Logging System**: Comprehensive logging with different severity levels
- **Statistics Reporting**: Real-time statistics and periodic reports
- **Configurable Rules**: Easy-to-modify detection rules

## Requirements

- Python 3.6+
- Linux/Unix system (for raw socket access)
- Root/Administrator privileges (required for packet capture)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/kripsdeveloper/pyids-lite-basic.git
cd pyids-lite-basic
```

2. Make the script executable:
```bash
chmod +x ids.py
```

## Usage

### Basic Usage

Run with default settings (requires root privileges):
```bash
sudo python3 ids.py
```

### Advanced Usage

Specify network interface and log file:
```bash
sudo python3 ids.py -i eth0 -l /var/log/ids.log
```

### Command Line Options

- `-i, --interface`: Network interface to monitor (default: eth0)
- `-l, --log`: Log file path (default: ids.log)
- `-h, --help`: Show help message

### Example

```bash
# Monitor eth0 interface and log to custom file
sudo python3 ids.py -i eth0 -l /var/log/security.log

# Monitor wireless interface
sudo python3 ids.py -i wlan0
```

## Configuration

The IDS uses predefined rules that can be modified in the `load_rules()` method:

### Detection Rules

- **Port Scan Threshold**: 10 connections per minute
- **Request Rate Threshold**: 50 requests per minute
- **Suspicious Ports**: 22, 23, 135, 139, 445, 1433, 3306, 3389
- **Malicious Patterns**: SQL injection, XSS, directory traversal, code injection patterns

### Customizing Rules

Edit the `load_rules()` method in `ids.py`:

```python
def load_rules(self):
    rules = {
        'port_scan_threshold': 15, 
        'suspicious_ports': [22, 80, 443, 3389], 
        'blacklisted_ips': ['192.168.1.100', '10.0.0.50'], 
    }
    return rules
```

## Log Format

The IDS generates logs in the following format:

```
2025-07-28 10:30:45,123 - WARNING - ALERT: PORT_SCAN - {'src_ip': '192.168.1.100', 'dest_ip': '192.168.1.1', 'dest_port': 22, 'connection_count': 15}
2024-07-28 10:31:02,456 - WARNING - ALERT: SQL_INJECTION - {'src_ip': '10.0.0.50', 'dest_ip': '192.168.1.10', 'pattern': '(?i)(union.*select|drop.*table)', 'payload_snippet': 'GET /login.php?id=1 UNION SELECT * FROM users--'}
```

## Attack Types Detected

| Attack Type | Description | Severity |
|-------------|-------------|----------|
| SQL_INJECTION | SQL injection attempts | HIGH |
| XSS_ATTEMPT | Cross-site scripting attacks | HIGH |
| CODE_INJECTION | Code injection attempts | HIGH |
| BLACKLISTED_IP | Traffic from blacklisted IPs | HIGH |
| PORT_SCAN | Port scanning activities | MEDIUM |
| DIRECTORY_TRAVERSAL | Directory traversal attempts | MEDIUM |
| SUSPICIOUS_PORT | Access to suspicious ports | MEDIUM |
| COMMAND_INJECTION | Command injection attempts | HIGH |

## Stat

The IDS provides real-time statistics including:

- Total packets processed
- Number of suspicious packets detected
- Number of blocked IP addresses
- System uptime
- Detection rates

Statistics are logged every minute and displayed in the console.

## Limitations

- **Raw Socket Requirement**: Requires root privileges for packet capture
- **Linux/Unix Only**: Currently supports Unix-like systems only
- **Single Interface**: Monitors one network interface at a time
- **Basic Pattern Matching**: Uses regex patterns for detection (may have false positives)
- **No Persistent Storage**: Blocked IPs are not persistent across restarts

## Security Considerations

- Run with minimal privileges after initial setup
- Regularly update detection patterns
- Monitor log files for disk space usage
- Consider implementing log rotation
- Review and tune thresholds based on your network environment

## Troubleshooting

### Common Issues

1. **Permission Denied Error**:
   ```
   Solution: Run with sudo/root privileges
   ```

2. **Socket Creation Failed**:
   ```
   Solution: Ensure you're running on a supported system with proper network permissions
   ```

3. **High False Positives**:
   ```
   Solution: Adjust detection thresholds in the rules configuration
   ```

### Debug Mode

For debugging, modify the logging level in the script:
```python
logging.basicConfig(level=logging.DEBUG)
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-detection`)
3. Commit your changes (`git commit -am 'Add new detection rule'`)
4. Push to the branch (`git push origin feature/new-detection`)
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for educational purposes and authorized security testing only. Users are responsible for complying with all applicable laws and regulations. The authors are not responsible for any misuse of this software.

## Contact

- Email: alpkrips@gmail.com

## Changelog

### v1.0.0
- Initial release
- Basic packet capture and analysis
- Multiple attack detection patterns
- Real-time logging and statistics
- IP blacklisting functionality
