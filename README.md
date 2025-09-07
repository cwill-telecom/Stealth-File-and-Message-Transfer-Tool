# Stealth-File-and-Message-Transfer-Tool


A pair of Python scripts for covert file and message transfer using stealth network techniques. These tools use various obfuscation methods and non-standard protocols to make traffic appear as normal network noise.

## Features

- **Covert Communication**: Transfers files and messages using stealth techniques
- **Multiple Obfuscation Methods**: Base64 encoding, compression, XOR encryption, or no additional obfuscation
- **Protocol Randomization**: Uses uncommon IP protocols (41, 47, 50, 51)
- **IPv6 Encapsulation**: Wraps traffic in IPv6 packets with random addresses
- **Configurable Parameters**: Adjustable chunk sizes, delays, and ports
- **Cross-Platform**: Works on any system with Python and Scapy

## Components

- **stealth_sender.py** - Sends files and messages using stealth techniques
- **stealth_receiver.py** - Receives files and messages sent by the sender

## Installation

1. Ensure you have Python 3.6+ installed
2. Install the required dependency:

```bash
pip install scapy
```

3. Download both scripts to your system

## Usage

### Sender Script

```
python3 stealth_sender.py -i <interface> -d4 <destination_ip> [-m <message> | -f <file>] [options]
```

### Receiver Script

```
python3 stealth_receiver.py -i <interface> [options]
```

## Options

### Sender Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface` | Network interface (e.g., eth0, wlan0) | Required |
| `-d4, --destination4` | Destination IPv4 address | Required |
| `-m, --message` | Message to send (text) | Optional |
| `-f, --file` | File to send | Optional |
| `-O, --obfuscation` | Obfuscation method: none, base64, compression, xor | none |
| `--delay` | Delay between packets (milliseconds) | 0 |
| `--chunk-size` | File chunk size (bytes) | 500 |
| `-sp, --srcport` | Source port | 443 |
| `-dp, --dstport` | Destination port | 443 |
| `-T, --tcp` | Use TCP instead of UDP | False |
| `-v, --verbose` | Verbose output | False |

### Receiver Options

| Option | Description | Default |
|--------|-------------|---------|
| `-i, --interface` | Network interface (e.g., eth0, wlan0, lo) | Required |
| `-o, --output-dir` | Output directory for received files | received_files |
| `-v, --verbose` | Verbose output | False |

## Obfuscation Methods

- **none**: No additional obfuscation beyond the standard protocol hiding
- **base64**: Encodes file data using Base64 encoding
- **compression**: Compresses file data using zlib compression
- **xor**: Applies XOR encryption with a fixed key

## Examples

### Basic Message Transfer

**Sender:**
```bash
python3 stealth_sender.py -i eth0 -d4 192.168.1.100 -m "Hello, this is a secret message!"
```

**Receiver:**
```bash
python3 stealth_receiver.py -i eth0
```

### File Transfer with Base64 Obfuscation

**Sender:**
```bash
python3 stealth_sender.py -i eth0 -d4 192.168.1.100 -f secret.txt -O base64 --delay 10
```

**Receiver:**
```bash
python3 stealth_receiver.py -i eth0 -v
```

### File Transfer with Compression

**Sender:**
```bash
python3 stealth_sender.py -i eth0 -d4 192.168.1.100 -f largefile.zip -O compression --chunk-size 1000
```

**Receiver:**
```bash
python3 stealth_receiver.py -i eth0 -o downloads
```

### File Transfer with XOR Encryption

**Sender:**
```bash
python3 stealth_sender.py -i wlan0 -d4 10.0.0.5 -f sensitive.doc -O xor -T -sp 5353 -dp 5353
```

**Receiver:**
```bash
python3 stealth_receiver.py -i wlan0 -v
```

### Using Custom Ports and TCP

**Sender:**
```bash
python3 stealth_sender.py -i eth0 -d4 192.168.1.100 -f data.bin -O base64 -T -sp 8080 -dp 8080 --delay 5
```

**Receiver:**
```bash
python3 stealth_receiver.py -i eth0 -o received_files -v
```

## Stealth Techniques

The tool employs several techniques to avoid detection:

- Uses uncommon IP protocols (41, 47, 50, 51) instead of standard TCP/UDP
- Encapsulates traffic in IPv6 packets with random addresses
- Adds random obfuscation headers to mimic legitimate traffic
- Supports configurable delays between packets to avoid pattern detection
- Uses common ports (like 443) to appear as HTTPS traffic

## Troubleshooting

If you encounter issues:

1. Ensure both sender and receiver are using the same network interface
2. Check that firewalls are not blocking the traffic
3. Use the `-v` flag for verbose output to debug issues
4. Verify that the destination IP address is correct
5. Try different obfuscation methods if one isn't working
6. Try different delay and chunk-size attributes when send files.

## Legal and Ethical Considerations

This tool is intended for:

- Security research and education
- Authorized penetration testing
- Testing network monitoring systems
- Legitimate covert communication with proper authorization



## Disclaimer

This tool is provided for educational and authorized testing purposes only. The authors are not responsible for any misuse or damage caused by this program.
