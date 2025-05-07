<p align="center">
  <img src="img/logo.png" alt="JoomlaBrute Logo" width="300"/>
</p>

<h1 align="center">JoomlaBrute</h1>

<p align="center">
  <strong>A sophisticated Joomla administrator brute force tool for security testing and penetration testing purposes.</strong>
  <br />
  This tool helps identify weak administrator credentials in Joomla CMS installations.
</p>

<p align="center">
  <a href="https://github.com/0xricksanchez/joomla_brute/blob/main/LICENSE"><img src="https://img.shields.io/github/license/0xricksanchez/joomla_brute" alt="License"></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/python-3.11%2B-blue" alt="Python Version"></a>
  <a href="https://github.com/0xricksanchez/joomla_brute/releases"><img src="https://img.shields.io/badge/version-v1.0-red" alt="Tool Version"></a>
</p>

## 🔍 Features

- **Smart Detection**: Auto-detects Joomla version when possible
- **Rate Limit Handling**: Adapts to anti-brute force measures with exponential backoff
- **Token Management**: Intelligently handles Joomla's CSRF tokens
- **Flexible Authentication**: Supports multiple user/password combinations
- **Configurable Timing**: Control delay and jitter to avoid detection
- **Proxy Support**: Route requests through a proxy for additional anonymity
- **Comprehensive Logging**: Detailed logs for security reports
- **User-friendly Output**: Clear statistics and progress reporting

## 🔧 Requirements

- Python 3.11+
- Required packages:
  - requests
  - beautifulsoup4
  - tqdm
  - colorama
  - lxml (optional, but recommended for XML parsing)

## 📥 Installation

Clone the repository and install the dependencies:

```bash
git clone https://github.com/0xricksanchez/joomla_brute.git
cd joomla_brute
pip install -r requirements.txt
```

## 🚀 Usage

```
python joomla_brute.py -u http://example.com -U admin -PL wordlist.txt -d 1.0
```

### Basic Options

```
  -u URL, --url URL       Base URL of Joomla site (e.g., http://example.com)
  -U USER, --user USER    Single username
  -UL USERLIST, --userlist USERLIST
                          File of usernames, one per line
  -p PASSWORD, --password PASSWORD
                          Single password
  -PL PASSWORDLIST, --passwordlist PASSWORDLIST
                          File of passwords, one per line
```

### Advanced Options

```
  --proxy PROXY           HTTP/S proxy (e.g., http://127.0.0.1:8080)
  -d DELAY, --delay DELAY
                          Base delay between login attempts in seconds (default: 1.0)
  -j JITTER, --jitter JITTER
                          Random +/- jitter added to delay in seconds (default: 0.5)
  -t TIMEOUT, --timeout TIMEOUT
                          Request timeout in seconds (default: 10.0)
  -r RETRIES, --retries RETRIES
                          Max retries for failed network requests (default: 3)
  -a USER_AGENT, --user-agent USER_AGENT
                          Custom User-Agent string
  -l LOG, --log LOG       Log file path (logs debug info regardless of verbosity)
  -x, --exit-on-success   Exit immediately after finding the first valid credential
  -q, --quiet             Minimal output (suppress banner, progress bars, stats)
  -v, --verbose           Enable verbose logging to console (DEBUG level)
  --version               Show version number and exit
```

## 📋 Examples

### Using Single Username/Password

```bash
python joomla_brute.py -u http://example.com -U admin -p password123
```

### Using Username and Password Lists

```bash
python joomla_brute.py -u http://example.com -UL users.txt -PL passwords.txt
```

### Using a Proxy with Slower Timing

```bash
python joomla_brute.py -u http://example.com -U admin -PL passwords.txt --proxy http://127.0.0.1:8080 -d 2.0 -j 1.0
```

### Finding All Valid Credentials in Quiet Mode

```bash
python joomla_brute.py -u http://example.com -UL users.txt -PL passwords.txt -q
```

### Exit After First Valid Credential with Verbose Logging

```bash
python joomla_brute.py -u http://example.com -UL users.txt -PL passwords.txt -x -v
```

## 📊 Output

JoomlaBrute provides detailed statistics upon completion:

```
________________________________________________________________________________

                      JOOMLA BRUTE FORCE - SUMMARY REPORT
________________________________________________________________________________
  Target URL             : http://example.com/administrator/
  Time Elapsed           : 00:01:23
  Total Attempts         : 150
  Average Speed          : 1.81 attempts/s
  Credentials Found      : 1
________________________________________________________________________________

________________________________________________________________________________
                              SUCCESSFUL LOGINS
________________________________________________________________________________
  admin                  : foobar123!
________________________________________________________________________________
```

## 💡 Tips

- Start with common admin usernames: `admin`, `administrator`, `root`, `joomla`
- Use the `-d` and `-j` parameters to avoid triggering anti-brute force measures
- Always log your activities with the `-l` option for documentation
- The `-v` flag helps debug connection issues or unexpected behaviors
- Consider using the `--proxy` option for sensitive testing
- Use `-x` to stop after finding the first valid credential (faster for POC)

## 🛡️ Defense Recommendations

If you're a Joomla administrator, protect against brute force attacks by:

1. Using strong, unique passwords
2. Implementing two-factor authentication
3. Using security plugins that limit login attempts
4. Using a Web Application Firewall (WAF)
5. Not exposing your admin panel directly to the internet
6. Changing the default admin username
7. Regularly updating your Joomla installation

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📝 License

This project is licensed under the Apache-2.0 License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Legal Disclaimer

This tool is intended for **legal security testing only**. Always obtain explicit written permission before testing any website or application. Unauthorized access to computer systems is illegal and unethical.

The author assumes NO responsibility for any misuse of this software or damage caused by it. Use at your own risk and only on systems you have permission to test.

## 📬 Contact

- Author: 0x434b (mail@0x434b.dev)
- Project Link: [https://github.com/0xricksanchez/joomla_brute](https://github.com/0xricksanchez/joomla_brute)
