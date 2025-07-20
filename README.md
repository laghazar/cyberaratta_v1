# Cyberaratta

A modern cybersecurity platform focused on phishing detection and security awareness.

## Overview

Cyberaratta is a web-based cybersecurity platform that helps users identify and report suspicious URLs, emails, and other potential phishing attempts. With a sleek cyber-themed interface and powerful scanning capabilities, it provides tools for the security-conscious user.

## Features

- **URL Checker** - Scan URLs against VirusTotal and Kaspersky databases to detect malicious websites
- **Phishing Report System** - Submit and categorize suspicious phishing attempts
- **Security Statistics** - View updated statistics about security threats
- **Responsive Design** - Fully optimized for all devices
- **Modern UI** - Cyber-themed interface with intuitive navigation

## Technologies

- Django web framework
- Python
- HTML/CSS/JavaScript
- Integration with VirusTotal and Kaspersky APIs
- Responsive design

## Installation

1. Clone the repository
   ```bash
   git clone https://github.com/yourusername/cyberaratta_v1.git
   cd cyberaratta_v1
   ```

2. Create and activate virtual environment
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies
   ```bash
   pip install -r requirements.txt
   ```

4. Apply migrations
   ```bash
   python manage.py migrate
   ```

5. Run the development server
   ```bash
   python manage.py runserver
   ```

6. Visit http://127.0.0.1:8000 in your browser

## Usage

### URL Checking
Enter any suspicious URL into the URL checker to scan it against multiple security databases. Results will show whether the URL is safe, suspicious, or dangerous.

### Reporting Phishing
Use the phishing report form to submit suspicious emails or websites you encounter. Include relevant details like the suspicious URL, email content, and category of threat.

## Configuration

To set up API connections with VirusTotal and Kaspersky, add your API keys to the settings:

```python
# settings.py
VIRUSTOTAL_API_KEY = 'your_api_key_here'
KASPERSKY_API_KEY = 'your_api_key_here'
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file