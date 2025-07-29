# 🛡️ CyberAratta

**A comprehensive cybersecurity awareness and threat intelligence platform designed for organizations, educational institutions, and security professionals.**

[![Django](https://img.shields.io/badge/Django-4.2+-092E20?style=flat&logo=django&logoColor=white)](https://djangoproject.com/)
[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat&logo=python&logoColor=white)](https://python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🎯 Overview

CyberAratta is an enterprise-grade cybersecurity platform that combines threat intelligence, security awareness training, and incident reporting capabilities. Built with Django and modern web technologies, it provides a comprehensive solution for organizations looking to enhance their cybersecurity posture through education, monitoring, and rapid response capabilities.

## ✨ Key Features

### 🔍 **Threat Intelligence & Monitoring**
- **Live Threat Map** - Real-time visualization of cyber threats with interactive Armenia-focused geographic mapping
- **URL Security Scanner** - Multi-engine scanning using VirusTotal and Kaspersky APIs for malicious website detection
- **Email & URL Analyzer** - Advanced analysis of suspicious communications and links

### 📊 **Security Awareness & Training**
- **Interactive Quiz System** - Gamified cybersecurity training with multiple difficulty levels
- **Educational Content** - Comprehensive learning modules for different user categories (school, student, professional)
- **Professional Field Specialization** - Targeted training for government, banking, education, and IT sectors

### 📋 **Incident Management**
- **Phishing Reporting System** - Streamlined incident reporting with file upload capabilities
- **Threat Categorization** - Advanced classification system for different types of cyber threats
- **Analytics Dashboard** - Real-time statistics and threat intelligence visualization

### 🎮 **Gamification & Engagement**
- **Millionaire-style Quiz** - Engaging cybersecurity knowledge assessment
- **Progress Tracking** - Individual and organizational progress monitoring
- **Certification System** - Achievement-based security awareness certification

### 🌐 **Multi-Language Support**
- Armenian and English language support
- Localized content for regional cybersecurity concerns
- Cultural adaptation for Armenian organizations

## 🏗️ Architecture & Technologies

### **Backend Framework**
- **Django 4.2+** - Robust web framework with security best practices
- **Celery** - Asynchronous task processing for background operations
- **Redis** - High-performance caching and message broker

### **Database & Storage**
- **SQLite/PostgreSQL** - Flexible database options for different deployment scales
- **Django ORM** - Secure database operations with built-in protection against SQL injection

### **External Integrations**
- **VirusTotal API** - Comprehensive malware and URL scanning
- **Kaspersky API** - Advanced threat detection capabilities
- **Custom Threat Intelligence** - Proprietary threat data collection and analysis

### **Frontend Technologies**
- **Bootstrap 4** - Responsive design framework
- **JavaScript/jQuery** - Interactive user interface components
- **CSS3** - Modern styling with cyber-themed aesthetics
- **Crispy Forms** - Enhanced form rendering and validation

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Redis server (for Celery task processing)
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/laghazar/cyberaratta_v1.git
   cd cyberaratta_v1
   ```

2. **Create and activate virtual environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate
   
   # macOS/Linux
   python -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Environment configuration**
   Create a `.env` file in the root directory:
   ```env
   SECRET_KEY=your-secret-key-here
   DEBUG=True
   REDIS_URL=redis://localhost:6379/0
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   KASPERSKY_API_KEY=your_kaspersky_api_key
   ```

5. **Database setup**
   ```bash
   python manage.py migrate
   python manage.py collectstatic --noinput
   ```

6. **Create superuser (optional)**
   ```bash
   python manage.py createsuperuser
   ```

7. **Load demo data (optional)**
   ```bash
   python populate_demo_data.py
   ```

8. **Start Redis server**
   ```bash
   # Windows (if Redis is installed)
   redis-server
   
   # macOS
   brew services start redis
   
   # Linux
   sudo systemctl start redis
   ```

9. **Start Celery worker (in separate terminal)**
   ```bash
   celery -A cyberaratta worker --loglevel=info
   ```

10. **Run the development server**
    ```bash
    python manage.py runserver
    ```

11. **Access the application**
    - Main application: http://127.0.0.1:8000/
    - Demo dashboard: http://127.0.0.1:8000/demo/
    - Admin panel: http://127.0.0.1:8000/admin/

## 📱 Application Modules

### 🗺️ **Threat Map** (`/threat_map/`)
Real-time visualization of cybersecurity threats with:
- Interactive geographic mapping
- Threat type categorization
- Temporal threat analysis
- Export capabilities for security reports

### 🧩 **Security Quiz** (`/quiz/`)
Gamified cybersecurity education featuring:
- Multiple question types and difficulty levels
- Category-based learning (School, Student, Professional)
- Progress tracking and certification
- Millionaire-style challenge mode

### 🔍 **URL Checker** (`/url-checker/`)
Comprehensive URL security analysis:
- Multi-engine scanning (VirusTotal, Kaspersky)
- Real-time threat detection
- Historical scan results
- Batch URL processing

### 📊 **Reporting System** (`/reporting/`)
Incident management and analytics:
- Phishing incident reporting
- File upload and analysis
- Threat categorization
- Statistical dashboards

### 👤 **Core Management**
User and system administration:
- User authentication and authorization
- Organization management
- System configuration
- API key management

## 🔧 Configuration

### API Integration
Configure external security services in your `.env` file:

```env
# VirusTotal Configuration
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# Kaspersky Configuration  
KASPERSKY_API_KEY=your_kaspersky_api_key_here

# Redis Configuration
REDIS_URL=redis://localhost:6379/0
```

### Database Configuration
For production deployment, configure PostgreSQL:

```python
# settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'cyberaratta',
        'USER': 'your_db_user',
        'PASSWORD': 'your_db_password',
        'HOST': 'localhost',
        'PORT': '5432',
    }
}
```

## 🎯 Use Cases

### **Educational Institutions**
- Cybersecurity curriculum integration
- Student assessment and certification
- Faculty training programs
- Campus-wide security awareness

### **Government Organizations**
- Employee security training
- Incident response coordination
- Threat intelligence sharing
- Compliance monitoring

### **Banking & Financial Services**
- Customer education on phishing
- Employee security protocols
- Real-time threat monitoring
- Regulatory compliance

### **IT & Technology Companies**
- Developer security training
- Threat intelligence integration
- Security culture development
- Client security services

## 🔒 Security Features

### **Data Protection**
- CSRF protection on all forms
- XSS prevention through Django's built-in templating
- SQL injection protection via ORM
- Secure session management
- Input validation and sanitization

### **API Security**
- Rate limiting on external API calls
- Secure API key storage and rotation
- Request/response logging for audit trails
- Error handling without information leakage

### **User Security**
- Password strength enforcement
- Session timeout management
- Secure authentication workflows
- Role-based access control

## 📈 Performance & Scalability

### **Optimization Features**
- Redis caching for improved response times
- Asynchronous task processing with Celery
- Database query optimization
- Static file compression and caching
- Responsive design for mobile performance

### **Monitoring & Analytics**
- Real-time dashboard metrics
- User engagement tracking
- Threat detection statistics
- System performance monitoring
- Error logging and alerting

## 🤝 Contributing

We welcome contributions from the cybersecurity community! Here's how you can help:

### **Development Setup**
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes and add tests
4. Commit your changes (`git commit -m 'Add amazing feature'`)
5. Push to the branch (`git push origin feature/amazing-feature`)
6. Open a Pull Request

### **Contribution Guidelines**
- Follow PEP 8 Python style guidelines
- Add unit tests for new features
- Update documentation for API changes
- Ensure backward compatibility
- Test across different Python versions

### **Areas for Contribution**
- 🔌 Additional API integrations (Shodan, IBM X-Force, etc.)
- 🌍 Internationalization and localization
- 📱 Mobile application development
- 🤖 Machine learning threat detection
- 📊 Advanced analytics and reporting
- 🎨 UI/UX improvements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **VirusTotal** for providing comprehensive malware scanning APIs
- **Kaspersky** for advanced threat detection capabilities
- **Django Community** for the robust web framework
- **Open Source Security Tools** that make this platform possible

## 📞 Support & Community

### **Documentation**
- [Architecture Documentation](docs/architecture.md)
- [API Documentation](docs/api.md)
- [Deployment Guide](docs/deployment.md)

### **Community**
- 🐛 [Report Issues](https://github.com/laghazar/cyberaratta_v1/issues)
- 💡 [Feature Requests](https://github.com/laghazar/cyberaratta_v1/discussions)
- 📧 Contact: [security@cyberaratta.am](mailto:security@cyberaratta.am)

### **Professional Services**
For enterprise deployment, custom integrations, or professional support, please contact our team for consultation and implementation services.

---

**Built with ❤️ for the cybersecurity community by the CyberAratta team**

*Protecting Armenia's digital future, one awareness session at a time.*