# CyberAratta - Technical and Security Overview

## What is CyberAratta?

CyberAratta is a website that helps people stay safe on the internet. It was made for people in Armenia. The website has many tools to check if websites are safe and to learn about internet dangers.

## How the Website Works

### Main Parts of the Website

1. **URL Checker**: This part checks if a website is safe or dangerous.
2. **Threat Map**: This shows where internet attacks come from on a map.
3. **Quiz System**: People can answer questions to learn about internet safety.
4. **Reporting**: People can tell us about dangerous emails or websites.

### Website Structure

The website is built like this:

```
Users → Web Server → Website Programs → Database
```

- **Users**: People who visit the website
- **Web Server**: Nginx (a program that sends website pages to users)
- **Website Programs**: Made with Django (a Python tool for making websites)
- **Database**: Stores all the information (SQLite or PostgreSQL)

## Security Features

### URL Checking System

When someone wants to check if a website is safe:

1. They type the website address
2. The system first checks if it's a known safe website (like google.com)
3. If not, it checks with security services:
   - VirusTotal
   - Kaspersky
   - Google Safe Browsing
4. The system shows if the website is:
   - Safe (green)
   - Suspicious (yellow)
   - Dangerous (red)

### Threat Map

The threat map shows:
- Where attacks come from
- What types of attacks happen (virus, phishing, etc.)
- How dangerous the attacks are

### Safety Quiz

The quiz helps people learn about internet safety:
- Different questions for students, teachers, and professionals
- Special questions for government, banking, and education workers
- A game-like system with Armenian cultural elements

### Reporting System

People can report dangerous emails or websites:
- They can upload files safely
- The system checks the files for safety
- The information helps protect other people

## How We Protect Your Information

### Data Protection

- We use Django's built-in security tools
- All forms are protected against CSRF attacks
- We prevent XSS attacks with special settings
- We check all uploaded files for safety

### API Security

- We keep API keys secure using environment variables
- We have a special system for connecting to security services
- We handle errors without showing sensitive information

### File Security

- We limit how big files can be:
  - Images: 5MB
  - Documents: 10MB
  - Videos: 50MB
  - Audio: 15MB
- We check what type of files people upload
- We store files in safe locations

## Technical Structure

### Languages and Tools

- **Programming**: Python 3.13
- **Web Framework**: Django 5.2.4
- **Front-end**: Bootstrap 5.3, jQuery, Chart.js, Leaflet.js
- **Database**: SQLite (for development), PostgreSQL (for production)
- **Task Processing**: Celery with Redis
- **Web Server**: Nginx with Gunicorn

### How Parts Work Together

- **Background Tasks**: The system uses Celery to check websites without making users wait
- **Caching**: Redis makes the website faster by saving information that's used often
- **Database**: Stores all user reports, quiz results, and security checks
- **Web Server**: Handles requests from users and sends back web pages

## Security Layers

The website has many layers of security:

1. **Web Application Firewall**: Blocks bad requests
2. **HTTPS/TLS**: Encrypts information between users and the website
3. **Authentication**: Makes sure only allowed people can access certain parts
4. **CSRF Protection**: Prevents fake requests
5. **XSS Protection**: Stops attackers from adding bad code to the website
6. **SQL Injection Protection**: Keeps the database safe
7. **Input Validation**: Checks all information users enter

## Future Improvements

We plan to make these improvements:
- Add machine learning to find new threats
- Add two-factor authentication for more security
- Add more ways to see security problems in real-time

---

*This document describes the CyberAratta cybersecurity awareness platform as it exists today. All features described are already implemented in the system.*
