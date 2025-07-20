# cyberaratta_v1
cyberaratta by phish hunters of Aratta

CyberAratta v1
Overview
CyberAratta v1 is a Django-based web application designed to provide cybersecurity-related functionalities, including a quiz system, threat map visualization, URL checking, and reporting features. The project is structured as a modular Django application with multiple apps (core, quiz, reporting, threat_map, url_checker) and utilizes Bootstrap for styling, Celery for asynchronous tasks, and SQLite as the default database.
Project Structure
The repository is organized as follows:

apps/: Contains Django apps for different functionalities:
core/: Handles the homepage and core features.
quiz/: Manages quiz-related functionality (e.g., questions, results).
reporting/: Provides reporting capabilities.
threat_map/: Displays a threat map visualization.
url_checker/: Handles URL checking tasks.


cyberaratta/: Django project settings and configuration files.
settings.py: Project settings (e.g., database, static files).
urls.py: Main URL routing.
celery.py: Celery configuration for asynchronous tasks.


static/: Static assets (CSS, JavaScript, images).
css/: Bootstrap and custom styles.
js/: JavaScript files, including Bootstrap and custom scripts (e.g., threat_map.js).
images/: Images used across the application (e.g., hero-image.jpg).


templates/: HTML templates for rendering pages.
core/: Homepage and stats templates.
quiz/: Quiz-related templates (e.g., millionaire.html, result.html).
reporting/: Reporting templates.
threat_map/: Threat map template.
url_checker/: URL checker template.
base.html: Base template for shared layout.


.env: Environment variables (e.g., SECRET_KEY, database credentials).
db.sqlite3: SQLite database file.
manage.py: Django management script.
requirements.txt: Python dependencies.
venv/: Virtual environment for the project.

Prerequisites

Python 3.10 or higher
Virtualenv (recommended for dependency isolation)
Redis (for Celery task queue)
Git

Setup Instructions

Clone the Repository:
git clone https://github.com/laghazar/cyberaratta_v1.git
cd cyberaratta_v1


Create and Activate a Virtual Environment:
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

Install Dependencies:
pip install -r requirements.txt

Configure Environment Variables:

Create a .env file in the project root (if not already present).
Add necessary variables, e.g.:SECRET_KEY=your-secret-key
DEBUG=True
DATABASE_URL=sqlite:///db.sqlite3
CELERY_BROKER_URL=redis://localhost:6379/0
Apply Database Migrations:
python manage.py makemigrations
python manage.py migrate


Collect Static Files:
python manage.py collectstatic


Run the Development Server:
python manage.py runserver


Access the application at http://localhost:8000.


Run Celery (for asynchronous tasks):

Ensure Redis is running locally or update CELERY_BROKER_URL in .env.
Start the Celery worker:celery -A cyberaratta worker --loglevel=info
Usage

Homepage: Access the main page at http://localhost:8000, rendered by core/templates/core/home.html.
Quiz: Navigate to the quiz section for interactive cybersecurity quizzes.
Threat Map: View real-time threat visualizations.
URL Checker: Submit URLs for security analysis.
Reporting: Generate reports based on collected data.
Use the Django admin panel (http://localhost:8000/admin) to manage data (create a superuser with python manage.py createsuperuser).

Contributing
Contributions are welcome. Please follow these steps:

Fork the repository.
Create a new branch (git checkout -b feature/your-feature).
Commit changes (git commit -m "Add your feature").
Push to the branch (git push origin feature/your-feature).
Open a pull request.

License
This project is licensed under the MIT License. See the LICENSE file for details (if applicable).




cyberaratta_v1/
├── apps/
│   ├── core/
│   │   ├── migrations/
│   │   ├── admin.py
│   │   ├── api_urls.py
│   │   ├── apps.py
│   │   ├── forms.py
│   │   ├── models.py
│   │   ├── urls.py
│   │   ├── utils.py
│   │   ├── views.py
│   │   └── __init__.py
│   ├── quiz/
│   │   ├── migrations/
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── forms.py
│   │   ├── models.py
│   │   ├── urls.py
│   │   ├── views.py
│   │   └── __init__.py
│   ├── reporting/
│   │   ├── migrations/
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── forms.py
│   │   ├── models.py
│   │   ├── urls.py
│   │   ├── views.py
│   │   └── __init__.py
│   ├── threat_map/
│   │   ├── migrations/
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── forms.py
│   │   ├── models.py
│   │   ├── urls.py
│   │   ├── views.py
│   │   └── __init__.py
│   ├── url_checker/
│   │   ├── migrations/
│   │   ├── admin.py
│   │   ├── apps.py
│   │   ├── forms.py
│   │   ├── models.py
│   │   ├── tasks.py
│   │   ├── urls.py
│   │   ├── views.py
│   │   └── __init__.py
│   └── __pycache__/
│       └── __init__.cpython-313.pyc
├── cyberaratta/
│   ├── __pycache__/
│   ├── __init__.py
│   ├── asgi.py
│   ├── celery.py
│   ├── settings.py
│   ├── urls.py
│   └── wsgi.py
├── static/
│   ├── css/
│   │   ├── bootstrap.min.css
│   │   └── custom.css
│   ├── images/
│   │   ├── hero-image.jpg
│   │   ├── quiz-icon.png
│   │   ├── reporting-icon.png
│   │   ├── threat-map-icon.png
│   │   └── url-checker-icon.png
│   └── js/
│       ├── bootstrap.min.js
│       ├── chart.min.js
│       └── threat_map.js
├── staticfiles/
│   ├── admin/
│   ├── css/
│   ├── images/
│   └── js/
├── templates/
│   ├── core/
│   │   ├── home.html
│   │   └── stats.html
│   ├── quiz/
│   │   ├── home.html
│   │   ├── millionaire.html
│   │   ├── question.html
│   │   ├── result.html
│   │   └── start.html
│   ├── reporting/
│   │   └── report.html
│   ├── threat_map/
│   │   └── map.html
│   ├── url_checker/
│   │   └── check.html
│   └── base.html
├── .env
├── README.md
├── db.sqlite3
├── manage.py
├── requirements.txt
└── venv/
    ├── Include/
    ├── Lib/
    │   └── site-packages/
    ├── Scripts/
    │   ├── activate
    │   ├── activate.bat
    │   ├── Activate.ps1
    │   ├── celery.exe
    │   ├── django-admin.exe
    │   └── python.exe
    ├── .gitignore
    └── pyvenv.cfg
