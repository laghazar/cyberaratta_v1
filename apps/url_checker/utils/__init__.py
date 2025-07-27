"""
URL Checker - utilities package

Սա հավաքածու է URL Checker համակարգի օգտակար գործիքների։
Հիմնական կոմպոնենտները ներառում են՝
- analyzer: URL-ի անվտանգության վերլուծություն
- api_clients: Արտաքին API ծառայությունների հետ ինտեգրացիա
- formatting: Պատասխանների ֆորմատավորում  
- validators: URL-ի վավերացում
- recommendations: Անվտանգության առաջարկություններ
- results: Արդյունքների ձևավորում
- database: Տվյալների շտեմարանի հետ աշխատանք
- helpers: Օժանդակ ֆունկցիաներ
"""

# Import key functions to make them available at package level
from .analyzer import analyze_url_pattern, analyze_url_safety
from .api_clients import check_url_virustotal, check_url_kaspersky, check_url_safebrowsing
from .validators import is_trusted_domain, is_valid_url, categorize_url
from .formatting import format_scan_result_html, format_overall_result
from .recommendations import generate_recommendations
from .results import format_detailed_response, calculate_security_score
from .database import save_url_check_results, get_recent_url_checks, get_url_check_statistics
from .helpers import (
    extract_domain_from_url, 
    clean_url, 
    generate_unique_id, 
    format_json_for_display,
    truncate_string,
    sanitize_filename
)

# Version
__version__ = '1.0.0'
