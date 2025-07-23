#!/usr/bin/env python3
"""
CyberAratta Platform Test Suite
Complete functionality testing for all modules
"""

import os
import sys
import django
import requests
import time
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'cyberaratta.settings')
django.setup()

from apps.reporting.models import PhishingReport, ContactInfo, ContactGuideline
from apps.threat_map.models import Threat, PhishingURL, CyberThreatIntelligence
from apps.quiz.models import Question, Answer, QuizCategory
from apps.url_checker.models import URLCheck

class CyberArattaTester:
    def __init__(self):
        self.base_url = "http://127.0.0.1:8001"
        self.results = []
        
    def log_test(self, test_name, status, message=""):
        """Log test results"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status_icon = "✅" if status else "❌"
        self.results.append({
            'test': test_name,
            'status': status,
            'message': message,
            'timestamp': timestamp
        })
        print(f"[{timestamp}] {status_icon} {test_name}: {message}")
    
    def test_homepage(self):
        """Test homepage functionality"""
        print("\n🏠 Testing Homepage...")
        try:
            response = requests.get(f"{self.base_url}/", timeout=10)
            if response.status_code == 200:
                self.log_test("Homepage Load", True, "Homepage loaded successfully")
                if "CyberAratta" in response.text:
                    self.log_test("Homepage Content", True, "Brand name found")
                else:
                    self.log_test("Homepage Content", False, "Brand name not found")
            else:
                self.log_test("Homepage Load", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Homepage Load", False, f"Error: {str(e)}")
    
    def test_quiz_module(self):
        """Test quiz functionality"""
        print("\n❓ Testing Quiz Module...")
        
        # Test quiz homepage
        try:
            response = requests.get(f"{self.base_url}/quiz/", timeout=10)
            if response.status_code == 200:
                self.log_test("Quiz Homepage", True, "Quiz page loaded")
            else:
                self.log_test("Quiz Homepage", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Quiz Homepage", False, f"Error: {str(e)}")
        
        # Test database data
        questions_count = Question.objects.count()
        categories_count = QuizCategory.objects.count()
        
        if questions_count > 0:
            self.log_test("Quiz Questions", True, f"{questions_count} questions found")
        else:
            self.log_test("Quiz Questions", False, "No questions in database")
            
        if categories_count > 0:
            self.log_test("Quiz Categories", True, f"{categories_count} categories found")
        else:
            self.log_test("Quiz Categories", False, "No categories in database")
    
    def test_reporting_module(self):
        """Test reporting functionality"""
        print("\n📊 Testing Reporting Module...")
        
        # Test reporting page
        try:
            response = requests.get(f"{self.base_url}/reporting/report/", timeout=10)
            if response.status_code == 200:
                self.log_test("Reporting Page", True, "Reporting page loaded")
            else:
                self.log_test("Reporting Page", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Reporting Page", False, f"Error: {str(e)}")
        
        # Test database data
        reports_count = PhishingReport.objects.count()
        contacts_count = ContactInfo.objects.count()
        guidelines_count = ContactGuideline.objects.count()
        
        if reports_count > 0:
            self.log_test("Phishing Reports", True, f"{reports_count} reports found")
        else:
            self.log_test("Phishing Reports", False, "No reports in database")
            
        if contacts_count > 0:
            self.log_test("Contact Info", True, f"{contacts_count} contacts found")
        else:
            self.log_test("Contact Info", False, "No contacts in database")
            
        if guidelines_count > 0:
            self.log_test("Contact Guidelines", True, f"{guidelines_count} guidelines found")
        else:
            self.log_test("Contact Guidelines", False, "No guidelines in database")
    
    def test_threat_map_module(self):
        """Test threat map functionality"""
        print("\n🗺️ Testing Threat Map Module...")
        
        # Test threat map page
        try:
            response = requests.get(f"{self.base_url}/threat_map/", timeout=10)
            if response.status_code == 200:
                self.log_test("Threat Map Page", True, "Threat map page loaded")
            else:
                self.log_test("Threat Map Page", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("Threat Map Page", False, f"Error: {str(e)}")
        
        # Test API endpoints
        api_endpoints = [
            '/threat_map/api/stats/',
            '/threat_map/api/threats/',
            '/threat_map/api/phishing-urls/'
        ]
        
        for endpoint in api_endpoints:
            try:
                response = requests.get(f"{self.base_url}{endpoint}", timeout=10)
                if response.status_code == 200:
                    self.log_test(f"API {endpoint}", True, "API working")
                else:
                    self.log_test(f"API {endpoint}", False, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test(f"API {endpoint}", False, f"Error: {str(e)}")
        
        # Test database data
        threats_count = Threat.objects.count()
        phishing_urls_count = PhishingURL.objects.count()
        intel_count = CyberThreatIntelligence.objects.count()
        
        if threats_count > 0:
            self.log_test("Threats Data", True, f"{threats_count} threats found")
        else:
            self.log_test("Threats Data", False, "No threats in database")
            
        if phishing_urls_count > 0:
            self.log_test("Phishing URLs", True, f"{phishing_urls_count} URLs found")
        else:
            self.log_test("Phishing URLs", False, "No phishing URLs in database")
            
        if intel_count > 0:
            self.log_test("Threat Intelligence", True, f"{intel_count} intel records found")
        else:
            self.log_test("Threat Intelligence", False, "No intel records in database")
    
    def test_url_checker_module(self):
        """Test URL checker functionality"""
        print("\n🔗 Testing URL Checker Module...")
        
        # Test URL checker page
        try:
            response = requests.get(f"{self.base_url}/url_checker/", timeout=10)
            if response.status_code == 200:
                self.log_test("URL Checker Page", True, "URL checker page loaded")
            else:
                self.log_test("URL Checker Page", False, f"Status code: {response.status_code}")
        except Exception as e:
            self.log_test("URL Checker Page", False, f"Error: {str(e)}")
        
        # Test database data
        url_checks_count = URLCheck.objects.count()
        
        if url_checks_count > 0:
            self.log_test("URL Checks", True, f"{url_checks_count} URL checks found")
        else:
            self.log_test("URL Checks", False, "No URL checks in database")
    
    def test_navigation(self):
        """Test navigation between pages"""
        print("\n🧭 Testing Navigation...")
        
        pages = [
            ('/', 'Homepage'),
            ('/quiz/', 'Quiz'),
            ('/reporting/report/', 'Reporting'),
            ('/threat_map/', 'Threat Map'),
            ('/url_checker/', 'URL Checker')
        ]
        
        for url, name in pages:
            try:
                response = requests.get(f"{self.base_url}{url}", timeout=10)
                if response.status_code == 200:
                    # Check if navigation menu is present
                    if 'navbar' in response.text and 'CyberAratta' in response.text:
                        self.log_test(f"Navigation to {name}", True, "Page accessible with nav")
                    else:
                        self.log_test(f"Navigation to {name}", False, "Navigation missing")
                else:
                    self.log_test(f"Navigation to {name}", False, f"Status: {response.status_code}")
            except Exception as e:
                self.log_test(f"Navigation to {name}", False, f"Error: {str(e)}")
    
    def generate_report(self):
        """Generate final test report"""
        print("\n" + "="*60)
        print("🎯 CYBERARATTA PLATFORM TEST REPORT")
        print("="*60)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r['status'])
        failed_tests = total_tests - passed_tests
        success_rate = (passed_tests / total_tests * 100) if total_tests > 0 else 0
        
        print(f"📊 SUMMARY:")
        print(f"   Total Tests: {total_tests}")
        print(f"   ✅ Passed: {passed_tests}")
        print(f"   ❌ Failed: {failed_tests}")
        print(f"   📈 Success Rate: {success_rate:.1f}%")
        print()
        
        if failed_tests > 0:
            print("❌ FAILED TESTS:")
            for result in self.results:
                if not result['status']:
                    print(f"   • {result['test']}: {result['message']}")
            print()
        
        print("🎯 PLATFORM STATUS:")
        if success_rate >= 90:
            print("   🟢 EXCELLENT - Platform is ready for production!")
        elif success_rate >= 75:
            print("   🟡 GOOD - Minor issues need attention")
        elif success_rate >= 50:
            print("   🟠 MODERATE - Several issues need fixing")
        else:
            print("   🔴 CRITICAL - Major issues require immediate attention")
        
        print("\n🚀 RECOMMENDATIONS:")
        if failed_tests == 0:
            print("   • All systems operational - ready for deployment!")
            print("   • Consider performance optimization")
            print("   • Add monitoring and logging")
        else:
            print("   • Fix failed tests before deployment")
            print("   • Review error logs for details")
            print("   • Test again after fixes")
    
    def run_all_tests(self):
        """Run all tests"""
        print("🛡️ STARTING CYBERARATTA PLATFORM TESTS")
        print("="*50)
        
        start_time = time.time()
        
        self.test_homepage()
        self.test_quiz_module()
        self.test_reporting_module()
        self.test_threat_map_module()
        self.test_url_checker_module()
        self.test_navigation()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n⏱️ Tests completed in {duration:.2f} seconds")
        self.generate_report()

if __name__ == '__main__':
    tester = CyberArattaTester()
    tester.run_all_tests()
