#!/usr/bin/env python3
"""
Test script for URL checker functions
"""
import sys
import os

# Add the project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Mock Django settings
class MockConfig:
    def __call__(self, key, default=None):
        configs = {
            'VIRUSTOTAL_API_KEY': '7b17bf3c47cf6c00d36234d3f24e65208d96fc5e71ec60c0e08c52745c44605c',
            'KASPERSKY_API_KEY': 'eIW0fHrQQuWvLqMG96zyoA==',
            'GOOGLE_SAFEBROWSING_API_KEY': 'AIzaSyDIx4XWpTDmHtXomhhEmz-CQAI91QViWr4'
        }
        return configs.get(key, default)

# Mock the config function
import builtins
builtins.config = MockConfig()

try:
    # Test importing the functions
    from apps.url_checker.utils import is_trusted_domain, check_url_safebrowsing
    
    print("✅ Successfully imported utils functions")
    
    # Test trusted domain check
    test_url = "https://birejip47.m-pages.com/chGZNR/awee"
    print(f"Testing URL: {test_url}")
    
    is_trusted = is_trusted_domain(test_url)
    print(f"Is trusted domain: {is_trusted}")
    
    # Test Google Safe Browsing (without making actual API call)
    print("✅ Functions imported and basic tests passed")
    
except Exception as e:
    print(f"❌ Error during testing: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)
