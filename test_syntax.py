#!/usr/bin/env python3
"""
Simple syntax test for utils.py
"""
import sys
import ast

try:
    with open('apps/url_checker/utils.py', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Parse the AST to check for syntax errors
    ast.parse(content)
    print("✅ No syntax errors found in utils.py")
    
except SyntaxError as e:
    print(f"❌ Syntax error found in utils.py:")
    print(f"Line {e.lineno}: {e.text}")
    print(f"Error: {e.msg}")
    sys.exit(1)
except FileNotFoundError:
    print("❌ utils.py file not found")
    sys.exit(1)
except Exception as e:
    print(f"❌ Error checking syntax: {e}")
    sys.exit(1)
