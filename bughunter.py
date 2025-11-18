#!/usr/bin/env python3
"""
BugHunter Toolkit - All-in-One Security Testing Tool
Author: Security Researcher
Description: Comprehensive toolkit for ethical hacking and bug bounty hunting
Warning: Use only on authorized targets!
"""

import socket
import requests
import threading
import sys
import os
import re
import json
import time
from urllib.parse import urlparse, urljoin
from datetime import datetime
import dns.resolver
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

# Color codes for terminal
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

def banner():
    print(f"""{Colors.CYAN}
    ╔══════════════════════════════════════════════════╗
    ║     🔍 BugHunter Toolkit v1.0 🔍                 ║
    ║     All-in-One Security Testing Suite           ║
    ║     For Ethical Hacking & Bug Bounty            ║
    ╚══════════════════════════════════════════════════╝
    {Colors.END}""")

def print_success(msg):
    print(f"{Colors.GREEN}[+] {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.BLUE}[*] {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.WARNING}[!] {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.FAIL}[-] {msg}{Colors.END}")

# ==================== SUBDOMAIN ENUMERATION ====================
def subdomain_enum(domain, wordlist=None):
    print_info(f"Starting subdomain enumeration for {domain}")
    
    # Default subdomain list
    default_subs = [
        "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
        "blog", "shop", "store", "portal", "webmail", "smtp", "pop", "ns1",
        "ns2", "vpn", "remote", "secure", "m", "mobile", "app", "dashboard"
    ]
    
    subdomains = wordlist if wordlist else default_subs
    found = []
    
    print_info(f"Testing {len(subdomains)} subdomains...")
    
    for sub in subdomains:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print_success(f"Found: {subdomain}")
            found.append(subdomain)
        except socket.gaierror:
            pass
    
    return found

# ==================== PORT SCANNER ====================
def port_scan(target, ports=None):
    print_info(f"Starting port scan on {target}")
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]
    ports_to_scan = ports if ports else common_ports
    
    open_ports = []
    
    def scan_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                return port
        except:
            pass
        return None
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(scan_port, port) for port in ports_to_scan]
        for future in as_completed(futures):
            result = future.result()
            if result:
                print_success(f"Port {result} is OPEN")
                open_ports.append(result)
    
    return open_ports

# ==================== DIRECTORY BRUTEFORCE ====================
def dir_bruteforce(url, wordlist=None):
    print_info(f"Starting directory bruteforce on {url}")
    
    default_dirs = [
        "admin", "login", "dashboard", "api", "backup", "config", "db",
        "upload", "uploads", "files", "images", "css", "js", "test",
        "dev", "staging", "temp", ".git", ".env", "phpinfo.php"
    ]
    
    directories = wordlist if wordlist else default_dirs
    found = []
    
    for dir_path in directories:
        test_url = urljoin(url, dir_path)
        try:
            response = requests.get(test_url, timeout=3, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                print_success(f"Found: {test_url} [Status: {response.status_code}]")
                found.append({"url": test_url, "status": response.status_code})
        except:
            pass
    
    return found

# ==================== WAF DETECTOR ====================
def detect_waf(url):
    print_info(f"Detecting WAF on {url}")
    
    waf_signatures = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS WAF": ["x-amzn-requestid", "x-amz-"],
        "Akamai": ["akamai"],
        "Sucuri": ["sucuri", "x-sucuri"],
        "Incapsula": ["incapsula", "x-cdn"],
        "ModSecurity": ["mod_security", "modsecurity"]
    }
    
    try:
        response = requests.get(url, timeout=5)
        headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        detected = []
        for waf, signatures in waf_signatures.items():
            for sig in signatures:
                if any(sig in h or sig in v for h, v in headers.items()):
                    detected.append(waf)
                    break
        
        if detected:
            print_warning(f"WAF Detected: {', '.join(set(detected))}")
        else:
            print_info("No WAF detected")
        
        return detected
    except Exception as e:
        print_error(f"Error: {e}")
        return []

# ==================== XSS SCANNER ====================
def xss_scan(url, params=None):
    print_info(f"Starting XSS scan on {url}")
    
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "'><script>alert(String.fromCharCode(88,83,83))</script>"
    ]
    
    vulnerable = []
    
    if not params:
        print_warning("No parameters specified for testing")
        return vulnerable
    
    for param in params:
        for payload in xss_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                if payload in response.text:
                    print_success(f"Potential XSS found: {param} with payload: {payload}")
                    vulnerable.append({"param": param, "payload": payload})
            except:
                pass
    
    return vulnerable

# ==================== SQL INJECTION SCANNER ====================
def sqli_scan(url, params=None):
    print_info(f"Starting SQL injection scan on {url}")
    
    sqli_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "1' OR '1'='1",
        "' UNION SELECT NULL--"
    ]
    
    vulnerable = []
    
    if not params:
        print_warning("No parameters specified for testing")
        return vulnerable
    
    for param in params:
        for payload in sqli_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                response = requests.get(test_url, timeout=5)
                
                error_patterns = [
                    "sql syntax", "mysql", "sqlserver", "postgresql", 
                    "oracle", "syntax error", "database error"
                ]
                
                if any(pattern in response.text.lower() for pattern in error_patterns):
                    print_success(f"Potential SQLi found: {param} with payload: {payload}")
                    vulnerable.append({"param": param, "payload": payload})
            except:
                pass
    
    return vulnerable

# ==================== HEADER ANALYZER ====================
def analyze_headers(url):
    print_info(f"Analyzing security headers for {url}")
    
    security_headers = {
        "Strict-Transport-Security": "HSTS",
        "Content-Security-Policy": "CSP",
        "X-Frame-Options": "Clickjacking Protection",
        "X-Content-Type-Options": "MIME Sniffing Protection",
        "X-XSS-Protection": "XSS Protection",
        "Referrer-Policy": "Referrer Policy"
    }
    
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        print_info("Security Headers Status:")
        for header, description in security_headers.items():
            if header in headers:
                print_success(f"{description} ({header}): Present")
            else:
                print_warning(f"{description} ({header}): Missing")
        
        return headers
    except Exception as e:
        print_error(f"Error: {e}")
        return {}

# ==================== REPORT GENERATOR ====================
def generate_report(data, filename=None):
    if not filename:
        filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print_success(f"Report saved to {filename}")
    except Exception as e:
        print_error(f"Error saving report: {e}")

# ==================== MAIN MENU ====================
def main_menu():
    while True:
        banner()
        print(f"\n{Colors.BOLD}Select an option:{Colors.END}")
        print("1.  Subdomain Enumeration")
        print("2.  Port Scanner")
        print("3.  Directory Bruteforce")
        print("4.  WAF Detector")
        print("5.  XSS Scanner")
        print("6.  SQL Injection Scanner")
        print("7.  Security Headers Analyzer")
        print("8.  Full Reconnaissance (All Tools)")
        print("9.  Generate Report")
        print("0.  Exit")
        
        choice = input(f"\n{Colors.CYAN}Enter your choice: {Colors.END}")
        
        if choice == "1":
            domain = input("Enter domain (e.g., example.com): ")
            subdomain_enum(domain)
        
        elif choice == "2":
            target = input("Enter target IP/domain: ")
            port_scan(target)
        
        elif choice == "3":
            url = input("Enter URL (e.g., https://example.com): ")
            dir_bruteforce(url)
        
        elif choice == "4":
            url = input("Enter URL: ")
            detect_waf(url)
        
        elif choice == "5":
            url = input("Enter URL: ")
            params = input("Enter parameters (comma-separated, e.g., id,name): ").split(',')
            xss_scan(url, [p.strip() for p in params])
        
        elif choice == "6":
            url = input("Enter URL: ")
            params = input("Enter parameters (comma-separated): ").split(',')
            sqli_scan(url, [p.strip() for p in params])
        
        elif choice == "7":
            url = input("Enter URL: ")
            analyze_headers(url)
        
        elif choice == "8":
            target = input("Enter target domain/URL: ")
            print_info("Starting full reconnaissance...")
            
            results = {}
            
            # Parse URL
            parsed = urlparse(target)
            domain = parsed.netloc or target
            url = target if parsed.scheme else f"http://{target}"
            
            results['subdomains'] = subdomain_enum(domain)
            results['ports'] = port_scan(domain)
            results['directories'] = dir_bruteforce(url)
            results['waf'] = detect_waf(url)
            results['headers'] = dict(analyze_headers(url))
            
            print_success("Full reconnaissance completed!")
            generate_report(results)
        
        elif choice == "9":
            print_info("Report generation is automatic after full recon")
        
        elif choice == "0":
            print_info("Exiting... Happy hunting! 🎯")
            sys.exit(0)
        
        else:
            print_error("Invalid choice!")
        
        input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
        os.system('clear' if os.name == 'posix' else 'cls')

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print_info("\n\nExiting... Happy hunting! 🎯")
        sys.exit(0)
