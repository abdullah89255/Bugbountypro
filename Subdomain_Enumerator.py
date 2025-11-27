#!/usr/bin/env python3
import requests
import threading
from queue import Queue

class SubdomainEnumerator:
    def __init__(self, domain, wordlist_file="subdomains.txt"):
        self.domain = domain
        self.wordlist_file = wordlist_file
        self.found_subdomains = []
        
    def check_subdomain(self, subdomain):
        url = f"http://{subdomain}.{self.domain}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                self.found_subdomains.append(url)
                print(f"[+] Found: {url}")
        except:
            pass
    
    def enumerate(self, threads=50):
        with open(self.wordlist_file, 'r') as f:
            subdomains = [line.strip() for line in f]
        
        queue = Queue()
        for subdomain in subdomains:
            queue.put(subdomain)
        
        def worker():
            while not queue.empty():
                subdomain = queue.get()
                self.check_subdomain(subdomain)
                queue.task_done()
        
        for _ in range(threads):
            threading.Thread(target=worker, daemon=True).start()
        
        queue.join()
        return self.found_subdomains
