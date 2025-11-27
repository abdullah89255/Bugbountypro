#!/usr/bin/env python3
import requests
import threading
from queue import Queue

class DirectoryBruteforcer:
    def __init__(self, base_url, wordlist_file="directories.txt"):
        self.base_url = base_url.rstrip('/')
        self.wordlist_file = wordlist_file
        self.found_directories = []
        
    def check_directory(self, directory):
        url = f"{self.base_url}/{directory}"
        try:
            response = requests.get(url, timeout=5)
            if response.status_code != 404:
                self.found_directories.append({
                    'url': url,
                    'status': response.status_code,
                    'size': len(response.content)
                })
                print(f"[{response.status_code}] {url}")
        except:
            pass
    
    def bruteforce(self, threads=20):
        with open(self.wordlist_file, 'r') as f:
            directories = [line.strip() for line in f]
        
        queue = Queue()
        for directory in directories:
            queue.put(directory)
        
        def worker():
            while not queue.empty():
                directory = queue.get()
                self.check_directory(directory)
                queue.task_done()
        
        for _ in range(threads):
            threading.Thread(target=worker, daemon=True).start()
        
        queue.join()
        return self.found_directories
