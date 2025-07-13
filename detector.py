import psutil
import os
import time
from colorama import Fore, Style

def is_suspicious(proc):
    try:
        name = proc.name()
        exe = proc.exe()
        username = proc.username()

        # القاعدة 1: العملية بدون اسم
        if not name or name.strip() == "":
            return True, "Unnamed process"

        # القاعدة 2: تعمل من مجلدات مؤقتة أو غير معتادة
        if "temp" in exe.lower() or "/tmp" in exe.lower():
            return True, f"Running from temp path: {exe}"

        # القاعدة 3: استهلاك الذاكرة مرتفع (أكثر من 500MB)
        mem_usage = proc.memory_info().rss / (1024 * 1024)
        if mem_usage > 500:
            return True, f"High memory usage: {mem_usage:.2f} MB"

    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False, ""

    return False, ""

def scan_processes():
    print(f"{Fore.CYAN}Scanning running processes...{Style.RESET_ALL}")
    time.sleep(1)
    for proc in psutil.process_iter(['pid', 'name']):
        suspicious, reason = is_suspicious(proc)
        if suspicious:
            print(f"{Fore.RED}[!] Suspicious Process Detected:{Style.RESET_ALL}")
            print(f"    PID: {proc.pid}")
            print(f"    Name: {proc.info['name']}")
            print(f"    Reason: {reason}")
            print("-" * 40)

if __name__ == "__main__":
    scan_processes()
