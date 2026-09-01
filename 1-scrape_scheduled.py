"""
This script schedules the scraper to run every 2 hours
to scrape from sources that refresh their feeds every ~90 minutes
such as PhishStats and OpenPhish

"""

import os
import sys
import time
import schedule
import subprocess

def get_api_key():
    """
    Retrives phishstats api key
    """
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        key_path = os.path.join(script_dir, "phishstats.key")
        with open(key_path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        print("[Error]: 'phishstats.key' file not found in the script directory", file=sys.stderr)
        return None

def run_scraper():
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] ****** Starting scraper ******")

    # force the working dir to this file's folder
    # to save output correctly
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    api_key = get_api_key()
    if not api_key:
        print("Skipping this cycle due to missing API key", file=sys.stderr)
        return

    # required commands to inject
    cmd = [
        sys.executable,
        "-u",
        "1-scrape.py",
        "--target-per-class",
        "300",
        "--phishing-sources",
        "openphish",
        "phishstats",
        "--phishstats-key",
        api_key,
    ]

    try:
        result = subprocess.run(cmd, check=True)
        done_time = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{done_time}] ****** Srape completed successfully")
    except subprocess.CalledProcessError as e:
        print(f"[Error] 1-scrape.py failed with exit code {e}", file=sys.stderr)
    except Exception as e:
        print(f"[Error] Failed to execute scraper {e}", file=sys.stderr)

if __name__ == "__main__":
    run_scraper()
    schedule.every(2).hours.do(run_scraper)
    print("[Status] Scheduler is active. Exit using 'Ctr+C'")

    while True:
        schedule.run_pending()
        time.sleep(1)