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

def run_phishstats_scraper():
    """Polls PhishStats API every 90 minutes."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] ****** Starting PhishStats scraper ******")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    api_key = get_api_key()
    if not api_key:
        print("Skipping PhishStats cycle due to missing API key", file=sys.stderr)
        return

    cmd = [
        sys.executable,
        "-u",
        "1-scrape.py",
        "--phishing-sources",
        "phishstats",
        "--phishstats-key",
        api_key,
        "--skip-legit",
    ]

    try:
        subprocess.run(cmd, check=True)
        done_time = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{done_time}] ****** PhishStats scrape completed successfully ******")
    except subprocess.CalledProcessError as e:
        print(f"[Error] 1-scrape.py failed in PhishStats cycle with exit code {e.returncode}", file=sys.stderr)
    except Exception as e:
        print(f"[Error] Failed to execute PhishStats scraper: {e}", file=sys.stderr)

def run_openphish_scraper():
    """Polls OpenPhish feed every 12 hours."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{now}] ****** Starting OpenPhish scraper ******")

    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    cmd = [
        sys.executable,
        "-u",
        "1-scrape.py",
        "--target-per-class",
        "300",
        "--phishing-sources",
        "openphish",
        "--skip-legit",
    ]

    try:
        subprocess.run(cmd, check=True)
        done_time = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{done_time}] ****** OpenPhish scrape completed successfully ******")
    except subprocess.CalledProcessError as e:
        print(f"[Error] 1-scrape.py failed in OpenPhish cycle with exit code {e.returncode}", file=sys.stderr)
    except Exception as e:
        print(f"[Error] Failed to execute OpenPhish scraper: {e}", file=sys.stderr) 

if __name__ == "__main__":
    run_phishstats_scraper()
    run_openphish_scraper()
    print("[Status] Scheduler is active. Exit using 'Ctr+C'")

    # schedule recurring jobs
    schedule.every(90).minutes.do(run_phishstats_scraper)
    schedule.every(12).hours.do(run_openphish_scraper)

    print("[Status] Scheduler active. PhishStats: every 90 mins | OpenPhish: every 12 hours.")
    print("[Status] Exit using 'Ctrl+C'")

    while True:
        schedule.run_pending()
        time.sleep(2)