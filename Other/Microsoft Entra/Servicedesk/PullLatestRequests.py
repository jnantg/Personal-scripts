# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SCRIPT                                                              ║
# ║  Name     : PullLatestRequest.py                                     ║
# ║  Version  : 1.0                                                     ║     
# ║  Date     : 2025-08-27                                               ║  
# ║  Author   : Jonathan Neerup-Andersen  ·  jna@ntg.com                 ║
# ║  License  : Free for non-commercial use (no warranty)                ║
# ║  Notes    : Forks welcome. Do whatever you want, be free.            ║
# ╚══════════════════════════════════════════════════════════════════════╝





#!/usr/bin/env python3
# Python 3.8+
# pip install requests

import json
import time
import pathlib
import requests
from typing import Iterator, Dict, Any

# ==== CONFIG ====
BASE_URL   = "https://servicedesk.xxx.com/api/v3/requests"  # on-prem URL
AUTHTOKEN  = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"          # replace
PORTAL_ID  = "1"                                             # replace if needed
ROW_COUNT  = 200                                             # tune for your env
STATE_FILE = pathlib.Path("./.sdp_last_run_ms")
VERIFY_TLS = False                                           # set True when certs fixed
TIMEOUT_S  = 60
MAX_RETRIES = 5

# ==== UTIL ====
def now_epoch_ms() -> int:
    return int(time.time() * 1000)

def load_last_run_ms(default_ago_days: int = 30) -> int:
    if STATE_FILE.exists():
        try:
            return int(STATE_FILE.read_text().strip())
        except Exception:
            pass
    return now_epoch_ms() - default_ago_days * 24 * 3600 * 1000

def save_last_run_ms(ts_ms: int) -> None:
    STATE_FILE.write_text(str(int(ts_ms)))

def backoff_sleep(attempt: int) -> None:
    # 1s, 2s, 4s, 8s, 16s
    time.sleep(min(16, 2 ** attempt))

# ==== CORE ====
def build_list_info(start_index: int, last_run_ms: int) -> Dict[str, Any]:
    # Minimal, fast filter: updated since last run (includes newly created)
    search_criteria = [
        {
            "field": "last_updated_time",
            "condition": "greater than",
            "value": str(last_run_ms)
        }
        # Optional extra belt-and-braces:
        # ,{
        #   "field": "created_time",
        #   "condition": "greater than",
        #   "value": str(last_run_ms),
        #   "logical_operator": "or"
        # }
    ]
    return {
        "list_info": {
            "row_count": ROW_COUNT,
            "start_index": start_index,
            "sort_field": "last_updated_time",
            "sort_order": "asc",
            "get_total_count": True,
            "search_criteria": search_criteria,
            "filter_by": {"name": "All_Requests"}
            # Optionally limit fields to reduce payload:
            # "fields_required": ["id","subject","status","requester","created_time","last_updated_time"]
        }
    }

def paged_request_generator(last_run_ms: int) -> Iterator[Dict[str, Any]]:
    headers = {
        "authtoken": AUTHTOKEN,
        "PORTALID": PORTAL_ID,
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/vnd.manageengine.sdp.v3+json",
    }

    start_index = 1
    while True:
        payload = build_list_info(start_index, last_run_ms)
        params = {"input_data": json.dumps(payload)}
        attempt = 0
        while True:
            try:
                resp = requests.get(
                    BASE_URL,
                    headers=headers,
                    params=params,
                    verify=VERIFY_TLS,
                    timeout=TIMEOUT_S,
                )
                if resp.status_code == 429 and attempt < MAX_RETRIES:
                    attempt += 1
                    backoff_sleep(attempt)
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except requests.RequestException as e:
                if attempt < MAX_RETRIES:
                    attempt += 1
                    backoff_sleep(attempt)
                    continue
                raise RuntimeError(f"API request failed after retries: {e}")

        for r in data.get("requests", []):
            yield r

        li = data.get("list_info", {}) or {}
        has_more = li.get("has_more_rows")
        if not has_more:
            break
        # Next page using start_index stepping (official pagination)
        start_index = int(li.get("start_index", start_index)) + int(li.get("row_count", ROW_COUNT))

def main():
    last_run_ms = load_last_run_ms()
    print(f"[sdp] Fetching requests with last_updated_time > {last_run_ms} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(last_run_ms/1000))} UTC)")

    fetched = 0
    # Stream to stdout as JSON Lines (easy to ingest), and collect latest seen watermark as we go
    latest_seen_ms = last_run_ms

    for req in paged_request_generator(last_run_ms):
        # Track newest last_updated_time to advance watermark only after full success
        lut = int(req.get("last_updated_time", {}).get("value", 0) or
                  req.get("last_updated_time", 0) or 0)
        # Some builds return plain long, others {"display_value": "...", "value": "ms"}
        if lut == 0 and isinstance(req.get("last_updated_time"), dict):
            lut = int(req["last_updated_time"].get("value") or 0)
        latest_seen_ms = max(latest_seen_ms, lut)

        print(json.dumps(req, ensure_ascii=False))
        fetched += 1

    # Move watermark forward to "now" to avoid reprocessing items edited mid-run.
    # If you prefer exactly latest_seen_ms, swap the variable.
    new_watermark = now_epoch_ms()
    save_last_run_ms(new_watermark)

    print(f"[sdp] Done. Fetched {fetched} requests. Watermark advanced to {new_watermark} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(new_watermark/1000))} UTC)")

if __name__ == "__main__":
    main()
