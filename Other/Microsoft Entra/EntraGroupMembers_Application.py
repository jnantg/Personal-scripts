# ╔══════════════════════════════════════════════════════════════════════╗
# ║  SCRIPT                                                              ║
# ║  Name     : EntraUserPull_GroupMembers.py                            ║
# ║  Version  : 1.0                                                      ║
# ║  Date     : 2025-09-02                                               ║
# ║  Author   : Jonathan Neerup-Andersen  ·  jna@ntg.com                 ║
# ║  License  : Free for non-commercial use (no warranty)                ║
# ║  Notes    : Pull only active users from a specific Entra group       ║
# ╚══════════════════════════════════════════════════════════════════════╝

import os, csv, requests

from msal import ConfidentialClientApplication

# ── Configuration ──────────────────────────────────────────────────────
# Set these env vars: TENANT_ID, CLIENT_ID, CLIENT_SECRET
GROUP_NAME = os.getenv("GROUP_NAME", "DK-TEST-GROUP-01")  #Single entry or comma seperated list to pull users from multiple groups
INCLUDE_TRANSITIVE = True  # True = include nested group users
OUTPUT_FILE = f"entra_users_{GROUP_NAME}.csv"

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
    raise SystemExit("Missing required env vars: TENANT_ID, CLIENT_ID, CLIENT_SECRET")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH = "https://graph.microsoft.com/v1.0"

# ── Auth ───────────────────────────────────────────────────────────────
app = ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=AUTHORITY,
)
result = app.acquire_token_silent(SCOPE, account=None) or app.acquire_token_for_client(scopes=SCOPE)
if "access_token" not in result:
    raise SystemExit(f"Auth failed: {result}")

headers = {"Authorization": f"Bearer {result['access_token']}"}

# ── Helpers ────────────────────────────────────────────────────────────
def _odata_escape(value: str) -> str:
    # OData single quotes are escaped by doubling them
    return value.replace("'", "''")

def _paged_get(url: str):
    while url:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        yield from data.get("value", [])
        url = data.get("@odata.nextLink")

# ── Resolve group by displayName (exact match) ─────────────────────────
escaped = _odata_escape(GROUP_NAME)
group_search_url = f"{GRAPH}/groups?$select=id,displayName&$filter=displayName eq '{escaped}'&$top=999"

matches = list(_paged_get(group_search_url))
if not matches:
    raise SystemExit(f"No group found with displayName = '{GROUP_NAME}'")
if len(matches) > 1:
    ids = ", ".join(g['id'] for g in matches)
    raise SystemExit(
        f"Multiple groups found with displayName = '{GROUP_NAME}'. "
        f"Be explicit. Candidate IDs: {ids}"
    )

group_id = matches[0]["id"]

# ── Pull users from the group (optionally transitive) ──────────────────
select = "id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled"
members_path = "transitiveMembers" if INCLUDE_TRANSITIVE else "members"
# Cast to only users to avoid devices/SPNs/groups
url = f"{GRAPH}/groups/{group_id}/{members_path}/microsoft.graph.user?$select={select}&$top=999"

users = []
for u in _paged_get(url):
    # Keep only active users
    if u.get("accountEnabled") is True:
        users.append(u)

# ── Export CSV ─────────────────────────────────────────────────────────
fieldnames = ["id","displayName","userPrincipalName","mail","jobTitle","department","accountEnabled"]
with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=fieldnames)
    writer.writeheader()
    for u in users:
        writer.writerow({k: u.get(k, "") for k in fieldnames})

print(f"Group: {GROUP_NAME} ({group_id})")
print(f"Active users exported: {len(users)}")
print(f"File: {OUTPUT_FILE}")
