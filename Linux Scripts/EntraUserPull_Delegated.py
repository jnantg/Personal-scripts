# EntraUserPull_Delegated.py
import os, csv, requests, msal, pathlib
from msal_extensions import PersistedTokenCache, build_encrypted_persistence, FilePersistence

TENANT_ID = os.getenv("TENANT_ID")
AUTHORITY  = f"https://login.microsoftonline.com/{TENANT_ID}"
CLIENT_ID = os.getenv("CLIENT_ID")
SCOPES = ["User.Read.All"]  # or ["User.ReadBasic.All"]
GRAPH = "https://graph.microsoft.com/v1.0"
ONLY_LICENSED = os.getenv("ONLY_LICENSED") == "1"  # optional

def token_cache():
    cache_dir = pathlib.Path(os.getenv("LOCALAPPDATA", pathlib.Path.home())) / "EntraUserPull"
    cache_dir.mkdir(parents=True, exist_ok=True)
    path = str(cache_dir / "msal_cache.bin")
    try:
        persistence = build_encrypted_persistence(path)
    except Exception:
        if os.getenv("ALLOW_PLAINTEXT_CACHE") == "1":
            persistence = FilePersistence(path)
        else:
            raise
    return PersistedTokenCache(persistence)

app = msal.PublicClientApplication(CLIENT_ID, authority=AUTHORITY, token_cache=token_cache())
acct = next(iter(app.get_accounts()), None)
result = app.acquire_token_silent(SCOPES, account=acct)
if not result:
    flow = app.initiate_device_flow(scopes=SCOPES)
    if "user_code" not in flow:
        raise SystemExit(f"Device code start failed: {flow.get('error')} - {flow.get('error_description')}")
    print(flow["message"])
    result = app.acquire_token_by_device_flow(flow)
if "access_token" not in result:
    raise SystemExit(f"Auth failed: {result}")

headers = {"Authorization": f"Bearer {result['access_token']}"}
params = {
    "$select": "id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled,userType",
    "$top": "999",
    # Exclude shared/room/equipment (disabled) and guests:
    "$filter": "accountEnabled eq true and userType eq 'Member'",
}
if ONLY_LICENSED:
    # Return only users with at least one license
    headers["ConsistencyLevel"] = "eventual"
    params["$count"] = "true"
    params["$filter"] += " and assignedLicenses/$count ne 0"

all_users = []
url = f"{GRAPH}/users"
while url:
    r = requests.get(url, headers=headers, params=params if url.endswith("/users") else None, timeout=30)
    r.raise_for_status()
    data = r.json()
    all_users.extend(data.get("value", []))
    url = data.get("@odata.nextLink", None)  # nextLink already contains encoded params

with open("entra_users.csv", "w", newline="", encoding="utf-8") as f:
    fields = ["id","displayName","userPrincipalName","mail","jobTitle","department","accountEnabled","userType"]
    w = csv.DictWriter(f, fieldnames=fields)
    w.writeheader()
    for u in all_users:
        w.writerow({k: u.get(k, "") for k in fields})

print(f"Exported {len(all_users)} active member users to entra_users.csv")