import os, csv, requests
from msal import ConfidentialClientApplication

TENANT_ID = os.getenv("TENANT_ID")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPE = ["https://graph.microsoft.com/.default"]
GRAPH = "https://graph.microsoft.com/v1.0"

app = ConfidentialClientApplication(
    client_id=CLIENT_ID,
    client_credential=CLIENT_SECRET,
    authority=AUTHORITY,
)

result = app.acquire_token_silent(SCOPE, account=None)
if not result:
    result = app.acquire_token_for_client(scopes=SCOPE)
if "access_token" not in result:
    raise SystemExit(f"Auth failed: {result}")

headers = {"Authorization": f"Bearer {result['access_token']}"}
select = "id,displayName,userPrincipalName,mail,jobTitle,department,accountEnabled"
url = f"{GRAPH}/users?$select={select}&$top=999"

all_users = []
while url:
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    data = resp.json()
    all_users.extend(data.get("value", []))
    url = data.get("@odata.nextLink")

# Write CSV
with open("entra_users.csv", "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["id","displayName","userPrincipalName","mail","jobTitle","department","accountEnabled"]
    )
    writer.writeheader()
    for u in all_users:
        writer.writerow({k: u.get(k, "") for k in writer.fieldnames})

print(f"Exported {len(all_users)} users to entra_users.csv")
