import os, requests
BACKEND = "http://127.0.0.1:8200"
r = requests.post(f"{BACKEND}/api/v1/auth/login",
                  json={"username": "msecops", "password": "admin-pass"}, timeout=10)
print("login:", r.status_code)
tok = r.json()["access_token"]; H = {"Authorization": f"Bearer {tok}"}

os.environ["MLFLOW_TRACKING_URI"] = f"{BACKEND}/mlflow"
os.environ["MLFLOW_TRACKING_TOKEN"] = tok
os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "10")
import mlflow
mlflow.set_experiment("diag_experiment")
with mlflow.start_run(run_name="diag_run") as run:
    mlflow.log_param("p", 1); mlflow.log_metric("acc", 0.9)
    rid = run.info.run_id
print("logged run:", rid)

mr = requests.get(f"{BACKEND}/api/v1/mlflow/runs?limit=50", headers=H, timeout=30).json()
print("GET /mlflow/runs count =", len(mr.get("runs", [])))
for x in mr.get("runs", [])[:5]:
    print("   run", x["run_id"][:8], "owner=", x.get("owner"), "exp=", x.get("experiment"))

reg = requests.get(f"{BACKEND}/api/v1/registry", headers=H, timeout=30).json()
print("GET /registry artifacts =", len(reg.get("artifacts", [])), "zones =", reg.get("zones"))
for a in reg.get("artifacts", [])[:5]:
    print("   art", a["run_id"][:8], "owner=", a.get("owner"), "zone=", a.get("zone"),
          "check=", a.get("check_status"))

art = requests.get(f"{BACKEND}/api/v1/artifacts", headers=H, timeout=30).json()
print("GET /artifacts mine =", len(art.get("mine", [])), "shared =", len(art.get("shared_with_me", [])))
print("DIAG_DONE")
