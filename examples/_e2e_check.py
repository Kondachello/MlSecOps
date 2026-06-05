"""Временный e2e-чек новых фич (НЕ для прода). Требует поднятый backend :8200 + MLflow :5000."""
import os, requests
B="http://127.0.0.1:8200"
def login(u,p): return requests.post(f"{B}/api/v1/auth/login",json={"username":u,"password":p}).json()["access_token"]
AD={"Authorization":f"Bearer {login('msecops','admin-pass')}"}

# 1) health
print("health:", requests.get(f"{B}/api/v1/mlflow/health",headers=AD).json().get("ok"))

# 2) log a FRAUD run through proxy (HIGH tier) -> versioning-like
os.environ["MLFLOW_TRACKING_URI"]=f"{B}/mlflow"; os.environ["MLFLOW_TRACKING_TOKEN"]=login('msecops','admin-pass')
os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT","15")
import mlflow
mlflow.set_experiment("fraud_scoring")
with mlflow.start_run(run_name="fraud_v1") as run:
    mlflow.log_param("C",1.0); mlflow.log_metric("accuracy",0.97)
    mlflow.set_tags({"model.name":"fraud_model","model.description":"кредитный скоринг"})
    rid=run.info.run_id
print("logged fraud run", rid[:8])

# 3) manual upload (no experiment tie)
r=requests.post(f"{B}/api/v1/artifacts/manual",headers=AD,params={"name":"external_blob","description":"вручную"})
print("manual upload:", r.status_code, r.json().get("run_id","")[:8])

# 4) security check on fraud run -> HIGH tier
r=requests.post(f"{B}/api/v1/artifacts/{rid}/check",headers=AD).json()
print("check:", r.get("check_status"), "tier:", r.get("tier"))

# 5) deploy HIGH -> pending_approve, appears in pending queue
print("deploy:", requests.post(f"{B}/api/v1/artifacts/{rid}/deploy",headers=AD,json={"reason":"go"}).json().get("stage"))
print("pending queue:", [a["run_id"][:8] for a in requests.get(f"{B}/api/v1/approvals/pending",headers=AD).json()["pending"]])

# 6) approve (HITL) -> approved, promote -> prod
print("approve:", requests.post(f"{B}/api/v1/artifacts/{rid}/approve",headers=AD,json={"reason":"ok"}).json().get("stage"))
print("promote:", requests.post(f"{B}/api/v1/artifacts/{rid}/promote",headers=AD,json={"reason":"prod"}).json().get("stage"))

# 7) monitoring/models shows it with inference placeholder + model card
mon=requests.get(f"{B}/api/v1/monitoring/models",headers=AD).json()["models"]
me=[m for m in mon if m["run_id"]==rid]
if me: print("monitoring:", me[0]["model_name"], me[0]["model_description"], "inf:", me[0]["inference_metrics"]["p95_latency_ms"],"ms, zone",me[0]["zone"])

# 8) rollback prod -> previous, then restore -> prod
print("rollback:", requests.post(f"{B}/api/v1/artifacts/{rid}/rollback",headers=AD,json={"reason":"rb"}).json().get("stage"))
print("restore:", requests.post(f"{B}/api/v1/artifacts/{rid}/restore",headers=AD,json={"reason":"rs"}).json().get("stage"))

# 9) registry zones + incidents
reg=requests.get(f"{B}/api/v1/registry",headers=AD).json()
print("registry zones:", reg.get("zones"))
print("incidents:", len(requests.get(f"{B}/api/v1/findings",headers=AD).json()["findings"]))
print("E2E_OK")
