"""src/gates/ — Security Gates G0–G7. ОДИН гейт = ОДНА папка.

Единый контракт (docs/07_SECURITY_GATES.md §7.1):
  gate_check(target, ...) -> list[dict]  # {"check","status":PASS|FAIL|SKIP,"detail","evidence"?}
  build_report(target, results) -> dict  # {"gate","asset","passed","checks","failed_checks"}
  main()  # argparse, печать JSON в stdout, sys.exit(0|1)

Гейт САМ в БД не пишет — findings/events пишет оркестратор (ingest / Gatekeeper).
Каждый гейт собирается в свой Docker-образ mlsec-gate-<name>.
"""
