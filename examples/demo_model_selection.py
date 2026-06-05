import os
import tempfile
from pathlib import Path

import matplotlib.pyplot as plt
import mlflow
import mlflow.sklearn
import numpy as np
import requests
from sklearn.datasets import load_iris
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import ConfusionMatrixDisplay, accuracy_score, auc, roc_curve
from sklearn.model_selection import GridSearchCV, learning_curve, train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler, label_binarize

os.environ.setdefault("MLFLOW_HTTP_REQUEST_TIMEOUT", "15")
os.environ.setdefault("MLFLOW_HTTP_REQUEST_MAX_RETRIES", "2")

def login() -> str:
    r = requests.post(
        f"{BACKEND}/api/v1/auth/login",
        json={"username": DEV_USER, "password": DEV_PASSWORD},
        timeout=10,
    )
    if r.status_code != 200:
        raise SystemExit(f"[ERROR] login: {r.status_code} {r.text}")
    print(f"[ok] logged in as {DEV_USER}")
    return r.json()["access_token"]


def plot_confusion(clf, X_te, y_te, labels, path: Path) -> None:
    fig, ax = plt.subplots(figsize=(5, 4))
    ConfusionMatrixDisplay.from_estimator(clf, X_te, y_te, display_labels=labels, ax=ax)
    ax.set_title("Confusion Matrix (best model)")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_roc(clf, X_te, y_te, n_classes: int, path: Path) -> None:
    y_bin = label_binarize(y_te, classes=list(range(n_classes)))
    proba = clf.predict_proba(X_te)

    fig, ax = plt.subplots(figsize=(5, 4))
    for i in range(n_classes):
        fpr, tpr, _ = roc_curve(y_bin[:, i], proba[:, i])
        ax.plot(fpr, tpr, label=f"class {i}  AUC={auc(fpr, tpr):.2f}")
    ax.plot([0, 1], [0, 1], "k--")
    ax.set(xlabel="FPR", ylabel="TPR", title="ROC OvR (best model)")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


def plot_learning(clf_cls, params: dict, X, y, path: Path) -> None:
    sizes, tr_scores, val_scores = learning_curve(
        clf_cls(**params), X, y,
        cv=5, scoring="accuracy",
        train_sizes=np.linspace(0.2, 1.0, 6),
    )
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.plot(sizes, tr_scores.mean(1),  label="train")
    ax.plot(sizes, val_scores.mean(1), label="val")
    ax.fill_between(sizes, tr_scores.mean(1) - tr_scores.std(1),
                           tr_scores.mean(1) + tr_scores.std(1), alpha=0.15)
    ax.fill_between(sizes, val_scores.mean(1) - val_scores.std(1),
                           val_scores.mean(1) + val_scores.std(1), alpha=0.15)
    ax.set(xlabel="Train size", ylabel="Accuracy", title="Learning curve (best model)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


DEV_USER     = os.getenv("DEV_USER",       "kolya1")
DEV_PASSWORD = os.getenv("DEV_PASSWORD",   "123")
BACKEND      = os.getenv("GATEKEEPER_URL", "http://localhost:8200")
EXPERIMENT   = f"{DEV_USER}_model_selection"

token = login()
os.environ["MLFLOW_TRACKING_URI"]   = f"{BACKEND}/mlflow"
os.environ["MLFLOW_TRACKING_TOKEN"] = token

def main() -> None:    
    iris = load_iris(as_frame=True)
    X, y = iris.data, iris.target
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.25, stratify=y, random_state=42)

    mlflow.set_experiment(EXPERIMENT)

    candidates = {
        "logreg": make_pipeline(StandardScaler(), LogisticRegression(max_iter=500)),
        "knn":    make_pipeline(StandardScaler(), KNeighborsClassifier()),
        "rf":     RandomForestClassifier(n_estimators=50, random_state=42),
    }

    scores: dict[str, float] = {}
    print("\n=== Шаг 1: сравнение моделей ===")
    with mlflow.start_run(run_name="model_comparison"):
        for name, clf in candidates.items():
            clf.fit(X_tr, y_tr)
            acc = accuracy_score(y_te, clf.predict(X_te))
            scores[name] = acc
            mlflow.log_metric(f"val_acc_{name}", acc)
            print(f"  {name:8s}  acc={acc:.3f}")

    best_name = max(scores, key=scores.__getitem__)
    print(f"\n  >>> Лучшая: {best_name}  ({scores[best_name]:.3f})")

    param_grids = {
        "logreg": {"logisticregression__C": [0.01, 0.1, 1.0, 10.0]},
        "knn":    {"kneighborsclassifier__n_neighbors": [3, 5, 7, 11]},
        "rf":     {"n_estimators": [50, 100, 200], "max_depth": [None, 5, 10]},
    }

    print("\n=== Шаг 2: GridSearchCV ===")
    grid = GridSearchCV(candidates[best_name], param_grids[best_name], cv=5, scoring="accuracy", refit=True)
    grid.fit(X_tr, y_tr)
    best_clf = grid.best_estimator_
    best_acc = accuracy_score(y_te, best_clf.predict(X_te))
    print(f"  best_params={grid.best_params_}")
    print(f"  val_acc (after tuning)={best_acc:.3f}")

    print("\n=== Шаг 3: логируем финальный ран ===")
    with mlflow.start_run(run_name=f"best_{best_name}_tuned") as run:
        mlflow.log_params({"model": best_name, **grid.best_params_})
        mlflow.log_metrics({"val_acc": best_acc, "cv_best_score": grid.best_score_})
        mlflow.set_tags({
            "mlflow.user": DEV_USER,
            "security.data_source_type": "local",
            "security.dataset_origin": "sklearn.datasets.load_iris",
        })

        with tempfile.TemporaryDirectory() as tmp:
            tmp_p = Path(tmp)
            plot_confusion(best_clf, X_te, y_te, iris.target_names, tmp_p / "confusion.png")
            plot_roc(best_clf, X_te, y_te, n_classes=3, path=tmp_p / "roc.png")
            if best_name == "rf":
                plot_learning(RandomForestClassifier, grid.best_params_,
                              X.values, y.values, tmp_p / "learning_curve.png")
            for png in tmp_p.glob("*.png"):
                mlflow.log_artifact(str(png))
                print(f"  logged {png.name}")

        try:
            mlflow.sklearn.log_model(best_clf, name="model", registered_model_name=f"best_{best_name}")
        except TypeError:
            mlflow.sklearn.log_model(best_clf, artifact_path="model", registered_model_name=f"best_{best_name}")

        print(f"\n[ok] run_id={run.info.run_id}  acc={best_acc:.3f}")
        print(f"     experiment={EXPERIMENT}")


if __name__ == "__main__":
    main()
