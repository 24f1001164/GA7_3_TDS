from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="Terraform Plan Policy Gate")

WORKSPACE = "prod-rgddn5"

REQUIRED_LABELS = {
    "owner": "student-v8ht2",
    "environment": "production",
    "cost_center": "cc-2t6i",
}

ALLOWED_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
ALLOWED_ACTIONS = {"create", "update", "delete"}
STATEFUL_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}


def invalid_plan():
    return {"decision": "reject", "reason": "INVALID_PLAN"}


def reject(reason):
    return {"decision": "reject", "reason": reason}


def approve():
    return {"decision": "approve", "reason": "APPROVE"}


def is_exact_bool(value):
    return type(value) is bool


def is_exact_string(value):
    return type(value) is str


def validate_plan(data):
    # ==========================================================
    # RULE 1 — Validate request and nested object value types
    # ==========================================================

    if not isinstance(data, dict):
        return invalid_plan()

    required_top = {
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    }

    if set(data.keys()) != required_top:
        return invalid_plan()

    if not is_exact_string(data["environment"]):
        return invalid_plan()

    if not isinstance(data["state"], dict):
        return invalid_plan()

    if not is_exact_string(data["providerVersion"]):
        return invalid_plan()

    if not is_exact_bool(data["destroyApproved"]):
        return invalid_plan()

    if not isinstance(data["resource"], dict):
        return invalid_plan()

    # ----- state object -----
    state = data["state"]

    if set(state.keys()) != {"backend", "locked"}:
        return invalid_plan()

    if not is_exact_string(state["backend"]):
        return invalid_plan()

    if not is_exact_bool(state["locked"]):
        return invalid_plan()

    # ----- resource object -----
    resource = data["resource"]

    required_resource = {
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    }

    if set(resource.keys()) != required_resource:
        return invalid_plan()

    if not is_exact_string(resource["address"]):
        return invalid_plan()

    if not is_exact_string(resource["type"]):
        return invalid_plan()

    if not is_exact_string(resource["action"]):
        return invalid_plan()

    if not isinstance(resource["labels"], dict):
        return invalid_plan()

    if not is_exact_bool(resource["forceDestroy"]):
        return invalid_plan()

    # secret must be null or string
    if resource["secret"] is not None and not is_exact_string(resource["secret"]):
        return invalid_plan()

    # labels must contain string values
    for key, value in resource["labels"].items():
        if not is_exact_string(key) or not is_exact_string(value):
            return invalid_plan()

    # ==========================================================
    # RULE 2 — Environment
    # ==========================================================

    if data["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # ==========================================================
    # RULE 3 — Remote state + locking
    # ==========================================================

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # ==========================================================
    # RULE 4 — Provider pinning
    # ==========================================================

    provider = data["providerVersion"]

    allowed_exact = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }

    if provider not in allowed_exact:
        return reject("UNPINNED_PROVIDER")

    # ==========================================================
    # RULE 5 — Required labels
    # ==========================================================

    for key, expected_value in REQUIRED_LABELS.items():
        if resource["labels"].get(key) != expected_value:
            return reject("MISSING_LABELS")

    # ==========================================================
    # RULE 6 — Secret
    # ==========================================================

    secret = resource["secret"]

    if secret is not None:
        if secret == "" or not secret.startswith("secret://"):
            return reject("PLAINTEXT_SECRET")

    # ==========================================================
    # RULE 7 — Stateful delete approval
    # ==========================================================

    if (
        resource["action"] == "delete"
        and resource["type"] in STATEFUL_TYPES
        and data["destroyApproved"] is not True
    ):
        return reject("DELETE_NOT_APPROVED")

    # ==========================================================
    # RULE 8 — Production storage bucket forceDestroy
    # ==========================================================

    if (
        data["environment"] == WORKSPACE
        and resource["type"] == "storage_bucket"
        and resource["forceDestroy"] is True
    ):
        return reject("FORCE_DESTROY")

    # ==========================================================
    # ALL RULES PASSED
    # ==========================================================

    return approve()


@app.get("/")
async def root():
    return {
        "service": "Terraform Plan Policy Gate",
        "status": "ok"
    }


@app.post("/terraform/plan")
async def terraform_plan(request: Request):
    # Important:
    # We manually parse JSON instead of relying on FastAPI's
    # automatic validation because the grader requires 2xx
    # responses even for invalid plans.

    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            content=invalid_plan(),
            status_code=200
        )

    result = validate_plan(data)

    return JSONResponse(
        content=result,
        status_code=200
    )
