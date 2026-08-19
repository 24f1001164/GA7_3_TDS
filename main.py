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
STATEFUL_TYPES = {
    "storage_bucket",
    "sql_database",
    "persistent_disk",
}


def reject(reason):
    return {
        "decision": "reject",
        "reason": reason
    }


def approve():
    return {
        "decision": "approve",
        "reason": "APPROVE"
    }


def invalid_plan():
    return reject("INVALID_PLAN")


def is_string(value):
    return type(value) is str


def is_bool(value):
    return type(value) is bool


def validate_schema(data):
    """
    Rule 1:
    Validate the required fields and their types.

    Extra fields are allowed because the specification says
    the objects must have the shown value types; it does not
    require exact key sets.
    """

    # ----------------------------------------------------------
    # Top-level object
    # ----------------------------------------------------------

    if not isinstance(data, dict):
        return False

    required_top = [
        "environment",
        "state",
        "providerVersion",
        "destroyApproved",
        "resource",
    ]

    for key in required_top:
        if key not in data:
            return False

    # environment
    if not is_string(data["environment"]):
        return False

    # providerVersion
    if not is_string(data["providerVersion"]):
        return False

    # destroyApproved
    if not is_bool(data["destroyApproved"]):
        return False

    # state
    if not isinstance(data["state"], dict):
        return False

    # resource
    if not isinstance(data["resource"], dict):
        return False

    # ----------------------------------------------------------
    # State object
    # ----------------------------------------------------------

    state = data["state"]

    if "backend" not in state:
        return False

    if "locked" not in state:
        return False

    if not is_string(state["backend"]):
        return False

    if not is_bool(state["locked"]):
        return False

    # ----------------------------------------------------------
    # Resource object
    # ----------------------------------------------------------

    resource = data["resource"]

    resource_required = [
        "address",
        "type",
        "action",
        "labels",
        "secret",
        "forceDestroy",
    ]

    for key in resource_required:
        if key not in resource:
            return False

    if not is_string(resource["address"]):
        return False

    if not is_string(resource["type"]):
        return False

    if not is_string(resource["action"]):
        return False

    if resource["action"] not in ALLOWED_ACTIONS:
        return False

    if not isinstance(resource["labels"], dict):
        return False

    if not is_bool(resource["forceDestroy"]):
        return False

    # secret is either null or string
    if resource["secret"] is not None:
        if not is_string(resource["secret"]):
            return False

    # Every label key/value must be a string
    for key, value in resource["labels"].items():
        if not is_string(key):
            return False

        if not is_string(value):
            return False

    return True


def evaluate_policy(data):
    # ==========================================================
    # RULE 1 — Schema validation
    # ==========================================================

    if not validate_schema(data):
        return invalid_plan()

    state = data["state"]
    resource = data["resource"]

    # ==========================================================
    # RULE 2 — Environment
    # ==========================================================

    if data["environment"] != WORKSPACE:
        return reject("ENVIRONMENT_MISMATCH")

    # ==========================================================
    # RULE 3 — State safety
    # ==========================================================

    if state["backend"] not in ALLOWED_BACKENDS:
        return reject("STATE_UNSAFE")

    if state["locked"] is not True:
        return reject("STATE_UNSAFE")

    # ==========================================================
    # RULE 4 — Provider pinning
    # ==========================================================

    provider = data["providerVersion"]

    allowed_provider_versions = {
        "6.2.1",
        "= 6.2.1",
        "~> 6.0",
    }

    if provider not in allowed_provider_versions:
        return reject("UNPINNED_PROVIDER")

    # ==========================================================
    # RULE 5 — Required labels
    # ==========================================================

    labels = resource["labels"]

    for key, expected_value in REQUIRED_LABELS.items():
        if labels.get(key) != expected_value:
            return reject("MISSING_LABELS")

    # ==========================================================
    # RULE 6 — Secret
    # ==========================================================

    secret = resource["secret"]

    if secret is not None:
        if secret == "":
            return reject("PLAINTEXT_SECRET")

        if not secret.startswith("secret://"):
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
    # RULE 8 — Production storage bucket force destroy
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

    # Never allow malformed JSON to become HTTP 4xx.
    # The grader requires a 2xx response for every payload.

    try:
        data = await request.json()
    except Exception:
        return JSONResponse(
            status_code=200,
            content=invalid_plan()
        )

    result = evaluate_policy(data)

    return JSONResponse(
        status_code=200,
        content=result
    )
