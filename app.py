from flask import Flask, request, jsonify
import os

app = Flask(__name__)

# Flag from Railway environment variables
FLAG = os.getenv(
    "FLAG",
    "nullgrids{1d0r_s3rv1c3_4cc0unt}"
)

# Simulated internal user database
USERS = {
    "1": {
        "id": "1",
        "username": "alice",
        "email": "alice@nullgrids.internal",
        "role": "engineer",
        "department": "infra",
        "salary": 95000,
        "internal_notes": "Standard engineer account.",
        "secret": None
    },

    "2": {
        "id": "2",
        "username": "bob",
        "email": "bob@nullgrids.internal",
        "role": "engineer",
        "department": "platform",
        "salary": 102000,
        "internal_notes": "Recently promoted.",
        "secret": None
    },

    "3": {
        "id": "3",
        "username": "charlie",
        "email": "charlie@nullgrids.internal",
        "role": "manager",
        "department": "security",
        "salary": 145000,
        "internal_notes": "Has access to breach report.",
        "secret": None
    },

    "42": {
        "id": "42",
        "username": "deep_thought",
        "email": "ai@nullgrids.internal",
        "role": "bot",
        "department": "sandbox",
        "salary": 0,
        "internal_notes": "Fake flag ahead.",
        "secret": "nullgrids{th1s_1s_4_d3c0y_n0t_th3_r34l_0n3}"
    },

    "77": {
        "id": "77",
        "username": "svc_legacy",
        "email": "legacy@nullgrids.internal",
        "role": "service_account",
        "department": "archived",
        "salary": 0,
        "internal_notes": "Decommissioned 2024.",
        "secret": None
    },

    "99": {
        "id": "99",
        "username": "svc_audit",
        "email": "audit@nullgrids.internal",
        "role": "service_account",
        "department": "internal_audit",
        "salary": 0,
        "internal_notes": "Automated audit service.",
        "secret": FLAG
    }
}

# Simulated API tokens
SESSIONS = {
    "tok_alice_1a2b3c": "1",
    "tok_bob_4d5e6f": "2",
    "tok_charlie_7g8h9i": "3"
}


def get_current_user(req):

    token = req.headers.get(
        "X-Auth-Token",
        ""
    )

    uid = SESSIONS.get(token)

    if not uid:
        return None, None

    return uid, USERS[uid]


@app.route("/")
def index():

    return """
    <html>

    <head>
        <title>NullGrids HR Portal</title>
    </head>

    <body style='font-family:monospace;background:#0a0a0a;color:#00ff88;padding:40px'>

        <h1>NullGrids HR Portal — API v2</h1>

        <p>
            Use your employee token via
            <code>X-Auth-Token</code> header.
        </p>

        <p>Demo tokens:</p>

        <ul>
            <li>
                Alice:
                <code>tok_alice_1a2b3c</code>
            </li>

            <li>
                Bob:
                <code>tok_bob_4d5e6f</code>
            </li>

            <li>
                Charlie:
                <code>tok_charlie_7g8h9i</code>
            </li>
        </ul>

        <p>
            Endpoints:
        </p>

        <ul>
            <li>GET /api/users</li>
            <li>GET /api/profile/&lt;id&gt;</li>
            <li>GET /api/report</li>
        </ul>

    </body>
    </html>
    """


@app.route("/health")
def health():
    return "OK"


@app.route("/api/users")
def list_users():

    uid, user = get_current_user(request)

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    directory = [
        {
            "id": u["id"],
            "username": u["username"],
            "department": u["department"]
        }

        for u in USERS.values()

        if u["role"] != "service_account"
    ]

    return jsonify({
        "employees": directory,
        "total": len(directory)
    })


@app.route("/api/profile/<int:user_id>")
def get_profile(user_id):

    uid, user = get_current_user(request)

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    target = USERS.get(str(user_id))

    if not target:

        return jsonify({
            "error": "User not found"
        }), 404

    # Vulnerable IDOR
    profile = {
        "id": target["id"],
        "username": target["username"],
        "email": target["email"],
        "role": target["role"],
        "department": target["department"],
        "internal_notes": target["internal_notes"]
    }

    # Only managers see salary
    if user["role"] == "manager":
        profile["salary"] = target["salary"]

    # Secret leak vulnerability
    if target["secret"]:
        profile["secret"] = target["secret"]

    return jsonify(profile)


@app.route("/api/report")
def report():

    uid, user = get_current_user(request)

    if not user:

        return jsonify({
            "error": "Unauthorized"
        }), 401

    if user["role"] not in (
        "manager",
        "service_account"
    ):

        return jsonify({
            "error": "Access denied"
        }), 403

    return jsonify({
        "report": "Q1 2026 Security Audit",
        "status": "CLASSIFIED",
        "summary": "3 anomalies detected",
        "note": "Full details restricted"
    })


if __name__ == "__main__":

    port = int(
        os.environ.get("PORT", 8080)
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )
