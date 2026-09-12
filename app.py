"""
app.py
------
Flask application entry point for the Password Strength Analyzer.

SECURITY NOTES FOR THIS FILE:
- No password is ever written to `app.logger`, `print()`, a file, or a
  database. Passwords exist only as local variables inside a single
  request's handling and are discarded once the response is sent.
- The analyze endpoint exists mainly for API-completeness / server-side
  validation; the UI actually performs the real-time analysis in the
  browser with JavaScript (script.js) so keystrokes are NOT sent to the
  server as the user types.
- Basic security headers are added to every response.
- Errors are handled so that stack traces are never shown to the user.
"""

from __future__ import annotations

from flask import Flask, render_template, request, jsonify

from analyzer import analyze_password, DEFAULT_POLICY
from generator import generate_password, generation_options_from_dict, PasswordGenerationError

app = Flask(__name__)

# Reasonable input guardrails, independent of the analyzer's own limits.
MAX_REQUEST_PASSWORD_LENGTH = 256


@app.after_request
def set_security_headers(response):
    """Attach basic security-related HTTP headers to every response.

    These are a reasonable baseline for a small educational app, not an
    exhaustive production security configuration.
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # A conservative Content-Security-Policy: only allow same-origin
    # scripts/styles, since this app ships all of its own JS/CSS and does
    # not load anything from third-party origins.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self'; "
        "img-src 'self'; "
        "connect-src 'self'"
    )
    return response


@app.route("/")
def index():
    return render_template("index.html", policy=DEFAULT_POLICY)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze a password submitted in a JSON body.

    Expected body: {"password": "..."}

    The password value is read once, analyzed, and discarded. It is
    never logged and never included in the JSON response.
    """
    data = request.get_json(silent=True) or {}
    password = data.get("password", "")

    if not isinstance(password, str):
        return jsonify({"error": "Invalid input."}), 400

    if len(password) > MAX_REQUEST_PASSWORD_LENGTH:
        return jsonify({"error": "Password is too long."}), 400

    result = analyze_password(password)
    # Defense in depth: explicitly ensure the original password can never
    # leak into the response, even if the analyzer changes in the future.
    result.pop("password", None)
    return jsonify(result)


@app.route("/api/generate", methods=["POST"])
def api_generate():
    """Generate a secure random password based on the requested options.

    The generated password is returned once in the JSON response and is
    never stored server-side.
    """
    data = request.get_json(silent=True) or {}

    try:
        options = generation_options_from_dict(data)
        password = generate_password(**options)
    except PasswordGenerationError as exc:
        return jsonify({"error": str(exc)}), 400
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid generator configuration."}), 400

    return jsonify({"password": password, "length": len(password)})


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"error": "Not found."}), 404


@app.errorhandler(500)
def server_error(_error):
    # Never expose internal stack traces or exception details to the client.
    return jsonify({"error": "An unexpected error occurred."}), 500


if __name__ == "__main__":
    # debug=False in any environment resembling production; kept False
    # here by default so tracebacks are never shown to end users.
    app.run(debug=False, host="127.0.0.1", port=5000)
