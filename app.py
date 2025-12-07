import os
import json
import urllib.parse
import urllib.request

from flask import Flask, request, redirect, make_response

app = Flask(__name__)

GOOGLE_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
GOOGLE_TOKENINFO_ENDPOINT = "https://oauth2.googleapis.com/tokeninfo"

CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")


def build_redirect_uri():
    """
    Redirect URI Google will send the user back to.
    We read it from env so it matches GCP config exactly.
    """
    return os.environ.get("GOOGLE_REDIRECT_URI")


@app.route("/")
def index():
    return (
        "<html><body>"
        "<h1>TripSpark Auth</h1>"
        "<p><a href=\"/login\">Login with Google</a></p>"
        "</body></html>"
    )


@app.route("/login")
def login():
    if not CLIENT_ID:
        return "GOOGLE_CLIENT_ID not set", 500

    redirect_uri = build_redirect_uri()
    if not redirect_uri:
        return "GOOGLE_REDIRECT_URI not set", 500

    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "consent",
    }

    auth_url = GOOGLE_AUTH_ENDPOINT + "?" + urllib.parse.urlencode(params)
    return redirect(auth_url)


@app.route("/oauth2/callback")
def oauth2_callback():
    error = request.args.get("error")
    if error:
        return f"Error from Google: {error}", 400

    code = request.args.get("code")
    if not code:
        return "Missing 'code' parameter", 400

    if not CLIENT_ID or not CLIENT_SECRET:
        return "Client ID/Secret not configured", 500

    redirect_uri = build_redirect_uri()
    if not redirect_uri:
        return "GOOGLE_REDIRECT_URI not set", 500

    # Exchange code for tokens
    data = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }

    encoded_data = urllib.parse.urlencode(data).encode("utf-8")
    token_req = urllib.request.Request(
        GOOGLE_TOKEN_ENDPOINT,
        data=encoded_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )

    try:
        with urllib.request.urlopen(token_req) as resp:
            token_response = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return f"Error exchanging code for tokens: {e}", 500

    id_token = token_response.get("id_token")
    if not id_token:
        return f"No id_token in token response: {token_response}", 500

    # Decode id_token using tokeninfo endpoint
    tokeninfo_url = GOOGLE_TOKENINFO_ENDPOINT + "?" + urllib.parse.urlencode(
        {"id_token": id_token}
    )

    try:
        with urllib.request.urlopen(tokeninfo_url) as resp:
            user_info = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        return f"Error calling tokeninfo: {e}", 500

    email = user_info.get("email", "unknown")
    sub = user_info.get("sub", "unknown")

    html = f"""
    <html>
      <body>
        <h1>Logged in with Google</h1>
        <p><b>Email:</b> {email}</p>
        <p><b>Sub (Google user ID):</b> {sub}</p>
        <h2>Raw user info</h2>
        <pre>{json.dumps(user_info, indent=2)}</pre>
      </body>
    </html>
    """
    resp = make_response(html)
    resp.headers["Content-Type"] = "text/html"
    return resp


if __name__ == "__main__":
    # For local testing 
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
