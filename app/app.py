from flask import Flask, redirect, url_for, session, render_template_string, jsonify, request
from authlib.integrations.flask_client import OAuth
from dotenv import load_dotenv
import requests
import os
from functools import wraps
import base64
import json

load_dotenv()
app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

oauth = OAuth(app)
oauth.register(
    name="keycloak",
    client_id=os.getenv("KEYCLOAK_CLIENT_ID"),
    client_secret=os.getenv("KEYCLOAK_CLIENT_SECRET"),
    server_metadata_url=os.getenv("KEYCLOAK_SERVER_METADATA_URL"),
    client_kwargs={"scope": "openid profile email", "verify": False},
)

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = session.get("user")
            if not user:
                return redirect(url_for("private"))
            if "roles" not in user or role not in user["roles"]:
                return jsonify(message="You do not have the required role to access this resource."), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def root():
    return redirect(url_for("home"))

@app.route('/home')
def home():
    return jsonify(message="Welcome to the Home Page!")

@app.route('/public')
def public():
    return jsonify(message="This is the Public Page, accessible to everyone.")

@app.route('/private')
def private():
    redirect_uri = url_for("auth", _external=True)
    return oauth.keycloak.authorize_redirect(redirect_uri)

# Auth callback
@app.route("/auth")
def auth():
    token = oauth.keycloak.authorize_access_token()
    print("Access Token:", token)
    access_token = token.get("access_token")
    if access_token:
        # Decode the access token to extract roles
        payload_part = access_token.split('.')[1]
        padding = len(payload_part) % 4
        if padding > 0:
            payload_part += '=' * (4 - padding)
        decoded_payload = base64.urlsafe_b64decode(payload_part).decode('utf-8')
        payload = json.loads(decoded_payload)
        roles = payload.get("resource_access", {}).get("flask-app", {}).get("roles", [])
    else:
        roles = []

    user_info = oauth.keycloak.parse_id_token(token, nonce=None)
    print("ID Token:", user_info)
    user_info["roles"] = roles
    session["user"] = user_info
    return redirect(url_for("private_access"))

@app.route('/private_access', methods=['GET', 'POST'])
@role_required("flask_role")
def private_access():
    if request.method == 'POST':
        image_url = request.form.get('image_url', 'https://placedog.net/500')
    else:
        image_url = 'https://placedog.net/500'

    return render_template_string('''
        <html>
            <head><title>Private Page</title></head>
            <body>
                <h1>This is the Private Page, accessible only to users with the 'flask_role' role.</h1>
                <img src="{{ image_url }}" alt="Dog Image">
                <form method="post">
                    <label for="image_url">Enter new image URL:</label>
                    <input type="text" id="image_url" name="image_url">
                    <button type="submit">Change Image</button>
                </form>
            </body>
        </html>
    ''', image_url=image_url)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
