#!/usr/bin/env python
import os
import json
import requests
from flask import redirect, request, url_for
from oauthlib.oauth2 import WebApplicationClient
from otterwiki.server import app
from otterwiki.auth import auth_manager

# Configuration
OAUTH_CLIENT_ID = os.environ.get("OAUTH_CLIENT_ID", None)
OAUTH_CLIENT_SECRET = os.environ.get("OAUTH_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)


# OAuth 2 client setup
client = WebApplicationClient(OAUTH_CLIENT_ID)

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/-/oauth2_login")
def oauth2_login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    # scopes that let you retrieve user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        hosted_domain=os.environ.get("GOOGLE_AUTH_DOMAIN", None),
        redirect_uri=request.base_url.replace("oauth2_login","gcp_login/callback"),
        scope=["openid", "email", "profile"],
    )
    print(request_uri)
    return redirect(request_uri)

@app.route("/-/gcp_login/callback")
def gcp_callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")
    # Find out what URL to hit to get tokens that allow you to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code
    )

    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(OAUTH_CLIENT_ID, OAUTH_CLIENT_SECRET),
    )

    # Parse the tokens!
    response = token_response.json()
    if 'error' in response.keys():
        print(type(response))
        return f"Error from Oauth  serveur : {response}.", 400

    client.parse_request_body_response(json.dumps(response))
    # Now that you have tokens (yay) let's find and hit the URL
    # from Google that gives you the user's profile information,
    # including their Google profile image and email
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    user_info = userinfo_response.json()
    # app, and now you've verified their email through Google!
    if not user_info.get("hd", "not_available") == os.environ.get("GOOGLE_AUTH_DOMAIN", None):
        return "User email not available or not verified by Google.", 400

    if user_info.get("email_verified"):
        unique_id = user_info["sub"]
        users_email = user_info["email"]
        picture = user_info["picture"]
        users_name = user_info["given_name"]
    else:
        return "User email not available or not verified by Google.", 400
    # Create a user in your db with the information provided
    # by Google
    user = auth_manager.handle_login(
        id=unique_id, name=users_name, email=users_email, profile_pic=picture
    )
    return redirect("/")

