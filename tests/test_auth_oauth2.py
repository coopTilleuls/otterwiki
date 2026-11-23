#!/usr/bin/env python
# vim: set et ts=8 sts=4 sw=4 ai:

"""
OAuth2 (Google SSO) has no passwords: the password based flows must send
the user to the SSO instead of crashing, and nothing may log in without it.
"""

import re
from datetime import datetime

import pytest

from conftest import CSRFTestClient


class OAuth2TestClient(CSRFTestClient):
    """'/' redirects anonymous users to Google, fetch the csrf token from
    a page that is public instead."""

    def _get_csrf_token(self):
        response = self.get("/-/about")
        match = re.search(
            r'name="csrf-token" content="([^"]+)"', response.data.decode()
        )
        return match.group(1) if match else None


def add_user(app, auth_manager, email="alice@example.org"):
    from otterwiki.models import db

    with app.app_context():
        db.session.add(
            auth_manager.User(
                name="Alice",
                email=email,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )
        )
        db.session.commit()


@pytest.fixture
def oauth2_app(create_app):
    """create_app with the auth_manager swapped for OAuth2.

    The auth_manager and the oauth2 routes are set up at import time based
    on AUTH_METHOD, so the OAuth2 auth_manager is patched in and the oauth2
    routes registered (once per process) for testing.
    """
    import otterwiki.auth
    from otterwiki.auth import OAuth2

    app = create_app
    if "oauth2_login" not in app.view_functions:
        # flask refuses to add routes once the app served a request
        got_first_request = app._got_first_request
        app._got_first_request = False
        try:
            import otterwiki.oauth2  # noqa: F401
        finally:
            app._got_first_request = got_first_request

    original_auth_manager = otterwiki.auth.auth_manager
    original_auth_method = app.config.get("AUTH_METHOD")
    original_features = app.jinja_env.globals.get("auth_supported_features")
    original_login_view = otterwiki.auth.login_manager.login_view
    original_client_class = app.test_client_class

    oauth2 = OAuth2()
    app.config["AUTH_METHOD"] = "OAUTH2"
    app.config["READ_ACCESS"] = "REGISTERED"
    app.config["WRITE_ACCESS"] = "REGISTERED"
    app.config["ATTACHMENT_ACCESS"] = "REGISTERED"
    otterwiki.auth.auth_manager = oauth2
    otterwiki.auth.login_manager.login_view = "oauth2_login"
    app.jinja_env.globals.update(
        auth_supported_features=oauth2.supported_features()
    )
    app.test_client_class = OAuth2TestClient

    yield app

    otterwiki.auth.auth_manager = original_auth_manager
    otterwiki.auth.login_manager.login_view = original_login_view
    app.test_client_class = original_client_class
    app.config["AUTH_METHOD"] = original_auth_method
    app.jinja_env.globals.update(auth_supported_features=original_features)


def assert_redirects_to_sso(rv):
    assert rv.status_code == 302, rv.status_code
    assert rv.location.endswith("/-/oauth2_login"), rv.location


@pytest.mark.parametrize(
    "path",
    [
        "/-/lost_password",
        "/-/recover_password/sometoken",
        "/-/confirm_email/sometoken",
        "/-/request_confirmation_link/someone@example.org",
    ],
)
def test_password_flows_get_redirect_to_sso(oauth2_app, path):
    client = oauth2_app.test_client()
    assert_redirects_to_sso(client.get(path))


def test_register_get_redirects(oauth2_app):
    client = oauth2_app.test_client()
    # registration disabled: index, otherwise the SSO; never a 500
    for disabled in (True, False):
        oauth2_app.config["DISABLE_REGISTRATION"] = disabled
        rv = client.get("/-/register")
        assert rv.status_code == 302


def test_register_post_never_creates_user(oauth2_app):
    from otterwiki.auth import auth_manager

    oauth2_app.config["DISABLE_REGISTRATION"] = False
    client = oauth2_app.test_client()
    rv = client.post(
        "/-/register",
        data={
            "email": "mallory@example.org",
            "name": "Mallory",
            "password1": "correct horse battery",
            "password2": "correct horse battery",
        },
    )
    assert_redirects_to_sso(rv)
    with oauth2_app.app_context():
        assert auth_manager.get_all_user() == []


def test_password_login_post_redirects_and_does_not_login(oauth2_app):
    from otterwiki.auth import auth_manager

    # an existing user (e.g. created via the SSO) has no usable password
    add_user(oauth2_app, auth_manager)

    client = oauth2_app.test_client()
    rv = client.post(
        "/-/login",
        data={"email": "alice@example.org", "password": "", "remember": "1"},
    )
    assert_redirects_to_sso(rv)
    # still anonymous: reading the wiki sends to the SSO
    rv = client.get("/Home")
    assert rv.status_code == 302
    assert "/-/oauth2_login" in rv.location


def test_lost_password_post_redirects(oauth2_app):
    client = oauth2_app.test_client()
    with oauth2_app.test_mail.record_messages() as outbox:
        rv = client.post(
            "/-/lost_password", data={"email": "alice@example.org"}
        )
        assert_redirects_to_sso(rv)
        assert len(outbox) == 0


def test_check_credentials_never_authenticates(oauth2_app):
    from otterwiki.auth import auth_manager, check_credentials

    add_user(oauth2_app, auth_manager)
    with oauth2_app.app_context():
        assert check_credentials("alice@example.org", "") is None
        assert check_credentials("alice@example.org", "x") is None


def test_anonymous_cannot_read_or_write(oauth2_app):
    client = oauth2_app.test_client()
    rv = client.get("/Home")
    assert rv.status_code == 302
    assert "/-/oauth2_login" in rv.location
    rv = client.post("/Home/save", data={"content": "pwned", "commit": "x"})
    assert rv.status_code == 403


def follow_to_sso(client, path):
    """Follow the redirects of an anonymous request up to the SSO, return
    the final location."""
    from urllib.parse import urlsplit

    rv = client.get(path)
    for _ in range(3):
        assert rv.status_code == 302, (path, rv.status_code)
        location = urlsplit(rv.location)
        if location.path == "/-/oauth2_login":
            return rv.location
        rv = client.get(
            location.path + ("?" + location.query if location.query else "")
        )
    raise AssertionError(f"{path} never reached the SSO: {rv.location}")


@pytest.mark.parametrize(
    "path",
    [
        "/Home/history",
        "/Home/source",
        "/Home/blame",
        "/Home/attachments",
        "/Home/a/file.txt",
        "/-/index",
        "/-/search",
        "/-/changelog",
        "/-/log",
    ],
)
def test_anonymous_is_sent_to_sso_with_next(oauth2_app, path):
    from urllib.parse import parse_qs, urlsplit

    client = oauth2_app.test_client()
    location = follow_to_sso(client, path)
    next_url = parse_qs(urlsplit(location).query).get("next", [""])[0]
    assert next_url.startswith(path), (path, location)


def test_login_form_redirects_anonymous_to_sso(oauth2_app):
    client = oauth2_app.test_client()
    assert_redirects_to_sso(client.get("/-/login"))
