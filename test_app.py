import jwt

from app import app, valid_key, expired_key


def test_jwks_endpoint():
    """JWKS endpoint should return the valid public key."""
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")

    assert response.status_code == 200

    data = response.get_json()

    assert "keys" in data
    assert len(data["keys"]) == 1

    key = data["keys"][0]

    assert key["kid"] == valid_key["kid"]
    assert key["kty"] == "RSA"
    assert key["alg"] == "RS256"
    assert key["use"] == "sig"
    assert "n" in key
    assert "e" in key


def test_expired_key_not_in_jwks():
    """Expired key must not be returned by JWKS."""
    client = app.test_client()

    response = client.get("/.well-known/jwks.json")
    data = response.get_json()

    kids = [key["kid"] for key in data["keys"]]

    assert valid_key["kid"] in kids
    assert expired_key["kid"] not in kids


def test_valid_auth():
    """POST /auth should return a valid signed JWT."""
    client = app.test_client()

    response = client.post("/auth")

    assert response.status_code == 200

    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)

    assert header["kid"] == valid_key["kid"]
    assert header["alg"] == "RS256"

    payload = jwt.decode(
        token,
        valid_key["private_key"].public_key(),
        algorithms=["RS256"]
    )

    assert payload["sub"] == "fake-user"
    assert "iat" in payload
    assert "exp" in payload


def test_expired_auth():
    """Expired query parameter should return an expired JWT."""
    client = app.test_client()

    response = client.post("/auth?expired=true")

    assert response.status_code == 200

    token = response.get_data(as_text=True)

    header = jwt.get_unverified_header(token)

    assert header["kid"] == expired_key["kid"]

    payload = jwt.decode(
        token,
        expired_key["private_key"].public_key(),
        algorithms=["RS256"],
        options={"verify_exp": False}
    )

    assert payload["exp"] < payload["iat"]


def test_auth_get_not_allowed():
    """GET requests to /auth should not be allowed."""
    client = app.test_client()

    response = client.get("/auth")

    assert response.status_code == 405
