from datetime import datetime, timedelta, timezone
import base64
import uuid

from flask import Flask, jsonify, request
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa


app = Flask(__name__)


def generate_key(expired=False):
    """Generate an RSA key pair with a unique kid and expiration time."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    kid = str(uuid.uuid4())

    if expired:
        expiry = datetime.now(timezone.utc) - timedelta(hours=1)
    else:
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)

    return {
        "private_key": private_key,
        "kid": kid,
        "expiry": expiry
    }


valid_key = generate_key()
expired_key = generate_key(expired=True)


def int_to_base64(value):
    """Convert an integer to URL-safe Base64 without padding."""
    value_bytes = value.to_bytes(
        (value.bit_length() + 7) // 8,
        byteorder="big"
    )

    return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")


def key_to_jwk(key):
    """Convert an RSA public key to JWK format."""
    public_key = key["private_key"].public_key()
    public_numbers = public_key.public_numbers()

    return {
        "kty": "RSA",
        "use": "sig",
        "kid": key["kid"],
        "alg": "RS256",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e)
    }


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return all currently valid public keys."""
    keys = []

    if valid_key["expiry"] > datetime.now(timezone.utc):
        keys.append(key_to_jwk(valid_key))

    return jsonify({"keys": keys}), 200


@app.route("/auth", methods=["POST"])
def auth():
    """Issue a signed JWT using either the valid or expired key."""
    use_expired = "expired" in request.args

    if use_expired:
        selected_key = expired_key
    else:
        selected_key = valid_key

    now = datetime.now(timezone.utc)

    if use_expired:
        expiration = now - timedelta(hours=1)
    else:
        expiration = now + timedelta(hours=1)

    payload = {
        "sub": "fake-user",
        "iat": int(now.timestamp()),
        "exp": int(expiration.timestamp())
    }

    token = jwt.encode(
        payload,
        selected_key["private_key"],
        algorithm="RS256",
        headers={"kid": selected_key["kid"]}
    )

    return token, 200, {"Content-Type": "application/jwt"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
