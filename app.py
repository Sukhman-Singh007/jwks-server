"""SQLite-backed JWKS server for CSCE 3550 Project 2."""
import json
import sqlite3
import time
from contextlib import closing

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

DB_NAME = 'totally_not_my_privateKeys.db'


def generate_key():
    """Serialize a fresh RSA private key as PKCS1 PEM bytes."""
    return rsa.generate_private_key(65537, 2048).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def initialize_database(path):
    """Preserve existing keys and ensure both expiry categories exist."""
    now = int(time.time())
    with closing(sqlite3.connect(path)) as db, db:
        db.execute('''CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )''')
        # A write transaction serializes concurrent startup checks/inserts.
        db.execute('BEGIN IMMEDIATE')
        for comparison, expiry in [('<=', now - 1), ('>', now + 7200)]:
            # comparison is an internal constant, never request data.
            row = db.execute(
                f'SELECT kid FROM keys WHERE exp {comparison} ? LIMIT 1',
                (now,),
            ).fetchone()
            if row is None:
                db.execute('INSERT INTO keys(key, exp) VALUES (?, ?)',
                           (generate_key(), expiry))


def read_keys(path, expired=False):
    """Read keys using a bound timestamp; user values never enter SQL."""
    comparison = '<=' if expired else '>'
    with closing(sqlite3.connect(path)) as db:
        return db.execute(
            f'SELECT kid, key, exp FROM keys WHERE exp {comparison} ? '
            'ORDER BY exp DESC, kid DESC', (int(time.time()),)
        ).fetchall()


def create_app(database=DB_NAME):
    """Create an app using a database relative to the working directory."""
    app = Flask(__name__)
    app.config['DATABASE'] = str(database)
    initialize_database(app.config['DATABASE'])

    @app.post('/auth')
    def authenticate():
        # Authentication is deliberately mocked, accepting Basic/JSON/no body.
        expired = 'expired' in request.args
        rows = read_keys(app.config['DATABASE'], expired)
        if not rows:
            return jsonify(error='No matching signing key available'), 503
        kid, pem, key_expiry = rows[0]
        private_key = serialization.load_pem_private_key(pem, password=None)
        now = int(time.time())
        expiry = min(now + 3600, key_expiry) if not expired else key_expiry
        token = jwt.encode({'sub': 'userABC', 'iat': now, 'exp': expiry},
                           private_key, algorithm='RS256',
                           headers={'kid': str(kid)})
        return token, 200, {'Content-Type': 'text/plain; charset=utf-8'}

    @app.get('/.well-known/jwks.json')
    def jwks():
        keys = []
        for kid, pem, _ in read_keys(app.config['DATABASE']):
            public_key = serialization.load_pem_private_key(
                pem, password=None).public_key()
            key = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
            key.update(kid=str(kid), alg='RS256', use='sig')
            keys.append(key)
        return jsonify(keys=keys)

    return app


if __name__ == '__main__':  # pragma: no cover
    create_app().run(host='0.0.0.0', port=8080)
