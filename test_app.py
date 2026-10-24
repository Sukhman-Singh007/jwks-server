"""Behavioral tests using isolated temporary SQLite databases."""
import sqlite3
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization

from app import create_app, generate_key, initialize_database, read_keys


@pytest.fixture
def server(tmp_path):
    path = tmp_path / 'totally_not_my_privateKeys.db'
    app = create_app(path)
    app.config['TESTING'] = True
    return app.test_client(), path


@pytest.mark.parametrize('kwargs', [
    {}, {'auth': ('userABC', 'password123')},
    {'json': {'username': 'userABC', 'password': 'password123'}},
])
def test_valid_token_verifies_with_published_key(server, kwargs):
    client, _ = server
    response = client.post('/auth', **kwargs)
    assert response.status_code == 200
    token = response.get_data(as_text=True)
    header = jwt.get_unverified_header(token)
    keys = client.get('/.well-known/jwks.json').get_json()['keys']
    key = next(key for key in keys if key['kid'] == header['kid'])
    claims = jwt.decode(token, jwt.PyJWK.from_dict(key).key,
                        algorithms=['RS256'])
    assert claims['sub'] == 'userABC'
    assert claims['exp'] > time.time()
    assert key['use'] == 'sig'
    assert not {'d', 'p', 'q'}.intersection(key)


@pytest.mark.parametrize('query', ['?expired', '?expired=false',
                                   '?expired=1%27%20OR%201=1--'])
def test_expired_parameter_presence(server, query):
    client, path = server
    token = client.post('/auth' + query).get_data(as_text=True)
    kid = jwt.get_unverified_header(token)['kid']
    public_ids = {key['kid'] for key in client.get(
        '/.well-known/jwks.json').get_json()['keys']}
    assert kid not in public_ids
    row = next(row for row in read_keys(path, True) if str(row[0]) == kid)
    public = serialization.load_pem_private_key(row[1], None).public_key()
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public, algorithms=['RS256'])


def test_schema_pem_and_restart_persistence(server):
    _, path = server
    with sqlite3.connect(path) as db:
        before = db.execute('SELECT * FROM keys').fetchall()
        schema = db.execute('PRAGMA table_info(keys)').fetchall()
    assert [(r[1], r[2]) for r in schema] == [
        ('kid', 'INTEGER'), ('key', 'BLOB'), ('exp', 'INTEGER')]
    assert all(isinstance(row[1], bytes) for row in before)
    assert all(row[1].startswith(b'-----BEGIN RSA PRIVATE KEY-----')
               for row in before)
    initialize_database(path)
    create_app(path)
    with sqlite3.connect(path) as db:
        assert db.execute('SELECT * FROM keys').fetchall() == before


def test_jwks_includes_all_and_only_valid_keys(server):
    client, path = server
    with sqlite3.connect(path) as db:
        db.execute('INSERT INTO keys(key, exp) VALUES (?, ?)',
                   (generate_key(), int(time.time()) + 8000))
        db.execute('INSERT INTO keys(key, exp) VALUES (?, ?)',
                   (generate_key(), int(time.time())))
    expected = {str(row[0]) for row in read_keys(path)}
    actual = client.get('/.well-known/jwks.json').get_json()['keys']
    assert len(expected) == 2
    assert {key['kid'] for key in actual} == expected


def test_missing_keys_and_empty_jwks(server):
    client, path = server
    with sqlite3.connect(path) as db:
        db.execute('DELETE FROM keys')
    assert client.post('/auth').status_code == 503
    assert client.post('/auth?expired').status_code == 503
    assert client.get('/.well-known/jwks.json').get_json() == {'keys': []}
    initialize_database(path)
    assert len(read_keys(path)) == len(read_keys(path, True)) == 1


def test_wrong_methods(server):
    client, _ = server
    assert client.get('/auth').status_code == 405
    assert client.post('/.well-known/jwks.json').status_code == 405
