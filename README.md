# Project 2: SQLite-backed JWKS server

Author: Sukhman Singh | CSCE 3550

## Run (macOS/Linux)

Open a terminal in this repository:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

The server listens on port 8080. The database is created in the terminal's
current working directory as `totally_not_my_privateKeys.db`.
Run the official Gradebot client from this same directory so it can inspect it.

## API

- `POST /auth`: plain-text RS256 JWT with a string `kid` header and future `exp`.
- `POST /auth?expired`: token signed using a stored expired key, with expired `exp`.
  Presence of the parameter selects expired keys, even `?expired=false`.
- `GET /.well-known/jwks.json`: every currently valid public RSA key. Never
  includes private RSA parameters or expired keys.

Authentication is mocked as required. HTTP Basic credentials, JSON credentials,
and an empty POST are accepted; this is not production user authentication.
The mock subject is `userABC`.

## Database and security

The exact required `keys(kid INTEGER PRIMARY KEY AUTOINCREMENT, key BLOB NOT
NULL, exp INTEGER NOT NULL)` schema is created on startup. Private keys use
PKCS1 PEM bytes. Startup retains existing rows and creates a missing expired
or valid key category. Newly generated valid keys expire two hours later.
The token lifetime is at most one hour and never exceeds its key expiration.

All SQL data values use SQLite `?` parameter binding. The comparison operator
is chosen from two hard-coded constants; no request content becomes SQL.
Connections close after each operation. No database or private key belongs in
Git: the included `.gitignore` excludes generated databases.
Private keys are intentionally unencrypted on disk for this assignment;
protect the database with filesystem access controls.

## Tests and lint

```sh
python -m pytest
python -m flake8 app.py test_app.py
```

Tests verify RSA signatures using the published JWKS, Basic/JSON requests,
expired-token rejection, SQL-like query text, schema, PEM serialization,
restart persistence, multiple valid keys, expiry boundaries, missing keys,
and HTTP methods. Tests use temporary databases and do not alter the server DB.
See `test-output.txt` for the actual development test results.

## Required screenshots and submission

1. Start the server with `python app.py`.
2. In another terminal in this directory, print your identification:
   `echo "Sukhman Singh | CSCE 3550 | Project 2"`.
3. Stop any running server, then run the v1.1.2 client:
   `./gradebot project-2 --dir=. --run='.venv/bin/python app.py' --code-dir=. --database=totally_not_my_privateKeys.db`.
   This client starts the server itself.
4. Capture the actual rubric/points table with identification visible and save
   it as `screenshots/gradebot.png`.
5. Print the same identification, run `python -m pytest`, and take a screenshot
   showing the coverage percentage. Save as `screenshots/coverage.png`.
6. Upload the repository contents, including both screenshots, to GitHub.
7. Submit your actual `https://github.com/YOUR_USERNAME/YOUR_REPOSITORY` URL.

Official Gradebot v1.1.2 was run on October 24, 2026: all four functional
criteria received full points (65/65), Quality received 4.25/5, and the client
reported 98.93%. This does not include the instructor-graded screenshot and
test-suite rubric items. No Project 2 result screenshot is included yet. `test-output.txt` is genuine text
output, not a substitute for the required screenshots. Review the code and
follow your course's rules on attribution and assistance before submitting.
