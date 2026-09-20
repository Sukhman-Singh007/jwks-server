# JWKS Server - Project 1

**Student:** Sukhman Singh  
**Course:** CSCE 3550

## Description

This project implements a basic RESTful JWKS server using Python and Flask.

The server generates RSA key pairs with unique Key IDs (`kid`) and expiration timestamps. It provides a JWKS endpoint containing valid public keys and an authentication endpoint that issues signed JSON Web Tokens (JWTs).

The server can also issue an expired JWT for testing purposes.

## Features

- RSA key pair generation
- Unique `kid` values
- Key expiration
- JWKS public key endpoint
- JWT signing using RS256
- Valid JWT generation
- Expired JWT generation
- Expired keys excluded from JWKS
- Automated tests using pytest
- Test coverage above 80%

## Endpoints

### GET /.well-known/jwks.json

Returns currently valid public keys in JWKS format.

### POST /auth

Returns a valid JWT signed using the active RSA private key.

### POST /auth?expired=true

Returns an expired JWT signed using the expired RSA private key.

## Installation

Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate