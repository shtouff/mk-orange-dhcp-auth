import os
from typing import Annotated

from fastapi import FastAPI, Path, Query

from auth import load_credentials, make_orange_authentication, hex_string

app = FastAPI()
username, password = load_credentials(os.getenv('CREDENTIALS', '/dev/null'))


@app.get("/api/hash")
def get_api_hash():
    return hex_string(make_orange_authentication(username, password))


@app.get("/api/hashes")
def get_api_hashes(q: Annotated[int | None, Query()] = 10):
    return [
        hex_string(make_orange_authentication(username, password))
        for i in range(q)
    ]

