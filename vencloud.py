import base64
import hashlib
import os
import sqlite3
import aiohttp
from aiohttp import web

SIZE_LIMIT = 33554432
ROOT_REDIRECT = ""
DISCORD_CLIENT_ID = ""
DISCORD_CLIENT_SECRET = ""
DISCORD_REDIRECT_URI = ""
PEPPER_SETTINGS = "pepper_settings"
PEPPER_SECRETS = "pepper_secrets"

conn: sqlite3.Connection = sqlite3.connect('users_vencloud.db')
c: sqlite3.Cursor = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        secret TEXT
    )
''')

c.execute('''
    CREATE TABLE IF NOT EXISTS settings (
        user_id TEXT PRIMARY KEY,
        value BLOB,
        written INTEGER
    )
''')
conn.commit()

def hash_string(s: str) -> str:
    return hashlib.sha1(s.encode()).hexdigest()

async def check_auth(request: web.Request) -> web.Response | None:
    auth_token = request.headers.get("Authorization")

    if not auth_token:
        return web.json_response({"error": "Missing authorization"}, status=401)

    try:
        token = base64.b64decode(auth_token).decode()
        secret, user_id = token.split(":")
    except:
        return web.json_response({"error": "Invalid authorization"}, status=401)

    hashed_user_id = hash_string(PEPPER_SECRETS + user_id)
    c.execute("SELECT secret FROM users WHERE user_id = ?", (hashed_user_id,))
    row = c.fetchone()

    if not row or row[0] != secret:
        return web.json_response({"error": "Invalid authorization"}, status=401)

    request["user_id"] = user_id

async def get_oauth_callback(request: web.Request) -> web.Response:
    code = request.query.get("code")
    if not code:
        return web.json_response({"error": "Missing code"}, status=400)

    async with aiohttp.ClientSession() as session:
        async with session.post("https://discord.com/api/oauth2/token", data={
            "client_id": DISCORD_CLIENT_ID,
            "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": DISCORD_REDIRECT_URI,
            "scope": "identify"
        }) as response:
            if response.status != 200:
                return web.json_response({"error": "Invalid code"}, status=400)
            access_token_result = await response.json()

        access_token = access_token_result["access_token"]

        async with session.get("https://discord.com/api/users/@me", headers={
            "Authorization": f"Bearer {access_token}"
        }) as response:
            if response.status != 200:
                return web.json_response({"error": "Failed to request user"}, status=500)
            user_result = await response.json()

        user_id = user_result["id"]

        hashed_user_id = hash_string(PEPPER_SECRETS + user_id)
        c.execute("SELECT secret FROM users WHERE user_id = ?", (hashed_user_id,))
        row = c.fetchone()

        if not row:
            secret = base64.b64encode(os.urandom(48)).decode()
            c.execute("INSERT INTO users (user_id, secret) VALUES (?, ?)", (hashed_user_id, secret))
            conn.commit()
        else:
            secret = row[0]

        return web.json_response({"secret": secret})

async def get_oauth_settings(request: web.Request) -> web.Response:
    return web.json_response({
        "clientId": DISCORD_CLIENT_ID,
        "redirectUri": DISCORD_REDIRECT_URI
    })

async def head_settings(request: web.Request) -> web.Response:
    auth_check = await check_auth(request)
    if auth_check is not None:
        return auth_check

    user_id = request["user_id"]
    hashed_user_id = hash_string(PEPPER_SETTINGS + user_id)

    c.execute("SELECT written FROM settings WHERE user_id = ?", (hashed_user_id,))
    row = c.fetchone()

    if not row:
        return web.Response(status=404)

    written = row[0]
    response = web.Response(status=204)
    response.headers["ETag"] = str(written)
    return response

async def get_settings(request: web.Request) -> web.Response:
    auth_check = await check_auth(request)
    if auth_check is not None:
        return auth_check

    user_id = request["user_id"]
    hashed_user_id = hash_string(PEPPER_SETTINGS + user_id)

    c.execute("SELECT value, written FROM settings WHERE user_id = ?", (hashed_user_id,))
    row = c.fetchone()

    if not row:
        return web.Response(status=404)

    value, written = row
    if_none_match = request.headers.get("If-None-Match")

    if if_none_match == str(written):
        return web.Response(status=304)

    response = web.Response(body=value)
    response.content_type = 'application/octet-stream'
    response.headers["ETag"] = str(written)
    return response

async def put_settings(request: web.Request) -> web.Response:
    auth_check = await check_auth(request)
    if auth_check is not None:
        return auth_check

    if request.content_type != 'application/octet-stream':
        return web.json_response({"error": "Content type must be application/octet-stream"}, status=415)

    body = await request.read()
    if len(body) > SIZE_LIMIT:
        return web.json_response({"error": "Settings are too large"}, status=413)

    user_id = request["user_id"]
    hashed_user_id = hash_string(PEPPER_SETTINGS + user_id)
    written = int(request.loop.time() * 1000)

    c.execute("REPLACE INTO settings (user_id, value, written) VALUES (?, ?, ?)", (hashed_user_id, body, written))
    conn.commit()

    return web.json_response({"written": written})

async def delete_settings(request: web.Request) -> web.Response:
    auth_check = await check_auth(request)
    if auth_check is not None:
        return auth_check

    user_id = request["user_id"]
    hashed_user_id = hash_string(PEPPER_SETTINGS + user_id)

    c.execute("DELETE FROM settings WHERE user_id = ?", (hashed_user_id,))
    conn.commit()

    return web.Response(status=204)

async def delete_user(request: web.Request) -> web.Response:
    auth_check = await check_auth(request)
    if auth_check is not None:
        return auth_check

    user_id = request["user_id"]
    hashed_user_id = hash_string(PEPPER_SECRETS + user_id)

    c.execute("DELETE FROM users WHERE user_id = ?", (hashed_user_id,))
    c.execute("DELETE FROM settings WHERE user_id = ?", (hashed_user_id,))
    conn.commit()

    return web.Response(status=204)

async def get_root(request: web.Request) -> web.Response:
    return web.Response(text="pong")

async def vencloud(request: web.Request) -> web.Response:
    get_paths = {
        "/v1/oauth/callback": get_oauth_callback,
        "/v1/oauth/settings": get_oauth_settings,
        "/v1/settings": get_settings,
        "/v1": get_root
    }

    head_paths = {
        "/v1/settings": head_settings
    }

    put_paths = {
        "/v1/settings": put_settings
    }

    delete_paths = {
        "/v1/settings": delete_settings,
        "/v1": delete_user
    }

    methods = {
        "HEAD": head_paths,
        "GET": get_paths,
        "PUT": put_paths,
        "DELETE": delete_paths
    }

    for method, path_map in methods.items():
        if request.method == method:
            for route, handler in path_map.items():
                if request.path == route:
                    return await handler(request=request)

    return web.Response(status=404)

__all__ = [
    "vencloud"
]
