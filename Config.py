from json import loads
from os import environ
from typing import Any, Dict, Optional, Tuple
from requests import Response, request
from time import time, sleep
from urllib.parse import quote as urlquote
from psycopg.connection import Connection
from psycopg_pool import ConnectionPool
from nacl.signing import VerifyKey
from hashlib import sha256
from functools import wraps
from requests import post
from re import compile, IGNORECASE, search, escape
sleep(3)

APPID = environ['APP_ID']
CLIENT_PUBLIC_KEY = environ['CLIENT_PUBLIC_KEY']
DATABASE_URL = environ['DATABASE_URL']
TOKEN = environ['TOKEN']
HASHING_KEY = environ['HASHING_KEY']
OPENAI_KEY = environ['OPENAI_KEY']
bannedwords = set(environ.get('BANNED_WORDS', '').lower().split(','))
starttime = round(time())

errors = {
    'loginrejected': 'Login rejected - You are not in Sound\'s World',
    'notloggedin': 'You are not logged in - Please login to perform this action',
    'emptyconfession': 'Confession cannot be empty - Please provide a confession',
    'confessiontoolong': 'Confession is too long - Please provide a confession that is less than 1000 characters',
    'usernotfound': 'User not found.',
    'indefintelysuspended': 'You are indefinitely suspended.',
    'suspended': 'You are currently suspended. Please wait until your suspension is over',
    'oncooldown': 'You are currently on cooldown. Please wait until your cooldown is over',
    'confessionnotfound': 'Confession not found.',
    'alreadyupvoted': 'You have already upvoted this confession.',
    'alreadyreported': 'You have already reported this confession.',
    'noaccess': 'You do not have access to this function.',
    'badcontent': 'Your confession triggered the content filter. Please try again with another confession.',
}

dbpool = ConnectionPool(conninfo = DATABASE_URL, min_size = 3, max_size = 10)

def psqlrun(query: str, data: Optional[Tuple] = None, commit: bool = False, fetchall: bool = False):
    result = None
    with dbpool.getconn() as conn:
        with conn.cursor() as cursor:
            cursor.execute(query, data)
            if query.strip().lower().startswith("select") or "returning" in query.lower():
                if fetchall:
                    result = cursor.fetchall()
                else:
                    result = cursor.fetchone()
            if commit:
                conn.commit()
    dbpool.putconn(conn)
    return result




def parse_ratelimit_header(request: Any) -> float:
    reset_after: Optional[str] = request.headers.get('X-Ratelimit-Reset-After')
    return float(reset_after)

def makereq(method: str, path: str, payload: Optional[Dict[str, Any]] = None, files: Optional[Dict] = None, reason: Optional[str] = None) -> Response:
    if method not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
        raise TypeError('Invalid request method')
    
    headers: Dict[str, str] = {}
    headers['Authorization'] = f"Bot {TOKEN}"

    if files == None:
        headers['Content-Type'] = 'application/json'

    if reason is not None:
        headers['X-Audit-Log-Reason'] = urlquote(reason, safe='/ ')

    
    for attempt in range(5):
        if files == None:
            r = request(method, url = f"https://discord.com/api/v10{path}", json = payload, headers = headers)
        else:
            r = request(method, url = f"https://discord.com/api/v10{path}", data = payload, files = files, headers = headers)
        r.encoding = 'utf-8'

        data = r.text or None
        if data and r.headers['Content-Type'] == 'application/json':
            data = loads(data)

        if 300 > r.status_code >= 200:
            return r

        remaining = r.headers.get('X-Ratelimit-Remaining')
        if remaining == '0' and r.status_code != 429:
            delta = parse_ratelimit_header(r)
            sleep(delta)
            continue

        if r.status_code == 429:
            print(data)
            try:
                retry_after: float = data['retry_after']
            except KeyError:
                retry_after: float = parse_ratelimit_header(r)
            sleep(retry_after)
            continue

        if r.status_code >= 500:
            sleep(1 + attempt * 2)
            continue

        if r.status_code in [403, 404, 401, 400]:
            print(f'response {r.status_code} was recieved from discord')
            return r
    
    raise Exception('request failed after 5 retries')

class IntType:
    PING = 1
    APPLICATION_COMMAND = 2
    MESSAGE_COMPONENT = 3
    APPLICATION_COMMAND_AUTOCOMPLETE = 4
    MODAL_SUBMIT = 5

class IntRespType:
    PONG = 1
    CHANNEL_MESSAGE_WITH_SOURCE = 4
    DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE = 5
    DEFERRED_UPDATE_MESSAGE = 6
    UPDATE_MESSAGE =  7
    APPLICATION_COMMAND_AUTOCOMPLETE_RESULT = 8
    MODAL = 9

def verify_key(raw_body: bytes, signature: str, timestamp: str, client_public_key: str) -> bool:
    message = timestamp.encode() + raw_body
    try:
        vk = VerifyKey(bytes.fromhex(client_public_key))
        vk.verify(message, bytes.fromhex(signature))
        return True
    except Exception as ex:
        print(ex)
    return False

def verify_key_decorator(client_public_key):
    from flask import request, jsonify

    def _decorator(f):
        @wraps(f)
        def __decorator(*args, **kwargs):
            signature = request.headers.get('X-Signature-Ed25519')
            timestamp = request.headers.get('X-Signature-Timestamp')
            if signature is None or timestamp is None or not verify_key(request.data, signature, timestamp, client_public_key):
                return 'Bad request signature', 401

            if request.json and request.json.get('type') == IntType.PING:
                return jsonify({
                    'type': IntRespType.PONG
                })

            return f(*args, **kwargs)
        return __decorator
    return _decorator

def hashuserid(userid: int) -> str:
    return sha256((str(userid) + HASHING_KEY).encode()).hexdigest()

def formatage(seconds):
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m"
    elif seconds < 86400:
        return f"{seconds // 3600}h"
    else:
        return f"{seconds // 86400}d"

def aiscan(text: str) -> bool:
    r = post(url = 'https://api.openai.com/v1/moderations', headers = {'Authorization': f'Bearer {OPENAI_KEY}'}, json = {'model': 'omni-moderation-latest', 'input': text})
    if r.status_code == 200:
        data = r.json()
        badcategories = ['harassment/threatening', 'hate', 'hate/threatening', 'self-harm/intent', 'self-harm/instructions', 'sexual', 'sexual/minors', 'violence', 'violence/graphic']
        for category in badcategories:
            if data['results'][0]['categories'][category]:
                return True
        return False
    else:
        print(r.status_code)
        print(str(r.json()))
        return False
    
def containsurl(text: str) -> bool:
    urlregex = compile(r"(https?://|www\.)\S+|(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|gov|edu|io|co|xyz|info|biz|me|gg|dev)(/[\w\-.~:/?#\[\]@!$&'()*+,;=%]*)?", IGNORECASE)

    return bool(urlregex.search(text))

def containsbannedwords(text: str) -> bool:
    lowertext = text.lower()

    return any(search(rf"\b{escape(word)}\b", lowertext) for word in bannedwords)

def containscharspam(text: str) -> bool:
    return bool(search(r"(.)\1{6,}", text))  # 7+ repeated chars

def proactivechecks(text: str) -> bool:
    return (
        containsbannedwords(text)
        or containsurl(text)
        or containscharspam(text)
        or aiscan(text)
    )
