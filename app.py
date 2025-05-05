from flask import Flask, request, jsonify, render_template, redirect, Request
from flask_discord import DiscordOAuth2Session
from Config import psqlrun, hashuserid, formatage, errors
from time import time, sleep
from typing import Optional
from os import environ
from urllib.parse import urlencode
sleep(3)

APPID = environ['APP_ID']
CLIENT_PUBLIC_KEY = environ['CLIENT_PUBLIC_KEY']
CLIENT_SECRET = environ['CLIENT_SECRET']
TOKEN = environ['TOKEN']
SECRET_KEY = environ['SECRET_KEY']
XMO_HASH = environ['XMO_HASH']

app = Flask(__name__)
app.secret_key = SECRET_KEY
environ['OAUTHLIB_INSECURE_TRANSPORT'] = 'false'
app.config['DISCORD_CLIENT_ID'] = APPID
app.config['DISCORD_CLIENT_SECRET'] = CLIENT_SECRET
app.config['DISCORD_BOT_TOKEN'] = TOKEN
app.config['DISCORD_REDIRECT_URI'] = 'https://confessions.xmo.dev/callback'

discord = DiscordOAuth2Session(app)

def dynamicredirect(request: Request, error: Optional[str] = None) -> redirect:
    queryparams = request.args.to_dict(flat = True)

    if error:
        error = errors.get(error, "Unknown error")
        queryparams["err"] = error

    return redirect(f"/?{urlencode(queryparams)}")


@app.route("/login/")
def login():
    redirect_url = request.args.get('redirect_url', '/')
    if request.headers.get("User-Agent") == "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)":
        return render_template('crawler.html')
    
    return discord.create_session(scope = ["identify", "guilds"], prompt = False, data = {"base": False, "url": redirect_url})

@app.route("/callback/")
def callback():
    if request.headers.get("User-Agent") == "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)":
        return render_template('crawler.html')
    
    try:
        data = discord.callback()
    except Exception as e:
        print(str(e))
        return "something went wrong", 404
    
    # perform an upsert on the user table after running validation checks
    userhash = hashuserid(discord.fetch_user().id)
    userguilds = discord.fetch_guilds()
    guilds = [int(guild.id) for guild in userguilds]
    if 452237221840551938 not in guilds: # they're not in sound's world
        # reject login
        discord.revoke()
        return redirect("/") if data.get("base") else redirect(data.get("url"))
    
    # they're in the server, so they can login, add confessions, whatever
    psqlrun(query = "INSERT INTO users (userhash) VALUES (%s) ON CONFLICT (userhash) DO NOTHING;", data = (userhash,), commit = True)

    return redirect("/") if data.get("base") else redirect(data.get("url"))

@app.route("/logout/")
def logout():
    redirect_url = request.args.get('redirect_url', '/')
    if request.headers.get("User-Agent") == "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)":
        return render_template('crawler.html')
    
    discord.revoke()
    return redirect(redirect_url)



@app.route("/", methods = ["GET"])
def index():
    loggedin = discord.authorized
    sort = request.args.get("sort", "trending")  # default to trending
    if sort not in ['trending', 'newest', 'top']:
        sort = 'trending'

    search = request.args.get("q", "").strip()
    if len(search) > 100:
        search = search[:100]  # truncate to 100 characters

    basequery = "SELECT id, content, createdat, COALESCE(array_length(upvoters, 1), 0) AS upvotes, COALESCE(array_length(reporters, 1), 0) AS reports, (COALESCE(array_length(upvoters, 1), 0) / POWER(EXTRACT(EPOCH FROM (NOW() - createdat)) + 600, 0.9)) AS score FROM confessions WHERE deletedby IS NULL"

    queryparams = []
    if search:
        basequery += " AND content ILIKE %s"
        queryparams.append(f"%{search}%")

    if sort == 'trending':
        basequery += " ORDER BY score DESC"
    elif sort == 'newest':
        basequery += " ORDER BY createdat DESC"
    elif sort == 'top':
        basequery += " ORDER BY upvotes DESC"

    basequery += " LIMIT 50;"

    data = psqlrun(query = basequery, data = tuple(queryparams), fetchall = True)

    feed = []
    now = int(time())
    for confession in data:
        confessionid = confession[0]
        content = confession[1]
        createdat = confession[2]
        upvotes = confession[3] if confession[3] is not None else 0
        reports = confession[4] if confession[4] is not None else 0

        ageseconds = now - int(createdat.timestamp())
        age = formatage(ageseconds)

        feed.append({
            "id": confessionid,
            "content": content,
            "createdat": createdat,
            "upvotes": upvotes,
            "reports": reports,
            "age": age
        })

    return render_template('index.html', loggedin = loggedin, feed = feed, sort = sort)

@app.route("/audit", methods = ["GET"])
def audit():
    loggedin = discord.authorized
    data = psqlrun(query = "SELECT id, confessionid, userhash, action, timestamp, method FROM auditlog ORDER BY timestamp DESC;", fetchall = True)

    entries = []
    for item in data:
        confessionid = item[1]
        userhash = item[2]
        action = item[3]
        timestamp = item[4]
        method = item[5]

        entries.append({
            "confessionid": confessionid,
            "userhash": userhash,
            "action": action,
            "timestamp": timestamp,
            "method": method,
        })

    return render_template('audit.html', loggedin = loggedin, entries = entries)

@app.route("/about", methods = ["GET"])
def about():
    loggedin = discord.authorized
    return render_template('about.html', loggedin = loggedin)

@app.route("/submit", methods = ["POST"])
def submit():
    if not discord.authorized:
        return redirect("/")
    
    confession = request.form.get("confession", "").strip()
    if not confession:
        return redirect("/") # empty confession
    if len(confession) > 1000:
        return redirect("/") # confession too long
    
    # ensure the user exists in the database. they should, but just in case
    userhash = hashuserid(discord.fetch_user().id)
    userdata = psqlrun(query = "SELECT cooldownuntil, suspensionuntil FROM users WHERE userhash = %s;", data = (userhash,), fetchall = False)
    if userdata is None:
        return redirect("/") # user not found in database
    
    cooldownuntil = userdata[0]
    suspensionuntil = userdata[1]

    # check if they're suspended indefinitely
    if suspensionuntil == 0:
        return redirect("/")

    now = int(time())
    if cooldownuntil is not None and now < cooldownuntil:
        return redirect("/") # user is on cooldown
    
    if suspensionuntil is not None and now < suspensionuntil:
        return redirect("/") # user is suspended
    
    # good to go, insert the confession and audit log and start the cooldown
    cooldownuntil = now + 300
    psqlrun(query = "UPDATE users SET cooldownuntil = %s WHERE userhash = %s;", data = (cooldownuntil, userhash), commit = True)

    confessionid = int(psqlrun(query = "INSERT INTO confessions (userhash, content, upvoters, reporters) VALUES (%s, %s, %s, %s) RETURNING id;", data = (userhash, confession, [], []), commit = True)[0])
    
    psqlrun(query = "INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);", data = (confessionid, userhash, "CREATE", "USER"), commit = True)
    return redirect("/")

@app.route("/upvote", methods=["POST"])
def upvote():
    if not discord.authorized:
        return redirect("/")
    
    userhash = hashuserid(discord.fetch_user().id)
    confessionid = request.form.get("confession_id")

    # Check if user has already upvoted
    data = psqlrun("SELECT upvoters FROM confessions WHERE id = %s;", data = (confessionid,), fetchall = False)
    if not data:
        return redirect("/")  # Invalid confession

    upvoters = data[0] or []

    if userhash in upvoters:
        return dynamicredirect(request, "alreadyupvoted")  # Already upvoted

    # Add user to upvoters
    psqlrun("UPDATE confessions SET upvoters = array_append(upvoters, %s) WHERE id = %s;", data = (userhash, confessionid), commit = True)

    # Audit log
    psqlrun("INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);",data = (confessionid, userhash, "UPVOTE", "USER"), commit = True)

    return redirect("/")

@app.route("/report", methods=["POST"])
def report():
    if not discord.authorized:
        return redirect("/")
    
    userhash = hashuserid(discord.fetch_user().id)
    confessionid = request.form.get("confession_id")

    # Check if user has already reported
    data = psqlrun("SELECT reporters FROM confessions WHERE id = %s;", data = (confessionid,), fetchall = False)
    if not data:
        return redirect("/")  # Invalid confession

    reporters = data[0] or []

    if userhash in reporters:
        return redirect("/")  # Already reported

    # Add user to upvoters
    psqlrun("UPDATE confessions SET reporters = array_append(reporters, %s) WHERE id = %s;", data = (userhash, confessionid), commit = True)

    # Audit log
    psqlrun("INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);", data = (confessionid, userhash, "REPORT", "USER"),commit = True)

    # additionally, if the confession has five reports, hide it from the feed/delete it
    data = psqlrun(query = "SELECT array_length(reporters, 1) FROM confessions WHERE id = %s;", data = (confessionid,), fetchall = False)


    if data and data[0] >= 5:
        psqlrun(query = "UPDATE confessions SET deletedby = 2 WHERE id = %s;", data = (confessionid,), commit = True)
        psqlrun(query = "INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);", data = (confessionid, "N/A", "DELETE", "SYSTEM"), commit = True)

        delconfessioncount = int(psqlrun(query = "UPDATE users SET deletedconfessions = deletedconfessions + 1 WHERE userhash = %s RETURNING deletedconfessions;", data = (userhash,), commit = True)[0])

        if delconfessioncount >= 3:
            # suspend the user for 1 day
            suspensionuntil = int(time()) + 86400
            psqlrun(query = "UPDATE users SET suspensionuntil = %s WHERE userhash = %s;", data = (suspensionuntil, userhash), commit = True)

            # audit log the suspension
            psqlrun(query = "INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);", data = (confessionid, userhash, "SUSPEND", "SYSTEM"), commit = True)
        
        if delconfessioncount >= 5:
            # suspend the user for 3 days
            suspensionuntil = int(time()) + 259200
            psqlrun(query = "UPDATE users SET suspensionuntil = %s WHERE userhash = %s;", data = (suspensionuntil, userhash), commit = True)

            # audit log the suspension
            psqlrun(query = "INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);", data = (confessionid, userhash, "SUSPEND", "SYSTEM"), commit = True)

        if delconfessioncount >= 8:
            # suspend the user indefinitely
            suspensionuntil = 0
            psqlrun(query = "UPDATE users SET suspensionuntil = %s WHERE userhash = %s;", data = (suspensionuntil, userhash), commit = True)

            # audit log the suspension
            psqlrun(query = "INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);", data = (confessionid, userhash, "SUSPEND", "SYSTEM"), commit = True)

    return redirect("/")

@app.route("/admin/delete/<confessionid>", methods = ["GET"])
def admin_delete(confessionid: str):
    if not discord.authorized:
        return redirect("/")
    
    userhash = hashuserid(discord.fetch_user().id)
    
    if userhash != XMO_HASH:
        return redirect("/")
    
    # delete the confession and add to audit log
    psqlrun(query = "UPDATE confessions SET deletedby = 1 WHERE id = %s;", data = (confessionid,), commit = True)
    psqlrun(query = "INSERT INTO auditlog (confessionid, userhash, action, method) VALUES (%s, %s, %s, %s);", data = (confessionid, "N/A", "DELETE", "ADMIN"), commit = True)

    return jsonify({"status": "success"})