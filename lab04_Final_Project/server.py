from flask import Flask, jsonify, request, redirect, url_for
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from flask_socketio import SocketIO, emit, join_room, leave_room, ConnectionRefusedError
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
from flask_bcrypt import Bcrypt
import secrets
import os
import database_helper
from database_helper import DatabaseErrorCode
import utils

import hmac
import hashlib

app = Flask(__name__)
socketio = SocketIO(app)
bcrypt = Bcrypt(app)

app.debug = True

app.secret_key = os.environ.get("FLASK_SECRET_KEY", "supersekrit")
app.config["GOOGLE_OAUTH_CLIENT_ID"] = os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

google_bp = make_google_blueprint(scope=["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"], offline=True)
app.register_blueprint(google_bp, url_prefix="/login")

@app.teardown_request
def after_request(exception):
    database_helper.close_session()

@socketio.on("connect", namespace='/autologout')
def connection_open(auth):
    if not auth or not 'token' in auth or not 'public_key' in auth or not check_signature_websocket(auth["token"], auth["public_key"]):
        raise ConnectionRefusedError("unauthenticated")

    token = database_helper.read_logged_in_user(auth["public_key"]).token
    join_room(token)

def send_autologout(token):
    emit("autologout", to=token, namespace='/autologout')

@app.route("/", methods = ["GET"])
def root():
    return app.send_static_file("client.html")

@app.route("/welcome", methods = ["GET"])
@app.route("/home", methods = ["GET"])
@app.route("/browse", methods = ["GET"])
@app.route("/account", methods = ["GET"])
def alt_root():
    return redirect("/")

@app.route("/auth/google", methods=["GET"])
def google_login():
    if not google.authorized:
        return redirect(url_for("google.login"))

    try:
        return redirect_authorized_to_home()
    except:
        return redirect(url_for("google.login"))

@oauth_authorized.connect
def redirect_to_app(blueprint, token):
    blueprint.token = token
    try:
        return redirect_authorized_to_home()
    except:
        return redirect('/')

def redirect_authorized_to_home():
    resp = google.get("/oauth2/v1/userinfo")
    user_info_dto = resp.json()
    token = utils.generate_token()
    email = user_info_dto["email"]

    if database_helper.read_user(email):
        result = google_sign_in(email, token)
    else:
        result = google_sign_up(user_info_dto, token)

    if result:
        return result

    response = redirect('/')
    response.set_cookie('session_token', token, max_age=5)
    response.set_cookie('authorized_user', email, max_age=5)
    return response

def google_sign_in(email, token):
    old_sessions = database_helper.read_all_user_sessions(email)

    if database_helper.create_logged_in_user(email, token) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    if old_sessions:
        for old_session in old_sessions:
            send_autologout(old_session.token)

            if database_helper.delete_logged_in_user(old_session.username, old_session.token) != DatabaseErrorCode.Success:
                return "{}", 500 #Internal Server Error

def google_sign_up(user_info_dto, token):
    user_info = {
        "email": user_info_dto["email"],
        "password": None,
        "first_name": user_info_dto["given_name"],
        "family_name": user_info_dto["family_name"],
        "gender": None,
        "city": None,
        "country": None
    }
    if database_helper.create_user(user_info) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    if database_helper.create_logged_in_user(user_info_dto["email"], token) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error


@app.route('/sign_in', methods=['POST'])
def sign_in():
    json = request.get_json()

    if "username" not in json or "password" not in json:
        return "{}", 400 #Bad Request

    # we manage that with the websocket and the auto-logged out
    #if database_helper.read_logged_in_user(json['username']) is not None:
    #   return "{}", 409 #Conflict

    user = database_helper.read_user(json["username"])

    if not user:
        return '{}', 404 # Not Found

    if not validate_password(user.password, json["password"]):
        return "{}", 401 # Unauthenticated, wrong password

    old_sessions = database_helper.read_all_user_sessions(json['username'])

    token = utils.generate_token()
    result = database_helper.create_logged_in_user(json["username"], token)

    if result != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error


    if old_sessions:
        for old_session in old_sessions:
            send_autologout(old_session.token)

            if database_helper.delete_logged_in_user(old_session.username, old_session.token) != DatabaseErrorCode.Success:
                return "{}", 500 #Internal Server Error

    response_body = {"token" : token}

    return jsonify(response_body), 200 #OK

@app.route('/sign_up', methods=['POST'])
def sign_up():
    json = request.get_json()

    for key in ["email", "password", "first_name", "family_name", "gender", "city", "country"]:
        if key not in json or len(json[key]) > 255:
            return "{}", 400 #Bad Request

    if len(json["password"]) < 3:
        return "{}", 400 #Bad Request

    if database_helper.read_user(json["email"]) is not None:
        return "{}", 409 #Conflict

    user_info = {
        "email": json["email"],
        "password": generate_secure_password(json["password"]),
        "first_name": json["first_name"],
        "family_name": json["family_name"],
        "gender": json["gender"],
        "city": json["city"],
        "country": json["country"]
    }

    result = database_helper.create_user(user_info)

    if result != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    return jsonify(user_info), 201 #Created successfully

@app.route('/sign_out', methods=['DELETE'])
def sign_out():
    check_signature_result = check_signature()
    if check_signature_result:
        return check_signature_result

    user_email = request.headers['Public-Key']
    token = database_helper.read_logged_in_user(user_email).token

    if database_helper.delete_logged_in_user(user_email, token) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    if google.authorized:
        google_token = google_bp.token["access_token"]

        _ = google.post(
            "https://accounts.google.com/o/oauth2/revoke",
            params={"token": google_token},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )

    return "{}", 200 #OK

@app.route('/change_password', methods=["PUT"])
def change_password():
    check_signature_result = check_signature()
    if check_signature_result:
        return check_signature_result

    json = request.get_json()
    if  "old_password" not in json["data"] or "new_password" not in json["data"]:
        return "{}", 400 #Bad Request

    user = database_helper.read_user(json["public_key"])

    if not validate_password(user.password, json["data"]["old_password"]):
        return "{}", 401 # Unauthenticated, wrong password

    if database_helper.update_user_password(user.email, generate_secure_password(json["data"]["new_password"])) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    return "{}", 200 # OK

@app.route('/get_user_data', methods=['GET', 'POST'])
def get_user_data():
    check_signature_result = check_signature()
    if check_signature_result:
        return check_signature_result

    user = database_helper.read_user(request.headers['Public-Key'])

    user_dto = {
        "email": user.email,
        "first_name": user.first_name,
        "family_name": user.family_name,
        "gender": user.gender,
        "city": user.city,
        "country": user.country
    }

    return jsonify(user_dto), 200 #OK


@app.route('/get_user_data/<email>', methods=['GET'])
def get_user_data_by_email(email):
    check_signature_result = check_signature()
    if check_signature_result:
        return check_signature_result

    user = database_helper.read_user(email)

    if user is None:
        return "{}", 404 #Not Found

    user_dto = {
        "email": user.email,
        "first_name": user.first_name,
        "family_name": user.family_name,
        "gender": user.gender,
        "city": user.city,
        "country": user.country
    }

    return jsonify(user_dto), 200 #Success


@app.route('/message/get', methods=['GET'])
def get_user_messages_by_token():
    check_signature_result = check_signature()
    if check_signature_result:
        return check_signature_result

    email = request.headers["Public-Key"]
    messages = database_helper.read_message(email)

    return jsonify_messages(reversed(messages)), 200 #OK


@app.route('/message/get/<email>', methods=['GET'])
def get_user_messages_by_email(email):
    check_signature_result = check_signature()
    if check_signature_result:
        return check_signature_result

    if database_helper.read_user(email) is None:
        return "{}", 404 #Not Found

    result = database_helper.read_message(email)

    return jsonify_messages(reversed(result)), 200 #OK

def jsonify_messages(messages_result):
    message_info = [{"author" : m.author,
                     "owner" : m.owner,
                     "content" : m.message } for m in messages_result]
    return jsonify(message_info)


@app.route('/message/post', methods=['POST'])
def post_message():
    check_signature_result = check_signature()
    if check_signature_result:
        return check_signature_result

    message_data = request.get_json()["data"]
    if "owner" not in message_data or "message" not in message_data or "author" not in message_data:
        return "{}", 400 #Bad Request

    result = database_helper.create_message(message_data)

    if result is DatabaseErrorCode.IntegrityError or len(message_data["message"]) > 1000:
        return "{}", 400   #Bad request, owner/author not valid or over caracter limits

    if result is not DatabaseErrorCode.Success:
        return "{}", 500  #Internal server error

    return "{}", 201    #Created

# SECURITY FUNCITONS

def generate_secure_password(password):
    salt = secrets.token_hex(16)
    hashed_password = bcrypt.generate_password_hash(password + salt).decode('utf-8')
    return (hashed_password + salt)

def validate_password(psw_stored, psw_to_validate):
    salt = psw_stored[-32:]
    psw_hashed = psw_stored[:-32]
    print(salt)
    return bcrypt.check_password_hash(psw_hashed, psw_to_validate + salt)

def check_signature():
    headers = request.headers
    if "Authorization" not in headers:
        return "{}", 401 #Unauthenticated

    incoming_signature = headers["Authorization"]

    if request.method in ['GET', 'DELETE']:
        if 'Public-Key' not in headers:
            return '{}', 400 #Bad Request
        public_key = headers['Public-Key']
    else:
        if "public_key" not in request.json:
            return "{}", 400 #Bad Request TODO: check if valid status code
        public_key = request.json["public_key"]

    user_session = database_helper.read_logged_in_user(public_key)
    if user_session is None:
        return "{}", 401 #Unauthenticated

    if request.method in ['GET', 'DELETE']:
        message = public_key + user_session.token + request.method + request.path
    else:
        message = request.data.decode("utf-8") + user_session.token

    private_key = bytes(user_session.token , 'utf-8')
    message = bytes(message, 'utf-8')
    local_signature = hmac.new(private_key, msg = message, digestmod = hashlib.sha256).hexdigest()

    if local_signature != incoming_signature:
        return "{}", 401 #Unauthenticated

    return None

def check_signature_websocket(incoming_signature, public_key):
    user_session = database_helper.read_logged_in_user(public_key)
    if user_session is None:
        False

    message = public_key + user_session.token

    private_key = bytes(user_session.token , 'utf-8')
    message = bytes(message, 'utf-8')
    local_signature = hmac.new(private_key, msg = message, digestmod = hashlib.sha256).hexdigest()

    return (local_signature == incoming_signature)

if __name__ == '__main__':
    http_server = WSGIServer(('0.0.0.0', 5000), app, handler_class=WebSocketHandler)
    http_server.serve_forever()
