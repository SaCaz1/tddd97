from flask import Flask, jsonify, request, redirect, url_for
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
from flask_socketio import SocketIO, emit, join_room, leave_room, ConnectionRefusedError
from flask_dance.contrib.google import make_google_blueprint, google
from flask_dance.consumer import oauth_authorized
import json
import os
import database_helper
from database_helper import DatabaseErrorCode
import utils


app = Flask(__name__)
socketio = SocketIO(app)

app.debug = True

app.secret_key = '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' #os.environ.get("FLASK_SECRET_KEY", "supersekrit")
app.config["GOOGLE_OAUTH_CLIENT_ID"] =  '1019540628960-bgkqval4a7iceas5tattfc65v8ju2icc.apps.googleusercontent.com'#os.environ.get("GOOGLE_OAUTH_CLIENT_ID")
app.config["GOOGLE_OAUTH_CLIENT_SECRET"] = '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' #os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET")
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config["SESSION_REFRESH_EACH_REQUEST"] = False
google_bp = make_google_blueprint(scope=["openid", "https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"])
app.register_blueprint(google_bp, url_prefix="/auth")

@socketio.on("connect", namespace='/autologout')
def connection_open(auth):
    if not auth or not 'token' in auth or database_helper.read_user_by_token(auth["token"]) is None:
        raise ConnectionRefusedError("unauthenticated")
    join_room(auth["token"])

def send_autologout(token):
    emit("autologout", to=token, namespace='/autologout')


@app.route("/", methods = ["GET"])
def root():
    response = app.send_static_file("client.html")
    # response.delete_cookie('session_token')
    return response


@app.route("/home", methods = ["GET"])
@app.route("/browse", methods = ["GET"])
@app.route("/account", methods = ["GET"])
def alt_root():
    response = app.send_static_file("client.html")
    # response.delete_cookie('session_token')
    return response


@app.route("/welcome", methods = ["GET"])
def welcome_root():
    return redirect("/")


@app.teardown_request
def after_request(exception):
    database_helper.close_session();

@google_bp.route("/google", methods=["GET", "POST"])
def google_login():
    return redirect(url_for("auth.google"))

@oauth_authorized.connect
def redirect_to_home(bluepring, token):
    # retrieve email address
    # if account is created - go to / with newly generated sesison token
    # if not - create user account and go to / with newly generated sesion token
    resp = google.get("/oauth2/v1/userinfo")
    user_info_dto = resp.json()
    token = utils.generate_token()

    if database_helper.read_user(user_info_dto["email"]):
        google_sign_in(user_info_dto["email"], token)

    else:
        google_sign_up(user_info_dto, token)

    response = redirect('/')
    response.set_cookie('session_token', token)
    return response

def google_sign_in(email, token):
    old_session = database_helper.read_logged_in_user(email)
    result = database_helper.create_logged_in_user(email, token)

    if result != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    if old_session:
        if database_helper.delete_logged_in_user(old_session.username, old_session.token) != DatabaseErrorCode.Success:
            return "{}", 500 #Internal Server Error

        send_autologout(old_session.token)

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
        database_helper.create_user(user_info)
        result = database_helper.create_logged_in_user(user_info_dto["email"], token)

        if result != DatabaseErrorCode.Success:
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

    if user.password != json["password"]:
        return "{}", 401 # Unauthenticated, wrong password

    old_session = database_helper.read_logged_in_user(json['username'])

    token = utils.generate_token()
    result = database_helper.create_logged_in_user(json["username"], token)

    if result != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error


    if old_session:
        if database_helper.delete_logged_in_user(old_session.username, old_session.token) != DatabaseErrorCode.Success:
            return "{}", 500 #Internal Server Error

        send_autologout(old_session.token)

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
        "password": json["password"],
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
    headers = request.headers
    if "Authorization" not in headers:
        return "{}", 401 #Unauthenticated

    token = headers["Authorization"]
    user = database_helper.read_user_by_token(token)

    if user is None:
        return "{}", 401 # Unauthorized

    if database_helper.delete_logged_in_user(user.email, token) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    return "{}", 200 #OK

@app.route('/change_password', methods=["PUT"])
def change_password():
    json = request.get_json()
    headers = request.headers

    if "Authorization" not in headers:
        return "{}", 401 #Unauthenticated

    if  "old_password" not in json or "new_password" not in json:
        return "{}", 400 #Bad Request

    user = database_helper.read_user_by_token(headers["Authorization"])

    if user.password != json["old_password"]:
        return "{}", 401 # Unauthenticated, wrong password

    if user is None:
        return "{}", 401 # Unauthorized, user not connected

    if database_helper.update_user_password(user.email, json["new_password"]) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    return "{}", 200 # OK

@app.route('/get_user_data_by_token', methods=['GET'])
def get_user_data_by_token():
    headers = request.headers

    if "Authorization" not in headers:
        return "{}", 401 #Unauthorized

    token = headers.get("Authorization")
    user = database_helper.read_user_by_token(token)

    if user is None:
        return "{}", 401 #Unauthorized, user not connected

    user_info = {
        "email": user.email,
        "first_name": user.first_name,
        "family_name": user.family_name,
        "gender": user.gender,
        "city": user.city,
        "country": user.country
    }

    return jsonify(user_info), 200 #OK


@app.route('/get_user_data/<email>', methods=['GET'])
def get_user_data_by_email(email):
    headers = request.headers

    if "Authorization" not in headers:
        return "{}", 401 #Unauthenticated

    token = headers.get("Authorization")

    if database_helper.read_user_by_token(token) is None:
        return "{}", 401 #Unauthorized, user not connected

    user = database_helper.read_user(email)

    if user is None:
        return "{}", 404 #Not Found
    else:
        user_info = {
            "email": user.email,
            "first_name": user.first_name,
            "family_name": user.family_name,
            "gender": user.gender,
            "city": user.city,
            "country": user.country
        }

        return jsonify(user_info), 200 #Success


@app.route('/message/get', methods=['GET'])
def get_user_messages_by_token():
    headers = request.headers

    if "Authorization" not in headers:
        return "{}", 401 #Unauthenticated

    token = headers.get("Authorization")

    user = database_helper.read_user_by_token(token)
    if user is None:
        return "{}", 401 #Unauthorized, user not connected

    result = database_helper.read_message(user.email)

    return jsonify_messages(reversed(result)), 200 #OK


@app.route('/message/get/<email>', methods=['GET'])
def get_user_messages_by_email(email):
    headers = request.headers

    if "Authorization" not in headers:
        return "{}", 401 #Unauthenticated

    token = headers.get("Authorization")
    user = database_helper.read_user_by_token(token)

    if user is None:
        return "{}", 401 #Unauthorized, user not connected

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
    headers = request.headers
    if "Authorization" not in headers:
        return "{}", 401 #Unauthenticated

    if database_helper.read_user_by_token(headers["Authorization"]) is None:
        return "{}", 401 # Unauthorized


    json = request.get_json()
    if "owner" not in json or "message" not in json or "author" not in json:
        return "{}", 400 #Bad Request

    result = database_helper.create_message(json)

    if result is DatabaseErrorCode.IntegrityError or len(json["message"]) > 1000:
        return "{}", 400   #Bad request, owner/author not valid or over caracter limits

    if result is not DatabaseErrorCode.Success:
        return "{}", 500  #Internal server error

    return "{}", 201    #Created

if __name__ == '__main__':
    http_server = WSGIServer(('0.0.0.0', 5000), app, handler_class=WebSocketHandler)
    http_server.serve_forever()
