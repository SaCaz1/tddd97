from flask import Flask, jsonify, request, g
from gevent.pywsgi import WSGIServer
from geventwebsocket.handler import WebSocketHandler
import json
import database_helper
from database_helper import DatabaseErrorCode
import utils


app = Flask(__name__)

g.ws_clients = {} #user_email : ws of connected clients

app.debug = True

@app.route("/", methods = ["GET"])
def root():
    return app.send_static_file("client.html")

@app.teardown_request
def after_request(exception):
    database_helper.close_session();

@app.route('/api')
async def api():
    if request.environ.get('wsgi.websocket'):
        ws = request.environ['wsgi.websocket']

        while not ws.closed():
            message = json.loads(ws.receive())

            if message.get('type') == 'connection_open':
                token = data.get('token')
                user_email = database_helper.get_user_data_by_token(token)["email"]
                sessions = database_helper.read_all_user_sessions(user_email);

                if token not in [s.token for s in sessions]:
                    # handle not existing token somehow
                    return

                if len(sessions) > 1:
                    old_tokens = filter(lambda s: s.token != token, sessions)
                    for old_token in old_tokens:
                        database_helper.delete_logged_in_user(user_email, old_token)

                g.ws_clients[user_email].close()
                g.ws_clients[user_email] = ws
            elif message.get('type') == 'sign_out':
                token = message.get('token')
                user_email = message.get('username')

                database_helper.delete_logged_in_user(user_email, token)

                g.ws_clients[user_email].close()
                g.ws_clients[user_email] = ws

def disconnect_user_ws(username):
    try:
        g.ws_clients[username].close()
        g.ws_clients[username] = None
    catch Error as e:
        print(e)


@app.route('/sign_in', methods=['POST'])
def sign_in():
    json = request.get_json()

    if "username" not in json or "password" not in json:
        return "{}", 400 #Bad Request

    # we manage that with the websocket and the auto-logged out
    #if database_helper.read_logged_in_user(json['username']) is not None:
        #return "{}", 409 #Conflict

    user = database_helper.read_user(json["username"])

    if not user:
        return '{}', 404 # Not Found

    if user.password != json["password"]:
        return "{}", 403 # Forbidden, wrong password

    token = utils.generate_token()

    result = database_helper.create_logged_in_user(json["username"], token)

    if result != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    disconnect_user_ws(json["username"])

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
        return "{}", 400 #Bad Request

    token = headers["Authorization"]
    user = database_helper.read_user_by_token(token)

    if user is None:
        return "{}", 401 # Unauthorized

    if database_helper.delete_logged_in_user(user.email, token) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    disconnect_user_ws(user.email)

    return "{}", 200 #OK

@app.route('/change_password', methods=["PUT"])
def change_password():
    json = request.get_json()
    headers = request.headers

    if "Authorization" not in headers or "old_password" not in json or "new_password" not in json:
        return "{}", 400 #Bad Request

    user = database_helper.read_user_by_token(headers["Authorization"])

    if user.password != json["old_password"]:
        return "{}", 403 # Forbidden, wrong password

    if user is None:
        return "{}", 401 # Unauthorized, user not connected

    if database_helper.update_user_password(user.email, json["new_password"]) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    return "{}", 200 # OK

@app.route('/get_user_data_by_token', methods=['GET'])
def get_user_data_by_token():
    headers = request.headers

    if "Authorization" not in headers:
        return "{}", 400 #Bad Request

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
        return "{}", 400 #Bad Request

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
        return "{}", 400 #Bad Request

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
        return "{}", 400 #Bad Request

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
        return "{}", 400 #Bad Request

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
