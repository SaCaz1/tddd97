from flask import Flask, jsonify, request
import database_helper
from database_helper import DatabaseErrorCode
import utils

app = Flask(__name__)

app.debug = True

@app.teardown_request
def after_request(exception):
    database_helper.close_session();

@app.route('/sign_in', methods=['POST'])
def sign_in():
    json = request.get_json()

    if "username" not in json or "password" not in json:
        return "{}", 400 #Bad Request

    if database_helper.read_logged_in_user(json['username']) is not None:
        return "{}", 409 #Conflict

    user = database_helper.read_user(json["username"])

    if user is None or user.password != json["password"]:
        return "{}", 403 #Forbidden

    token = utils.generate_token()

    result = database_helper.create_logged_in_user(json["username"], token)

    if result != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    response_body = "{token: %s}" % token

    return response_body, 200 #OK


@app.route('/sign_up', methods=['POST'])
def sign_up():
    json = request.get_json()

    for key in ["email", "password", "first_name", "family_name", "gender", "city", "country"]:
        if key not in json:
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

    user = database_helper.read_user_by_token(headers["Authorization"])

    if user is None:
        return "{}", 404 #Not Found

    if database_helper.delete_logged_in_user(user.email) != DatabaseErrorCode.Success:
        return "{}", 500 #Internal Server Error

    return "{}", 200 #OK

@app.route('/change_password', methods=["PUT"])
def change_password():
    json = request.get_json()
    headers = request.headers

    if "Authorization" not in headers or "old_password" not in json or "new_password" not in json:
        return "{}", 400 #Bad Request

    user = database_helper.read_user_by_token(headers["Authorization"])

    if user is None or user.password != json["old_password"]:
        return "{}", 403 # Forbidden

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
        return "{}", 403 #Forbidden

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
        return "{}", 403 #Forbidden


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
        return "{}", 403 #Forbidden, user not connected

    result = database_helper.read_message(user.email)


    return jsonify_messages(result), 200 #OK


@app.route('/message/get/<email>', methods=['GET'])
def get_user_messages_by_email(email):
    headers = request.headers

    if "Authorization" not in headers:
        return "{}", 400 #Bad Request

    token = headers.get("Authorization")
    user = database_helper.read_user_by_token(token)

    if user is None:
        return "{}", 403 #Forbidden, user not connected

    if database_helper.read_user(email) is None:
        return "{}", 404 #Not Found

    result = database_helper.read_message(email)

    return jsonify_messages(result), 200 #OK

def jsonify_messages(messages_result):
    message_info = []
    for message in messages_result:
        message_info.append({
        "owner": message.owner,
        "message": message.message,
        "author": message.author
        });

    return jsonify(message_info)


@app.route('/message/post', methods=['POST'])
def post_message():
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
    app.run()
