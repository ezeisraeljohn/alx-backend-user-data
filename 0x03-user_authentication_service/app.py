#!/usr/bin/env python3

""" The app"""

from flask import Flask, jsonify, abort, make_response, redirect
from flask import request
from auth import Auth

app = Flask(__name__)
AUTH = Auth()


@app.route("/", methods=["Get"], strict_slashes=False)
def home():
    """This is the home of the app"""
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"], strict_slashes=False)
def create_user():
    """This creates a user"""
    email = request.form["email"]
    password = request.form["password"]

    if email and password:
        try:
            AUTH.register_user(email, password)
            return jsonify({"email": f"{email}", "message": "user created"})
        except ValueError:
            return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """Logs a user in"""
    email = request.form["email"]
    password = request.form["password"]
    user = AUTH.valid_login(email, password)
    if not user:
        abort(401)
    else:
        session_id = AUTH.create_session(email=email)
        response = jsonify({"email": f"{email}", "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response


@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    session_id = request.cookies["session_id"]
    user = AUTH.get_user_from_session_id(session_id=session_id)
    if not user:
        abort(403)
    AUTH.destroy_session(user.id)

    return redirect("/")


@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile():
    session_id = request.cookies["session_id"]
    user = AUTH.get_user_from_session_id(session_id)
    if not user:
        abort(403)
    if user:
        return jsonify({"email": f"{user.email}"}), 200


@app.route("/reset_password", methods=["GET"], strict_slashes=False)
def get_reset_password_token():
    email = request.form["email"]
    try:
        reset_token = AUTH.get_reset_password_token(email=email)
        return jsonify({"email": f"{email}", "reset_token": reset_token})
    except ValueError:
        abort(403)


@app.route("/reset_password", methods=["PUT"], strict_slashes=False)
def update_password():
    reset_token = request.form["reset_token"]
    new_password = request.form["new_password"]
    email = request.form["email"]

    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": f"{email}", "message": "Password updated"})
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
