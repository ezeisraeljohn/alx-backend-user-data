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
        response = make_response()
        response.set_cookie("session_id", session_id)
    return jsonify({"email": f"{email}", "message": "logged in"})


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
    return jsonify({"email": f"{user.email}"}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
