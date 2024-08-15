#!/usr/bin/env python3

""" The app"""

from flask import Flask, jsonify
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
            return jsonify({"message": "email already existed"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
