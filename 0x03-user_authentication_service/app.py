#!/usr/bin/env python3

""" The app"""

from flask import Flask, jsonify

app = Flask(__name__)


@app.route("/", methods=["Get"], strict_slashes=False)
def home():
    """This is the home of the app"""
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
