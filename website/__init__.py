from flask import Flask


def create_app():
    app = Flask(__name__)
    app.congfig['SECRET_KEY'] = 'worldgenius'

    return app
