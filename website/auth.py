from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
import hashlib
import os
from flask_login import login_user, login_required, logout_user, current_user


auth = Blueprint('auth', __name__)


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if verify_password(user.password, password):
                flash('Logged in successfully', category='success')
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect Password', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("login.html", boolean=True)


@auth.route('/logout')
def logout():
    return "<p>logout</p>"


@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.', category='error')

        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords do not match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            hashed_password = hash_password(password1)
            new_user = User(email=email, first_name=first_name,
                            password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            flash('Account Created', category='success')
            return redirect(url_for('views.home'))

    return render_template("sign_up.html")


# def hash_password(password):
#     salt = os.urandom(32)  # generate random salt
#     key = hashlib.pbkdf2_hmac('sha256', password.encode(
#         'utf-8'), salt, 100000)  # hash the pass
#     return salt + key

def hash_password(password):
    # Generate a random salt
    salt = os.urandom(16)
    # Create the password hash using SHA-256
    password_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt, 100000)
    return salt + password_hash


def verify_password(stored_password, input_password):
    salt = stored_password[:16]
    stored_password_hash = stored_password[16:]
    input_password_hash = hashlib.pbkdf2_hmac(
        'sha256', input_password.encode('utf-8'), salt, 100000)
    return stored_password_hash == input_password_hash
