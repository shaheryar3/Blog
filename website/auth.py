from flask import Blueprint, render_template, redirect, url_for, request, flash
from . import db
from hashlib import sha256
from .models import User
from flask_login import login_user, logout_user, login_required,current_user
from werkzeug.security import generate_password_hash, check_password_hash
auth = Blueprint("auth", __name__)


@auth.route("/sign-in", methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in!", category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Password is incorrect.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template("sign-in.html",user=current_user)



@auth.route("/sign-up", methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get("email")
        username = request.form.get("username")
        password1 = request.form.get("password")
        password2 = request.form.get("password2")

        email_exists = User.query.filter_by(email=email).first()
        username_exists = User.query.filter_by(username=username).first()

        if email_exists:
            flash('Email is already in use.', category='error')
        elif username_exists:
            flash('Username is already in use.', category='error')
        elif password1 != password2:
            flash('Password don\'t match!', category='error')
        elif len(username) < 2:
            flash('Username is too short.', category='error')
        elif len(password1) < 6:
            flash('Password is too short.', category='error')
        elif len(email) < 4:
            flash("Email is invalid.", category='error')
        else:
            hashed_password = generate_password_hash(password1)
            new_user = User(email=email, username=username, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user,remember=True)
            flash('User created!')
            return redirect(url_for('views.home'))

    return render_template("sign-up.html",user=current_user)


@auth.route("/sign-out")
@login_required
def signout():
    logout_user()
    return redirect(url_for("views.home"))
