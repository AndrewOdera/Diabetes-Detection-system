from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import numpy as np
import csv
import io
import matplotlib.pyplot as plt
import base64
from io import StringIO
import pickle
from sklearn.linear_model import LogisticRegression
from flask_login import login_required, current_user
from flask_login import LoginManager


clf = LogisticRegression()


app = Flask(
    __name__, template_folder='/home/joseph/Documents/Diabetes System/templates')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'mysecretkey'
model = pickle.load(open("model.pkl", "rb"))
db = SQLAlchemy(app)
# --------------------==============database===============================================


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
# ----------------=============================route for the app=====================


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/about')
def about():
    return render_template('about.html')
# ===============================================signup===========================session


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect(url_for('signup'))
        else:
            new_user = User(username=username, email=email,
                            password=generate_password_hash(password))
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully')
            return redirect(url_for('login'))
    return render_template('signup.html')
# -==================================================login session-------=========================


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password')
            return redirect(url_for('login'))
    return render_template('login.html')
# ==================================================logout session---------===============


@app.route('/logout')
def logout():
    session.clear()
    flash('You have logged out')
    return redirect(url_for('login'))

# ----------------------------------Dashboard-+++++++++++++---------------------------------#


@app.route('/dashboard', methods=['GET', 'POST'])
def dashboard():
    user_id = session.get('user_id')
    if user_id:
        user = User.query.get(user_id)
        prediction_text = ''
        if request.method == 'POST':
            text1 = request.form['1']
            text2 = request.form['2']
            text3 = request.form['3']
            text4 = request.form['4']
            text5 = request.form['5']
            text6 = request.form['6']
            text7 = request.form['7']
            text8 = request.form['8']

            row_df = pd.DataFrame([pd.Series([text1,text2,text3, text4, text5, text6,text7,text8])])

            prediction = model.predict_proba(row_df)
            output = '{0:.{1}f}'.format(prediction[0][1], 2)
            output = float(output) * 100

            if output > 40.0:
                prediction_text = f'You have a positive diabetes detection.\nProbability of having Diabetes is {output}%'
            else:
                prediction_text = f'You are safe.\n Probability of having diabetes is {output}%'

        return render_template('dashboard.html', user=user, prediction=prediction_text)
    else:
        return redirect(url_for('login'))

#________++++++++++++++++++++++++++++++++results---===========================

@app.route('/results')
@login_required
def results():
    prediction = request.args.get('pred')
    return render_template("results.html", user=current_user, pred=prediction)
#############################################################################

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
