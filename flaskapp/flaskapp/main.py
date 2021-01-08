from flask import render_template
from flask import url_for
from flask import flash
from flask import redirect
from flask import request
from flask import jsonify
from flask import make_response
from flaskapp import app
from flaskapp import db
from flaskapp import bcrypt
from flaskapp.form import RegistrationForm
from flaskapp.form import LoginForm
from flaskapp.tables import User
from flask_login import login_user 
from flask_login import current_user
from flask_login import logout_user 
from flask_login import login_required
from flask_cors import CORS, cross_origin


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')


@app.route("/about")
def about():
    return render_template('about.html', title='About')


@app.route("/register", methods=['GET', 'POST'])
@cross_origin(origin='*')

def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    hashed_password = bcrypt.generate_password_hash(request.headers.get('password')).decode('utf-8')
    user = User(username=request.headers.get('username'), email=request.headers.get('email'), password=hashed_password)
    emailInUse = User.query.filter_by(email=request.headers.get('email')).first()
    userInUse = User.query.filter_by(username=request.headers.get('username')).first()

    if emailInUse:
        responseObject = {
                    'status': 'failure',
                    'message': 'Email already registered.',
                }
        return make_response(jsonify(responseObject)), 202
    elif userInUse:
        responseObject = {
                    'status': 'failure',
                    'message': 'Username already registered.',
                }
        return make_response(jsonify(responseObject)), 202
    db.session.add(user)
    db.session.commit()

    #Generate JWT for authentication
    auth_token = user.encode_auth_token(user.id)
    print(auth_token)

    
    responseObject = {
                    'status': 'success',
                    'message': 'Successfully registered.',
                    'auth_token': auth_token.decode_auth_token(auth_token)
                }
    return make_response(jsonify(responseObject)), 201

@app.route("/login", methods=['GET', 'POST'])
@cross_origin(origin='*')

def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    user = User.query.filter_by(email=request.headers.get('email')).first()
    print(user)
    if user and bcrypt.check_password_hash(user.password, request.headers.get('password')):
        return jsonify(goodReturn='good')
    
    return jsonify(badReturn='bad')


@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')

#@app.route("/register-device")
#@login_required
#def register_device():
#    form = RegistrationForm()
#    if form.validate_on_submit():
#        device = Device()
