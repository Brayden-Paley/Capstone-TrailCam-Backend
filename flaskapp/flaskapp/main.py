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

### MUST HAVE PyJWT==1.7.1 INSTALLED, NOT ANY NEW VERSION!!!
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
    if auth_token:
        responseObject = {
                     'status': 'success',
                     'message': 'Successfully registered.',
                     'auth_token': auth_token.decode()
                    }
    return make_response(jsonify(responseObject)), 201

@app.route("/login", methods=['GET', 'POST'])
@cross_origin(origin='*')

def login():
    
    user = User.query.filter_by(email=request.headers.get('email')).first()
    if user and bcrypt.check_password_hash(user.password, request.headers.get('password')):
        auth_token = user.encode_auth_token(user.id)
        if auth_token:
            responseObject = {
                     'status': 'success',
                     'message': 'Successfully registered.',
                     'auth_token': auth_token.decode()
                    }
        return make_response(jsonify(responseObject)), 201
    else:
        responseObject = {
                'status': 'failure',
                'message': 'Email or password are incorrect',
            }
        return make_response(jsonify(responseObject)), 202

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/account")
@login_required
def account():
    return render_template('account.html', title='Account')


@app.route("/pictures", methods=['GET', 'POST'])
@cross_origin(origin='http://localhost:3000/main/homePage', headers=['Content- Type','Authorization'])
def pictures():
    auth_header = request.headers.get('Authorization')

    if auth_header:
            auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        if not isinstance(resp, str):
            responseObject = {
                'status': 'success',
                'images': [
                {
                'img': '/images/profile.jpeg',
                'title': 'Image11',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image2',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image3',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image4',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image5',
                'author': 'author',
                },
                {   
                'img': '/images/testPic2.jpeg',
                'title': 'Image6',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image7',
                'author': 'author',
                },{
                'img': '/images/profile.jpeg',
                'title': 'Image11',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image2',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image3',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image4',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image5',
                'author': 'author',
                },
                {   
                'img': '/images/testPic2.jpeg',
                'title': 'Image6',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image7',
                'author': 'author',
                },{
                'img': '/images/profile.jpeg',
                'title': 'Image11',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image2',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image3',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image4',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image5',
                'author': 'author',
                },
                {   
                'img': '/images/testPic2.jpeg',
                'title': 'Image6',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image7',
                'author': 'author',
                },{
                'img': '/images/profile.jpeg',
                'title': 'Image11',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image2',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image3',
                'author': 'author',
                },
                {
                'img': '/images/testPic2.jpeg',
                'title': 'Image4',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image5',
                'author': 'author',
                },
                {   
                'img': '/images/testPic2.jpeg',
                'title': 'Image6',
                'author': 'author',
                },
                {
                'img': '/images/profile.jpeg',
                'title': 'Image7',
                'author': 'author',
                }
            ]
            }
            return make_response(jsonify(responseObject)), 200
        responseObject = {
            'status': 'failure',
            'message': 'Expired token'
        }
        return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'failure',
            'message': 'Provide a valid auth token.'
        }
    return make_response(jsonify(responseObject)), 401
    

@app.route("/register-device", methods=['GET', 'POST'])
@cross_origin(origin='http://localhost:3000/main/devicesPage', headers=['Content- Type','Authorization'])
def registerDevice():
    auth_header = request.headers.get('Authorization')
    serial_id = request.headers.get('serial-id')


    if auth_header:
            auth_token = auth_header.split(" ")[1]
    else:
        auth_token = ''
    if auth_token:
        resp = User.decode_auth_token(auth_token)
        user = User.query.filter(User.id == resp.get('sub')).first()
        setattr(user, 'serialId', serial_id)
        db.session.commit()



        #user = User.query.filter_by(id=resp.get('sub')).update({'serialId': serial_id})

        if not isinstance(resp, str):
            responseObject = {
                'status': 'success',
                'message': 'successfully registered the camera!'}
            return make_response(jsonify(responseObject)), 200
        responseObject = {
            'status': 'failure',
            'message': 'Expired token'
        }
        return make_response(jsonify(responseObject)), 401
    else:
        responseObject = {
            'status': 'failure',
            'message': 'Provide a valid auth token.'
        }
    return make_response(jsonify(responseObject)), 401


