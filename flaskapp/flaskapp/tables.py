import datetime
from flaskapp import db
from flaskapp import login_manager
from flask_login import UserMixin
import jwt
from flaskapp import app
import json



@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(264), unique=True, nullable=False)
    filepath = db.Column(db.String(264), unique=True, nullable=False)
    seen = db.Column(db.Boolean, default=False, nullable=False)
    cameraId = db.Column(db.Integer, nullable=False)
	
    def __repr__(self):
        return f"Image('{self.filename}', '{self.seen}')"


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  
    password = db.Column(db.String(60), nullable=False)
    serialId = db.Column(db.String(60), nullable=True)
    

    def __repr__(self):
        return f"User('{self.username}', '{self.email}')"

    def encode_auth_token(self, user_id):
        """
        Generates the Auth Token
        :return: string
        """
        try:
            payload = {
                'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, hours=1, minutes=1, seconds=5),
                'iat': datetime.datetime.utcnow(),
                'sub': user_id
            }
            return jwt.encode(
                payload,
                app.config.get('SECRET_KEY'),
                algorithm='HS256'
            )
        except Exception as e:
            return e

    @staticmethod
    def decode_auth_token(auth_token):
        """
        Decodes the auth token
        :param auth_token:
        :return: integer|string
        """
        try:
            payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
            return payload
        except jwt.ExpiredSignatureError:
            return 'Signature expired. Please log in again.'
        except jwt.InvalidTokenError:
            return 'Invalid token. Please log in again.'