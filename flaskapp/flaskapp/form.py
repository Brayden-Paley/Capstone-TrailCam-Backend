from flask_wtf import FlaskForm
from wtforms import StringField
from wtforms import PasswordField 
from wtforms import SubmitField 
from wtforms import BooleanField
from wtforms.validators import DataRequired 
from wtforms.validators import Length 
from wtforms.validators import Email
from wtforms.validators import EqualTo 
from wtforms.validators import ValidationError
from flaskapp.tables import User


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username duplicate')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email Duplicate')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')
