from flask import flash, current_app
from flask_wtf import RecaptchaField
from flask_security.forms import RegisterForm, StringField, Required,ConfirmRegisterForm,ForgotPasswordForm, LoginForm, validators
from flask_security import UserMixin, RoleMixin
from .shared import db
from classes import Sec
from globals import globalvars

import datetime

class ExtendedRegisterForm(RegisterForm):
    username = StringField('username', [validators.Regexp(r'^[\w]+$', message='Username contains invalid characters')])
    email = StringField('email', [Required()])
    if globalvars.recaptchaEnabled is True:
        recaptcha = RecaptchaField()

    def validate(self):
        success = True
        if not super(ExtendedRegisterForm, self).validate():
            success = False
        if db.session.query(User).filter(User.username == self.username.data.strip()).first():
            self.username.errors.append("Username already taken")
            success = False
        if db.session.query(User).filter(User.email == self.email.data.strip()).first():
            self.email.errors.append("Email address already taken")
            success = False
        return success

class ExtendedConfirmRegisterForm(ConfirmRegisterForm):
    username = StringField('username', [validators.Regexp(r'^[\w]+$', message='Username contains invalid characters')])
    email = StringField('email', [Required()])
    if globalvars.recaptchaEnabled is True:
        recaptcha = RecaptchaField()

    def validate(self):
        success = True
        if not super(ExtendedConfirmRegisterForm, self).validate():
            success = False
        if db.session.query(User).filter(User.username == self.username.data.strip()).first():
            self.username.errors.append("Username already taken")
            success = False
        if db.session.query(User).filter(User.email == self.email.data.strip()).first():
            self.email.errors.append("Email address already taken")
            success = False
        return success

class OSPLoginForm(LoginForm):

    def validate(self):
        isvalid = False
        userQuery = Sec.User.query.filter_by(username=self.email.data.strip(), authType=0).first()
        if userQuery is not None:
            isvalid = True
        if isvalid is False:
            userQuery = Sec.User.query.filter_by(email=self.email.data.strip(), authType=0).first()
            if userQuery is not None:
                isvalid = True
        if isvalid is True:
            response = super(OSPLoginForm, self).validate()
            return response
        else:
            flash("Invalid Username or Password","error")
            return False

roles_users = db.Table('roles_users',
        db.Column('id', db.Integer(), primary_key=True),
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))
    default = db.Column(db.Boolean)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    uuid = db.Column(db.String(255))
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    fs_uniquifier = db.Column(db.String(255))
    password = db.Column(db.String(255))
    biography = db.Column(db.String(4096))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(100))
    current_login_ip = db.Column(db.String(100))
    login_count = db.Column(db.Integer)
    pictureLocation = db.Column(db.String(255))
    authType = db.Column(db.Integer)
    oAuthID = db.Column(db.String(2048))
    oAuthProvider = db.Column(db.String(40))
    xmppToken = db.Column(db.String(64))
    oAuthToken = db.relationship('OAuth2Token', backref='userObj', lazy='joined')
    roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
    invites = db.relationship('invitedViewer', backref='user', lazy="dynamic")
    channels = db.relationship('Channel', backref='owner', lazy="dynamic")
    notifications = db.relationship('userNotification', backref='user', lazy="dynamic")
    subscriptions = db.relationship('channelSubs', backref='user', cascade="all, delete-orphan", lazy="dynamic")

    def serialize(self):
        return {
            'id': str(self.id),
            'uuid': self.uuid,
            'username': self.username,
            'biography': self.biography,
            'pictureLocation': "/images/" + str(self.pictureLocation),
            'channels': [obj.channelLoc for obj in self.channels],
            'page': '/profile/' + str(self.username) + '/'
        }

class OAuth2Token(db.Model):
    __tablename__ = "OAuth2Token"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(40))
    token_type = db.Column(db.String(40))
    access_token = db.Column(db.String(2048))
    refresh_token = db.Column(db.String(2048))
    expires_at = db.Column(db.Integer)
    user = db.Column(db.ForeignKey(User.id))

    def __init__(self, name, token_type, access_token, refresh_token, expires_at, user):
        self.name = name
        self.token_type = token_type
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.expires_at = expires_at
        self.user = user

    def to_token(self):
        return dict(
            access_token=self.access_token,
            token_type=self.token_type,
            refresh_token=self.refresh_token,
            expires_at=self.expires_at,
        )

class Guest(db.Model):
    __tablename__ = "Guest"
    id = db.Column(db.Integer, primary_key=True)
    UUID = db.Column(db.String(255))
    last_active_at = db.Column(db.DateTime())
    last_active_ip = db.Column(db.String(100))

    def __init__(self, UUID, current_login_ip):
        self.UUID = UUID
        self.last_active_at = datetime.datetime.now()
        self.last_active_ip = current_login_ip
