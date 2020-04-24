# -*- coding: UTF-8 -*-
from gevent import monkey
monkey.patch_all(thread=True)

# Import Standary Python Libraries
import uuid
import socket
import shutil
import os
import subprocess
import time
import sys
import random
import json
import hashlib
import logging
import datetime

# Import 3rd Party Libraries
import git
from flask import Flask, redirect, request, abort, render_template, url_for, flash, send_from_directory, Response, session
from flask_session import Session
from flask_security import Security, SQLAlchemyUserDatastore, login_required, current_user, roles_required
from flask_security.utils import hash_password
from flask_security.signals import user_registered
from flask_security import utils
from sqlalchemy.sql.expression import func
from flask_socketio import emit, join_room, leave_room
from flask_uploads import UploadSet, configure_uploads, IMAGES, patch_request_class
#from flask_mail import Mail, Message
from flask_migrate import Migrate, migrate, upgrade
from flaskext.markdown import Markdown
from flask_debugtoolbar import DebugToolbarExtension
from flask_cors import CORS
import xmltodict
from werkzeug.middleware.proxy_fix import ProxyFix

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis
from apscheduler.schedulers.background import BackgroundScheduler
import psutil
import requests

# Import Paths
cwp = sys.path[0]
sys.path.append(cwp)
sys.path.append('./classes')

#----------------------------------------------------------------------------#
# Configuration Imports
#----------------------------------------------------------------------------#
from conf import config

#----------------------------------------------------------------------------#
# Global Vars Imports
#----------------------------------------------------------------------------#
from globals import globalvars

#----------------------------------------------------------------------------#
# App Configuration Setup
#----------------------------------------------------------------------------#
coreNginxRTMPAddress = "127.0.0.1"

sysSettings = None

app = Flask(__name__)

# Flask App Environment Setup
app.debug = config.debugMode
app.wsgi_app = ProxyFix(app.wsgi_app)
app.jinja_env.cache = {}
app.config['WEB_ROOT'] = globalvars.videoRoot
app.config['SQLALCHEMY_DATABASE_URI'] = config.dbLocation
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
if config.dbLocation[:6] != "sqlite":
    app.config['SQLALCHEMY_MAX_OVERFLOW'] = -1
    app.config['SQLALCHEMY_POOL_RECYCLE'] = 600
    app.config['SQLALCHEMY_POOL_TIMEOUT'] = 1200
    app.config['MYSQL_DATABASE_CHARSET'] = "utf8"
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {'encoding': 'utf8', 'pool_use_lifo': 'True', 'pool_size': 20, "pool_pre_ping": True}
else:
    pass
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_COOKIE_NAME'] = 'ospSession'
app.config['SECRET_KEY'] = config.secretKey
app.config['SECURITY_PASSWORD_HASH'] = "pbkdf2_sha512"
app.config['SECURITY_PASSWORD_SALT'] = config.passwordSalt
app.config['SECURITY_REGISTERABLE'] = config.allowRegistration
app.config['SECURITY_RECOVERABLE'] = True
app.config['SECURITY_CONFIRMABLE'] = config.requireEmailRegistration
app.config['SECURITY_SEND_REGISTER_EMAIL'] = config.requireEmailRegistration
app.config['SECURITY_CHANGABLE'] = True
app.config['SECURITY_USER_IDENTITY_ATTRIBUTES'] = ['username','email']
app.config['SECURITY_FLASH_MESSAGES'] = True
app.config['UPLOADED_PHOTOS_DEST'] = app.config['WEB_ROOT'] + 'images'
app.config['UPLOADED_DEFAULT_DEST'] = app.config['WEB_ROOT'] + 'images'
app.config['SECURITY_POST_LOGIN_VIEW'] = 'main_page'
app.config['SECURITY_POST_LOGOUT_VIEW'] = 'main_page'
app.config['SECURITY_MSG_EMAIL_ALREADY_ASSOCIATED'] = ("Username or Email Already Associated with an Account", "error")
app.config['SECURITY_MSG_INVALID_PASSWORD'] = ("Invalid Username or Password", "error")
app.config['SECURITY_MSG_INVALID_EMAIL_ADDRESS'] = ("Invalid Username or Password","error")
app.config['SECURITY_MSG_USER_DOES_NOT_EXIST'] = ("Invalid Username or Password","error")
app.config['SECURITY_MSG_DISABLED_ACCOUNT'] = ("Account Disabled","error")
app.config['VIDEO_UPLOAD_TEMPFOLDER'] = app.config['WEB_ROOT'] + 'videos/temp'
app.config["VIDEO_UPLOAD_EXTENSIONS"] = ["PNG", "MP4"]

#----------------------------------------------------------------------------#
# Modal Imports
#----------------------------------------------------------------------------#

from classes import Stream
from classes import Channel
from classes import dbVersion
from classes import RecordedVideo
from classes import topics
from classes import settings
from classes import banList
from classes import Sec
from classes import upvotes
from classes import apikey
from classes import views
from classes import comments
from classes import invites
from classes import webhook
from classes import logs
from classes import subscriptions
from classes import notifications

#----------------------------------------------------------------------------#
# Function Imports
#----------------------------------------------------------------------------#
from functions import database
from functions import system
from functions import securityFunc
from functions import cache
from functions import themes
from functions import votes
from functions import videoFunc
from functions import webhookFunc
from functions import commentsFunc
from functions import subsFunc

#----------------------------------------------------------------------------#
# Blueprint Filter Imports
#----------------------------------------------------------------------------#
from blueprints.apiv1 import api_v1
from blueprints.streamers import streamers_bp
from blueprints.channels import channels_bp
from blueprints.topics import topics_bp
from blueprints.play import play_bp
from blueprints.clip import clip_bp
from blueprints.upload import upload_bp

#----------------------------------------------------------------------------#
# Template Filter Imports
#----------------------------------------------------------------------------#
from functions import templateFilters

#----------------------------------------------------------------------------#
# Begin App Initialization
#----------------------------------------------------------------------------#
# Initialize Flask-Limiter
if config.redisPassword == '' or config.redisPassword is None:
    app.config["RATELIMIT_STORAGE_URL"] = "redis://" + config.redisHost + ":" + str(config.redisPort)
else:
    app.config["RATELIMIT_STORAGE_URL"] = "redis://" + config.redisPassword + "@" + config.redisHost + ":" + str(config.redisPort)
logger = logging.getLogger('gunicorn.error').handlers

# Initialize Redis for Flask-Session
if config.redisPassword != '':
    r = redis.Redis(host=config.redisHost, port=config.redisPort)
    app.config["SESSION_REDIS"] = r
else:
    r = redis.Redis(host=config.redisHost, port=config.redisPort, password=config.redisPassword)
    app.config["SESSION_REDIS"] = r
r.flushdb()

# Initialize Flask-SocketIO
from classes.shared import socketio
if config.redisPassword != '':
    socketio.init_app(app, logger=False, engineio_logger=False, message_queue="redis://" + config.redisHost + ":" + str(config.redisPort),  cors_allowed_origins=[])
else:
    socketio.init_app(app, logger=False, engineio_logger=False, message_queue="redis://" + config.redisPassword + "@" + config.redisHost + ":" + str(config.redisPort),  cors_allowed_origins=[])

limiter = Limiter(app, key_func=get_remote_address)

# Begin Database Initialization
from classes.shared import db

db.init_app(app)
db.app = app
migrateObj = Migrate(app, db)

# Initialize Flask-Session
Session(app)

# Initialize Flask-CORS Config
cors = CORS(app, resources={r"/apiv1/*": {"origins": "*"}})

# Initialize Debug Toolbar
toolbar = DebugToolbarExtension(app)

# Initialize Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, Sec.User, Sec.Role)
security = Security(app, user_datastore, register_form=Sec.ExtendedRegisterForm, confirm_register_form=Sec.ExtendedConfirmRegisterForm, login_form=Sec.OSPLoginForm)

# Initialize Flask-Uploads
photos = UploadSet('photos', IMAGES)
configure_uploads(app, photos)
patch_request_class(app)

# Initialize Flask-Markdown
md = Markdown(app, extensions=['tables'])

# Initialize Scheduler
scheduler = BackgroundScheduler()
#scheduler.add_job(func=processAllHubConnections, trigger="interval", seconds=180)
scheduler.start()

# Attempt Database Load and Validation
try:
    database.init(app, user_datastore)
except:
    print("DB Load Fail due to Upgrade or Issues")

# Initialize Flask-Mail
from classes.shared import email

email.init_app(app)
email.app = app

# Register all Blueprints
app.register_blueprint(api_v1)
app.register_blueprint(channels_bp)
app.register_blueprint(play_bp)
app.register_blueprint(clip_bp)
app.register_blueprint(streamers_bp)
app.register_blueprint(topics_bp)
app.register_blueprint(upload_bp)

# Initialize Jinja2 Template Filters
templateFilters.init(app)

# Log Successful Start and Transfer Control
system.newLog("0", "OSP Started Up Successfully - version: " + str(globalvars.version))

#----------------------------------------------------------------------------#
# Jinja 2 Gloabl Environment Functions
#----------------------------------------------------------------------------#
app.jinja_env.globals.update(check_isValidChannelViewer=securityFunc.check_isValidChannelViewer)
app.jinja_env.globals.update(check_isCommentUpvoted=votes.check_isCommentUpvoted)

#----------------------------------------------------------------------------#
# Context Processors
#----------------------------------------------------------------------------#

@app.context_processor
def inject_notifications():
    notificationList = []
    if current_user.is_authenticated:
        userNotificationQuery = notifications.userNotification.query.filter_by(userID=current_user.id).all()
        for entry in userNotificationQuery:
            if entry.read is False:
                notificationList.append(entry)
        notificationList.sort(key=lambda x: x.timestamp, reverse=True)
    return dict(notifications=notificationList)


@app.context_processor
def inject_sysSettings():

    sysSettings = db.session.query(settings.settings).first()
    allowRegistration = config.allowRegistration

    return dict(sysSettings=sysSettings, allowRegistration=allowRegistration)

@app.context_processor
def inject_ownedChannels():
    if current_user.is_authenticated:
        if current_user.has_role("Streamer"):
            ownedChannels = Channel.Channel.query.filter_by(owningUser=current_user.id).with_entities(Channel.Channel.id, Channel.Channel.channelLoc, Channel.Channel.channelName).all()

            return dict(ownedChannels=ownedChannels)
        else:
            return dict(ownedChannels=[])
    else:
        return dict(ownedChannels=[])

#----------------------------------------------------------------------------#
# Flask Signal Handlers.
#----------------------------------------------------------------------------#

@user_registered.connect_via(app)
def user_registered_sighandler(app, user, confirm_token):
    default_role = user_datastore.find_role("User")
    user_datastore.add_role_to_user(user, default_role)
    webhookFunc.runWebhook("ZZZ", 20, user=user.username)
    system.newLog(1, "A New User has Registered - Username:" + str(user.username))
    if config.requireEmailRegistration:
        flash("An email has been sent to the email provided. Please check your email and verify your account to activate.")
    db.session.commit()

#----------------------------------------------------------------------------#
# Error Handlers.
#----------------------------------------------------------------------------#
@app.errorhandler(404)
def page_not_found(e):
    sysSettings = settings.settings.query.first()
    system.newLog(0, "404 Error - " + str(request.url))
    return render_template(themes.checkOverride('404.html'), sysSetting=sysSettings), 404

@app.errorhandler(500)
def page_not_found(e):
    sysSettings = settings.settings.query.first()
    system.newLog(0,"500 Error - " + str(request.url))
    return render_template(themes.checkOverride('500.html'), sysSetting=sysSettings, error=e), 500

#----------------------------------------------------------------------------#
# Additional Handlers.
#----------------------------------------------------------------------------#

@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

#----------------------------------------------------------------------------#
# Route Controllers.
#----------------------------------------------------------------------------#

@app.route('/')
def main_page():

    firstRunCheck = system.check_existing_settings()

    if firstRunCheck is False:
        return render_template('/firstrun.html')

    else:
        activeStreams = Stream.Stream.query.order_by(Stream.Stream.currentViewers).all()

        randomRecorded = RecordedVideo.RecordedVideo.query.filter_by(pending=False, published=True)\
            .join(Channel.Channel, RecordedVideo.RecordedVideo.channelID == Channel.Channel.id)\
            .join(Sec.User, RecordedVideo.RecordedVideo.owningUser == Sec.User.id)\
            .with_entities(RecordedVideo.RecordedVideo.id, RecordedVideo.RecordedVideo.owningUser, RecordedVideo.RecordedVideo.views, RecordedVideo.RecordedVideo.length, RecordedVideo.RecordedVideo.thumbnailLocation, RecordedVideo.RecordedVideo.channelName, RecordedVideo.RecordedVideo.topic, RecordedVideo.RecordedVideo.videoDate, Sec.User.pictureLocation, Channel.Channel.protected, Channel.Channel.channelName.label('ChanName'))\
            .order_by(func.random()).limit(16)

        randomClips = RecordedVideo.Clips.query.filter_by(published=True)\
            .join(RecordedVideo.RecordedVideo, RecordedVideo.Clips.parentVideo == RecordedVideo.RecordedVideo.id)\
            .join(Channel.Channel, Channel.Channel.id==RecordedVideo.RecordedVideo.channelID)\
            .join(Sec.User, Sec.User.id == Channel.Channel.owningUser)\
            .with_entities(RecordedVideo.Clips.id, RecordedVideo.Clips.thumbnailLocation, Channel.Channel.owningUser, RecordedVideo.Clips.views, RecordedVideo.Clips.length, RecordedVideo.Clips.clipName, Channel.Channel.protected, Channel.Channel.channelName, RecordedVideo.RecordedVideo.topic, RecordedVideo.RecordedVideo.videoDate, Sec.User.pictureLocation)\
            .order_by(func.random()).limit(16)

        return render_template(themes.checkOverride('index.html'), streamList=activeStreams, randomRecorded=randomRecorded, randomClips=randomClips)

@app.route('/view/<loc>/')
def view_page(loc):
    sysSettings = settings.settings.query.first()

    requestedChannel = Channel.Channel.query.filter_by(channelLoc=loc).first()

    if requestedChannel is not None:

        if requestedChannel.protected and sysSettings.protectionEnabled:
            if not securityFunc.check_isValidChannelViewer(requestedChannel.id):
                return render_template(themes.checkOverride('channelProtectionAuth.html'))

        streamData = Stream.Stream.query.filter_by(streamKey=requestedChannel.streamKey).first()

        streamURL = ''
        edgeQuery = settings.edgeStreamer.query.filter_by(active=True).all()
        if edgeQuery == []:
            if sysSettings.adaptiveStreaming is True:
                streamURL = '/live-adapt/' + requestedChannel.channelLoc + '.m3u8'
            elif requestedChannel.record is True and requestedChannel.owner.has_role("Recorder") and sysSettings.allowRecording is True:
                streamURL = '/live-rec/' + requestedChannel.channelLoc + '/index.m3u8'
            elif requestedChannel.record is False or requestedChannel.owner.has_role("Recorder") is False or sysSettings.allowRecording is False :
                streamURL = '/live/' + requestedChannel.channelLoc + '/index.m3u8'
        else:
            # Handle Selecting the Node using Round Robin Logic
            if sysSettings.adaptiveStreaming is True:
                streamURL = '/edge-adapt/' + requestedChannel.channelLoc + '.m3u8'
            else:
                streamURL = '/edge/' + requestedChannel.channelLoc + '/index.m3u8'

        requestedChannel.views = requestedChannel.views + 1
        if streamData is not None:
            streamData.totalViewers = streamData.totalViewers + 1
        db.session.commit()

        topicList = topics.topics.query.all()

        chatOnly = request.args.get("chatOnly")

        if chatOnly == "True" or chatOnly == "true":
            if requestedChannel.chatEnabled:
                hideBar = False

                hideBarReq = request.args.get("hideBar")
                if hideBarReq == "True" or hideBarReq == "true":
                    hideBar = True

                return render_template(themes.checkOverride('chatpopout.html'), stream=streamData, streamURL=streamURL, sysSettings=sysSettings, channel=requestedChannel, hideBar=hideBar)
            else:
                flash("Chat is Not Enabled For This Stream","error")

        isEmbedded = request.args.get("embedded")

        newView = views.views(0, requestedChannel.id)
        db.session.add(newView)
        db.session.commit()

        requestedChannel = Channel.Channel.query.filter_by(channelLoc=loc).first()

        if isEmbedded is None or isEmbedded == "False":

            secureHash = None
            rtmpURI = None

            endpoint = 'live'

            if requestedChannel.protected:
                if current_user.is_authenticated:
                    secureHash = hashlib.sha256((current_user.username + requestedChannel.channelLoc + current_user.password).encode('utf-8')).hexdigest()
                    username = current_user.username
                    rtmpURI = 'rtmp://' + sysSettings.siteAddress + ":1935/" + endpoint + "/" + requestedChannel.channelLoc + "?username=" + username + "&hash=" + secureHash
            else:
                rtmpURI = 'rtmp://' + sysSettings.siteAddress + ":1935/" + endpoint + "/" + requestedChannel.channelLoc

            randomRecorded = RecordedVideo.RecordedVideo.query.filter_by(pending=False, published=True, channelID=requestedChannel.id).order_by(func.random()).limit(16)

            clipsList = []
            for vid in requestedChannel.recordedVideo:
                for clip in vid.clips:
                    if clip.published is True:
                        clipsList.append(clip)
            clipsList.sort(key=lambda x: x.views, reverse=True)

            subState = False
            if current_user.is_authenticated:
                chanSubQuery = subscriptions.channelSubs.query.filter_by(channelID=requestedChannel.id, userID=current_user.id).first()
                if chanSubQuery is not None:
                    subState = True

            return render_template(themes.checkOverride('channelplayer.html'), stream=streamData, streamURL=streamURL, topics=topicList, randomRecorded=randomRecorded, channel=requestedChannel, clipsList=clipsList,
                                   subState=subState, secureHash=secureHash, rtmpURI=rtmpURI)
        else:
            isAutoPlay = request.args.get("autoplay")
            if isAutoPlay is None:
                isAutoPlay = False
            elif isAutoPlay.lower() == 'true':
                isAutoPlay = True
            else:
                isAutoPlay = False
            return render_template(themes.checkOverride('player_embed.html'), channel=requestedChannel, stream=streamData, streamURL=streamURL, topics=topicList, isAutoPlay=isAutoPlay)

    else:
        flash("No Live Stream at URL","error")
        return redirect(url_for("main_page"))





@app.route('/unsubscribe')
def unsubscribe_page():
    if 'email' in request.args:
        emailAddress = request.args.get("email")
        userQuery = Sec.User.query.filter_by(email=emailAddress).first()
        if userQuery is not None:
            subscriptionQuery = subscriptions.channelSubs.query.filter_by(userID=userQuery.id).all()
            for sub in subscriptionQuery:
                db.session.delete(sub)
            db.session.commit()
        return emailAddress + " has been removed from all subscriptions"

@app.route('/settings/user', methods=['POST','GET'])
@login_required
def user_page():
    if request.method == 'GET':
        return render_template(themes.checkOverride('userSettings.html'))
    elif request.method == 'POST':
        emailAddress = request.form['emailAddress']
        password1 = request.form['password1']
        password2 = request.form['password2']
        biography = request.form['biography']

        if password1 != "":
            if password1 == password2:
                newPassword = hash_password(password1)
                current_user.password = newPassword
                system.newLog(1, "User Password Changed - Username:" + current_user.username)
                flash("Password Changed")
            else:
                flash("Passwords Don't Match!")

        if 'photo' in request.files:
            file = request.files['photo']
            if file.filename != '':
                oldImage = None

                if current_user.pictureLocation is not None:
                    oldImage = current_user.pictureLocation

                filename = photos.save(request.files['photo'], name=str(uuid.uuid4()) + '.')
                current_user.pictureLocation = filename

                if oldImage is not None:
                    try:
                        os.remove(oldImage)
                    except OSError:
                        pass

        current_user.email = emailAddress

        current_user.biography = biography
        system.newLog(1, "User Info Updated - Username:" + current_user.username)
        db.session.commit()

    return redirect(url_for('user_page'))

@app.route('/settings/user/subscriptions')
@login_required
def subscription_page():
    channelSubList = subscriptions.channelSubs.query.filter_by(userID=current_user.id).all()

    return render_template(themes.checkOverride('subscriptions.html'), channelSubList=channelSubList)

@app.route('/settings/user/addInviteCode')
@login_required
@roles_required('Streamer')
def user_addInviteCode():
    if 'inviteCode' in request.args:
        inviteCode = request.args.get("inviteCode")
        inviteCodeQuery = invites.inviteCode.query.filter_by(code=inviteCode).first()
        if inviteCodeQuery is not None:
            if inviteCodeQuery.isValid():
                existingInviteQuery = invites.invitedViewer.query.filter_by(inviteCode=inviteCodeQuery.id, userID=current_user.id).first()
                if existingInviteQuery is None:
                    if inviteCodeQuery.expiration is not None:
                        remainingDays = (inviteCodeQuery.expiration - datetime.datetime.now()).days
                    else:
                        remainingDays = 0
                    newInvitedUser = invites.invitedViewer(current_user.id, inviteCodeQuery.channelID, remainingDays, inviteCode=inviteCodeQuery.id)
                    inviteCodeQuery.uses = inviteCodeQuery.uses + 1
                    db.session.add(newInvitedUser)
                    db.session.commit()
                    system.newLog(3, "User Added Invite Code to Account - Username:" + current_user.username + " Channel ID #" + str(inviteCodeQuery.channelID))
                    flash("Added Invite Code to Channel", "success")
                    if 'redirectURL' in request.args:
                        return redirect(request.args.get("redirectURL"))
                else:
                    flash("Invite Code Already Applied", "error")
            else:
                system.newLog(3, "User Attempted to add Expired Invite Code to Account - Username:" + current_user.username + " Channel ID #" + str(inviteCodeQuery.channelID))
                flash("Invite Code Expired", "error")
        else:
            flash("Invalid Invite Code", "error")
    return redirect(url_for('main_page'))


@app.route('/settings/admin', methods=['POST','GET'])
@login_required
@roles_required('Admin')
def admin_page():
    videos_root = app.config['WEB_ROOT'] + 'videos/'
    sysSettings = settings.settings.query.first()
    if request.method == 'GET':
        if request.args.get("action") is not None:
            action = request.args.get("action")
            setting = request.args.get("setting")

            if action == "delete":
                if setting == "topics":
                    topicID = int(request.args.get("topicID"))

                    topicQuery = topics.topics.query.filter_by(id=topicID).first()

                    channels = Channel.Channel.query.filter_by(topic=topicID).all()
                    videos = RecordedVideo.RecordedVideo.query.filter_by(topic=topicID).all()

                    defaultTopic = topics.topics.query.filter_by(name="Other").first()

                    for chan in channels:
                        chan.topic = defaultTopic.id
                    for vid in videos:
                        vid.topic = defaultTopic.id

                    system.newLog(1, "User " + current_user.username + " deleted Topic " + str(topicQuery.name))
                    db.session.delete(topicQuery)
                    db.session.commit()
                    flash("Topic Deleted")
                    return redirect(url_for('admin_page',page="topics"))

                elif setting == "channel":
                    channelID = int(request.args.get("channelID"))

                    channelQuery = Channel.Channel.query.filter_by(id=channelID).first()

                    for vid in channelQuery.recordedVideo:
                        for upvote in vid.upvotes:
                            db.session.delete(upvote)

                        vidComments = vid.comments
                        for comment in vidComments:
                            db.session.delete(comment)

                        vidViews = views.views.query.filter_by(viewType=1, itemID=vid.id)
                        for view in vidViews:
                            db.session.delete(view)

                        db.session.delete(vid)
                    for upvote in channelQuery.upvotes:
                        db.session.delete(upvote)


                    filePath = videos_root + channelQuery.channelLoc

                    if filePath != videos_root:
                        shutil.rmtree(filePath, ignore_errors=True)

                    system.newLog(1, "User " + current_user.username + " deleted Channel " + str(channelQuery.id))
                    db.session.delete(channelQuery)
                    db.session.commit()

                    flash("Channel Deleted")
                    return redirect(url_for('admin_page', page="channels"))

                elif setting == "users":
                    userID = int(request.args.get("userID"))

                    userQuery = Sec.User.query.filter_by(id=userID).first()

                    if userQuery is not None:

                        commentQuery = comments.videoComments.query.filter_by(userID=int(userID)).all()
                        for comment in commentQuery:
                            db.session.delete(comment)
                        db.session.commit()

                        inviteQuery = invites.invitedViewer.query.filter_by(userID=int(userID)).all()
                        for invite in inviteQuery:
                            db.session.delete(invite)
                        db.session.commit()

                        channelQuery = Channel.Channel.query.filter_by(owningUser=userQuery.id).all()

                        for chan in channelQuery:

                            for vid in chan.recordedVideo:
                                for upvote in vid.upvotes:
                                    db.session.delete(upvote)

                                vidComments = vid.comments
                                for comment in vidComments:
                                    db.session.delete(comment)

                                vidViews = views.views.query.filter_by(viewType=1, itemID=vid.id)
                                for view in vidViews:
                                    db.session.delete(view)

                                for clip in vid.clips:
                                    db.session.delete(clip)

                                db.session.delete(vid)
                            for upvote in chan.upvotes:
                                db.session.delete(upvote)

                            filePath = videos_root + chan.channelLoc

                            if filePath != videos_root:
                                shutil.rmtree(filePath, ignore_errors=True)

                            db.session.delete(chan)

                        flash("User " + str(userQuery.username) + " Deleted")
                        system.newLog(1, "User " + current_user.username + " deleted User " + str(userQuery.username))

                        db.session.delete(userQuery)
                        db.session.commit()

                        return redirect(url_for('admin_page', page="users"))

                elif setting == "userRole":
                    userID = int(request.args.get("userID"))
                    roleID = int(request.args.get("roleID"))

                    userQuery = Sec.User.query.filter_by(id=userID).first()
                    roleQuery = Sec.Role.query.filter_by(id=roleID).first()

                    if userQuery is not None and roleQuery is not None:
                        user_datastore.remove_role_from_user(userQuery,roleQuery.name)
                        db.session.commit()
                        system.newLog(1, "User " + current_user.username + " Removed Role " + roleQuery.name + " from User" + userQuery.username)
                        flash("Removed Role from User")

                    else:
                        flash("Invalid Role or User!")
                    return redirect(url_for('admin_page', page="users"))

            elif action == "add":
                if setting == "userRole":
                    userID = int(request.args.get("userID"))
                    roleName = str(request.args.get("roleName"))

                    userQuery = Sec.User.query.filter_by(id=userID).first()
                    roleQuery = Sec.Role.query.filter_by(name=roleName).first()

                    if userQuery is not None and roleQuery is not None:
                        user_datastore.add_role_to_user(userQuery, roleQuery.name)
                        db.session.commit()
                        system.newLog(1, "User " + current_user.username + " Added Role " + roleQuery.name + " to User " + userQuery.username)
                        flash("Added Role to User")
                    else:
                        flash("Invalid Role or User!")
                    return redirect(url_for('admin_page', page="users"))
            elif action == "toggleActive":
                if setting == "users":
                    userID = int(request.args.get("userID"))
                    userQuery = Sec.User.query.filter_by(id=userID).first()
                    if userQuery is not None:
                        if userQuery.active:
                            userQuery.active = False
                            system.newLog(1, "User " + current_user.username + " Disabled User " + userQuery.username)
                            flash("User Disabled")
                        else:
                            userQuery.active = True
                            system.newLog(1, "User " + current_user.username + " Enabled User " + userQuery.username)
                            flash("User Enabled")
                        db.session.commit()
                    return redirect(url_for('admin_page', page="users"))
            elif action == "backup":
                dbTables = db.engine.table_names()
                dbDump = {}
                for table in dbTables:
                    for c in db.Model._decl_class_registry.values():
                        if hasattr(c, '__table__') and c.__tablename__ == table:
                            tableDict = system.table2Dict(c)
                            dbDump[table] = tableDict
                userQuery = Sec.User.query.all()
                dbDump['roles'] = {}
                for user in userQuery:
                    userroles = user.roles
                    dbDump['roles'][user.username] = []
                    for role in userroles:
                        dbDump['roles'][user.username].append(role.name)
                dbDumpJson = json.dumps(dbDump)
                system.newLog(1, "User " + current_user.username + " Performed DB Backup Dump")
                return Response(dbDumpJson, mimetype='application/json', headers={'Content-Disposition':'attachment;filename=OSPBackup-' + str(datetime.datetime.now()) + '.json'})

            return redirect(url_for('admin_page'))

        page = None
        if request.args.get('page') is not None:
            page = str(request.args.get("page"))
        repoSHA = "N/A"
        remoteSHA = repoSHA
        branch = "Local Install"
        validGitRepo = False
        try:
            repo = git.Repo(search_parent_directories=True)
            validGitRepo = True
        except:
            pass

        if validGitRepo:
            try:
                remoteSHA = None
                if repo is not None:
                    repoSHA = str(repo.head.object.hexsha)
                    branch = repo.active_branch
                    branch = branch.name
                    remote = repo.remotes.origin.fetch()[0].commit
                    remoteSHA = str(remote)
            except:
                validGitRepo = False
                branch = "Local Install"


        appDBVer = dbVersion.dbVersion.query.first().version
        userList = Sec.User.query.all()
        roleList = Sec.Role.query.all()
        channelList = Channel.Channel.query.all()
        streamList = Stream.Stream.query.all()
        topicsList = topics.topics.query.all()
        edgeNodes = settings.edgeStreamer.query.all()

        # 30 Days Viewer Stats
        viewersTotal = 0

        # Create List of 30 Day Viewer Stats
        statsViewsLiveDay = db.session.query(func.date(views.views.date), func.count(views.views.id)).filter(views.views.viewType == 0).filter(views.views.date > (datetime.datetime.now() - datetime.timedelta(days=30))).group_by(func.date(views.views.date)).all()
        statsViewsLiveDayArray = []
        for entry in statsViewsLiveDay:
            viewersTotal = viewersTotal + entry[1]
            statsViewsLiveDayArray.append({'t': (entry[0]), 'y': entry[1]})

        statsViewsRecordedDay = db.session.query(func.date(views.views.date), func.count(views.views.id)).filter(views.views.viewType == 1).filter(views.views.date > (datetime.datetime.now() - datetime.timedelta(days=30))).group_by(func.date(views.views.date)).all()
        statsViewsRecordedDayArray = []

        for entry in statsViewsRecordedDay:
            viewersTotal = viewersTotal + entry[1]
            statsViewsRecordedDayArray.append({'t': (entry[0]), 'y': entry[1]})

        statsViewsDay = {
            'live': statsViewsLiveDayArray,
            'recorded': statsViewsRecordedDayArray
        }

        currentViewers = 0
        for stream in streamList:
            currentViewers = currentViewers + stream.currentViewers

        nginxStatDataRequest = requests.get('http://127.0.0.1:9000/stats')
        nginxStatData = (json.loads(json.dumps(xmltodict.parse(nginxStatDataRequest.text))))

        globalWebhookQuery = webhook.globalWebhook.query.all()

        #hubServerQuery = hubConnection.hubServers.query.all()
        #hubRegistrationQuery = hubConnection.hubConnection.query.all()

        themeList = []
        themeDirectorySearch = os.listdir("./templates/themes/")
        for theme in themeDirectorySearch:
            hasJSON = os.path.isfile("./templates/themes/" + theme + "/theme.json")
            if hasJSON:
                themeList.append(theme)

        logsList = logs.logs.query.order_by(logs.logs.timestamp.desc()).limit(250)

        system.newLog(1, "User " + current_user.username + " Accessed Admin Interface")

        return render_template(themes.checkOverride('admin.html'), appDBVer=appDBVer, userList=userList, roleList=roleList, channelList=channelList, streamList=streamList, topicsList=topicsList, repoSHA=repoSHA,repoBranch=branch,
                               remoteSHA=remoteSHA, themeList=themeList, statsViewsDay=statsViewsDay, viewersTotal=viewersTotal, currentViewers=currentViewers, nginxStatData=nginxStatData, globalHooks=globalWebhookQuery,
                               logsList=logsList, edgeNodes=edgeNodes, page=page)
    elif request.method == 'POST':

        settingType = request.form['settingType']

        if settingType == "system":

            serverName = request.form['serverName']
            serverProtocol = request.form['siteProtocol']
            serverAddress = request.form['serverAddress']
            smtpSendAs = request.form['smtpSendAs']
            smtpAddress = request.form['smtpAddress']
            smtpPort = request.form['smtpPort']
            smtpUser = request.form['smtpUser']
            smtpPassword = request.form['smtpPassword']
            serverMessageTitle = request.form['serverMessageTitle']
            serverMessage = request.form['serverMessage']
            theme = request.form['theme']
            restreamMaxBitrate = request.form['restreamMaxBitrate']

            recordSelect = False
            uploadSelect = False
            adaptiveStreaming = False
            showEmptyTables = False
            allowComments = False
            smtpTLS = False
            smtpSSL = False
            protectionEnabled = False

            if 'recordSelect' in request.form:
                recordSelect = True

            if 'uploadSelect' in request.form:
                uploadSelect = True

            if 'adaptiveStreaming' in request.form:
                adaptiveStreaming = True

            if 'showEmptyTables' in request.form:
                showEmptyTables = True

            if 'allowComments' in request.form:
                allowComments = True

            if 'smtpTLS' in request.form:
                smtpTLS = True

            if 'smtpSSL' in request.form:
                smtpSSL = True

            if 'enableProtection' in request.form:
                protectionEnabled = True

            systemLogo = None
            if 'photo' in request.files:
                file = request.files['photo']
                if file.filename != '':
                    filename = photos.save(request.files['photo'], name=str(uuid.uuid4()) + '.')
                    systemLogo = "/images/" + filename

            validAddress = system.formatSiteAddress(serverAddress)
            try:
                externalIP = socket.gethostbyname(validAddress)
            except socket.gaierror:
                flash("Invalid Server Address/IP", "error")
                return redirect(url_for("admin_page", page="settings"))

            sysSettings.siteName = serverName
            sysSettings.siteProtocol = serverProtocol
            sysSettings.siteAddress = serverAddress
            sysSettings.smtpSendAs = smtpSendAs
            sysSettings.smtpAddress = smtpAddress
            sysSettings.smtpPort = smtpPort
            sysSettings.smtpUsername = smtpUser
            sysSettings.smtpPassword = smtpPassword
            sysSettings.smtpTLS = smtpTLS
            sysSettings.smtpSSL = smtpSSL
            sysSettings.allowRecording = recordSelect
            sysSettings.allowUploads = uploadSelect
            sysSettings.adaptiveStreaming = adaptiveStreaming
            sysSettings.showEmptyTables = showEmptyTables
            sysSettings.allowComments = allowComments
            sysSettings.systemTheme = theme
            sysSettings.serverMessageTitle = serverMessageTitle
            sysSettings.serverMessage = serverMessage
            sysSettings.protectionEnabled = protectionEnabled
            sysSettings.restreamMaxBitrate = int(restreamMaxBitrate)

            if systemLogo is not None:
                sysSettings.systemLogo = systemLogo

            db.session.commit()

            sysSettings = settings.settings.query.first()

            app.config.update(
                SERVER_NAME=None,
                SECURITY_EMAIL_SENDER=sysSettings.smtpSendAs,
                MAIL_DEFAULT_SENDER=sysSettings.smtpSendAs,
                MAIL_SERVER=sysSettings.smtpAddress,
                MAIL_PORT=sysSettings.smtpPort,
                MAIL_USE_SSL=sysSettings.smtpSSL,
                MAIL_USE_TLS=sysSettings.smtpTLS,
                MAIL_USERNAME=sysSettings.smtpUsername,
                MAIL_PASSWORD=sysSettings.smtpPassword,
                SECURITY_EMAIL_SUBJECT_PASSWORD_RESET = sysSettings.siteName + " - Password Reset Request",
                SECURITY_EMAIL_SUBJECT_REGISTER = sysSettings.siteName + " - Welcome!",
                SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE = sysSettings.siteName + " - Password Reset Notification",
                SECURITY_EMAIL_SUBJECT_CONFIRM = sysSettings.siteName + " - Email Confirmation Request",
                SECURITY_FORGOT_PASSWORD_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/forgot_password.html',
                SECURITY_LOGIN_USER_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/login_user.html',
                SECURITY_REGISTER_USER_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/register_user.html',
                SECURITY_RESET_PASSWORD_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/reset_password.html',
                SECURITY_SEND_CONFIRMATION_TEMPLATE = 'themes/'  + sysSettings.systemTheme + '/security/send_confirmation.html')

            email.init_app(app)
            email.app = app

            themeList = []
            themeDirectorySearch = os.listdir("./templates/themes/")
            for theme in themeDirectorySearch:
                hasJSON = os.path.isfile("./templates/themes/" + theme + "/theme.json")
                if hasJSON:
                    themeList.append(theme)

            # Import Theme Data into Theme Dictionary
            with open('templates/themes/' + sysSettings.systemTheme + '/theme.json') as f:

                globalvars.themeData = json.load(f)

            system.newLog(1, "User " + current_user.username + " altered System Settings")

            return redirect(url_for('admin_page', page="settings"))

        elif settingType == "topics":

            if 'topicID' in request.form:
                topicID = int(request.form['topicID'])
                topicName = request.form['name']

                topicQuery = topics.topics.query.filter_by(id=topicID).first()

                if topicQuery is not None:

                    topicQuery.name = topicName

                    if 'photo' in request.files:
                        file = request.files['photo']
                        if file.filename != '':
                            oldImage = None

                            if topicQuery.iconClass is not None:
                                oldImage = topicQuery.iconClass

                            filename = photos.save(request.files['photo'], name=str(uuid.uuid4()) + '.')
                            topicQuery.iconClass = filename

                            if oldImage is not None:
                                try:
                                    os.remove(oldImage)
                                except OSError:
                                    pass
            else:
                topicName = request.form['name']

                topicImage = None
                if 'photo' in request.files:
                    file = request.files['photo']
                    if file.filename != '':
                        filename = photos.save(request.files['photo'], name=str(uuid.uuid4()) + '.')
                        topicImage = filename

                newTopic = topics.topics(topicName, topicImage)
                db.session.add(newTopic)

            db.session.commit()
            return redirect(url_for('admin_page', page="topics"))

        elif settingType == "edgeNode":
            address = request.form['address']
            port = request.form['edgePort']
            loadPct = request.form['edgeLoad']
            newEdge = settings.edgeStreamer(address, port, loadPct)

            try:
                edgeXML = requests.get("http://" + address + ":9000/stat").text
                edgeDict = xmltodict.parse(edgeXML)
                if "nginx_rtmp_version" in edgeDict['rtmp']:
                    newEdge.status = 1
                    db.session.add(newEdge)
                    db.session.commit()
            except:
                newEdge.status = 0
                db.session.add(newEdge)
                db.session.commit()

            return redirect(url_for('admin_page', page="ospedge"))

        elif settingType == "newuser":

            password = request.form['password1']
            email = request.form['emailaddress']
            username = request.form['username']

            passwordhash = utils.hash_password(password)

            user_datastore.create_user(email=email, username=username, password=passwordhash)
            db.session.commit()

            user = Sec.User.query.filter_by(username=username).first()
            user_datastore.add_role_to_user(user, 'User')
            db.session.commit()
            return redirect(url_for('admin_page', page="users"))

        return redirect(url_for('admin_page'))

@app.route('/settings/dbRestore', methods=['POST'])
def settings_dbRestore():
    validRestoreAttempt = False
    if not settings.settings.query.all():
        validRestoreAttempt = True
    elif current_user.is_authenticated:
        if current_user.has_role("Admin"):
            validRestoreAttempt = True

    if validRestoreAttempt:

        restoreJSON = None
        if 'restoreData' in request.files:
            file = request.files['restoreData']
            if file.filename != '':
                restoreJSON = file.read()
        if restoreJSON is not None:
            restoreDict = json.loads(restoreJSON)

            ## Restore Settings

            meta = db.metadata
            for table in reversed(meta.sorted_tables):
                db.session.execute(table.delete())
            db.session.commit()

            for roleData in restoreDict['role']:
                user_datastore.find_or_create_role(name=roleData['name'], description=roleData['description'])
            db.session.commit()

            serverSettings = settings.settings(restoreDict['settings'][0]['siteName'],
                                               restoreDict['settings'][0]['siteProtocol'],
                                               restoreDict['settings'][0]['siteAddress'],
                                               restoreDict['settings'][0]['smtpAddress'],
                                               int(restoreDict['settings'][0]['smtpPort']),
                                               eval(restoreDict['settings'][0]['smtpTLS']),
                                               eval(restoreDict['settings'][0]['smtpSSL']),
                                               restoreDict['settings'][0]['smtpUsername'],
                                               restoreDict['settings'][0]['smtpPassword'],
                                               restoreDict['settings'][0]['smtpSendAs'],
                                               eval(restoreDict['settings'][0]['allowRecording']),
                                               eval(restoreDict['settings'][0]['allowUploads']),
                                               eval(restoreDict['settings'][0]['adaptiveStreaming']),
                                               eval(restoreDict['settings'][0]['showEmptyTables']),
                                               eval(restoreDict['settings'][0]['allowComments']), globalvars.version)
            serverSettings.id = int(restoreDict['settings'][0]['id'])
            serverSettings.systemTheme = restoreDict['settings'][0]['systemTheme']
            serverSettings.systemLogo = restoreDict['settings'][0]['systemLogo']
            serverSettings.protectionEnabled = eval(restoreDict['settings'][0]['protectionEnabled'])
            if 'restreamMaxBitrate' in restoreDict['settings'][0]:
                serverSettings.restreamMaxBitrate = restoreDict['settings'][0]['restreamMaxBitrate']
            if 'serverMessage' in restoreDict['settings'][0]:
                serverSettings.serverMessage = restoreDict['settings'][0]['serverMessage']
            if 'serverMessageTitle' in restoreDict['settings'][0]:
                serverSettings.serverMessageTitle = restoreDict['settings'][0]['serverMessageTitle']

            # Remove Old Settings
            oldSettings = settings.settings.query.all()
            for row in oldSettings:
                db.session.delete(row)
            db.session.commit()

            db.session.add(serverSettings)
            db.session.commit()

            sysSettings = settings.settings.query.first()

            if settings is not None:
                app.config.update(
                    SERVER_NAME=None,
                    SECURITY_EMAIL_SENDER=sysSettings.smtpSendAs,
                    MAIL_DEFAULT_SENDER=sysSettings.smtpSendAs,
                    MAIL_SERVER=sysSettings.smtpAddress,
                    MAIL_PORT=sysSettings.smtpPort,
                    MAIL_USE_TLS=sysSettings.smtpTLS,
                    MAIL_USE_SSL=sysSettings.smtpSSL,
                    MAIL_USERNAME=sysSettings.smtpUsername,
                    MAIL_PASSWORD=sysSettings.smtpPassword,
                    SECURITY_EMAIL_SUBJECT_PASSWORD_RESET=sysSettings.siteName + " - Password Reset Request",
                    SECURITY_EMAIL_SUBJECT_REGISTER=sysSettings.siteName + " - Welcome!",
                    SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE=sysSettings.siteName + " - Password Reset Notification",
                    SECURITY_EMAIL_SUBJECT_CONFIRM=sysSettings.siteName + " - Email Confirmation Request",
                    SECURITY_FORGOT_PASSWORD_TEMPLATE='themes/' + sysSettings.systemTheme + '/security/forgot_password.html',
                    SECURITY_LOGIN_USER_TEMPLATE='themes/' + sysSettings.systemTheme + '/security/login_user.html',
                    SECURITY_REGISTER_USER_TEMPLATE='themes/' + sysSettings.systemTheme + '/security/register_user.html',
                    SECURITY_RESET_PASSWORD_TEMPLATE='themes/' + sysSettings.systemTheme + '/security/reset_password.html',
                    SECURITY_SEND_CONFIRMATION_TEMPLATE='themes/' + sysSettings.systemTheme + '/security/send_confirmation.html')

                email.init_app(app)
                email.app = app

            ## Restore Edge Nodes
            oldEdgeNodes = settings.edgeStreamer.query.all()
            for node in oldEdgeNodes:
                db.session.delete(node)
            db.session.commit()

            if 'edgeStreamer' in restoreDict:
                for node in restoreDict['edgeStreamer']:
                    restoredNode = settings.edgeStreamer(node['address'], node['port'], node['loadPct'])
                    restoredNode.status = int(node['status'])
                    restoredNode.active = eval(node['active'])
                    db.session.add(restoredNode)
                    db.session.commit()

            ## Restores Users
            oldUsers = Sec.User.query.all()
            for user in oldUsers:
                db.session.delete(user)
            db.session.commit()
            for restoredUser in restoreDict['user']:
                user_datastore.create_user(email=restoredUser['email'], username=restoredUser['username'],
                                           password=restoredUser['password'])
                db.session.commit()
                user = Sec.User.query.filter_by(username=restoredUser['username']).first()
                user.pictureLocation = restoredUser['pictureLocation']
                user.active = eval(restoredUser['active'])
                user.biography = restoredUser['biography']

                if restoredUser['confirmed_at'] != "None":
                    try:
                        user.confirmed_at = datetime.datetime.strptime(restoredUser['confirmed_at'], '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        user.confirmed_at = datetime.datetime.strptime(restoredUser['confirmed_at'], '%Y-%m-%d %H:%M:%S.%f')
                db.session.commit()

                user = Sec.User.query.filter_by(username=restoredUser['username']).first()
                user.id = int(restoredUser['id'])
                db.session.commit()

                user = Sec.User.query.filter_by(username=restoredUser['username']).first()
                for roleEntry in restoreDict['roles'][user.username]:
                    user_datastore.add_role_to_user(user, roleEntry)
                db.session.commit()


            ## Restore Topics
            oldTopics = topics.topics.query.all()
            for topic in oldTopics:
                db.session.delete(topic)
            db.session.commit()
            for restoredTopic in restoreDict['topics']:
                topic = topics.topics(restoredTopic['name'], restoredTopic['iconClass'])
                topic.id = int(restoredTopic['id'])
                db.session.add(topic)
            db.session.commit()

            ## Restores Channels
            oldChannels = Channel.Channel.query.all()
            for channel in oldChannels:
                db.session.delete(channel)
            db.session.commit()
            for restoredChannel in restoreDict['Channel']:
                if restoredChannel['owningUser'] != "None":
                    channel = Channel.Channel(int(restoredChannel['owningUser']), restoredChannel['streamKey'],
                                              restoredChannel['channelName'], int(restoredChannel['topic']),
                                              eval(restoredChannel['record']), eval(restoredChannel['chatEnabled']),
                                              eval(restoredChannel['allowComments']), restoredChannel['description'])
                    channel.id = int(restoredChannel['id'])
                    channel.channelLoc = restoredChannel['channelLoc']
                    channel.chatBG = restoredChannel['chatBG']
                    channel.chatTextColor = restoredChannel['chatTextColor']
                    channel.chatAnimation = restoredChannel['chatAnimation']
                    channel.views = int(restoredChannel['views'])
                    channel.protected = eval(restoredChannel['protected'])
                    channel.channelMuted = eval(restoredChannel['channelMuted'])
                    channel.defaultStreamName = restoredChannel['defaultStreamName']
                    channel.showChatJoinLeaveNotification = eval(restoredChannel['showChatJoinLeaveNotification'])
                    channel.imageLocation = restoredChannel['imageLocation']
                    channel.offlineImageLocation = restoredChannel['offlineImageLocation']
                    channel.autoPublish = eval(restoredChannel['autoPublish'])
                    if 'rtmpRestream' in restoredChannel:
                        channel.rtmpRestream = eval(restoredChannel['rtmpRestream'])
                    if 'rtmpRestreamDestination' in restoredChannel:
                        channel.rtmpRestreamDestination = restoredChannel['rtmpRestreamDestination']

                    db.session.add(channel)
                else:
                    flash("Error Restoring Channel: ID# " + str(restoredChannel['id']), "error")
            db.session.commit()
            
            ## Restore Subscriptions
            oldSubscriptions = subscriptions.channelSubs.query.all()
            for sub in oldSubscriptions:
                db.session.delete(sub)
            db.session.commit()

            if 'channel_subs' in restoreDict:
                for restoredChannelSub in restoreDict['channel_subs']:
                    channelID = int(restoredChannelSub['channelID'])
                    userID = int(restoredChannelSub['userID'])

                    channelSub = subscriptions.channelSubs(channelID, userID)
                    channelSub.id = int(restoredChannelSub['id'])
                    db.session.add(channelSub)
                db.session.commit()

            ## Restored Videos - Deletes if not restored to maintain DB
            oldVideos = RecordedVideo.RecordedVideo.query.all()
            for video in oldVideos:
                db.session.delete(video)
            db.session.commit()

            if 'restoreVideos' in request.form:

                for restoredVideo in restoreDict['RecordedVideo']:
                    if restoredVideo['channelID'] != "None":
                        try:
                            video = RecordedVideo.RecordedVideo(int(restoredVideo['owningUser']),
                                                            int(restoredVideo['channelID']), restoredVideo['channelName'],
                                                            int(restoredVideo['topic']), int(restoredVideo['views']),
                                                            restoredVideo['videoLocation'],
                                                            datetime.datetime.strptime(restoredVideo['videoDate'],
                                                                                       '%Y-%m-%d %H:%M:%S'),
                                                            eval(restoredVideo['allowComments']), eval(restoredVideo['published']))
                        except ValueError:
                            video = RecordedVideo.RecordedVideo(int(restoredVideo['owningUser']),
                                                                int(restoredVideo['channelID']),
                                                                restoredVideo['channelName'],
                                                                int(restoredVideo['topic']),
                                                                int(restoredVideo['views']),
                                                                restoredVideo['videoLocation'],
                                                                datetime.datetime.strptime(restoredVideo['videoDate'],
                                                                                           '%Y-%m-%d %H:%M:%S.%f'),
                                                                eval(restoredVideo['allowComments']), eval(restoredVideo['published']))
                        video.id = int(restoredVideo['id'])
                        video.description = restoredVideo['description']
                        if restoredVideo['length'] != "None":
                            video.length = float(restoredVideo['length'])
                        video.thumbnailLocation = restoredVideo['thumbnailLocation']
                        video.pending = eval(restoredVideo['pending'])
                        video.published = eval(restoredVideo['published'])
                        if 'gifLocation' in restoredVideo:
                            if restoredVideo['gifLocation'] != "None":
                                video.gifLocation = restoredVideo['gifLocation']
                        db.session.add(video)
                    else:
                        flash("Error Restoring Recorded Video: ID# " + str(restoredVideo['id']), "error")
                db.session.commit()

            oldClips = RecordedVideo.Clips.query.all()
            for clip in oldClips:
                db.session.delete(clip)
            db.session.commit()
            if 'restoreVideos' in request.form:
                for restoredClip in restoreDict['Clips']:
                    if restoredClip['parentVideo'] != "None":
                        newClip = RecordedVideo.Clips(int(restoredClip['parentVideo']), float(restoredClip['startTime']),
                                                      float(restoredClip['endTime']), restoredClip['clipName'],
                                                      restoredClip['description'])
                        newClip.id = int(restoredClip['id'])
                        newClip.views = int(restoredClip['views'])
                        newClip.thumbnailLocation = restoredClip['thumbnailLocation']
                        newClip.published = eval(restoredClip['published'])
                        if 'gifLocation' in restoredClip:
                            if restoredClip['gifLocation'] != "None":
                                newClip.gifLocation = restoredClip['gifLocation']
                        db.session.add(newClip)
                    else:
                        flash("Error Restoring Clip: ID# " + str(restoredClip['id']), "error")
                db.session.commit()

            ## Restores API Keys
            oldAPI = apikey.apikey.query.all()
            for api in oldAPI:
                db.session.delete(api)
            db.session.commit()

            for restoredAPIKey in restoreDict['apikey']:
                if restoredAPIKey['userID'] != "None":
                    key = apikey.apikey(int(restoredAPIKey['userID']), int(restoredAPIKey['type']),
                                        restoredAPIKey['description'], 0)
                    key.id = int(restoredAPIKey['id'])
                    key.key = restoredAPIKey['key']
                    if restoredAPIKey['expiration'] != "None":
                        try:
                            key.createdOn = datetime.datetime.strptime(restoredAPIKey['createdOn'], '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            key.createdOn = datetime.datetime.strptime(restoredAPIKey['createdOn'], '%Y-%m-%d %H:%M:%S.%f')
                        try:
                            key.expiration = datetime.datetime.strptime(restoredAPIKey['expiration'], '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            key.expiration = datetime.datetime.strptime(restoredAPIKey['expiration'], '%Y-%m-%d %H:%M:%S.%f')
                    db.session.add(key)
                else:
                    flash("Error Restoring API Key: ID# " + str(restoredAPIKey['id']), "error")
            db.session.commit()

            ## Restores Webhooks
            oldWebhooks = webhook.webhook.query.all()
            for hook in oldWebhooks:
                db.session.delete(hook)
            db.session.commit()

            for restoredWebhook in restoreDict['webhook']:
                if restoredWebhook['channelID'] != "None":
                    hook = webhook.webhook(restoredWebhook['name'], int(restoredWebhook['channelID']),
                                           restoredWebhook['endpointURL'], restoredWebhook['requestHeader'],
                                           restoredWebhook['requestPayload'], int(restoredWebhook['requestType']),
                                           int(restoredWebhook['requestTrigger']))
                    db.session.add(hook)
                else:
                    flash("Error Restoring Webook ID# " + restoredWebhook['id'], "error")
            db.session.commit()

            ## Restores Global Webhooks
            oldWebhooks = webhook.globalWebhook.query.all()
            for hook in oldWebhooks:
                db.session.delete(hook)
            db.session.commit()

            for restoredWebhook in restoreDict['global_webhook']:
                hook = webhook.globalWebhook(restoredWebhook['name'], restoredWebhook['endpointURL'],
                                             restoredWebhook['requestHeader'], restoredWebhook['requestPayload'],
                                             int(restoredWebhook['requestType']), int(restoredWebhook['requestTrigger']))
                db.session.add(hook)
            db.session.commit()

            ## Restores Views
            oldViews = views.views.query.all()
            for view in oldViews:
                db.session.delete(view)
            db.session.commit()

            if 'restoreVideos' in request.form:
                for restoredView in restoreDict['views']:
                    if not (int(restoredView['viewType']) == 1 and 'restoreVideos' not in request.form):
                        view = views.views(int(restoredView['viewType']), int(restoredView['itemID']))
                        view.id = int(restoredView['id'])
                        try:
                            view.date = datetime.datetime.strptime(restoredView['date'], '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            view.date = datetime.datetime.strptime(restoredView['date'], '%Y-%m-%d %H:%M:%S.%f')
                        db.session.add(view)
                db.session.commit()

            ## Restores Invites
            oldInviteCode = invites.inviteCode.query.all()
            for code in oldInviteCode:
                db.session.delete(code)
            db.session.commit()

            for restoredInviteCode in restoreDict['inviteCode']:
                if restoredInviteCode['channelID'] != "None":
                    code = invites.inviteCode(0, int(restoredInviteCode['channelID']))
                    code.id = int(restoredInviteCode['id'])
                    if restoredInviteCode['expiration'] != "None":
                        try:
                            code.expiration = datetime.datetime.strptime(restoredInviteCode['expiration'],
                                                                     '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            code.expiration = datetime.datetime.strptime(restoredInviteCode['expiration'],
                                                                         '%Y-%m-%d %H:%M:%S.%f')
                    else:
                        code.expiration = None
                    code.uses = int(restoredInviteCode['uses'])
                    db.session.add(code)
                else:
                    flash("Error Invite Code: ID# " + str(restoredInviteCode['id']), "error")
            db.session.commit()

            oldInvitedViewers = invites.invitedViewer.query.all()
            for invite in oldInvitedViewers:
                db.session.delete(invite)
            db.session.commit()

            for restoredInvitedViewer in restoreDict['invitedViewer']:
                if restoredInvitedViewer['channelID'] != "None" and restoredInvitedViewer['userID'] != "None":
                    invite = invites.invitedViewer(int(restoredInvitedViewer['userID']),
                                                   int(restoredInvitedViewer['channelID']), 0, None)
                    invite.id = int(restoredInvitedViewer['id'])
                    try:
                        invite.addedDate = datetime.datetime.strptime(restoredInvitedViewer['addedDate'],
                                                                  '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        invite.addedDate = datetime.datetime.strptime(restoredInvitedViewer['addedDate'],
                                                                      '%Y-%m-%d %H:%M:%S.%f')
                    try:
                        invite.expiration = datetime.datetime.strptime(restoredInvitedViewer['expiration'],
                                                                   '%Y-%m-%d %H:%M:%S')
                    except ValueError:
                        invite.expiration = datetime.datetime.strptime(restoredInvitedViewer['expiration'],
                                                                       '%Y-%m-%d %H:%M:%S.%f')
                    if 'inviteCode' in restoredInvitedViewer:
                        if restoredInvitedViewer['inviteCode'] is not None:
                            invite.inviteCode = int(restoredInvitedViewer['inviteCode'])
                    db.session.add(invite)
                else:
                    flash("Error Restoring Invited Viewer: ID# " + str(restoredInvitedViewer['id']), "error")
            db.session.commit()

            ## Restores Comments
            oldComments = comments.videoComments.query.all()
            for comment in oldComments:
                db.session.delete(comment)
            db.session.commit()

            if 'restoreVideos' in request.form:
                for restoredComment in restoreDict['videoComments']:
                    if restoredComment['userID'] != "None" and restoredComment['videoID'] != "None":
                        comment = comments.videoComments(int(restoredComment['userID']), restoredComment['comment'],
                                                         int(restoredComment['videoID']))
                        comment.id = int(restoredComment['id'])
                        try:
                            comment.timestamp = datetime.datetime.strptime(restoredComment['timestamp'], '%Y-%m-%d %H:%M:%S')
                        except ValueError:
                            comment.timestamp = datetime.datetime.strptime(restoredComment['timestamp'], '%Y-%m-%d %H:%M:%S.%f')
                        db.session.add(comment)
                    else:
                        flash("Error Restoring Video Comment: ID# " + str(restoredComment['id']), "error")
                db.session.commit()

            ## Restores Ban List
            oldBanList = banList.banList.query.all()
            for ban in oldBanList:
                db.session.delete(ban)
            db.session.commit()

            for restoredBan in restoreDict['ban_list']:
                if restoredBan['channelLoc'] != "None" and restoredBan['userID'] != "None":
                    ban = banList.banList(restoredBan['channelLoc'], int(restoredBan['userID']))
                    ban.id = int(restoredBan['id'])
                    db.session.add(ban)
                else:
                    flash("Error Restoring Channel Ban Entry: ID# " + str(restoredBan['id']), "error")
            db.session.commit()

            ## Restores Upvotes
            oldChannelUpvotes = upvotes.channelUpvotes.query.all()
            for upvote in oldChannelUpvotes:
                db.session.delete(upvote)
            db.session.commit()
            oldStreamUpvotes = upvotes.streamUpvotes.query.all()
            for upvote in oldStreamUpvotes:
                db.session.delete(upvote)
            db.session.commit()
            oldVideoUpvotes = upvotes.videoUpvotes.query.all()
            for upvote in oldVideoUpvotes:
                db.session.delete(upvote)
            db.session.commit()
            oldCommentUpvotes = upvotes.commentUpvotes.query.all()
            for upvote in oldCommentUpvotes:
                db.session.delete(upvote)
            db.session.commit()
            oldClipUpvotes = upvotes.clipUpvotes.query.all()
            for upvote in oldClipUpvotes:
                db.session.delete(upvote)
            db.session.commit()

            for restoredUpvote in restoreDict['channel_upvotes']:
                if restoredUpvote['userID'] != "None" and restoredUpvote['channelID'] != "None":
                    upvote = upvotes.channelUpvotes(int(restoredUpvote['userID']), int(restoredUpvote['channelID']))
                    upvote.id = int(restoredUpvote['id'])
                    db.session.add(upvote)
                else:
                    flash("Error Restoring Upvote: ID# " + str(restoredUpvote['id']), "error")
            db.session.commit()

            if 'restoreVideos' in request.form:
                for restoredUpvote in restoreDict['stream_upvotes']:
                    if restoredUpvote['userID'] != "None" and restoredUpvote['streamID'] != "None":
                        upvote = upvotes.streamUpvotes(int(restoredUpvote['userID']), int(restoredUpvote['streamID']))
                        upvote.id = int(restoredUpvote['id'])
                        db.session.add(upvote)
                    else:
                        flash("Error Restoring Upvote: ID# " + str(restoredUpvote['id']), "error")
            db.session.commit()

            if 'restoreVideos' in request.form:
                for restoredUpvote in restoreDict['video_upvotes']:
                    if restoredUpvote['userID'] != "None" and restoredUpvote['videoID'] != "None":
                        upvote = upvotes.videoUpvotes(int(restoredUpvote['userID']), int(restoredUpvote['videoID']))
                        upvote.id = int(restoredUpvote['id'])
                        db.session.add(upvote)
                    flash("Error Restoring Upvote: ID# " + str(restoredUpvote['id']), "error")
                db.session.commit()
                for restoredUpvote in restoreDict['clip_upvotes']:
                    if restoredUpvote['userID'] != "None" and restoredUpvote['clipID'] != "None":
                        upvote = upvotes.clipUpvotes(int(restoredUpvote['userID']), int(restoredUpvote['clipID']))
                        upvote.id = int(restoredUpvote['id'])
                        db.session.add(upvote)
                    flash("Error Restoring Upvote: ID# " + str(restoredUpvote['id']), "error")
                db.session.commit()
            if 'restoreVideos' in request.form:
                for restoredUpvote in restoreDict['comment_upvotes']:
                    if restoredUpvote['userID'] != "None" and restoredUpvote['commentID'] != "None":
                        upvote = upvotes.commentUpvotes(int(restoredUpvote['userID']), int(restoredUpvote['commentID']))
                        upvote.id = int(restoredUpvote['id'])
                        db.session.add(upvote)
                    else:
                        flash("Error Restoring Upvote: ID# " + str(restoredUpvote['id']), "error")

            # Logic to Check the DB Version
            dbVersionQuery = dbVersion.dbVersion.query.first()

            if dbVersionQuery is None:
                newDBVersion = dbVersion.dbVersion(globalvars.appDBVersion)
                db.session.add(newDBVersion)
                db.session.commit()

            db.session.commit()

            # Import Theme Data into Theme Dictionary
            with open('templates/themes/' + sysSettings.systemTheme + '/theme.json') as f:

                globalvars.themeData = json.load(f)

            flash("Database Restored from Backup", "success")
            session.clear()
            return redirect(url_for('main_page', page="backup"))

    else:
        if settings.settings.query.all():
            flash("Invalid Restore Attempt","error")
            return redirect(url_for('main_page'))
        else:
            return redirect(url_for('initialSetup'))


@app.route('/settings/channels', methods=['POST','GET'])
@login_required
@roles_required('Streamer')
def settings_channels_page():
    sysSettings = settings.settings.query.first()
    channelChatBGOptions = [{'name': 'Default', 'value': 'Standard'},{'name': 'Plain White', 'value': 'PlainWhite'}, {'name': 'Deep Space', 'value': 'DeepSpace'}, {'name': 'Blood Red', 'value': 'BloodRed'}, {'name': 'Terminal', 'value': 'Terminal'}, {'name': 'Lawrencium', 'value': 'Lawrencium'}, {'name': 'Lush', 'value': 'Lush'}, {'name': 'Transparent', 'value': 'Transparent'}]
    channelChatAnimationOptions = [{'name':'No Animation', 'value':'None'},{'name': 'Slide-in From Left', 'value': 'slide-in-left'}, {'name':'Slide-In Blurred From Left','value':'slide-in-blurred-left'}, {'name':'Fade-In', 'value': 'fade-in-fwd'}]
    videos_root = app.config['WEB_ROOT'] + 'videos/'

    if request.method == 'GET':
        if request.args.get("action") is not None:
            action = request.args.get("action")
            streamKey = request.args.get("streamkey")

            requestedChannel = Channel.Channel.query.filter_by(streamKey=streamKey).first()

            if action == "delete":
                if current_user.id == requestedChannel.owningUser:

                    filePath = videos_root + requestedChannel.channelLoc
                    if filePath != videos_root:
                        shutil.rmtree(filePath, ignore_errors=True)

                    channelVid = requestedChannel.recordedVideo
                    channelUpvotes = requestedChannel.upvotes
                    channelStreams = requestedChannel.stream

                    for entry in channelVid:

                        vidComments = channelVid.comments
                        for comment in vidComments:
                            db.session.delete(comment)

                        vidViews = views.views.query.filter_by(viewType=1, itemID=channelVid.id)
                        for view in vidViews:
                            db.session.delete(view)

                        db.session.delete(entry)
                    for entry in channelUpvotes:
                        db.session.delete(entry)
                    for entry in channelStreams:
                        db.session.delete(entry)

                    db.session.delete(requestedChannel)
                    db.session.commit()
                    flash("Channel Deleted")
                else:
                    flash("Invalid Deletion Attempt","Error")

    elif request.method == 'POST':

        requestType = request.form['type']
        channelName = system.strip_html(request.form['channelName'])
        topic = request.form['channeltopic']
        description = system.strip_html(request.form['description'])


        record = False

        if 'recordSelect' in request.form and sysSettings.allowRecording is True:
            record = True

        autoPublish = False
        if 'publishSelect' in request.form:
            autoPublish = True

        rtmpRestream = False
        if 'rtmpSelect' in request.form:
            rtmpRestream = True

        chatEnabled = False

        if 'chatSelect' in request.form:
            chatEnabled = True

        chatJoinNotifications = False
        if 'chatJoinNotificationSelect' in request.form:
            chatJoinNotifications = True

        allowComments = False

        if 'allowComments' in request.form:
            allowComments = True

        protection = False

        if 'channelProtection' in request.form:
            protection = True

        if requestType == 'new':

            newUUID = str(uuid.uuid4())

            newChannel = Channel.Channel(current_user.id, newUUID, channelName, topic, record, chatEnabled, allowComments, description)

            if 'photo' in request.files:
                file = request.files['photo']
                if file.filename != '':
                    filename = photos.save(request.files['photo'], name=str(uuid.uuid4()) + '.')
                    newChannel.imageLocation = filename

            db.session.add(newChannel)
            db.session.commit()

        elif requestType == 'change':
            streamKey = request.form['streamKey']
            origStreamKey = request.form['origStreamKey']

            chatBG = request.form['chatBG']
            chatAnimation = request.form['chatAnimation']
            chatTextColor = request.form['chatTextColor']

            defaultstreamName = request.form['channelStreamName']

            rtmpRestreamDestination = request.form['rtmpDestination']

            # TODO Validate ChatBG and chatAnimation

            requestedChannel = Channel.Channel.query.filter_by(streamKey=origStreamKey).first()

            if current_user.id == requestedChannel.owningUser:
                requestedChannel.channelName = channelName
                requestedChannel.streamKey = streamKey
                requestedChannel.topic = topic
                requestedChannel.record = record
                requestedChannel.chatEnabled = chatEnabled
                requestedChannel.allowComments = allowComments
                requestedChannel.description = description
                requestedChannel.chatBG = chatBG
                requestedChannel.showChatJoinLeaveNotification = chatJoinNotifications
                requestedChannel.chatAnimation = chatAnimation
                requestedChannel.chatTextColor = chatTextColor
                requestedChannel.protected = protection
                requestedChannel.defaultStreamName = defaultstreamName
                requestedChannel.autoPublish = autoPublish
                requestedChannel.rtmpRestream = rtmpRestream
                requestedChannel.rtmpRestreamDestination = rtmpRestreamDestination

                if 'photo' in request.files:
                    file = request.files['photo']
                    if file.filename != '':
                        oldImage = None

                        if requestedChannel.imageLocation is not None:
                            oldImage = requestedChannel.imageLocation

                        filename = photos.save(request.files['photo'], name=str(uuid.uuid4()) + '.')
                        requestedChannel.imageLocation = filename

                        if oldImage is not None:
                            try:
                                os.remove(oldImage)
                            except OSError:
                                pass

                if 'offlinephoto' in request.files:
                    file = request.files['offlinephoto']
                    if file.filename != '':
                        oldImage = None

                        if requestedChannel.offlineImageLocation is not None:
                            oldImage = requestedChannel.offlineImageLocation

                        filename = photos.save(request.files['offlinephoto'], name=str(uuid.uuid4()) + '.')
                        requestedChannel.offlineImageLocation = filename

                        if oldImage is not None:
                            try:
                                os.remove(oldImage)
                            except OSError:
                                pass

                flash("Channel Edited")
                db.session.commit()
            else:
                flash("Invalid Change Attempt","Error")
            redirect(url_for('settings_channels_page'))

    topicList = topics.topics.query.all()
    user_channels = Channel.Channel.query.filter_by(owningUser = current_user.id).all()

    # Calculate Channel Views by Date based on Video or Live Views
    user_channels_stats = {}
    for channel in user_channels:

        # 30 Days Viewer Stats
        viewersTotal = 0

        statsViewsLiveDay = db.session.query(func.date(views.views.date), func.count(views.views.id)).filter(
            views.views.viewType == 0).filter(views.views.itemID == channel.id).filter(
            views.views.date > (datetime.datetime.now() - datetime.timedelta(days=30))).group_by(
            func.date(views.views.date)).all()
        statsViewsLiveDayArray = []
        for entry in statsViewsLiveDay:
            viewersTotal = viewersTotal + entry[1]
            statsViewsLiveDayArray.append({'t': (entry[0]), 'y': entry[1]})

        statsViewsRecordedDayDict = {}
        statsViewsRecordedDayArray = []

        for vid in channel.recordedVideo:
            statsViewsRecordedDay = db.session.query(func.date(views.views.date), func.count(views.views.id)).filter(
                views.views.viewType == 1).filter(views.views.itemID == vid.id).filter(
                views.views.date > (datetime.datetime.now() - datetime.timedelta(days=30))).group_by(
                func.date(views.views.date)).all()

            for entry in statsViewsRecordedDay:
                if entry[0] in statsViewsRecordedDayDict:
                    statsViewsRecordedDayDict[entry[0]] = statsViewsRecordedDayDict[entry[0]] + entry[1]
                else:
                    statsViewsRecordedDayDict[entry[0]] = entry[1]
                viewersTotal = viewersTotal + entry[1]

        for entry in statsViewsRecordedDayDict:
            statsViewsRecordedDayArray.append({'t': entry, 'y': statsViewsRecordedDayDict[entry]})

        sortedStatsArray = sorted(statsViewsRecordedDayArray, key=lambda d: d['t'])

        statsViewsDay = {
            'live': statsViewsLiveDayArray,
            'recorded': sortedStatsArray
        }

        user_channels_stats[channel.id] = statsViewsDay

    return render_template(themes.checkOverride('user_channels.html'), channels=user_channels, topics=topicList, viewStats=user_channels_stats, channelChatBGOptions=channelChatBGOptions, channelChatAnimationOptions=channelChatAnimationOptions)

@app.route('/settings/api', methods=['GET'])
@login_required
@roles_required('Streamer')
def settings_apikeys_page():
    apiKeyQuery = apikey.apikey.query.filter_by(userID=current_user.id).all()
    return render_template(themes.checkOverride('apikeys.html'),apikeys=apiKeyQuery)

@app.route('/settings/api/<string:action>', methods=['POST'])
@login_required
@roles_required('Streamer')
def settings_apikeys_post_page(action):
    if action == "new":
        newapi = apikey.apikey(current_user.id, 1, request.form['keyName'], request.form['expiration'])
        db.session.add(newapi)
        db.session.commit()
        flash("New API Key Added","success")
    elif action == "delete":
        apiQuery = apikey.apikey.query.filter_by(key=request.form['key']).first()
        if apiQuery.userID == current_user.id:
            db.session.delete(apiQuery)
            db.session.commit()
            flash("API Key Deleted","success")
        else:
            flash("Invalid API Key","error")
    return redirect(url_for('settings_apikeys_page'))

@app.route('/settings/initialSetup', methods=['POST'])
def initialSetup():
    firstRunCheck = system.check_existing_settings()

    if firstRunCheck is False:

        sysSettings = settings.settings.query.all()

        for setting in sysSettings:
            db.session.delete(setting)
        db.session.commit()

        username = request.form['username']
        email = request.form['email']
        password1 = request.form['password1']
        password2 = request.form['password2']
        serverName = request.form['serverName']
        serverProtocol = str(request.form['siteProtocol'])
        serverAddress = str(request.form['serverAddress'])
        smtpSendAs = request.form['smtpSendAs']
        smtpAddress = request.form['smtpAddress']
        smtpPort = request.form['smtpPort']
        smtpUser = request.form['smtpUser']
        smtpPassword = request.form['smtpPassword']

        recordSelect = False
        uploadSelect = False
        adaptiveStreaming = False
        showEmptyTables = False
        allowComments = False
        smtpTLS = False
        smtpSSL = False

        if 'recordSelect' in request.form:
            recordSelect = True

        if 'uploadSelect' in request.form:
            uploadSelect = True

        if 'adaptiveStreaming' in request.form:
            adaptiveStreaming = True

        if 'showEmptyTables' in request.form:
            showEmptyTables = True

        if 'allowComments' in request.form:
            allowComments = True

        if 'smtpTLS' in request.form:
            smtpTLS = True

        if 'smtpSSL' in request.form:
            smtpSSL = True

        validAddress = system.formatSiteAddress(serverAddress)
        try:
            externalIP = socket.gethostbyname(validAddress)
        except socket.gaierror:
            flash("Invalid Server Address/IP", "error")
            return redirect(url_for("initialSetup"))

        if password1 == password2:

            passwordhash = utils.hash_password(password1)

            user_datastore.create_user(email=email, username=username, password=passwordhash)
            db.session.commit()
            user = Sec.User.query.filter_by(username=username).first()
            user.confirmed_at = datetime.datetime.now()

            user_datastore.find_or_create_role(name='Admin', description='Administrator')
            user_datastore.find_or_create_role(name='User', description='User')
            user_datastore.find_or_create_role(name='Streamer', description='Streamer')
            user_datastore.find_or_create_role(name='Recorder', description='Recorder')
            user_datastore.find_or_create_role(name='Uploader', description='Uploader')

            user_datastore.add_role_to_user(user, 'Admin')
            user_datastore.add_role_to_user(user, 'Streamer')
            user_datastore.add_role_to_user(user, 'Recorder')
            user_datastore.add_role_to_user(user, 'Uploader')
            user_datastore.add_role_to_user(user, 'User')

            serverSettings = settings.settings(serverName, serverProtocol, serverAddress, smtpAddress, smtpPort, smtpTLS, smtpSSL, smtpUser, smtpPassword, smtpSendAs, recordSelect, uploadSelect, adaptiveStreaming, showEmptyTables, allowComments, globalvars.version)
            db.session.add(serverSettings)
            db.session.commit()

            sysSettings = settings.settings.query.first()

            if settings is not None:
                app.config.update(
                    SERVER_NAME=None,
                    SECURITY_EMAIL_SENDER=sysSettings.smtpSendAs,
                    MAIL_DEFAULT_SENDER=sysSettings.smtpSendAs,
                    MAIL_SERVER=sysSettings.smtpAddress,
                    MAIL_PORT=sysSettings.smtpPort,
                    MAIL_USE_TLS=sysSettings.smtpTLS,
                    MAIL_USE_SSL=sysSettings.smtpSSL,
                    MAIL_USERNAME=sysSettings.smtpUsername,
                    MAIL_PASSWORD=sysSettings.smtpPassword,
                    SECURITY_EMAIL_SUBJECT_PASSWORD_RESET = sysSettings.siteName + " - Password Reset Request",
                    SECURITY_EMAIL_SUBJECT_REGISTER = sysSettings.siteName + " - Welcome!",
                    SECURITY_EMAIL_SUBJECT_PASSWORD_NOTICE = sysSettings.siteName + " - Password Reset Notification",
                    SECURITY_EMAIL_SUBJECT_CONFIRM = sysSettings.siteName + " - Email Confirmation Request",
                    SECURITY_FORGOT_PASSWORD_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/forgot_password.html',
                    SECURITY_LOGIN_USER_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/login_user.html',
                    SECURITY_REGISTER_USER_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/register_user.html',
                    SECURITY_RESET_PASSWORD_TEMPLATE = 'themes/' + sysSettings.systemTheme + '/security/reset_password.html',
                    SECURITY_SEND_CONFIRMATION_TEMPLATE = 'themes/'  + sysSettings.systemTheme + '/security/send_confirmation.html')

                email .init_app(app)
                email.app = app

                # Import Theme Data into Theme Dictionary
                with open('templates/themes/' + sysSettings.systemTheme + '/theme.json') as f:

                    globalvars.themeData = json.load(f)

        else:
            flash('Passwords do not match')
            return redirect(url_for('main_page'))

    return redirect(url_for('main_page'))


@app.route('/rtmpstat/<node>')
@login_required
@roles_required('Admin')
def rtmpStat_page(node):
    r = None
    if node == "localhost":
        r = requests.get("http://127.0.0.1:9000/stat").text
    else:
        nodeQuery = settings.edgeStreamer.query.filter_by(address=node).first()
        if nodeQuery is not None:
            r = requests.get('http://' + nodeQuery.address + ":9000/stat").text

    if r is not None:
        data = None
        try:
            data = xmltodict.parse(r)
            data = json.dumps(data)
        except:
            return abort(500)
        return (data)
    return abort(500)

@app.route('/search', methods=["POST"])
def search_page():
    if 'term' in request.form:
        search = str(request.form['term'])

        topicList = topics.topics.query.filter(topics.topics.name.contains(search)).all()

        streamerList = []
        streamerList1 = Sec.User.query.filter(Sec.User.username.contains(search)).all()
        streamerList2 = Sec.User.query.filter(Sec.User.biography.contains(search)).all()
        for stream in streamerList1:
            if stream.has_role('Streamer'):
                streamerList.append(stream)
        for stream in streamerList2:
            if stream not in streamerList and stream.has_role('streamer'):
                streamerList.append(stream)

        channelList = []
        channelList1 = Channel.Channel.query.filter(Channel.Channel.channelName.contains(search)).all()
        channelList2 = Channel.Channel.query.filter(Channel.Channel.description.contains(search)).all()
        for channel in channelList1:
            channelList.append(channel)
        for channel in channelList2:
            if channel not in channelList:
                channelList.append(channel)

        videoList = []
        videoList1 = RecordedVideo.RecordedVideo.query.filter(RecordedVideo.RecordedVideo.channelName.contains(search)).filter(RecordedVideo.RecordedVideo.pending == False, RecordedVideo.RecordedVideo.published == True).all()
        videoList2 = RecordedVideo.RecordedVideo.query.filter(RecordedVideo.RecordedVideo.description.contains(search)).filter(RecordedVideo.RecordedVideo.pending == False, RecordedVideo.RecordedVideo.published == True).all()
        for video in videoList1:
            videoList.append(video)
        for video in videoList2:
            if video not in videoList:
                videoList.append(video)

        streamList = Stream.Stream.query.filter(Stream.Stream.streamName.contains(search)).all()

        clipList = []
        clipList1 = RecordedVideo.Clips.query.filter(RecordedVideo.Clips.clipName.contains(search)).filter(RecordedVideo.Clips.published == True).all()
        clipList2 = RecordedVideo.Clips.query.filter(RecordedVideo.Clips.description.contains(search)).filter(RecordedVideo.Clips.published == True).all()
        for clip in clipList1:
            clipList.append(clip)
        for clip in clipList2:
            if clip not in clipList:
                clipList.append(clip)

        return render_template(themes.checkOverride('search.html'), topicList=topicList, streamerList=streamerList, channelList=channelList, videoList=videoList, streamList=streamList, clipList=clipList)

    return redirect(url_for('main_page'))

@login_required
@app.route('/notifications')
def notification_page():
    notificationQuery = notifications.userNotification.query.filter_by(userID=current_user.id, read=False).order_by(notifications.userNotification.timestamp.desc())
    return render_template(themes.checkOverride('notifications.html'), notificationList=notificationQuery)

@app.route('/auth', methods=["POST","GET"])
def auth_check():

    sysSettings = settings.settings.query.with_entities(settings.settings.protectionEnabled).first()
    if sysSettings.protectionEnabled is False:
        return 'OK'

    channelID = ""
    if 'X-Channel-ID' in request.headers:
        channelID = request.headers['X-Channel-ID']

        channelQuery = Channel.Channel.query.filter_by(channelLoc=channelID).with_entities(Channel.Channel.id, Channel.Channel.protected).first()
        if channelQuery is not None:
            if channelQuery.protected:
                if securityFunc.check_isValidChannelViewer(channelQuery.id):
                    db.session.close()
                    return 'OK'
                else:
                    db.session.close()
                    return abort(401)
            else:
                return 'OK'

    db.session.close()
    abort(400)

### Start NGINX-RTMP Authentication Functions

@app.route('/auth-key', methods=['POST'])
def streamkey_check():
    sysSettings = settings.settings.query.first()

    key = request.form['name']
    ipaddress = request.form['addr']

    channelRequest = Channel.Channel.query.filter_by(streamKey=key).first()

    currentTime = datetime.datetime.now()

    if channelRequest is not None:
        userQuery = Sec.User.query.filter_by(id=channelRequest.owningUser).first()
        if userQuery is not None:
            if userQuery.has_role('Streamer'):

                if not userQuery.active:
                    returnMessage = {'time': str(currentTime), 'status': 'Unauthorized User - User has been Disabled', 'key': str(key), 'ipAddress': str(ipaddress)}
                    print(returnMessage)
                    return abort(400)

                returnMessage = {'time': str(currentTime), 'status': 'Successful Key Auth', 'key': str(key), 'channelName': str(channelRequest.channelName), 'userName': str(channelRequest.owningUser), 'ipAddress': str(ipaddress)}
                print(returnMessage)

                validAddress = system.formatSiteAddress(sysSettings.siteAddress)

                externalIP = socket.gethostbyname(validAddress)
                existingStreamQuery = Stream.Stream.query.filter_by(linkedChannel=channelRequest.id).all()
                if existingStreamQuery:
                    for stream in existingStreamQuery:
                        db.session.delete(stream)
                    db.session.commit()

                defaultStreamName = templateFilters.normalize_date(str(currentTime))
                if channelRequest.defaultStreamName != "":
                    defaultStreamName = channelRequest.defaultStreamName

                newStream = Stream.Stream(key, defaultStreamName, int(channelRequest.id), channelRequest.topic)
                db.session.add(newStream)
                db.session.commit()

                if channelRequest.record is False or sysSettings.allowRecording is False or userQuery.has_role("Recorder") is False:
                    if sysSettings.adaptiveStreaming:
                        return redirect('rtmp://' + coreNginxRTMPAddress + '/stream-data-adapt/' + channelRequest.channelLoc, code=302)
                    else:
                        return redirect('rtmp://' + coreNginxRTMPAddress + '/stream-data/' + channelRequest.channelLoc, code=302)
                elif channelRequest.record is True and sysSettings.allowRecording is True and userQuery.has_role("Recorder"):

                    userCheck = Sec.User.query.filter_by(id=channelRequest.owningUser).first()
                    existingRecordingQuery = RecordedVideo.RecordedVideo.query.filter_by(channelID=channelRequest.id, pending=True).all()
                    if existingRecordingQuery:
                        for recording in existingRecordingQuery:
                            db.session.delete(recording)
                            db.session.commit()

                    newRecording = RecordedVideo.RecordedVideo(userCheck.id, channelRequest.id, channelRequest.channelName, channelRequest.topic, 0, "", currentTime, channelRequest.allowComments, False)
                    db.session.add(newRecording)
                    db.session.commit()
                    if sysSettings.adaptiveStreaming:
                        return redirect('rtmp://' + coreNginxRTMPAddress + '/streamrec-data-adapt/' + channelRequest.channelLoc, code=302)
                    else:
                        return redirect('rtmp://' + coreNginxRTMPAddress + '/streamrec-data/' + channelRequest.channelLoc, code=302)
                else:
                    returnMessage = {'time': str(currentTime), 'status': 'Streaming Error due to mismatched settings', 'key': str(key), 'ipAddress': str(ipaddress)}
                    print(returnMessage)
                    db.session.close()
                    return abort(400)
            else:
                returnMessage = {'time': str(currentTime), 'status': 'Unauthorized User - Missing Streamer Role', 'key': str(key), 'ipAddress': str(ipaddress)}
                print(returnMessage)
                db.session.close()
                return abort(400)
        else:
            returnMessage = {'time': str(currentTime), 'status': 'Unauthorized User - No Such User', 'key': str(key), 'ipAddress': str(ipaddress)}
            print(returnMessage)
            db.session.close()
            return abort(400)
    else:
        returnMessage = {'time': str(currentTime), 'status': 'Failed Key Auth', 'key':str(key), 'ipAddress': str(ipaddress)}
        print(returnMessage)
        db.session.close()
        return abort(400)


@app.route('/auth-user', methods=['POST'])
def user_auth_check():
    sysSettings = settings.settings.query.first()

    key = request.form['name']
    ipaddress = request.form['addr']

    requestedChannel = Channel.Channel.query.filter_by(channelLoc=key).first()

    if requestedChannel is not None:
        authedStream = Stream.Stream.query.filter_by(streamKey=requestedChannel.streamKey).first()

        if authedStream is not None:
            returnMessage = {'time': str(datetime.datetime.now()), 'status': 'Successful Channel Auth', 'key': str(requestedChannel.streamKey), 'channelName': str(requestedChannel.channelName), 'ipAddress': str(ipaddress)}
            print(returnMessage)

            if requestedChannel.imageLocation is None:
                channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
            else:
                channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + requestedChannel.imageLocation)

            webhookFunc.runWebhook(requestedChannel.id, 0, channelname=requestedChannel.channelName, channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(requestedChannel.id)), channeltopic=requestedChannel.topic,
                       channelimage=channelImage, streamer=templateFilters.get_userName(requestedChannel.owningUser), channeldescription=str(requestedChannel.description),
                       streamname=authedStream.streamName, streamurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/view/" + requestedChannel.channelLoc), streamtopic=templateFilters.get_topicName(authedStream.topic),
                       streamimage=(sysSettings.siteProtocol + sysSettings.siteAddress + "/stream-thumb/" + requestedChannel.channelLoc + ".png"))

            subscriptionQuery = subscriptions.channelSubs.query.filter_by(channelID=requestedChannel.id).all()
            for sub in subscriptionQuery:
                # Create Notification for Channel Subs
                newNotification = notifications.userNotification(templateFilters.get_userName(requestedChannel.owningUser) + " has started a live stream in " + requestedChannel.channelName, "/view/" + str(requestedChannel.channelLoc),
                                                                 "/images/" + str(requestedChannel.owner.pictureLocation), sub.userID)
                db.session.add(newNotification)
            db.session.commit()

            try:
                subsFunc.processSubscriptions(requestedChannel.id,
                                 sysSettings.siteName + " - " + requestedChannel.channelName + " has started a stream",
                                 "<html><body><img src='" + sysSettings.siteProtocol + sysSettings.siteAddress + sysSettings.systemLogo + "'><p>Channel " + requestedChannel.channelName +
                                 " has started a new video stream.</p><p>Click this link to watch<br><a href='" + sysSettings.siteProtocol + sysSettings.siteAddress + "/view/" + str(requestedChannel.channelLoc)
                                 + "'>" + requestedChannel.channelName + "</a></p>")
            except:
                system.newLog(0, "Subscriptions Failed due to possible misconfiguration")

            inputLocation = ""
            if requestedChannel.protected and sysSettings.protectionEnabled:
                owningUser = Sec.User.query.filter_by(id=requestedChannel.owningUser).first()
                secureHash = hashlib.sha256((owningUser.username + requestedChannel.channelLoc + owningUser.password).encode('utf-8')).hexdigest()
                username = owningUser.username
                inputLocation = 'rtmp://' + coreNginxRTMPAddress + ":1935/live/" + requestedChannel.channelLoc + "?username=" + username + "&hash=" + secureHash
            else:
                inputLocation = "rtmp://" + coreNginxRTMPAddress + ":1935/live/" + requestedChannel.channelLoc

            # Begin RTMP Restream Function
            if requestedChannel.rtmpRestream is True:

                p = subprocess.Popen(["ffmpeg", "-i", inputLocation, "-c", "copy", "-f", "flv", requestedChannel.rtmpRestreamDestination, "-c:v", "libx264", "-maxrate", str(sysSettings.restreamMaxBitrate) + "k", "-bufsize", "6000k", "-c:a", "aac", "-b:a", "160k", "-ac", "2"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                globalvars.restreamSubprocesses[requestedChannel.channelLoc] = p

            # Start OSP Edge Nodes
            ospEdgeNodeQuery = settings.edgeStreamer.query.filter_by(active=True).all()
            if ospEdgeNodeQuery is not []:
                globalvars.edgeRestreamSubprocesses[requestedChannel.channelLoc] = []

                for node in ospEdgeNodeQuery:
                    subprocessConstructor = ["ffmpeg", "-i", inputLocation, "-c", "copy"]
                    subprocessConstructor.append("-f")
                    subprocessConstructor.append("flv")
                    if sysSettings.adaptiveStreaming:
                        subprocessConstructor.append("rtmp://" + node.address + "/stream-data-adapt/" + requestedChannel.channelLoc)
                    else:
                        subprocessConstructor.append("rtmp://" + node.address + "/stream-data/" + requestedChannel.channelLoc)

                    p = subprocess.Popen(subprocessConstructor, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    globalvars.edgeRestreamSubprocesses[requestedChannel.channelLoc].append(p)

            db.session.close()
            return 'OK'
        else:
            returnMessage = {'time': str(datetime.datetime.now()), 'status': 'Failed Channel Auth. No Authorized Stream Key', 'channelName': str(key), 'ipAddress': str(ipaddress)}
            print(returnMessage)
            db.session.close()
            return abort(400)
    else:
        returnMessage = {'time': str(datetime.datetime.now()), 'status': 'Failed Channel Auth. Channel Loc does not match Channel', 'channelName': str(key), 'ipAddress': str(ipaddress)}
        print(returnMessage)
        db.session.close()
        return abort(400)


@app.route('/deauth-user', methods=['POST'])
def user_deauth_check():
    sysSettings = settings.settings.query.first()

    key = request.form['name']
    ipaddress = request.form['addr']

    authedStream = Stream.Stream.query.filter_by(streamKey=key).all()

    channelRequest = Channel.Channel.query.filter_by(streamKey=key).first()

    if authedStream is not []:
        for stream in authedStream:
            streamUpvotes = upvotes.streamUpvotes.query.filter_by(streamID=stream.id).all()
            pendingVideo = RecordedVideo.RecordedVideo.query.filter_by(channelID=channelRequest.id, videoLocation="", pending=True).first()

            if pendingVideo is not None:
                pendingVideo.channelName = stream.streamName
                pendingVideo.views = stream.totalViewers
                pendingVideo.topic = stream.topic

                for upvote in streamUpvotes:
                    newVideoUpvote = upvotes.videoUpvotes(upvote.userID, pendingVideo.id)
                    db.session.add(newVideoUpvote)
                db.session.commit()

            for vid in streamUpvotes:
                db.session.delete(vid)
            db.session.delete(stream)
            db.session.commit()

            # End RTMP Restream Function
            if channelRequest.rtmpRestream is True:
                if channelRequest.channelLoc in globalvars.restreamSubprocesses:
                    p = globalvars.restreamSubprocesses[channelRequest.channelLoc]
                    p.kill()
                    try:
                        del globalvars.restreamSubprocesses[channelRequest.channelLoc]
                    except KeyError:
                        pass

            if channelRequest.channelLoc in globalvars.edgeRestreamSubprocesses:
                for p in globalvars.edgeRestreamSubprocesses[channelRequest.channelLoc]:
                    p.kill()
                try:
                    del globalvars.edgeRestreamSubprocesses[channelRequest.channelLoc]
                except KeyError:
                    pass

            returnMessage = {'time': str(datetime.datetime.now()), 'status': 'Stream Closed', 'key': str(key), 'channelName': str(channelRequest.channelName), 'userName':str(channelRequest.owningUser), 'ipAddress': str(ipaddress)}

            print(returnMessage)

            if channelRequest.imageLocation is None:
                channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
            else:
                channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + channelRequest.imageLocation)

            webhookFunc.runWebhook(channelRequest.id, 1, channelname=channelRequest.channelName,
                       channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(channelRequest.id)),
                       channeltopic=channelRequest.topic,
                       channelimage=channelImage, streamer=templateFilters.get_userName(channelRequest.owningUser),
                       channeldescription=str(channelRequest.description),
                       streamname=stream.streamName,
                       streamurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/view/" + channelRequest.channelLoc),
                       streamtopic=templateFilters.get_topicName(stream.topic),
                       streamimage=(sysSettings.siteProtocol + sysSettings.siteAddress + "/stream-thumb/" + str(channelRequest.channelLoc) + ".png"))
        return 'OK'
    else:
        returnMessage = {'time': str(datetime.datetime.now()), 'status': 'Stream Closure Failure - No Such Stream', 'key': str(key), 'ipAddress': str(ipaddress)}
        print(returnMessage)
        db.session.close()
        return abort(400)


@app.route('/recComplete', methods=['POST'])
def rec_Complete_handler():
    key = request.form['name']
    path = request.form['path']

    sysSettings = settings.settings.query.first()

    requestedChannel = Channel.Channel.query.filter_by(channelLoc=key).first()

    pendingVideo = RecordedVideo.RecordedVideo.query.filter_by(channelID=requestedChannel.id, videoLocation="", pending=True).first()

    videoPath = path.replace('/tmp/',requestedChannel.channelLoc + '/')
    imagePath = videoPath.replace('.flv','.png')
    gifPath = videoPath.replace('.flv', '.gif')
    videoPath = videoPath.replace('.flv','.mp4')

    pendingVideo.thumbnailLocation = imagePath
    pendingVideo.videoLocation = videoPath
    pendingVideo.gifLocation = gifPath

    videos_root = app.config['WEB_ROOT'] + 'videos/'
    fullVidPath = videos_root + videoPath

    pendingVideo.pending = False

    if requestedChannel.autoPublish is True:
        pendingVideo.published = True
    else:
        pendingVideo.published = False

    db.session.commit()

    if requestedChannel.imageLocation is None:
        channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
    else:
        channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + requestedChannel.imageLocation)

    if requestedChannel.autoPublish is True:
        webhookFunc.runWebhook(requestedChannel.id, 6, channelname=requestedChannel.channelName,
               channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(requestedChannel.id)),
               channeltopic=templateFilters.get_topicName(requestedChannel.topic),
               channelimage=channelImage, streamer=templateFilters.get_userName(requestedChannel.owningUser),
               channeldescription=str(requestedChannel.description), videoname=pendingVideo.channelName,
               videodate=pendingVideo.videoDate, videodescription=pendingVideo.description,videotopic=templateFilters.get_topicName(pendingVideo.topic),
               videourl=(sysSettings.siteProtocol + sysSettings.siteAddress + '/play/' + str(pendingVideo.id)),
               videothumbnail=(sysSettings.siteProtocol + sysSettings.siteAddress + '/videos/' + str(pendingVideo.thumbnailLocation)))

        subscriptionQuery = subscriptions.channelSubs.query.filter_by(channelID=requestedChannel.id).all()
        for sub in subscriptionQuery:
            # Create Notification for Channel Subs
            newNotification = notifications.userNotification(templateFilters.get_userName(requestedChannel.owningUser) + " has posted a new video to " + requestedChannel.channelName + " titled " + pendingVideo.channelName, '/play/' + str(pendingVideo.id),
                                                             "/images/" + str(requestedChannel.owner.pictureLocation), sub.userID)
            db.session.add(newNotification)
        db.session.commit()

        subsFunc.processSubscriptions(requestedChannel.id, sysSettings.siteName + " - " + requestedChannel.channelName + " has posted a new video",
                         "<html><body><img src='" + sysSettings.siteProtocol + sysSettings.siteAddress + sysSettings.systemLogo + "'><p>Channel " + requestedChannel.channelName + " has posted a new video titled <u>" + pendingVideo.channelName +
                         "</u> to the channel.</p><p>Click this link to watch<br><a href='" + sysSettings.siteProtocol + sysSettings.siteAddress + "/play/" + str(pendingVideo.id) + "'>" + pendingVideo.channelName + "</a></p>")

    while not os.path.exists(fullVidPath):
        time.sleep(1)

    if os.path.isfile(fullVidPath):
        pendingVideo.length = videoFunc.getVidLength(fullVidPath)
        db.session.commit()

    db.session.close()
    return 'OK'

@app.route('/playbackAuth', methods=['POST'])
def playback_auth_handler():
    stream = request.form['name']

    streamQuery = Channel.Channel.query.filter_by(channelLoc=stream).first()
    if streamQuery is not None:

        if streamQuery.protected is False:
            db.session.close()
            return 'OK'
        else:
            username = request.form['username']
            secureHash = request.form['hash']

            if streamQuery is not None:
                requestedUser = Sec.User.query.filter_by(username=username).first()
                if requestedUser is not None:
                    isValid = False
                    validHash = hashlib.sha256((requestedUser.username + streamQuery.channelLoc + requestedUser.password).encode('utf-8')).hexdigest()
                    if secureHash == validHash:
                        isValid = True
                    if isValid is True:
                        if streamQuery.owningUser == requestedUser.id:
                            db.session.close()
                            return 'OK'
                        else:
                            if securityFunc.check_isUserValidRTMPViewer(requestedUser.id,streamQuery.id):
                                db.session.close()
                                return 'OK'
    db.session.close()
    return abort(400)

@app.route('/robots.txt')
def static_from_root():
    return send_from_directory(app.static_folder, request.path[1:])

### Start Socket.IO Functions ###

@socketio.on('testEmail')
def test_email(info):
    sysSettings = settings.settings.query.all()
    validTester = False
    if sysSettings == [] or sysSettings is None:
        validTester = True
    else:
        if current_user.has_role('Admin'):
            validTester = True
    if validTester is True:
        smtpServer = info['smtpServer']
        smtpPort = int(info['smtpPort'])
        smtpTLS = bool(info['smtpTLS'])
        smtpSSL = bool(info['smtpSSL'])
        smtpUsername = info['smtpUsername']
        smtpPassword = info['smtpPassword']
        smtpSender = info['smtpSender']
        smtpReceiver = info['smtpReceiver']

        results = system.sendTestEmail(smtpServer, smtpPort, smtpTLS, smtpSSL, smtpUsername, smtpPassword, smtpSender, smtpReceiver)
        db.session.close()
        emit('testEmailResults', {'results': str(results)}, broadcast=False)
        return 'OK'

@socketio.on('toggleChannelSubscription')
@limiter.limit("10/minute")
def toggle_chanSub(payload):
    if current_user.is_authenticated:
        sysSettings = settings.settings.query.first()
        if 'channelID' in payload:
            channelQuery = Channel.Channel.query.filter_by(id=int(payload['channelID'])).first()
            if channelQuery is not None:
                currentSubscription = subscriptions.channelSubs.query.filter_by(channelID=channelQuery.id, userID=current_user.id).first()
                subState = False
                if currentSubscription is None:
                    newSub = subscriptions.channelSubs(channelQuery.id, current_user.id)
                    db.session.add(newSub)
                    subState = True

                    channelImage = None
                    if channelQuery.imageLocation is None:
                        channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
                    else:
                        channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + channelQuery.imageLocation)

                    pictureLocation = current_user.pictureLocation
                    if current_user.pictureLocation is None:
                        pictureLocation = '/static/img/user2.png'
                    else:
                        pictureLocation = '/images/' + pictureLocation

                    # Create Notification for Channel Owner on New Subs
                    newNotification = notifications.userNotification(current_user.username + " has subscribed to " + channelQuery.channelName, "/channel/" + str(channelQuery.id), "/images/" + str(current_user.pictureLocation), channelQuery.owningUser)
                    db.session.add(newNotification)
                    db.session.commit()

                    webhookFunc.runWebhook(channelQuery.id, 10, channelname=channelQuery.channelName,
                               channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(channelQuery.id)),
                               channeltopic=templateFilters.get_topicName(channelQuery.topic),
                               channelimage=str(channelImage), streamer=templateFilters.get_userName(channelQuery.owningUser),
                               channeldescription=str(channelQuery.description),
                               user=current_user.username, userpicture=sysSettings.siteProtocol + sysSettings.siteAddress + str(pictureLocation))
                else:
                    db.session.delete(currentSubscription)
                db.session.commit()
                db.session.close()
                emit('sendChanSubResults', {'state': subState}, broadcast=False)
    db.session.close()
    return 'OK'

@socketio.on('cancelUpload')
def handle_videoupload_disconnect(videofilename):
    ospvideofilename = app.config['VIDEO_UPLOAD_TEMPFOLDER'] + '/' + str(videofilename['data'])
    thumbnailFilename = ospvideofilename + '.png'
    videoFilename = ospvideofilename + '.mp4'

    time.sleep(5)

    if os.path.exists(thumbnailFilename) and time.time() - os.stat(thumbnailFilename).st_mtime > 5:
            os.remove(thumbnailFilename)
    if os.path.exists(videoFilename) and time.time() - os.stat(videoFilename).st_mtime > 5:
            os.remove(videoFilename)

    return 'OK'

@socketio.on('newViewer')
def handle_new_viewer(streamData):
    channelLoc = str(streamData['data'])

    sysSettings = settings.settings.query.first()

    requestedChannel = Channel.Channel.query.filter_by(channelLoc=channelLoc).first()
    stream = Stream.Stream.query.filter_by(streamKey=requestedChannel.streamKey).first()

    userSID = request.cookies.get('ospSession')

    streamSIDList = r.smembers(channelLoc + '-streamSIDList')
    if streamSIDList is None:
        r.sadd(channelLoc + '-streamSIDList', userSID)
    elif userSID.encode('utf-8') not in streamSIDList:
        r.sadd(channelLoc + '-streamSIDList', userSID)

    currentViewers = len(streamSIDList)

    streamName = ""
    streamTopic = 0

    requestedChannel.currentViewers = currentViewers
    db.session.commit()

    if stream is not None:
        stream.currentViewers = currentViewers
        db.session.commit()
        streamName = stream.streamName
        streamTopic = stream.topic

    else:
        streamName = requestedChannel.channelName
        streamTopic = requestedChannel.topic

    if requestedChannel.imageLocation is None:
        channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
    else:
        channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + requestedChannel.imageLocation)

    join_room(streamData['data'])

    if requestedChannel.showChatJoinLeaveNotification:
        if current_user.is_authenticated:
            pictureLocation = current_user.pictureLocation
            if current_user.pictureLocation is None:
                pictureLocation = '/static/img/user2.png'
            else:
                pictureLocation = '/images/' + pictureLocation

            streamUserList = r.smembers(channelLoc + '-streamUserList')
            if streamUserList is None:
                r.rpush(channelLoc + '-streamUserList', current_user.username)
            elif current_user.username.encode('utf-8') not in streamUserList:
                r.rpush(channelLoc + '-streamUserList', current_user.username)

            emit('message', {'user':'Server','msg': current_user.username + ' has entered the room.', 'image': pictureLocation}, room=streamData['data'])
        else:
            emit('message', {'user':'Server','msg': 'Guest has entered the room.', 'image': '/static/img/user2.png'}, room=streamData['data'])

    else:
        if current_user.is_authenticated:
            r.rpush(channelLoc + '-streamUserList', current_user.username)

    if current_user.is_authenticated:
        pictureLocation = current_user.pictureLocation
        if current_user.pictureLocation is None:
            pictureLocation = '/static/img/user2.png'
        else:
            pictureLocation = '/images/' + pictureLocation

        webhookFunc.runWebhook(requestedChannel.id, 2, channelname=requestedChannel.channelName,
                   channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(requestedChannel.id)),
                   channeltopic=requestedChannel.topic, channelimage=channelImage, streamer=templateFilters.get_userName(requestedChannel.owningUser),
                   channeldescription=str(requestedChannel.description), streamname=streamName, streamurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/view/" + requestedChannel.channelLoc),
                   streamtopic=templateFilters.get_topicName(streamTopic), streamimage=(sysSettings.siteProtocol + sysSettings.siteAddress + "/stream-thumb/" + requestedChannel.channelLoc + ".png"),
                   user=current_user.username, userpicture=(sysSettings.siteProtocol + sysSettings.siteAddress + str(pictureLocation)))
    else:
        webhookFunc.runWebhook(requestedChannel.id, 2, channelname=requestedChannel.channelName,
                   channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(requestedChannel.id)),
                   channeltopic=requestedChannel.topic, channelimage=channelImage, streamer=templateFilters.get_userName(requestedChannel.owningUser),
                   channeldescription=str(requestedChannel.description), streamname=streamName,
                   streamurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/view/" + requestedChannel.channelLoc),
                   streamtopic=templateFilters.get_topicName(streamTopic), streamimage=(sysSettings.siteProtocol + sysSettings.siteAddress + "/stream-thumb/" + requestedChannel.channelLoc + ".png"),
                   user="Guest", userpicture=(sysSettings.siteProtocol + sysSettings.siteAddress + '/static/img/user2.png'))

    handle_viewer_total_request(streamData, room=streamData['data'])

    db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('openPopup')
def handle_new_popup_viewer(streamData):
    join_room(streamData['data'])
    return 'OK'

@socketio.on('removeViewer')
def handle_leaving_viewer(streamData):
    channelLoc = str(streamData['data'])

    requestedChannel = Channel.Channel.query.filter_by(channelLoc=channelLoc).first()
    stream = Stream.Stream.query.filter_by(streamKey=requestedChannel.streamKey).first()

    userSID = request.cookies.get('ospSession')

    streamSIDList = r.smembers(channelLoc + '-streamSIDList')
    if streamSIDList is not None:
        r.srem(channelLoc + '-streamSIDList', userSID)

    currentViewers = len(streamSIDList)

    requestedChannel.currentViewers = currentViewers
    if requestedChannel.currentViewers < 0:
        requestedChannel.currentViewers = 0
    db.session.commit()

    if stream is not None:
        stream.currentViewers = currentViewers
        if stream.currentViewers < 0:
            stream.currentViewers = 0
        db.session.commit()
    leave_room(streamData['data'])

    if current_user.is_authenticated:
        streamUserList = r.lrange(channelLoc + '-streamUserList', 0, -1)
        if streamUserList is not None:
            r.lrem(channelLoc + '-streamUserList', 1, current_user.username)

        if requestedChannel.showChatJoinLeaveNotification:
            pictureLocation = current_user.pictureLocation
            if current_user.pictureLocation is None:
                pictureLocation = '/static/img/user2.png'
            else:
                pictureLocation = '/images/' + pictureLocation

            emit('message', {'user':'Server', 'msg': current_user.username + ' has left the room.', 'image': pictureLocation}, room=streamData['data'])
        else:
            if requestedChannel.showChatJoinLeaveNotification:
                emit('message', {'user':'Server', 'msg': 'Guest has left the room.', 'image': '/static/img/user2.png'}, room=streamData['data'])

    handle_viewer_total_request(streamData, room=streamData['data'])

    db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('disconnect')
def disconnect():

    return 'OK'

@socketio.on('closePopup')
def handle_leaving_popup_viewer(streamData):
    leave_room(streamData['data'])
    return 'OK'

@socketio.on('getViewerTotal')
def handle_viewer_total_request(streamData, room=None):
    channelLoc = str(streamData['data'])

    viewers = len(r.smembers(channelLoc + '-streamSIDList'))

    streamUserList = r.lrange(channelLoc + '-streamUserList', 0, -1)
    if streamUserList is None:
        streamUserList = []

    channelQuery = Channel.Channel.query.filter_by(channelLoc=channelLoc).first()
    if channelQuery != None:
        channelQuery.currentViewers = viewers
        for stream in channelQuery.stream:
            stream.currentViewers = viewers
        db.session.commit()



    decodedStreamUserList = []
    for entry in streamUserList:
        user = entry.decode('utf-8')
        # Prevent Duplicate Usernames in Master List, but allow users to have multiple windows open
        if user not in decodedStreamUserList:
            decodedStreamUserList.append(user)

    db.session.commit()
    db.session.close()
    if room is None:
        emit('viewerTotalResponse', {'data': str(viewers), 'userList': decodedStreamUserList})
    else:
        emit('viewerTotalResponse', {'data': str(viewers), 'userList': decodedStreamUserList}, room=room)
    return 'OK'
@socketio.on('getUpvoteTotal')
def handle_upvote_total_request(streamData):
    loc = streamData['loc']
    vidType = str(streamData['vidType'])

    myUpvote = False
    totalUpvotes = 0

    totalQuery = None
    myVoteQuery = None

    if vidType == 'stream':
        loc = str(loc)
        channelQuery = Channel.Channel.query.filter_by(channelLoc=loc).first()
        if channelQuery.stream:
            stream = channelQuery.stream[0]
            totalQuery = upvotes.streamUpvotes.query.filter_by(streamID=stream.id).count()
            try:
                myVoteQuery = upvotes.streamUpvotes.query.filter_by(userID=current_user.id, streamID=stream.id).first()
            except:
                pass

    elif vidType == 'video':
        loc = int(loc)
        totalQuery = upvotes.videoUpvotes.query.filter_by(videoID=loc).count()
        try:
            myVoteQuery = upvotes.videoUpvotes.query.filter_by(userID=current_user.id, videoID=loc).first()
        except:
            pass
    elif vidType == "comment":
        loc = int(loc)
        totalQuery = upvotes.commentUpvotes.query.filter_by(commentID=loc).count()
        try:
            myVoteQuery = upvotes.commentUpvotes.query.filter_by(userID=current_user.id, commentID=loc).first()
        except:
            pass
    elif vidType == "clip":
        loc = int(loc)
        totalQuery = upvotes.clipUpvotes.query.filter_by(clipID=loc).count()
        try:
            myVoteQuery = upvotes.clipUpvotes.query.filter_by(userID=current_user.id, clipID=loc).first()
        except:
            pass

    if totalQuery is not None:
        totalUpvotes = totalQuery
    if myVoteQuery is not None:
        myUpvote = True

    db.session.commit()
    db.session.close()
    emit('upvoteTotalResponse', {'totalUpvotes': str(totalUpvotes), 'myUpvote': str(myUpvote), 'type': vidType, 'loc': loc})
    return 'OK'

@socketio.on('changeUpvote')
@limiter.limit("10/minute")
def handle_upvoteChange(streamData):
    loc = streamData['loc']
    vidType = str(streamData['vidType'])

    if vidType == 'stream':
        loc = str(loc)
        channelQuery = Channel.Channel.query.filter_by(channelLoc=loc).first()
        if channelQuery.stream:
            stream = channelQuery.stream[0]
            myVoteQuery = upvotes.streamUpvotes.query.filter_by(userID=current_user.id, streamID=stream.id).first()

            if myVoteQuery is None:
                newUpvote = upvotes.streamUpvotes(current_user.id, stream.id)
                db.session.add(newUpvote)

                # Create Notification for Channel Owner on New Like
                newNotification = notifications.userNotification(current_user.username + " liked your live stream - " + channelQuery.channelName, "/view/" + str(channelQuery.channelLoc), "/images/" + str(current_user.pictureLocation), channelQuery.owningUser)
                db.session.add(newNotification)

            else:
                db.session.delete(myVoteQuery)
            db.session.commit()

    elif vidType == 'video':
        loc = int(loc)
        videoQuery = RecordedVideo.RecordedVideo.query.filter_by(id=loc).first()
        if videoQuery is not None:
            myVoteQuery = upvotes.videoUpvotes.query.filter_by(userID=current_user.id, videoID=loc).first()

            if myVoteQuery is None:
                newUpvote = upvotes.videoUpvotes(current_user.id, loc)
                db.session.add(newUpvote)

                # Create Notification for Video Owner on New Like
                newNotification = notifications.userNotification(current_user.username + " liked your video - " + videoQuery.channelName, "/play/" + str(videoQuery.id), "/images/" + str(current_user.pictureLocation), videoQuery.owningUser)
                db.session.add(newNotification)

            else:
                db.session.delete(myVoteQuery)
            db.session.commit()
    elif vidType == "comment":
        loc = int(loc)
        videoCommentQuery = comments.videoComments.query.filter_by(id=loc).first()
        if videoCommentQuery is not None:
            myVoteQuery = upvotes.commentUpvotes.query.filter_by(userID=current_user.id, commentID=videoCommentQuery.id).first()
            if myVoteQuery is None:
                newUpvote = upvotes.commentUpvotes(current_user.id, videoCommentQuery.id)
                db.session.add(newUpvote)

                # Create Notification for Video Owner on New Like
                newNotification = notifications.userNotification(current_user.username + " liked your comment on a video", "/play/" + str(videoCommentQuery.videoID), "/images/" + str(current_user.pictureLocation), videoCommentQuery.userID)
                db.session.add(newNotification)

            else:
                db.session.delete(myVoteQuery)
            db.session.commit()
    elif vidType == 'clip':
        loc = int(loc)
        clipQuery = RecordedVideo.Clips.query.filter_by(id=loc).first()
        if clipQuery is not None:
            myVoteQuery = upvotes.clipUpvotes.query.filter_by(userID=current_user.id, clipID=loc).first()

            if myVoteQuery is None:
                newUpvote = upvotes.clipUpvotes(current_user.id, loc)
                db.session.add(newUpvote)

                # Create Notification for Clip Owner on New Like
                newNotification = notifications.userNotification(current_user.username + " liked your clip - " + clipQuery.clipName, "/clip/" + str(clipQuery.id), "/images/" + str(current_user.pictureLocation), clipQuery.recordedVideo.owningUser)
                db.session.add(newNotification)

            else:
                db.session.delete(myVoteQuery)
            db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('newScreenShot')
def newScreenShot(message):
    video = message['loc']
    timeStamp = message['timeStamp']
    videos_root = app.config['WEB_ROOT'] + 'videos/'

    if video is not None:
        videoQuery = RecordedVideo.RecordedVideo.query.filter_by(id=int(video)).first()
        if videoQuery is not None and videoQuery.owningUser == current_user.id:
            videoLocation = videos_root + videoQuery.videoLocation
            thumbnailLocation = videos_root + videoQuery.channel.channelLoc + '/tempThumbnail.png'
            try:
                os.remove(thumbnailLocation)
            except OSError:
                pass
            result = subprocess.call(['ffmpeg', '-ss', str(timeStamp), '-i', videoLocation, '-s', '384x216', '-vframes', '1', thumbnailLocation])
            tempLocation = '/videos/' + videoQuery.channel.channelLoc + '/tempThumbnail.png?dummy=' + str(random.randint(1,50000))
            if 'clip' in message:
                emit('checkClipScreenShot', {'thumbnailLocation': tempLocation, 'timestamp': timeStamp}, broadcast=False)
            else:
                emit('checkScreenShot', {'thumbnailLocation': tempLocation, 'timestamp':timeStamp}, broadcast=False)
            db.session.close()
    return 'OK'

@socketio.on('setScreenShot')
def setScreenShot(message):
    timeStamp = message['timeStamp']
    videos_root = app.config['WEB_ROOT'] + 'videos/'

    if 'loc' in message:
        video = message['loc']
        if video is not None:
            videoQuery = RecordedVideo.RecordedVideo.query.filter_by(id=int(video)).first()
            if videoQuery is not None and videoQuery.owningUser == current_user.id:
                videoLocation = videos_root + videoQuery.videoLocation
                newThumbnailLocation = videoQuery.videoLocation[:-3] + "png"
                newGifThumbnailLocation = videoQuery.videoLocation[:-3] + "gif"
                videoQuery.thumbnailLocation = newThumbnailLocation
                fullthumbnailLocation = videos_root + newThumbnailLocation
                newGifFullThumbnailLocation = videos_root + newGifThumbnailLocation

                videoQuery.thumbnailLocation = newThumbnailLocation
                videoQuery.gifLocation = newGifThumbnailLocation

                db.session.commit()
                db.session.close()
                try:
                    os.remove(fullthumbnailLocation)
                except OSError:
                    pass
                try:
                    os.remove(newGifFullThumbnailLocation)
                except OSError:
                    pass
                result = subprocess.call(['ffmpeg', '-ss', str(timeStamp), '-i', videoLocation, '-s', '384x216', '-vframes', '1', fullthumbnailLocation])
                gifresult = subprocess.call(['ffmpeg', '-ss', str(timeStamp), '-t', '3', '-i', videoLocation, '-filter_complex', '[0:v] fps=30,scale=w=384:h=-1,split [a][b];[a] palettegen=stats_mode=single [p];[b][p] paletteuse=new=1', '-y', newGifFullThumbnailLocation])

    elif 'clipID' in message:
        clipID = message['clipID']
        clipQuery = RecordedVideo.Clips.query.filter_by(id=int(clipID)).first()
        if clipQuery is not None and current_user.id == clipQuery.recordedVideo.owningUser:
            thumbnailLocation = clipQuery.thumbnailLocation
            fullthumbnailLocation = videos_root + thumbnailLocation
            videoLocation = videos_root + clipQuery.recordedVideo.videoLocation
            newClipThumbnail = clipQuery.recordedVideo.channel.channelLoc + '/clips/clip-' + str(clipQuery.id) + '.png'
            fullNewClipThumbnailLocation = videos_root + newClipThumbnail
            clipQuery.thumbnailLocation = newClipThumbnail

            try:
                os.remove(fullthumbnailLocation)
            except OSError:
                pass
            result = subprocess.call(['ffmpeg', '-ss', str(timeStamp), '-i', videoLocation, '-s', '384x216', '-vframes', '1', fullNewClipThumbnailLocation])

            # Generate Gif
            if clipQuery.gifLocation != None:
                gifLocation = clipQuery.gifLocation
                fullthumbnailLocation = videos_root + gifLocation

                try:
                    os.remove(fullthumbnailLocation)
                except OSError:
                    pass

            newClipThumbnail = clipQuery.recordedVideo.channel.channelLoc + '/clips/clip-' + str(clipQuery.id) + '.gif'
            fullNewClipThumbnailLocation = videos_root + newClipThumbnail
            clipQuery.gifLocation = newClipThumbnail

            db.session.commit()
            db.session.close()

            gifresult = subprocess.call(['ffmpeg', '-ss', str(timeStamp), '-t', '3', '-i', videoLocation, '-filter_complex', '[0:v] fps=30,scale=w=384:h=-1,split [a][b];[a] palettegen=stats_mode=single [p];[b][p] paletteuse=new=1', '-y', fullNewClipThumbnailLocation])

    return 'OK'

@socketio.on('updateStreamData')
def updateStreamData(message):
    channelLoc = message['channel']

    sysSettings = settings.settings.query.first()

    channelQuery = Channel.Channel.query.filter_by(channelLoc=channelLoc, owningUser=current_user.id).first()

    if channelQuery is not None:
        stream = channelQuery.stream[0]
        stream.streamName = system.strip_html(message['name'])
        stream.topic = int(message['topic'])
        db.session.commit()

        if channelQuery.imageLocation is None:
            channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
        else:
            channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + channelQuery.imageLocation)

        webhookFunc.runWebhook(channelQuery.id, 4, channelname=channelQuery.channelName,
                   channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(channelQuery.id)),
                   channeltopic=channelQuery.topic,
                   channelimage=channelImage, streamer=templateFilters.get_userName(channelQuery.owningUser),
                   channeldescription=str(channelQuery.description),
                   streamname=stream.streamName,
                   streamurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/view/" + channelQuery.channelLoc),
                   streamtopic=templateFilters.get_topicName(stream.topic),
                   streamimage=(sysSettings.siteProtocol + sysSettings.siteAddress + "/stream-thumb/" + channelQuery.channelLoc + ".png"))
        db.session.commit()
        db.session.close()
    return 'OK'

@socketio.on('text')
@limiter.limit("1/second")
def text(message):
    """Sent by a client when the user entered a new message.
    The message is sent to all people in the room."""
    room = message['room']
    msg = system.strip_html(message['msg'])

    sysSettings = settings.settings.query.first()

    channelQuery = Channel.Channel.query.filter_by(channelLoc=room).first()

    #global streamSIDList

    if channelQuery is not None:

        userSID = request.cookies.get('ospSession')
        if userSID.encode('utf-8') not in r.smembers(channelQuery.channelLoc + '-streamSIDList'):
            r.sadd(channelQuery.channelLoc + '-streamSIDList', userSID)
        if current_user.username.encode('utf-8') not in r.lrange(channelQuery.channelLoc + '-streamUserList', 0, -1):
            r.rpush(channelQuery.channelLoc + '-streamUserList', current_user.username)

        pictureLocation = current_user.pictureLocation
        if current_user.pictureLocation is None:
            pictureLocation = '/static/img/user2.png'
        else:
            pictureLocation = '/images/' + pictureLocation

        if msg.startswith('/'):
            if msg.startswith('/test '):
                commandArray = msg.split(' ',1)
                if len(commandArray) >= 2:
                    command = commandArray[0]
                    target = commandArray[1]
                    msg = 'Test Received - Success: ' + command + ":" + target
            elif msg == ('/sidlist'):
                if current_user.has_role('Admin'):
                    msg = str((r.smembers(channelQuery.channelLoc + '-streamSIDList')))
            elif msg.startswith('/mute'):
                if (current_user.has_role('Admin')) or (current_user.id == channelQuery.owningUser):
                    channelQuery.channelMuted = True
                    db.session.commit()
                    msg = "<b> *** " + current_user.username + " has muted the chat channel ***"
                    emit('message', {'user': current_user.username, 'image': pictureLocation, 'msg': msg}, room=room)
                    return
            elif msg.startswith('/unmute'):
                if (current_user.has_role('Admin')) or (current_user.id == channelQuery.owningUser):
                    channelQuery.channelMuted = False
                    db.session.commit()
                    msg = "<b> *** " + current_user.username + " has unmuted the chat channel ***"
                    emit('message', {'user': current_user.username, 'image': pictureLocation, 'msg': msg}, room=room)
                    return
            elif msg.startswith('/ban '):
                if (current_user.has_role('Admin')) or (current_user.id == channelQuery.owningUser):
                    commandArray = msg.split(' ', 1)
                    if len(commandArray) >= 2:
                        command = commandArray[0]
                        target = commandArray[1]

                        userQuery = Sec.User.query.filter_by(username=target).first()

                        if userQuery is not None:
                            newBan = banList.banList(room, userQuery.id)
                            db.session.add(newBan)
                            db.session.commit()
                            msg = '<b>*** ' + target + ' has been banned ***</b>'
            elif msg.startswith('/unban '):
                if (current_user.has_role('Admin')) or (current_user.id == channelQuery.owningUser):
                    commandArray = msg.split(' ', 1)
                    if len(commandArray) >= 2:
                        command = commandArray[0]
                        target = commandArray[1]

                        userQuery = Sec.User.query.filter_by(username=target).first()

                        if userQuery is not None:
                            banQuery = banList.banList.query.filter_by(userID=userQuery.id, channelLoc=room).first()
                            if banQuery is not None:
                                db.session.delete(banQuery)
                                db.session.commit()

                                msg = '<b>*** ' + target + ' has been unbanned ***</b>'

        banQuery = banList.banList.query.filter_by(userID=current_user.id, channelLoc=room).first()

        if banQuery is None:
            if channelQuery.channelMuted == False or channelQuery.owningUser == current_user.id:
                flags = ""
                if current_user.id == channelQuery.owningUser:
                    flags = "Owner"

                if channelQuery.imageLocation is None:
                    channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
                else:
                    channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + channelQuery.imageLocation)

                streamName = None
                streamTopic = None

                if channelQuery.stream:
                    streamName = channelQuery.stream[0].streamName
                    streamTopic = channelQuery.stream[0].topic
                else:
                    streamName = channelQuery.channelName
                    streamTopic = channelQuery.topic

                webhookFunc.runWebhook(channelQuery.id, 5, channelname=channelQuery.channelName,
                           channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(channelQuery.id)),
                           channeltopic=templateFilters.get_topicName(channelQuery.topic),
                           channelimage=channelImage, streamer=templateFilters.get_userName(channelQuery.owningUser),
                           channeldescription=str(channelQuery.description),
                           streamname=streamName,
                           streamurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/view/" + channelQuery.channelLoc),
                           streamtopic=templateFilters.get_topicName(streamTopic), streamimage=(sysSettings.siteProtocol + sysSettings.siteAddress + "/stream-thumb/" + channelQuery.channelLoc + ".png"),
                           user=current_user.username, userpicture=sysSettings.siteProtocol + sysSettings.siteAddress + pictureLocation, message=msg)
                emit('message', {'user': current_user.username, 'image': pictureLocation, 'msg':msg, 'flags':flags}, room=room)
                db.session.commit()
                db.session.close()

            else:
                msg = '<b>*** Chat Channel has been muted and you can not send messages ***</b>'
                emit('message', {'user': current_user.username, 'image': pictureLocation, 'msg': msg}, broadcast=False)
                db.session.commit()
                db.session.close()

        elif banQuery:
            msg = '<b>*** You have been banned and can not send messages ***</b>'
            emit('message', {'user': current_user.username, 'image': pictureLocation, 'msg': msg}, broadcast=False)
            db.session.commit()
            db.session.close()
    return 'OK'

@socketio.on('getServerResources')
def get_resource_usage(message):
    cpuUsage = psutil.cpu_percent(interval=1)
    cpuLoad = psutil.getloadavg()
    cpuLoad = str(cpuLoad[0]) + ", " + str(cpuLoad[1]) + ", " + str(cpuLoad[2])
    memoryUsage = psutil.virtual_memory()[2]
    memoryUsageTotal = round(float(psutil.virtual_memory()[0])/1000000,2)
    memoryUsageAvailable = round(float(psutil.virtual_memory()[1])/1000000,2)
    diskUsage = psutil.disk_usage('/')[3]
    diskTotal = round(float(psutil.disk_usage('/')[0])/1000000,2)
    diskFree = round(float(psutil.disk_usage('/')[2]) / 1000000, 2)

    emit('serverResources', {'cpuUsage':str(cpuUsage), 'cpuLoad': cpuLoad, 'memoryUsage': memoryUsage, 'memoryUsageTotal': str(memoryUsageTotal), 'memoryUsageAvailable': str(memoryUsageAvailable), 'diskUsage': diskUsage, 'diskTotal': str(diskTotal), 'diskFree': str(diskFree)})
    return 'OK'

@socketio.on('generateInviteCode')
def generateInviteCode(message):
    selectedInviteCode = str(message['inviteCode'])
    daysToExpire = int(message['daysToExpiration'])
    channelID = int(message['chanID'])

    channelQuery = Channel.Channel.query.filter_by(id=channelID, owningUser=current_user.id).first()

    if channelQuery is not None:
        newInviteCode = invites.inviteCode(daysToExpire, channelID)
        if selectedInviteCode != "":
            inviteCodeQuery = invites.inviteCode.query.filter_by(code=selectedInviteCode).first()
            if inviteCodeQuery is None:
                newInviteCode.code = selectedInviteCode
            else:
                db.session.close()
                return False

        db.session.add(newInviteCode)
        db.session.commit()

        emit('newInviteCode', {'code': str(newInviteCode.code), 'expiration': str(newInviteCode.expiration), 'channelID':str(newInviteCode.channelID)}, broadcast=False)

    else:
        pass
    db.session.close()
    return 'OK'

@socketio.on('deleteInviteCode')
def deleteInviteCode(message):
    code = message['code']
    codeQuery = invites.inviteCode.query.filter_by(code=code).first()
    channelQuery = Channel.Channel.query.filter_by(id=codeQuery.channelID).first()
    if codeQuery is not None:
        if (channelQuery.owningUser is current_user.id) or (current_user.has_role('Admin')):
            channelID = channelQuery.id
            db.session.delete(codeQuery)
            db.session.commit()
            emit('inviteCodeDeleteAck', {'code': str(code), 'channelID': str(channelID)}, broadcast=False)
        else:
            emit('inviteCodeDeleteFail', {'code': 'fail', 'channelID': 'fail'}, broadcast=False)
    else:
        emit('inviteCodeDeleteFail', {'code': 'fail', 'channelID': 'fail'}, broadcast=False)

    db.session.close()
    return 'OK'

@socketio.on('addUserChannelInvite')
def addUserChannelInvite(message):
    channelID = int(message['chanID'])
    username = message['username']
    daysToExpire = message['daysToExpiration']

    channelQuery = Channel.Channel.query.filter_by(id=channelID, owningUser=current_user.id).first()

    if channelQuery is not None:
        invitedUserQuery = Sec.User.query.filter(func.lower(Sec.User.username) == func.lower(username)).first()
        if invitedUserQuery is not None:
            previouslyInvited = False
            for invite in invitedUserQuery.invites:
                if invite.channelID is channelID:
                    previouslyInvited = True

            if not previouslyInvited:
                newUserInvite = invites.invitedViewer(invitedUserQuery.id, channelID, daysToExpire)
                db.session.add(newUserInvite)
                db.session.commit()

                emit('invitedUserAck', {'username': username, 'added': str(newUserInvite.addedDate), 'expiration': str(newUserInvite.expiration), 'channelID': str(channelID), 'id': str(newUserInvite.id)}, broadcast=False)
                db.session.commit()
                db.session.close()
    db.session.close()
    return 'OK'

@socketio.on('deleteInvitedUser')
def deleteInvitedUser(message):
    inviteID = int(message['inviteID'])
    inviteIDQuery = invites.invitedViewer.query.filter_by(id=inviteID).first()
    channelQuery = Channel.Channel.query.filter_by(id=inviteIDQuery.channelID).first()
    if inviteIDQuery is not None:
        if (channelQuery.owningUser is current_user.id) or (current_user.has_role('Admin')):
            db.session.delete(inviteIDQuery)
            db.session.commit()
            emit('invitedUserDeleteAck', {'inviteID': str(inviteID)}, broadcast=False)
    db.session.close()
    return 'OK'

@socketio.on('deleteVideo')
def deleteVideoSocketIO(message):
    if current_user.is_authenticated:
        videoID = int(message['videoID'])
        result = videoFunc.deleteVideo(videoID)
        if result is True:
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('editVideo')
def editVideoSocketIO(message):
    if current_user.is_authenticated:
        videoID = int(message['videoID'])
        videoName = system.strip_html(message['videoName'])
        videoTopic = int(message['videoTopic'])
        videoDescription = message['videoDescription']
        videoAllowComments = False
        if message['videoAllowComments'] == "True" or message['videoAllowComments'] == True:
            videoAllowComments = True

        result = videoFunc.changeVideoMetadata(videoID, videoName, videoTopic, videoDescription, videoAllowComments)
        if result is True:
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('createClip')
def createclipSocketIO(message):
    if current_user.is_authenticated:
        videoID = int(message['videoID'])
        clipName = system.strip_html(message['clipName'])
        clipDescription = message['clipDescription']
        startTime = float(message['clipStart'])
        stopTime = float(message['clipStop'])
        result = videoFunc.createClip(videoID, startTime, stopTime, clipName, clipDescription)
        if result[0] is True:
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('moveVideo')
def moveVideoSocketIO(message):
    if current_user.is_authenticated:
        videoID = int(message['videoID'])
        newChannel = int(message['destinationChannel'])

        result = videoFunc.moveVideo(videoID, newChannel)
        if result is True:
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('togglePublished')
def togglePublishedSocketIO(message):
    sysSettings = settings.settings.query.first()
    if current_user.is_authenticated:
        videoID = int(message['videoID'])
        videoQuery = RecordedVideo.RecordedVideo.query.filter_by(owningUser=current_user.id, id=videoID).first()
        if videoQuery is not None:
            newState = not videoQuery.published
            videoQuery.published = newState

            if videoQuery.channel.imageLocation is None:
                channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/static/img/video-placeholder.jpg")
            else:
                channelImage = (sysSettings.siteProtocol + sysSettings.siteAddress + "/images/" + videoQuery.channel.imageLocation)

            if newState is True:

                webhookFunc.runWebhook(videoQuery.channel.id, 6, channelname=videoQuery.channel.channelName,
                           channelurl=(sysSettings.siteProtocol + sysSettings.siteAddress + "/channel/" + str(videoQuery.channel.id)),
                           channeltopic=templateFilters.get_topicName(videoQuery.channel.topic),
                           channelimage=channelImage, streamer=templateFilters.get_userName(videoQuery.channel.owningUser),
                           channeldescription=str(videoQuery.channel.description), videoname=videoQuery.channelName,
                           videodate=videoQuery.videoDate, videodescription=str(videoQuery.description),
                           videotopic=templateFilters.get_topicName(videoQuery.topic),
                           videourl=(sysSettings.siteProtocol + sysSettings.siteAddress + '/play/' + str(videoQuery.id)),
                           videothumbnail=(sysSettings.siteProtocol + sysSettings.siteAddress + '/videos/' + str(videoQuery.thumbnailLocation)))

                subscriptionQuery = subscriptions.channelSubs.query.filter_by(channelID=videoQuery.channel.id).all()
                for sub in subscriptionQuery:
                    # Create Notification for Channel Subs
                    newNotification = notifications.userNotification(templateFilters.get_userName(videoQuery.channel.owningUser) + " has posted a new video to " + videoQuery.channel.channelName + " titled " + videoQuery.channelName, '/play/' + str(videoQuery.id), "/images/" + str(videoQuery.channel.owner.pictureLocation), sub.userID)
                    db.session.add(newNotification)
                db.session.commit()

                subsFunc.processSubscriptions(videoQuery.channel.id, sysSettings.siteName + " - " + videoQuery.channel.channelName + " has posted a new video", "<html><body><img src='" +
                                     sysSettings.siteProtocol + sysSettings.siteAddress + sysSettings.systemLogo + "'><p>Channel " + videoQuery.channel.channelName + " has posted a new video titled <u>" +
                                     videoQuery.channelName + "</u> to the channel.</p><p>Click this link to watch<br><a href='" + sysSettings.siteProtocol + sysSettings.siteAddress + "/play/" +
                                     str(videoQuery.id) + "'>" + videoQuery.channelName + "</a></p>")

            db.session.commit()
            db.session.close()
            return 'OK'
        else:
            db.session.commit()
            db.session.close()
            return abort(500)
    else:
        db.session.commit()
        db.session.close()
        return abort(401)

@socketio.on('togglePublishedClip')
def togglePublishedClipSocketIO(message):
    if current_user.is_authenticated:
        clipID = int(message['clipID'])
        clipQuery = RecordedVideo.Clips.query.filter_by(id=clipID).first()

        if clipQuery is not None and current_user.id == clipQuery.recordedVideo.owningUser:
            newState = not clipQuery.published
            clipQuery.published = newState

            if newState is True:

                subscriptionQuery = subscriptions.channelSubs.query.filter_by(channelID=clipQuery.recordedVideo.channel.id).all()
                for sub in subscriptionQuery:
                    # Create Notification for Channel Subs
                    newNotification = notifications.userNotification(templateFilters.get_userName(clipQuery.recordedVideo.owningUser) + " has posted a new clip to " +
                                                                     clipQuery.recordedVideo.channel.channelName + " titled " + clipQuery.clipName,'/clip/' +
                                                                     str(clipQuery.id),"/images/" + str(clipQuery.recordedVideo.channel.owner.pictureLocation), sub.userID)
                    db.session.add(newNotification)
            db.session.commit()
            db.session.close()
            return 'OK'
        else:
            db.session.commit()
            db.session.close()
            return abort(500)
    else:
        db.session.commit()
        db.session.close()
        return abort(401)


@socketio.on('saveUploadedThumbnail')
def saveUploadedThumbnailSocketIO(message):
    if current_user.is_authenticated:
        videoID = int(message['videoID'])
        videoQuery = RecordedVideo.RecordedVideo.query.filter_by(id=videoID, owningUser=current_user.id).first()
        if videoQuery is not None:
            thumbnailFilename = message['thumbnailFilename']
            if thumbnailFilename != "" or thumbnailFilename is not None:
                videos_root = app.config['WEB_ROOT'] + 'videos/'

                thumbnailPath = videos_root + videoQuery.thumbnailLocation
                shutil.move(app.config['VIDEO_UPLOAD_TEMPFOLDER'] + '/' + thumbnailFilename, thumbnailPath)
                db.session.commit()
                db.session.close()
                return 'OK'
            else:
                db.session.commit()
                db.session.close()
                return abort(500)
        else:
            db.session.commit()
            db.session.close()
            return abort(401)
    return abort(401)

@socketio.on('editClip')
def changeClipMetadataSocketIO(message):
    if current_user.is_authenticated:
        clipID = int(message['clipID'])
        clipName = message['clipName']
        clipDescription = message['clipDescription']

        result = videoFunc.changeClipMetadata(clipID, clipName, clipDescription)

        if result is True:
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('deleteClip')
def deleteClipSocketIO(message):
    if current_user.is_authenticated:
        clipID = int(message['clipID'])

        result = videoFunc.deleteClip(clipID)

        if result is True:
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('checkUniqueUsername')
def deleteInvitedUser(message):
    newUsername = message['username']
    userQuery = Sec.User.query.filter(func.lower(Sec.User.username) == func.lower(newUsername)).first()
    if userQuery is None:
        emit('checkUniqueUsernameAck', {'results': str(1)}, broadcast=False)
    else:
        emit('checkUniqueUsernameAck', {'results': str(0)}, broadcast=False)
    db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('checkEdge')
def checkEdgeNode(message):
    if current_user.has_role('Admin'):
        edgeID = int(message['edgeID'])
        edgeNodeQuery = settings.edgeStreamer.query.filter_by(id=edgeID).first()
        if edgeNodeQuery is not None:
            try:
                edgeXML = requests.get("http://" + edgeNodeQuery.address + ":9000/stat").text
                edgeDict = xmltodict.parse(edgeXML)
                if "nginx_rtmp_version" in edgeDict['rtmp']:
                    edgeNodeQuery.status = 1
                    emit('edgeNodeCheckResults', {'edgeID': str(edgeNodeQuery.id), 'status': str(1)}, broadcast=False)
                    db.session.commit()
                    return 'OK'
            except:
                edgeNodeQuery.status = 0
                emit('edgeNodeCheckResults', {'edgeID': str(edgeNodeQuery.id), 'status': str(0)}, broadcast=False)
                db.session.commit()
                return 'OK'
        return abort(500)
    return abort(401)

@socketio.on('toggleOSPEdge')
def toggleEdgeNode(message):
    if current_user.has_role('Admin'):
        edgeID = int(message['edgeID'])
        edgeNodeQuery = settings.edgeStreamer.query.filter_by(id=edgeID).first()
        if edgeNodeQuery is not None:
            edgeNodeQuery.active = not edgeNodeQuery.active
            db.session.commit()
            system.rebuildOSPEdgeConf()
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('deleteOSPEdge')
def deleteEdgeNode(message):
    if current_user.has_role('Admin'):
        edgeID = int(message['edgeID'])
        edgeNodeQuery = settings.edgeStreamer.query.filter_by(id=edgeID).first()
        if edgeNodeQuery is not None:
            db.session.delete(edgeNodeQuery)
            db.session.commit()
            system.rebuildOSPEdgeConf()
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('deleteStream')
def deleteActiveStream(message):
    if current_user.has_role('Admin'):
        streamID = int(message['streamID'])
        streamQuery = Stream.Stream.query.filter_by(id=streamID).first()
        if streamQuery is not None:
            pendingVideo = RecordedVideo.RecordedVideo.query.filter_by(pending=True, channelID=streamQuery.linkedChannel).all()
            for pending in pendingVideo:
                db.session.delete(pending)
            db.session.delete(streamQuery)
            db.session.commit()
            return 'OK'
        else:
            return abort(500)
    else:
        return abort(401)

@socketio.on('submitWebhook')
def addChangeWebhook(message):

    invalidTriggers = [20]

    channelID = int(message['webhookChannelID'])

    channelQuery = Channel.Channel.query.filter_by(id=channelID, owningUser=current_user.id).first()
    if channelQuery is not None:
        webhookName = message['webhookName']
        webhookEndpoint = message['webhookEndpoint']
        webhookTrigger = int(message['webhookTrigger'])
        webhookHeader = message['webhookHeader']
        webhookPayload = message['webhookPayload']
        webhookReqType = int(message['webhookReqType'])
        webhookInputAction = message['inputAction']
        webhookInputID = message['webhookInputID']

        if webhookInputAction == 'new' and webhookTrigger not in invalidTriggers:
            newWebHook = webhook.webhook(webhookName, channelID, webhookEndpoint, webhookHeader, webhookPayload, webhookReqType, webhookTrigger)
            db.session.add(newWebHook)
            db.session.commit()
            emit('newWebhookAck', {'webhookName': webhookName, 'requestURL':webhookEndpoint, 'requestHeader':webhookHeader, 'requestPayload':webhookPayload, 'requestType':webhookReqType, 'requestTrigger':webhookTrigger, 'requestID':newWebHook.id, 'channelID':channelID}, broadcast=False)
        elif webhookInputAction == 'edit' and webhookTrigger not in invalidTriggers:
            existingWebhookQuery = webhook.webhook.query.filter_by(channelID=channelID, id=int(webhookInputID)).first()
            if existingWebhookQuery is not None:
                existingWebhookQuery.name = webhookName
                existingWebhookQuery.endpointURL = webhookEndpoint
                existingWebhookQuery.requestHeader = webhookHeader
                existingWebhookQuery.requestPayload = webhookPayload
                existingWebhookQuery.requestType = webhookReqType
                existingWebhookQuery.requestTrigger = webhookTrigger


                emit('changeWebhookAck', {'webhookName': webhookName, 'requestURL': webhookEndpoint, 'requestHeader': webhookHeader, 'requestPayload': webhookPayload, 'requestType': webhookReqType, 'requestTrigger': webhookTrigger, 'requestID': existingWebhookQuery.id, 'channelID': channelID}, broadcast=False)
    db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('deleteWebhook')
def deleteWebhook(message):
    webhookID = int(message['webhookID'])
    webhookQuery = webhook.webhook.query.filter_by(id=webhookID).first()

    if webhookQuery is not None:
        channelQuery = webhookQuery.channel
        if channelQuery is not None:
            if channelQuery.owningUser is current_user.id:
                db.session.delete(webhookQuery)
                db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('submitGlobalWebhook')
def addChangeGlobalWebhook(message):

    if current_user.has_role('Admin'):
        webhookName = message['webhookName']
        webhookEndpoint = message['webhookEndpoint']
        webhookTrigger = int(message['webhookTrigger'])
        webhookHeader = message['webhookHeader']
        webhookPayload = message['webhookPayload']
        webhookReqType = int(message['webhookReqType'])
        webhookInputAction = message['inputAction']
        webhookInputID = message['webhookInputID']

        if webhookInputAction == 'new':
            newWebHook = webhook.globalWebhook(webhookName, webhookEndpoint, webhookHeader, webhookPayload, webhookReqType, webhookTrigger)
            db.session.add(newWebHook)
            db.session.commit()
            emit('newGlobalWebhookAck', {'webhookName': webhookName, 'requestURL':webhookEndpoint, 'requestHeader':webhookHeader, 'requestPayload':webhookPayload, 'requestType':webhookReqType, 'requestTrigger':webhookTrigger, 'requestID':newWebHook.id}, broadcast=False)
        elif webhookInputAction == 'edit':
            existingWebhookQuery = webhook.globalWebhook.query.filter_by(id=int(webhookInputID)).first()
            if existingWebhookQuery is not None:
                existingWebhookQuery.name = webhookName
                existingWebhookQuery.endpointURL = webhookEndpoint
                existingWebhookQuery.requestHeader = webhookHeader
                existingWebhookQuery.requestPayload = webhookPayload
                existingWebhookQuery.requestType = webhookReqType
                existingWebhookQuery.requestTrigger = webhookTrigger

                emit('changeGlobalWebhookAck', {'webhookName': webhookName, 'requestURL': webhookEndpoint, 'requestHeader': webhookHeader, 'requestPayload': webhookPayload, 'requestType': webhookReqType, 'requestTrigger': webhookTrigger, 'requestID': existingWebhookQuery.id}, broadcast=False)
    db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('deleteGlobalWebhook')
def deleteGlobalWebhook(message):
    webhookID = int(message['webhookID'])
    webhookQuery = webhook.globalWebhook.query.filter_by(id=webhookID).first()

    if webhookQuery is not None:
        if current_user.has_role('Admin'):
            db.session.delete(webhookQuery)
            db.session.commit()
    db.session.close()
    return 'OK'

@socketio.on('markNotificationAsRead')
def markUserNotificationRead(message):
    notificationID = message['data']
    notificationQuery = notifications.userNotification.query.filter_by(notificationID=notificationID, userID=current_user.id).first()
    if notificationQuery is not None:
        notificationQuery.read = True
    db.session.commit()
    db.session.close()
    return 'OK'

if __name__ == '__main__':
    app.jinja_env.auto_reload = False
    app.config['TEMPLATES_AUTO_RELOAD'] = False
    socketio.run(app, Debug=config.debugMode)
