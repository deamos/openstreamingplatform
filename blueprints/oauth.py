import datetime
import requests

from flask import redirect, url_for, Blueprint, flash, abort
from flask_security.utils import login_user
from classes import settings
from classes import Sec
from classes.shared import oauth, db

import json

from app import user_datastore
from functions.oauth import fetch_token, discord_processLogin
from functions.system import newLog
from functions.webhookFunc import runWebhook

oauth_bp = Blueprint('oauth', __name__, url_prefix='/oauth')

@oauth_bp.route('/login/<provider>')
def oAuthLogin(provider):
    sysSettings = settings.settings.query.first()
    if sysSettings is not None:

        oAuthClient = oauth.create_client(provider)
        redirect_url = sysSettings.siteProtocol + sysSettings.siteAddress + '/oauth/authorize/' + provider
        return oAuthClient.authorize_redirect(redirect_url)
    else:
        redirect(url_for('root.main_page'))

@oauth_bp.route('/authorize/<provider>')
def oAuthAuthorize(provider):
    oAuthClient = oauth.create_client(provider)
    oAuthProviderQuery = settings.oAuthProvider.query.filter_by(name=provider).first()
    if oAuthProviderQuery is not None:
        token = oAuthClient.authorize_access_token()

        userData = oAuthClient.get(oAuthProviderQuery.profile_endpoint)
        userDataDict = userData.json()

        userQuery = Sec.User.query.filter_by(oAuthID=userDataDict['id'], oAuthProvider=provider, authType=1).first()

        # If oAuth ID, Provider, and Auth Type Match - Initiate Login
        if userQuery != None:
            existingTokenQuery = Sec.OAuth2Token.query.filter_by(user=userQuery.id).all()
            for existingToken in existingTokenQuery:
                db.session.delete(existingToken)
            db.session.commit()
            newToken = Sec.OAuth2Token(provider, token['token_type'], token['access_token'], token['refresh_token'], token['expires_at'], userQuery.id)
            db.session.add(newToken)
            db.session.commit()

            if userQuery.active is False:
                flash("User has been Disabled.  Please contact your administrator","error")
                return(redirect('/login'))
            else:
                login_user(userQuery)

                if oAuthProviderQuery.preset_auth_type == "Discord":
                    discord_processLogin(userDataDict, userQuery)

                return(redirect(url_for('root.main_page')))

        # If No Match, Determine if a User Needs to be created
        else:
            existingUsernameQuery = Sec.User.query.filter_by(username=userDataDict[oAuthProviderQuery.username_value]).first()

            # No Username Match - Create New User
            if existingUsernameQuery is None:
                user_datastore.create_user(email=userDataDict[oAuthProviderQuery.email_value], username=userDataDict[oAuthProviderQuery.username_value], active=True, confirmed_at=datetime.datetime.now(), authType=1, oAuthID=userDataDict['id'], oAuthProvider=provider)
                db.session.commit()
                user = Sec.User.query.filter_by(username=userDataDict[oAuthProviderQuery.username_value]).first()
                user_datastore.add_role_to_user(user, 'User')

                if oAuthProviderQuery.preset_auth_type == "Discord":
                    discord_processLogin(userDataDict, user)

                newToken = Sec.OAuth2Token(provider, token['token_type'], token['access_token'], token['refresh_token'], token['expires_at'], user.id)
                db.session.add(newToken)
                db.session.commit()
                login_user(user)

                runWebhook("ZZZ", 20, user=user.username)
                newLog(1, "A New User has Registered - Username:" + str(user.username))

                return(redirect(url_for('root.main_page')))
            else:
                flash("A username already exists with that name and is not configured for the oAuth provider or oAuth login","error")
                return(redirect('/login'))
