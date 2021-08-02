import logging
from os import environ
from flask import Flask
from flask import request, session, render_template, redirect
from flask_session import Session
from datetime import timedelta
from aldap.logs import Logs
from aldap.bruteforce import BruteForce
from aldap.parameters import Parameters
from aldap.aldap import Aldap

# --- Parameters --------------------------------------------------------------
param = Parameters()

# --- Brute Force -------------------------------------------------------------
bruteForce = BruteForce()

# --- Logging -----------------------------------------------------------------
logs = Logs('main')
logging.getLogger('werkzeug').setLevel(logging.ERROR) # Flask log level to ERROR
environ['WERKZEUG_RUN_MAIN'] = 'true'

# --- Flask -------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=param.get('FLASK_SECRET_KEY', 'Change me from env variables!')
)

# Flask-Session module
SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = '/tmp/'
SESSION_USE_SIGNER = True
SESSION_COOKIE_NAME = 'another-ldap'
SESSION_COOKIE_DOMAIN = param.get('COOKIE_DOMAIN', None)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = param.get('ENABLE_HTTPS', False, bool)
PERMANENT_SESSION_LIFETIME = timedelta(days=7)
app.config.from_object(__name__)
Session(app)

# --- Routes ------------------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    layout = {
        'callback': '',
        'alert': '',
        'metadata': {
            'title': 'PMI - Data Ocean',
            'description': '',
            'footer': 'PSE DevOps Engineers'}
    }

    if bruteForce.isIpBlocked():
        layout['alert'] = 'Blocked by Brute Force.'
        return render_template('login.html', layout=layout)

    # Get return page to redirect the user after successful login
    layout['callback'] = request.args.get('callback', default='/', type=str)

    if request.method == 'POST':
        logs.debug({'message':'Form requested.'})
        username = request.form.get('username', default=None, type=str)
        password = request.form.get('password', default=None, type=str)
        if (username is None) or (password is None):
            layout['alert'] = 'Username or password incorrect.'
            return render_template('login.html', layout=layout)

        aldap = Aldap()
        if aldap.authentication(username, password):
            logs.info({'message':'Form: Authentication successful, creating Session.'})
            session['username'] = username
            session['groups'] = aldap.getUserGroups(username)
            return redirect(layout['callback'])

        logs.warning({'message': 'Form: Authentication failed, deleting Session.'})
        layout['alert'] = 'Username or password incorrect.'
        try:
            del(session['username'])
            del(session['groups'])
        except KeyError:
            pass

    return render_template('login.html', layout=layout)

@app.route('/', defaults={'path': ''}, methods=['GET'])
@app.route('/<path:path>', methods=['GET'])
def catch_all(path):
    if bruteForce.isIpBlocked():
        return 'Unauthorized', 401

    # Basic Auth request
    if request.authorization:
        logs.debug({'message':'Basic-Auth requested.'})
        username = request.authorization.username
        password = request.authorization.password
        if not username or not password:
            return 'Unauthorized', 401

        aldap = Aldap()
        if aldap.authentication(username, password):
            logs.info({'message':'Basic-Auth: Authentication successful.'})
            groups = aldap.getUserGroups(username)
            authorization, matchedGroups = aldap.authorization(username, groups)
            if authorization:
                logs.info({'message':'Basic-Auth: Authorization successful.'})
                return 'Authorized', 200, [('x-username', username),('x-groups', ",".join(matchedGroups))]
            else:
                logs.warning({'message': 'Basic-Auth: Authorization failed.'})
                return 'Unauthorized', 401

        logs.warning({'message': 'Basic-Auth: Authentication failed.'})
        return 'Unauthorized', 401

    # Session auth request
    logs.debug({'message':'Session requested.'})
    if ('username' in session) and ('groups' in session):
        logs.info({'message':'Session: Authentication successful.'})
        aldap = Aldap()
        authorization, matchedGroups = aldap.authorization(session['username'], session['groups'])
        if authorization:
            logs.info({'message':'Session: Authorization successful.'})
            return 'Authorized', 200, [('x-username', session['username']),('x-groups', ",".join(matchedGroups))]
        else:
            logs.warning({'message': 'Session: Authorization failed.'})
            return 'Unauthorized', 401

    logs.warning({'message': 'Session: Authentication failed.'})
    return 'Unauthorized', 401

@app.after_request
def remove_header(response):
    response.headers['Server'] = ''
    return response

if __name__ == '__main__':
    if param.get('ENABLE_HTTPS', False, bool):
        app.run(host='0.0.0.0', port=9000, debug=False, ssl_context='adhoc')
    else:
        app.run(host='0.0.0.0', port=9000, debug=False)