from flask import Flask
from flask import request, session, render_template, redirect, url_for
from flask_session import Session
from werkzeug.exceptions import HTTPException
from datetime import timedelta
from tempfile import gettempdir
from aldap.logs import Logs
from aldap.bruteforce import BruteForce
from aldap.parameters import Parameters
from aldap.aldap import Aldap
from aldap.prometheus import Prometheus

# --- Parameters --------------------------------------------------------------
param = Parameters()

# --- Brute Force -------------------------------------------------------------
bruteForce = BruteForce()

# --- Logging -----------------------------------------------------------------
logs = Logs('main')

# --- Flask -------------------------------------------------------------------
app = Flask(__name__)
app.config.update(
    SECRET_KEY=param.get('FLASK_SECRET_KEY', 'Change me from env variables!')
)

# Flask-Session module
SESSION_TYPE = 'filesystem'
SESSION_FILE_DIR = gettempdir()
SESSION_USE_SIGNER = True
SESSION_COOKIE_NAME = 'another-ldap'
SESSION_COOKIE_DOMAIN = param.get('COOKIE_DOMAIN', None)
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SECURE = True
PERMANENT_SESSION_LIFETIME = timedelta(days=param.get('PERMANENT_SESSION_LIFETIME', 7, int))
SESSION_COOKIE_SAMESITE = 'Lax'
app.config.from_object(__name__)
Session(app)


# --- Routes ------------------------------------------------------------------
@app.route('/login', methods=['POST'])
def login():
    logs.debug({'message':'/login requested.'})

    # Get return page to redirect the user after successful login
    protocol = request.args.get('protocol', default='', type=str)
    callback = request.args.get('callback', default='', type=str)

    # Get inputs from the form
    username = request.form.get('username', default=None, type=str)
    password = request.form.get('password', default=None, type=str)
    if (username is None) or (password is None):
        bruteForce.addFailure()
        return redirect(url_for('index', protocol=protocol, callback=callback, alert=True))

    # Authenticate user
    aldap = Aldap()
    if aldap.authentication(username, password):
        logs.info({'message':'Login: Authentication successful, adding user and groups to the Session.'})
        prometheus = Prometheus()
        prometheus.addLastConnection(username)
        session['username'] = username
        session['groups'] = aldap.getUserGroups(username)
        if (protocol in ['http', 'https']) and callback:
            return redirect(protocol+'://'+callback)
        return redirect(url_for('index'))

    # Authentication failed
    logs.warning({'message': 'Login: Authentication failed, invalid credentials.'})
    bruteForce.addFailure()
    return redirect(url_for('index', protocol=protocol, callback=callback, alert=True))


@app.route('/auth', methods=['GET'])
def auth():
    logs.debug({'message':'/auth requested.'})

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
                prometheus = Prometheus()
                prometheus.addLastConnection(username)
                return 'Authorized', 200, [('x-username', username),('x-groups', ",".join(matchedGroups))]

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
            prometheus = Prometheus()
            prometheus.addLastConnection(session['username'])
            return 'Authorized', 200, [('x-username', session['username']),('x-groups', ",".join(matchedGroups))]

        logs.warning({'message': 'Session: Authorization failed.'})
        return 'Unauthorized', 401

    logs.warning({'message': 'Session: Authentication failed.'})
    return 'Unauthorized', 401


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logs.debug({'message':'/logout requested.'})
    try:
        session.clear()
    except KeyError:
        pass
    return redirect(url_for('index'))


@app.route('/', methods=['GET'])
def index():
    logs.debug({'message':'/ requested.'})
    layout = {
        'metadata': {
            'title': param.get('METADATA_TITLE', 'Another LDAP', str),
            'description': param.get('METADATA_DESCRIPTION', '', str),
            'footer': param.get('METADATA_FOOTER', 'Powered by Another LDAP', str)
        },
        'authenticated': False,
        'username': '',
        'protocol': '',
        'callback': '',
        'alert': ''
    }

    if ('username' in session) and ('groups' in session):
        layout['authenticated'] = True
        layout['username'] = session['username']

    # Get return page to redirect the user after successful login
    layout['protocol'] = request.args.get('protocol', default='', type=str)
    layout['callback'] = request.args.get('callback', default='', type=str)

    # Alerts for the user UI
    if 'alert' in request.args:
        layout['alert'] = 'Authentication failed, invalid username or password.'
    if layout['authenticated'] and layout['protocol'] and layout['callback']:
        layout['alert'] = 'Authorization failed, invalid LDAP groups.'

    return render_template('login.html', layout=layout)


@app.before_request
def beforeAll():
    logs.debug({'message':'Before-all.'})
    if bruteForce.isIpBlocked():
        return 'Unauthorized', 401


@app.after_request
def afterAll(response):
    logs.debug({'message':'After-all.'})
    if response.status_code == 401:
        bruteForce.addFailure() # Increase Brute force failures
    if 'username' not in session:
        session.clear() # Remove Session file and cookie
    response.headers['Server'] = '' # Remove Server header
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.errorhandler(HTTPException)
def handle_exception(e):
    logs.error({'message': 'Exception.', 'code': e.code, 'name': e.name, 'description': e.description})
    return 'Not Found', 404


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9000, ssl_context='adhoc', debug=False, use_reloader=False)