from flask import Flask, render_template, url_for, flash, redirect, request, session, abort
from flask.json import jsonify
import requests
from forms import RegisterationForm, LoginForm
from user.models import User
from functools import wraps
import jwt
import datetime
import os
from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google_auth_oauthlib.flow import Flow
from google.oauth2 import id_token
from pip._vendor import cachecontrol
import google.auth.transport.requests
import pathlib

app = Flask(__name__)
limiter = Limiter(app, key_func=get_remote_address)

UPLOAD_FOLDER = ''
ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}


app.config['SECRET_KEY'] = '6e00bb81eb20ca764a4415432109c235'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

GOOGLE_CLENT_ID = ""
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

flow = Flow.from_client_secrets_file( 

    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'google_id' in session:
            return f(*args, **kwargs)

        if 'token' in session:
            token = session['token']
        else:
            token = None
            
        if not token:
            return jsonify({'message': 'Invalid request /missing token'}), 403
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            return jsonify({'message': 'invalid request/invalid token'}), 403
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/', methods=['GET', "POST"])
def register():
    form = RegisterationForm()
    if form.validate_on_submit():
        flash(f'Account created for {form.name.data}', 'success')
        User().signup()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/login/', methods=['GET', "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        token = jwt.encode({'_id': User().get_id(), 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'])
        session['token'] = token       
        return redirect(url_for('image_load'))
    return render_template('login.html', form=form)


@app.route('/glogin')
def glogin():
    authorization_url, state= flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)


@app.route('/image_load', methods=['GET', "POST"])
@token_required
@limiter.limit('5/minute')
def image_load():
    
    if request.method == 'POST':

        if 'myImage' not in request.files:
            return render_template('image_load.html', msg = 'no file part')

        file = request.files['myImage']
        
        if file.filename == '':
            return render_template('image_load.html', msg = 'no file uploaded')

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return render_template('image.html', filename=filename)
        return render_template('image_load.html', msg = 'wrong file extension')

    return render_template('image_load.html')



@app.route('/logout')
@token_required
def logout():
    print(session)
    if 'google_id' in session:
        del session['google_id']
        return redirect(url_for('login'))

    del session['token']
    return redirect(url_for('login'))


@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response = request.url)

    if not session['state'] == request.args['state']:
        abort(500)
    
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session = cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token = credentials._id_token,
        request = token_request,
        audience = GOOGLE_CLENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    return redirect(url_for("image_load"))