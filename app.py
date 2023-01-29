from flask import Flask, redirect, url_for, request, abort, jsonify, render_template, send_from_directory, logging, session, g, flash
import flask, logging, functools, sqlite3
from flask_limiter import Limiter
from datetime import timedelta
from flask_login import LoginManager, current_user, login_user, login_required, UserMixin, logout_user, AnonymousUserMixin
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.recaptcha import RecaptchaField
from itsdangerous import URLSafeTimedSerializer
from flask_mail import Message, Mail
import threading
from datetime import datetime, timedelta
from authlib.integrations.flask_client import OAuth
import os, json, requests
import hashlib
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import StringField, SubmitField, SelectField
from  sqlalchemy.ext.mutable import MutableList

#blueprints
from blueprints.index import route as ir


with open("auth/keys.json", "r") as fd:
    insecure_data = json.load(fd)
app = Flask(__name__, static_folder="static")
app.register_blueprint(ir)

#basic settings
app.testing = True
app.debug=True
superuser = ['']


# define login constants
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "0"  
GOOGLE_CLIENT_ID = insecure_data["web"]["client_id"]
client_secrets_file = "./auth/keys.json" #set the path to where the .json file you got Google console is
flow = Flow.from_client_secrets_file(  #Flow is OAuth 2.0 a class that stores all the information on how we want to authorize our users
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
    redirect_uri="http://localhost:5000/auth/google/callback"  #and the redirect URI is the point where the user will end up after the authorization
)
app.secret_key = insecure_data["app_key"]


# define csrf protection
WTF_CSRF_ENABLED = True
WTF_CSRF_SECRET_KEY = insecure_data["csrf"]
app.config['RECAPTCHA_PUBLIC_KEY'] = ""
app.config['RECAPTCHA_PRIVATE_KEY'] = ""
app.config['RECAPTCHA_DATA_ATTRS'] = {'theme': 'light'}


#define forms
class SearchCommunityForm(FlaskForm):
    city_name = StringField()
    submit = SubmitField()

class ApplyCommunityForm(FlaskForm):
    city_name = StringField()
    submit = SubmitField()

class CreatePetitionForm(FlaskForm):
    city_name = SelectField()
    petition_name = StringField()
    petition_description = StringField()
    submit = SubmitField()


#Define database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy()
db.init_app(app)

@app.before_first_request
def create_table():
    db.create_all()
    if not LiveCities.query.filter_by(city_name="Minneapolis").first():
        db.session.add(LiveCities("Minneapolis", True))
    db.session.commit()

class LiveCities(db.Model):
    __tablename__ = 'livecities'
    city_name = db.Column(db.String(30), primary_key=True, unique=True)
    live = db.Column(db.Boolean(), default=False, nullable=False)

    def __init__(self, city_name, live=True):
        self.city_name = city_name
        self.live = live
    
    def push_live(self):
        self.live = True

    def get_live(self):
        return self.live

class Petition(db.Model):
    __tablename__ = 'petition'
    id = db.Column(db.Integer(), primary_key=True, unique=True)
    poster_id = db.Column(db.String(30), unique=True)
    city_name = db.Column(db.String(30))
    name = db.Column(db.String(150))
    description = db.Column(db.Text())
    signatures = db.Column(db.Integer())
    signers = db.Column(MutableList.as_mutable(db.PickleType))

    def __init__(self, id, poster_id, city_name, name, desciption):
        self.id = id 
        self.poster_id = poster_id
        self.city_name = city_name
        self.name = name
        self.description = desciption
        self.signatures = 0
        self.signers = []
    
    def modify_description(self, newdescription):
        self.description = newdescription
    
    def sign(self, signer):
        print(self.signers)
        if signer in self.signers:
            return False
        else:
            self.signatures += 1
            self.signers.append(signer)
            return True




# routes

@app.route('/', methods=['GET'])
def index(): 
    return redirect(url_for("home"))

@app.route('/home', methods=['GET'])
def home(): 
    return redirect(url_for("login"))

def check_oauth(function):  #a function to check if the user is authorized or not
    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        if not session.get("google_id"):
            if request.method == "POST":
                return {"Error":"Unuathenticated"}, 403
            else:
                return redirect(url_for("login")), 302
        else:
            return function()
    return wrapper


@app.route('/login', methods=['GET'])
def login(): 
    return render_template("login.html")

@app.route("/logout")
@check_oauth
def logout():
    session.clear() #wipe server side session data
    return redirect(url_for("index"))

@app.route('/auth/google')
def auth_googles():
    authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
    session["state"] = state
    return redirect(authorization_url)

@app.route('/auth/google/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    print(id_info)
    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    session["profile_pic"] = id_info.get("picture")
    session["authenticated"] = True
    return redirect("/home")

def create_id():
    if len(db.session.query(Petition).all()) != 0:
        return db.session.query(Petition).all()[-1].id+1
    else:
        return 0

@app.route('/dashboard', methods=["GET","POST"])
@check_oauth
def dashboard():
    form = CreatePetitionForm()
    form.city_name.choices = [(q.city_name, q.city_name) for q in LiveCities.query.order_by('city_name')]
    if request.method == "GET":
        return render_template("dashboard.html", form=form, message="", petition=Petition)
    poster_id = session['google_id']
    city_name = request.form['city_name']
    petition_name = request.form["petition_name"]
    petition_description = request.form["petition_description"]
    if Petition.query.filter_by(poster_id=poster_id).first():
        return render_template("dashboard.html", form=form, message="You already have a petition active.", petition=Petition)
    record = Petition(create_id(), poster_id, city_name, petition_name, petition_description)
    db.session.add(record)
    db.session.commit()
    return render_template("dashboard.html", form=form, message="Your petition is live! View it on the "+city_name+" page!", petition=Petition)

@app.route('/communities/')
def communities():
    return redirect(url_for("communities_search"))

@app.route('/communities/search', methods=["GET","POST"])
def communities_search():
    form = SearchCommunityForm()
    if request.method == "GET":
        return render_template("search.html", form=form, message="")
    name = request.form["city_name"]
    searched_city = LiveCities.query.filter_by(city_name=name).first()
    if not searched_city:
        return render_template("search.html", form=form, message="City not found. Please make sure the name is correct. Otherwise <a href=\"/communities/apply\">Apply for a city to be added</a>")
    if not searched_city.get_live():
        return render_template("application.html", form=form, message="This city has been suggested and is being reviewed, hang tight!")
    return redirect(url_for("communities_view", name=name))

@app.route('/communities/apply',methods=["GET","POST"])
def communities_apply():
    form = ApplyCommunityForm()
    if request.method == "GET":
        return render_template("application.html", form=form)
    name = request.form["city_name"]
    city = LiveCities.query.filter_by(city_name=name).first()
    if city: #exists
        if city.get_live():
            return redirect(url_for("communities_view", name=name))
        else:
            return render_template("application.html", form=form, message="This city has already been suggested! Hang tight!")
    record = LiveCities(city_name=name)
    db.session.add(record)
    db.session.commit()
    return render_template("application.html", form=form, message="Your application has b een submitted to a site moderator and will be reviewed within the next 24h, hang tight while we create your community page!")

@app.route('/communities/<name>',methods=["GET","POST"])
def communities_view(name):
    city = LiveCities.query.filter_by(city_name=name).first() #exists
    if not city:
        return redirect(url_for("communities_search"))
    if not city.get_live():
        return redirect(url_for("communities_search"))
    return render_template("communities.html", community=city, petition=Petition)

@app.route('/petitions/<id>',methods=["GET","POST"])
def petitions(id):
    petition = Petition.query.filter_by(id=id).first() #exists
    if not petition:
        return "<html>No pet found</html>"
    return render_template("petition.html", petition=petition)


@check_oauth
@app.route('/petitions/<id>/sign',methods=["POST"])
def sign(id):
    petition = Petition.query.filter_by(id=id).first() #exists
    if not petition:
        return {"success":"false","message":"Petition id not found"}, 400
    if petition.sign(session['google_id']):
        db.session.commit()
        return {"success":"true","message":"Petition signed!"}, 200
    else:
        return {"success":"false","message":"Petition already signed."}, 400
        


@app.errorhandler(429)
def rate_limit(e):
    return "<html>\n<h1>You are accessing the resource too fast</h1>\n</html>", 429

@app.errorhandler(405)
def method_not_allowed(e):
    return {"status":"fail","errors":["invalid request method"]}, 405


@app.errorhandler(404)
def page_not_found(e):
    if request.method == 'POST':
        return {"status":"fail","errors":["the requeted resource wasn\'t found"]}, 403
    else:
        return ""

@app.errorhandler(403)
def page_not_found(e):
    if request.method == 'POST':
        return {"status":"fail","errors":["Forbidden"]}, 403
    else:
        return '<html>\n<h1>403 Forbidden</h1>\n<br>\n<br>\n<p>You have been denied from viewing the resource</html>'





if __name__ == '__main__':
    #from waitress import serve
    #serve(app, host=hst, port=prt, url_scheme='https')
    app.run(host="localhost", port="5000")
