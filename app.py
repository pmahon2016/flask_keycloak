import oidc as oidc
from flask import Flask, render_template, abort, request, redirect, url_for, g
import hashlib
import os
from wtforms import SubmitField
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from werkzeug.utils import secure_filename
from flask_oidc import OpenIDConnect

import json




app = Flask(__name__)
app.config.update({
    'SECRET_KEY': 'SomethingNotEntirelySecret',
    'TESTING': True,
    'DEBUG': True,
    'OIDC_CLIENT_SECRETS': 'client_secrets.json',
    'OIDC_ID_TOKEN_COOKIE_SECURE': False,
    'OIDC_REQUIRE_VERIFIED_EMAIL': False,
    'OIDC_USER_INFO_ENABLED': True,
    'OIDC_OPENID_REALM': 'myrealm',
    'OIDC_SCOPES': ['openid', 'email', 'profile'],
    'OIDC_INTROSPECTION_AUTH_METHOD': 'client_secret_post'
})

oidc = OpenIDConnect(app)
hashes = {}


@app.before_request
def before_request():
    if oidc.user_loggedin:
        g.user = oidc.user_getfield('preferred_username')
        g.email = oidc.user_getfield('email')
        g.name = oidc.user_getfield('name')
    else:
        g.user = None


class FileUpload(FlaskForm):
    file = FileField(validators=[FileRequired()])
    submit = SubmitField('Get Hash')


@app.route("/", methods=['GET', 'POST'])
def upload():
    form = FileUpload()
    userdb = {}
    if form.validate_on_submit():
        filename = secure_filename(form.file.data.filename)
        form.file.data.save('uploads/' + filename)

        with open('uploads/' + filename, 'rb') as f:
            fileread = f.read()
            option = request.form['exampleRadios']
            if option == 'SHA-256':
                hash_value = hashlib.sha256(fileread).hexdigest()
            elif option == 'SHA-384':
                hash_value = hashlib.sha384(fileread).hexdigest()
            elif option == 'SHA-512':
                hash_value = hashlib.sha512(fileread).hexdigest()
            elif option == 'MD5':
                hash_value = hashlib.md5(fileread).hexdigest()
            else:
                print("No Algo Provided")

            if g.user:
                if os.path.isfile('hashes.json'):
                    with open('hashes.json', 'r') as jf:
                        userdb = json.load(jf)

                if g.user in userdb.keys():
                    userdb[g.user].append({filename: hash_value})
                else:
                    userdb[g.user] = [{filename: hash_value}]

                with open('hashes.json', 'w') as fp:
                    json.dump(userdb, fp, indent=4)

            os.remove('uploads/' + filename)
            return render_template('output.html', plaintext=filename,
                                   hstring=hash_value, algo=option, p_requests=userdb)

    return render_template('hash.html', form=form)


@app.route("/userprofile")
@oidc.require_login
def userprofile():
    return render_template("userprofile.html")


@app.route("/login")
@oidc.require_login
def login():
    return redirect(url_for("upload"))


@app.route("/logout")
def logout():
    oidc.logout()
    return redirect(url_for("upload"))


if __name__ == '__main__':
    app.run()
