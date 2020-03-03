# Date: 02/08/2019
# Author: Mohamed
# Description: A secure notebook

import os
import sys
from time import time
from flask_wtf import CSRFProtect
from datetime import timedelta, datetime
from lib.cipher import get_random_bytes, CryptoAES
from lib.database.database import Account, Profile
from lib.const import SessionConst, CredentialConst, ProfileConst, PermissionConst
from flask import Flask, flash, render_template, request, session, jsonify, redirect, url_for, escape

# app
if getattr(sys, 'frozen', False):
    path = os.path.abspath('.')

    if not os.path.exists('database'):
        os.mkdir(os.path.join(path, 'database'))

    static_folder = os.path.join(path, 'static')
    template_folder = os.path.join(path, 'templates')

    app = Flask(__name__, template_folder=template_folder,
                static_folder=static_folder)
else:
    app = Flask(__name__)

app.config['SECRET_KEY'] = get_random_bytes(0x20)
app.permanent_session_lifetime = timedelta(
    minutes=SessionConst.SESSION_TTL.value)

# Protection against CSRF attack
CSRFProtect(app)

# databases
account_db = Account()
profile_db = Profile()

# core functions


def login_required(func):
    def wrapper(*args, **kwargs):
        if not 'logged_in' in session:
            return redirect(url_for('index'))
        elif not session['logged_in']:
            return redirect(url_for('index'))
        else:
            return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


def permission_required(func):
    def wrapper(*args, **kwargs):
        if session['access_level'] == PermissionConst.NONE.value:
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


def admin_required(func):
    def wrapper(*args, **kwargs):
        if session['access_level'] != PermissionConst.ROOT.value:
            return redirect(url_for('admin'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper


def invalid_username(username):
    if len(username) < CredentialConst.MIN_USERNAME_LENGTH.value:
        return 'Username must be at least {} characters long'.format(
            CredentialConst.MIN_USERNAME_LENGTH.value
        )

    if len(username) > CredentialConst.MAX_USERNAME_LENGTH.value:
        return 'Username must not be longer than {} characters'.format(
            CredentialConst.MAX_USERNAME_LENGTH.value
        )

    if username.isdigit():
        return 'Username must contain a letter'

    if not username[0].isalpha():
        return 'Username must start with a letter'

    if [_ for _ in username if not _.isdigit() and not _.isalpha()]:
        return 'Username must not contain special characters'


def invalid_password(username, password, confirm):
    if password != confirm:
        return 'Passwords do not match'

    if len(password) < CredentialConst.MIN_PASSWORD_LENGTH.value:
        return 'Password must be at least {} characters long'.format(
            CredentialConst.MIN_PASSWORD_LENGTH.value
        )

    if len(password) > CredentialConst.MAX_PASSWORD_LENGTH.value:
        return 'Password must not be longer than {} characters'.format(
            CredentialConst.MAX_PASSWORD_LENGTH.value
        )

    if not ' ' in password:
        return 'Password must contain at least 1 space character'

    if password[0] == ' ' or password[-1] == ' ':
        return 'Password must not start or end with a space character'

    if password[-1].isdigit():
        return 'Password must not end with a number'

    if not [_ for _ in password if _.isalpha() if _ == _.upper()]:
        return 'Password must contain at least 1 capital letter'

    if ''.join([_ for _ in username if _.isalpha()]).lower() in password.lower():
        return 'Password must not contain your username'


def get_user_key():
    user_id = session['user_id']
    master_key = session['master_key']

    encrypted_user_key = account_db.get_encrypted_user_key(user_id)
    decrypted_user_key = CryptoAES.decrypt(encrypted_user_key, master_key)

    return decrypted_user_key


def create_topic(topic_name, time_stamp):
    user_key = get_user_key()
    user_id = session['user_id']
    topic_name = topic_name.strip()

    return profile_db.add_topic(user_id, user_key, topic_name, time_stamp)


def get_topics():
    user_key = get_user_key()
    user_id = session['user_id']

    return profile_db.decrypt_topics(user_id, user_key)


def create_note(topic_id, note_title, time_stamp):
    user_key = get_user_key()
    note_title = note_title.strip()

    return profile_db.add_note(topic_id, user_key, note_title, '', time_stamp)


def get_notes(topic_id):
    user_key = get_user_key()
    return profile_db.decrypt_notes(topic_id, user_key)


def delete_usr(user_id):
    if user_id == session['user_id'] and session['access_level'] == PermissionConst.ROOT.value:
        if account_db.get_admin() == 1:

            # sorry, I can't allow you to do that
            return False

    account_db.delete_account(user_id)
    profile_db.delete_account(user_id)
    return True

# endpoints
@app.before_request
def single_browser():
    if not 'logged_in' in session:
        return

    if not session['logged_in']:
        return

    if (time() - session['last_checked']) < 1.5:
        return

    user_id = session['user_id']
    session_token = session['token']
    session['last_checked'] = time()

    if not account_db.is_logged_in(user_id, session_token):
        logout()


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html', PermissionConst=PermissionConst)


@app.route('/updateusername', methods=['POST'])
@login_required
def update_username():
    resp = {'msg': 'Username Changed Successfully', 'resp_code': -1}

    if not 'username' in request.form:
        resp['msg'] = 'Incomplete form'
        return jsonify(resp)

    username = escape(request.form['username'].strip().lower())
    username_error = invalid_username(username)

    if username_error:
        resp['msg'] = username_error
        return jsonify(resp)

    if account_db.account_exists(username):
        resp['msg'] = 'Username already exists'
        return jsonify(resp)

    user_id = session['user_id']
    account_db.update_username(user_id, username)

    resp['resp_code'] = 0
    return jsonify(resp)


@app.route('/updatepassword', methods=['POST'])
@login_required
def update_password():
    resp = {'msg': 'Password Changed Successfully', 'resp_code': -1}

    if not ('old' in request.form and 'new' in request.form and 'conf' in request.form):
        resp['resp'] = 'Incomplete form'
        return jsonify(resp)

    old_password = escape(request.form['old'].strip())
    new_password = escape(request.form['new'].strip())
    confirm_password = escape(request.form['conf'].strip())

    if (
        (len(old_password) > CredentialConst.MAX_PASSWORD_LENGTH.value) or
        (len(new_password) > CredentialConst.MAX_PASSWORD_LENGTH.value) or
        (new_password != confirm_password)
    ):

        resp['msg'] = 'Password must not be longer than {} characters'.format(
            CredentialConst.MAX_PASSWORD_LENGTH.value
        )

        return jsonify(resp)

    user_id = session['user_id']

    if not account_db.compare_passwords(user_id, old_password):
        resp['msg'] = 'Check your current password field'
        return jsonify(resp)

    username = account_db.get_user_name(user_id)
    password_error = invalid_password(username, new_password, confirm_password)

    if password_error:
        resp['msg'] = password_error
        return jsonify(resp)

    if account_db.compare_passwords(user_id, new_password):
        resp['msg'] = 'You are already using that password'
        return jsonify(resp)

    new_master_key = account_db.update_password(
        user_id, old_password, new_password)
    session['master_key'] = new_master_key

    resp['resp_code'] = 0
    return jsonify(resp)

# topic
@app.route('/createtopic', methods=['POST'])
@login_required
def createtopic():
    resp = {'topic_id': '', 'date_created': '', 'resp': 'error-msg'}

    if not ('topic_name' in request.form and 'time_stamp' in request.form):
        return jsonify(resp)

    timestamp = request.form['time_stamp']

    if not timestamp.isdigit():
        return jsonify(resp)

    current_time = int(timestamp)/1000

    try:
        datetime.fromtimestamp(current_time)
    except:
        return jsonify(resp)

    topic_name = escape(request.form['topic_name'].strip())
    topic_len = len(topic_name)

    if (
        (topic_len < ProfileConst.MIN_TOPIC_LENGTH.value) or
        (topic_len > ProfileConst.MAX_TOPIC_LENGTH.value)
    ):
        return jsonify(resp)

    if profile_db.get_total_topics(session['user_id']) >= ProfileConst.MAX_TOPICS.value:
        return jsonify(resp)

    resp['resp'] = 'success-msg'
    resp['topic_id'], resp['date_created'] = create_topic(
        topic_name, current_time)

    return jsonify(resp)


@app.route('/gettopics', methods=['POST'])
@login_required
def gettopics():
    resp = {'topics': []}
    resp['topics'] = get_topics()

    return jsonify(resp)


@app.route('/topic')
@login_required
def gettopic():
    if not 'id' in request.args:
        return render_template('topic.html', PermissionConst=PermissionConst)

    user_id = session['user_id']
    user_key = get_user_key()
    topic_id = escape(request.args.get('id'))

    if not profile_db.topic_exists(user_id, topic_id):
        return render_template('topic.html', PermissionConst=PermissionConst)

    topic = profile_db.decrypt_topic(topic_id, user_key)
    return render_template('topic.html', topic=topic, PermissionConst=PermissionConst)


@app.route('/settings/topic')
@login_required
def settings_topic():
    if not 'topic_id' in request.args:
        return redirect(url_for('index'))

    user_id = session['user_id']
    user_key = get_user_key()
    topic_id = escape(request.args.get('topic_id'))

    if not profile_db.topic_exists(user_id, topic_id):
        return redirect(url_for('index'))

    topic = profile_db.decrypt_topic(topic_id, user_key, get_notes=False)

    return render_template('settingstopic.html', topic=topic, PermissionConst=PermissionConst)


@app.route('/settings/topic/update', methods=['POST'])
@login_required
def update_topic():
    resp = {'resp': 'error-msg'}

    if not ('topic_id' in request.form and 'modified_name' in request.form):
        return jsonify(resp)

    modified_name = escape(request.form['modified_name'].strip())
    topic_id = escape(request.form['topic_id'].strip())
    modified_name_len = len(modified_name)
    user_id = session['user_id']
    user_key = get_user_key()

    if (
        (modified_name_len < ProfileConst.MIN_TOPIC_LENGTH.value) or
        (modified_name_len > ProfileConst.MAX_TOPIC_LENGTH.value) or
        not (profile_db.topic_exists(user_id, topic_id))
    ):
        return jsonify(resp)

    profile_db.modify_topic(topic_id, user_key, modified_name)

    resp['resp'] = 'success-msg'
    return jsonify(resp)


@app.route('/settings/topic/delete', methods=['POST'])
@login_required
def delete_topic():
    resp = {'resp': 'error-msg'}

    if not 'topic_id' in request.form:
        return jsonify(resp)

    user_id = session['user_id']
    topic_id = escape(request.form['topic_id'].strip())

    if not profile_db.topic_exists(user_id, topic_id):
        return jsonify(resp)

    profile_db.delete_topic(topic_id)

    resp['resp'] = 'success-msg'
    return jsonify(resp)

# note
@app.route('/createnote', methods=['POST'])
@login_required
def createnote():
    resp = {'note_id': '', 'date_created': '', 'resp': 'error-msg'}

    if not ('topic_id' in request.form and 'note_title' in request.form and 'time_stamp' in request.form):
        return jsonify(resp)

    if profile_db.get_total_notes(session['user_id']) >= ProfileConst.MAX_NOTES.value:
        return jsonify(resp)

    note_title = escape(request.form['note_title'].strip())
    topic_id = escape(request.form['topic_id'].strip())
    timestamp = escape(request.form['time_stamp'])
    note_len = len(note_title)

    if (
        (note_len < ProfileConst.MIN_NOTE_LENGTH.value) or
        (note_len > ProfileConst.MAX_NOTE_LENGTH.value)
    ):
        return jsonify(resp)

    if not timestamp.isdigit():
        return jsonify(resp)

    current_time = int(timestamp)/1000

    try:
        datetime.fromtimestamp(current_time)
    except:
        return jsonify(resp)

    resp['resp'] = 'success-msg'
    resp['note_id'], resp['date_created'] = create_note(
        topic_id, note_title, current_time)

    return jsonify(resp)


@app.route('/getnotes', methods=['POST'])
@login_required
def getnotes():
    resp = {'notes': []}

    if not 'topic_id' in request.form:
        return jsonify(resp)

    topic_id = escape(request.form['topic_id'].strip())

    if not len(topic_id):
        return jsonify(resp)

    resp['notes'] = get_notes(topic_id)
    return jsonify(resp)


@app.route('/note', methods=['GET'])
@login_required
def get_note():
    if not ('topic_id' in request.args and 'note_id' in request.args):
        return redirect(url_for('index'))

    user_id = session['user_id']
    topic_id = escape(request.args.get('topic_id'))
    note_id = escape(request.args.get('note_id'))

    if not (profile_db.topic_exists(user_id, topic_id) and profile_db.note_exists(topic_id, note_id)):
        return redirect(url_for('index'))

    user_key = get_user_key()
    topic = profile_db.decrypt_topic(topic_id, user_key, False)
    topic_info = {'topic_id': topic_id, 'topic_name':  topic['topic_name']}

    note = dict(topic_info, **profile_db.decrypt_note(note_id, user_key))

    return render_template('note.html', note=note, PermissionConst=PermissionConst)


@app.route('/save', methods=['POST'])
@login_required
def save_note():
    resp = {'resp': 'success-msg'}

    if not ('topic_id' in request.form and 'note_id' in request.form and 'content' in request.form):
        return jsonify(resp)

    user_id = session['user_id']
    user_key = get_user_key()
    note_id = escape(request.form['note_id'].strip())
    topic_id = escape(request.form['topic_id'].strip())
    note_content = escape(request.form['content'].strip())

    if not (profile_db.topic_exists(user_id, topic_id) and profile_db.note_exists(topic_id, note_id)):
        return jsonify(resp)

    profile_db.modify_note_content(topic_id, note_id, note_content, user_key)
    return jsonify(resp)


@app.route('/modify', methods=['POST'])
@login_required
def modify_note():
    resp = {'resp': 'error-msg'}

    if not ('topic_id' in request.form and 'note_id' in request.form and 'modified_title' in request.form):
        return jsonify(resp)

    note_title = escape(request.form['modified_title'])
    modified_title_len = len(note_title)
    topic_id = escape(request.form['topic_id'])
    note_id = escape(request.form['note_id'])
    user_id = session['user_id']
    user_key = get_user_key()

    if (
        (modified_title_len < ProfileConst.MIN_NOTE_LENGTH.value) or
        (modified_title_len > ProfileConst.MAX_NOTE_LENGTH.value) or
        not profile_db.topic_exists(user_id, topic_id) or
        not profile_db.note_exists(topic_id, note_id)
    ):
        return jsonify(resp)

    profile_db.modify_note_title(topic_id, note_id, note_title, user_key)
    resp['resp'] = 'success-msg'

    return jsonify(resp)


@app.route('/delete', methods=['POST'])
@login_required
def delete_note():
    resp = {'resp': 'error-msg'}

    if not ('topic_id' in request.form and 'note_id' in request.form):
        return jsonify(resp)

    user_id = session['user_id']
    note_id = escape(request.form['note_id'])
    topic_id = escape(request.form['topic_id'])

    if not (profile_db.topic_exists(user_id, topic_id) and profile_db.note_exists(topic_id, note_id)):
        return jsonify(resp)

    profile_db.delete_note(topic_id, note_id)

    resp['resp'] = 'success-msg'
    return jsonify(resp)


@app.route('/session_check', methods=['POST'])
@login_required
def session_check():
    return jsonify({'resp': 0})

# admin
@app.route('/admin')
@login_required
@permission_required
def admin():

    users = []
    stats = {'total_users': 0, 'total_topics': 0, 'total_notes': 0}

    for row in account_db.get_users():
        user_id = row[0]
        ip_address = account_db.get_ip_address(user_id)
        permission = account_db.get_access_level(user_id)
        last_online = account_db.get_last_online(user_id)
        date_created = account_db.get_date_created(user_id)
        username = account_db.get_user_name(user_id).title()
        permission = ('Admin' if permission == PermissionConst.ROOT.value
                      else 'View Only' if permission == PermissionConst.VIEW.value else 'User')

        total_notes = profile_db.get_total_notes(user_id)
        total_topics = profile_db.get_total_topics(user_id)

        stats['total_users'] += 1
        stats['total_notes'] += total_notes
        stats['total_topics'] += total_topics

        users.append({
            'user_id': user_id,
            'username': username,
            'ip_address': ip_address,
            'access_level': permission,
            'last_online': last_online,
            'total_notes': total_notes,
            'date_created': date_created,
            'total_topics': total_topics,
        })

    stats['total_users'] = '{:02,}'.format(stats['total_users'])
    stats['total_notes'] = '{:02,}'.format(stats['total_notes'])
    stats['total_topics'] = '{:02,}'.format(stats['total_topics'])

    return render_template('admin.html', users=users, stats=stats)


@app.route('/edit_user')
@login_required
@admin_required
def edit_user():
    if not 'id' in request.args:
        return redirect(url_for('admin'))

    user_id = escape(request.args.get('id'))

    if not account_db.user_id_exists(user_id):
        return redirect(url_for('admin'))

    user = {}

    user['user_id'] = user_id
    permission = account_db.get_access_level(user_id)
    user['ip_address'] = account_db.get_ip_address(user_id)
    user['last_online'] = account_db.get_last_online(user_id)
    user['date_created'] = account_db.get_date_created(user_id)
    user['username'] = account_db.get_user_name(user_id).title()
    user['total_notes'] = '{:02,}'.format(profile_db.get_total_notes(user_id))
    user['total_topics'] = '{:02,}'.format(
        profile_db.get_total_topics(user_id))
    user['access_level'] = ('Admin' if permission == PermissionConst.ROOT.value
                            else 'View Only' if permission == PermissionConst.VIEW.value else 'User')

    return render_template('adminedit.html', user=user, PermissionConst=PermissionConst)


@app.route('/update_access', methods=['POST'])
@login_required
@admin_required
def update_access():
    resp = {'resp': 'error-msg'}

    if not ('user_id' in request.form and 'access_id' in request.form):
        return jsonify(resp)

    user_id = escape(request.form['user_id'])
    access_id = escape(request.form['access_id'])

    if not account_db.user_id_exists(user_id):
        return jsonify(resp)

    if not access_id.isdigit():
        return jsonify(resp)

    access_id = int(access_id)

    if (access_id != PermissionConst.ROOT.value and
        access_id != PermissionConst.VIEW.value and
            access_id != PermissionConst.NONE.value):
        return jsonify(resp)

    if access_id == account_db.get_access_level(user_id):
        return jsonify(resp)

    if user_id == session['user_id']:
        if account_db.get_admin() == 1:
            # sorry, I can't allow you to do that
            return jsonify(resp)

    resp['resp'] = 'success-msg'
    account_db.update_permission(user_id, access_id)

    account_db.logout(user_id)
    return jsonify(resp)


@app.route('/logout_user', methods=['POST'])
@login_required
@admin_required
def logout_user():
    resp = {'resp': 'error'}

    if not 'user_id' in request.form:
        return jsonify(resp)

    user_id = escape(request.form['user_id'])

    if not account_db.user_id_exists(user_id):
        return jsonify(resp)

    resp['resp'] = 'success'
    account_db.logout(user_id)
    return jsonify(resp)


@app.route('/delete_user', methods=['POST'])
@login_required
@admin_required
def delete_user():
    resp = {'resp': 'error'}

    if not 'user_id' in request.form:
        return jsonify(resp)

    user_id = escape(request.form['user_id'])

    if not account_db.user_id_exists(user_id):
        return jsonify(resp)

    if delete_usr(user_id):
        resp['resp'] = 'success'

    return jsonify(resp)


@app.route('/')
def index():
    if not 'logged_in' in session:
        session['logged_in'] = False
        return render_template('index.html')

    if not session['logged_in']:
        username = session.get('username')
        username = username if username else ''

        if username:
            session.pop('username')

        return render_template('index.html', username=username)

    last_active_timestamp = session['last_active']
    return render_template('home.html', PermissionConst=PermissionConst, lastActiveTimestamp=last_active_timestamp)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'logged_in' in session:
        if session['logged_in']:
            return redirect(url_for('index'))

    if request.method == 'GET':
        return render_template('register.html', min_password_length=CredentialConst.MIN_PASSWORD_LENGTH.value,
                               max_password_length=CredentialConst.MAX_PASSWORD_LENGTH.value)

    form = request.form

    if not ('username' in form and 'password' in form and 'confirm' in form):
        flash('Incomplete form', 'error')
        return render_template('register.html', min_password_length=CredentialConst.MIN_PASSWORD_LENGTH.value,
                               max_password_length=CredentialConst.MAX_USERNAME_LENGTH.value)

    username, password, confirm = escape(form['username'].strip()), escape(
        form['password']), escape(form['confirm'])
    creds = {'username': username, 'password': password,
             'confirm': confirm if confirm == password else '', 'success': 0}

    if not (username and password and confirm):
        flash('Incomplete form', category='error')
        return render_template('register.html', data=creds, min_password_length=CredentialConst.MIN_PASSWORD_LENGTH.value,
                               max_password_length=CredentialConst.MAX_USERNAME_LENGTH.value)

    username_error = invalid_username(username)

    if username_error:
        flash(username_error, 'error')
        return render_template('register.html', data=creds,
                               min_password_length=CredentialConst.MIN_PASSWORD_LENGTH.value,
                               max_password_length=CredentialConst.MAX_USERNAME_LENGTH.value)

    if account_db.account_exists(username.lower()):
        flash('{} already exists'.format(username).format(username), 'error')
        return render_template('register.html', data=creds, min_password_length=CredentialConst.MIN_PASSWORD_LENGTH.value,
                               max_password_length=CredentialConst.MAX_USERNAME_LENGTH.value)

    password_error = invalid_password(username, password, confirm)

    if password_error:
        flash(password_error, 'error')
        return render_template('register.html', data=creds, min_password_length=CredentialConst.MIN_PASSWORD_LENGTH.value,
                               max_password_length=CredentialConst.MAX_USERNAME_LENGTH.value)

    creds['success'] = 1
    session['logged_in'] = False
    account_db.register(username, password.strip())

    return render_template('register.html', data=creds, min_password_length=CredentialConst.MIN_PASSWORD_LENGTH.value,
                           max_password_length=CredentialConst.MAX_USERNAME_LENGTH.value)


@app.route('/login', methods=['GET', 'POST'])
def login():

    if not 'logged_in' in session:
        return redirect(url_for('index'))

    if session['logged_in']:
        return redirect(url_for('index'))

    if not ('username' in request.form and 'password' in request.form and 'timestamp' in request.form):
        return jsonify({'is_authenticated': False, 'msg': 'Provide all requirements'})

    username = escape(request.form['username'].strip())
    password = escape(request.form['password'])
    timestamp = escape(request.form['timestamp'])

    if not timestamp.isdigit():
        return jsonify({'is_authenticated': False, 'msg': 'Invalid timestamp'})

    current_time = int(timestamp)/1000

    try:
        datetime.fromtimestamp(current_time)
    except:
        return jsonify({'is_authenticated': False, 'msg': 'Invalid timestamp'})

    if ((len(password) > CredentialConst.MAX_PASSWORD_LENGTH.value) or
        (len(username) > CredentialConst.MAX_USERNAME_LENGTH.value) or
                (len(username) < CredentialConst.MIN_USERNAME_LENGTH.value)
        ):
        return jsonify({'is_authenticated': False, 'msg': 'Account does not exist'})

    session['username'] = username
    ip_addr = request.headers.get('X-Forwarded-For')
    account_data, err_msg = account_db.authenticate(
        username, password, ip_addr, current_time)

    if not account_data:
        return jsonify({'is_authenticated': False, 'msg': err_msg})

    user_id, master_key, token, last_active, access_level = account_data

    session['token'] = token
    session.permanent = True
    session['logged_in'] = True
    session['user_id'] = user_id
    session['last_checked'] = time()
    session['master_key'] = master_key
    session['last_active'] = last_active
    session['username'] = username.title()
    session['access_level'] = access_level

    return jsonify({'is_authenticated': True, 'msg': ''})


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user_id = session['user_id']

    if not delete_usr(user_id):
        return jsonify({'resp': ''})

    session.clear()
    return jsonify({'resp': ''})


@app.route('/logout')
@login_required
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
