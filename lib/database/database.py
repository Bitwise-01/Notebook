# Date: 02/08/2019
# Author: Mohamed
# Description: DBMS

import bcrypt
import sqlite3
from time import time
from os import urandom
from hashlib import sha256
from datetime import datetime
from lib.cipher import CryptoAES
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from lib.const import DatabaseConst, PermissionConst


class DatabaseWrapper:

    def __init__(self, db_path):
        self.db_path = db_path

    def db_query(self, cmd, args, fetchone=True):
        database = sqlite3.connect(self.db_path)
        sql = database.cursor().execute(cmd, args)
        data = sql.fetchone()[0] if fetchone else sql.fetchall()
        database.close()
        return data

    def db_update(self, cmd, args):
        database = sqlite3.connect(self.db_path)
        database.cursor().execute(cmd, args)
        database.commit()
        database.close()

    def db_create(self, cmd):
        database = sqlite3.connect(self.db_path)
        database.cursor().execute(cmd)
        database.commit()
        database.close()


class Account(DatabaseWrapper):

    def __init__(self):
        super().__init__(DatabaseConst.ACCOUNT_DB.value)
        self.create_tables()

    def create_tables(self):
        self.db_create('''
            CREATE TABLE IF NOT EXISTS
            Account(
                user_id TEXT,
                username TEXT,
                password TEXT,
                encrypted_key TEXT,
                access_level INTEGER,
                PRIMARY KEY(user_id, encrypted_key)
            );
        ''')

        self.db_create('''
            CREATE TABLE IF NOT EXISTS
            Status(
                ip_address TEXT,
                session_token TEXT,
                last_online INTEGER,
                time_created INTEGER,
                stat_id TEXT NOT NULL,
                FOREIGN KEY(stat_id) REFERENCES Account(user_id)
            );
        ''')

        self.db_create('''
        CREATE TABLE IF NOT EXISTS
            Attempt(
                last_attempt INTEGER,
                ampt_id TEXT NOT NULL,
                attempts_made INTEGER DEFAULT 0,
                FOREIGN KEY(ampt_id) REFERENCES Account(user_id)
            );
        ''')

        self.db_create('''
        CREATE TABLE IF NOT EXISTS
            Lock(
                lock_id TEXT NOT NULL,
                time_locked INTEGER DEFAULT 0,
                FOREIGN KEY(lock_id) REFERENCES Account(user_id)
            );
        ''')

    @property
    def is_firstuser(self):
        data = self.db_query('SELECT * FROM Account;', [], False)
        return False if len(data) else True

    def register(self, username, password):
        time_created = time()

        username = username.lower()
        hashed_password = self.hash_password(password)

        user_id = self.generate_user_id(username, password)
        user_key = self.generate_user_key(username, password)
        master_key = self.generate_master_key(user_id, password, time_created)
        encrypted_key = b64encode(
            CryptoAES.encrypt(user_key, master_key)).decode()

        self.db_update('''
            INSERT INTO Account(user_id, encrypted_key, username, password, access_level)
            VALUES(?, ?, ?, ?, ?);
            ''', [user_id, encrypted_key, username, hashed_password,
                  PermissionConst.ROOT.value if self.is_firstuser else PermissionConst.NONE.value]
        )

        self.db_update('''
            INSERT INTO Status(last_online, time_created, stat_id)
            VALUES(?, ?, ?);
            ''', [time_created, time_created, user_id]
        )

        self.db_update('''
            INSERT INTO Attempt(last_attempt, ampt_id)
            VALUES(?, ?);
            ''', [time_created, user_id]
        )

        self.db_update('''
            INSERT INTO Lock(lock_id)
            VALUES(?);
            ''', [user_id]
        )

    def delete_account(self, user_id):
        self.db_update('DELETE FROM Account WHERE user_id=?;', [user_id])
        self.db_update('DELETE FROM Status WHERE stat_id=?;', [user_id])
        self.db_update('DELETE FROM Attempt WHERE ampt_id=?;', [user_id])
        self.db_update('DELETE FROM Lock WHERE lock_id=?;', [user_id])

    # -------- Authenticate -------- #

    def account_exists(self, username):
        data = self.db_query(
            'SELECT * FROM Account WHERE username=?;', [username], False)
        return True if len(data) else False

    def compare_passwords(self, user_id, password):
        hashed_password = self.db_query(
            'SELECT password FROM Account WHERE user_id=?;', [user_id])
        return True if bcrypt.hashpw(password.encode(), hashed_password) == hashed_password else False

    def check_password(self, username, password):
        hashed_password = self.db_query(
            'SELECT password FROM Account WHERE username=?;', [username])
        return True if bcrypt.hashpw(password.encode(), hashed_password) == hashed_password else False

    def authenticate(self, username, password, ip_address, current_time):
        username = username.lower()

        if not self.account_exists(username):
            return [], 'Account does not exist'

        user_id = self.get_user_id(username)

        if self.is_locked(user_id):
            return [], 'Your account is temporarily locked'

        if not self.check_password(username, password):

            self.failed_attempt(user_id)
            attempts_made = self.failed_attempts_counts(user_id)

            attempts_left = (
                DatabaseConst.MAX_FAILED_ATTEMPTS.value - attempts_made)

            if attempts_left == 0:
                return [], 'Your account is temporarily locked'

            return [], f'Invalid password; {attempts_left } attempt(s) remaining'

        master_key = self.generate_master_key(user_id, password)
        access_level = self.get_access_level(user_id)
        token = self.generate_session_token(user_id)
        last_active = self.get_last_active(user_id, current_time)
        self.login(user_id, token, ip_address)

        return [user_id, master_key, token, last_active, access_level], ''

    def login(self, user_id, token, ip_address):
        self.db_update(
            'UPDATE Attempt SET attempts_made=? WHERE ampt_id=?;', [0, user_id])
        self.db_update('UPDATE Status SET session_token=? WHERE stat_id=?;', [
                       token, user_id])
        self.db_update('UPDATE Status SET ip_address=? WHERE stat_id=?;', [
                       ip_address, user_id])

    def logout(self, user_id):
        token = self.generate_session_token(user_id)
        self.db_update('UPDATE Status SET session_token=? WHERE stat_id=?;', [
                       token, user_id])

    def is_logged_in(self, user_id, session_token):
        token = self.db_query(
            'SELECT session_token FROM Status WHERE stat_id=?;', [user_id])

        if token != session_token:
            return False
        return True

    # -------- Attempts -------- #

    def lock_account(self, user_id):
        self.db_update('UPDATE Lock SET time_locked=? WHERE lock_id=?;', [
                       time(), user_id])

    def failed_attempt(self, user_id):
        current_value = self.failed_attempts_counts(user_id)
        new_value = current_value + 1

        self.db_update('''
        UPDATE Attempt 
        SET attempts_made=? 
        WHERE ampt_id=?;''',
                       [new_value, user_id])

        if current_value >= DatabaseConst.MAX_FAILED_ATTEMPTS.value-1:
            if not self.is_locked(user_id):
                self.lock_account(user_id)

    def failed_attempts_counts(self, user_id):
        return self.db_query('SELECT attempts_made FROM Attempt WHERE ampt_id=?;', [user_id])

    def is_locked(self, user_id):
        time_locked = self.locked(user_id)

        if time_locked:

            if (time() - time_locked) >= DatabaseConst.LOCK_TIME.value:
                self.remove_locked_account(user_id)
                return False
            else:
                return True
        else:
            return False

    def locked(self, user_id):
        return self.db_query('''
            SELECT time_locked
            FROM Lock
            INNER JOIN Account ON account.user_id = Lock.lock_id
            WHERE Lock.lock_id=?;
            ''', [user_id]
        )

    def remove_locked_account(self, user_id):
        self.db_update(
            'UPDATE Attempt SET attempts_made=? WHERE ampt_id=?;', [0, user_id])

    # -------- Update -------- #

    def update_password(self, user_id, old_password, new_password):
        hashed_password = self.hash_password(new_password)

        old_master_key = self.generate_master_key(user_id, old_password)
        new_master_key = self.generate_master_key(user_id, new_password)

        old_encrypted_key = self.get_encrypted_user_key(user_id)
        user_key = CryptoAES.decrypt(old_encrypted_key, old_master_key)
        new_encrypted_key = b64encode(
            CryptoAES.encrypt(user_key, new_master_key)).decode()

        self.db_update('''
            UPDATE Account SET
            password=?,
            encrypted_key=?
            WHERE user_id=?;            
        ''', [hashed_password, new_encrypted_key, user_id])

        return new_master_key

    def update_username(self, user_id, username):
        self.db_update('UPDATE Account SET username=? WHERE user_id=?;', [
                       username.lower(), user_id])

    # -------- Misc -------- #

    def hash_password(self, password):
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

    def generate_user_id(self, username, password):
        user_id = b64encode(username.encode() +
                            password.encode() + urandom(64 * 64))
        return sha256(user_id).digest().hex()

    def generate_user_key(self, username, password):
        return sha256((username + password).encode() + get_random_bytes(64 * 4)).digest()

    def generate_master_key(self, user_id, password, time_created=None):
        time_created = self.db_query('''
            SELECT time_created
            FROM Status
            WHERE stat_id=?;''',
                                     [user_id]) if not time_created else time_created

        return sha256(password.encode() + str(time_created).encode()).digest()

    def generate_session_token(self, user_id):
        return sha256(user_id.encode() + urandom(64 * 64) + str(time()).encode()).digest().hex()

    def get_time_created(self, user_id):
        return self.db_query('SELECT time_created FROM Status WHERE stat_id=?;', [user_id])

    def get_user_id(self, username):
        return self.db_query('SELECT user_id FROM Account WHERE username=?;', [username])

    def get_user_name(self, user_id):
        return self.db_query('SELECT username FROM Account WHERE user_id=?;', [user_id])

    def get_master_key(self, username, password):
        user_id = self.get_user_id(username)
        time_created = self.get_time_created(user_id)
        return self.generate_master_key(time_created, password)

    def get_encrypted_user_key(self, user_id):
        user_key = self.db_query(
            'SELECT encrypted_key FROM Account WHERE user_id=?;', [user_id])
        return b64decode(user_key)

    def get_access_level(self, user_id):
        return self.db_query('SELECT access_level FROM Account WHERE user_id=?;', [user_id])

    def get_last_active(self, user_id, current_time):
        last_online = self.db_query(
            'SELECT last_online FROM Status WHERE stat_id=?;', [user_id])
        self.db_update('UPDATE Status SET last_online=? WHERE stat_id=?;', [
                       current_time, user_id])
        return last_online

    def get_last_online(self, user_id):
        epoch = self.db_query(
            'SELECT last_online FROM Status WHERE stat_id=?;', [user_id])
        return self.format_date(epoch)

    def get_date_created(self, user_id):
        epoch = self.get_time_created(user_id)
        return self.format_date(epoch)

    def format_date(self, epoch):
        return datetime.fromtimestamp(epoch).strftime('%b %d, %Y')

    def get_users(self):
        return self.db_query('SELECT user_id FROM Account ORDER BY access_level;', [], False)

    def get_admin(self):
        return self.db_query('SELECT COUNT(*) FROM Account WHERE access_level=?;', [PermissionConst.ROOT.value])

    def get_ip_address(self, user_id):
        ip_addr = self.db_query(
            'SELECT ip_address FROM Status WHERE stat_id=?;', [user_id])
        return '0.0.0.0' if not ip_addr else ip_addr

    def update_permission(self, user_id, permission_id):
        self.db_update('UPDATE Account SET access_level=? WHERE user_id=?;', [
                       permission_id, user_id])

    def user_id_exists(self, user_id):
        return self.db_query('SELECT COUNT(*) FROM Account WHERE user_id=?;', [user_id])


class Profile(DatabaseWrapper):

    def __init__(self):
        super().__init__(DatabaseConst.PROFILE_DB.value)
        self.create_tables()

    def create_tables(self):
        self.db_create('''
            CREATE TABLE IF NOT EXISTS
            Topic(
                user_id TEXT, 
                topic_id TEXT,
                date_created INTEGER,
                encrypted_topic_name TEXT,
                PRIMARY KEY(user_id, topic_id)
            );
        ''')

        self.db_create('''
            CREATE TABLE IF NOT EXISTS
            Note(
                note_id TEXT,
                topic_id TEXT, 
                encrypted_title TEXT,
                date_created INTEGER,
                encrypted_content TEXT, 
                FOREIGN KEY(topic_id) REFERENCES Topic(topic_id)
            );
        ''')

    def delete_account(self, user_id):
        topics = self.db_query(
            'SELECT topic_id FROM Topic WHERE user_id=?;', [user_id], False)

        for topic in topics:
            self.delete_topic(topic[0])

    # -------- Topic -------- #

    def topic_exists(self, user_id, topic_id):
        data = self.db_query(
            'SELECT * FROM Topic WHERE user_id=? AND topic_id=?;', [user_id, topic_id], False)
        return True if len(data) else False

    def add_topic(self, user_id, user_key, topic_name, time_stamp):
        topic_id = sha256(user_id.encode() +
                          str(time()).encode() + urandom(16)).digest().hex()
        encrypted_topic_name = b64encode(CryptoAES.encrypt(
            topic_name.encode(), user_key)).decode()

        self.db_update('''
            INSERT INTO Topic(user_id, topic_id, encrypted_topic_name, date_created)
            VALUES(?, ?, ?, ?);
        ''', [user_id, topic_id, encrypted_topic_name, time_stamp])

        return topic_id, time_stamp

    def modify_topic(self, topic_id, user_key, modified_topic_name):
        encrypted_topic_name = b64encode(CryptoAES.encrypt(
            modified_topic_name.encode(), user_key)).decode()

        self.db_update('''
            UPDATE Topic SET
            encrypted_topic_name=?
            WHERE topic_id=?;            
        ''', [encrypted_topic_name, topic_id])

    def delete_topic(self, topic_id):
        self.db_update('DELETE FROM Topic WHERE topic_id=?;', [topic_id])
        self.db_update('DELETE FROM Note WHERE topic_id = ?;', [topic_id])

    def decrypt_topic(self, topic_id, user_key, get_notes=True):
        if get_notes:
            notes = self.db_query('''
            SELECT note_id 
            FROM Note 
            INNER JOIN Topic ON Topic.topic_id = Note.topic_id
            WHERE Note.topic_id=?;
            ''', [topic_id], False)

            note_ids = [note[0] for note in notes]
        else:
            note_ids = []

        encrypted_topic_name, date_created = self.db_query('''
            SELECT encrypted_topic_name, date_created
            FROM Topic 
            WHERE topic_id=?;
        ''', [topic_id], False)[0]

        topic_name = CryptoAES.decrypt(
            b64decode(encrypted_topic_name), user_key).decode()
        return {'topic_id': topic_id, 'topic_name': topic_name, 'date_created': date_created, 'notes': note_ids}

    def decrypt_topics(self, user_id, user_key):
        topics = self.db_query(
            'SELECT topic_id FROM Topic WHERE user_id=? ORDER BY date_created DESC;', [user_id], False)
        return [self.decrypt_topic(topic[0], user_key, get_notes=False) for topic in topics]

    def get_total_topics(self, user_id):
        return self.db_query('SELECT COUNT(*) FROM Topic WHERE user_id=?', [user_id])

    # -------- Note -------- #

    def note_exists(self, topic_id, note_id):
        data = self.db_query(
            'SELECT * FROM Note WHERE topic_id=? AND note_id=?;', [topic_id, note_id], False)
        return True if len(data) else False

    def add_note(self, topic_id, user_key, note_title, content, time_stamp):
        date_created = time_stamp
        encrypted_content = b64encode(CryptoAES.encrypt(
            content.encode(), user_key)).decode()
        encrypted_title = b64encode(CryptoAES.encrypt(
            note_title.encode(), user_key)).decode()
        note_id = sha256(topic_id.encode() +
                         str(time()).encode() + urandom(16)).digest().hex()

        self.db_update('''
            INSERT INTO Note(topic_id, note_id, date_created, encrypted_title, encrypted_content)  
            VALUES(?, ?, ?, ?, ?); 
        ''', [topic_id, note_id, date_created, encrypted_title, encrypted_content])

        return note_id, date_created

    def modify_note_title(self, topic_id, note_id, note_title, user_key):
        encrypted_title = b64encode(CryptoAES.encrypt(
            note_title.encode(), user_key)).decode()

        self.db_update('''
            UPDATE Note SET
            encrypted_title=?
            WHERE topic_id=? AND note_id=?;
        ''', [encrypted_title, topic_id, note_id])

    def modify_note_content(self, topic_id, note_id, note_content, user_key):
        encrypted_content = b64encode(CryptoAES.encrypt(
            note_content.encode(), user_key)).decode()

        self.db_update('''
            UPDATE Note SET 
            encrypted_content=?
            WHERE topic_id=? AND note_id=?; 
        ''', [encrypted_content, topic_id, note_id])

    def delete_note(self, topic_id, note_id):
        self.db_update('DELETE FROM Note WHERE topic_id=? AND note_id=?;', [
                       topic_id, note_id])

    def decrypt_note(self, note_id, user_key, get_content=True):

        if get_content:
            encrypted_title, encrypted_content, date_created = self.db_query('''
                SELECT encrypted_title, encrypted_content, date_created
                FROM Note 
                WHERE note_id=?;
            ''', [note_id], False)[0]

            title = CryptoAES.decrypt(
                b64decode(encrypted_title), user_key).decode()
            content = CryptoAES.decrypt(
                b64decode(encrypted_content), user_key).decode()

            return {'note_id': note_id, 'note_title': title, 'note_content': content, 'date_created': date_created}
        else:
            encrypted_title, date_created = self.db_query('''
                SELECT encrypted_title, date_created 
                FROM Note 
                WHERE note_id=?;
            ''', [note_id], False)[0]

            title = CryptoAES.decrypt(
                b64decode(encrypted_title), user_key).decode()

            return {'note_id': note_id, 'note_title': title, 'date_created': date_created}

    def decrypt_notes(self, topic_id, user_key):
        notes = self.db_query(
            'SELECT note_id FROM Note WHERE topic_id=? ORDER BY date_created DESC;', [topic_id], False)
        return [self.decrypt_note(note[0], user_key, get_content=False) for note in notes]

    def get_total_notes(self, user_id):
        topics = self.db_query(
            'SELECT topic_id FROM Topic WHERE user_id=?;', [user_id], False)

        total = 0
        for topic in topics:
            total += self.db_query(
                'SELECT COUNT(*) FROM Note WHERE topic_id=?;', [topic[0]])

        return total
