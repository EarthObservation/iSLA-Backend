from urllib.parse import urldefrag
from project import db
from passlib.hash import sha256_crypt as sha256
from flask_mail import Message
from itsdangerous import URLSafeTimedSerializer
from flask import url_for, render_template
from project import mail
from flask import current_app
from datetime import datetime

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    first_name = db.Column(db.String(32), index=True)
    last_name = db.Column(db.String(32), index=True)
    email = db.Column(db.String, index=True)
    user_name = db.Column(db.String(32), index=True)
    password = db.Column(db.String(128), nullable=False)

    registered_on = db.Column(db.DateTime, nullable=False)
    terms_accepted = db.Column(db.Boolean, nullable=False, default=False)
    confirmed = db.Column(db.Boolean, nullable=False, default=False)
    confirmed_on = db.Column(db.DateTime, nullable=True)

    authenticated = db.Column(db.Boolean, nullable=False, default=False)

    def save_to_db(self):
        db.session.add(self)
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Save to database failed."
                })
            return e

    @staticmethod
    def send_email(subject, recipients, html_body):
        try:
            msg = Message(subject, recipients=(recipients))
            msg.html = html_body
            mail.send(msg)
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Send email failed."
                })
            return e

    @staticmethod
    def send_confirmation_email(email, language):
        try:
            confirm_serializer = URLSafeTimedSerializer(
                current_app.config['SECRET_KEY'])
            confirm_url = url_for('email_confirmation', token=confirm_serializer.dumps(
                email, salt=current_app.config['SECRET_KEY']), _external=True)
            if language == 'SI' or language == 'sl-SI' or language == 'sl' or language == 'si':
                html = render_template(
                    'email_confirmation_si.html', confirm_url=confirm_url)
                subject = '[iSLA] Prosimo potrdite e-naslov.'
            else:
                html = render_template(
                    'email_confirmation_en.html', confirm_url=confirm_url)
                subject = '[iSLA] Please confirm your email.'
            User().send_email(subject, [email], html)

        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Send conformation email failed."
                })
            return e

    @staticmethod
    def send_password_reset_email(email, language):
        try:
            password_reset_serializer = URLSafeTimedSerializer(
                current_app.config['SECRET_KEY'])
            token = password_reset_serializer.dumps(
                email, salt=current_app.config['SECRET_KEY'])
            password_reset_url = url_for(
                'reset_password', token=token, _external=True)
            if language == 'SI' or language == 'sl-SI' or language == 'sl' or language == 'si':
                html = render_template(
                    'password_reset_si.html', password_reset_url=password_reset_url)
                subject = '[iSLA] Za vaš račun je bila zahtevana ponastavitev gesla.'
            else:
                html = render_template(
                    'password_reset_en.html', password_reset_url=password_reset_url)
                subject = '[iSLA] Password reset was requested for your account.'
            User().send_email(subject, [email], html)
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Send password reset email failed."
                })
            return e

    @staticmethod
    def update_email(user_name, email, language):
        try:
            user = User().find_by_username(user_name)
            user.email = email
            user.confirmed = False
            user.confirmed_on = None
            db.session.add(user)
            db.session.commit()
            User().send_confirmation_email(email, language)
        except Exception as e:
            db.session.rollback()
            db.session.colse()
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Update email failed."
                })
            return e

    @staticmethod
    def confirm_email(email, confirmation_time):
        try:
            user = User().find_by_email(email)
            user.confirmed = True
            user.confirmed_on = confirmation_time
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Confirm email failed."
                })
            return e
        
    @classmethod
    def find_by_username(cls, user_name):
        try:
            user = cls.query.filter_by(user_name=user_name).first()
            return user
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Find user by user_name failed."
                })
            return e

    @classmethod
    def find_by_email(cls, email):
        try:
            user = cls.query.filter_by(email=email).first()
            return user
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Find user by email failed."
                })
            return e

    @staticmethod
    def generate_hash(password):
        try:
            hash = sha256.encrypt(password)
            return hash
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Generate hash failed."
                })
            return e
        
    @staticmethod
    def verify_hash(password, hash):
        try:
            return sha256.verify(password, hash)
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Verify hash failed."
                })
            return e
        
    @classmethod
    def get_user_password_hash(cls, user_name):
        try:
            user_hash = cls.query.filter_by(user_name=user_name).first().password
            return user_hash
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Get user password hash failed."
                })
            return e

    @classmethod
    def update_password(cls, user_name, new_password):
        try:
            user = cls.query.filter_by(user_name=user_name).first()
            user.password = new_password
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": "Update password failed."
                })
            return e

    # Generates a random string for user personal folder name, checks if the folder is alredy in use by another user and if not creates the folder.
    # Also generates personal folder tree and copies all the init files to it.
'''     @staticmethod
    def generate_personal_folder(length):
        folder_name = generate_random_string(length)
        if not User.find_by_personal_folder(folder_name):
            users_folder = current_app.config['PERSONAL_FOLDERS_LOCATION']
            personal_folder_path = os.path.join(users_folder, folder_name)
            try:
                this_folder = os.path.join(personal_folder_path, 'mapfiles')
                os.makedirs(this_folder)
                init_map_folder = current_app.config['INIT_MAP_FOLDER']
                copy_tree(init_map_folder, os.path.join(
                    personal_folder_path, 'mapfiles', 'map'))
                return folder_name
            except Exception as e:
                current_app.logger.debug(e)
                return Response(
                    response=json.dumps({
                        "message": "Internal server error"
                    }),
                    status=500,
                    mimetype="application/json",
                    headers={'Access-Control-Allow-Origin': '*'}
                )
        else:
            generate_personal_folder(length) '''

    # Checks if there is already the same string in the database column personalFolder.
'''     @classmethod
    def find_by_personal_folder(cls, personal_folder):
        try:
            folderExists = cls.query.filter_by(
                personal_folder=personal_folder).first()
            return folderExists

        except Exception as e:
            print(e)
            return {
                "error_code": 500,
                "user_message": "error-message-500",
                "user_window": True
            } '''
