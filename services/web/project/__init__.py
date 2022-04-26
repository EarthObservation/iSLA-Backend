from flask import Flask, redirect
from flask_restx import Api
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_mail import Mail
import logging
from flask import json, Response
from datetime import datetime

app = Flask(__name__)
app.app_context()
app.config.from_object("project.config.Config")

api = Api(app,  version='1.0', title="iSLA API for user and task management.", ordered=True)

# Extensions
db = SQLAlchemy(app)
mail = Mail(app)
logging.basicConfig(level=logging.DEBUG)
handler = logging.FileHandler(app.config['LOG'])
app.logger.addHandler(handler)
jwt = JWTManager(app)

from project.models import revoked_token_model
from project.resources import user_resources

@app.errorhandler(404)
def handle_404_error(_error):
    app.logger.error(f"{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}: {_error}")
    return redirect(f'{app.config["DEV_REDIRECT_HOME"]}/notfound')
    

@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return Response(
        response=json.dumps({
            "message": "Token expired. Requesting new token."
            }),
            status=401,
            mimetype="application/json",
            headers={'Access-Control-Allow-Origin':'*'}
            )


@jwt.token_in_blocklist_loader
def check_if_token_in_blacklist(cls, decrypted_token):
    try:
        jti = decrypted_token['jti']
        return revoked_token_model.RevokedToken.is_jti_blacklisted(jti)
    except Exception as e:
        print(e)

api.add_resource(user_resources.UserRegistration, '/user/registration')
api.add_resource(user_resources.UserLogin, '/user/login')
api.add_resource(user_resources.UserLogoutAccess, '/user/logout/access')
api.add_resource(user_resources.UserLogoutRefresh, '/user/logout/refresh')
api.add_resource(user_resources.TokenRefresh, '/user/token/refresh')
api.add_resource(user_resources.EmailConfirmation, '/user/confirm/<token>')
api.add_resource(user_resources.RequestResetPassword, '/user/requestresetpassword')
api.add_resource(user_resources.ResetPassword, '/user/resetpassword/<token>')
api.add_resource(user_resources.UpdateEmail, '/user/updateemail')
api.add_resource(user_resources.UpdatePassword, '/user/updatepassword')
api.add_resource(user_resources.FetchUserData, '/user/fetchuserdata')

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True, threaded=True)