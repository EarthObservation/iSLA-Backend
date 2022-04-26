from flask_restx import Resource, reqparse, inputs
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from project.models.user_model import User
from project.models.revoked_token_model import RevokedToken
from datetime import datetime
from itsdangerous import URLSafeTimedSerializer
from flask import current_app
from flask import redirect
from flask import json, Response
from project import api


@api.doc(params={
    "first_name": "Your actual first name.",
    "last_name": "Your actual last name.",
    "user_name": "Pick anything you want but it has to be unique.",
    "email": "Email address you use, it will be used to verify you really exisit.",
    "password": "Pick a strong password to make you and us safe.",
    "confirm_password": "Just to make sure there are not any typos.",
    "language": "Automatically added from the browser if you are using web app browser interface, if language is not supported or provided it defaults to EN.",
    "terms_checked": "Confirm that you accept terms of use, privacy policy and cookies policy of our organization."
})
class UserRegistration(Resource):
    # Register new user.
    def post(self):
        registration_parser = reqparse.RequestParser()
        registration_parser.add_argument(
            "first_name", required=True, type=str, help="Your actual first name.")
        registration_parser.add_argument(
            "last_name", required=True, type=str, help="Your actual last name.")
        registration_parser.add_argument(
            "user_name", required=True, type=str, help="Pick anything you want but it has to be unique.")
        registration_parser.add_argument(
            "email", required=True, type=str, help="Email address you use, it will be used to verify you really exisit.")
        registration_parser.add_argument(
            "password", required=True, type=str, help="Pick a strong password to make you and us safe.")
        registration_parser.add_argument(
            "confirm_password", required=True, type=str, help="Just to make sure there are not any typos.")
        registration_parser.add_argument("language", type=str, default="EN",
                                         help="Automatically added from the browser if you are using web app browser interface, if language is not supported or provided it defaults to EN.")
        registration_parser.add_argument("terms_checked", required=True, type=inputs.boolean, default=False,
                                         help="Confirm that you accept terms of use, privacy policy and cookies policy of our organization.")

        registration_data = registration_parser.parse_args(strict=True, )

        # Use only if the frontend is JS and the bool notations are different from Pythons'.
        # if registration_data["terms_checked"] == "true":
        #     terms = True
        # elif registration_data["terms_checked"] == "false":
        #     terms = False

        # Check if languge was provided and default to EN if not provided
        # if registration_data["language"] is not None:
        #     language = registration_data["language"]
        # else:
        #     language = "EN"

        # Check for required parameters presence once more and return proper response with help message.
        if registration_data["first_name"] is None or registration_data["last_name"] is None or registration_data["user_name"] is None or registration_data["email"] is None or registration_data["password"] is None:
            current_app.logger.warn({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": "Registration: Incomplete data sent."
                })
            return Response(
                response=json.dumps({
                    "message": "The data you sent is not complete. Check the form for empty inputs."
                }),
                status=500,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # Check if selected user_name already exists in database. It has to be unique.
        if User.find_by_username(registration_data["user_name"]):
            current_app.logger.warn({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": "Registration: Existing user."
                })
            return Response(
                response=json.dumps({
                    "message": "This user name is already taken. Please choose another."
                }),
                status=409,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # Check if email alrady exists in the database. It has to be unique.
        if User.find_by_email(registration_data["email"]):
            current_app.logger.warn({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": "Registration: Existing email address."
                })
            return Response(
                response=json.dumps({
                    "message": "This address is in use. Are you already registered?"
                }),
                status=409,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # Check if the passowrds are the same to avoid typos and hashing unwanted or unkonown passwords.
        if registration_data["password"] != registration_data["confirm_password"]:
            current_app.logger.warn({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": "Registration: Password mismatch."
                })
            return Response(
                response=json.dumps({
                    "message": "You misspelled one of the passwords. They should be the same."
                }),
                status=500,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # Check if terms and conditions were checked.
        if registration_data["terms_checked"] != True:
            current_app.logger.warn({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": "Registration: Terms not agreed upon."
                })
            return Response(
                response=json.dumps({
                    "message": "Seems you do not agree with our policies. You should if you wish to continue."
                }),
                status=500,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # Create new user class.
        new_user = User(
            first_name=registration_data["first_name"],
            last_name=registration_data["last_name"],
            user_name=registration_data["user_name"],
            email=registration_data["email"],
            password=User.generate_hash(registration_data["password"]),
            registered_on=datetime.now(),
            confirmed=False,
            terms_accepted=registration_data["terms_checked"],
        )
        current_app.logger.info({
            "date": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            "code": 20,
            "message": f"Registration: User {registration_data['user_name']} class created."
            })

        try:
            # Save new user to database and send confirmation mail.
            new_user.save_to_db()
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Registration: User {registration_data['user_name']} saved to database."
                })
            new_user.send_confirmation_email(
                registration_data["email"], registration_data["language"])
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Registration: User {registration_data['user_name']} sent confirmation email to {registration_data['email']}."
                })
            # Response is just a message, user has to confirm email first to complete registration, and use the api.
            return Response(
                response=json.dumps({
                    "message": "We sent you an email and you should check your inbox to confirm it.",
                }),
                status=200,
                mimetype="application/json",
            )
            
        # Return error with message if something went wrong during user creation.
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Registration: Failed to create user {registration_data['user_name']}."
                })
            return Response(
                response=json.dumps({
                    "message": "Something went wrong and we are working on it. Please try again later."
                }),
                status=511,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )


@api.doc(params={
    "user_name": "Your user name.",
    "password": "Your password."
})
class UserLogin(Resource):
    # Login user, it returns access and refresh tokens used to authenticate on protected resources and renew access token after it expires.
    def post(self):
        login_parser = reqparse.RequestParser()
        login_parser.add_argument(
            "user_name", required=True, type=str, help="Your user name")
        login_parser.add_argument(
            "password", required=True, type=str, help="Passsword")
        login_data = login_parser.parse_args()

        # Check if user exists.
        user = User.find_by_username(login_data["user_name"])
        if not user:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Login: User {login_data['user_name']} does not exist."
                })
            return Response(
                response=json.dumps({
                    "message": "Invalid credentials"
                }),
                status=511,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # Check if user confirmed email after registration.
        if not user.confirmed:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Login: User {login_data['user_name']} tried to login but has not confirmed his email yet."
                })
            return Response(
                response=json.dumps({
                    "message": "You must confirm your email address first."
                }),
                status=500,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )

        # Verify if password matches with password hash in the database.
        if User.verify_hash(login_data["password"], user.password):
            # Produce access and refresh token from user name and return them.
            try:
                access_token = create_access_token(
                    identity=login_data["user_name"])
                refresh_token = create_refresh_token(
                    identity=login_data["user_name"])
                # Set authentication status to True. It will have to be set to False on logout or token expiration.
                user.authenticated = True
                current_app.logger.warning({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 30,
                    "message": f"Login: User {login_data['user_name']} successsfully logged in."
                    })
                return Response(
                    response=json.dumps({
                        # Return also user name and email to display it in frontend.
                        "user_name": user.user_name,
                        "email": user.email,
                        "access_token": access_token,
                        "refresh_token": refresh_token
                    }),
                    status=200,
                    mimetype="application/json",
                )
            # Return error with message if something went wrong during token creation.
            except Exception as e:
                current_app.logger.error({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 40,
                    "error":  e,
                    "message": f"Login:  Something went wrong wwhile logging in user {login_data['user_name']}"
                    })
                return Response(
                    response=json.dumps({
                        "message": "Something went wrong and we are working on it. Please try again later."
                    }),
                    status=511,
                    mimetype="application/json",
                    headers={"Access-Control-Allow-Origin": "*"}
                )
        # Refuse acces if authentication fails.
        else:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Login: User {login_data['user_name']} provided invalid credentials."
                })
            return Response(
                response=json.dumps({
                    "message": "Invalid credentials.",
                }),
                status=401,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )


@api.doc(params={
    "jti": "Valid access token to be revoked.",
})
# Log out with access token.
class UserLogoutAccess(Resource):
    @jwt_required()  # Resoource is protected.
    def get(self):
        # Get token from header.
        jti = get_jwt()["jti"]
        # Identify users from token.
        user_name = get_jwt_identity()
        user = User.find_by_username(user_name)

        try:
            # Add token to revoked tokens table.
            print(jti)
            revoked_token = RevokedToken(jti=jti)
            revoked_token.add()

            # Change authentication to false.
            user.authenticated = False
            
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Logout access: User {user_name} logged out access token."
                })
            # Return nice message.
            return Response(
                response=json.dumps({
                    "message": "Logged out succesfully.",
                }),
                status=200,
                mimetype="application/json",
            )
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Logout access: User {user_name} error while logging out access token."
                })
            return Response(
                response=json.dumps({
                    "message": "Something went wrong and we are working on it. You might not log out correctly"
                }),
                status=511,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )


@api.doc(params={
    "jti": "Valid refresh token to be revoked.",
})
# Log out with refresh token
class UserLogoutRefresh(Resource):
    @jwt_required(refresh=True)  # Resoource is protected.
    def get(self):
        # Get token from header.
        jti = get_jwt()["jti"]

        try:
            # Add token to revoked tokens table.
            revoked_token = RevokedToken(jti=jti)
            revoked_token.add()
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Logout refresh: User logged out refresh token."
                })
            # Return nice message.
            return Response(
                response=json.dumps({
                    "message": "Logged out refresh succesfully.",
                }),
                status=200,
                mimetype="application/json",
            )

        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Logout refresh: Error while logging out refresh token."
                })
            return Response(
                response=json.dumps({
                    "message": "Something went wrong and we are working on it. You might not log out correctly"
                }),
                status=511,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )


@api.doc(params={
    "jti": "Valid refresh token.",
})
# Use valid refresh token to create new fresh access token
class TokenRefresh(Resource):
    @jwt_required(refresh=True)  # Protected by refresh token.
    def get(self):
        # Get the identity of refresh token user.
        current_user = get_jwt_identity()
        try:
            # create new access and refresh tokens for current user.
            access_token = create_access_token(identity=current_user)
            refresh_token = create_refresh_token(identity=current_user)
            # Return new tokens. No messeage is needed here as it should work automatically without user knowledge as long as he/she posesses valid refresh token.
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Token refresh: User {current_user} succesfully refreshed tokens."
                })
            return Response(
                response=json.dumps({
                    "access_token": access_token,
                    "refresh_token": refresh_token
                }),
                status=200,
                mimetype="application/json",
            )
        except Exception as e:
            # Log error here and also send logout signal to frontend to delete all user data, redirect to login and set user.authenitcated to False.
            current_user.authenticated = False
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Token refresh: User {current_user} error while refreshing token."
                })
            return Response(
                response=json.dumps({
                    "message": "Failed to refresh token, please log out and log in again."
                }),
                status=409,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )


@api.doc(params={
    "token": "Unique token sent in URL not header generated on registartion and received in email.",
})
# Validate that the email and user exist. This resource is accesible from URL sent to user via email during registration.
class EmailConfirmation(Resource):
    def get(self, token):
        # Get the serializer and decode email from token.
        try:
            confirm_serializer = URLSafeTimedSerializer(
                current_app.config["SECRET_KEY"])
            email = confirm_serializer.loads(
                token, salt=current_app.config["SECRET_KEY"], max_age=3600)
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Confirm email: User with address {email} requested email comnfirmation."
                })
        except:
            # If something went wrong redirect user to display notification because it is not posssible to return response to email account.
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Confirm email: Error while decoding user email address."
                })
            return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/emailnotok")

        # Find user by email.
        try:
            user = User.find_by_email(email)
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Confirm email: User does not exist."
                })
            return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/emailnotok")

        # If user is already confirmed redirect to display notification.
        if user.confirmed:
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Confirm email: User {user.user_name} email address is already confirmed."
                })
            return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/emailconfirmed")
        
        # If user is not confirmed yet, confirm it.
        else:
            try:
                User.confirm_email(email, datetime.now())
                current_app.logger.info({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 20,
                    "message": f"Confirm email: User {user.user_name} succcesfully confirmed email address."
                    })
                # Redirect to display notification.
                return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/emailok")
            
            except Exception as e:
                current_app.logger.error({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 40,
                    "error": e,
                    "message": f"Confirm email: Error while confirmning user {user.user_name} email address."
                    })
                # Redirect to display notification.
                return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/error500")

@api.doc(params={
    "email": "Email you used to register the account.",
})
# Request a link to the unique page from where user is able to set the new password. URL is sent via email.
class RequestResetPassword(Resource):
    def post(self):  # Consider changing to GET request.
        # Get parameters from body.
        reset_password_request_parser = reqparse.RequestParser()
        reset_password_request_parser.add_argument(
            "email", required=True, type=str, help="Email you used to register the account.")
        reset_password_request_parser.add_argument(
            "language", type=str, default="EN", help="Automatically added from the browser if you are using web app browser interface, if language is not supported or provided it defaults to EN.")

        reset_password_request_data = reset_password_request_parser.parse_args()

        try:
            # Find user by email.
            user = User.find_by_email(reset_password_request_data["email"])

            # User might not exist so check first and return error if not.
            if not user:
                current_app.logger.warning({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 30,
                    "message": f"Pasword reset request: Unknown user with address {reset_password_request_data['email']} requested password reset."
                    })
                return Response(
                    response=json.dumps({
                        "message": "We do not recognise this email."
                    }),
                    status=409,
                    mimetype="application/json",
                    headers={"Access-Control-Allow-Origin": "*"}
                )

            # Check if user confirmed email.
            if not user.confirmed:
                current_app.logger.warning({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 30,
                    "message": f"Pasword reset request: Unconfirmed user with address {reset_password_request_data['email']} requested password reset."
                    })
                return Response(
                    response=json.dumps({
                        "message": "This email address is not confirmed yet. Please check your inbox."
                    }),
                    status=409,
                    mimetype="application/json",
                    headers={"Access-Control-Allow-Origin": "*"}
                )
            # Send password reset URL via email.
            user.send_password_reset_email(
                reset_password_request_data["email"], reset_password_request_data["language"])
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Pasword reset request: Password reset link sent to {user.user_name}."
                })
            return Response(
                response=json.dumps({
                    "message": "We sent you an email with further instructions. Please check your inbox."
                }),
                status=200,
                mimetype="application/json",
            )

        # Return error if something went wrong.
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Pasword reset request: Internal error while procesing password reset request."
                })
            return Response(
                response=json.dumps({
                    "message": "Something went wrong and we are working on it. Please try again later."
                }),
                status=500,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )


@api.doc(params={
    "token": "Unique token sent in URL not header generated on password reset request and received in email.",
})
# Validates the token received in email and redirects to a safe page where user can set new password.
class ResetPassword(Resource):
    def get(request, token):
        # Get the serializer and decode token to get user email.
        try:
            password_reset_serializer = URLSafeTimedSerializer(
                current_app.config["SECRET_KEY"])
            email = password_reset_serializer.loads(
                token, salt=current_app.config["SECRET_KEY"], max_age=3600)
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Reset password GET: Received password reeset redirection request from {email}."
                })

        # Redirect to error page if something went wrong.
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Reset password GET: Error while decoding token."
                })
            return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/error500")

        # Find user by decoded email.
        user = User.find_by_email(email)
        # If user dosen't exist redirect to error page.
        if not user:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Reset password GET: Unknown user requested password reset."
                })
            return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/emailnotok")

        # If user exists redirect to view where user can change password.
        try:
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Reset password GET: User {user.user_name} redirected to password reset form."
                })
            return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/resetpassword/{token}")
        # Redirect to error page if something went wrong.
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Reset password GET: Error while redirecting to password reset form."
                })
            return redirect(f"{current_app.config['DEV_REDIRECT_HOME']}/error500")

    @api.doc(params={
        "token": "Unique token sent in URL not header generated on password reset request and received in email.",
        "password": "New password.",
        "token_1": "Should be also sent in body."
    })
    # Receives the new password and stores it in database, hashed.
    def post(self, token):
        reset_password_parser = reqparse.RequestParser()
        reset_password_parser.add_argument(
            "password", required=True, type=str, help="New password")
        reset_password_parser.add_argument(
            "token", required=True, type=str, help="Unique token sent in URL not header generated on password reset request and received in email.")
        reset_password_data = reset_password_parser.parse_args()
        try:
            # Decode user email from token.
            password_reset_serializer = URLSafeTimedSerializer(
                current_app.config["SECRET_KEY"])
            email = password_reset_serializer.loads(
                token, salt=current_app.config["SECRET_KEY"], max_age=3600)
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Reset password POST: Received new password to update from {email}."
                })
        except Exception as e:
            # Returns only notification as we are again in the application.
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Reset password POST: Error while decoding token."
                })
            return Response(
                response=json.dumps({
                    "message": "Something went wrong and we are working on it. Please try again later."
                }),
                status=500,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )
        # Check if user exists in database.
        user = User.find_by_email(email)
        if not user:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Reset password POST: Unknown user tried to update password."
                })
            return Response(
                response=json.dumps({
                    "message": "We do not recogize you. "
                }),
                status=409,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"}
            )
        # If user exists update the password.
        try:
            pass_hash = User.generate_hash(reset_password_data["password"])
            User.update_password(user.user_name, pass_hash)
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Reset password POST: Successfully updated user {user.user_name} password."
                })
            return Response(
                response=json.dumps({
                    "message": "Your password was successfully updated. Try it! You will be automatically redirected to login page."
                }),
                status=200,
                mimetype="application/json",
            )

        # On error inform of exception.
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Reset password POST: Error while updating password."
                })
            return Response(
                response=json.dumps({
                    "message": "Something went wrong and we are working on it. Please try again later."
                }),
                status=500,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"
                         })


@api.doc(params={
    "token": "User session token to identfy the user. Must be sent it header.",
    "new_email": "New email to replace the old one. Sent in request body.",
})
# User can update the email from the user settings. This triggers the new email confirmation cycle.
class UpdateEmail(Resource):
    @jwt_required()  # Extracts token from header and checkes validity.
    def post(self):
        # Get user identity from token.
        user_name = get_jwt_identity()
        user = User.find_by_username(user_name)
        current_app.logger.info({
            "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            "code": 20,
            "message": f"Update email: Received update email request from {user_name}."
            })

        # Check if user exists.
        if not user:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Update email: Unknown user requested email update."
                })
            return Response(
                response=json.dumps({
                    "message": "Hmmm..."
                }),
                status=511,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"
                         })
        # Get new email from request body.
        update_email_parser = reqparse.RequestParser()
        update_email_parser.add_argument(
            "new_email", required=True, type=str, help="New email.")
        update_email_parser.add_argument("language", type=str, default="EN",
                                         help="Automatically added from the browser if you are using web app browser interface, if language is not supported or provided it defaults to EN.")
        update_email_data = update_email_parser.parse_args()

        # Check if new email already exist in database.
        user_by_email = User.find_by_email(update_email_data["new_email"])
        # If not update user email in database. User will have to confrim it again.
        if not user_by_email:
            try:
                user.update_email(
                    user_name, update_email_data["new_email"], update_email_data["language"])
                current_app.logger.info({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 20,
                    "message": f"Update email: Updated user {user_name} email."
                    })
                return Response(
                    response=json.dumps({
                        "message": "We sent you an email and you should check your inbox to confirm it."
                    }),
                    status=200,
                    mimetype="application/json",
                )

            except Exception as e:
                current_app.logger.error({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 40,
                    "error": e,
                    "message": f"Update email: Error while updatinneg email."
                    })
                return Response(
                    response=json.dumps({
                        "message": "Something went wrong and we are working on it. Please try again later."
                    }),
                    status=511,
                    mimetype="application/json",
                    headers={"Access-Control-Allow-Origin": "*"
                             })
        # Notify user that email is already in use.
        else:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Update email: User tried to update change email with email that already exist."
                })
            return Response(
                response=json.dumps({
                    "message": "This email is already in use."
                }),
                status=511,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"
                         })


@api.doc(params={
    "token": "User session token to identfy the user. Must be sent it header.",
    "old_password": "Password that is currently in use. Must be checked and confirmed to match the one in database.",
    "new_password": "New password."
})
# Update the password with newer one.
class UpdatePassword(Resource):
    @jwt_required()  # Extracts token from header and checkes validity.
    def post(self):
        update_password_parser = reqparse.RequestParser()
        update_password_parser.add_argument(
            "old_password", required=True, type=str, help="Old password.")
        update_password_parser.add_argument(
            "new_password", required=True, type=str, help="New password.")
        update_password_data = update_password_parser.parse_args()

        # Get the user identity from token.
        user_name = get_jwt_identity()
        user = User.find_by_username(user_name)
        current_app.logger.info({
            "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            "code": 20,
            "message": f"Update password: Received update password request from {user_name}"
            })
        # Get current password hash from database and compare to old_password that user submitted.
        old_password = User.get_user_password_hash(user_name)
        if User.verify_hash(update_password_data["old_password"], old_password):
            # Update password in the database and notify the frontend.
            try:
                new_password = User.generate_hash(
                    update_password_data["new_password"])
                User.update_password(user_name, new_password)

                # Change the user authenticaion to false.
                user.authenticated = False
                current_app.logger.info({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 20,
                    "message": f"Update password: Password updates successfully for {user_name}."
                    })
                return Response(
                    response=json.dumps({
                        "message": "You have sucessfully updated your password. You will be logged out now."
                    }),
                    status=200,
                    mimetype="application/json",
                )

            except Exception as e:
                current_app.logger.error({
                    "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                    "code": 40,
                    "error": e,
                    "message": f"Update password: Error while updating password for {user_name}."
                    })
                return Response(
                    response=json.dumps({
                        "message": "Something went wrong and we are working on it. Please try again later."
                    }),
                    status=511,
                    mimetype="application/json",
                    headers={"Access-Control-Allow-Origin": "*"
                             })
        else:
            # If the submitted old_password and the one in database do not match log user out.
            user.authenticated = False
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Update password: User {user_name} tried to update password with wrong old password."
                })
            return Response(
                response=json.dumps({
                    "message": "If you do not know your old password you can not set a new one. You will be logged out now due to security reasons. You can request a password reset link on the landing page."
                }),
                status=401,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"
                         })


@api.doc(params={
    "token": "User session token to identfy the user. Must be sent it header."
})
# Fetches the user data if the access and refresh token are present in local storage to extend the session and fetch the data required for this.
class FetchUserData(Resource):
    @jwt_required()  # Extracts token from header and checkes validity.
    def post(self):
        # Get user idetnity from token.
        user_name = get_jwt_identity()
        current_app.logger.info({
            "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
            "code": 20,
            "message": f"Fetch user data: User {user_name} fetched their data."
            })
        if not user_name:
            current_app.logger.warning({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 30,
                "message": f"Fetch user data: User tried to fetch data with invalid token."
                })
            return Response(
                response=json.dumps({
                    "message": "Invalid token."
                }),
                status=511,
                mimetype="application/json",
                headers={"Access-Control-Allow-Origin": "*"
                         })

        # If user exists return user name and email.
        try:
            user = User.find_by_username(user_name)
            current_app.logger.info({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 20,
                "message": f"Fetch user data: Fetched user {user_name} data."
                })
            return Response(response=json.dumps({
                "user_name": user.user_name,
                "email": user.email,
            }),
                status=200,
                mimetype="application/json"
            )
        except Exception as e:
            current_app.logger.error({
                "date": datetime.now().strftime('%d/%m/%Y %H:%M:%S'),
                "code": 40,
                "error": e,
                "message": f"Fetch user data: Error while feching user {user_name} data."
                })
            
