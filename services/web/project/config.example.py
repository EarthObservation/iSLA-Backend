import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    LOG = f'{os.getenv("APP_FOLDER")}/project/logs/log.log'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite://')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    STATIC_FOLDER = f'{os.getenv("APP_FOLDER")}/project/static'
    INIT_MAP_FOLDER = f'{os.getenv("APP_FOLDER")}/project/static/map'
    SECRET_KEY = '<random strong string>'
    JWT_SECRET_KEY = '<random strong string>'
    BUNDLE_ERRORS = True
    JWT_BLACKLIST_ENABLED = True
    JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']
    ## Dev addres of frontend
    DEV_REDIRECT_HOME = 'http://localhost:8080/#'
    ## Dev addres of backend
    PROD_REDIRECT_HOME = 'http://localhost:1337/#'
    ## Mail provider settings
    MAIL_SERVER = "<smtp server address for mail sending>"
    MAIL_PORT = "<port for sending the emails>"
    MAIL_USERNAME = "<username for mail provider>"
    MAIL_PASSWORD  = "<password/token for mail provider>"
    MAIL_DEFAULT_SENDER = "<default address of the sender e.g. info@your-domain.org>"