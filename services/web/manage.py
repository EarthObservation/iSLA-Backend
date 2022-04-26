from flask.cli import FlaskGroup

from project import app, db
from project.models.user_model import User
from datetime import datetime


cli = FlaskGroup(app)

@cli.command("create_db")
def create_db():
    db.drop_all()
    db.create_all()
    db.session.commit()

@cli.command("seed_db")
def seed_db():
    db.session.add(User(
        first_name="Billary",
        last_name="Hillary",
        user_name="redneck",
        email="billary.hillary@popular-domain.com",
        password=User.generate_hash("s0mE_Rand0m-5tr0ng#5TR1ng"),
        registered_on=datetime.now(),
        confirmed=True,
        confirmed_on=datetime.now(),
        terms_accepted=True,
    ))
    db.session.commit()

if __name__ == "__main__":
    cli()