from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask import g

Base = declarative_base()

class User(Base):
    __tablename__ = "user"
    email = Column('email', String, primary_key=True)
    password = Column('password', String)
    first_name = Column('first_name', String)
    family_name = Column('family_name', String)
    gender = Column('gender', String)
    city = Column('city', String)
    country = Column('country', String)

class LoggedInUser(Base):
    __tablename__ = "logged_in_user"
    username = Column('username', String, ForeignKey("user.email"))
    token = Column('token', String, primary_key=True)

class Post(Base):
    __tablename__ = "post"
    owner = Column('owner', String, ForeignKey("user.email"))
    author = Column('author', String, ForeignKey("user.email"))
    message = Column('message', String)

DATABASE_URI = 'database.db'


def get_session():
    session = getattr(g, 'session', None)

    if session is None:
        engine = create_engine(f"sqlite:///{DATABASE_URI}")

        Session = sessionmaker()
        Session.configure(bind=engine)
        session = g.session = Session()

    return session

def close_session():
    session = g.session
    if session is not None:
        session.close()

results = get_session().query(
    User.first_name
)

if results.first() is not None:
    for result in results:
        print(user.first_name)
else:
    print("no users")

close_session()
