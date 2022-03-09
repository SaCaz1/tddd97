import sqlalchemy
from sqlalchemy import Column, Integer, String, ForeignKey, create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask import g
from enum import Enum
import subprocess

subprocess.call('./lab04_Final_Project/setup_database.sh')

class DatabaseErrorCode(Enum):
    Success = 0
    IntegrityError = 1
    ObjectNotFound = 2
    GeneralError = 3

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
    id = Column('id', Integer, primary_key=True)
    owner = Column('owner', String, ForeignKey("user.email"))
    author = Column('author', String, ForeignKey("user.email"))
    message = Column('message', String)


DATABASE_URI = 'database.db'


def get_session():
    session = getattr(g, 'session', None)
    if session is None:
        engine = create_engine(f"sqlite:///{DATABASE_URI}")
        event.listen(engine, 'connect', lambda conn, _ : conn.execute('PRAGMA foreign_keys = ON;'))

        Session = sessionmaker()
        Session.configure(bind=engine)
        session = g.session = Session()

    return session

def close_session():
    session = getattr(g, 'session', None)
    if session is not None:
        session.close()
        g.session = None

def create_user(information):
    user = User()
    user.email = information["email"]
    user.password = information["password"]
    user.first_name = information["first_name"]
    user.family_name = information["family_name"]
    user.gender = information["gender"]
    user.city = information["city"]
    user.country = information["country"]

    try:
        session = get_session()
        session.add(user)
        session.commit()
    except sqlalchemy.exc.IntegrityError:
        return DatabaseErrorCode.IntegrityError
    except Exception:
        return DatabaseErrorCode.GeneralError

    return DatabaseErrorCode.Success


def read_user(email):
    session = get_session()

    user = session.query(User).filter(User.email == email).one_or_none()

    return user


def create_logged_in_user(username, token):
    logged_in_user = LoggedInUser()
    logged_in_user.username = username
    logged_in_user.token = token

    try:
        session = get_session()
        session.add(logged_in_user)
        session.commit()
    except sqlalchemy.exc.IntegrityError:
        return DatabaseErrorCode.IntegrityError
    except Exception:
        return DatabaseErrorCode.GeneralError

    return DatabaseErrorCode.Success

def read_logged_in_user(email):
    session = get_session()
    result = session.query(LoggedInUser).filter(LoggedInUser.username == email).one_or_none()
    return result

def read_all_user_sessions(email):
    session = get_session()
    results = session.query(LoggedInUser).filter(LoggedInUser.username == email).all()
    return results

def delete_logged_in_user(email, token):
    session = get_session()
    result = session.query(LoggedInUser).filter(LoggedInUser.username == email and LoggedInUser.token == token)
    if result.first() is not None:
        session.delete(result.first())
        session.commit()
    else:
        return DatabaseErrorCode.ObjectNotFound

    return DatabaseErrorCode.Success

def read_user_by_token(token):
    session = get_session()

    logged_in_user = session.query(LoggedInUser).filter(LoggedInUser.token == token).one_or_none()

    if logged_in_user is None:
        return None

    return read_user(logged_in_user.username)

def read_message(owner_email):
    session = get_session()
    result = session.query(Post).filter(Post.owner == owner_email)
    return result.all()

def create_message(information):
    post = Post()
    post.owner = information["owner"]
    post.author = information["author"]
    post.message = information["message"]

    try:
        session = get_session()
        session.add(post)
        session.commit()
    except sqlalchemy.exc.IntegrityError:
        return DatabaseErrorCode.IntegrityError
    except Exception:
        return DatabaseErrorCode.GeneralError

    return DatabaseErrorCode.Success

def update_user_password(username, new_password):
    session = get_session()
    result = session.query(User).filter(User.email == username)

    if result.first() is not None:
        result.update(values={"password" : new_password})
        session.commit()
    else:
        return DatabaseErrorCode.ObjectNotFound

    return DatabaseErrorCode.Success
