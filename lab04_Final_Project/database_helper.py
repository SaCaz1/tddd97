import sqlalchemy
from sqlalchemy import Column, Integer, String, ForeignKey, create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from flask import g
from enum import Enum
import subprocess

subprocess.call('./lab04_Final_Project/setup_database.sh')

class DatabaseErrorCode(Enum):
    """Error codes for database"""

    Success = 0
    IntegrityError = 1
    ObjectNotFound = 2
    GeneralError = 3

Base = declarative_base()

class User(Base):
    """ Class mapping 'user' table.

    Attributes
    ----------
    email : str
        User's email
    password : str
        User's encrypted password
    first_name : str
        User's first name
    family_name : str
        User's family name
    gender : str
        User's gender
    city : str
        User's city
    country : str
        User's country
    """

    __tablename__ = "user"
    email = Column('email', String, primary_key=True)
    password = Column('password', String)
    first_name = Column('first_name', String)
    family_name = Column('family_name', String)
    gender = Column('gender', String)
    city = Column('city', String)
    country = Column('country', String)

class LoggedInUser(Base):
    """ Class mapping 'logged_in_user' table.

    Attributes
    ----------
    username : str
        User's username
    token : str
        Token associated with the user's session
    """

    __tablename__ = "logged_in_user"
    username = Column('username', String, ForeignKey("user.email"))
    token = Column('token', String, primary_key=True)

class Post(Base):
    """Class mapping 'post' table.

    Attributes
    ----------
    id : int
        Identification number associated with the post
    owner : str
        Email of the owner of the post
    author : str
        Email of the author of the post
    message : str
        Post's message
    location : str
        Location of the author when posting
    """

    __tablename__ = "post"
    id = Column('id', Integer, primary_key=True)
    owner = Column('owner', String, ForeignKey("user.email"))
    author = Column('author', String, ForeignKey("user.email"))
    message = Column('message', String)
    location = Column('location', String)


DATABASE_URI = 'database.db'


def get_session():
    """ Returns the session associated with the database.

    Returns
    -------
    Session
        Session associated with the database
    """

    session = getattr(g, 'session', None)
    if session is None:
        engine = create_engine(f"sqlite:///{DATABASE_URI}")
        event.listen(engine, 'connect', lambda conn, _ : conn.execute('PRAGMA foreign_keys = ON;'))

        Session = sessionmaker()
        Session.configure(bind=engine)
        session = g.session = Session()

    return session

def close_session():
    """ Closes the session associated with the database."""

    session = getattr(g, 'session', None)
    if session is not None:
        session.close()
        g.session = None

def create_user(information):
    """ Create a new user and add it to the database.

    Parameters
    ----------
    information : dict
        Dictionary containing the new user's information

    Returns
    -------
    DatabaseErrorCode
        Error code indicating if the user was successfully created and added to the database.
    """

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
    """ Reads and returns user's information from the database.

    Parameters
    ----------
    email : string
        Email of the user to read

    Returns
    -------
    User or None
        User object corresponding to the user's email. None if not found.
    """

    session = get_session()

    user = session.query(User).filter(User.email == email).one_or_none()

    return user


def create_logged_in_user(username, token):
    """ Create a new logged in user and add it to the database.

    Parameters
    ----------
    username : str
        Logged in user's username
    token : str
        Token associated with the user's session

    Returns
    -------
    DatabaseErrorCode
        Error code indicating if the logged in user was created and added to the database successfully
    """

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
    """ Reads and returns the first logged in user's information corresponding in the database.

    Parameters
    ----------
    email : string
        Email of the logged in user to read

    Returns
    -------
    LoggedInUser or None
        First LoggedInUser object corresponding to the logged in user's email. None if not found.
    """

    session = get_session()
    result = session.query(LoggedInUser).filter(LoggedInUser.username == email).one_or_none()
    return result

def read_all_user_sessions(email):
    """ Reads and returns logged in user's information from all sessions in the database.

    Parameters
    ----------
    email : string
        Email of the logged in user to read

    Returns
    -------
    List
        List of LoggedInUser object corresponding to the logged in user's email.
    """

    session = get_session()
    results = session.query(LoggedInUser).filter(LoggedInUser.username == email).all()
    return results

def delete_logged_in_user(email, token):
    """ Deletes the logged in user from database.

    Parameters
    ----------
    email : str
        Email of the logged in user to delete
    token : str
        Token associated with the user's session

    Returns
    -------
    DatabaseErrorCode
        Error code indicating if the logged in user was successfully deleted from the database.
    """

    session = get_session()
    result = session.query(LoggedInUser).filter(LoggedInUser.username == email and LoggedInUser.token == token)
    if result.first() is not None:
        session.delete(result.first())
        session.commit()
    else:
        return DatabaseErrorCode.ObjectNotFound

    return DatabaseErrorCode.Success

def read_user_by_token(token):
    """ Reads and returns user's information from the database using the given token.

    Parameters
    ----------
    token : string
        Token associated with the user's session

    See Also
    --------
    read_user

    Returns
    -------
    User or None
        User object corresponding to the token. None if not found.
    """

    session = get_session()

    logged_in_user = session.query(LoggedInUser).filter(LoggedInUser.token == token).one_or_none()

    if logged_in_user is None:
        return None

    return read_user(logged_in_user.username)

def read_message(owner_email):
    """ Reads and returns the messages associated with the owner.

    Parameters
    ----------
    owner_email : str
        Email of the owner of the messages

    Returns
    -------
    List
        List of Post objects corresponding to the messages of the owner
    """

    session = get_session()
    result = session.query(Post).filter(Post.owner == owner_email)
    return result.all()

def create_message(information):
    """ Create a new message and add it to the database.

    Parameters
    ----------
    information : dict
        Dictionary containing the new message's information

    Returns
    -------
    DatabaseErrorCode
        Error code indicating if the message was successfully created and added to the database.
    """

    post = Post()
    post.owner = information["owner"]
    post.author = information["author"]
    post.message = information["message"]
    post.location = information["location"]

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
    """ Updates the user's password in the database.

    Parameters
    ----------
    username : str
        Username of the user to update
    new_password : str
        New password with which to replace the old password in the database

    Returns
    -------
    DatabaseErrorCode
        Error code indicating if the user's password was successfully updated.
    """

    session = get_session()
    result = session.query(User).filter(User.email == username)

    if result.first() is not None:
        result.update(values={"password" : new_password})
        session.commit()
    else:
        return DatabaseErrorCode.ObjectNotFound

    return DatabaseErrorCode.Success
