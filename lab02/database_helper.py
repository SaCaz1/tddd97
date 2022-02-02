from sqlalchemy import Column, Integer, String, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

# user = Table(
# 'user'
# Base.metadata,
# Column('email', String),
# Column('password', String),
# Column('first_name', String),
# Column('family_name', String),
# Column('gender', String),
# Column('city', String),
# Column('country', String),
# )

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


DATABASE_URI = 'database.db'


engine = create_engine(f"sqlite:///{DATABASE_URI}")

Session = sessionmaker()
Session.configure(bind=engine)
session = Session()

results = session.query(
    User.first_name
)

if results.first() is not None:
    for result in results:
        print(user.first_name)
else:
    print("no users")

session.close()
