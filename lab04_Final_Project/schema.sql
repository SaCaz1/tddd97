drop table if exists user;
drop table if exists logged_in_user;
drop table if exists post;

create table if not exists user(
  email varchar(255),
  password varchar(255),
  first_name varchar(255),
  family_name varchar(255),
  gender varchar(255),
  city varchar(255),
  country varchar(255),
  primary key (email)
);

create table if not exists logged_in_user(
  username varchar(255),
  token varchar(255),
  primary key (token),
  FOREIGN KEY(username) REFERENCES user(email)
);

create table if not exists post(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner varchar(255),
  author varchar(255),
  message varchar(1000),
  location varchar(255),
  FOREIGN KEY (owner) REFERENCES user(email),
  FOREIGN KEY (author) REFERENCES user(email)
);
