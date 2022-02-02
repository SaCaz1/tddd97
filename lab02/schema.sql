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
