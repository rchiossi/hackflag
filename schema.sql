drop table if exists users;
create table users (
  name string not null primary key,
  password string not null,
  type string not null
);

drop table if exists flags;
create table flags (
  value string not null primary key,
  name string not null
);

drop table if exists scoreboard;
create table scoreboard (
  id integer primary key autoincrement,
  user string not null,
  flag string not null
);
