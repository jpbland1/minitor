CREATE TABLE IF NOT EXISTS OnionRelays {
  identity CHAR(20) NOT NULL,
  digest CHAR(20) NOT NULL,
  ntor_onion_key CHAR(32) NOT NULL,
  address INT4 NOT NULL,
  or_port INT2 NOT NULL,
  dir_port INT2 NOT NULL,
  hsdir INT1 DEFAULT 0,
  previous_hash CHAR(32) NOT NULL,
  current_hash CHAR(32) NOT NULL
};
