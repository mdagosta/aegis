CREATE TABLE member_auth_type (
  member_auth_type_id SERIAL NOT NULL,
  member_auth_type_name VARCHAR(50) NOT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (member_auth_type_name),
  UNIQUE (member_auth_type_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON member_auth_type FOR EACH ROW EXECUTE PROCEDURE update_dttm();

INSERT INTO member_auth_type (member_auth_type_name) VALUES ('Email Link Auth');



-- Only write to this table if the authentication is successful
-- When the user logs out, mark it deleted, after which it should not be used.
CREATE TABLE member_auth (
  member_auth_id SERIAL NOT NULL,
  member_auth_type_id INTEGER NOT NULL REFERENCES member_auth_type(member_auth_type_id),
  magic_token VARCHAR(10) NOT NULL,
  user_id BIGINT NOT NULL REFERENCES user_(user_id),
  email_id BIGINT NOT NULL REFERENCES email(email_id),
  member_id BIGINT NOT NULL REFERENCES member(member_id),
  ip_address VARCHAR(50) NOT NULL,
  register_flag BOOLEAN DEFAULT NULL,
  login_flag BOOLEAN DEFAULT NULL,
  expire_dttm TIMESTAMP NOT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (member_auth_id),
  UNIQUE (magic_token)
);
CREATE INDEX ON member_auth(member_id);
CREATE TRIGGER update_dttm BEFORE UPDATE ON member_auth FOR EACH ROW EXECUTE PROCEDURE update_dttm();
