CREATE TABLE google_access (
  google_access_id SERIAL NOT NULL,
  google_user_id INTEGER NOT NULL REFERENCES google_user(google_user_id),
  expire_dttm TIMESTAMP DEFAULT NULL,
  access_token VARCHAR(8192) DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (google_access_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON google_access FOR EACH ROW EXECUTE PROCEDURE update_dttm();
CREATE INDEX ON google_access(google_user_id);
CREATE INDEX ON google_access(expire_dttm);

CREATE TABLE google_picture (
  google_picture_id SERIAL NOT NULL,
  image_data BYTEA NOT NULL,     -- https://stackoverflow.com/a/54541
  google_user_id INTEGER NOT NULL REFERENCES google_user(google_user_id),
  content_type VARCHAR(20) NOT NULL,
  image_size INTEGER NOT NULL,
  version_md5 VARCHAR(32) NOT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (google_picture_id),
  UNIQUE (google_user_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON google_picture FOR EACH ROW EXECUTE PROCEDURE update_dttm();
