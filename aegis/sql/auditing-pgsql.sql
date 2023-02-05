CREATE TABLE marketing (
  marketing_id SERIAL NOT NULL,
  marketing_name VARCHAR(50) NOT NULL,
  marketing_type_cd VARCHAR(2) DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (marketing_id),
  UNIQUE (marketing_name)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON marketing FOR EACH ROW EXECUTE PROCEDURE update_dttm();


CREATE TABLE audit_session (
  audit_session_id BIGSERIAL NOT NULL,
  user_id INTEGER DEFAULT NULL REFERENCES user_(user_id),
  member_id INTEGER DEFAULT NULL REFERENCES member(member_id),
  marketing_id INTEGER DEFAULT NULL REFERENCES marketing(marketing_id),
  request_cnt INTEGER NOT NULL DEFAULT '0',
  view_cnt INTEGER NOT NULL DEFAULT '0',
  api_cnt INTEGER NOT NULL DEFAULT '0',
  ip_tx VARCHAR(46) DEFAULT NULL,
  country_cd VARCHAR(5) DEFAULT NULL,
  region_cd VARCHAR(5) DEFAULT NULL,
  user_agent_id INTEGER DEFAULT NULL,
  robot_ind BOOLEAN DEFAULT NULL,
  first_request_name VARCHAR(50) DEFAULT NULL,
  last_request_name VARCHAR(50) DEFAULT NULL,
  last_request_dttm TIMESTAMP DEFAULT NULL,
  session_time INTEGER DEFAULT NULL,
  referer_tx TEXT,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (audit_session_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON audit_session FOR EACH ROW EXECUTE PROCEDURE update_dttm();
CREATE INDEX ON audit_session(member_id);
CREATE INDEX ON audit_session(create_dttm);
CREATE INDEX ON audit_session(marketing_id);


CREATE TABLE audit_request (
  audit_request_id BIGSERIAL NOT NULL,
  audit_session_id INTEGER NOT NULL REFERENCES audit_session(audit_session_id),
  user_id INTEGER DEFAULT NULL REFERENCES user_(user_id),
  member_id INTEGER DEFAULT NULL REFERENCES member(member_id),
  marketing_id INTEGER DEFAULT NULL REFERENCES marketing(marketing_id),
  request_name VARCHAR(50) NOT NULL,
  request_nbr INTEGER NOT NULL,
  view_ind BOOLEAN NOT NULL,
  api_ind BOOLEAN NOT NULL,
  ip_tx VARCHAR(46) DEFAULT NULL,
  country_cd VARCHAR(6) DEFAULT NULL,
  region_cd VARCHAR(5) DEFAULT NULL,
  user_agent_id INTEGER DEFAULT NULL,
  robot_ind BOOLEAN DEFAULT NULL,
  referer_tx TEXT,
  url_path_tx TEXT,
  url_query_tx TEXT,
  cookies_tx TEXT,
  formpost_tx TEXT,
  http_status_nbr INTEGER DEFAULT NULL,
  exec_time INTEGER DEFAULT NULL,
  db_query_time INTEGER DEFAULT NULL,
  db_update_time INTEGER DEFAULT NULL,
  db_iter_time INTEGER DEFAULT NULL,
  db_query_cnt INTEGER DEFAULT NULL,
  db_update_cnt INTEGER DEFAULT NULL,
  db_iter_cnt INTEGER DEFAULT NULL,
  render_time INTEGER DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (audit_request_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON audit_request FOR EACH ROW EXECUTE PROCEDURE update_dttm();
CREATE INDEX ON audit_request(audit_session_id);
CREATE INDEX ON audit_request(create_dttm);
CREATE INDEX ON audit_request(request_name);


CREATE TABLE audit_request_data (
  audit_request_data_id BIGSERIAL,
  audit_request_id INTEGER NOT NULL REFERENCES audit_request(audit_request_id),
  audit_session_id INTEGER NOT NULL REFERENCES audit_session(audit_session_id),
  request_url TEXT NOT NULL,
  request_method TEXT NOT NULL,
  request_bytes INTEGER NOT NULL,
  run_host VARCHAR(50) DEFAULT NULL,
  run_env VARCHAR(50) DEFAULT NULL,
  response_bytes INTEGER DEFAULT NULL,
  response_ms INTEGER DEFAULT NULL,
  response_status INTEGER DEFAULT NULL,
  request_headers TEXT NOT NULL,
  request_body TEXT NOT NULL,
  response_headers TEXT DEFAULT NULL,
  response_body TEXT DEFAULT NULL,
  response_error TEXT DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (audit_request_data_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON audit_request_data FOR EACH ROW EXECUTE PROCEDURE update_dttm();
CREATE INDEX ON audit_request_data(audit_request_id);
CREATE INDEX ON audit_request_data(audit_session_id);
