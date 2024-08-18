CREATE TABLE marketing (
  marketing_id INT NOT NULL AUTO_INCREMENT,
  marketing_name VARCHAR(50) DEFAULT NULL,
  marketing_type_cd VARCHAR(2) DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (marketing_id),
  UNIQUE(marketing_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE audit_session (
  audit_session_id BIGINT NOT NULL AUTO_INCREMENT,
  user_id BIGINT DEFAULT NULL REFERENCES user(user_id),
  member_id BIGINT DEFAULT NULL REFERENCES member(member_id),
  marketing_id INT DEFAULT NULL REFERENCES marketing(marketing_id),
  user_agent_id BIGINT DEFAULT NULL REFERENCES user_agent(user_agent_id),
  request_cnt int NOT NULL DEFAULT '0',
  view_cnt int NOT NULL DEFAULT '0',
  api_cnt int NOT NULL DEFAULT '0',
  ip_tx varchar(46) DEFAULT NULL,
  country_cd varchar(5) DEFAULT NULL,
  region_cd varchar(25) DEFAULT NULL,
  robot_ind tinyint DEFAULT NULL,
  first_request_name VARCHAR(50) DEFAULT NULL,
  last_request_name VARCHAR(50) DEFAULT NULL,
  last_request_dttm DATETIME DEFAULT NULL,
  session_time INT DEFAULT NULL,
  referer_tx TEXT,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (audit_session_id),
  KEY marketing (marketing_id),
  KEY create_dttm (create_dttm),
  KEY member_id (member_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE audit_request (
  audit_request_id BIGINT NOT NULL AUTO_INCREMENT,
  audit_session_id BIGINT NOT NULL,
  user_id BIGINT DEFAULT NULL,
  member_id BIGINT DEFAULT NULL,
  premium_cd varchar(1) DEFAULT NULL,
  marketing_id BIGINT DEFAULT NULL,
  created_dttm timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  request_name varchar(50) NOT NULL,
  request_nbr int NOT NULL,
  view_ind tinyint NOT NULL,
  api_ind tinyint NOT NULL,
  ip_tx varchar(46) DEFAULT NULL,
  country_cd varchar(6) DEFAULT NULL,
  region_cd varchar(25) DEFAULT NULL,
  user_agent_tx text,
  user_agent_id BIGINT DEFAULT NULL,
  robot_ind tinyint DEFAULT NULL,
  referer_tx text,
  url_path_tx text,
  url_query_tx text,
  cookies_tx text,
  formpost_tx text,
  http_status_nbr SMALLINT DEFAULT NULL,
  exec_time int DEFAULT NULL,
  db_query_time int DEFAULT NULL,
  db_update_time int DEFAULT NULL,
  db_iter_time int DEFAULT NULL,
  db_query_cnt int DEFAULT NULL,
  db_update_cnt int DEFAULT NULL,
  db_iter_cnt int DEFAULT NULL,
  mc_time int DEFAULT NULL,
  mc_cnt int DEFAULT NULL,
  mail_time int DEFAULT NULL,
  upload_time int DEFAULT NULL,
  render_time int DEFAULT NULL,
  PRIMARY KEY (audit_request_id),
  KEY audit_session (audit_session_id),
  KEY created_dttm (created_dttm),
  KEY request (request_name,created_dttm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE TABLE audit_request_data (
  audit_request_data_id BIGINT NOT NULL AUTO_INCREMENT,
  audit_request_id BIGINT NOT NULL REFERENCES audit_request(audit_request_id),
  audit_session_id BIGINT NOT NULL REFERENCES audit_session(audit_session_id),
  request_url TEXT NOT NULL,
  request_method TEXT NOT NULL,
  request_bytes BIGINT NOT NULL,
  run_host VARCHAR(50) DEFAULT NULL,
  run_env VARCHAR(50) DEFAULT NULL,
  response_bytes BIGINT DEFAULT NULL,
  response_ms BIGINT DEFAULT NULL,
  response_status INTEGER DEFAULT NULL,
  request_headers TEXT NOT NULL,
  request_body MEDIUMTEXT NOT NULL,
  response_headers TEXT DEFAULT NULL,
  response_body MEDIUMTEXT DEFAULT NULL,
  response_error TEXT DEFAULT NULL,
  create_dttm timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  delete_dttm datetime DEFAULT NULL,
  PRIMARY KEY (audit_request_data_id),
  KEY audit_session_id (audit_session_id),
  KEY audit_request_id (audit_request_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

INSERT INTO marketing (marketing_name) VALUES ('direct');
INSERT INTO marketing (marketing_name) VALUES ('referral');
INSERT INTO marketing (marketing_name) VALUES ('organic');
