CREATE TABLE build (
  build_id SERIAL NOT NULL,
  branch VARCHAR(100) NOT NULL,
  revision VARCHAR(100) NOT NULL,
  version VARCHAR(100) DEFAULT NULL,
  env VARCHAR(20) NOT NULL,
  build_output_tx TEXT DEFAULT NULL,
  build_exit_status INTEGER DEFAULT NULL,
  build_exec_sec DECIMAL DEFAULT NULL,
  build_size DECIMAL DEFAULT NULL,
  previous_version VARCHAR(100) DEFAULT NULL,
  deploy_dttm TIMESTAMP DEFAULT NULL,
  deploy_output_tx TEXT DEFAULT NULL,
  deploy_exit_status INTEGER DEFAULT NULL,
  revert_dttm TIMESTAMP DEFAULT NULL,
  revert_output_tx TEXT DEFAULT NULL,
  revert_exit_status INTEGER DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (build_id),
  UNIQUE (version)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON build FOR EACH ROW EXECUTE PROCEDURE update_dttm();
