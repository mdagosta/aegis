-- hydra_type: the structure of each type of work to be performed by hydra.
CREATE TABLE hydra_type (
  hydra_type_id SERIAL NOT NULL,
  hydra_type_name VARCHAR(100) NOT NULL,
  hydra_type_desc TEXT DEFAULT NULL,
  priority_ndx INTEGER NOT NULL DEFAULT '0',
  status VARCHAR(20) DEFAULT NULL,            -- canceled, running, scheduled, disabled, ugc/on-demand/trigger etc?
  last_run_dttm TIMESTAMP DEFAULT NULL,
  next_run_dttm TIMESTAMP DEFAULT NULL,
  next_run_sql VARCHAR(100) DEFAULT NULL,     -- date_add(now(), interval 6 hour). NOT REQUIRED.
  claimed_dttm TIMESTAMP DEFAULT NULL,
  run_cnt BIGINT NOT NULL DEFAULT '0',
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (hydra_type_name),
  UNIQUE (hydra_type_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON hydra_type FOR EACH ROW EXECUTE PROCEDURE update_dttm();


-- hydra_queue: putting the hydra_type and its work-specific data onto the queue for processing
CREATE TABLE hydra_queue (
  hydra_queue_id SERIAL NOT NULL,
  hydra_type_id BIGINT NOT NULL,
  priority_ndx INTEGER NOT NULL DEFAULT '0',           -- Lower number = higher priority
  work_host VARCHAR(100) DEFAULT NULL,                 -- If specified only select this queue item on that zone
  work_env VARCHAR(20) DEFAULT NULL,                   -- If specified only select this queue item on that environment
  work_data TEXT DEFAULT NULL,                          -- JSON string describing the work-specific data
  work_dttm TIMESTAMP NOT NULL,                         -- When the work is scheduled to be done
  start_dttm TIMESTAMP DEFAULT NULL,                    -- When the work actually started
  claimed_dttm TIMESTAMP DEFAULT NULL,
  finish_dttm TIMESTAMP DEFAULT NULL,
  try_cnt int NOT NULL DEFAULT '0',
  error_cnt int NOT NULL DEFAULT '0',
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (priority_ndx, work_dttm, hydra_queue_id),
  UNIQUE (hydra_queue_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON hydra_queue FOR EACH ROW EXECUTE PROCEDURE update_dttm();
CREATE INDEX ON hydra_queue(hydra_type_id);


-- hydra_job: recording the progress of each job after it's finished being worked on
CREATE TABLE hydra_job (
  hydra_job_id SERIAL NOT NULL,
  hydra_type_id int NOT NULL,
  status VARCHAR(20) NOT NULL,
  start_dttm TIMESTAMP NOT NULL,
  finish_dttm TIMESTAMP DEFAULT NULL,
  run_time int NOT NULL DEFAULT '0',
  row_cnt int NOT NULL DEFAULT '0',
  last_row_id int DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (hydra_job_id)
);
CREATE TRIGGER update_dttm BEFORE UPDATE ON hydra_job FOR EACH ROW EXECUTE PROCEDURE update_dttm();
CREATE INDEX ON hydra_job(hydra_type_id, start_dttm);
