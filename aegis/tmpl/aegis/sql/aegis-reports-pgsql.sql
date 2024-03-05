-- report_type: the structure of each type of report to be run.
CREATE TABLE report_type (
  report_type_id SERIAL NOT NULL,
  report_type_name VARCHAR(250) NOT NULL,
  report_sql TEXT NOT NULL,
  report_schema VARCHAR(250) DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (report_type_name)
);
CREATE INDEX ON report_type(report_type_id);
CREATE TRIGGER update_dttm BEFORE UPDATE ON report_type FOR EACH ROW EXECUTE PROCEDURE update_dttm();
