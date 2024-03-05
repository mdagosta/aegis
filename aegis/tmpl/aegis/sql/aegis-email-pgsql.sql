CREATE TABLE email_type (
  email_type_id SERIAL NOT NULL,
  email_type_name VARCHAR(100) NOT NULL,
  template_name VARCHAR(100) NOT NULL,
  txnl_ind BOOLEAN NOT NULL,         -- Is it Transactional / Relationship Email?
  bulk_ind BOOLEAN NOT NULL,         -- Is it Bulk Email?
  min_period INTEGER DEFAULT NULL,   -- Minimum Period in seconds before another email of this type can be sent to the same user
  min_count INTEGER DEFAULT NULL,    -- Minimum Number of emails before another email of this type can be sent to the same user
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (email_type_id),
  UNIQUE (email_type_name)
);

CREATE TABLE email_tracking (
  email_tracking_id SERIAL NOT NULL,
  email_type_id INTEGER NOT NULL REFERENCES email_type(email_type_id),
  from_email_id INTEGER NOT NULL,
  to_email_id INTEGER NOT NULL,
  email_uuid CHAR(32) NOT NULL,
  email_data TEXT NOT NULL,
  send_dttm TIMESTAMP NOT NULL,
  claimed_dttm TIMESTAMP DEFAULT NULL,
  sent_dttm TIMESTAMP DEFAULT NULL,
  deliver_dttm TIMESTAMP DEFAULT NULL,
  open_dttm TIMESTAMP DEFAULT NULL,
  click_dttm TIMESTAMP DEFAULT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  PRIMARY KEY (email_tracking_id),
  UNIQUE (email_uuid)
);
CREATE INDEX ON email_tracking(send_dttm, sent_dttm);

CREATE TRIGGER update_dttm BEFORE UPDATE ON email_type FOR EACH ROW EXECUTE PROCEDURE update_dttm();
CREATE TRIGGER update_dttm BEFORE UPDATE ON email_tracking FOR EACH ROW EXECUTE PROCEDURE update_dttm();

INSERT INTO email_type (email_type_name, template_name, txnl_ind, bulk_ind) VALUES ('Welcome', 'welcome', TRUE, FALSE);
