CREATE TABLE monitor (
  monitor_id bigint NOT NULL AUTO_INCREMENT,
  monitor_host varchar(80) COLLATE utf8_unicode_ci NOT NULL,
  monitor_cmd varchar(500) NOT NULL,
  monitor_stdout MEDIUMTEXT NOT NULL,
  monitor_stderr MEDIUMTEXT NOT NULL,
  monitor_status INT NOT NULL,
  create_dttm timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  delete_dttm datetime DEFAULT NULL,
  PRIMARY KEY (monitor_id),
  KEY monitor_host (monitor_host),
  KEY monitor_date (create_dttm)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;
