CREATE TABLE cache (
  cache_id SERIAL NOT NULL,
  create_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  update_dttm TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  delete_dttm TIMESTAMP DEFAULT NULL,
  cache_key VARCHAR(200) NOT NULL,
  cache_json JSON NOT NULL,
  cache_expiry TIMESTAMP NOT NULL,
  PRIMARY KEY (cache_key),
  UNIQUE(cache_id),
  KEY cache_expiry (cache_expiry)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
