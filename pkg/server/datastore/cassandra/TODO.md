# Query and performance optimizations:


## Bundle 
CREATE TABLE IF NOT EXISTS federates_with_by_trust_domain (
  trust_domain text,
  entry_id     text,
  PRIMARY KEY (trust_domain, entry_id)
);

Write to both federates_with and federates_with_by_trust_domain on entry create/update, and then in DeleteBundle(..., Restrict) you can: