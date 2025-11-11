# Query and performance optimizations:


## Bundle 
CREATE TABLE IF NOT EXISTS federates_with_by_trust_domain (
  trust_domain text,
  entry_id     text,
  PRIMARY KEY (trust_domain, entry_id)
);

Write to both federates_with and federates_with_by_trust_domain on entry create/update, and then in DeleteBundle(..., Restrict) you can

## Registration Entries

CREATE TABLE IF NOT EXISTS reg_selectors_index (
  selector_type  text,
  selector_value text,
  entry_id       text,
  PRIMARY KEY ((selector_type, selector_value), entry_id)
);

CREATE TABLE IF NOT EXISTS federates_with_by_trust_domain (
  trust_domain text,
  entry_id     text,
  PRIMARY KEY ((trust_domain), entry_id)
);
