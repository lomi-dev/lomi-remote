-- Public pre-token assertion only: no rows, NOTICEs, identifiers or credentials.
DO $private_policy$
BEGIN
 IF current_setting('log_destination') IS DISTINCT FROM 'stderr'
 OR current_setting('logging_collector') IS DISTINCT FROM 'off'
 OR current_setting('log_statement') IS DISTINCT FROM 'none'
 OR current_setting('log_min_error_statement') IS DISTINCT FROM 'panic'
 OR current_setting('log_min_messages') IS DISTINCT FROM 'panic'
 OR current_setting('log_error_verbosity') IS DISTINCT FROM 'terse'
 OR current_setting('log_min_duration_statement') IS DISTINCT FROM '-1'
 OR current_setting('log_min_duration_sample') IS DISTINCT FROM '-1'
 OR current_setting('log_transaction_sample_rate') IS DISTINCT FROM '0'
 OR current_setting('log_parameter_max_length') IS DISTINCT FROM '0'
 OR current_setting('log_parameter_max_length_on_error') IS DISTINCT FROM '0'
 OR current_setting('client_encoding') IS DISTINCT FROM 'UTF8'
 OR current_user IS DISTINCT FROM 'e2_owner'
 OR session_user IS DISTINCT FROM 'e2_owner'
 THEN
  RAISE EXCEPTION USING ERRCODE='P0001', MESSAGE='private policy rejected';
 END IF;
END $private_policy$;
