package sqlguard

import "strings"

// allowedFunctions is the fixed function allowlist (owner decision #11):
// side-effect-free built-ins only, not configurable in M1. Anything touching
// files, the network, sleeping, locks, settings, sequences or other databases
// (pg_sleep, pg_read_file, dblink, lo_import, set_config, nextval,
// pg_advisory_lock, ...) is absent and therefore refused. Names match
// unqualified or pg_catalog-qualified; any other schema is refused.
var allowedFunctions = toSet(`
	lower upper length char_length character_length octet_length bit_length
	substr substring trim btrim ltrim rtrim replace translate overlay
	concat concat_ws left right position strpos split_part initcap repeat reverse
	lpad rpad starts_with format md5 sha256 encode decode to_hex ascii chr
	quote_ident quote_literal quote_nullable
	regexp_replace regexp_match regexp_matches regexp_like regexp_count regexp_instr regexp_substr
	regexp_split_to_array regexp_split_to_table
	abs ceil ceiling floor round trunc mod power pow sqrt cbrt sign div exp ln log log10
	greatest least width_bucket pi degrees radians
	now statement_timestamp transaction_timestamp clock_timestamp
	date_trunc date_part extract age date_bin
	make_date make_time make_timestamp make_timestamptz make_interval
	to_char to_date to_timestamp to_number timezone
	justify_days justify_hours justify_interval isfinite
	count sum avg min max array_agg string_agg bool_and bool_or every
	stddev stddev_pop stddev_samp variance var_pop var_samp corr
	percentile_cont percentile_disc mode
	row_number rank dense_rank percent_rank cume_dist ntile
	lag lead first_value last_value nth_value
	json_build_object jsonb_build_object json_build_array jsonb_build_array
	json_agg jsonb_agg json_object_agg jsonb_object_agg
	to_json to_jsonb row_to_json array_to_json json_object jsonb_object
	json_extract_path json_extract_path_text jsonb_extract_path jsonb_extract_path_text
	json_array_elements json_array_elements_text jsonb_array_elements jsonb_array_elements_text
	json_array_length jsonb_array_length json_each json_each_text jsonb_each jsonb_each_text
	json_object_keys jsonb_object_keys json_typeof jsonb_typeof
	jsonb_set jsonb_set_lax jsonb_insert jsonb_strip_nulls json_strip_nulls jsonb_pretty
	jsonb_path_query jsonb_path_query_array jsonb_path_query_first jsonb_path_exists jsonb_path_match
	array_length array_lower array_upper array_ndims array_dims array_position array_positions
	array_remove array_replace array_append array_prepend array_cat array_to_string
	string_to_array string_to_table unnest cardinality generate_series generate_subscripts
	to_tsvector to_tsquery plainto_tsquery phraseto_tsquery websearch_to_tsquery ts_rank ts_rank_cd ts_headline
	num_nulls num_nonnulls pg_typeof
	gen_random_uuid uuid_generate_v4 random
`)

// aggregateFunctions are the allowlisted aggregates: called without OVER
// they collapse rows, so a read using one has no row identity.
var aggregateFunctions = toSet(`
	count sum avg min max array_agg string_agg bool_and bool_or every
	stddev stddev_pop stddev_samp variance var_pop var_samp corr
	percentile_cont percentile_disc mode
	json_agg jsonb_agg json_object_agg jsonb_object_agg
`)

func toSet(words string) map[string]bool {
	set := map[string]bool{}
	for _, w := range strings.Fields(words) {
		set[w] = true
	}
	return set
}

// functionAllowed reports whether a called function name, as written in the
// statement (optionally schema-qualified), is on the allowlist.
func functionAllowed(name string) bool {
	return allowedFunctions[strings.TrimPrefix(name, "pg_catalog.")]
}
