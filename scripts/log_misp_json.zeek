module Intel::MISP;

export {
	redef enum Log::ID += { Intel::MISP::LOG };

	# Pattern of intel sources to exclude from misp.log.
	# Matches are checked against each source string on the intel item.
	const ignore_sources: pattern = /QRishing/ &redef;

	# Minimum byte threshold. Connections where BOTH directions
	# are below this value are suppressed from misp.log.
	const byte_threshold: count = 4096 &redef;

	type Detection: record {
		connection: string &log &optional;
		ioc_type: Intel::TypeSet &log &optional;
	};

	type format: record {
		ioc: string &log &optional;
		timestamp_rfc3339ns: string &log &optional;
		detection: string &log &optional;
		ioc_type: Intel::Type &log &optional;
		uid: string &log &optional;
		url: string &log &default="";
		sources: set[string] &optional;
	};

	global Intel::MISP::log: event(rec: Intel::MISP::format);
	global Intel::MISP::to_json: event(rec: Intel::Info);
	global Intel::MISP::add_uid: event(rec: Intel::Info);

	# In-memory table of intel matches keyed by connection UID.
	# Entries are enriched with full connection data on teardown.
	global misp: table[string] of Intel::Info &read_expire=6 hrs;
}

# Convert a Zeek time value to RFC3339 nanosecond format.
function to_rfc3339ns(t: time): string
	{
	local tt = fmt("%s", t);
	local b = split_string(tt, /\./);
	local nanoseconds = b[1];
	local rfc3339ns = fmt("%s.%s000Z",
	    strftime("%Y-%m-%dT%H:%M:%S", t), nanoseconds);
	return rfc3339ns;
	}

# Convert a byte count to a human-readable string.
function bytes_to_human(num: double): string
	{
	if ( num < 0.0 )
		return "0.00B";

	if ( num < 1024.0 )
		return fmt("%.2fB", num);
	if ( num < 1048576.0 )
		return fmt("%.2fKB", num / 1024.0);
	if ( num < 1073741824.0 )
		return fmt("%.2fMB", num / 1048576.0);
	if ( num < 1099511627776.0 )
		return fmt("%.2fGB", num / 1073741824.0);
	if ( num < 1125899906842624.0 )
		return fmt("%.2fTB", num / 1099511627776.0);

	return fmt("%.2fPB", num / 1125899906842624.0);
	}

# Log policy hook: suppress records whose sources all match ignore patterns.
hook Intel::MISP::log_policy(rec: Intel::MISP::format, id: Log::ID,
    filter: Log::Filter)
	{
	local dominated = T;

	for ( source in rec$sources )
		{
		if ( ignore_sources !in source )
			{
			dominated = F;
			break;
			}
		}

	if ( dominated )
		break;
	}

# Event handler: write to misp.log after source filtering.
event Intel::MISP::log(rec: Intel::MISP::format)
	{
	local should_ignore = F;

	for ( source in rec$sources )
		{
		if ( ignore_sources in source )
			{
			should_ignore = T;
			break;
			}
		}

	if ( ! should_ignore )
		Log::write(Intel::MISP::LOG, rec);
	}

# Cache intel match by connection UID for later enrichment.
event Intel::MISP::add_uid(rec: Intel::Info)
	{
	if ( rec$uid !in misp )
		misp[rec$uid] = rec;
	}

# Triggered when Zeek logs an intel match. Stores the record for
# enrichment when the connection is torn down.
event Intel::log_intel(rec: Intel::Info)
	{
	@if ( Cluster::is_enabled() )
		Broker::publish(Cluster::worker_topic, Intel::MISP::add_uid, rec);
	@else
		event Intel::MISP::add_uid(rec);
	@endif

	if ( rec$uid !in misp )
		misp[rec$uid] = rec;

	log_reporter(fmt("Inside Intel::log_intel %s", misp[rec$uid]));
	}

# Debug hook for Intel::match events.
event Intel::match(s: Intel::Seen, items: set[Intel::Item]) &priority=-10
	{
	log_reporter(fmt("Intel::match: %s, %s", s, items));
	}

# On connection teardown, enrich the cached intel record with full
# connection metadata and emit the JSON log entry.
event connection_state_remove(c: connection)
	{
	if ( c$uid !in misp )
		return;

	log_reporter("inside conn_state_remove");

	misp[c$uid]$seen$conn = c;

	@if ( Cluster::is_enabled() )
		Broker::publish(Cluster::manager_topic, Intel::MISP::to_json, misp[c$uid]);
	@else
		event Intel::MISP::to_json(misp[c$uid]);
	@endif

	delete misp[c$uid];
	}

# Format the enriched intel record into the JSON schema and emit the log event.
event Intel::MISP::to_json(rec: Intel::Info)
	{
	log_reporter("Inside Intel::MISP::to_json");

	local orig = rec$id$orig_h;
	local resp = rec$id$resp_h;

	local bytes_up = rec$seen$conn$orig$num_bytes_ip;
	local bytes_down = rec$seen$conn$resp$num_bytes_ip;

	# Condition 1: Stop if the originator is not local.
	if ( orig !in Site::local_nets )
		return;

	# Condition 2: Stop if the destination is also local (internal-to-internal).
	if ( resp in Site::local_nets )
		return;

	# Condition 3: Stop if BOTH upload and download are below threshold.
	if ( bytes_up < byte_threshold && bytes_down < byte_threshold )
		return;

	# Build defanged IP representation for safe display in tickets/alerts.
	# Per Romain's spec (2024/11/12):
	# "detection": "*TCP traffic*: `131[.]243.162.251:64990` -> ..."
	local sip: vector of string;
	local dip: vector of string;

	if ( is_v6_addr(orig) )
		{
		sip = split_string1(fmt("%s", orig), /\:/);
		dip = split_string1(fmt("%s", resp), /\:/);
		}
	else
		{
		sip = split_string1(fmt("%s", orig), /\./);
		dip = split_string1(fmt("%s", resp), /\./);
		}

	local sport = fmt("%d", rec$id$orig_p);
	local dport = fmt("%d", rec$id$resp_p);

	local proto = to_upper(fmt("%s", get_port_transport_proto(rec$id$orig_p)));
	proto = fmt("*%s Traffic*:", proto);

	local s: format;
	s$ioc = rec$seen$indicator;
	s$timestamp_rfc3339ns = to_rfc3339ns(rec$ts);
	s$ioc_type = rec$seen$indicator_type;
	s$uid = rec$uid;
	s$sources = rec$sources;

	if ( is_v6_addr(orig) )
		{
		s$detection = fmt(
		    "%s: `%s[:]%s:%s` -> `%s[:]%s:%s` [%s]\n*Total bytes*: %s up/%s down",
		    proto, sip[0], sip[1], sport, dip[0], dip[1], dport,
		    rec$seen$where, bytes_to_human(bytes_up),
		    bytes_to_human(bytes_down));
		}
	else
		{
		s$detection = fmt(
		    "%s: `%s[.]%s:%s` -> `%s[.]%s:%s` [%s]\n*Total bytes*: %s up/%s down",
		    proto, sip[0], sip[1], sport, dip[0], dip[1], dport,
		    rec$seen$where, bytes_to_human(bytes_up),
		    bytes_to_human(bytes_down));
		}

	event Intel::MISP::log(s);
	}

# Initialize the MISP JSON log stream.
event zeek_init()
	{
	Log::create_stream(Intel::MISP::LOG, [$columns=Intel::MISP::format]);

	local f = Log::get_filter(Intel::MISP::LOG, "default");
	f$path = "misp";
	f$config = table(["use_json"] = "T",
	    ["JSON::TimestampFormat"] = "JSON::TS_ISO8601");
	f$policy = Intel::MISP::log_policy;

	Log::add_filter(Intel::MISP::LOG, f);
	}
