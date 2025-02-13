module Intel::MISP;

export {
	redef enum Log::ID += { Intel::MISP::LOG };

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
	#global Intel::MISP::log_policy: hook(rec: Intel::MISP::format, id: Log::ID, filter: Log::Filter);
}

function to_rfc3339ns(t: time): string
	{
	local tt = fmt("%s", t);
	local b = split_string(tt, /\./);
	local nanoseconds = b[1];
	local rfc3339ns = fmt("%s.%s000Z", strftime("%Y-%m-%dT%H:%M:%S", t),
	    nanoseconds);
	return rfc3339ns;
	}

function bytes_to_human(num: double): string
	{
	if ( num > 0 && num <= 1024 )
		return fmt("%.2fB", num);
	if ( num > 1025 && num <= 1048576 )
		return fmt("%.2fKB", num / 1024);
	if ( num > 1048577 && num <= 1073741824 )
		return fmt("%.2fMB", num / 1048576);
	if ( num > 1073741824 + 1 && num <= 1099511627776 )
		return fmt("%.2fGB", num / 1073741824);
	if ( num > 1099511627776 + 1 && num <= 1125899906842624 )
		return fmt("%.2fTB", num / 1099511627776);

	return "B";
	}

hook Intel::MISP::log_policy(rec: Intel::MISP::format, id: Log::ID,
    filter: Log::Filter)
	{
	local ignore_sources: pattern = /Phishing|PhishingToday|IJC3|ijc3/;

	for ( source in rec$sources )
		{
		if ( ! ( ignore_sources in source ) )
			{
			break;
			}
		}
	}

event Intel::MISP::log(rec: Intel::MISP::format)
	{
	local ignore_sources: pattern = /QRishing/;
	local dont_log = F;

	for ( source in rec$sources )
		if ( ignore_sources in source )
			dont_log = T;

	if ( ! dont_log )
		Log::write(Intel::MISP::LOG, rec);
	}

event Intel::log_intel(rec: Intel::Info)
	{
	local s: format;
	local d: Detection;

	# below is 'twisting it' but oh well,
	# per romain ask 2024/11/12 - Ash
	# "detection": "*TCP traffic*: `13[.]23.162.251:64990` -> `17[.]20.2.5:443` [Conn::IN_RESP]\n*Total bytes*: 2Mb up/1MB down"

	local sip = split_string1(fmt("%s", rec$id$orig_h), /\./);
	local dip = split_string1(fmt("%s", rec$id$resp_h), /\./);
	local sport = fmt("%d", rec$id$orig_p);
	local dport = fmt("%d", rec$id$resp_p);
	local bytes_up = rec$seen$conn$orig$num_bytes_ip;
	local bytes_down = rec$seen$conn$resp$num_bytes_ip;
	local proto = to_upper(fmt("%s", get_port_transport_proto(rec$id$orig_p)));
	proto = fmt("*%s Traffic*:", proto);

	s$ioc = rec$seen$indicator;
	s$timestamp_rfc3339ns = to_rfc3339ns(rec$ts);
	#s$detection = d;
	s$detection = fmt(
	    "%s: `%s[.]%s:%s` -> `%s[.]%s:%s` [%s]\n*Total bytes*: %s up/%s down",
	    proto, sip[0], sip[1], sport, dip[0], dip[1], dport, rec$seen$where,
	    bytes_to_human(bytes_up), bytes_to_human(bytes_down));

	s$ioc_type = rec$seen$indicator_type;
	s$uid = rec$uid;
	s$sources = rec$sources;

	event Intel::MISP::log(s);
	}

event zeek_init()
	{
	Log::create_stream(Intel::MISP::LOG, [ $columns=Intel::MISP::format ]);

	local f = Log::get_filter(Intel::MISP::LOG, "default");
	f$path = "misp";
	f$config = table([ "use_json" ] = "T", [ "JSON::TimestampFormat" ] =
	    "JSON::TS_ISO8601");
	f$policy = Intel::MISP::log_policy;

	Log::add_filter(Intel::MISP::LOG, f);
	}
