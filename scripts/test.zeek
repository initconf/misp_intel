redef Intel::read_files += {
#"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-lbl-whitelist.txt",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/hits.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-domain.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-hostname.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-ip-dst.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-ip-src.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-ja3-fingerprint-md5.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-md5.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-sha1.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-sha256.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-sha512.intel",
	"/usr/local/zeek-cpp/packages/MISP_INTEL/scripts/feeds/misp-url.intel",
};

@load frameworks/intel/do_notice
@load frameworks/intel/seen
@load frameworks/intel/removal
@load frameworks/intel/whitelist

# handle this failure
# Reporter::WARNING       /YURT/feeds/BRO-feeds/analyst1/7672-aisSensorTaskings.tsv/Input::READER_ASCII:
# Init: cannot open /YURT/feeds/BRO-feeds/analyst1/7672-aisSensorTaskings.tsv      (empty)

module Intel;

#redef enum Notice::Type += { MISPReadFail, };

event reporter_error(t: time, msg: string, location: string)
	{
	if ( /MISP.*\/Input::READER_ASCII:/ in msg )
		{
		NOTICE([ $note=Intel::MISPReadFail, $identifier=cat(msg), $suppress_for=1hrs,
		    $msg=fmt("%s", msg) ]);
		}
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == Intel::MISPReadFail )
		{
		add n$actions[Notice::ACTION_EMAIL];
		}
	}
