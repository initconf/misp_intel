module Intel;

@load frameworks/intel/do_notice
@load frameworks/intel/seen
@load frameworks/intel/removal
@load frameworks/intel/whitelist

redef Intel::read_files += { "/YURT/feeds/MISP/LBL/misp-lbl-whitelist.txt",
    "/YURT/feeds/MISP/LBL/misp-domain.intel",
    "/YURT/feeds/MISP/LBL/misp-hostname.intel",
    "/YURT/feeds/MISP/LBL/misp-ip-dst.intel",
    "/YURT/feeds/MISP/LBL/misp-ip-src.intel",
    "/YURT/feeds/MISP/LBL/misp-ja3-fingerprint-md5.intel",
    "/YURT/feeds/MISP/LBL/misp-md5.intel",
    "/YURT/feeds/MISP/LBL/misp-sha1.intel",
    "/YURT/feeds/MISP/LBL/misp-sha256.intel",
    "/YURT/feeds/MISP/LBL/misp-sha512.intel",
    "/YURT/feeds/MISP/LBL/misp-url.intel",  };

# handle this failure
redef enum Notice::Type += { MISPReadFail, };

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
