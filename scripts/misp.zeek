module Intel::MISP;

@load frameworks/intel/do_notice
@load frameworks/intel/seen
@load frameworks/intel/removal
@load frameworks/intel/whitelist

export {
	# Base directory for MISP intel feed files.
	# Redef this to point to your local feed path.
	#const Intel::MISP::feed_dir: string = "/YURT/feeds/MISP/LBL" &redef;
	const Intel::MISP::feed_dir: string = "" &redef;
}

# Notice for MISP intel feed read failures.
redef enum Notice::Type += { ReadFail };

event reporter_error(t: time, msg: string, location: string)
	{
	if ( /MISP.*\/Input::READER_ASCII:/ in msg )
		{
		NOTICE([$note=Intel::MISP::ReadFail, $identifier=cat(msg),
		    $suppress_for=1hrs, $msg=fmt("%s", msg)]);
		}
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == Intel::MISP::ReadFail )
		{
		add n$actions[Notice::ACTION_EMAIL];
		}
	}
