redef Intel::read_files += {
	"/YURT/feeds/analyst1/feed1.tsv", #
	"/YURT/feeds/analyst1/remove.tsv", # REMOVED
	"/YURT/feeds/analyst1/whitelist.tsv", # WHITELISTED
};

@load frameworks/intel/do_notice
@load frameworks/intel/seen
@load frameworks/intel/removal
@load frameworks/intel/whitelist

# handle this failure
# Reporter::WARNING       /YURT/feeds/BRO-feeds/analyst1/feed1.tsv/Input::READER_ASCII:
# Init: cannot open /YURT/feeds/BRO-feeds/analyst1/feed1.tsv      (empty)

module Intel;

redef enum Notice::Type += { Analyst1ReadFail, };

event reporter_warning(t: time, msg: string, location: string)
	{
	if ( /analyst1.*\/Input::READER_ASCII:/ in msg )
		{
		NOTICE([ $note=Intel::Analyst1ReadFail, $msg=fmt("%s", msg) ]);
		}
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == Intel::Analyst1ReadFail )
		{
		add n$actions[Notice::ACTION_EMAIL];
		}
	}
