module Intel::Analyst1;

@load frameworks/intel/do_notice
@load frameworks/intel/seen
@load frameworks/intel/removal
@load frameworks/intel/whitelist

export {
	# Base directory for Analyst1 AIS sensor tasking feeds.
	# Redef this to point to your local feed path.
	const Analyst1::feed_dir: string = "/usr/local/feeds/analyst1" &redef;
}

redef Intel::read_files += {
	fmt("%s/a1-aisSensorTaskings.tsv", Analyst1::feed_dir),  #  Critical
	fmt("%s/a2-aisSensorTaskings.tsv", Analyst1::feed_dir),  #  Medium
	fmt("%s/remove.tsv", Analyst1::feed_dir),                  # Removal list
	fmt("%s/whitelist.tsv", Analyst1::feed_dir),               # Whitelist
};

# Notice for Analyst1 intel feed read failures.
redef enum Notice::Type += { Intel::Analyst1::ReadFail };

event reporter_warning(t: time, msg: string, location: string)
	{
	if ( /analyst1.*\/Input::READER_ASCII:/ in msg )
		{
		NOTICE([$note=Intel::Analyst1::ReadFail,
		    $msg=fmt("%s", msg)]);
		}
	}

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == Intel::Analyst1::ReadFail )
		{
		add n$actions[Notice::ACTION_EMAIL];
		}
	}
