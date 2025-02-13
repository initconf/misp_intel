redef Intel::read_files += {
	"/YURT/feeds/analyst1/7671-aisSensorTaskings.tsv", # CRITICAL
	"/YURT/feeds/analyst1/7672-aisSensorTaskings.tsv", # HIGH
	#"/YURT/feeds/analyst1/7673-aisSensorTaskings.tsv", # medium too many FP
	#"/YURT/feeds/analyst1/7674-aisSensorTaskings.tsv", # Low
	#"/YURT/feeds/analyst1/7675-aisSensorTaskings.tsv", # IOC Blocklists
	#"/YURT/feeds/analyst1/7677-aisSensorTaskings.tsv", # PPPO-FPSS Firepower-IPv4
	"/YURT/feeds/analyst1/7678-aisSensorTaskings.tsv", # iJC3 Watchlist
	"/YURT/feeds/analyst1/7679-aisSensorTaskings.tsv", # PPPO-FPSS Email Security
	"/YURT/feeds/analyst1/7680-aisSensorTaskings.tsv", # PPPO-FPSS Firepower-Domains
	"/YURT/feeds/analyst1/7681-aisSensorTaskings.tsv", # PPPO-FPSS Firepower-IPv6
	"/YURT/feeds/analyst1/7682-aisSensorTaskings.tsv", # PPPO FPSS Firepower - URLs
	"/YURT/feeds/analyst1/7683-aisSensorTaskings.tsv", #	PPPO FPSS Firepower - Hashes

	"/YURT/feeds/analyst1/remove.tsv", # REMOVED
	"/YURT/feeds/analyst1/whitelist.tsv", # WHITELISTED
};

@load frameworks/intel/do_notice
@load frameworks/intel/seen
@load frameworks/intel/removal
@load frameworks/intel/whitelist

# handle this failure
# Reporter::WARNING       /YURT/feeds/BRO-feeds/analyst1/7672-aisSensorTaskings.tsv/Input::READER_ASCII:
# Init: cannot open /YURT/feeds/BRO-feeds/analyst1/7672-aisSensorTaskings.tsv      (empty)

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
