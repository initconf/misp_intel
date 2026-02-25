module Intel::MISP;

export {
	# Enable debug logging. When T, debug messages are printed
	# (non-cluster) and sent via reporter_info events.
	const DEBUG: bool = F &redef;

	global log_reporter: function(msg: string);
}

function log_reporter(msg: string)
	{
	if ( ! DEBUG )
		return;

	@if ( ! Cluster::is_enabled() )
		print fmt("%s", msg);
	@endif

	event reporter_info(network_time(), msg, peer_description);
	}
