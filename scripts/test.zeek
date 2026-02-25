# Test configuration: override feed paths to use local package directory.
# This script is NOT loaded in production (__load__.zeek).
# Use it for local development testing:
#   zeek -C -r trace.pcap scripts scripts/test.zeek

module Intel;

redef MISP::feed_dir = "/usr/local/zeek-cpp/packages/misp_intel/scripts/feeds";

redef Intel::read_files += {
	fmt("%s/hits.intel", MISP::feed_dir),
};
