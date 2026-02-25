# Test: Domain indicator matching via inline .intel file.
# Loads a single MISP domain indicator (1drv.ms) and replays int.pcap.
# Expects misp.log entries for connections whose X509 cert matched 1drv.ms.

# --- Inline feed files (tab-separated) ---

# @TEST-START-FILE feeds/misp-domain.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
1drv.ms	Intel::DOMAIN	MISP	test domain indicator	-
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-hostname.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-ip-dst.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-ip-src.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-ja3-fingerprint-md5.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-md5.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-sha1.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-sha256.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-sha512.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-url.intel
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/misp-lbl-whitelist.txt
#fields	indicator	indicator_type	meta.whitelist_source
# @TEST-END-FILE

# @TEST-START-FILE feeds/7712-aisSensorTaskings.tsv
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/7713-aisSensorTaskings.tsv
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/remove.tsv
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-START-FILE feeds/whitelist.tsv
#fields	indicator	indicator_type	meta.source	meta.desc	meta.url
# @TEST-END-FILE

# @TEST-EXEC: zeek -C -r $TRACES/int.pcap ../../../scripts %INPUT
# @TEST-EXEC: btest-diff misp.log

redef Intel::read_files = {
	"./feeds/misp-lbl-whitelist.txt",
	"./feeds/misp-domain.intel",
	"./feeds/misp-hostname.intel",
	"./feeds/misp-ip-dst.intel",
	"./feeds/misp-ip-src.intel",
	"./feeds/misp-ja3-fingerprint-md5.intel",
	"./feeds/misp-md5.intel",
	"./feeds/misp-sha1.intel",
	"./feeds/misp-sha256.intel",
	"./feeds/misp-sha512.intel",
	"./feeds/misp-url.intel",
	"./feeds/7712-aisSensorTaskings.tsv",
	"./feeds/7713-aisSensorTaskings.tsv",
	"./feeds/remove.tsv",
	"./feeds/whitelist.tsv",
};
redef Site::local_nets += { 10.1.0.0/16, 10.2.0.0/16 };

# Remove RFC 5737 TEST-NET-2 from local_nets so anonymised remote
# IPs (198.51.100.x) are treated as external by misp.zeek.
event zeek_init() &priority=-10
	{
	delete Site::local_nets[198.51.100.0/24];
	}
