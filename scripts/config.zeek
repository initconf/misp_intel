module Intel::MISP;

redef Intel::MISP::feed_dir = "/home/bro/zeek-cpp/packages/misp_intel/scripts/feeds/" ;

redef Intel::read_files += {
        fmt("%s/misp-lbl-whitelist.txt", Intel::MISP::feed_dir),
        fmt("%s/misp-domain.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-hostname.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-ip-dst.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-ip-src.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-ja3-fingerprint-md5.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-md5.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-sha1.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-sha256.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-sha512.intel", Intel::MISP::feed_dir),
        fmt("%s/misp-url.intel", Intel::MISP::feed_dir),
};

