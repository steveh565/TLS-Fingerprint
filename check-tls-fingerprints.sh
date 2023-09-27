#!/bin/bash

# Check /var/log/ltm for new TLS Fingerprints
for i in `grep FingerprintDB /var/log/ltm |cut -d : -f 8 | sort | uniq`; do (
    ### do something ###
    echo "TLS Fingerprint: $i"
) done;
