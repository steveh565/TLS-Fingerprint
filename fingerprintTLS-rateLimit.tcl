when RULE_INIT {
    # Default rate to limit requests
    set static::maxRate 15
    # Default rate to
    set static::warnRate 12
    # During this many seconds
    set static::timeout 1
}
when CLIENT_ACCEPTED {
    ## Collect the TCP payload
    TCP::collect
}
when CLIENT_DATA {
    #debug flag - set to 1 for more logging
    set debug 0
    
    ## Get the TLS packet type and versions
    if { ! [info exists rlen] } {
        ## We actually only need the recort type (rtype), record length (rlen) handshake type (hs_type) and 'inner' SSL version (inner_sslver) here
        ## But it's easiest to parse them all out of the payload along with the bytes we don't need (outer_sslver & rilen)
        binary scan [TCP::payload] cSScH6S rtype outer_sslver rlen hs_type rilen inner_sslver

        if { ( ${rtype} == 22 ) and ( ${hs_type} == 1 ) } {
            ## This is a TLS ClientHello message (22 = TLS handshake, 1 = ClientHello)
            ## Call the fingerprintTLS proc
            set ja3_fingerprint [call fingerprintTLS-proc::fingerprintTLS [TCP::payload] ${rlen} ${inner_sslver}]
            binary scan [md5 ${ja3_fingerprint}] H* ja3_digest

            if {$debug} { log local0. "TLSfingerprint: [IP::client_addr]:[TCP::client_port] ja3 ${ja3_fingerprint}->${ja3_digest}" }

            #check if fingerprint matches a known malicious fingerprint, if yes, drop connection
            if {[class match ${ja3_fingerprint} equals allowed_TLSfingerprintdb]} {
                if {$debug} { log local0. "TLSfingerprint: ALLOW known approved fingerprint $ja3_fingerprint" }
            } elseif {[class match ${ja3_fingerprint} equals malicious_TLSfingerprintdb]} {
                log local0. "TLSfingerprint: ALERT - DROP [IP::client_addr]:[TCP::client_port] - known malicious fingerprint $ja3_fingerprint"
                drop
                return
            } else {
                #use generated digest of the signature for rate limiting
                set suspicious_fingerprint ${ja3_digest}
                #rate limit fingerprint
                #Increment and Get the current request count bucket
                #monitor an unrecognized fingerprint and rate limit it
                set currentCount [table incr -mustexist "Count_[IP::client_addr]_${suspicious_fingerprint}"]
                if { $currentCount eq "" } {
                    # Initialize a new request count bucket
                    table set "Count_[IP::client_addr]_${suspicious_fingerprint}" 1 indef $static::timeout
                    set currentCount 1
                }

                # Actually check fingerprint for being over limit
                if { $currentCount >= $static::maxRate } {
                    log local0. "TLSfingerprint: ALERT - [IP::client_addr]_${suspicious_fingerprint} r/s ${currentCount} exceeded ${static::maxRate} r/s. Action: DROP. FingerprintDB: ${ja3_fingerprint}"
                    drop
                    return
                }
                if { $currentCount > $static::warnRate } {
                    if {$debug} { log local0. "WARNING: fingerprint:[IP::client_addr]_${suspicious_fingerprint} exceeded ${static::warnRate} requests per second. Will reject at ${static::maxRate}. Current requests: ${currentCount}." }
                } else {
                    if {$debug} { log local0. "TLSfingerprint: fingerprint:[IP::client_addr]_${suspicious_fingerprint}: currentCount: ${currentCount}" }
                }
            }
        }
    }

    # Collect the rest of the record if necessary
    if { [TCP::payload length] < $rlen } {
        TCP::collect $rlen
    }

    ## Release the paylaod
    TCP::release
}