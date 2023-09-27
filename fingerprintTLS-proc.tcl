## Library-Rule

## JA3 TLS Fingerprint Procedure #################
##
## Author: Aaron Brailsford, 06/2020
## Based on the TLS Fingerprinting iRule by Kevin Stewart @ https://devcentral.f5.com/s/articles/tls-fingerprinting-a-method-for-identifying-a-tls-client-without-decrypting-24598
## Derived from Lee Brotherston's "tls-fingerprinting" project @ https://github.com/LeeBrotherston/tls-fingerprinting
## Purpose: to identify the user agent based on unique characteristics of the TLS ClientHello message
## Input:
##   Full TCP payload collected in CLIENT_DATA event of a TLS handshake ClientHello message
##   Record length (rlen)
##   TLS inner version (sslversion)
##############################################
proc fingerprintTLS { payload rlen sslversion } {
  ## The first 43 bytes of a ClientHello message are the record type, TLS versions, some length values and the
  ## handshake type. We should already know this stuff from the calling iRule. We're also going to be walking the
  ## packet, so the field_offset variable will be used to track where we are.
  set field_offset 43

  ## The first value in the payload after the offset is the session ID, which may be empty. Grab the session ID length
  ## value and move the field_offset variable that many bytes forward to skip it.
  binary scan ${payload} @${field_offset}c sessID_len
  set field_offset [expr {${field_offset} + 1 + ${sessID_len}}]

  ## The next value in the payload is the ciphersuite list length (how big the ciphersuite list is.
  binary scan ${payload} @${field_offset}S cipherList_len

  ## Now that we have the ciphersuite list length, let's offset the field_offset variable to skip over the length (2) bytes
  ## and go get the ciphersuite list.
  set field_offset [expr {${field_offset} + 2}]
  binary scan ${payload} @${field_offset}S[expr {${cipherList_len} / 2}] cipherlist_decimal

  ## Next is the compression method length and compression method. First move field_offset to skip past the ciphersuite
  ## list, then grab the compression method length. Then move field_offset past the length (2)
  ## Finally, move field_offset past the compression method bytes.
  set field_offset [expr {${field_offset} + ${cipherList_len}}]
  binary scan ${payload} @${field_offset}c compression_len
  set field_offset [expr {${field_offset} + 1}]
  set field_offset [expr {${field_offset} + ${compression_len}}]

  ## We should be in the extensions section now, so we're going to just run through the remaining data and
  ## pick out the extensions as we go. But first let's make sure there's more record data left, based on
  ## the current field_offset vs. rlen.
  if { [expr {${field_offset} < ${rlen}}] } {
    ## There's extension data, so let's go get it. Skip the first 2 bytes that are the extensions length
    set field_offset [expr {${field_offset} + 2}]

    ## Make a variable to store the extension types we find
    set extensions_list ""

    ## Pad rlen by 1 byte
    set rlen [expr {${rlen} + 1}]

    while { [expr {${field_offset} <= ${rlen}}] } {
      ## Grab the first 2 bytes to determine the extension type
      binary scan ${payload} @${field_offset}S ext
      set ext [expr {$ext & 0xFFFF}]

      ## Store the extension in the extensions_list variable
      lappend extensions_list ${ext}

      ## Increment field_offset past the 2 bytes of the extension type
      set field_offset [expr {${field_offset} + 2}]

      ## Grab the 2 bytes of extension lenth
      binary scan ${payload} @${field_offset}S ext_len

      ## Increment field_offset past the 2 bytes of the extension length
      set field_offset [expr {${field_offset} + 2}]

      ## Look for specific extension types in case these need to increment the field_offset (and because we need their values)
      switch $ext {
        "11" {
          ## ec_point_format - there's another 1 byte after length
          ## Grab the extension data
          binary scan ${payload} @[expr {${field_offset} + 1}]s ext_data
          set ec_point_format ${ext_data}
        }
        "10" {
          ## elliptic_curves - there's another 2 bytes after length
          ## Grab the extension data
          binary scan ${payload} @[expr {${field_offset} + 2}]S[expr {(${ext_len} - 2) / 2}] ext_data
          set elliptic_curves ${ext_data}
        }
        default {
          ## Grab the otherwise unknown extension data
          binary scan ${payload} @${field_offset}H[expr {${ext_len} * 2}] ext_data
        }
      }

      ## Increment the field_offset past the extension data length. Repeat this loop until we reach rlen (the end of the payload)
      set field_offset [expr {${field_offset} + ${ext_len}}]
    }
  }

  ## Now let's compile all of that data.
  ## The cipherlist values need masking with 0xFFFF to return the unsigned integers we need
  foreach cipher $cipherlist_decimal {
   lappend cipd [expr {$cipher & 0xFFFF}]
  }
  set cipd_str [join $cipd "-"]
  if { ( [info exists extensions_list] ) and ( ${extensions_list} ne "" ) } { set exte [join ${extensions_list} "-"] } else { set exte "" }
  if { ( [info exists elliptic_curves] ) and ( ${elliptic_curves} ne "" ) } { set ecur [join ${elliptic_curves} "-"] } else { set ecur "" }
  if { ( [info exists ec_point_format] ) and ( ${ec_point_format} ne "" ) } { set ecfp [join ${ec_point_format} "-"] } else { set ecfp "" }

  set ja3_str "${sslversion},${cipd_str},${exte},${ecur},${ecfp}"
  ## binary scan [md5 ${ja3_str}] H* ja3_digest

  ## Un-comment this line to display the fingerprint string in the LTM log for troubleshooting
  #log local0. "ja3 = ${ja3_str}"

  return ${ja3_str}
}