proc logger { lifecycle tracer message } {
  if { $static::ENABLE_LOGGING != 0 } {
    log local0. "$lifecycle [substr $tracer 0 80] - $message"
  }
}

when RULE_INIT {
  # Define "static" strings to reduce the chance of typos in iRule
  set static::ENABLE_LOGGING 0
  set static::UNKNOWN "unknown"
  set static::ROOT_COOKIE_NAME "VoP_server_root_affinity"
  set static::SCOPED_COOKIE_NAME "VoP_server_scoped_affinity"
  set static::HEADER_VERSE_REQUEST "X-Verse-Request"
  set static::SHIMMER_ID_HEADER "X-Verse-ShimmerS-ID"
}

when CLIENT_ACCEPTED {
  call logger "ACC" "" "New client accepted."
  set retries 0
  set serverNeeded 0
  set retryBasedOnAffinity 0
  set retryOriginalForAuthChallenge 0
  set serverSelected $static::UNKNOWN
  set newDest $static::UNKNOWN
  set mailServerAffinity $static::UNKNOWN
  set lastKnownAuthTarget $static::UNKNOWN
}

#1.a We are in the middle of authenticating against a Domino server.
#  FINAL: target auth server indicted in cookie
#1.b We are NOT in the middle of authentication against a Domino server
#  2.a Servers lookup requests must target a hub server which hosts the domain catalog.
#    FINAL: target the hub server with serverslookup and the domain catalog
#  2.b The request needs to be analyzed deeper
#    3.a Request is pool dependent
#      4.a Host pool already identified and not needing to clear root cookie
#        FINAL: use pool already identified in scoped affinity cookie
#      4.b We already tried a lookup and have identified a target - affinity will be set upon success
#        FINAL: try the pool that was determined from response triggering this "retry"
#      4.c Host pool has NOT been identified yet
#        FINAL: Transform the request and perform a lookup - saving the original URI for retry after analyzing lookup
#    3.b Request is NOT pool dependent
#      FINAL: Send to any mail server w/ verse installed (alt: or pin to the users home cluster)

when HTTP_REQUEST {
  set targetPool [LB::server pool]
  set originalRequest [HTTP::request]
  set requestedURI [HTTP::uri]
  set path [string tolower [HTTP::path]]
  set query [string tolower [HTTP::query]]
  set expectedCookiePath "/"
  set mode $static::UNKNOWN
  # Assume that the request should use the root scoped cookie,
  #   the logged in user's own affinity, unless we are able to
  #   determine that this request is an Archive/Delegation request.
  # If the request is archive or delegation, affinityCookieName will
  #   will be set to #scopedCookieName
  set affinityCookieName $static::ROOT_COOKIE_NAME
  call logger "REQ" $requestedURI "START HTTP_REQUEST"

  # Redirect to /verse if user doesn't specify a path
  if { $path eq "/" } {
    HTTP::respond 301 Location "https://[HTTP::host]/verse$query"
    return
  }
  # In older versions of domino, xhr requests are not always handled (by Domino)
  #   in the manner that Verse expects.
  # See HTTP_RESPONSE to see how the unexpected response code (302) is re-written
  #   to 401 if the request was XHR
  # TODO: link to the specific issue that needed to be resolved
  set xhr 0
  if { ($query contains "&xhr=1") or ($query starts_with "xhr=1") } {
    set xhr 1
  }
  ############################################################################
  # Some POST requests to Verse APIs contain payload data that needs to be
  #   re-sent on a retry.
  # Explicitly "collecting" here in the HTTP_REQUEST will enable us to store
  #   the actual POST request data later during the HTTP_REQUEST_DATA event.
  # More details can be read here:
  #   https://clouddocs.f5.com/api/irules/HTTP__payload.html
  ############################################################################
  set h_method [HTTP::method]
  if { $h_method eq "POST"} {
    if { [HTTP::header exists "Content-Length"] } {
      set content_length [HTTP::header "Content-Length"]
      if { $content_length eq 0 } {
        set collect_length 0
      } elseif { $content_length < 1048577 } {
        set collect_length $content_length
      } else {
        # This is the maximum content-length that can be collected.
        set collect_length 1048577
        call logger "REQ" $requestedURI "content-length '$content_length' exceeds maximum collectable content length of 1048577 "
      }
      if { $content_length > 0 } {
        # Call collect if there is content so that the content is available
        #   during the HTTP_REQUEST_DATA event
        HTTP::collect $collect_length
      }
    }
  }

  set DomAuthTargetCookieExists [HTTP::cookie exists "DomAuthTarget"]
  call logger "REQ" $requestedURI "DomAuthTargetCookieExists: $DomAuthTargetCookieExists"
  if { ($DomAuthTargetCookieExists eq 1) } {
    ##### 1.a We are in the middle of authenticating against a Domino server.
    call logger "REQ" $requestedURI "Request IS part of authentication flow: [HTTP::cookie value "DomAuthTarget"]"
    # Domino authentication must start and end on the same Domino server.
    if { ($DomAuthTargetCookieExists eq 1) } {
      set fields [split [HTTP::cookie value "DomAuthTarget"] "."]
    }
    set authPool [lindex $fields 0]
    set encodedAuthMemberIP [lindex $fields 1]
    set authPoolMemberPort [expr [lindex $fields 2]/256]
    set hexDecodedIP [format %X $encodedAuthMemberIP]
    scan $hexDecodedIP "%2x%2x%2x%2x" l m n o
    set decodedAuthMemberIP "$o.$n.$m.$l"
    pool $authPool member $decodedAuthMemberIP $authPoolMemberPort
    call logger "REQ" $requestedURI "using pool, ip, port: $authPool $decodedAuthMemberIP $authPoolMemberPort"
    set targetPool $authPool
  } else {
    ##### 1.b We are NOT in the middle of authentication against a Domino server
    call logger "REQ" $requestedURI "Request is NOT part of authentication flow"
    if { ([string tolower [HTTP::uri]] contains "/serverslookup") } {
      ##### 2.a Servers lookup requests must target a hub server which hosts the domain catalog.
      call logger "REQ" $requestedURI "Request for /serverlookup must target hub server."
      pool verseproxy_hub
      set targetPool verseproxy_hub
      call logger "REQ" $requestedURI "setting pool to verseproxy_hub for /serverslookup request"
    } else {
      ##### 2.b The request needs to be analyzed deeper
      call logger "REQ" $requestedURI "Request needs to be analyzed more..."
      # Requests made by the Verse client will have an X-Verse-Request header
      # The following types of Verse requests will not contain this header:
      #   - JS resource/bundle requests
      #     - All servers should be running the same version of Verse to avoid
      #       missmatched resources being loaded
      #   - Initial page load/navigation requests made by the browser
      call logger "REQ" $requestedURI "headerIndicatesFromVerse: [HTTP::header exists $static::HEADER_VERSE_REQUEST]"
      # Determine if the request is "scoped" or not
      set isPoolDependentRequest 0
      set targetNSFPath $static::UNKNOWN
      set tentativeNSFPath "[substr [HTTP::path] 0 ".nsf/"].nsf"
      call logger "REQ" $requestedURI "tentativeNSFPath: $tentativeNSFPath"
      if {
          (($path contains ".nsf")
          or ($path contains "/verse/userinfo")
          or ($path contains "/verse/checksession")
          or ($path contains "/verse/userredirectinfo")
          or ($path contains "/verse/ical"))
          and !($tentativeNSFPath contains "Forms9.nsf")
      } {
        set isPoolDependentRequest 1
        # The "scope" attribute's value will be the full path to the nsf in question
        if { ($path contains ".nsf/") } {
          set targetNSFPath $tentativeNSFPath
          set expectedCookiePath $targetNSFPath;
          set affinityCookieName $static::SCOPED_COOKIE_NAME
        }
      }
      call logger "REQ" $requestedURI "isPoolDependentRequest: $isPoolDependentRequest"
      set affinityCookieExists [HTTP::cookie exists $affinityCookieName]
      call logger "REQ" $requestedURI "CORRECT affinityCookieName named \"$affinityCookieName\" exists? $affinityCookieExists"
      if { ($isPoolDependentRequest eq 1) } {
        ##### 3.a Request is pool dependent
        call logger "REQ" $requestedURI "Request is pool dependent" 
        if { ($affinityCookieExists eq 1) } {
          ##### 4.a Host pool already identified
          set mailServerAffinity [HTTP::cookie value $affinityCookieName]
          call logger "REQ" $requestedURI "Host pool already idenfied via nsf-path scoped affinity cookie: $mailServerAffinity" 
          pool $mailServerAffinity
          set targetPool $mailServerAffinity
        } elseif { ($newDest ne $static::UNKNOWN) } {
          #### 4.b We already tried a lookup and have identified a target - affinity will be set upon success
          call logger "REQ" $requestedURI "Performed lookup and identified newDest: $newDest" 
          pool $newDest
          set targetPool $newDest
        } elseif { ($retryOriginalForAuthChallenge ne 1) } {
          ##### 4.c Host pool has NOT been identified yet AND we aren't retrying
          # a request with the intention of returning the replayed request's
          # auth-challenge response.
          call logger "REQ" $requestedURI "Host pool is unknown" 
          set serverNeeded 1
          pool verseproxy_hub
          set targetPool verseproxy_hub
          set lookupURI "/serverslookup"
          if { !($targetNSFPath eq $static::UNKNOWN) } {
            set lookupURI "$lookupURI?nsfpath=[string trim $targetNSFPath "/"]"
          }
          set requestedURI $lookupURI
          HTTP::uri $lookupURI
          call logger "REQ" $requestedURI "Performing lookup request [HTTP::host][HTTP::uri]" 
        } elseif { ($retryOriginalForAuthChallenge eq 1) } {
          ##### 4.d Host pool has NOT been identified AND we are retrying
          # a request with the inention of returning the replayed request's
          # auth-challenge response
          pool verseproxy_hub
          set targetPool verseproxy_hub
          call logger "REQ" $requestedURI "Retrying original request after lookup resulted in auth challenge"
        } else {
          ##### 4.e Default case
          call logger "REQ" $requestedURI "Request is pool dependent but case not currently handled"
        }
      } else {
        ##### 3.b Request is NOT pool dependent
        # NOTE: If all mail servers have Verse configured the same way, and are running
        #       the same Verse version, then any mail server can serve requests that
        #       are not pool dependent
        call logger "REQ" $requestedURI "Request is not pool dependent"
        pool verseproxy_mailpool
        set targetPool verseproxy_mailpool
      }
    }
  }

  call logger "REQ" $requestedURI "Will use pool: $targetPool"
  set requestCookieNames [HTTP::cookie names]
  set newCookieHeaderString ""
  call logger "REQ" $requestedURI "original cookie header strings: [HTTP::header values "Cookie"]"
  foreach requestCookieName $requestCookieNames {
    set appendCookieString ""
    set cookieValue [HTTP::cookie value $requestCookieName]
    if { ($requestCookieName starts_with "$targetPool~-~") or ($requestCookieName starts_with "/verseproxy_general/$targetPool~-~") } {
      set split [split $requestCookieName "~-~"]
      set originalCookieName [lindex [split $requestCookieName "~-~"] end]
      set cookiePath [HTTP::cookie path $requestCookieName]
      set cookieDomain [HTTP::cookie domain $requestCookieName]
      set cookieVersion [HTTP::cookie version $requestCookieName]
      set appendCookieString "$originalCookieName=$cookieValue"
    } else {
      set appendCookieString "$requestCookieName=$cookieValue"
    }
    if { ($newCookieHeaderString ne "") } {
      set newCookieHeaderString "$newCookieHeaderString; "
    }
    set newCookieHeaderString "$newCookieHeaderString$appendCookieString"
  }
  HTTP::header replace "Cookie" $newCookieHeaderString
  call logger "REQ" $requestedURI "final cookie header strings: [HTTP::header values "Cookie"]"
  call logger "REQ" $requestedURI "END HTTP_REQUEST"
}

when HTTP_REQUEST_DATA {
  ############################################################################
  # Ensure any request payload is preserved as we forward the request
  ############################################################################
  set paylength [HTTP::payload length]
  set requestData [HTTP::payload [HTTP::payload length]]
  set originalRequest [binary format a*a* $originalRequest $requestData]
}

when HTTP_RESPONSE {
  set responseCrafted 0
  call logger "RESP" $requestedURI "Used server [LB::server addr] of pool: [LB::server pool]"
  call logger "RESP" $requestedURI "Status code: [HTTP::status]"
  set setCookieHeaderValues [HTTP::header values "Set-Cookie"]
  HTTP::header remove "Set-Cookie"

  foreach setCookieHeaderValue $setCookieHeaderValues {
    if { !($setCookieHeaderValue starts_with "BIGipServer") } {
      set cookieName [lindex [split $setCookieHeaderValue "="] 0]
      set remainingCookieAttributes [string trimleft $setCookieHeaderValue $cookieName]
      set newCookieName "[LB::server pool]~-~$cookieName"
      HTTP::header insert "Set-Cookie" "$newCookieName$remainingCookieAttributes"
      if { ($cookieName eq "ShimmerS") } {
        HTTP::header insert $static::SHIMMER_ID_HEADER $newCookieName
      }
    } else {
      HTTP::header insert "Set-Cookie" $setCookieHeaderValue
    }
  }

  if { ([HTTP::status] == 404) and ($retries < 8) } {
    incr retries
    if { ($affinityCookieExists eq 1) and ($retries eq 1) } {
      # User is logged in and refreshed the page
      # First retry based on last known affinity
      set retryBasedOnAffinity 1
      call logger "RESP" $requestedURI "Retrying original request with reselection No. $retries due to 404"
    } else {
      set serverSelected $static::UNKNOWN
      call logger "RESP" $requestedURI "Retrying original request with reselection No. $retries due to 404"
    }
    HTTP::retry $originalRequest
    return
  } elseif { ([HTTP::status] == 302) } {
    set locationHeader [HTTP::header location]
    if { ($locationHeader starts_with "https://versetestadfs2019.vopdf.cwp.pnp-hcl.com/adfs/ls/?SAMLRequest=") } {
      set authPool [LB::server pool]
      set authPoolMember [LB::server addr]
      set authPoolMemberPort [LB::server port]

      scan $authPoolMember "%u.%u.%u.%u." a b c d
      set shiftb [expr ($b<<8)]
      set shiftc [expr ($c<<16)]
      set shiftd [expr ($d<<24)]
      set xorDestComponents [expr $shiftd|$shiftc|$shiftb|$a]
      set pcookie "$authPool.$xorDestComponents.[expr 256*$authPoolMemberPort].0000"

      call logger "RESP" $requestedURI "authCookie: $authPool $authPoolMember $authPoolMemberPort $expectedCookiePath"
      HTTP::cookie insert name DomAuthTarget value $pcookie path "/"
      set records [split $originalRequest "\n"]
      set newRequest $static::UNKNOWN
      set foundCookieHeader 0
      ## Iterate over the records
      foreach rec $records {
          ## Split into fields on colons
          if { $rec starts_with "Cookie: " } {
            call logger "RESP" $requestedURI "Found cookie header"
            set rec "Cookie: DomAuthTarget=$pcookie; [substr $rec "8"]"
            set foundCookieHeader 1
          }
          if { $newRequest eq $static::UNKNOWN } {
            set newRequest "$rec\n"
          } else {
            set newRequest "$newRequest$rec\n"
          }
      }
      if { ($foundCookieHeader eq 0) } {
        call logger "RESP" $requestedURI "Creating cookie header"
        set newCookieString "Cookie: DomAuthTarget=$pcookie;\n"
        set newRequest "$newRequest$newCookieString"
      }
      call logger "RESP" $requestedURI "unmodified original request: $originalRequest"
      set originalRequest $newRequest
      call logger "RESP" $requestedURI "newRequest: $newRequest"
    } elseif { ($locationHeader starts_with "http://proxytestvop01.vop.cwp.pnp-hcl.com") or ($locationHeader starts_with "https://proxytestvop01.vop.cwp.pnp-hcl.com") } {
      HTTP::header insert "Set-Cookie" "DomAuthTarget=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
      HTTP::header insert "Set-Cookie" "VoP_server_root_affinity=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT"
      call logger "RESP" $requestedURI "New login success means that the current user may have changed"
      call logger "RESP" $requestedURI "clearing DomAuthTarget and VoP_server_root_affinity cookies since 302 location header was: $locationHeader"
    }
  }

  call logger "RESP" $requestedURI "serverSelected: $serverSelected"
  if { $serverSelected == "new" } {
    set pcookie $newDest
    HTTP::cookie insert name $affinityCookieName value $pcookie path $expectedCookiePath
    call logger "RESP" $requestedURI "New encoded persistence cookie set for $newDest with scope $expectedCookiePath and value $pcookie"
    # Reset serverSelected to it's initial state.
    set serverSelected $static::UNKNOWN
    set newDest $static::UNKNOWN
  }

  ############################################################################
  # This is a response to a serverslookup request. Check the response for
  #   an X-Domino-Servers header containing a list of server FQDN/Hostnames
  #   that host the current target nsf.
  ############################################################################
  if { $serverNeeded == 1} {
    set server_list [split [HTTP::header X-Domino-Servers], ,]
    call logger "RESP" $requestedURI "Server_list: $server_list"
    set anyXDominoHeaderServerFound 0

    ############################################################################
    # Check if the IP of the current node matches an IP of one of the servers
    #   returned as part of the X-Domino-Servers header.
    # In order to map from FQDN/Hostname to IP, leverage a
    #   "String type Data Group".
    # If we are on the correct server, no need to change servers
    ############################################################################
    foreach {svr} $server_list {
      if { "" ne $svr } {
        set anyXDominoHeaderServerFound 1;
        set trimmedSvr "[string trim ${svr}]"
        set newDest [class search -value /verseproxy_general/NSCLUSTERLOOKUP1 contains $trimmedSvr]
        call logger "RESP" $requestedURI "set newDest to $newDest based on trimmed svr: <$trimmedSvr>"
        if { [LB::server pool] eq $newDest } {
          call logger "RESP" $requestedURI "Already on right pool: $newDest"
          set serverSelected "orig"
          break
        }
      }
    }

    ############################################################################
    # Retry the original request against an nsf hosting server that is up
    ############################################################################
    if { ($serverSelected == "orig") and ([LB::status node $newDest] eq "up")} {
      call logger "RESP" $requestedURI "Retrying original request for original server"
      # Retry the original request against the current ("original") server
      HTTP::retry $originalRequest
      set responseCrafted 1
    } else {
      # Start with the first server in the list, and traverse until we find a
      #   node that is currently up
      foreach {svr} $server_list {
        if { "" ne $svr } {
          set trimmedSvr "[string trim ${svr}]"
          set newDest [class search -value /verseproxy_general/NSCLUSTERLOOKUP1 contains $trimmedSvr]
          # call logger "RESP" $requestedURI "Status of $newDest [LB::status node $newDest]"
          set serverSelected "new"
          call logger "RESP" $requestedURI "newDest: $newDest"
          HTTP::retry $originalRequest
          set responseCrafted 1
          break
        }
      }
    }
    call logger "RESP" $requestedURI "anyXDominoHeaderServerFound: $anyXDominoHeaderServerFound"
    if { ($requestedURI starts_with "/serverslookup") and ($anyXDominoHeaderServerFound ne 1) and (([HTTP::status] == 401) or ([HTTP::status] == 302)) } {
      call logger "RESP" $requestedURI "HTTP status: [HTTP::status]"
      # The lookup request didn't return any host servers. The user may not be logged in?
      call logger "RESP" $requestedURI "performing original request against [LB::server addr]"
      call logger "RESP" $requestedURI "originalRequest: $originalRequest"
      set retryOriginalForAuthChallenge 1
      HTTP::retry $originalRequest
      set responseCrafted 1
    } elseif { ($requestedURI starts_with "/serverslookup") and ($anyXDominoHeaderServerFound ne 1) and ([HTTP::status] == 200) } {
      call logger "RESP" $requestedURI "Returning serverslookup error page."
      # Lookup performed successfully, but no host servers found for current nsf target
      HTTP::respond 500 content {
        <html>
          <head>
              <title>Apology Page</title>
          </head>
          <body>
              We are sorry, but the server lookup request was not successful.<br>
              If you feel you have reached this page in error, please try again.
          </body>
        </html>
      }
    } elseif { ($serverSelected ne "new") and ($anyXDominoHeaderServerFound eq 1) } {
      # TODO: this would indicate that all valid servers are down? how do we handle such a case
      HTTP::respond 500 content {
        <html>
          <head>
              <title>Apology Page</title>
          </head>
          <body>
              We are sorry, but the all identified target servers are offline.<br>
              If you feel you have reached this page in error, please try again.
          </body>
        </html>
      }
    } else {
      # Either ($serverSelected eq "orig") or ($server_seelcted eq "new")
      #   Either way, we are retrying the server against the nsf hosting server
      call logger "RESP" $requestedURI "X-Domino-XXX header found, clearing executedUnsuccessfulServerLookupMustLogin"
    }
  }

  if { ($responseCrafted == 0) } {
    if { ($xhr == 1) and ([HTTP::status] == 302) } {
      call logger "RESP" $requestedURI "rewriting 302 to 401 for xhr request"
      clientside[HTTP::respond 401 WWW-Authenticate "Realm=\"/\""]
      return
    }
  }
}
