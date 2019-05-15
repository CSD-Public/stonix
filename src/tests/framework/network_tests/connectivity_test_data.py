

##########################################################
# Data for test: zzzConnectivity_is_page_available
# NOTE: 
# valid_connections tests will fail if the test system
# uses a proxy to reach those sites
# 
# Test case data for: zzzConnectivity_is_page_available
#                      expected, test#, host, website
#                       result   number 
test_case_data_is_page_available = \
{ "valid_connections" : [(True, "001", "https://www.google.com", "/"),
                         (True, "002", "https://www.github.com:443", "/explore"),
                         (True, "003", "http://ftp.funet.fi", "/pub/Linux/kernel/v4.x/testing"),
                        ],
  "invlaid_connections" : [(False, "010", "http://ftp.funet.fii", "/foobar"),
                           (False, "011", "http://www.cnn.com", "/foobar"),
                           (False, "012", "http://garblat", "/"),
                           (False, "013", "http://examplefoobar", "/"),
                          ],
}


##########################################################
# Data for test: zzzConnectivity_is_site_socket_online
#                        test#, expected, host
#                               result
test_case_data_site_socket_online = \
{ "valid_connections" : [("001", True, "www.google.com"),
                         ("002", True, "www.github.com"),
                        ],
  "invlaid_connections" : [("010", False, "ha234567"),
                           ("011", False, "GGlartBlatG.GartBlat"),
                           ("012", False, "hgarblat.hgarblat"),
                          ],
}

