'''
Test data for zzzTestFrameworkSHlaunchdTwoHelperMethods test.

Assumption made that Stonix is installed on the test system.
'''

service_path_test_data = {'valid_service_paths': ['/Library/LaunchDaemons/gov.lanl.stonix.report.plist',
                                                  '/System/Library/LaunchDaemons/org.cupsd.plist',
                                                  '/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist'],
                          'invalid_service_paths': ['/etc/stonix.conf',
                                                    'foobar.test/LaunchDaemons',
                                                    '/3test/LaunchAgents',
                                                    '/^abc.test/LaunchAgents/one.two.three',
                                                    '/+/LaunchDaemons/one.two-three'] }

name_from_service_test_data = {'valid_service_plists': ['/Library/LaunchDaemons/gov.lanl.stonix.report.plist',
                                                        '/System/Library/LaunchDaemons/org.cupsd.plist',
                                                        '/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist'],
                               'invalid_service_plists': ['/etc/stonix.conf',
                                                          '/tmp/tmp/tmp/tmp']}

target_valid_test_data = {'valid_target_data': [['/Library/LaunchDaemons/gov.lanl.stonix.report.plist', {'serviceName': ['servicename', 'gov.lanl.stonix.report']}],
                                                 ['/System/Library/LaunchDaemons/org.cupsd.plist', {'serviceName': ['domainTarget', 'org.cups.cupsd']}],
                                                 ['/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist', {'serviceName': ['serviceTarget', 'com.apple.mDNSResponder.reloaded']}]],
                          'invalid_target_data': [['/Library/LaunchDaemons/gov.lanl.stonix.report.plist', {'serviceName': ['tardisName', 'gov.lanl.stonix.report']}],
                                                  ['/System/Library/LaunchDaemons/org.cupsd.plist', {'serviceName': ['targetName', 123]}],
                                                  ['/System/Library/LaunchDaemons/com.apple.mDNSResponder.plist', {'serviceName': ['targetName', '+test']}]]}
