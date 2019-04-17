###############################################################################
#                                                                             #
# Copyright 2019. Triad National Security, LLC. All rights reserved.          #
# This program was produced under U.S. Government contract 89233218CNA000001  #
# for Los Alamos National Laboratory (LANL), which is operated by Triad       #
# National Security, LLC for the U.S. Department of Energy/National Nuclear   #
# Security Administration.                                                    #
#                                                                             #
# All rights in the program are reserved by Triad National Security, LLC, and #
# the U.S. Department of Energy/National Nuclear Security Administration. The #
# Government is granted for itself and others acting on its behalf a          #
# nonexclusive, paid-up, irrevocable worldwide license in this material to    #
# reproduce, prepare derivative works, distribute copies to the public,       #
# perform publicly and display publicly, and to permit others to do so.       #
#                                                                             #
###############################################################################

#!/bin/sh
rm *.gz
rm *.dmg
rm -rf stonix
#mkdir stonix
rm -rf stonix4mac/*.log
rm -rf stonix4mac/dist
rm -rf stonix4mac/build
find . -name "*.pyc" -exec rm {} \;
#rm stonix4mac/admin_credentials_ui.py
#rm stonix4mac/general_warning_ui.py
#rm stonix4mac/stonix_wrapper_ui.py
rm stonix4mac/*.spec
rm *.log
rm *.old
rm *.xml
rm -rf dmgs/stonix4mac.*
rm -rf /tmp/stonix
rm -rf /tmp/stonix4mac
find . -iname "*.pyc" -print -exec rm {} \;
rm -rf /tmp/xcodebuild.py.log
rm -rf /tmp/build.py.log

