###############################################################################
#                                                                             #
# Copyright 2015-2019.  Los Alamos National Security, LLC. This material was       #
# produced under U.S. Government contract DE-AC52-06NA25396 for Los Alamos    #
# National Laboratory (LANL), which is operated by Los Alamos National        #
# Security, LLC for the U.S. Department of Energy. The U.S. Government has    #
# rights to use, reproduce, and distribute this software.  NEITHER THE        #
# GOVERNMENT NOR LOS ALAMOS NATIONAL SECURITY, LLC MAKES ANY WARRANTY,        #
# EXPRESS OR IMPLIED, OR ASSUMES ANY LIABILITY FOR THE USE OF THIS SOFTWARE.  #
# If software is modified to produce derivative works, such modified software #
# should be clearly marked, so as not to confuse it with the version          #
# available from LANL.                                                        #
#                                                                             #
# Additionally, this program is free software; you can redistribute it and/or #
# modify it under the terms of the GNU General Public License as published by #
# the Free Software Foundation; either version 2 of the License, or (at your  #
# option) any later version. Accordingly, this program is distributed in the  #
# hope that it will be useful, but WITHOUT ANY WARRANTY; without even the     #
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    #
# See the GNU General Public License for more details.                        #
#                                                                             #
###############################################################################
<?php

# place to store the files
$target_path = "results/${_SERVER['REMOTE_ADDR']}-" . rand(1,1000000000) . ".xml";

if ($_FILES["file"]["error"] > 0) {
	# just return the code. script will check for OK or code
	echo $_FILES["file"]["error"] . "\n";
}
else {
#	echo "Upload: " . $_FILES["file"]["name"] . "\n";
#	echo "Type: " . $_FILES["file"]["type"] . "\n";
#	echo "Size: " . ($_FILES["file"]["size"] / 1024) . " Kb \n";
#	echo "Temp file: " . $_FILES["file"]["tmp_name"] . "\n";
	
	if (file_exists($target_path)) {
		echo $target_path . " already exists. \n";
	}
	else {
		move_uploaded_file($_FILES["file"]["tmp_name"], $target_path);
		echo "ok $target_path\n";
	}
}

?>
