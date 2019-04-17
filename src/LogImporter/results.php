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
