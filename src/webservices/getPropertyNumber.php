<?php
# script to validate a property number against a serial number
# usage:
# curl -S http://dev-y.lanl.gov/liveupdate/stom/getPropertyNumber.php?serial=XXXXXXXX
# curl -S http://int.lanl.gov/liveupdate/stom/getPropertyNumber.php?serial=XXXXXXXX
# where XXXXXXXX is the serial number of the Mac

$hostname = "webdb.lanl.gov";
$database = "common_pro";
$username = "QueryUser";
$password = "ReadOnly1";

$db = mysql_connect($hostname, $username, $password) or trigger_error(mysql_error(),E_USER_ERROR); 

$serial = $_GET['serial'];

mysql_select_db($database, $db);
$query = sprintf("select bar_code from property where serial_no = '${serial}'");
$result = mysql_query($query, $db);
$result_list = mysql_fetch_assoc($result);

echo $result_list[bar_code];


?>