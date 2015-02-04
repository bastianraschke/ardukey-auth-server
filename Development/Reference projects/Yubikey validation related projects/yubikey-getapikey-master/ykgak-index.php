<?php
require_once 'Auth/Yubico.php';
require_once 'ykgak-config.php';

$email = "";
$otp = "";
$password = "";
$email_err = "";
$otp_err = "";
$internal_err = false;
$comment = "";

if (isset($_REQUEST["email"])) {
  $email = htmlspecialchars ($_REQUEST["email"]);
}

if (isset($_REQUEST["password"])) {
  $password = htmlspecialchars ($_REQUEST["password"]);
}

if (isset($_REQUEST["comment"])) {
  $comment = htmlspecialchars ($_REQUEST["comment"]);
}

if (isset($_REQUEST["otp"])) {
  $otp = htmlspecialchars ($_REQUEST["otp"]);
  $comment = $otp;
}

if ($email &&
# The regexp may be a bit conservative, but better safe than sorry.
    !preg_match("/^[0-9a-zA-Z._-]+@[0-9a-zA-Z_.-]+\.[0-9a-zA-Z_-]+$/",
		$email)) {
  $email_err = "Invalid e-mail address";
}

if ($otp && !preg_match("/^[a-z]+$/", $otp)) {
  $email_err = "Invalid YubiKey OTP";
} else if ($otp) {
  $yubi = &new Auth_Yubico($client_id, $client_key);
  $auth = $yubi->verify($otp);
  if (PEAR::isError($auth)) {
    $otp_err = "OTP failed: " . $auth->getMessage();
  }
}

function doit () {
  global $spooldir, $gakgpghome, $pgpkeyids;
  global $email, $otp, $email_err, $otp_err, $internal_err;
  global $id, $key;

  $str = `find "$spooldir" -type f -regex '.*/ykgak-[0-9]+.asc' | sed -e 's,.*/ykgak-,,' -e 's/.asc//' | sort -n | tail -1 2> /dev/null`;
  if (sscanf ($str, "%d", $id) != 1) {
    error_log ("cannot find highest unused client id in $spooldir");
    $internal_err = true;
    return;
  }
  $id++;

  $file = $spooldir . "/ykgak-$id.asc";
  $cmd = "gpg --batch --homedir $gakgpghome --armor --encrypt --sign --recipient " . (implode (" --recipient ", $pgpkeyids)) . " >> $file 2>&1";

  $fh = fopen($file, "x");
  if (!$fh) {
    error_log ("cannot open output for writing");
    $internal_err = true;
    return;
  }
  fwrite ($fh, "$cmd\n");
  fclose ($fh);

  $fh = fopen("/dev/urandom", "r");
  if (!$fh) {
    error_log ("cannot open /dev/urandom");
    $internal_err = true;
    return;
  }
  if (!($rnd = fread ($fh, 20))) {
    error_log ("cannot read from /dev/urandom");
    $internal_err = true;
    return;
  }
  fclose ($fh);
  $key = base64_encode ($rnd);

  $h = popen($cmd, "w");
  if (!$h) {
    error_log ("cannot start cmd");
    $internal_err = true;
    return;
  }
  
  $str = sprintf ("'%d','%s','%s','%s','%s'\n",
		  $id, gmdate("U"), $key, $comment, $email);
  fwrite ($h, $str);
  $rc = pclose ($h);
  if ($rc != 0) {
    error_log ("non-zero exit code from gpg");
    $internal_err = true;
    return;
  }
}

$is_email_valid = $email && !$email_err;
$is_otp_valid = $otp && !$otp_err;
$is_password_to_bypass_otp_valid = $password_to_bypass_otp && $password == $password_to_bypass_otp;

if ($is_email_valid && ($is_otp_valid || $is_password_to_bypass_otp_valid)) {
  doit();
}

if ("json" == $_REQUEST['format']) {
  if (!$internal_err && isset($id) && isset($key)) {
    $data['status'] = true;
    $data['id'] = $id;
    $data['key'] = $key;
  } else {
    $data['status'] = false;
    $data['error'] = "A system error encountered, if this persists please contact support@yubico.com.";
  }
  exit(json_encode($data));
}
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html lang="en"	xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">

<head>
  <meta http-equiv="content-type" content="text/html; charset=utf-8"/>
  <meta http-equiv="Cache-Control" content="no-cache, must-revalidate"/>
  <link rel="stylesheet" type="text/css" href="misc/style.css" />
  <title>Yubico Get API Key</title>
</head>

<?php if (!$email || $email_err) { ?>
<body onLoad="document.getapikey.email.focus();">
<?php } else  { ?>
<body onLoad="document.getapikey.otp.focus();">
<?php } ?>
<div id="stripe">&nbsp;</div>
<div id="container">
  <div id="logoArea">
    <img src="misc/yubicoLogo.png" alt="yubicoLogo" style="display:block;margin-top:17px;margin-bottom:auto;"/>
  </div>

  <div id="greenBarContent">
    <div id="greenBarImage">
      <img src="misc/yubikey.png" alt="yubikey" width="102" height="89"/>
    </div>
    <div id="greenBarText">
      <h3>Yubico Get API Key</h3>
    </div>
  </div>

  <div id="bottomContent">

<?php if (!$internal_err && isset($id) && isset($key)) { ?>

    <p>Congratulations!  Please find below your client identity and
      client API key.</p>

    <p><table>
	<tr><td>Client ID:</td><td><b><?php print $id; ?></b></td></tr>
	<tr><td>Secret key:</td><td><b><?php print $key; ?></b></td></tr>
      </table></p>

    <p>Be sure to protect the secret.  If you need to generate more
      client id/keys for your different applications, please come back.</p>

    <p>Note that it may take up until <b>5 minutes</b> until all
      validation servers know about your newly generated client.

<?php } else { ?>

    <p>Here you can generate a shared symmetric key for use with the
      Yubico Web Services.  You need to authenticate yourself using a
      Yubikey One-Time Password and provide your e-mail address as a
      reference.</p>

<?php if ($internal_err) { ?>
    <p><font color="red">A system error encountered, if this persists please contact support@yubico.com.</font></p>
<?php } ?>

    <form name="getapikey" method="post">

    <table>
    <tr>
      <td>Your <b>e-mail</b> address:</td>
      <td><input type="text" name="email"
		 value="<?php echo $email; ?>"/></td>
      <td><font color="red"><?php print $email_err; ?></font></td>
    </tr>
    <tr>
      <td>YubiKey <b>one-time password</b>:</td>
      <td><input type="text" name="otp"/></td>
      <td><font color="red"><?php print $otp_err; ?></font></td>
    </tr>
    <tr>
      <td></td>
      <td align=center><input type=submit value="Get API Key"/></td>
    </tr>
    </table>

    </form>
  </div>
<?php } ?>
</div>
</body>
</html>
