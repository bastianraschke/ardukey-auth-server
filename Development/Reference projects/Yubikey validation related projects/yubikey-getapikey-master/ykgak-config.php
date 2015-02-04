<?php
# ID: Client id for verifying YubiKey OTPs.
$client_id = 1;
# KEY: Shared secret used when verifying YubiKey OTPs.
$client_key = "";
# SPOOLDIR: Where encrypted files are stored.
$spooldir = "/var/spool/ykgak";
# PGPHOME: Where GnuPG secret key lives (for signing).
$gakgpghome = "/etc/ykgak";
# PGPKEYIDS: List of OpenPGP key ids to encrypt to.
$pgpkeyids = array("1234abcd", "fdab6789");
# PASSWORD: Used to authenticate instead of an OTP.
$password_to_bypass_otp = "secretpassword";
?>
