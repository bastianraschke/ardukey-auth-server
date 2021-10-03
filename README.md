# ArduKey auth server

## Installation

First you have to install the server via your package manager. For example:

    ~# apt-get install ardukey-auth-server

Important note: First you need to add the "PM Codeworks" repository. See [this page](http://www.pm-codeworks.de/repository.html) for the instructions.

## Manual package build and installation

If you don't want to use pre-build packages, you can easyly build your own packages using the tool `debuild`:

    ~$ cd ./src/
    ~$ debuild

After that, the generated packages can be found in the upper directory. You can install the packages with `dpkg`:

    ~# dpkg -i ../*.deb

And fix the dependency problems, if occurred:

    ~# apt-get -f install

## Configuration

Note: All changes will be done in file `/etc/ardukey-auth-server.conf`.

You should change the address, the server is listening on. This address must be available for all systems that should verify One-Time passwords (OTP):

    server_address = 11.22.33.44

Than restart the auth-server:

    ~# /etc/init.d/ardukey-auth-server restart

## Maintaining

First add an ArduKey device with the following command:

    ~# ardukey-auth-conf --add-ardukey cccccccccccb b0d4a2d69bc4 7a1858592fcb76bd5eb2685421aed45e

Note: In this example, an ArduKey device with the public id `cccccccccccb`, the secret id `b0d4a2d69bc4` and the AES key `7a1858592fcb76bd5eb2685421aed45e` will be added to database of auth-server.

All systems (a PAM module for example) that should verify OTPs from users need a valid "API key" to sign and verify communication to/from auth-server.

Now, generate a new API key:

    ~# ardukey-auth-conf --generate-apikey

The command outputs the "API id" and the "shared secret". Give this information to the administrator who wants to set up the ArduKey PAM module for example.

Further maintanance: Check out the man page of `ardukey-auth-conf` for all available commands:

    ~$ man ardukey-auth-conf

## Debugging server

You can also start the server in debugging mode. First shut down the `ardukey-auth-server` service which runs on the server:

    ~# /etc/init.d/ardukey-auth-server stop

Than start service in debugging mode on terminal:

    ~# ardukey-auth-server --debug

Now you will see all debugging output from the `ardukey-auth-server`.

## Request structure

Requests will be sent via HTTP GET to:
http://127.0.0.1:8080/ardukeyotp/1.0/verify

with the following parameters:

| Parameter | Description                              |
|-----------|------------------------------------------|
| otp       | The one-time-pad type by an ArduKey.     |
| nonce     | A random string, to make request unique. |
| apiId     | The API ID, to identify the API key.     |
| hmac      | The signature of this request.           |

The HMAC is a SHA-256 hash value that is calculated by key sorted (alphabetical) request parameter values:

    hmac = SHA256(apiId + otp + nonce)

## Further information

Additionally you can check out [this article](https://sicherheitskritisch.de/2015/06/ardukey-otp-generator-fuer-zweifaktor-authentifizierung-2fa-mit-arduino/), which explains the complete ArduKey infrastructure in detail (the article is in German):


## Questions

If you have any questions to this project, just ask me via email:

<bastian.raschke@posteo.de>
