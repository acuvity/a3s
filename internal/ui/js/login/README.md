# Login UI

A simple UI that handles authentication using A3S. Currently it supports `MTLS`, `LDAP` and `OIDC`.

## Install requirements

You need to have [nodejs](https://nodejs.org/) and [yarn (v1)](https://yarnpkg.com/getting-started/install) installed.

## Launch the app

- For the first time ony, run `yarn` to install the dependencies.
- Then, run `yarn start` to start the local dev server.
- Follow the instruction to open the app in your browser.

> If `yarn start` fails, stop it and run again. There seems to be some bug with snowpack. We'll resolve it soon.
> For CORS issue, start Chrome using `open -n -a /Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --args --user-data-dir="/tmp/chrome_dev_test" --disable-web-security` (this command works for macOS only).
> For cert issue, open the a3s server url in your broswer and trust the certificate.

## SAML login
The Dockerfile and run.sh contain example of a revese proxy that is being used for SAML login.
A `/saml-verify` route will forward the relayState and SAMLResponse to the provider window of the app where the login will be finalized and client will receive a token via secure cookie.

Setup:
* make sure the certs are available https://github.com/acuvity/acuvity/pull/277#issue-2276614784

<details>
<summary>import saml source</summary>

```
a3sctl import ../a3s/dev/saml/a3s-samlsource.yaml -n /orgs/acuvity.ai
```
</details>

<details>
<summary>create saml apiauthorization</summary>

```
acuctl api create apiauthorization -n /orgs/acuvity.ai -d "{'name': 'saml', 'description': 'SAML auth', 'role': 'Administrator', 'subject': [['@source:name=default', '@source:namespace=/orgs/acuvity.ai', '@source:type=saml']]}"
```
</details>

<details>
<summary>running via nginx locally</summary>

```
make container ARCH=native &&
docker run -v $CERTS_FOLDER:/certs -e FRONTEND_TLS_CERT=/certs/public-server-cert.pem -e FRONTEND_TLS_KEY=/certs/public-server-key.pem -e FRONTEND_TLS_KEY_PASS=/certs/public-server-key.pass -p 3000:1443 docker.io/local/acuvity/containers/frontend:v0.0.0-a556fbe
```
</details>

