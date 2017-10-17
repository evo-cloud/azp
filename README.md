#Authn/z Proxy

A simple HTTP proxy does Authn/z with HTTPS termination.

It supports

- OpenID Connect based authentication
- RBAC based URL path matching
- HTTPS termination

It's quick and handy to run in front of your application which doesn't supports
HTTPS, Authn, Authz and make your application secure.

It doesn't do

- Multiple backend servers

##Quick Start

### Build

Written in Go and built by Go, that's simple.

You don't want to install Go?

- Install [Docker](https://get.docker.com)
- Install [HyperMake](https://evo-cloud.github.com/hmake)

And issue a single command:

```
hmake
```

The binary is in your hand, at `bin/OS/ARCH/azp`.

### Launch

HTTPS is required, so you need to prepare your certificates.
For testing, generate self-signed certificate:

```
openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 3650 -out cert.pem -subj /CN=localhost
```

Get `CLIENT_ID` and `CLIENT_SECRET` from your Google account

```
bin/linux/amd64/azp -b http://my-backend-server/ -c CLIENT_ID -s CLIENT_SECRET
```

And point your browser to `https://localhost:8443` and you will be directed to
Google account login.

### RBAC Rules

RBAC is enabled when `-rbac-rules RULES.json` is specified.
Here's an example of `RULES.json`:

```json
{
    "rules": [
        {"id": "private", "path": "/internal/"},
        {"id": "privileged", "method": "POST|PUT|PATCH|DELETE", "path": "/users/"},
        {"id": "all", "path": "/"}
    ],
    "binding": {
        "private": ["developers", "me@name.com", "-support@name.com"],
        "privileged": ["admins"],
        "all": ["*"]
    }
}
```

### TD;LR

```
bin/linux/amd64/azp --help
```

for details.

## License

MIT
