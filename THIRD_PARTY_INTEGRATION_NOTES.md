## Talking to Baskerville over a Kafka connection

banjax-go can optionally send and receive messages over a Kafka bus. We use this to
communicate with our Baskerville ML anomaly detection system.

Messages sent on `kafka_command_topic` (from Baskerville to banjax-go):
* `{"name": "challenge_ip", "value": "1.2.3.4"}`
  * Tells banjax-go to challenge this IP the next time it's seen.

Messages sent on `kafka_report_topic` (from banjax-go to Baskerville):
* `{"name": "ip_passed_challenge", "value_ip": "1.2.3.4", "value_site": "example.com"}`
  * Tells Baskerville an IP passed a challenge.
* `{"name": "ip_failed_challenge", [same as above]...}`
  * Tells Baskerville an IP failed a challenge.
* `{"name": "ip_banned", [same as above]...}`
  * Tells Baskerville an IP failed enough challenges to get banned.

The banning threshold is configured with:
```yaml
too_many_failed_challenges_interval_seconds: 10
too_many_failed_challenges_threshold: 3
```

The Kafka connection is configured with:
```yaml
kafka_brokers:
  - "localhost:9092"
kafka_security_protocol: 'ssl'
kafka_ssl_ca: "/etc/banjax-next/caroot.pem"
kafka_ssl_cert: "/etc/banjax-next/certificate.pem"
kafka_ssl_key: "/etc/banjax-next/key.pem"
kafka_ssl_key_password: password
kafka_report_topic: 'banjax_report_topic'
kafka_command_topic: 'banjax_command_topic'
```

## Deploying alongside or in front of an existing setup

You should be able to get a quick demo of banjax-go + Nginx + a test origin server
running with `docker-compose up`.

You're probably running an existing Nginx (or similar) server. We describe two options
for adding banjax-go to your setup. The first involves changing your existing Nginx
configuration to talk to banjax-go. The second involves adding a new Nginx server in
front of your existing one.

### Talking to banjax-go from an existing Nginx (or other) setup

You'll want to read the sample `nginx.conf` under `supporting_containers/nginx` and understand
how it works.

An incoming request matches a location block like this. The `proxy_pass` directive
sends the request to banjax-go.
```
location / {
    proxy_pass http://127.0.0.1:8081/auth_request?;
}
```

banjax-go responds with one of:
* A challenge page containing JS that will set cookies for authenticating subsequent requests.
  This response gets sent back to the client.
* A response with `X-Accel-Redirect` set to `@access_granted` or `@access_denied`. This header
  tells Nginx not to respond to the client yet, but to perform an internal redirect to one
  of the location blocks called `@access_granted` or `@access_denied`.
```
location @access_denied {
    return 403 "access denied";
}

location @access_granted {
    proxy_pass http://test-origin:8080;
}
```

We're only using this with Nginx, but other proxy servers seem to have a similar mechanism.


### Deploying Nginx + banjax-go in front of an existing web server

The easiest way to get started here would be to edit the sample `nginx.conf` under
`supporting_containers/nginx` to point to your origin server (change all the
`proxy_pass http://test-origin:8080;` lines).

Then use the provided `docker-compose.yml` to start Dockerized instances of Nginx and
banjax-go: `docker-compose up --build nginx banjax-next`.

Now you can make a request through this new Nginx with:
```
curl --header "Host: example.com" http://127.0.0.1:80
```
or
```
curl --resolve example.com:80:127.0.0.1 http://127.0.0.1:80
```

For non-HTTPS requests like shown here, these commands will do the same thing
(namely, ensure an HTTP Host: header gets sent to Nginx so it knows which server
block to use). For HTTPS requests, the second form of the command will also ensure
the hostname gets sent in the TLS SNI field so that Nginx knows which server key to
use for the TLS connection. For a single-site Nginx configuration with
`server_name _;`, you might not have to worry about any of this.

#### Running the new Nginx + banjax-go on the same host as your existing server

You'll want to change your existing server to listen on, for example, 127.0.0.1:8080, and
configure the new Nginx to `proxy_pass` to that local address.

Binding on 127.0.0.1 will let the new Nginx connect to it over the loopback interface,
but will keep others from being to connect to it over the internet.

Then configure the new Nginx to listen on 0.0.0.0:80 (and 443).

#### Running the new Nginx + banjax-go on a host other than your existing server

You'll need to point your DNS records to the new host's IP address.

And you'll configure the new Nginx to point to your existing server's IP address and port.

And you'll want to use a firewall on the existing host to that only the new Nginx is allowed
to connect to it.
