# local-tester

Local-only test runner for debugging how POST/PUT/DELETE requests are handled.
Not used by CI or the Go integration tests.

A slim alpine container with just bash, curl and jq. It runs `test-methods.sh`,
which exercises the write endpoints on test-origin twice: once straight at the
origin, and once through the nginx + banjax edge. The origin echoes back what it
actually received, so a body dropped in the proxy chain shows up as a mismatch
between the two rows.

It is declared in the root `docker-compose.yml` under the `tools` profile, so it
never starts as part of `docker compose up`.

## Running

Bring the stack up, then run the tester on demand:

```sh
docker compose up --build -d
docker compose run --rm local-tester
```

Run a subset by passing a substring of the case name:

```sh
docker compose run --rm local-tester login
```

Because it runs inside the compose network it reaches `test-origin:8080` and
`nginx:80` directly, so it does not care which host ports are published or
whether port 80 is free on the host.

To run the script on the host instead of in the container, point it at the
published ports:

```sh
ORIGIN_URL=http://localhost:8080 EDGE_URL=http://localhost \
    supporting-containers/local-tester/test-methods.sh
```

Environment variables, overridable with `docker compose run -e`:

| Variable | In-container default | Purpose |
| --- | --- | --- |
| `ORIGIN_URL` | `http://test-origin:8080` | test-origin, bypassing the edge |
| `EDGE_URL` | `http://nginx` | the nginx + banjax edge |
| `EDGE_HOST` | `localhost` | `Host` header, must match an nginx `server_name` |

## Reading the output

Every case prints two rows. `DIRECT` goes straight to test-origin, `EDGE` goes
through nginx and banjax. `sent=` is the Content-Length the client claimed,
`got=` is the number of body bytes the origin actually read.

- Both rows `body intact` - the body survives the proxy chain.
- `DIRECT` intact but `EDGE` says `BODY LOST` - the body is being discarded
  between nginx and the origin, not by the origin.
- `no origin report` - the response did not come from test-origin at all (a ban
  page, an nginx error, or a `Host` that matched a different `server_name`).

The last check sends a `PUT` through the edge and reads the state back from the
origin, since a 200 with an intact body still would not prove the write applied.

The script exits non-zero if any check fails.

## Origin endpoints it exercises

Added to `supporting-containers/test-origin/hello-world.go`:

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/login` | Simulated login. Accepts JSON or urlencoded form with `username` and `password`; the password `correct-horse` succeeds, anything else gives 401. |
| `PUT` | `/api/resources/:id` | Modifies a resource from a JSON body (`name`, `value`). |
| `DELETE` | `/api/resources/:id` | Deletes a resource. |
| `GET` | `/api/resources` | Lists current resources, to confirm writes landed. |
| `POST` | `/api/resources/reset` | Restores the seeded resources so a run is repeatable. |
| `ANY` | `/echo` | Reports whatever arrived. Use this when the only question is whether the body made it through. |

Resource state is in-memory, so restarting the container resets it. Every
endpoint embeds a `request` object in its JSON response describing what the
origin received: method, content type, claimed Content-Length, bytes actually
read, and a `body_complete` flag.
