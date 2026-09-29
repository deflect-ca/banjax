### The `auth_request` endpoint that Nginx talks to

Nginx `proxy_pass`es to banjax, which makes a decision (Allow, Challenge, NginxBlock, or IptablesBlock)
based on the requested host, the client IP, and the client User-Agent. In pseudocode, banjax's
decision-making works like this:

```python
if has_valid_password_cookie():
    return access_granted()

if password_protected_path[requested_host][requested_path]:
    if password_protected_path_exceptions[requested_host][requested_path]:
        return access_granted()
    else:
        return send_or_validate_password_page()

decision = per_site_decision_lists[requested_host][client_ip]
if decision == Allow:
    return access_granted()
if decision == Challenge:
    return send_or_validate_challenge()
if decision in [NginxBlock, IptablesBlock]:
    return access_denied()

decision = per_site_user_agent_decision_lists[requested_host][client_user_agent]
if decision == Allow:
    return access_granted()
if decision == Challenge:
    return send_or_validate_challenge()
if decision in [NginxBlock, IptablesBlock]:
    return access_denied()

decision = global_decision_lists[client_ip]
# [...] same as above

decision = global_user_agent_decision_lists[client_user_agent]
# [...] same as above

# The expiring decision lists are checked narrowest scope first: session id,
# then User-Agent, then host, then IP. Note that a "baskerville is disabled for
# this site" skip does not return; it falls through to the next check below.

decision = expiring_decision_lists_session_id[client_session_id]
if decision == Allow:
    return access_granted()
if decision == Challenge:
    if per_site_sha_inv_path_exceptions[requested_host][requested_path]:
        return access_granted()
    if sites_to_disable_baskerville[requested_host] and decision.from_baskerville:
        pass  # skip challenge, fall through to the User-Agent check below
    else:
        return send_or_validate_challenge()
if decision in [NginxBlock, IptablesBlock]:
    if sites_to_disable_baskerville[requested_host] and decision.from_baskerville:
        pass  # skip block, fall through to the User-Agent check below
    else:
        return access_denied()

decision = expiring_user_agent_decision_lists[client_user_agent]
if decision == Challenge:
    # [...] same as above, falling through to the host check below
if decision in [NginxBlock, IptablesBlock]:
    # [...] same as above, falling through to the host check below

decision = expiring_host_decision_lists[requested_host]
if decision == Challenge:
    # [...] same as above, falling through to the IP check below

decision = expiring_decision_lists[client_ip]
if decision == Allow:
    return access_granted()
if decision == Challenge:
    if per_site_sha_inv_path_exceptions[requested_host][requested_path]:
        return access_granted()
    if sites_to_disable_baskerville[requested_host] and decision.from_baskerville:
        pass  # skip challenge, fall through to sitewide_sha_inv_list check below
    else:
        return send_or_validate_challenge()
if decision in [NginxBlock, IptablesBlock]:
    if sites_to_disable_baskerville[requested_host] and decision.from_baskerville:
        pass  # skip block, fall through to sitewide_sha_inv_list check below
    else:
        return access_denied()

if sitewide_sha_inv_list[requested_host]:
    fail_action = sitewide_sha_inv_list[requested_host].fail_action  # Block or Allow
    if password_protected_path_exceptions[requested_host][requested_path]:
        return access_granted()
    else:
        return send_or_validate_challenge(fail_action)

# if nothing matched above
return access_granted()
```

The IP-based decision lists are populated from:
  * the config file, which is read at startup and reloaded on SIGHUP. See `per_site_decision_lists`
    and `global_decision_lists`. This is useful for allowlisting or blocklisting known good or bad IPs.
  * the regex-based rate-limiting rules explained in more detail below.
  * commands received over the Kafka connection. This is how Baskerville communicates with banjax.

The static User-Agent decision lists (`per_site_user_agent_decision_lists` and
`global_user_agent_decision_lists`) are loaded from the config file only. Each entry is either a plain
substring match or a regex pattern (detected automatically by the presence of regex metacharacters).
Patterns are pre-compiled at config load time. Decision severity order is IptablesBlock → NginxBlock →
Challenge → Allow; the first matching pattern wins.

The expiring User-Agent and host lists are separate from those static lists. They are populated only by
Kafka commands (see below), they match the User-Agent string exactly (no substring or regex matching),
and their entries disappear when their TTL expires.

`access_granted()` returns a response with a header: `X-Accel-Redirect: @access_granted` which instructs
Nginx to perform an internal redirect to the location block named `@access_granted`. That block should
`proxy_pass` to the upstream origin site.

`access_denied()` works similarly, but the `@access_denied` block might just return a "403, access denied"
response.

The relevant Nginx config might look similar to:

```
location /wp-admin/ {
	error_page 500 501 502 @fail_closed;
	proxy_pass http://<banjax>/auth_request?;
}

location / {
	error_page 500 501 502 @fail_open;
	proxy_pass http://<banjax>/auth_request?;
}

location @access_denied {
	return 403 "access denied";
}

location @access_granted {
	proxy_pass http://<upstream site>;
}

location @fail_open {
	proxy_pass http://<upstream site>;
}

location @fail_closed {
	return 403 "error talking to banjax, failing closed";
}
```

It's probably a good idea to add per-block logging and caching behavior to the above.

### Kafka commands and the expiring decision lists

Baskerville (or `supporting-containers/kafka-cmd-tester` during development) sends JSON command
messages on `kafka_command_topic`. Each command writes into one of the four expiring decision lists
checked above:

| Command | Keyed on | Decision | List |
| --- | --- | --- | --- |
| `challenge_ip` | `value` (IP) | Challenge | IP |
| `block_ip` | `value` (IP) | NginxBlock | IP |
| `challenge_session` | `session_id` | Challenge | session id |
| `block_session` | `session_id` | NginxBlock | session id |
| `challenge_ua` | `ua` | Challenge | User-Agent |
| `block_ua` | `ua` | NginxBlock | User-Agent |
| `challenge_all` | `host` | Challenge | host |
| `clear_rules` | any of `host`, `value`, `session_id`, `ua` | — | removes entries |

`challenge_all` is the temporary, Kafka-driven equivalent of the `sitewide_sha_inv_list` config
entry: it challenges every request to a host until the TTL expires, without editing the config file.
The host list only acts on a Challenge decision; the User-Agent list only acts on Challenge and the
two block decisions (an Allow there is ignored).

Writes never downgrade an existing entry: a new decision is only stored if it is more severe than
the one already in the list for that key.

`clear_rules` takes any combination of `host`, `value` (IP), `session_id`, and `ua`, and clears each
one it is given from the corresponding expiring list. The `/unban` HTTP API does the same thing for a
single `ip`, `host`, or `ua` form field.

Each command's lifetime comes from the config (`expiring_decision_ttl_seconds` for challenges,
`block_ip_ttl_seconds` / `block_session_ttl_seconds`, optionally overridden per site by
`sites_to_block_ip_ttl_seconds` / `sites_to_block_session_ttl_seconds` for blocks). A command may
carry a `ttl` field (in seconds) to override that on a per-message basis; any positive value wins
over the config default.

Commands for a host listed in `sites_to_disable_baskerville` are dropped on arrival, and any
Baskerville-origin decision already in an expiring list is skipped at decision time for such a host.
This includes `clear_rules`: one whose `host` is such a site is dropped as a whole, including its
`value` / `ua` / `session_id` fields.

The lengths of the expiring lists are reported in the metrics log as `LenExpiringChallenges` /
`LenExpiringBlocks` (IP and session id), `LenExpiringSitewideChallenges` / `LenExpiringSitewideBlocks`
(host), and `LenExpiringUAChallenges` / `LenExpiringUABlocks` (User-Agent).

### Challenge-response authentication (SHA-inverse and password-protected paths)

There are currently two forms of challenge-response authentication which involve a back-and-forth
between banjax and the browser: a SHA-inverting proof-of-work challenge, and a basic password form.
The first is useful for denying access to simple bots which don't execute JavaScript, and the second is
useful for adding another layer of authentication in front of sensitive routes (for example, `wp-admin`).

`send_or_validate_password_page()` and `send_or_validate_challenge()` both basically work like:

```python
if cookie_contains_solved_challenge(cookie):
    return access_granted()
else:
    return 401, challenge page + new cookie
```

If a client fails too many challenges (exceeding `too_many_failed_challenges_threshold`), they are
blocked at the iptables level (or nginx level if the IP is in a per-site allowlist). This rate-limiting
applies to both SHA-inverse and password challenges.

### Regex-based rate-limits

One of the ways the decision lists are populated is by tailing an Nginx access log and applying regex-based
rate-limiting rules.  The log format expected looks like this:
```
1617871463.867 1.2.3.4 GET /wp-admin/ HTTP/1.1 Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) -
```

and a rule looks like this:
```yaml
- decision: challenge
  hits_per_interval: 800
  interval: 30
  regex: .*
  rule: "All sites/methods: 800 req/30 sec"
```

Decisions correspond to those mentioned above: "allow", "challenge", "nginx_block", "iptables_block".

The log tailing loop basically looks like this:
```python
for log_line in lines(log_file):
    for rule in rules:
        if not rule.regex.match(log_line):
            continue

        rule_state = ip_to_rule_states[ip][rule]
        if (rule_state == None) or (log_line.timestamp - rule_state.interval_start_time > rule.interval):
            rule_state = {num_hits: 1, interval_start_time: log_line.timestamp}
        else:
            rule_state.num_hits++

        if rule_state.num_hits > rule.hits_per_interval:
            global_decision_lists[ip] = rule.decision
```

The actual code has some extra stuff to deal with adding/removing iptables rules and clearing stale decisions
from the Nginx cache.

Regex-triggered decisions are stored in the expiring decision list with a TTL controlled by
`expiring_decision_ttl_seconds`. After the TTL expires, the decision is removed and any static
decision from the config file takes effect again.
