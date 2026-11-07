### The `auth_request` endpoint that Nginx talks to

Nginx `proxy_pass`es to banjax, which makes a decision (Allow, Challenge, AltChaChallenge, TooManyRequests, NginxBlock, or IptablesBlock)
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
if decision == AltChaChallenge:
    return send_or_validate_altcha_challenge()
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
if decision == Allow and sites_to_rate_limit_global_allowlist[requested_host]:
    if expiring_ip_host_decision_lists[client_ip, requested_host] == TooManyRequests:
        return too_many_requests()
# [...] same as above

decision = global_user_agent_decision_lists[client_user_agent]
# [...] same as above

# The expiring decision lists are checked narrowest scope first: session id,
# then User-Agent, then host, then IP (or a subnet covering it). Note that a
# "baskerville is disabled for this site" skip does not return; it falls through
# to the next check below.
# Wherever Challenge is handled below, AltChaChallenge is handled the same way, with
# send_or_validate_altcha_challenge() in place of send_or_validate_challenge().

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

decision = expiring_user_agent_decision_lists[(client_user_agent, requested_host)]
if decision == Challenge:
    # [...] same as above, falling through to the host check below
if decision in [NginxBlock, IptablesBlock]:
    # [...] same as above, falling through to the host check below

decision = expiring_host_decision_lists[requested_host]
if decision == Challenge:
    # [...] same as above, falling through to the IP check below

decision = expiring_decision_lists[client_ip]
# a block_subnet/challenge_subnet acts as if sent for every IP in the subnet,
# so the most severe of the IP's own entry and any covering subnet entry wins
decision = max(decision, expiring_decision_lists_subnet[subnet containing client_ip])
if decision == Allow:
    return access_granted()
if decision == Challenge:
    if per_site_sha_inv_path_exceptions[requested_host][requested_path]:
        return access_granted()
    if sites_to_disable_baskerville[requested_host] and decision.from_baskerville:
        pass  # skip challenge, fall through to the sitewide checks below
    else:
        return send_or_validate_challenge()
if decision == TooManyRequests:
    return too_many_requests()
if decision in [NginxBlock, IptablesBlock]:
    if sites_to_disable_baskerville[requested_host] and decision.from_baskerville:
        pass  # skip block, fall through to the sitewide checks below
    else:
        return access_denied()

# sitewide_altcha_list is checked first, so a site listed in both gets the AltCha challenge
if sitewide_altcha_list[requested_host]:
    # block, no_block, block_click or no_block_click: fail_action Block or Allow, and _click
    # serves the one-click checkbox instead of solving on page load
    fail_action = sitewide_altcha_list[requested_host].fail_action
    if password_protected_path_exceptions[requested_host][requested_path]:
        return access_granted()
    else:
        return send_or_validate_altcha_challenge(fail_action)

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
AltChaChallenge → Challenge → Allow; the first matching pattern wins.

The expiring User-Agent and host lists are separate from those static lists. They are populated only by
Kafka commands (see below), they match the User-Agent string exactly (no substring or regex matching),
and their entries disappear when their TTL expires. An expiring User-Agent entry only applies to the
host given in the command.

`access_granted()` returns a response with a header: `X-Accel-Redirect: @access_granted` which instructs
Nginx to perform an internal redirect to the location block named `@access_granted`. That block should
`proxy_pass` to the upstream origin site.

`access_denied()` works similarly, but the `@access_denied` block might just return a "403, access denied"
response.

`too_many_requests()` is answered by banjax itself, like a challenge page: a 429 with a plain HTML page
(no JavaScript to solve, `too_many_requests_html` to override it) and a `Retry-After` header set to the
time left on the decision. TooManyRequests only comes from the regex rate limits; the static decision
lists reject it.

`send_or_validate_altcha_challenge()` is `send_or_validate_challenge()` with an ALTCHA v2 proof-of-work page
(cookie `deflect_altcha`, `altcha_max_number` / `altcha_cost` difficulty, `altcha_challenge_html` to override
the page). The page runs the official ALTCHA widget, loaded from jsDelivr pinned to one version with a
Subresource Integrity hash. By default it solves on page load; a decision with the click option
(Kafka `altcha_click`, or a `*_click` `sitewide_altcha_list` entry) shows the widget's one-click
checkbox instead, and only solves once the visitor ticks it. Either way it solves a PBKDF2/SHA-256
challenge in Web Workers: banjax picks a secret
counter in 0..`altcha_max_number`, and the client derives keys of `altcha_cost` iterations from 0 upwards
until one matches. The widget needs a secure context (`crypto.subtle`), so the AltCha challenge only
works over HTTPS; over plain HTTP the page shows a "verification failed" message. A solution is checked
with one HMAC (the challenge carries a signature of its derived key), never by re-running the key
derivation, and must carry the binding (IP or User-Agent) in its signed data.
It is a stronger, independent challenge: a solved sha-inv cookie does not pass it (while a solved
AltCha cookie does pass a sha-inv challenge, reported as `ShaChallengePassedByAltCha`), and its failures are
counted on their own against `altcha_too_many_failed_challenges_threshold` within
`altcha_too_many_failed_challenges_interval_seconds` (3 and 10 when unset or not positive, since a
zero threshold would ban on the first, cookie-less request). Exceeding it gets the IP an IptablesBlock
(an NginxBlock if the IP is allowlisted in the per-site list), like too many failed sha-inv challenges.
AltChaChallenge can be used in the static IP and User-Agent lists, in regex rules, and from Kafka.
Overall severity is Allow < Challenge < AltChaChallenge < TooManyRequests < NginxBlock < IptablesBlock.

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
messages on `kafka_command_topic`. Each command writes into one of the five expiring decision lists
checked above:

| Command | Keyed on | Decision | List |
| --- | --- | --- | --- |
| `challenge_ip` | `value` (IP) | Challenge | IP |
| `block_ip` | `value` (IP) | NginxBlock | IP |
| `challenge_subnet` | `value` (IPv4 CIDR) | Challenge | subnet |
| `block_subnet` | `value` (IPv4 CIDR) | NginxBlock | subnet |
| `challenge_session` | `session_id` | Challenge | session id |
| `block_session` | `session_id` | NginxBlock | session id |
| `challenge_ua` | `ua` + `host` | Challenge | User-Agent |
| `block_ua` | `ua` + `host` | NginxBlock | User-Agent |
| `challenge_all` | `host` | Challenge | host |
| `altcha_challenge_ip` | `value` (IP) | AltChaChallenge | IP |
| `altcha_challenge_subnet` | `value` (IPv4 CIDR) | AltChaChallenge | subnet |
| `altcha_challenge_session` | `session_id` | AltChaChallenge | session id |
| `altcha_challenge_ua` | `ua` + `host` | AltChaChallenge | User-Agent |
| `altcha_challenge_all` | `host` | AltChaChallenge | host |
| `clear_rules` | any of `host`, `value`, `session_id`, `ua` | — | removes entries |

The `altcha_challenge_*` commands take an optional integer `altcha_max_number`: the difficulty of the
challenge served while that decision lasts, in place of `altcha_max_number` from the config. It is
clamped to 1000..20000 (out-of-range values become the nearest limit) and ignored by every other
command. They also take an optional boolean `altcha_click`: true serves the one-click checkbox
challenge instead of the default one that solves on page load. And an optional boolean
`altcha_force_new`: true rejects AltCha cookies whose challenge was minted before the command arrived
(each challenge carries a signed `issued_at`), so clients that already passed must solve a new one;
the new cookie is then accepted. Without it a valid cookie keeps passing a new decision until it
expires. Writes still never downgrade, but an `altcha_challenge_*` command for a key that already
holds an AltChaChallenge with a different difficulty, click mode or force-new time replaces it, so
resending the command changes them (and each resent `altcha_force_new` forces another new challenge).

`challenge_all` is the temporary, Kafka-driven equivalent of the `sitewide_sha_inv_list` config
entry: it challenges every request to a host until the TTL expires, without editing the config file.
The host list only acts on a Challenge or AltChaChallenge decision; the User-Agent list only acts on
those two and the two block decisions (an Allow there is ignored). The `altcha_challenge_*` commands
use the same `expiring_decision_ttl_seconds` default TTL as the `challenge_*` ones.

`block_subnet` / `challenge_subnet` cover every IP in a subnet with one command, e.g. a botnet
rotating through a `/24` to evade per-IP blocks. The value is normalized to its network address
(`202.46.62.7/24` is stored as `202.46.62.0/24`); IPv6 subnets and anything broader than `/16` are
rejected. The subnet list is checked in the same step as the IP list and acts as if the command had
been sent for every IP in the subnet: when both an IP entry and one or more covering subnet entries
exist, the most severe decision wins. Subnet matches are reported as `ExpiringSubnetChallenge` /
`ExpiringSubnetAltChaChallenge` / `ExpiringSubnetBlock`.

Writes never downgrade an existing entry: a new decision is only stored if it is more severe than
the one already in the list for that key.

`clear_rules` takes any combination of `host`, `value` (IP, or subnet if it contains a `/`),
`session_id`, and `ua`, and clears each one it is given from the corresponding expiring list. A `ua`
is cleared only on `host` when one is given, and on every host otherwise. The `/unban` HTTP API does
the same thing for a single `ip`, `host`, `ua` (optionally scoped by `host`), or `subnet` form field.
Clearing an IP does not clear a subnet covering it, and vice versa.

`challenge_ua` / `block_ua` without a `host` are dropped.

Each command's lifetime comes from the config (`expiring_decision_ttl_seconds` for challenges,
`block_ip_ttl_seconds` / `block_session_ttl_seconds`, optionally overridden per site by
`sites_to_block_ip_ttl_seconds` / `sites_to_block_session_ttl_seconds` for blocks; `block_subnet`
uses the `block_ip` ones). A command may
carry a `ttl` field (in seconds) to override that on a per-message basis; any positive value wins
over the config default.

Commands for a host listed in `sites_to_disable_baskerville` are dropped on arrival, and any
Baskerville-origin decision already in an expiring list is skipped at decision time for such a host.
This includes `clear_rules`: one whose `host` is such a site is dropped as a whole, including its
`value` / `ua` / `session_id` fields.

The lengths of the expiring lists are reported in the metrics log as `LenExpiringChallenges` /
`LenExpiringBlocks` (IP and session id), `LenExpiringSitewideChallenges` / `LenExpiringSitewideBlocks`
(host), `LenExpiringUAChallenges` / `LenExpiringUABlocks` (User-Agent), and
`LenExpiringSubnetChallenges` / `LenExpiringSubnetBlocks` (subnet). `LenExpiringTooManyRequests`
(IP and IP+host).

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

With `two_step_ban_esculation: true` the failed-challenge ban is only an nginx-level block
(`FailedChallengeBlock`). It is checked right after a valid password cookie and before the
password paths, the static lists and the expiring lists, so the IP is not served challenges while
it is blocked; protected IPs and IPs allowlisted on the requested host are exempt. Other expiring
blocks keep their usual place. With
`too_many_403_ban_to_iptables_ban: true`, any IP that banjax answers with more than
`too_many_403_ban_threshold` 403s within `too_many_403_ban_interval_seconds` is escalated to an
iptables ban (never for protected IPs or IPs in the per-site allowlist for the requested host).

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

Decisions correspond to those mentioned above: "allow", "challenge", "too_many_requests", "nginx_block",
"iptables_block".

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

IPs that a static list allows are skipped by the log tailer. The one exception is an IP in the global
allow list (exact IP or CIDR) requesting a site listed in `sites_to_rate_limit_global_allowlist`. This
is meant for verified bots, which share their IPs across every site:
  * hits are counted per IP+site rather than per IP,
  * whatever the rule's decision (other than "allow"), the IP gets TooManyRequests, stored in a
    separate IP+site expiring list, so it only applies to that one site and is never an iptables ban,
  * an IP in the site's per-site allow list stays exempt.

`/unban` and Kafka `clear_rules` for an IP also clear its IP+site entries.
