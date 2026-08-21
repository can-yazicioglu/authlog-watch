# authlog-watch

![CI](https://github.com/can-yazicioglu/authlog-watch/actions/workflows/ci.yml/badge.svg)

A command line tool that reads a Linux SSH auth log and reports which source IPs are showing brute force behaviour.

## Why

One failed SSH login is not much of a signal. People fat finger passwords all the time. What actually separates an attack from a mistake is not how many attempts happened, it is how many different accounts were tried from the same address. A real user who mistypes a password only ever retries the one account they meant to log into. An address that cycles through root, admin, oracle and postgres in the space of a minute is not a person who forgot their password, it is a script working down a wordlist, so username spread is treated here as the strongest signal in the tool rather than raw volume.

The other finding worth paying attention to above everything else is a successful login that comes right after a run of failures from the same address. Volume and username spread tell you an attack was attempted, they do not tell you whether it worked. A success following several failures means the credentials may have actually been guessed, which is the difference between an attack that bounced off and one that needs an incident response right now, so that case is always reported at the highest severity the tool has.

## Usage

```bash
# Scan the bundled sample log
authlog-watch samples/auth.log

# Read from stdin instead of a file
cat /var/log/auth.log | authlog-watch -

# Emit JSON for feeding into another tool
authlog-watch samples/auth.log --json

# Typical cron job: only mail when something critical shows up
authlog-watch --min-severity critical --no-color > /tmp/authlog-watch.out
if [ $? -eq 1 ]; then
    mail -s "authlog-watch: critical finding on $(hostname)" security@example.com < /tmp/authlog-watch.out
fi
```

Real output from running against the bundled sample log:

```
authlog-watch  scanned 66 lines, parsed 47 events

  CRITICAL  198.51.100.23   successful login as deploy after 6 failed attempts
            method=password  succeeded=2026-01-12T03:22:30  prior_failures=6

  HIGH      203.0.113.44    tried 14 distinct usernames
            tried=admin, administrator, ftpuser, git, guest, jenkins, mysql, oracle, postgres, root, support, test, ubuntu, webmaster

  MEDIUM    192.0.2.77      11 failed attempts as root
            span=02:00:00

  MEDIUM    203.0.113.44    25 failed attempts across 14 usernames
            span=00:03:36

  MEDIUM    203.0.113.44    7 failed attempts within a 60s window
            peak=7 attempts in 60s (7.0/min)

5 findings  (1 critical, 1 high, 3 medium)
```

## Detection rules

| Rule | Fires when | Severity |
| --- | --- | --- |
| `high_volume` | An IP has at least `--volume-threshold` total failures | Medium, or High above 3x the threshold |
| `burst` | An IP has at least `--window-threshold` failures inside any `--window-seconds` window | Medium |
| `username_spray` | An IP has tried at least `--spray-threshold` distinct usernames | High |
| `success_after_failures` | A success follows at least `--success-after-failures` failures from the same IP | Critical |

## Options

| Flag | Default | Meaning |
| --- | --- | --- |
| `path` | `/var/log/auth.log` | Log file to scan, or `-` for stdin |
| `--json` | off | Emit JSON instead of the text report |
| `--min-severity` | `low` | Drop findings below this level from output and from the exit code |
| `--volume-threshold` | `10` | Total failures from one IP to count as high volume |
| `--window-seconds` | `60` | Length of the burst detection window |
| `--window-threshold` | `5` | Failures inside the window to count as a burst |
| `--spray-threshold` | `5` | Distinct usernames from one IP to count as spraying |
| `--success-after-failures` | `3` | Failures before a success to flag it as critical |
| `--year` | current year | Year to assume for syslog timestamps that omit one |
| `--no-color` | off | Disable ANSI colour, also respects the `NO_COLOR` environment variable |
| `--version` | | Print the version and exit |

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | No findings at or above `--min-severity` |
| `1` | At least one finding at or above `--min-severity` |
| `2` | Usage error, missing file, or permission denied |

Exit code 1 for a real finding makes the tool usable directly from cron, a nonzero exit is what triggers cron's own mail-on-failure behaviour, and code 2 is kept distinct so a broken cron job (wrong path, no read permission) does not get silently confused with an actual detection.

## Log formats supported

Only lines emitted by `sshd` are read, everything else (`sudo`, `cron`, `systemd-logind`, and so on) is skipped. Two timestamp styles are recognised in the same file:

- Traditional syslog with no year, for example `Jan 12 03:14:02`, using `--year` (or the current year) to fill in the missing part, with a rollover correction for logs that cross into a new year.
- RFC 3339 as written by modern rsyslog and systemd, for example `2026-01-12T03:14:02.123456+00:00`.

## Development

```bash
git clone https://github.com/can-yazicioglu/authlog-watch.git
cd authlog-watch
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
pytest
```

## Design notes

There are zero runtime dependencies, on purpose. This is a tool meant to be dropped onto a server that is already having a bad day, so it should not need a package install, a virtual environment, or network access to run, a copy of the standard library is enough.

Detection is deliberately kept separate from parsing. The parser's only job is turning a line into a `LogEvent`, it knows nothing about thresholds or severities. Each detection rule is a plain function of a list of events and a config object, so a new rule can be added without touching the parser at all.

## Limitations

- Only OpenSSH password and public key events are understood, other authentication methods and other daemons are out of scope.
- Each source IP is judged on its own, there is no correlation across many IPs cooperating in the same attack.
- The tool has no state between runs, so scanning the same log twice reports the same findings twice, nothing is remembered.
- This is a detection aid, not an intrusion prevention system, it does not block, throttle, or otherwise act on anything it finds.

## Roadmap

- [ ] Correlate failures across many source IPs to catch distributed attacks
- [ ] GeoIP enrichment for source addresses
- [ ] A `--since` flag to limit the scan to a time range
- [ ] Read from the systemd journal directly, as an alternative to flat files
- [ ] A state file so repeated runs only report new activity

## License

MIT, see [LICENSE](LICENSE).
