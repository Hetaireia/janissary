# Track B - Cloudflare setup (free tier, defaults)

The benchmark tests Cloudflare free tier in its **default configuration**.
Any custom rule, Bot Fight Mode tweak, or "I'm Under Attack" toggle
invalidates the run. The pre-registration is explicit on this point.

## 1. VPS baseline

- Small VPS (1 vCPU / 1 GB is enough for Juice Shop).
- Docker + Docker Compose installed.
- Firewall: allow 22 (SSH), 80, 443. Block 8080 from the public internet.
- Restrict 8080 to Cloudflare's IP ranges (see section 4).

## 2. Cloudflare DNS

1. A record for `juice.<yourdomain>` -> VPS public IP.
2. Proxy status: Proxied (orange cloud). DNS-only disables the WAF.
3. SSL/TLS mode: Flexible. Cloudflare terminates TLS for the public
   hostname and speaks HTTP to the origin.
4. Universal SSL: on (default).
## 3. Security settings

Leave every default. Specifically:

| Setting                 | Leave as |
|-------------------------|----------|
| Security Level          | Medium |
| Bot Fight Mode          | Off |
| Challenge Passage       | 30 min |
| Browser Integrity Check | On |
| WAF managed rules       | Default free-tier ruleset |
| Always Use HTTPS        | Off (Flexible default) |

If you change any of these, add a CF_NOTE= line to tools.env so the run
manifest records the divergence. A changed default is a custom rule.

## 4. Origin lock

Restrict port 8080 to Cloudflare IPs at the VPS firewall:

```bash
curl -s https://www.cloudflare.com/ips-v4 -o /tmp/cf-v4
curl -s https://www.cloudflare.com/ips-v6 -o /tmp/cf-v6
for ip in $(cat /tmp/cf-v4); do sudo ufw allow from "$ip" to any port 8080 proto tcp; done
for ip in $(cat /tmp/cf-v6); do sudo ufw allow from "$ip" to any port 8080 proto tcp; done
sudo ufw deny 8080/tcp
```

## 5. Pre-flight

Confirm Cloudflare is actually protecting the target:

```bash
curl -I "https://juice.<yourdomain>/"
for i in $(seq 1 200); do
  curl -s -o /dev/null -w "%{http_code}\n" "https://juice.<yourdomain>/?probe=$i"
done | sort | uniq -c
```

## 6. Between runs

Reset the target and let IP reputation decay. Run from
`benchmark/track_b`:

    docker compose down -v && docker compose up -d

Wait 5+ minutes between tools. Otherwise tool #2 starts from an
already-warm reputation and the comparison is invalid.

## 7. IP rotation

No proxy for official runs. If the operator IP is permanently banned
during tool #1, discard the run, log it in runs/, and re-execute from a
fresh IP after the ban expires. See BENCHMARK.md for the discard rule.
