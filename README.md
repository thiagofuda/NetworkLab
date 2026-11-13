# InfraLab

InfraLab is a personal project that I started in my free time to learn more
about Python and backend development with FastAPI.

I work with IT infrastructure, Linux, and cloud platforms, and I wanted to build
something that combines my daily work with my interest in programming.

The project started as NetworkLab, with a focus on networking tools. Over time,
I decided to expand it to include other infrastructure tools, cloud operations,
automation, and diagnostics.

The idea is simple: build useful tools, learn along the way, and share the
results. InfraLab is the public name; the repository, Python package, and
container image keep their existing NetworkLab names.

## Try it

The application is available at [xdb.com.br](https://xdb.com.br).

## Available Tools

### IP Information

Shows the client IP observed by the service, User-Agent, selected request
headers, and request time.

- HTML: `GET /tools/ip`
- JSON: `GET /api/ip`

Example response:

```json
{
  "ip_address": "203.0.113.10",
  "user_agent": "curl/8.0.0",
  "headers": {
    "accept": "*/*",
    "host": "xdb.com.br"
  },
  "requested_at": "2026-11-13T12:00:00+00:00"
}
```

### CIDR Calculator

Calculates network details for IPv4 and IPv6. Input addresses with host bits
are normalized to their network address. IPv4 results include a netmask and a
broadcast address when applicable; IPv6 has neither. The address count is
returned as text to preserve large IPv6 values.

- HTML: `GET /tools/cidr?cidr=192.168.10.25%2F24`
- JSON: `GET /api/cidr?cidr=192.168.10.25%2F24`
- IPv6 example: `2001:db8::1/64`
- Invalid input returns HTTP `422` from the API.

Example IPv4 response:

```json
{
  "input": "192.168.10.25/24",
  "ip_version": 4,
  "network_address": "192.168.10.0",
  "prefix_length": 24,
  "total_addresses": "256",
  "netmask": "255.255.255.0",
  "broadcast_address": "192.168.10.255"
}
```

### DNS Lookup

Looks up public DNS records using the resolver configured on the server. It
supports `A`, `AAAA`, `MX`, `TXT`, and `CNAME`; `A` is the default type.

- HTML: `GET /tools/dns?domain=example.com&record_type=A`
- JSON: `GET /api/dns?domain=example.com&record_type=A`
- Each record contains `value` and `ttl` in seconds.
- MX values include preference and mail exchanger, for example
  `10 mail.example.com.`. TXT segments are joined into one string, and CNAME
  values are fully qualified names.
- Invalid input returns `422`; nonexistent domains and record types return
  `404`; timeouts return `504`; resolver failures return `502`.
- Names with internal or special suffixes and unsupported record types are
  rejected. Responses are limited to 20 records and 1024 characters per value;
  `truncated` indicates when a limit was applied.

Example response (illustrative values):

```json
{
  "domain": "example.com",
  "record_type": "A",
  "status": "ok",
  "records": [
    {
      "value": "203.0.113.10",
      "ttl": 300
    }
  ],
  "error": null,
  "truncated": false
}
```

## Technologies

- Python 3.11+
- FastAPI and Pydantic Settings
- Jinja2, HTML, CSS, and Bootstrap
- dnspython
- Docker and Docker Compose
- Nginx and Let's Encrypt
- GitHub Actions and GitHub Container Registry (GHCR)
- pytest and Ruff

## Running Locally

```bash
git clone https://github.com/thiagofuda/NetworkLab.git
cd NetworkLab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The interactive API
documentation is available at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

## Tests

```bash
ruff check .
pytest -q
```

The suite includes unit tests for the services and API tests with FastAPI's
TestClient. DNS responses are mocked, so the tests do not depend on live DNS
queries.

## Infrastructure

InfraLab runs on a small DigitalOcean VPS called Dumbledore, using Ubuntu 26.04
LTS. Docker Compose runs the API, Nginx reverse proxy, and Certbot. HTTPS uses
Let's Encrypt, with a systemd timer checking certificate renewal. GitHub Actions
runs lint, tests, and container checks, publishes the image to GHCR, and deploys
updates from `main`.

The application source is in this repository. Server configuration is in my
[homeLab repository](https://github.com/thiagofuda/homeLab).

## What's Next?

These are ideas for the future, not available tools:

- SSL/TLS Certificate Checker
- HTTP Inspector
- Network and infrastructure diagnostics
- Read-only AWS and OCI diagnostics
- AI-assisted troubleshooting

The roadmap may change as I make progress.

## Development

This is a personal learning project, not a commercial product.

I use GitHub Copilot and ChatGPT to discuss ideas, review code, understand new
concepts, and help with development.

My goal is not just to make things work, but to understand what I'm building
and be able to maintain it myself.

Suggestions, feedback, and contributions are always welcome.