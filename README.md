# InfraLab

I've been working on this personal lab for a while. It started with a few networking tools, and I gradually added other things related to AWS, OCI, Terraform, and security.

I had more time to work on it during my vacation, so I decided to put it online.

https://xdb.com.br

## Available tools

| Tool | What it does |
| --- | --- |
| IP Information | Shows the IP address seen by the server. |
| CIDR Calculator | Calculates IPv4 and IPv6 network information. |
| DNS Lookup | Looks up A, AAAA, MX, TXT, and CNAME records. |
| AWS IAM Policy Validator | Checks the JSON structure of AWS IAM policies. |
| Terraform Plan Inspector | Analyzes Terraform plans in JSON format for AWS and OCI, highlighting changes that may need attention. |
| OCI IAM Policy Analyzer | Uses Gemini to identify potentially redundant or overly broad permissions. |

The networking tools have simple web pages. The others are APIs that can be called from a terminal or a script.

Endpoints and request formats are available at https://xdb.com.br/docs.

## Usage examples

### IP Information

```bash
curl https://xdb.com.br/api/ip
```

### CIDR Calculator

```bash
curl 'https://xdb.com.br/api/cidr?cidr=192.168.10.25%2F24'
```

### DNS Lookup

```bash
curl 'https://xdb.com.br/api/dns?domain=example.com&record_type=MX'
```

### AWS IAM Policy Validator

Example policy JSON (`policy.json`):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
```

```bash
curl -X POST 'https://xdb.com.br/api/aws/iam-validate' \
  -H 'Content-Type: text/plain' \
  --data-binary @policy.json
```

### Terraform Plan Inspector

Example requests with a Terraform Plan JSON file (`plan.json`), such as the output of `terraform show -json`:

**AWS**

```bash
curl -X POST 'https://xdb.com.br/api/aws/terraform-plan-analyze' \
  -H 'Content-Type: application/json' \
  --data-binary @plan.json
```

**OCI**

```bash
curl -X POST 'https://xdb.com.br/api/oci/terraform-plan-analyze' \
  -H 'Content-Type: application/json' \
  --data-binary @plan.json
```

### OCI IAM Policy Analyzer — Gemini

Example OCI policy (`oci-policy.json`):

```json
{
  "statements": [
    "Allow group Developers to inspect instances in compartment DEV",
    "Allow group Developers to read instances in compartment DEV",
    "Allow group Developers to manage instances in compartment DEV"
  ]
}
```

```bash
curl -X POST 'https://xdb.com.br/api/oci/iam-policy-analyze' \
  -H 'Content-Type: application/json' \
  --data-binary @oci-policy.json
```

Gemini results are suggestions for review. This integration uses the free tier of Google AI Studio, which has usage limits. Quota or throttling errors may happen occasionally.

## Note

This is a public lab, so please don't use confidential or company data.

## Technologies

Python, FastAPI, Docker, Docker Compose, Nginx, GitHub Actions, Google Gemini, pytest, and Ruff.

The application runs on a small DigitalOcean VPS.

Server configurations are in the [homeLab repository](https://github.com/thiagofuda/homeLab).

## Running locally

```bash
git clone https://github.com/thiagofuda/NetworkLab.git
cd NetworkLab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
uvicorn app.main:app --reload
```

App: http://127.0.0.1:8000  
API docs: http://127.0.0.1:8000/docs

The Gemini endpoint uses `GEMINI_API_KEY`, configured in a local `.env` file based on `.env.example`.

Tests:

```bash
ruff check .
pytest -q
```

External services are mocked in tests, so a Gemini API key isn't needed to run them.

## About the project

I work with infrastructure and cloud, and I use this project to try out ideas that come up in my day-to-day work.

I've also used Copilot, Codex, and ChatGPT to help with development and code reviews.

There's still plenty to improve when I have some free time.
