# NetworkLab

NetworkLab is a personal project created to learn and improve backend development with Python and FastAPI.

The main idea is to build a collection of useful tools for Network Engineers, System Administrators and Cloud Engineers. Besides being a learning project, the goal is to provide practical utilities that can be used in day-to-day infrastructure and networking tasks.

## Technologies

* Python
* FastAPI
* Bootstrap
* Docker
* Nginx

## Current Status

This project is under active development.

The first version focuses on building the project structure and creating the foundation for future tools.

## Planned Tools

* What's My IP
* DNS Lookup
* SSL Certificate Checker
* Port Checker
* CIDR Calculator
* HTTP Request Inspector
* JWT Decoder
* Base64 Encoder / Decoder
* JSON Formatter

## Goals

* Learn modern Python development.
* Improve FastAPI knowledge.
* Apply clean code principles.
* Practice Docker and deployment.
* Build a useful and maintainable project.

Contributions, suggestions and feedback are always welcome.

## Ferramentas disponíveis

### IP Information

Exibe o endereço IP do cliente, User-Agent, cabeçalhos HTTP e a data e hora da
requisição.

- Interface web: `GET /tools/ip`
- API JSON: `GET /api/ip`

Exemplo de resposta da API:

```json
{
  "ip_address": "127.0.0.1",
  "user_agent": "curl/8.0.0",
  "headers": {
    "host": "localhost:8000",
    "user-agent": "curl/8.0.0"
  },
  "requested_at": "2026-07-31T18:00:00+00:00"
}
```
