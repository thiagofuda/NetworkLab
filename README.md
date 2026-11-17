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

Shows the client IP observed by the service. The web page also displays the
User-Agent, selected request headers, and request time.

- HTML: `GET /tools/ip`
- Plain text: `GET /api/ip`

Example request and response (the IP address is illustrative):

```text
$ curl https://xdb.com.br/api/ip
203.0.113.10
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

### AWS IAM Policy Validator

API para verificar a sintaxe JSON e regras estruturais de policies de identidade
do IAM. Não utiliza credenciais, não chama a AWS e não altera a policy enviada.

- Endpoint: `POST /api/aws/iam-validate`, com corpo UTF-8 `text/plain`.
- Envie somente policies que você esteja autorizado a compartilhar. Mesmo sem
  armazenamento intencional pela aplicação, os dados trafegam até o servidor e
  podem passar por proxies ou infraestrutura de terceiros.
- `valid: true` significa apenas que as verificações implementadas passaram. Não
  garante aceitação pela AWS, avaliação completa das permissões ou segurança.
- Limites: 32 KiB por requisição, profundidade JSON de 20, 100 statements e 50
  erros e avisos combinados. `truncated` indica diagnósticos omitidos; uma policy
  inválida continua com `valid: false`.
- A análise concluída retorna `200`, inclusive para JSON ou estrutura inválidos.
  Corpo ausente ou UTF-8 inválido retorna `400`, corpo excessivo retorna `413`
  e tipo de conteúdo não suportado retorna `415`. Um proxy configurado com
  limitação de requisições pode retornar `429`.

Exemplo válido, usando um arquivo local `policy.json`:

```json
{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}}
```

```bash
curl -X POST 'https://xdb.com.br/api/aws/iam-validate' \
  -H 'Content-Type: text/plain' --data-binary @policy.json
```

Resposta:

```json
{"valid":true,"errors":[],"warnings":[],"truncated":false}
```

Para testar localmente JSON inválido e estrutura inválida, respectivamente:

```bash
curl -X POST 'http://127.0.0.1:8000/api/aws/iam-validate' \
  -H 'Content-Type: text/plain' --data-binary '{"Statement":'
curl -X POST 'http://127.0.0.1:8000/api/aws/iam-validate' \
  -H 'Content-Type: text/plain' --data-binary '{"Statement":{"Effect":"Allow"}}'
```

Os objetos em `errors` e `warnings` incluem um `code` estável e uma mensagem;
posição, campo e sugestão são fornecidos quando disponíveis. A validação não
consulta o catálogo de ações ou recursos da AWS e não avalia o significado
específico de operadores e chaves em `Condition`.

### Terraform Plan Inspector

Analisa o JSON criado por `terraform show -json` sem executar Terraform, acessar
provedores ou armazenar o plano. AWS e OCI usam o mesmo analisador, com rotas
separadas:

- AWS: `POST /api/aws/terraform-plan-analyze`
- OCI: `POST /api/oci/terraform-plan-analyze`
- Envie o arquivo local diretamente como `application/json`; multipart não é
  suportado.

**Não envie planos corporativos reais nem informações confidenciais à API
pública.** Planos podem conter valores sensíveis em texto claro. A aplicação não
registra intencionalmente nem armazena o payload e não o envia a serviços
externos, mas o corpo trafega pelo servidor e pela infraestrutura de rede.

Exemplo para AWS:

```bash
curl -X POST 'https://xdb.com.br/api/aws/terraform-plan-analyze' \
  -H 'Content-Type: application/json' --data-binary @plan.json
```

Exemplo para OCI:

```bash
curl -X POST 'https://xdb.com.br/api/oci/terraform-plan-analyze' \
  -H 'Content-Type: application/json' --data-binary @plan.json
```

A resposta de análise inclui `valid`, provider identificado, contagem das seis
ações, recursos e findings. Cada recurso tem `resource_index` (índice começando
em zero no array `resource_changes`), para distinguir endereços após a
sanitização de chaves string de `for_each`. A resposta nunca inclui objetos
`before` ou `after`. Finding confirmado tem `status: "confirmed"`; verificações
de SSH sem dados suficientes ou com atributos relevantes desconhecidos/sensíveis
retornam `status: "inconclusive"` e severidade `warning`.

As duas ações de replace contam uma vez como `replace`, não como create e delete.
Exclusões e replacements geram findings genéricos; na rota AWS, exclusões ou
replacements de `aws_db_instance` e `aws_rds_cluster` geram `RDS_DELETION`, e
regras de Security Group com TCP/22 público geram `PUBLIC_SSH_ACCESS`. A rota OCI
retorna somente findings genéricos.

Limites: corpo de 1 MiB, profundidade JSON de 40, 500 entradas em
`resource_changes` e 100 findings. Se findings excederem o limite, `truncated`
será `true`; trate essa resposta como incompleta. Planos AWS + OCI são rejeitados
com `MIXED_CLOUD_PROVIDERS`; planos sem metadados suficientes retornam
`PROVIDER_UNIDENTIFIED`. Erros usam `{"detail":{"code":"...","message":"..."}}`
com códigos estáveis, incluindo `INVALID_JSON`, `NOT_TERRAFORM_PLAN`,
`UNSUPPORTED_FORMAT_VERSION`, `PROVIDER_MISMATCH`, `RESOURCE_LIMIT_EXCEEDED` e
`PAYLOAD_TOO_LARGE`. JSON inválido retorna `400`; documento não aceito retorna
`422`; tipo de conteúdo não suportado retorna `415`; corpo acima do limite retorna
`413`; rate limiting do proxy retorna `429`.

`valid: true` significa apenas que o documento foi reconhecido e analisado; não
significa que Terraform ou um provider aceitará o plano, nem que as mudanças são
seguras. Outputs e drift não são analisados. A verificação de SSH cobre apenas
formatos conhecidos de regras de Security Group AWS e não é um scanner completo.

### OCI IAM Policy Analyzer

Analisa uma lista de statements OCI IAM em `POST /api/oci/iam-policy-analyze`.
O corpo deve ser `application/json` no formato `{"statements":["..."]}`; não
envie um objeto completo de policy da OCI e não é necessário usar multipart.
O serviço não consulta uma tenancy OCI e não usa credenciais OCI.

**Esta ferramenta envia os statements ao Google Gemini usando o Free Tier.**
Segundo os termos atuais dos serviços não pagos do Google, o conteúdo enviado e
as respostas podem ser usados para melhorar produtos e podem ser lidos por
revisores humanos. **Não envie policies corporativas confidenciais, dados
pessoais ou informações que você não esteja autorizado a compartilhar.** O
InfraLab não armazena nem registra intencionalmente os statements, mas eles são
transmitidos ao Google para análise.

Exemplo de entrada com 10 statements:

```json
{
  "statements": [
    "Allow group Developers to inspect instances in compartment DEV",
    "Allow group Developers to read instances in compartment DEV",
    "Allow group Developers to manage instances in compartment DEV",
    "Allow group QA to inspect instances in compartment DEV",
    "Allow group Developers to read instances in compartment QA",
    "Allow group Production/Developers to read instances in compartment DEV",
    "Allow group Developers to use instances in compartment DEV where request.region='IAD'",
    "Allow group Developers to use instances in compartment DEV where request.region='GRU'",
    "Allow group Developers to manage all-resources in tenancy",
    "Allow group Developers to inspect instances in compartment DEV"
  ]
}
```

```bash
curl -X POST 'https://xdb.com.br/api/oci/iam-policy-analyze' \
  -H 'Content-Type: application/json' --data-binary @oci-policy.json
```

A análise retorna `status` como `completed` ou `inconclusive`. Duplicações
equivalentes após normalizar espaços fora de valores são confirmadas pelo Python.
Redundâncias e permissões amplas sugeridas pelo Gemini são sempre candidatas para
revisão humana, com `review_only: true`; não há policy corrigida pronta para
aplicação. As sugestões apontam somente para índices originais e as condições
`suggested_keep_indexes` identifica statements originais a manter em consideração;
não são instruções para excluir statements. As condições `where`, principal/domínio,
resource type e location precisam coincidir para uma redundância permanecer
candidata. Comparações não verificadas ficam inconclusivas. Resource-family
equivalence não é analisada. Se o Gemini retornar índices inválidos ou JSON
incompatível, a resposta será inconclusiva.

Limites locais: corpo de 32 KiB, até 50 statements, 2.048 caracteres por
statement, 16 KiB somados, 12.000 tokens de entrada e 2.048 tokens de saída. O
modelo padrão é `gemini-3.5-flash-lite`; `GEMINI_MODEL` permite substituí-lo. Não há
fallback automático para modelos pagos. Quota excedida retorna `429`; chave
ausente, credenciais sem acesso ou modelo indisponível retornam `503`; request
rejeitado pelo Gemini retorna `502` (`GEMINI_REQUEST_REJECTED` ou
`GEMINI_SCHEMA_REJECTED`); timeout total de 20 segundos retorna `504`.
Falha de conexão com o Gemini retorna `503` (`GEMINI_CONNECTION_FAILED`).
JSON malformado retorna `400`, entrada/schema inválidos `422`, tipo de conteúdo
não suportado `415`, e corpo ou tokens acima do limite `413`.
Erros usam `{"detail":{"code":"...","message":"..."}}`.

`completed` indica que o serviço recebeu uma resposta Gemini válida, não que os
statements sejam equivalentes ou seguros. `inconclusive` indica que a comparação
não pôde ser validada com segurança. Uma lista `findings` vazia significa apenas
que não houve findings nesta análise, não que a policy foi aprovada.

Para desenvolvimento local, copie `.env.example` para `.env`, restrinja o acesso
ao arquivo com `chmod 600 .env` e preencha `GEMINI_API_KEY` localmente. O arquivo
`.env` é ignorado pelo Git; nunca coloque a chave no código, em exemplos ou no
Compose versionado. A integração não registra statements ou mensagens de erro
do provedor nos logs.

Exemplo ilustrativo de resposta (as conclusões do Gemini podem variar):

```json
{
  "status": "completed",
  "findings": [
    {
      "code": "POTENTIAL_REDUNDANCY",
      "source": "gemini",
      "assessment": "candidate",
      "severity": "warning",
      "statement_indexes": [0, 1, 2],
      "message": "Review these statements together.",
      "explanation": "The verbs are ordered generally, but this is not proof of equivalence for every resource type.",
      "suggested_keep_indexes": [2],
      "review_only": true
    },
    {
      "code": "EXACT_DUPLICATE",
      "source": "python",
      "assessment": "confirmed",
      "severity": "warning",
      "statement_indexes": [0, 9],
      "message": "These statements are identical after safe whitespace normalization.",
      "explanation": "Only whitespace outside quoted values was normalized.",
      "suggested_keep_indexes": [0],
      "review_only": true
    }
  ],
  "analysis_limitations": [
    "TENANCY_NOT_QUERIED",
    "RESOURCE_FAMILY_EQUIVALENCE_NOT_EVALUATED"
  ]
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