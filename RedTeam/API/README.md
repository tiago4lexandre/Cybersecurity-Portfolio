<!-- ===================================== -->
<!--        API SECURITY - PENTEST        -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Scenario-API%20Security%20Assessment-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Environment-Web%20Application%20Testing-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Role-Pentester%20%7C%20Security%20Researcher-black?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-API%20Discovery%20%26%20Exploitation-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Framework-Recon%20%7C%20Enumeration%20%7C%20Auth%20Testing-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Methodology-OWASP%20API%20Security%20Top%2010-informational?style=flat-square">
</p>

---

# 🔎 API Security: Descoberta, Enumeração e Exploração
## Metodologia Estruturada para Testes de Segurança em APIs Modernas

> Este documento apresenta um guia técnico completo para a análise de segurança em **APIs REST e GraphQL**, abordando desde o reconhecimento inicial até a exploração de vulnerabilidades críticas.
>
> O objetivo é aplicar uma metodologia estruturada de Pentest focada na superfície de ataque exposta por APIs, incluindo:
>
> - Reconhecimento e coleta de informações (OSINT)
> - Descoberta e enumeração de endpoints
> - Fuzzing de parâmetros e recursos ocultos
> - Testes de autenticação e autorização
> - Exploração de falhas como BOLA, BFLA, Injeções e JWT mal configurados
>
> O foco não está apenas na execução de ferramentas, mas em **compreender a lógica de negócio e identificar falhas que scanners automatizados frequentemente não detectam**.

---

## 🎯 Objetivo Técnico do Documento

Durante a construção deste material, são trabalhadas as seguintes competências:

- 🌐 Mapeamento da superfície de ataque de APIs
- 🔍 Descoberta ativa e passiva de endpoints
- 🧪 Fuzzing estruturado de parâmetros
- 🔐 Testes avançados de autenticação e autorização
- 🧠 Análise de falhas de lógica de negócio
- 📊 Documentação técnica de vulnerabilidades com impacto real

---

⚠️ Este material tem fins educacionais e deve ser utilizado apenas em ambientes autorizados para testes de segurança.

---
# APIs: Descoberta, Enumeração e Exploração

## Introdução

### 1.1. Por que Focar em APIs?

As APIs (Application Programming Interfaces) são a espinha dorsal da aplicação moderna, conectando serviços, transferindo dados e impulsionando a lógica de negócios. Por serem um alvo de alto valor e, muitas vezes, apresentarem falhas de implementação complexas, as APIs se tornaram o principal vetor de ataques a aplicações web. Diferente de um ataque a uma interface de usuário tradicional, um ataque a uma API visa a lógica de negócio e as camadas de autorização, que scanners automáticos frequentemente não conseguem detectar. Exemplos famosos, como as breaches da T-Mobile (37 milhões de registros expostos) e Optus (9.8 milhões), ocorreram devido a falhas simples de autorização em endpoints de API.

### 1.2. A Metodologia de Teste

Uma abordagem estruturada é fundamental para um pentest eficaz. O processo pode ser dividido em quatro fases principais:

1. **Reconhecimento (Recon):** Coletar o máximo de informações sobre o alvo de forma passiva e ativa.
2. **Descoberta e Enumeração:** Mapear a superfície de ataque, encontrando endpoints, parâmetros e versões de API.
3. **Manipulação e Testes:** Interceptar e modificar requisições para testar a lógica de negócio, autenticação e autorização.
4. **Exploração:** Aprofundar-se em vulnerabilidades específicas para confirmar e demonstrar o impacto.

---
## 2. Fase 1: Reconhecimento e Coleta de Informações (Recon)

O objetivo aqui é entender o máximo possível sobre a API antes de enviar uma requisição.

### 2.1. Fontes de Informação (OSINT)

- **Documentação da API:** Procure por arquivos como `swagger.json`, `swagger.yaml`, `openapi.json`, ou acesse endpoints como `/api/docs`, `/swagger`, `/redoc`. A documentação é um "mapa do tesouro" para o pentester.

- **Arquivos JavaScript (JS):** Aplicações web carregam suas lógicas em JS. Use ferramentas para extrair endpoints e parâmetros a partir desses arquivos.

- **Google Dorks:** Utilize operadores de busca para encontrar referências expostas.    
    - `site:target.com inurl:api`
    - `site:target.com filetype:json`
    - `"target.com" "api_key"`

- **GitHub e Repositórios:** Procure por chaves, tokens, ou trechos de código da empresa-alvo que possam ter sido vazados.
 
- **Wayback Machine/Arquivos Históricos:** Endpoints antigos, que podem ainda estar ativos, podem ser encontrados em serviços como o Wayback Machine. Ferramentas como `gau` e `waybackurls` automatizam essa coleta.

### 2.2. Ferramentas para Descoberta de URLs e Parâmetros

- **`gau` (Get All Urls):** Busca URLs conhecidas de múltiplas fontes (AlienVault, WayBack, etc.).

```bash
gau target.com | grep -E '\.json|/api/|/v1/'
```

- **`ParamSpider`:** Ferramenta para minerar parâmetros em URLs de arquivos web.

```bash
python3 paramspider.py -d target.com -o output.txt
```

- **`Katana`:** Um crawler avançado que pode descobrir endpoints tanto passiva quanto ativamente.

---
## 3. Fase 2: Descoberta e Enumeração de Endpoints

Esta fase envolve "força bruta" para encontrar recursos não documentados.

### 3.1. Fuzzing de Diretórios e Arquivos

Ferramentas como `ffuf`, `gobuster` ou `dirsearch` são usadas para testar milhares de caminhos possíveis em busca de diretórios e arquivos ocultos.

**Exemplo com ffuf:**

```bash
ffuf -u https://target.com/api/FUZZ \
	-w /usr/share/wordlists/api_endpoints.txt \
	-fc 404
```


- `-u`: A URL alvo, onde `FUZZ` é o local onde o conteúdo da wordlist será inserido.
- `-w`: Caminho para a wordlist.
- `-fc 404`: Filtra (esconde) respostas com código 404, mostrando apenas o que interessa (200, 403, 500, etc.).

**Exemplo de resultado:**

```text
admin                  [Status: 200, Size: 2543]
v1                     [Status: 401, Size: 60]
internal               [Status: 403, Size: 60]
swagger.json           [Status: 200, Size: 12893]
graphql                [Status: 400, Size: 100]
```

### 3.2. Fuzzing de Subdomínios e VHOSTs

APIs podem estar hospedadas em subdomínios como `api.target.com`, `dev-api.target.com`, `graphql.target.com`.

**Exemplo com ffuf para VHOST:**

```bash
ffuf -u https://target.com \
	-H "Host: FUZZ.target.com" \
	-w subdomains.txt \
	-fc 200
```

Este comando procura por subdomínios que respondam com um código diferente de 200, indicando que podem existir.

### 3.3. Fuzzing de Parâmetros

Encontrar parâmetros ocultos que uma API aceita pode levar a funcionalidades não intencionais ou vulnerabilidades.

**Exemplo com ffuf:**

```bash
ffuf -u 'https://target.com/api/user?FUZZ=1' \
	-w params.txt \
	-fs 635
```

- `-fs 635`: Filtra respostas com um tamanho específico (o tamanho da resposta para um parâmetro inválido).

### 3.4. Ferramentas Especializadas em API

- **Kiterunner:** Uma ferramenta feita especificamente para descobrir endpoints e recursos de API, utilizando wordlists comuns de APIs (como `api/objects`). Ele é mais eficiente que ferramentas de fuzzing web tradicionais para esse fim.

- **Enumageddon:** Ferramenta que combina fuzzing de URL com enumeração de serviços cloud (AWS S3, Azure Blobs, GCP Buckets).

**Exemplo com Enumageddon:**

```bash
enumageddon -u https://target.com/api/FUZZ -x json,xml,html -t 50
```

- `-x`: Extensões de arquivo para adicionar ao final do fuzzing.    
- `-t`: Número de threads.

Para enumeração de cloud:

```bash
enumageddon -k targetcompany --aws --gcp --azure
```

Este comando testa variações de nomes de buckets, como `targetcompany-backup`, `targetcompany-dev`, etc.

---
## 4. Fase 3: Manipulação de Requisições e Testes Manuais

Esta é a fase onde a análise humana se torna indispensável para encontrar falhas de lógica.

### 4.1. Interceptação e Modificação com Proxy

Ferramentas como **Burp Suite** e **OWASP ZAP** são o padrão-ouro para interceptar o tráfego entre seu navegador/aplicação e o servidor.

- **Proxy:** Configure seu navegador para rotear o tráfego pelo Burp/ZAP.
- **Repeater:** Envie uma requisição interceptada para o Repeater para modificá-la manualmente e reenviá-la várias vezes, observando as diferentes respostas.
- **Intruder:** Use para automatizar ataques de força bruta ou fuzzing em campos específicos de uma requisição (por exemplo, testar centenas de IDs de usuário).

### 4.2. Testes de Autenticação e Autorização

Esta é a área mais crítica e onde a maioria das breaches ocorre.

- **Autenticação:** Teste se é possível burlar o login (ex: SQL Injection), se tokens JWT podem ser forjados ou manipulados (algoritmo "none", fraquezas na assinatura), ou se chaves de API estão expostas.

- **Autorização:**    
    - **BOLA (Broken Object Level Authorization):** Teste se um usuário comum pode acessar ou modificar objetos de outro usuário alterando um ID na URL ou no corpo da requisição.
        - **Cenário:** `GET /api/user/123` -> `GET /api/user/456`

    - **BFLA (Broken Function Level Authorization):** Teste se um usuário comum pode acessar funções administrativas.        
        - **Cenário:** `GET /api/admin/users` -> `DELETE /api/users/1` (tentando excluir um usuário como não-admin)

### 4.3. Exemplos de Cenários de Ataque

**Cenário 1: Exposição de Dados por Falha de Autorização**  
Um aplicativo de e-commerce permite que usuários vejam seus pedidos. Um analista intercepta a requisição:

```text
GET /api/orders/12345 HTTP/1.1
Host: target.com
Cookie: session=ABC123
```

Ao alterar o ID do pedido para `12346`:

```text
GET /api/orders/12346 HTTP/1.1
```

Se a resposta retornar os dados do pedido de outro usuário, encontramos uma vulnerabilidade **BOLA** crítica.

**Cenário 2: Quebra de Autenticação JWT**  
Um token JWT tem a seguinte estrutura (HEADER.PAYLOAD.SIGNATURE). Um atacante pode modificar o header para usar o algoritmo `none` e remover a assinatura.

```json
// HEADER Original
{
  "alg": "HS256",
  "typ": "JWT"
}
// HEADER Modificado
{
  "alg": "none",
  "typ": "JWT"
}
```

Se o servidor aceitar tokens sem assinatura, o atacante pode forjar qualquer identidad.

---
## 5. Fase 4: Exploração de Vulnerabilidades Específicas

### 5.1. Injeção (SQL, NoSQL, Comandos)

APIs que não validam corretamente a entrada do usuário são suscetíveis a ataques de injeção.

- **SQL Injection:** Adicionar um caractere de escape (`'`) em um parâmetro e observar se um erro de banco de dados é retornado. Ferramentas como `sqlmap` automatizam a detecção e exploração.

```bash
sqlmap -u "https://target.com/api/user?id=1" --dbs
```

- **NoSQL Injection:** Comum em APIs que usam MongoDB. Teste com operadores como `{"$ne": null}` em corpos de requisições JSON.

### 5.2. Quebra de Autenticação e Gestão de Sessão

- **Força Bruta:** Teste se há rate limiting no endpoint de login. Use o **Burp Intruder** ou `ffuf` para testar centenas de senhas comuns.
- **Falha na Renovação de Token:** Um token de logout deve ser invalidado no servidor. Teste reutilizar um token antigo.

### 5.3. Exposição Excessiva de Dados

APIs frequentemente retornam objetos de banco de dados inteiros, contendo mais dados do que o necessário para o cliente.

- **Ação:** Examine as respostas da API em busca de campos sensíveis como `password_hash`, `credit_card_number`, `internal_id`, `api_key`, mesmo que eles não sejam exibidos na interface do usuário.

### 5.4. Ataques de Rate Limiting e DoS

APIs sem limites de taxa são vulneráveis a scraping de dados e ataques de negação de serviço.

- **Teste:** Utilize scripts ou ferramentas para enviar centenas de requisições rapidamente (`ffuf` com alta taxa de threads, ou scripts em Python) e observe se a API começa a responder lentamente ou com erros.

---
## 6. Principais Ferramentas e Exemplos Práticos

### 6.1. ffuf (Fuzz Faster U Fool)

Ferramenta rápida para fuzzing web.

- **Fuzzing de diretórios:**

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt
```

- **Fuzzing com extensões:**

```bash
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.json
```

- **Fuzzing de parâmetros POST:**

```bash
ffuf -u https://target.com/api/login \
	-X POST \
	-d "user=admin&password=FUZZ" \
	-w passwords.txt \
	-fc 401
```

### 6.2. Kiterunner

Focado em APIs, usa wordlists contextuais.

- **Escaneamento:**

```bash
kr scan https://target.com -w /usr/share/kiterunner/routes-large.kite
```

### 6.3. Burp Suite

- **Proxy:** Para ver e modificar tráfego HTTP/HTTPS.
- **Repeater:** Para testar manualmente variações de uma mesma requisição.
- **Intruder:** Para ataques automatizados de força bruta e fuzzing.

### 6.4. Enumageddon

- **Fuzzing Web:**

```bash
enumageddon -u https://target.com/FUZZ -x php,html,json
```

- **Enumeração Cloud:**

```bash
enumageddon -k empresa -k startup --aws --azure -o buckets.json
```


### 6.5. Outras Ferramentas Essenciais

- **Postman:** Para organizar coleções de requisições e explorar APIs de forma estruturada.
- **JWT_Tool:** Ferramenta especializada para testar a segurança de JSON Web Tokens.
- **Nuclei:** Scanner de vulnerabilidades baseado em templates, com muitos templates específicos para APIs.

---
## 7. Checklist do Pentest em API

| Fase                  | Atividade                                                  | Status |
| --------------------- | ---------------------------------------------------------- | ------ |
| **Recon**             | Coletar documentação (Swagger, OpenAPI)                    | ☐      |
|                       | Extrair endpoints de arquivos JS                           | ☐      |
|                       | Pesquisar por informações vazadas no GitHub                | ☐      |
|                       | Usar gau/waybackurls para endpoints históricos             | ☐      |
| **Enumeração**        | Fuzzing de diretórios/arquivos (ffuf, dirsearch)           | ☐      |
|                       | Fuzzing de subdomínios                                     | ☐      |
|                       | Fuzzing de parâmetros ocultos                              | ☐      |
|                       | Usar Kiterunner/Enumageddon para endpoints de API          | ☐      |
| **AuthN/AuthZ**       | Testar BOLA (alterar IDs de objetos)                       | ☐      |
|                       | Testar BFLA (acessar funções de admin)                     | ☐      |
|                       | Testar força de senhas e rate limiting no login            | ☐      |
|                       | Testar vulnerabilidades em JWT (alg: none, força da chave) | ☐      |
| **Input Validation**  | Testar injeções (SQL, NoSQL, Comandos)                     | ☐      |
|                       | Fuzzar todos os parâmetros para XSS                        | ☐      |
| **Lógica de Negócio** | Tentar burlar fluxos de compra/pagamento                   | ☐      |
|                       | Testar reuso de cupons/descontos                           | ☐      |
| **Configuração**      | Verificar métodos HTTP não autorizados (PUT, DELETE)       | ☐      |
|                       | Analisar respostas para exposição excessiva de dados       | ☐      |
|                       | Verificar headers de segurança (CORS, HSTS)                | ☐      |

---
## 8. Conclusão e Boas Práticas

O teste de penetração em APIs é uma disciplina que vai além do uso de scanners automatizados. Exige um profundo entendimento da lógica de negócio, da arquitetura da aplicação e um pensamento criativo para explorar falhas de autorização e lógica que máquinas não conseguem detectar.

**Boas Práticas Finais:**

- **Tenha Autorização:** Sempre obtenha permissão por escrito antes de testar qualquer sistema.
- **Mantenha-se Atualizado:** Consulte regularmente o **OWASP API Security Top 10** para entender as vulnerabilidades mais críticas do momento.
- **Documente Tudo:** Um bom relatório, com passos de reprodução claros e evidências (prints, requests/responses), é tão importante quanto encontrar a vulnerabilidade.
- **Automatize com Sabedoria:** Use ferramentas automatizadas para tarefas repetitivas (fuzzing, scanning), mas reserve seu tempo e inteligência para a análise manual e testes de lógica. A combinação de ambos os métodos é a chave para um pentest de alta qualidade.

