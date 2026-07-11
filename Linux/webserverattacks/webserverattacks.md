<!--
title: Ataques a servidores web
desc: Técnicas de auditoria e testes de intrusão em servidores web (Apache/Nginx) hospedados em ambientes Linux.
tags: linux, web-sec, attacks
readTime: 7 min
-->

<!-- ===================================== -->
<!--   WEB SERVER FINGERPRINTING & MISCONFIG -->
<!-- ===================================== -->
<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Web%20Security-blue?style=for-the-badge">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Penetration%20Testing-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Beginner%20→%20Intermediate-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Lab%20Documentation-green?style=flat-square">
</p>

---

# 📚 Web Server Fingerprinting & Misconfigurações
## Reconhecimento em Apache, Nginx, Node.js e Python HTTP Server
> Da leitura de cabeçalhos HTTP à identificação de erros de configuração: um guia prático de reconhecimento em quatro dos servidores web mais comuns em infraestrutura Linux, sem entrar em exploração ou escalonamento de privilégios.

---
## Introdução

### O Contexto do Pentesting Web

Durante um teste de penetração, você **quase sempre** encontrará pelo menos um servidor web. Às vezes, trata-se de um servidor Apache em produção com configuração cuidadosa. Às vezes, é um servidor HTTP Python esquecido que um desenvolvedor criou há dois anos e nunca desligou. **Ambos estão dentro do escopo. Ambos podem levar a algo interessante.**

Esta sala se concentra na fase de **reconhecimento** e **identificação de erros de configuração** em testes de aplicações web. Temos quatro servidores web diferentes em execução:

|Servidor|Porta|Caso de Uso Típico|
|---|---|---|
|**Apache2**|80|Servidor web tradicional, produção|
|**Python HTTP Server**|8000|Desenvolvimento, compartilhamento rápido|
|**Node.js Express**|3000|Aplicações modernas, APIs|
|**Nginx**|8080|Proxy reverso, servidor estático|

Esses quatro foram escolhidos por representarem os tipos de servidor mais comuns em infraestrutura Linux:

- **Apache** e **Nginx** cobrem o espaço tradicional de servidores web
- **Node.js** representa o padrão moderno de servidor de aplicações
- **Python HTTP Server** abrange servidores acidentais ou improvisados

### Objetivos da Sala

A sala **para** na identificação de erros de configuração. Não exploraremos vulnerabilidades no sentido tradicional:

- ❌ Sem shells
- ❌ Sem RCE
- ❌ Sem escalonamento de privilégios 

O objetivo é desenvolver **habilidades de reconhecimento** que permitam:

1. Identificar o que está exposto
2. Entender por que isso é importante
3. Mapear o cenário antes de qualquer exploração

> **Informação:** Em um ambiente real, esses serviços normalmente seriam executados em hosts separados. Este laboratório os consolida em uma única máquina para facilitar o gerenciamento. O comportamento, os cabeçalhos de resposta e as configurações incorretas que você verá são **idênticos** aos que encontraria em um ambiente distribuído.

---
## Identificando Servidores Web

### Por que a Identificação é Crucial

Antes de começar a enumerar diretórios ou testar entradas, você precisa saber **com o que está lidando**. O software do servidor web determina:

- Quais configurações incorretas são possíveis
- Quais caminhos valem a pena verificar
- Quais ferramentas serão mais eficazes

Identificar o servidor **não é uma mera formalidade**. Isso influencia **diretamente** todas as decisões subsequentes.

### 1. O Cabeçalho de Resposta Server

O sinal de identificação mais direto é o cabeçalho `Server` em uma resposta HTTP. Quando você faz qualquer solicitação a um servidor web, o servidor inclui esse cabeçalho em sua resposta.

**Comando básico:**

```bash
# -s suprime a barra de progresso
# -I envia uma requisição HEAD, retornando apenas cabeçalhos
curl -sI http://10.67.140.127:80
```

**Resposta do Apache:**

```http
HTTP/1.1 200 OK
Date: Wed, 08 Apr 2026 13:59:00 GMT
Server: Apache/2.4.58 (Ubuntu)
Last-Modified: Fri, 03 Apr 2026 18:12:44 GMT
ETag: "29af-64e9243796aa2"
Accept-Ranges: bytes
Content-Length: 10671
Vary: Accept-Encoding
Content-Type: text/html
```

**Análise dos Cabeçalhos:**

|Cabeçalho|Informação|Importância|
|---|---|---|
|`Server: Apache/2.4.58 (Ubuntu)`|Software e versão exata|CVEs aplicáveis, capacidades|
|`X-Powered-By: Express`|Framework (Node.js)|Rotas comuns, comportamento|
|`Content-Type`|Tipo de resposta|Indica API ou HTML|

**Observações importantes:**

- Nem todos os servidores expõem tantos detalhes 
- Uma implementação reforçada pode exibir apenas `Apache`
- A configuração padrão na maioria dos servidores Ubuntu deixa essas informações visíveis

### 2. O Cabeçalho X-Powered-By

Algumas estruturas adicionam um cabeçalho `X-Powered-By` que revela a camada de aplicação:

```http
X-Powered-By: Express
```

**Quando usar:**

- O cabeçalho `Server` está ausente    
- O cabeçalho `Server` é genérico
- Você suspeita de uma aplicação Node.js

### 3. Ferramentas de Desenvolvedor do Navegador

Se você estiver trabalhando em um navegador, a aba **Rede** das Ferramentas de Desenvolvedor fornece as mesmas informações:

1. Abra `http://10.67.140.127:3000`
2. Clique com botão direito → **Inspecionar** (ou F12)
3. Navegue até a aba **Rede**
4. Atualize a página
5. Selecione a requisição principal
6. Na seção **Cabeçalhos**, visualize os **Cabeçalhos de Resposta**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1775661823075.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1775661823075.png)

### 4. Páginas de Erro Padrão

A flag `-I` envia uma requisição `HEAD` que retorna apenas cabeçalhos. Para visualizar páginas de erro, use `GET`:

```bash
# HEAD request: apenas cabeçalhos
curl -sI http://10.67.140.127:PORT/
# GET request: resposta completa
curl -s http://10.67.140.127:PORT/nonexistent-page-xyz
```

**Características das páginas de erro:**

|Servidor|Característica da Página 404|
|---|---|
|**Python HTTP**|Texto plano, sem HTML|
|**Apache**|HTML com "Apache" no corpo|
|**Nginx**|HTML com versão no rodapé|
|**Node.js**|JSON ou HTML personalizado|

### Resumo dos Servidores no Laboratório

|Porta|Servidor|Cabeçalho Server Padrão|Identificador Alternativo|
|---|---|---|---|
|80|Apache2|`Apache/2.4.x (Ubuntu)`|Página 404|
|8000|Python HTTP|`SimpleHTTP/0.6 Python/3.xx.x`|Listagem de diretório|
|3000|Node.js Express|Nenhum (definido pelo app)|`X-Powered-By: Express`|
|8080|Nginx|`nginx/1.xx.x`|Página 404 com versão|

> **Nota:** O Node.js Express **não** define um cabeçalho `Server` por padrão. A ausência desse cabeçalho é, por si só, um sinal. O identificador confiável é o cabeçalho `X-Powered-By`.

---
## Servidor HTTP em Python

### O Que é e Por que Aparece em Pentests

O Python vem com um servidor HTTP integrado que qualquer desenvolvedor pode iniciar com um único comando:

```bash
# Serve o diretório atual na porta 8000
python3 -m http.server 8000
```

**Casos de uso legítimos:**

- Compartilhar arquivos rapidamente    
- Testar sites estáticos
- Transferir arquivos entre máquinas na mesma rede

**O problema:** Esse "compartilhamento rápido" às vezes acaba "exposto acidentalmente à internet por seis meses".

### Características de Segurança

| Aspecto               | Status                           |
| --------------------- | -------------------------------- |
| Controle de acesso    | ❌ Nenhum                         |
| Autenticação          | ❌ Nenhuma                        |
| Logs detalhados       | ❌ Apenas básico                  |
| Arquivos ocultos      | ✅ Servidos como qualquer arquivo |
| Listagem de diretório | ✅ Habilitada por padrão          |

> **Importante:** O servidor HTTP do Python serve **todo** o diretório de trabalho, incluindo arquivos ocultos como `.bashrc`, `.env`, `.git/`. Não há equivalente a `.htaccess`, nenhuma lista de bloqueio. **Se o arquivo existe, qualquer um pode baixá-lo.**

### 1. Listagem de Diretório

Quando nenhum arquivo `index.html` está presente, o Python HTTP Server gera uma página HTML listando **todos** os arquivos:

```bash
curl -s http://10.67.140.127:8000/
```

**Resposta:**

```html
<!DOCTYPE html>
<html>
<head>
    <title>Directory listing for /</title>
</head>
<body>
    <h1>Directory listing for /</h1>
    <hr>
    <ul>
        <li><a href=".env">.env</a></li>
        <li><a href="app.py">app.py</a></li>
        <li><a href="backup.zip">backup.zip</a></li>
        <li><a href="notes.txt">notes.txt</a></li>
        <li><a href="static/">static/</a></li>
    </ul>
    <hr>
</body>
</html>
```

![https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1775890440403.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1775890440403.png)

### 2. Acessando Dotfiles (Arquivos Ocultos)

Arquivos de configuração (dotfiles) como `.env` ficam ocultos da navegação normal no Linux, mas o servidor HTTP do Python **não respeita** essa convenção:

```bash
curl -s http://10.67.140.127:8000/.env
```

**Resposta:**

```text
SECRET_KEY=dev-secret-key-do-not-use
DATABASE_URL=postgresql://webapp:S3cur3DBPass!@localhost/production
DEBUG=True
API_KEY=sk_test_4eC39HqLyjWDarjtT1zdp7dc
```

**Arquivos comuns a procurar:**

| Arquivo               | O que pode conter                  |
| --------------------- | ---------------------------------- |
| `.env`                | Variáveis de ambiente, credenciais |
| `.git/config`         | URLs de repositório, credenciais   |
| `.bashrc`, `.profile` | Histórico, variáveis               |
| `.ssh/id_rsa`         | Chaves SSH (se exposto)            |
| `config.json`         | Configurações da aplicação         |

### 3. Download e Inspeção de Arquivos

Se encontrar arquivos `.zip`, `.tar.gz`, `.txt` ou outros na listagem:

```bash
# Baixar arquivo
curl -s http://10.67.140.127:8000/backup.zip -o backup.zip
# Descompactar
unzip backup.zip -d backup-contents/
# Inspecionar
cat backup-contents/db_dump.sql
```

**Exemplo de conteúdo:**

```sql
-- Database dump for staging environment

CREATE TABLE users (
    id INTEGER PRIMARY KEY, 
    username VARCHAR(50),
    password_hash VARCHAR(255)
);

INSERT INTO users VALUES 
    (1, 'admin', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8'),
    (2, 'jsmith', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918');

-- End of dump
```

### 4. Padrões de Detecção

**Em logs de acesso:**

```text
10.0.0.1 - - [08/Apr/2026 14:00:00] "GET / HTTP/1.1" 200 -
10.0.0.1 - - [08/Apr/2026 14:00:01] "GET /.env HTTP/1.1" 200 -
10.0.0.1 - - [08/Apr/2026 14:00:02] "GET /backup.zip HTTP/1.1" 200 -
```

**Respostas típicas:**

- Listagem de diretório → HTML com "Directory listing for"    
- Arquivo `.env` → texto plano com variáveis
- Código-fonte → texto plano (se `.py`)

### 5. Por que Isso é Importante

A descoberta de um servidor HTTP Python vulnerável é **realista** porque:

- **Não requer exploração** - o servidor está funcionando exatamente como projetado
- **Configuração incorreta** - está sendo executado em local inadequado
- **Impacto imediato** - arquivos sensíveis são expostos

**Documentação em um relatório real:**

> "O servidor HTTP Python na porta 8000 expõe listagem de diretório e arquivos sensíveis, incluindo `.env` com credenciais de banco de dados e arquivos de backup contendo dados de usuários. Isso permite que qualquer atacante acesse informações confidenciais sem autenticação."

> **Nota:** Se o diretório mostrar um arquivo `index.html`, o Python servirá esse arquivo em vez da listagem de diretório. Se você não vir uma listagem na raiz, tente solicitar caminhos diretamente ou navegar até subdiretórios.

---
## Apache2

### Contexto e Importância

O Apache é o servidor web mais amplamente utilizado no mundo, presente em **praticamente todos** os projetos que envolvem infraestrutura web. Sua configuração padrão no Ubuntu deixa vários recursos habilitados que testadores encontram com frequência.

### 1. Divulgação de Versão

Comece pelo básico: verifique o cabeçalho `Server`:

```bash
curl -SI http://10.67.140.127:80 | grep -i server
```

**Resposta:**

```text
Server: Apache/2.4.58 (Ubuntu)
```

**O que isso revela:**

- Versão exata: `2.4.58`    
- Sistema operacional: `Ubuntu`
- `ServerTokens OS` está habilitado (padrão)

**Valores de `ServerTokens`:**

|Valor|Exemplo|Nível de Detalhe|
|---|---|---|
|`OS`|`Apache/2.4.58 (Ubuntu)`|Máximo (padrão Ubuntu)|
|`ProductOnly`|`Apache`|Mínimo|
|`Min`|`Apache/2.4.58`|Apenas versão|
|`Full`|`Apache/2.4.58 (Unix) mod_ssl/2.4.58`|Máximo com módulos|

> **Importância:** Saber a versão exata ajuda a verificar vulnerabilidades conhecidas (CVEs) e entender as capacidades do servidor.

### 2. Listagem de Diretório

A diretiva `Options +Indexes` instrui o Apache a exibir uma listagem de arquivos quando um diretório não possui `index.html`.

**Verificação:**

```bash
curl -s http://10.67.140.127/files/
```

**Resposta:**

```html
<html>
<head>
    <title>Index of /files</title>
</head>
<body>
    <h1>Index of /files</h1>
    <hr>
    <pre>
        <a href="../">../</a>
        <a href="backup.sql">backup.sql</a>            2024-04-08 14:00  2.3M
        <a href="notes.txt">notes.txt</a>             2024-04-08 13:45  1.2K
        <a href="config.bak">config.bak</a>            2024-04-08 13:30  4.1K
    </pre>
    <hr>
</body>
</html>
```

![https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1777558921639.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1777558921639.png)

**O que procurar:**

- Arquivos de backup (`.bak`, `.backup`, `.old`)
- Arquivos de configuração (`.conf`, `.config`)
- Dumps de banco de dados (`.sql`)
- Arquivos de log (`.log`)

### 3. A Página mod_status

O Apache inclui uma página de status integrada gerenciada pelo módulo `mod_status`.

**Configuração segura (padrão Ubuntu):**

```apache
<Location /server-status>
    SetHandler server-status
    Require local  # Apenas localhost
</Location>
```

**Configuração vulnerável:**

```apache
<Location /server-status>
    SetHandler server-status
    Require all granted  # Qualquer IP
</Location>
```

**Verificação:**

```bash
curl -s http://10.67.140.127:80/server-status
```

**O que a página revela:**

- Conexões ativas e caminhos solicitados    
- Total de requisições desde a inicialização
- Estados dos workers (idle, reading, writing, closing)
- Versão exata do servidor
- Hora de inicialização

![https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1777558921642.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1777558921642.png)

> **Importante:** `mod_status` está ativado por padrão no Ubuntu. No entanto, uma diretiva `Require all granted` em qualquer lugar na configuração de um host virtual pode sobrescrever silenciosamente a restrição `Require local`, expondo `/server-status` a todos os IPs. **Sempre verifique `/server-status`.**

### 4. Encontrando Arquivos Não Vinculados com Gobuster

Nem tudo que é interessante está linkado em uma página ou visível em uma listagem. Ferramentas como **Gobuster** descobrem esses arquivos.

**Instalação (se necessário):**

```bash
sudo apt install gobuster
```

**Comando básico:**

```bash
gobuster dir -u http://10.67.140.127:80 \
    -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt \
    -x bak,txt,html \
    -t 20
```

**Parâmetros:**

| Flag | Descrição             |
| ---- | --------------------- |
| `-u` | URL alvo              |
| `-w` | Caminho da wordlist   |
| `-x` | Extensões para testar |
| `-t` | Número de threads     |

**Saída:**

```text
===============================================================
Gobuster v3.6
===============================================================
[+] Url:                     http://10.67.140.127
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt
[+] Extensions:              bak,txt
===============================================================
Starting gobuster
===============================================================
/.htpasswd            (Status: 403) [Size: 275]
/.htaccess            (Status: 403) [Size: 275]
/backup.bak           (Status: 200) [Size: 178]
/files                (Status: 301) [Size: 308] [--> http://10.67.140.127/files/]
/index.html           (Status: 200) [Size: 10671]
/server-status        (Status: 200) [Size: 17539]
===============================================================
Finished
===============================================================
```

**Interpretação dos status:**

|Status|Significado|Ação|
|---|---|---|
|`200`|Arquivo existe e é acessível|✅ Investigar|
|`301`|Redirecionamento (geralmente diretório)|✅ Seguir|
|`403`|Acesso proibido|ℹ️ Pode ser interessante|
|`404`|Não encontrado|❌ Ignorar|

### 5. Exemplo de Descoberta: backup.bak

```bash
curl -s http://10.67.140.127:80/backup.bak
```

**Resposta:**

```text
# Apache config backup - DO NOT COMMIT
ServerName company.internal
DocumentRoot /var/www/html
# DB credentials below
# user: dbadmin 
# pass: Backup2024!
# Last updated: 2024-11-15
```

### 6. Padrões de Investigação do Apache

1. ✅ Verificar cabeçalho `Server`    
2. ✅ Navegar por diretórios com listagem habilitada
3. ✅ Verificar `/server-status`
4. ✅ Executar Gobuster com extensões comuns
5. ✅ Baixar e inspecionar arquivos descobertos

---
## Node.js (Express)

### Diferenças Fundamentais

Aplicações Node.js se comportam de maneira **diferente** do Apache e Python HTTP:

- **Não** servem arquivos estáticos de um diretório raiz configurado 
- **Executam código** da aplicação
- O código decide o que retornar para cada requisição

**O problema:** Desenvolvedores frequentemente deixam recursos do modo de desenvolvimento habilitados em produção:

- Endpoints de depuração
- Respostas de erro detalhadas
- Variáveis de ambiente expostas

### 1. Fingerprinting do Framework

**Verificação:**

```bash
curl -sI http://10.66.170.171:3000
```

**Resposta:**

```http
HTTP/1.1 200 OK
X-Powered-By: Express
Content-Type: application/json; charset=utf-8
Content-Length: 56
ETag: W/"38-K8iCfm09rMr0MV0NsgqdAb94DAk"
Date: Sat, 11 Apr 2026 07:27:28 GMT
Connection: keep-alive
```

**Sinais de identificação:**

- ✅ `X-Powered-By: Express` - Framework confirmado    
- ✅ `Content-Type: application/json` - API REST
- ❌ `Server` cabeçalho ausente (padrão)

### 2. Lendo a Versão da Aplicação

O caminho raiz frequentemente retorna informações da aplicação:

```bash
curl -s http://10.66.170.171:3000
```

**Resposta:**

```json
{"status":"ok","app":"company-portal","version":"1.2.0"}
```

**O que anotar:**

- `app` - Nome da aplicação    
- `version` - Versão (comparar com vulnerabilidades conhecidas)
- `status` - Saúde da aplicação

### 3. Erros Verbosos (Verbose Errors)

Quando uma API falha, o Express (especialmente em modo desenvolvimento) retorna detalhes completos:

```bash
curl -s http://10.66.170.171:3000/api/users
```

**Resposta de erro:**

```json
{
    "error": "connect ECONNREFUSED 127.0.0.1:5432",
    "stack": "Error: connect ECONNREFUSED 127.0.0.1:5432\n    at /opt/nodeapp/app.js:16:15\n    at Layer.handle [as handle_request] (/opt/nodeapp/node_modules/express/lib/router/layer.js:95:5)\n    at next (/opt/nodeapp/node_modules/express/lib/router/route.js:149:13)\n    at Route.dispatch (/opt/nodeapp/node_modules/express/lib/router/route.js:119:3)\n    at Layer.handle [as handle_request] (/opt/nodeapp/node_modules/express/lib/router/layer.js:95:5)\n    at /opt/nodeapp/node_modules/express/lib/router/index.js:284:15\n    at Function.process_params (/opt/nodeapp/node_modules/express/lib/router/index.js:346:12)\n    at next (/opt/nodeapp/node_modules/express/lib/router/index.js:280:10)\n    at expressInit (/opt/nodeapp/node_modules/express/lib/middleware/init.js:40:5)\n    at Layer.handle [as handle_request] (/opt/nodeapp/node_modules/express/lib/router/layer.js:95:5)",
    "query": "SELECT * FROM users"
}
```

**Informações valiosas no stack trace:**

- Caminhos de arquivos internos: `/opt/nodeapp/app.js:16`
- Nomes de módulos: `express/lib/router`
- Consultas SQL: `SELECT * FROM users`
- Endereços internos: `127.0.0.1:5432`

> **Nota:** O manipulador de erros integrado do Express suprime stack traces em produção (`NODE_ENV=production`). No entanto, desenvolvedores frequentemente escrevem manipuladores personalizados que expõem detalhes independentemente do ambiente.

### 4. Enumerando Rotas com Endpoints de Depuração

Um dos achados mais valiosos: endpoints de depuração que listam todas as rotas.

```bash
curl -s http://10.66.170.171:3000/api/routes
```

**Resposta:**

```json
[
    {"method":"GET","path":"/"},
    {"method":"GET","path":"/api/users"},
    {"method":"GET","path":"/api/routes"},
    {"method":"GET","path":"/api/debug/env"},
    {"method":"POST","path":"/api/login"},
    {"method":"GET","path":"/static/config.js"}
]
```

> **Como funciona:** O endpoint lê `app._router.stack`, uma propriedade interna do Express. Este é um padrão reconhecido de má configuração.

**Limitações:**

- O Express 5 mudou a estrutura interna do roteador
- Algumas versões podem retornar formatos inesperados
- Nem todas as aplicações têm esse endpoint    

### 5. Variáveis de Ambiente Expostas

Endpoints de depuração frequentemente retornam `process.env`:

```bash
curl -s http://10.66.170.171:3000/api/debug/env
```

**Resposta:**

```json
{
    "NODE_ENV": "development",
    "DB_PASSWORD": "NodeDBPass2024!",
    "PORT": "3000",
    "DB_HOST": "localhost:5432",
    "APP_NAME": "company-portal",
    "SECRET_KEY": "supersecretkey123",
    "AWS_ACCESS_KEY": "AKIAIOSFODNN7EXAMPLE"
}
```

**O que procurar:**

- `NODE_ENV: development` → Modo de desenvolvimento em produção
- Credenciais: `DB_PASSWORD`, `SECRET_KEY`, `AWS_*`
- Configurações: `DB_HOST`, `API_URL`
- Chaves de API: `STRIPE_SECRET`, `GITHUB_TOKEN`

### 6. Servindo Arquivos Estáticos

O middleware `express.static()` serve recursos de front-end:

```bash
curl -s http://10.66.170.171:3000/static/config.js
```

**Resposta:**

```javascript
// Client-side configuration
const API_BASE = 'http://internal-api.company.local:8080';
const DEBUG = true;
const VERSION = '1.2.0';
const RECAPTCHA_KEY = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFKuojJfielT3';
```

**Padrões de arquivos estáticos:**

- `config.js` - Configuração do cliente
- `app.js` - Código JavaScript principal
- `style.css` - Folhas de estilo
- `/static/`, `/public/`, `/assets/` - Diretórios comuns

> **Nota:** `express.static()` por padrão retorna 404 para arquivos ocultos (que começam com `.`). Isso é o **oposto** do Python HTTP Server, que serve arquivos ocultos normalmente.

### 7. Checklist para Node.js Express

- Verificar `X-Powered-By` cabeçalho
- Acessar raiz para informações da aplicação
- Testar endpoints de API para erros verbosos
- Procurar endpoints de depuração (`/api/routes`, `/debug`, `/status`)
- Verificar variáveis de ambiente expostas
- Explorar diretórios de arquivos estáticos
- Analisar arquivos JavaScript do cliente

---
## Nginx

### Contexto e Posicionamento

O Nginx ocupa um espaço diferente do Apache e Node.js:

- **Proxy reverso** - Frente do servidor de aplicações
- **Balanceador de carga** - Distribui tráfego
- **Servidor estático** - Alta performance para arquivos estáticos

Em produção, geralmente está na **frente** do servidor de aplicações, lidando com tráfego público. Essa posição torna sua configuração **crítica**.

### 1. Divulgação de Versão

**Verificação:**

```bash
curl -sI http://10.66.170.171:8080 | grep -i server
```

**Resposta:**

```text
Server: nginx/1.24.0 (Ubuntu)
```

**Controle de divulgação:**

- `server_tokens on;` → Exibe versão (padrão)
- `server_tokens off;` → Oculta versão    

**Verificação de `server_tokens` via página de erro:**

```bash
curl -s http://10.66.170.171:8080/nonexistent-path
```

**Com `server_tokens on`:**

```html

<center><h1>404 Not Found</h1></center>
<hr><center>nginx/1.24.0 (Ubuntu)</center>
```

**Com `server_tokens off`:**

```html
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
```

### 2. Listagem de Diretório com autoindex

O Nginx não habilita listagem por padrão. Quando habilitada:

```nginx
location /files/ {
    autoindex on;
    root /var/www/nginx/;
}
```

**Verificação:**

```bash
curl -s http://10.66.170.171:8080/files/
```

**Resposta:**

```html
<html>
<head><title>Index of /files/</title></head>
<body>
<h1>Index of /files/</h1>
<hr>
<pre>
<a href="../">../</a>
<a href="deploy-notes.txt">deploy-notes.txt</a>                                   03-Apr-2026 18:23                 148
<a href="old-backup.tar.gz">old-backup.tar.gz</a>                                  03-Apr-2026 18:23                 236
<a href="server-config.txt">server-config.txt</a>                                  03-Apr-2026 18:23                 135
<a href=".env">.env</a>                                               03-Apr-2026 18:23                  45
</pre>
<hr>
</body>
</html>
```

**Características da listagem Nginx:**

- Tabela simples com nome, data e tamanho
- Ordem alfabética
- Inclui link para diretório pai (`../`)

### 3. O Endpoint stub_status

O módulo `stub_status` expõe métricas de conexão em tempo real:

```nginx
location /nginx_status {
    stub_status;
    allow all;  # ❌ Vulnerável - deve ser allow 127.0.0.1;
}
```

**Verificação:**

```bash
curl -s http://10.66.170.171:8080/nginx_status
```

**Resposta:**

```text
Active connections: 1 
server accepts handled requests
 15 15 15 
Reading: 0 Writing: 1 Waiting: 0 
```

**Interpretação:**

| Linha                   | Significado                              |
| ----------------------- | ---------------------------------------- |
| `Active connections: 1` | Conexões ativas no momento               |
| `15 15 15`              | Aceitas, processadas, requisições totais |
| `Reading: 0`            | Conexões lendo requisições               |
| `Writing: 1`            | Conexões escrevendo respostas            |
| `Waiting: 0`            | Conexões keep-alive esperando            |

**Por que isso é importante:**

- Confirma configuração de monitoramento interno
- Pode indicar outros endpoints de monitoramento
- Revela padrões de uso do servidor
- Informação operacional valiosa

### 4. Padrões de Investigação do Nginx

1. ✅ Verificar cabeçalho `Server`
2. ✅ Solicitar página inexistente para confirmar `server_tokens`
3. ✅ Procurar diretórios com `autoindex on`
4. ✅ Verificar `/nginx_status`
5. ✅ Examinar arquivos descobertos

### 5. Dicas para Configuração do Nginx

**Arquivos de configuração no Ubuntu:**

```bash
# Localização principal
/etc/nginx/nginx.conf
# Sites disponíveis
/etc/nginx/sites-available/
# Sites habilitados (links simbólicos)
/etc/nginx/sites-enabled/
```

**Diretivas de segurança importantes:**

```nginx
# Ocultar versão
server_tokens off;
# Restringir status
location /nginx_status {
    stub_status;
    allow 127.0.0.1;
    deny all;
}
# Desabilitar listagem
autoindex off;
# Headers de segurança
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
```

---
## Configurações Incorretas Comuns em Servidores

### Padrões que se Repetem

Já analisamos quatro servidores web diferentes, cada um com seu próprio modelo de configuração. Existem **padrões que se repetem** independentemente do servidor em execução.

### 1. Cabeçalhos de Segurança Ausentes

**O que são:** Cabeçalhos HTTP que instruem o navegador sobre como lidar com o conteúdo da página, protegendo contra ataques do lado do cliente.

|Cabeçalho|Protege Contra|Exemplo de Valor|
|---|---|---|
|`X-Frame-Options`|Clickjacking|`DENY` ou `SAMEORIGIN`|
|`X-Content-Type-Options`|MIME sniffing|`nosniff`|
|`Content-Security-Policy`|XSS, injeção|`default-src 'self'`|
|`Referrer-Policy`|Vazamento de referer|`no-referrer`|
|`Strict-Transport-Security`|Ataques downgrade|`max-age=31536000`|

**Verificação automática:**

```bash
for port in 80 8000 3000 8080; do
    echo "=== Port $port ==="
    curl -sI http://10.66.170.171:$port/ | \
        grep -iE "x-frame-options|x-content-type|content-security-policy|strict-transport|referrer-policy" || \
        echo "(no security headers found)"
done
```

**Resultado típico:**

```text
=== Port 80 ===
(no security headers found)
=== Port 8000 ===
(no security headers found)
=== Port 3000 ===
(no security headers found)
=== Port 8080 ===
(no security headers found)
```

> **Nota:** `Strict-Transport-Security` só se aplica a conexões HTTPS. Como este laboratório usa HTTP, sua ausência é esperada.

### 2. Scanner Automatizado com Nikto

**Nikto** é um scanner de servidor web que verifica:

- Configurações incorretas conhecidas
- Software desatualizado
- Interfaces administrativas expostas
- Cabeçalhos de segurança ausentes    

>**⚠️ Atenção:** Nikto gera **muito tráfego** e é fácil de detectar. Apropriado para testes autorizados, **não** para operações furtivas.

**Comando básico:**

```bash
nikto -h http://10.66.170.171:80 -nointeractive
```

**Saída:**

```text
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.66.170.171
+ Target Hostname:    10.66.170.171
+ Target Port:        80
+ Start Time:         2026-04-11 09:16:09 (GMT1)
---------------------------------------------------------------------------
+ Server: Apache/2.4.58 (Ubuntu)
+ Server leaks inodes via ETags, header found with file /, fields: 0x29af 0x64e9243796aa2 
+ The anti-clickjacking X-Frame-Options header is not present.
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS 
+ OSVDB-561: /server-status: This reveals Apache information.
+ OSVDB-3268: /files/: Directory indexing found.
+ OSVDB-3092: /files/: This might be interesting...
+ 6544 items checked: 0 error(s) and 6 item(s) reported
+ End Time:           2026-04-11 09:16:18 (GMT1) (9 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

**Interpretação dos achados:**

|Achado|Significado|Severidade|
|---|---|---|
|`Server: Apache/2.4.58`|Versão exposta|Baixa|
|`ETags leaks inodes`|Vazamento de informação|Baixa|
|`X-Frame-Options header is not present`|Sem proteção clickjacking|Média|
|`/server-status` exposto|Informação operacional pública|Média|
|`/files/: Directory indexing`|Listagem de diretório|Alta|

**Códigos de Tuning (para varreduras rápidas):**

```bash
nikto -h TARGET -Tuning 123
```

|Código|O que verifica|
|---|---|
|`1`|Arquivos de log interessantes|
|`2`|Configurações padrão/desatualizadas|
|`3`|Arquivos de backup/senha|
|`4`|Arquivos CGI/caminhos interessantes|
|`5`|Erros de servidor/configuração|
|`6`|URLs conhecidas/vulnerabilidades|
|`7`|Arquivos de upload|
|`8`|Arquivos PHP/ASP/ASPX|
|`9`|Vulnerabilidades SQL Injection|
|`0`|Verificação de diretórios vazios|

### 3. Matriz de Configurações Incorretas

|Configuração Incorreta|Apache|Python HTTP|Node.js|Nginx|
|---|---|---|---|---|
|**Divulgação de versão**|✅ Sim|✅ Sim|⚠️ Parcial|✅ Sim|
|**Listagem de diretório**|✅ `/files/`|✅ Raiz|❌ N/A|✅ `/files/`|
|**Endpoint de status**|✅ `/server-status`|❌ N/A|✅ `/api/debug/env`|✅ `/nginx_status`|
|**Arquivos sensíveis**|✅ `backup.bak`|✅ `.env`|✅ `config.js`|✅ `server-config.txt`|
|**Headers de segurança**|❌ Ausentes|❌ Ausentes|❌ Ausentes|❌ Ausentes|

### 4. Padrões de Comportamento por Tipo de Servidor

|Comportamento|Apache|Python HTTP|Node.js|Nginx|
|---|---|---|---|---|
|**Arquivos ocultos**|Bloqueados (`.htaccess`)|Servidos|Bloqueados (static)|Depende|
|**Páginas de erro**|HTML com versão|Texto plano|JSON/HTML|HTML com versão|
|**Configuração**|Arquivos `.conf`|Linha de comando|Código da aplicação|Arquivos `.conf`|
|**Autenticação**|`.htpasswd`|Nenhuma|Middleware|Nenhuma|

---
## Checklist do Pentester

### Fase 1: Descoberta (10-15 minutos)

- **Scannear portas**

```bash
nmap -sS -p- TARGET_IP
nmap -sV -p 80,443,3000,8000,8080 TARGET_IP
```

- **Identificar servidores**

```bash
for port in 80 443 3000 8000 8080; do
	curl -sI http://TARGET_IP:$port | grep -iE "server|x-powered-by"
done
```

- **Verificar cabeçalhos de segurança**

```bash
curl -sI http://TARGET_IP:PORT | grep -iE "x-frame|content-security|strict-transport"
```

### Fase 2: Enumeração (20-30 minutos)

- **Testar listagem de diretório**

```bash
# Apache/Nginx
curl -s http://TARGET_IP:PORT/files/
curl -s http://TARGET_IP:PORT/uploads/
# Python HTTP
curl -s http://TARGET_IP:8000/
```

- **Verificar endpoints de status**

```bash
# Apache
curl -s http://TARGET_IP:80/server-status
# Nginx
curl -s http://TARGET_IP:8080/nginx_status
# Node.js (depuração)
curl -s http://TARGET_IP:3000/api/routes
curl -s http://TARGET_IP:3000/api/debug/env
```

- **Baixar arquivos sensíveis**

```bash
# Arquivos comuns
curl -s http://TARGET_IP/.env
curl -s http://TARGET_IP/backup.bak
curl -s http://TARGET_IP/config.json
# Diretórios específicos
curl -s http://TARGET_IP/files/notes.txt
curl -s http://TARGET_IP/static/config.js
```

### Fase 3: Varredura Automatizada (15-30 minutos)

- **Executar Gobuster**

```bash
gobuster dir -u http://TARGET_IP:PORT \
	-w /usr/share/wordlists/dirb/common.txt \
	-x txt,bak,html,php,asp,aspx \
	-t 20
```

- **Executar Nikto**

```bash
nikto -h http://TARGET_IP:PORT -nointeractive -Tuning 123
```

- **Varredura com ferramentas específicas**

```bash
# Detectar servidores HTTP Python
whatweb http://TARGET_IP:8000
# Detectar frameworks Node.js
wappalyzer-cli http://TARGET_IP:3000
```

### Fase 4: Documentação

- **Registrar descobertas**
    - Versão exata do servidor
    - Endpoints expostos
    - Arquivos sensíveis encontrados
    - Headers de segurança ausentes
    - Credenciais encontradas

- **Categorizar por severidade**

|Severidade|Exemplo|
|---|---|
|**Crítica**|`.env` com credenciais de produção|
|**Alta**|Listagem de diretório com dados sensíveis|
|**Média**|Endpoint de status exposto|
|**Baixa**|Divulgação de versão|

- **Recomendar correções**
    - Desabilitar listagem de diretório
    - Remover endpoints de depuração
    - Adicionar cabeçalhos de segurança
    - Restringir endpoints de status
    - Remover servidores HTTP Python desnecessários

---
## Referências

### Documentação Oficial

**Apache:**

- [Apache HTTP Server Documentation](https://httpd.apache.org/docs/)    
- [Apache Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)
- [mod_status Documentation](https://httpd.apache.org/docs/2.4/mod/mod_status.html)
- [ServerTokens Directive](https://httpd.apache.org/docs/2.4/mod/core.html#servertokens)

**Nginx:**

- [Nginx Documentation](https://nginx.org/en/docs/)
- [Nginx Security Guide](https://www.nginx.com/resources/admin-guide/security-controls/)
- [stub_status Module](https://nginx.org/en/docs/http/ngx_http_stub_status_module.html)
- [autoindex Module](https://nginx.org/en/docs/http/ngx_http_autoindex_module.html)

**Node.js:**

- [Express.js Documentation](https://expressjs.com/)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)
- [Node.js Security](https://nodejs.org/en/docs/guides/security/)    

**Python:**

- [Python http.server Documentation](https://docs.python.org/3/library/http.server.html)
- [Python Security Considerations](https://docs.python.org/3/library/http.server.html#security-considerations)

### Ferramentas

- [Gobuster](https://github.com/OJ/gobuster) - Directory/file busting
- [Nikto](https://github.com/sullo/nikto) - Web server scanner
- [Nmap](https://nmap.org/) - Network discovery
- [Wappalyzer](https://www.wappalyzer.com/) - Technology detection
- [WhatWeb](https://github.com/urbanadventurer/WhatWeb) - Web scanner
- [Burp Suite](https://portswigger.net/burp) - Web pentesting platform

### Wordlists

- [SecLists](https://github.com/danielmiessler/SecLists) - Comprehensive wordlists
- [DirBuster Lists](https://github.com/digination/dirbuster-ng) - Directory busting
- [Common Web Paths](https://github.com/OWASP/OWASP-WebGoat)

### OWASP Resources

- [OWASP Top 10](https://owasp.org/Top10/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Security Headers](https://owasp.org/www-project-secure-headers/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)

### Leitura Adicional

**Livros:**

- "The Web Application Hacker's Handbook" - Stuttard & Pinto
- "OWASP Testing Guide" - OWASP Foundation
- "Web Security Testing Cookbook" - Hope & Walther

**Cursos:**

- PortSwigger Web Security Academy
- Offensive Security Web Expert (OSWE)
- eLearnSecurity Web Penetration Tester (eWPT)
