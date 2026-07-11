<!--
title: Splunk Data Manipulation
desc: Técnicas de parsing, enriquecimento de logs e ingestão estruturada de dados no Splunk.
tags: splunk, siem, blue-team
readTime: 7 min
-->

<!-- ===================================== -->
<!--     SPLUNK DATA MANIPULATION GUIDE    -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Splunk-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Data%20Parsing%20%7C%20Ingestion-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Layer-Log%20Processing-red?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-SIEM%20Engineering-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Security-Data%20Normalization-green?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Intermediate%20%E2%86%92%20Advanced-yellow?style=flat-square">
</p>

---

# 📊 Splunk: Manipulação de Dados
## Guia Técnico de Ingestão, Parsing, Extração e Normalização de Logs

> Em ambientes modernos de segurança, os dados são produzidos constantemente:
>
> firewalls, servidores, aplicações, endpoints, proxies e dispositivos de rede geram milhares — ou milhões — de eventos diariamente.
>
> Porém, dados brutos sozinhos possuem pouco valor.
>
> Antes que qualquer correlação, alerta ou investigação aconteça, existe uma etapa crítica:
>
> **a manipulação e interpretação correta dos dados.**
>
> É exatamente nesse ponto que o Splunk atua — transformando logs desestruturados em informações pesquisáveis, organizadas e acionáveis.

---

# Splunk: Manipulação de Dados

## Introdução

O processamento, a análise e a manipulação de dados são cruciais para extrair **insights significativos** e permitir uma análise eficaz de dados gerados por máquina. Dados analisados corretamente permitem extrair campos e valores, tornando-os pesquisáveis, estruturados e prontos para análise.

**Do ponto de vista da segurança**, esses recursos são particularmente valiosos para:

|Atividade|Benefício|
|---|---|
|Identificação de ameaças|Detecção precoce de comportamentos maliciosos|
|Resposta a incidentes|Ação rápida baseada em dados estruturados|
|Monitoramento de saúde do sistema|Visibilidade contínua do ambiente|
|Correlação de eventos|Conexão entre múltiplas fontes de dados|
|Detecção de anomalias|Identificação precisa de desvios|
|Criação de alertas|Gatilhos acionáveis baseados em padrões|

---

## Briefing do Cenário

Neste cenário, assumimos o papel de um **analista SOC da MSSP Cybertees Ltd**. Um de seus clientes requer a ingestão de dados de eventos no Splunk através de uma fonte personalizada. O Splunk deve estar devidamente configurado para analisar e transformar os logs adequadamente.

### Problemas a serem abordados

|Problema|Descrição|
|---|---|
|**Quebra de Eventos**|Configurar o Splunk para identificar e separar corretamente eventos individuais durante a ingestão|
|**Análise de Eventos Multilinha**|Configurar o Splunk para lidar corretamente com logs que abrangem múltiplas linhas|
|**Mascaramento de Dados Sensíveis**|Mascarar informações confidenciais em logs para cumprir padrões (ex: PCI DSS)|
|**Extração de Campos**|Extrair campos relevantes dos dados de eventos do cliente|

### Acesso ao Laboratório

- O Splunk está instalado no diretório padrão `/opt`
    
- Os scripts de trabalho estão localizados em `/home/ubuntu/Downloads/scripts/`
    
- Mude para o usuário root com `sudo su` após acessar o ambiente
    

> **Nota:** Se o Splunk parar de responder, execute `/opt/splunk/bin/splunk restart` como `root` e aguarde alguns minutos.

---

## Como o Splunk Processa Dados

Antes que o Splunk possa ser usado para pesquisar, visualizar ou alertar sobre dados, ele deve primeiro **ingeri-los e interpretá-los corretamente**. Esse processo, conhecido como **análise de dados**, transforma dados brutos em eventos estruturados e pesquisáveis.

O Splunk identifica timestamps, quebra eventos, atribui tipos de origem e extrai campos-chave — tudo controlado através do sistema de configuração e arquivos do Splunk.

### 1. Determinando o Formato dos Dados

O Splunk suporta uma ampla gama de formatos comuns, incluindo:

| Formato         | Descrição                                |
| --------------- | ---------------------------------------- |
| **CSV**         | Arquivos separados por vírgula           |
| **JSON**        | Dados estruturados em formato JavaScript |
| **XML**         | Dados hierárquicos extensíveis           |
| **Texto bruto** | Logs simples sem formatação específica   |

> Conhecer a estrutura dos seus dados ajuda a escolher ou criar o tipo de origem certo e garante que o Splunk aplique as regras corretas de análise.

### 2. Identificando o Tipo de Origem (sourcetype)

O `sourcetype` é uma das configurações mais importantes durante a ingestão de dados, pois representa:

- O tipo de dados    
- Como gerenciar **timestamps**
- Como tratar **quebras de linha**
- Como realizar **extrações de campo**

O Splunk vem com muitos tipos de origem embutidos para fontes de log populares, mas você também pode definir **tipos de origem personalizados**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764385571017.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764385571017.svg)

### 3. Configurando Entradas (inputs.conf)

O arquivo `inputs.conf` instrui o Splunk sobre:

|Configuração|Descrição|
|---|---|
|**Quais dados ingerir**|Arquivos, scripts, portas de rede|
|**Onde se originam**|Caminho do arquivo ou fonte|
|**Como coletá-los**|Intervalo, método de coleta|
|**Metadados básicos**|`sourcetype`, `host`, `source`|

**Locais dos arquivos de configuração:**

|Local|Finalidade|
|---|---|
|`/opt/splunk/etc/system/default`|Configurações padrão (**não editar** - serão sobrescritas em atualizações)|
|`/opt/splunk/etc/system/local`|Alterações personalizadas (**prioridade sobre default**)|

**Exemplo de entrada em `inputs.conf`:**

```bash
[monitor:///path/to/your/data]
disabled = false
index = your_index
sourcetype = your_sourcetype
```

### 4. Configurando Propriedades de Processamento (props.conf)

O arquivo `props.conf` define as configurações de análise de dados para tipos de origem específicos ou fontes de dados.

**Exemplo de entrada:**

```bash
[your_sourcetype]
SHOULD_LINEMERGE = false
TIME_FORMAT = %Y-%m-%d %H:%M:%S
```

### 5. Definindo Extrações de Campo

Você pode definir extrações de campo personalizadas em `props.conf` especificando:

- O tipo de origem
- O nome da extração de campo
- Uma expressão regular personalizada

```bash
[your_sourcetype]
EXTRACT-fieldname1 = regular_expression1
EXTRACT-fieldname2 = regular_expression2
```

> **Nota:** Na próxima tarefa, abordaremos outro arquivo de configuração que fornece uma solução mais eficiente para extrações de campo.

### Usando a Interface do Splunk

Embora esta sala foque na criação e edição de arquivos de configuração via linha de comando, o Splunk também fornece uma **interface web amigável** para gerenciar muitas das mesmas configurações.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764385659746.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764385659746.svg)

Através da UI, você pode:

- Definir tipos de origem
- Criar extrações de campo
- Gerenciar pesquisas
- Configurar opções de análise adicionais

---

## Explorando Arquivos de Configuração

O Splunk depende de uma série de [arquivos de configuração](https://docs.splunk.com/Documentation/Splunk/9.1.1/Admin/Listofconfigurationfiles) para controlar como os dados são coletados, analisados, transformados e tornados pesquisáveis.

> **Importante:** Arquivos em `/opt/splunk/etc/system/default` **não devem ser alterados**, pois são sobrescritos com atualizações. Faremos alterações no diretório `/local`.

### Principais Arquivos de Configuração

|Arquivo|Finalidade|Exemplo de Uso|
|---|---|---|
|**`inputs.conf`**|Define quais dados ingerir|`[monitor:///path/to/log]`|
|**`props.conf`**|Define como interpretar os dados|Configurações de timestamp e quebra de linha|
|**`transforms.conf`**|Define transformações e enriquecimentos|Extração de campos via regex|
|**`fields.conf`**|Define comportamento de campos personalizados|`INDEXED = true`|
|**`indexes.conf`**|Gerencia configuração de índices|Armazenamento, retenção, acesso|
|**`outputs.conf`**|Define destinos para dados indexados|Encaminhamento para instâncias remotas|

### Detalhamento dos Arquivos

#### transforms.conf

- **Finalidade:** Permite definir transformações e enriquecimentos de dados em eventos indexados.
- **Exemplo:** Extrair um campo `username` da linha de log:

```text
User john.doe logged in from 10.0.0.5
```

```bash
[extract_username]
REGEX = User\s+(\S+)\s+logged
FORMAT = username::$1
```

#### fields.conf

- **Finalidade:** Define como os campos personalizados ou extraídos se comportam no Splunk.
- **Exemplo:** Referenciando a entrada do `transforms.conf`:

```bash
[username]
INDEXED = true
```

#### indexes.conf

- **Finalidade:** Gerencia a configuração de índices, incluindo armazenamento, políticas de retenção e controle de acesso.
- **Exemplo:** Criando um novo índice `my_index`:


```bash
[my_index]
homePath = $SPLUNK_DB/my_index/db
coldPath = $SPLUNK_DB/my_index/colddb
thawedPath = $SPLUNK_DB/my_index/thaweddb
maxTotalDataSizeMB = 100000
```

#### utputs.conf

- **Finalidade:** Especifica o destino e as configurações para enviar dados indexados.
- **Exemplo:** Encaminhando dados para um indexador Splunk remoto:

```bash
[tcpout:group1]
server = 10.10.10.100:9997
```

### Estrofes no Splunk

Os arquivos de configuração do Splunk são organizados em seções chamadas **estrofes**, que definem como o Splunk deve lidar com um componente específico.

**Formato:** Cada estrofe começa com um rótulo entre colchetes `[]`

**Dependendo do arquivo, uma estrofe pode representar:**

| Arquivo           | O que a estrofe representa |
| ----------------- | -------------------------- |
| `indexes.conf`    | Um índice                  |
| `props.conf`      | Um tipo de fonte           |
| `transforms.conf` | Uma transformação de campo |
| `inputs.conf`     | Uma fonte de entrada       |
| `outputs.conf`    | Um grupo de saída          |

---

## Criando um Aplicativo Splunk

O Splunk vem com uma variedade de aplicativos padrão, sendo o **Search & Reporting** o mais familiar. Além dos aplicativos integrados, existem centenas de aplicativos adicionais desenvolvidos pela Splunk, fornecedores terceiros e a comunidade.

Você pode navegar e instalar esses aplicativos através do [Splunkbase](https://splunkbase.splunk.com/), o mercado de aplicativos da Splunk.

### Iniciando o Splunk

1. Navegue até `/opt/splunk/bin` e execute `./splunk start`
2. Acesse o Dashboard do Splunk em `10.67.159.179:8000`

### Criando seu Aplicativo

Após acessar o Painel do Splunk:

1. Clique no ícone de engrenagem `Manage Apps`
2. Esta página mostra os aplicativos padrão instalados
3. Clique em `Create app` para começar

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413352783.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413352783.svg)

**Preenchendo os detalhes do aplicativo:**

|Campo|Valor sugerido|
|---|---|
|**Nome do aplicativo**|`DataApp`|
|**Pasta**|`DataApp` (automático)|
|**Versão**|`1.0.0`|
|**Descrição**|(opcional, mas recomendado)|
|**Autor**|Seu nome|

Após preencher, clique `Save`. Seu novo aplicativo será colocado em `/opt/splunk/etc/apps/`

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413285480.svg|565](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413285480.svg)
**Verificando o aplicativo:**

1. Seu novo aplicativo listado na página `Apps`
2. Permissões e status do aplicativo
3. Ações do aplicativo
4. Clique `Launch App`

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413285534.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413285534.svg)

### Estrutura do Diretório do Aplicativo

```bash
ls /opt/splunk/etc/apps
DataApp                        splunk-dashboard-studio
SplunkForwarder                splunk_archiver
SplunkLightForwarder           splunk_assist
alert_logevent                 splunk_essentials_9_0
alert_webhook                  splunk_gdi
```

**Examinando o diretório `DataApp`:**

```bash
cd /opt/splunk/etc/apps/DataApp
ls
bin  default  local  metadata
```

|Diretório|Conteúdo|
|---|---|
|**`bin`**|Scripts ou executáveis personalizados usados pelo aplicativo|
|**`default`**|Arquivos de configuração padrão do aplicativo|
|**`local`**|Arquivos de configuração modificados (prioridade sobre default)|
|**`metadata`**|Metadados de permissão para o aplicativo|

### Gerando Logs com Python

Vamos criar um script Python que gera logs de exemplo no diretório `bin`:

```bash
cd bin
echo 'print("This is a sample log...")' > samplelogs.py 
python3 samplelogs.py
```

**Saída esperada:**

```text
This is a sample log...
```

### Criando Entradas (inputs.conf)

Para o Splunk ingerir os logs do script, precisamos criar um arquivo `inputs.conf` no diretório `local`:

```bash
nano /opt/splunk/etc/apps/DataApp/local/inputs.conf
```

Cole as seguintes linhas:

```bash
[script:///opt/splunk/etc/apps/DataApp/bin/samplelogs.py]
INDEX = main
SOURCETYPE = testing
HOST = test
INTERVAL = 5
```

**Explicação da entrada:**

|Parâmetro|Valor|Descrição|
|---|---|---|
|`[script://...]`|Caminho do script|Fonte dos dados|
|`INDEX`|`main`|Índice de destino|
|`SOURCETYPE`|`testing`|Tipo de origem personalizado|
|`HOST`|`test`|Identificador do host|
|`INTERVAL`|`5`|Execução a cada 5 segundos|

Reinicie o Splunk:

```bash
/opt/splunk/bin/splunk restart
```

### Verificando a Ingestão de Log

1. Verifique se você está usando o aplicativo `DataApp`
2. Pesquise `index = main`
3. Defina o intervalo de tempo para `All time (real time)`
4. Verifique os resultados da consulta

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413620211.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764413620211.svg)

---

## Configurando os Limites do Evento

**Quebra de eventos** refere-se ao processo de divisão de dados brutos em eventos individuais com base em limites definidos, permitindo que o Splunk entenda onde um evento termina e o próximo começa.

### Entendendo os Eventos

Nesta tarefa, utilizaremos o executável `vpnlogs`. Vamos copiá-lo para o diretório `bin` do nosso aplicativo:

```bash
cp /home/ubuntu/Downloads/scripts/vpnlogs /opt/splunk/etc/apps/DataApp/bin/
cd /opt/splunk/etc/apps/DataApp/bin/
./vpnlogs
```

**Saída do script:**

```bash
User: John Doe, Server: Server B, Action: DISCONNECT
User: Bob Johnson, Server: Server A, Action: CONNECT
User: John Doe, Server: Server D, Action: CONNECT
User: Emily Davis, Server: Server C, Action: CONNECT
User: Bob Johnson, Server: Server B, Action: CONNECT
User: Alice Smith, Server: Server C, Action: DISCONNECT
User: John Doe, Server: Server D, Action: CONNECT
User: Alice Smith, Server: Server C, Action: CONNECT
User: Michael Brown, Server: Server B, Action: DISCONNECT
```

**Campos identificados:**

|Campo|Descrição|
|---|---|
|`User`|O usuário que se conectou|
|`Server`|O servidor ao qual o usuário se conectou|
|`Action`|Ação: `CONNECT` ou `DISCONNECT`|

### Ingerindo Logs VPN

Adicione a seguinte entrada ao `inputs.conf` no diretório `local`:

```bash
[script:///opt/splunk/etc/apps/DataApp/bin/vpnlogs]
INDEX = main
SOURCETYPE = vpn_logs
HOST = vpn_server
INTERVAL = 5
```

Reinicie o Splunk:

```bash
/opt/splunk/bin/splunk restart
```

### Verificando os Logs (Problema Identificado)

No Splunk, execute a pesquisa:

```bash
index = main sourcetype = vpn_logs
```

Defina o intervalo de tempo para `All time (real time)`.

**Problema:** O Splunk é incapaz de determinar os limites do evento — cada evento inclui **todas as 10 linhas** dos logs VPN.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764560881318.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764560881318.svg)

### Corrigindo os Limites de Evento

Vamos criar um padrão regex para instruir o Splunk sobre como identificar o fim de cada evento.

**Observação dos eventos:** Todos os eventos terminam com `CONNECT` ou `DISCONNECT`.

**Testando o regex no [regex101](https://regex101.com/):**


| Expressão | `(CONNECT\|DISCONNECT)`                                         |
| --------- | --------------------------------------------------------------- |
| Função    | Corresponde a todas as ocorrências de `CONNECT` ou `DISCONNECT` |

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764319040700.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764319040700.svg)

### Criando o Arquivo props.conf

Crie o arquivo `props.conf` no diretório `local`:

```bash
nano /opt/splunk/etc/apps/DataApp/local/props.conf
```

Cole a seguinte entrada:

```bash
[vpn_logs]
SHOULD_LINEMERGE = false
MUST_BREAK_AFTER = (CONNECT|DISCONNECT)
```

**Explicação da configuração:**

|Configuração|Valor|Significado|
|---|---|---|
|`SHOULD_LINEMERGE`|`false`|Não mesclar linhas de log (cada linha é um evento)|
|`MUST_BREAK_AFTER`|`(CONNECT\|DISCONNECT)`|Iniciar novo evento após `CONNECT` ou `DISCONNECT`|

Reinicie o Splunk:

```bash
/opt/splunk/bin/splunk restart
```

### Verificando as Mudanças

Execute novamente a consulta `index = main sourcetype = vpn_logs`.

**Resultado:** Os limites do evento agora estão claramente definidos, e o Splunk reconhece cada linha de log como um **evento único**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764561512086.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764561512086.svg)

---

## Analisando Eventos Multilinha

Diferentes fontes de log têm suas próprias maneiras de gerar logs. Algumas geram eventos que **abrangem múltiplas linhas** — e o Splunk nos dá opções para configurar essa situação.

### Entendendo os Eventos

Nesta tarefa, utilizaremos o executável `authentication_logs`:

```bash
cp /home/ubuntu/Downloads/scripts/authentication_logs /opt/splunk/etc/apps/DataApp/bin/
/opt/splunk/etc/apps/DataApp/bin/authentication_logs
```

**Saída do script (log multilinha):**

```bash
[Authentication]: A login attempt was observed from the user Johny Bil and machine Nepture
at: Fri Nov 28 09:06:53 2025 which belongs to the Development department. The login attempt looks Normal.
```

Este log contém informações sobre:

- Tipo de autenticação
- Máquina
- Timestamp
- Departamento
- Outros detalhes relevantes

### Ingerindo Logs de Autenticação

Adicione a seguinte entrada ao `inputs.conf`:

```bash
[script:///opt/splunk/etc/apps/DataApp/bin/authentication_logs]
INDEX = main
SOURCETYPE = auth_logs
HOST = auth_server
INTERVAL = 5
```

Reinicie o Splunk.

### Verificando os Logs (Problema Identificado)

No Splunk, execute:

```bash
index = main sourcetype = auth_logs
```

**Problema:** O Splunk está dividindo cada evento em **dois eventos separados**, pois é incapaz de determinar os limites.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764481502014.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764481502014.svg)

### Corrigindo Eventos Multilinha

Observação: Cada log **começa** com o termo `[Authentication]`. Podemos usar isso como padrão para dividir os eventos.

**Atualizando o `props.conf`:**

```bash
[auth_logs]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = \[Authentication\]
```

**Explicação da configuração:**

|Configuração|Valor|Significado|
|---|---|---|
|`SHOULD_LINEMERGE`|`true`|Combinar múltiplas linhas em um único evento|
|`BREAK_ONLY_BEFORE`|`\[Authentication\]`|Iniciar novo evento antes do termo `[Authentication]`|

> **Nota:** O caractere `[` é escapado com `\` porque tem significado especial em regex.

Reinicie o Splunk.

### Verificando as Mudanças

Execute novamente `index = main sourcetype = auth_logs`.

**Resultado:** O Splunk agora está ingerindo corretamente eventos de múltiplas linhas como **eventos únicos**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764481709753.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764481709753.svg)

---

## Mascarando Dados Sensíveis

Mascarar campos sensíveis, como **números de cartão de crédito**, é crucial para manter a conformidade com padrões como:

|Padrão|Descrição|
|---|---|
|**PCI DSS**|Padrão de Segurança de Dados da Indústria de Cartões de Pagamento|
|**HIPAA**|Lei de Portabilidade e Responsabilidade de Seguros de Saúde|

O Splunk oferece recursos como **mascaramento de campo** e **anonimização** para salvaguardar dados confidenciais.

### Entendendo os Eventos

Vamos usar o script `purchase-details`:

```bash
cp /home/ubuntu/Downloads/scripts/purchase-details /opt/splunk/etc/apps/DataApp/bin/
/opt/splunk/etc/apps/DataApp/bin/purchase-details
```

**Saída do script:**

```bash
User Emma made a purchase with credit card 5555-5555-5555-5555.
User Sophia made a purchase with credit card 6011-1111-1111-1117.
User Michael made a purchase with credit card 5555-5555-5555-5555.
User David made a purchase with credit card 6011-1234-5678-9012.
User Olivia made a purchase with credit card 6011-1234-5678-9012.
```

### Ingerindo Registros de Compra

Adicione ao `inputs.conf`:

```bash
[script:///opt/splunk/etc/apps/DataApp/bin/purchase-details]
INDEX = main
SOURCETYPE = purchase_logs
HOST = order_server
INTERVAL = 5
```

### Configurando Limites de Eventos

Vamos criar um padrão regex para identificar o fim de cada linha de log.

**Testando no [regex101](https://regex101.com/):**

|Expressão|`\d{4}\.`|
|---|---|
|Função|Corresponde a 4 dígitos seguidos por um ponto final (marca o fim da linha)|

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764482217653.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764482217653.svg)

**Adicionando ao `props.conf`:**

```bash
[purchase_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = \d{4}\.
```

### Verificando os Logs (Problema Identificado)

No Splunk, execute `index = main sourcetype = purchase_logs`.

**Problema:** Os logs estão sendo ingeridos corretamente, mas **informações sensíveis de cartão de crédito estão visíveis** para todos.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764562757947.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764562757947.svg)

### Mascarando Informações de Cartão de Crédito

Usaremos o comando `SEDCMD` no `props.conf` para mascarar os dados sensíveis.

**Atualizando o `props.conf`:**

```bash
[purchase_logs]
SHOULD_LINEMERGE = true
MUST_BREAK_AFTER = \d{4}\.
SEDCMD-cc = s/-\d{4}-\d{4}-\d{4}/-XXXX-XXXX-XXXX/g
```

**Explicação do `SEDCMD-cc`:**

|Parte|Significado|
|---|---|
|`SEDCMD-cc`|Comando SED com nome `cc`|
|`s/`|Início do comando de substituição|
|`-\d{4}-\d{4}-\d{4}`|Padrão regex: `-` seguido de 4 dígitos, repetido 3 vezes|
|`-XXXX-XXXX-XXXX`|Texto de substituição (mascaramento)|
|`/g`|Substituir **todas** as ocorrências (global)|

**Exemplo de transformação:**

|Entrada|Saída|
|---|---|
|`5555-5555-5555-5555`|`5555-XXXX-XXXX-XXXX`|

Reinicie o Splunk.

### Verificando as Mudanças

Execute novamente `index = main sourcetype = purchase_logs`.

**Resultado:** As informações sensíveis de cartão de crédito foram mascaradas com sucesso!

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764563017191.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764563017191.svg)

---

## Extraindo Campos Personalizados

O Splunk faz um ótimo trabalho extraindo automaticamente campos de fontes de log suportadas. Mas e quanto a uma fonte de log personalizada, como os logs VPN que ingerimos anteriormente?

**Consulta:** `index = main sourcetype = vpn_logs`

**Problema:** Cada evento tem três campos distintos (`User`, `Server`, `Action`), mas eles **não estão sendo extraídos automaticamente**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764563359977.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764563359977.svg)

### Criando um Padrão Regex

**Exemplo de logs do `vpnlogs`:**

```text
User: John Doe, Server: Server B, Action: DISCONNECT
User: Bob Johnson, Server: Server A, Action: CONNECT
User: John Doe, Server: Server D, Action: CONNECT
```

**Expressão regular para extrair os três campos:**

```text
User:\s(.+?),\sServer:\s(.+?),\sAction:\s(\w+)
```

**Testando no [regex101](https://regex101.com/):**

|Grupo|Captura|
|---|---|
|Grupo 1|`John Doe` (User)|
|Grupo 2|`Server B` (Server)|
|Grupo 3|`DISCONNECT` (Action)|

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764482709280.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764482709280.svg)

### Configurando Transformações (transforms.conf)

Crie o arquivo `transforms.conf` no diretório `local`:

```bash
nano /opt/splunk/etc/apps/DataApp/local/transforms.conf
```

Cole a seguinte estrofe:

```bash
[vpn_custom_fields]
REGEX = User:\s(.+?),\sServer:\s(.+?),\sAction:\s(\w+)
FORMAT = User::$1 Server::$2 Action::$3
WRITE_META = true
```

**Explicação da configuração:**

|Configuração|Valor|Significado|
|---|---|---|
|`REGEX`|`User:\s(.+?)...`|Padrão para capturar os três campos|
|`FORMAT`|`User::$1 Server::$2 Action::$3`|Como nomear os campos extraídos|
|`WRITE_META`|`true`|Escrever metadados para indexação|

### Atualizando Propriedades de Processamento (props.conf)

Atualize o `props.conf` adicionando uma referência à transformação:

```bash
[vpn_logs]
SHOULD_LINEMERGE = false
MUST_BREAK_AFTER = (CONNECT|DISCONNECT)
TRANSFORM-vpn = vpn_custom_fields
```

> **Nota:** A linha `TRANSFORM-vpn = vpn_custom_fields` referencia a convenção de nomenclatura definida em `transforms.conf`.

### Configurando Campos (fields.conf)

Crie o arquivo `fields.conf` no diretório `local`:

```bash
nano /opt/splunk/etc/apps/DataApp/local/fields.conf
```

Cole as seguintes entradas:

```bash
[User]
INDEXED = true

[Server]
INDEXED = true

[Action]
INDEXED = true
```

**Explicação:** Instrui o Splunk a tratar os valores extraídos como **campos indexados**, garantindo que sejam reconhecíveis e pesquisáveis.

Reinicie o Splunk:

```bash
/opt/splunk/bin/splunk restart
```

### Verificando a Extração de Campo

Execute novamente `index = main sourcetype = vpn_logs`.

**Resultado:** A extração de campo personalizada foi realizada com sucesso! Agora os eventos são **pesquisáveis pelos campos** `User`, `Server` e `Action`.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764563714291.svg|697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1764563714291.svg)

### Exercício: Extração de Campos para Logs de Compra

Na tarefa anterior, ingerimos registros de compra e mascaramos as informações sensíveis de cartão de crédito.

**Tarefa:** Configurar o Splunk para extrair os campos `User` e `CC_Number` desses eventos.

**Expressão regular sugerida:**

```text
^User\s+([A-Za-z]+(?:\s+[A-Za-z]+)*?)\s+made a purchase with credit card\s+([0-9]{4}(?:-XXXX){3}|(?:\d{4}[\s-]?){3}\d{4})\.$
```

**Passos:**

1. Adicione uma entrada ao `transforms.conf` para a extração de campo
2. Atualize o `props.conf` com a referência à transformação
3. Altere o `fields.conf` para apresentar os novos campos
4. Reinicie o Splunk

---

## Resumo dos Padrões de Configuração

### inputs.conf

```bash
[script:///caminho/para/script]
INDEX = nome_do_indice
SOURCETYPE = nome_do_tipo_origem
HOST = nome_do_host
INTERVAL = segundos
```

### props.conf (Quebra de Eventos - Linha Única)

```bash
[nome_do_tipo_origem]
SHOULD_LINEMERGE = false
MUST_BREAK_AFTER = (regex_para_fim_do_evento)
```

### props.conf (Eventos Multilinha)

```bash
[nome_do_tipo_origem]
SHOULD_LINEMERGE = true
BREAK_ONLY_BEFORE = (regex_para_inicio_do_evento)
```

### props.conf (Mascaramento de Dados)

```bash
[nome_do_tipo_origem]
SEDCMD-nome = s/regex_para_encontrar/regex_para_substituir/g
```

### props.conf (Extrações de Campo)

```bash
[nome_do_tipo_origem]
TRANSFORM-nome = nome_da_transformacao
```

### transforms.conf

```bash
[nome_da_transformacao]
REGEX = (regex_para_capturar_campos)
FORMAT = nome_campo1::$1 nome_campo2::$2
WRITE_META = true
```

### fields.conf

```bash
[nome_do_campo]
INDEXED = true
```
