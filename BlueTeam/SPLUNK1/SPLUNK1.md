<!--
title: Splunk Analysis
desc: Análise de logs de segurança com a linguagem SPL (Search Processing Language) no Splunk.
tags: splunk, siem, blue-team, analysis
readTime: 8 min
-->

<!-- ===================================== -->
<!--         SPLUNK ANALYSIS GUIDE         -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Tool-Splunk-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Category-SIEM%20Platform-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Use%20Case-Log%20Analysis-red?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Detection%20%7C%20Investigation%20%7C%20Correlation-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Security%20Operations-green?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Beginner%20%E2%86%92%20Advanced-yellow?style=flat-square">
</p>

---

# 🔍 Splunk para SOC Analysts
## Guia Prático de Análise, Investigação e Correlação de Logs

> Em um ambiente de **Security Operations Center (SOC)**, dados são gerados a todo momento — mas apenas dados analisados se tornam inteligência.
>
> O Splunk não é apenas uma ferramenta de busca: ele é um **motor de investigação**, capaz de transformar milhões de eventos em evidências acionáveis.
>
> Para o Analista de Segurança, dominar o Splunk significa:
>
> - Identificar comportamentos suspeitos em meio ao ruído
> - Correlacionar eventos distribuídos em múltiplas fontes
> - Investigar incidentes com precisão e agilidade
> - Reduzir tempo de detecção e resposta (MTTD / MTTR)
>
> Este guia apresenta uma abordagem estruturada para:
>
> - Compreender a arquitetura do Splunk
> - Navegar pela interface de análise
> - Construir consultas eficientes com SPL
> - Filtrar, transformar e correlacionar dados
> - Aplicar o Splunk no contexto real de um SOC

---

## 🎯 Objetivo do Documento

Este material foi desenvolvido para:

- Capacitar analistas na utilização prática do Splunk
- Desenvolver habilidades de investigação baseada em logs
- Melhorar a eficiência na análise de alertas
- Reduzir tempo de triagem e investigação
- Fortalecer a tomada de decisão baseada em dados

---
# SPlunk Analysis

## 1. Introdução ao Splunk

O **Splunk** é uma plataforma de análise de dados em tempo real projetada para coletar, indexar, pesquisar e visualizar grandes volumes de dados não estruturados, como logs de servidores, eventos de segurança e dados de aplicações . Fundada em 2003 por **Michael Baum, Rob Das e Erik Swan**, a empresa foi criada com o objetivo de tornar os dados de máquina acessíveis, utilizáveis e valiosos para as organizações . O nome "Splunk" é uma referência à palavra "spelunking" (exploração de cavernas), simbolizando a exploração de dados em ambientes complexos .

![](https://www.vivantio.com/wp-content/uploads/2024-vivantio-integrations-cover-splunk.png)

### 1.1. O que é o Splunk?

O Splunk é amplamente reconhecido como uma das principais soluções de **SIEM (Security Information and Event Management)** do mercado, sendo utilizado por organizações de todos os portes para monitoramento de segurança, análise operacional e investigação de incidentes . Ele transforma dados brutos de máquina em _insights_ acionáveis através de uma interface intuitiva e da poderosa **SPL (Search Processing Language)** .

### 1.2. Para que Serve o Splunk?

O Splunk é utilizado em diversos cenários:

| Cenário de Uso                        | Descrição                                                                                                                  |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Monitoramento de Segurança (SIEM)** | Coleta e correlaciona logs de firewalls, endpoints, servidores e aplicações para detectar ameaças e responder a incidentes |
| **Análise de Logs**                   | Centraliza logs de diferentes fontes (Windows, Linux, aplicações) em um único local para busca e análise                   |
| **Observabilidade**                   | Monitora o desempenho de aplicações e infraestrutura, identificando gargalos e falhas                                      |
| **Conformidade**                      | Auxilia no atendimento a requisitos regulatórios como PCI-DSS, HIPAA e LGPD através de relatórios e trilhas de auditoria   |
| **Análise Forense**                   | Permite investigar eventos passados, reconstruir linhas do tempo de ataques e identificar a causa raiz de incidentes       |

### 1.3. Arquitetura Distribuída

O Splunk opera em uma arquitetura distribuída que permite escalabilidade e alta disponibilidade. Seus componentes principais trabalham em conjunto para coletar, processar e disponibilizar dados para análise .

---
## 2. Componentes do Splunk

O Splunk possui três componentes principais que formam a espinha dorsal de sua arquitetura: **Forwarder (Encaminhador)**, **Indexer (Indexador)** e **Search Head (Cabeçalho de Busca)**. Esses componentes trabalham em conjunto para permitir a pesquisa e análise de dados em escala.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/cc8fd73eaca524b34ca4dc5e17771997.png)

### 2.1. Splunk Forwarder

O **Forwarder** é um agente leve instalado nos endpoints que se deseja monitorar. Sua principal função é coletar dados localmente e enviá-los para a instância central do Splunk (Indexer). Ele é projetado para ser leve e consumir poucos recursos, não impactando o desempenho do endpoint monitorado.

**Principais fontes de dados coletadas por Forwarders:**

- **Servidores Web:** Logs de acesso, erros e tráfego HTTP/HTTPS
- **Máquinas Windows:** Eventos do Windows, logs do PowerShell, dados do Sysmon
- **Hosts Linux:** Logs de sistema (syslog), logs de aplicações
- **Bancos de Dados:** Solicitações de conexão, respostas, erros e auditoria
- **Firewalls e Dispositivos de Rede:** Logs de tráfego, conexões bloqueadas/permitidas

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/2369fa2efc856b793f1ecbf415681d4d.png)

O Forwarder coleta os dados das fontes de log e os envia para o Indexador Splunk.

### 2.2. Splunk Indexer

O **Indexer** é o componente responsável pelo processamento e armazenamento dos dados recebidos dos Forwarders. Ele desempenha um papel central no pipeline de dados:

1. **Parsing e Normalização:** Analisa os dados brutos, identifica timestamps e os decompõe em pares campo-valor
2. **Indexação:** Armazena os dados processados em índices, otimizando para buscas rápidas
3. **Compressão e Retenção:** Aplica compressão para reduzir uso de espaço e gerencia a retenção de dados conforme políticas configuradas

Após a indexação, os dados estão prontos para serem pesquisados e analisados.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/e699eaa9af523513e9c6a6ab8aaaa6a2.png)
### 2.3. Splunk Search Head

O **Search Head** é a interface onde os usuários interagem com o Splunk para pesquisar e analisar os dados indexados. Ele atua como um "gateway" para as buscas:

- **Interface de Pesquisa:** Fornece a interface web onde os analistas constroem consultas usando SPL
- **Distribuição de Buscas:** Distribui as consultas para os Indexers e agrega os resultados
- **Visualização:** Permite transformar resultados em tabelas, gráficos de pizza, barras, colunas e painéis interativos
- **Gestão de Conhecimento:** Armazena relatórios, alertas, painéis e objetos de conhecimento (lookups, macros)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/0f7738f88ca807d1edf2ac7d84f6951c.png)

O Search Head também permite transformar os resultados em visualizações apresentáveis:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/ce38f9780efac6e22af23c2574367255.png)

---
## 3. Navegando no Splunk

Ao acessar o Splunk, a tela inicial padrão é exibida, oferecendo acesso rápido às principais funcionalidades.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/3880f2e7938460c3aab5da62d622ceac.png)

Vamos analisar cada seção desta tela inicial.

### 3.1. Barra do Splunk

O painel superior é a **Barra do Splunk**, que fornece acesso rápido a configurações e notificações.

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-bar.png)

|Opção|Descrição|
|---|---|
|**Mensagens**|Visualiza notificações e mensagens do sistema|
|**Configurações**|Configura definições da instância Splunk (usuários, índices, etc.)|
|**Atividade**|Acompanha o progresso de tarefas e processos de pesquisa|
|**Ajuda**|Acessa tutoriais, documentação e suporte|
|**Localizar**|Pesquisa em todo o aplicativo|

A Barra do Splunk também permite alternar entre aplicativos instalados.

### 3.2. Painel Aplicativos

O **Painel Aplicativos** mostra os aplicativos instalados na instância Splunk. O aplicativo padrão em todas as instalações é o **Search & Reporting**, que fornece a interface principal para pesquisa e análise.

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-apps-panel.png)

Alternativamente, a troca entre aplicativos pode ser feita diretamente na Barra do Splunk:

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-bar2.png)

### 3.3. Explore o Splunk

O painel **Explore o Splunk** contém links rápidos para ações comuns:

- **Adicionar Dados:** Inicia o assistente para ingerir novas fontes de dados
- **Adicionar Aplicativos:** Acessa o Splunkbase para instalar novos aplicativos
- **Documentação:** Abre a documentação oficial do Splunk

![](https://assets.tryhackme.com/additional/splunk-overview/explore-splunk.png)

### 3.4. Painel do Splunk

O **Painel Inicial** exibe dashboards configurados para visualização rápida. Por padrão, nenhum dashboard é exibido. Você pode:

- Selecionar um dashboard existente no menu suspenso
- Criar seus próprios dashboards e adicioná-los ao Painel Inicial
- Filtrar dashboards pessoais na guia "Seus"

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-add-dashboard.gif)

> **Referência:** Consulte a [documentação oficial sobre navegação](https://docs.splunk.com/Documentation/Splunk/8.1.2/SearchTutorial/NavigatingSplunk) para mais detalhes.

---
## 4. Adicionando Dados ao Splunk

O Splunk pode ingerir qualquer tipo de dado. Segundo a documentação oficial, quando os dados são adicionados, eles são processados e transformados em uma série de eventos individuais. As fontes de dados são agrupadas em categorias.

A tabela abaixo (extraída da documentação do Splunk) detalha cada categoria de fonte de dados:

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-data-sources.png)

### 4.1. Prática: Upload de Logs VPN

Para adicionar dados, clique no link **"Add Data"** na tela inicial do Splunk:

![](https://assets.tryhackme.com/additional/splunk-overview/splunk-add-data.png)

Neste exemplo, utilizaremos a opção **Upload** para enviar um arquivo de log da máquina local.

**Passos para carregar dados com sucesso:**

| Passo                              | Descrição                                                                 |
| ---------------------------------- | ------------------------------------------------------------------------- |
| **1. Selecionar a Origem**         | Escolha o arquivo de log e confirme a fonte de dados                      |
| **2. Selecionar o Tipo de Origem** | Defina o tipo de log (ex: syslog, csv, json)                              |
| **3. Configurações de Entrada**    | Selecione o índice onde os logs serão armazenados e defina o nome do host |
| **4. Revisar**                     | Revise todas as configurações antes de prosseguir                         |
| **5. Concluído**                   | Finalize o carregamento. Os dados estarão prontos para análise            |

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5e8dd9a4a45e18443162feab/room-content/c36a6f1c70007602251f331aee914d5c.gif)

---
## 5. Pesquisa e Relatórios

O aplicativo **Pesquisa e Relatórios** do Splunk é a interface padrão para pesquisar e analisar dados. Ele oferece diversas funcionalidades que auxiliam analistas a aprimorar a experiência de pesquisa.

**Principais funcionalidades:**

1. **Cabeçalho de Pesquisa:** Área onde os analistas constroem consultas usando SPL
2. **Seletor de Duração:** Define o período de tempo da pesquisa (últimos 15 min, 1 hora, 24 horas, Todo o período, etc.)
3. **Histórico de Pesquisa:** Salva consultas utilizadas anteriormente
4. **Resumo de Dados:** Fornece visão geral de hosts, fontes e tipos de fonte disponíveis

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761637957195.svg)

### 5.1. Sua Primeira Pesquisa

Nesta sala, trabalharemos com o índice de logs do Windows. Realize sua primeira consulta definindo o intervalo de tempo como **"All time"** (Todo o período).

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761982351687.svg)

### 5.2. Barra Lateral de Campos

A barra lateral de campos, localizada no painel esquerdo da pesquisa, apresenta duas seções principais:

- **Campos Selecionados:** Campos extraídos por padrão. Você pode selecionar outros campos clicando neles e alternando a opção `Selected`
- **Campos Relevantes:** Exibe todos os campos encontrados nos resultados, permitindo exploração aprofundada

**Indicadores na barra lateral:**

| Símbolo      | Significado                                  |
| ------------ | -------------------------------------------- |
| `#`          | Campo numérico                               |
| `α`          | Campo alfanumérico (texto)                   |
| **Contagem** | Número de eventos que contêm o campo listado |

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761637958326.svg)

---
## 6. Search Processing Language (SPL)

A **SPL (Search Processing Language)** é a linguagem de consulta do Splunk. Ela combina comandos, funções e operadores que permitem filtrar, transformar e analisar dados dos logs ingeridos. Com SPL, é possível pesquisar grandes volumes de dados, aplicar filtros para refinar resultados e formatar a saída para destacar o que é mais importante.

### 6.1. Operadores de Busca

Os  [operadores](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/expressions-and-predicates/predicate-expressions) são os blocos de construção de qualquer consulta SPL. São usados para filtrar, remover e refinar resultados.

#### 6.1.1. Operadores Relacionais

Usados para comparar duas expressões.

| **Operador** | **Exemplo**              | **Explicação**                                                                        |
| ------------ | ------------------------ | ------------------------------------------------------------------------------------- |
| `=`          | `UserName = Mark`        | Pesquise todos os eventos em que o campo `UserName` seja igual a `Mark`.              |
| `!=`         | `UserName != Mark`       | Pesquise todos os eventos em que o nome do campo `UserName` seja diferente de `Mark`. |
| `<`          | `Age < 10`               | O campo `Age` tem um valor inferior a `10`.                                           |
| `<=`         | `Age <= 10`              | O campo `Age` tem um valor inferior ou igual a `10`.                                  |
| `>`          | `Outbound_Traffic > 50`  | O campo `Outboun_Traffic` tem um valor maior que `50`.                                |
| `>=`         | `Outbound_Traffic >= 50` | O campo `Outboun_Traffic` tem um valor maior ou igual a `50`.                         |

**Exemplo prático:** Localizar logs onde o campo `AccountName` não é igual a "System".

```
index = windowslogs AccountName != SYSTEM
```

Na captura de tela abaixo e em sua instância do Splunk, você pode ver que filtramos com sucesso todos os eventos que não incluem o valor `SYSTEM` no campo `AccountName`.

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761983277759.svg)

#### 6.1.2. Operadores Lógicos

O Splunk suporta os seguintes operadores lógicos, que podem ser usados ​​para conectar ou modificar condições e operar em valores booleanos (verdadeiro/falso).

| **Operadores** | **Exemplos**                                   | **Explicação**                                                                                                |
| -------------- | ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `NOT`          | `UserName NOT David`                           | Ignore os eventos em que o campo `UserName` contém o valor `David`.                                           |
| `AND`          | `UserName = David AND IPAddress = 10.10.10.10` | Retorna todos os eventos em que o campo `UserName` contém `David` e o campo `IPAddress` contém `10.10.10.10`. |
| `OR`           | `UserName = David OR UserName = John`          | Retorna todos os eventos em que o campo `UserName`contém `David` ou `John`.                                   |

**Exemplo prático:** Filtrar eventos excluindo "SYSTEM" e mantendo apenas "James".

```
index = windowslogs AccountName != SYSTEM AND AccountName = James
```

> **Nota:** O operador `AND` está implícito entre os termos. A consulta acima é equivalente a `index = windowslogs AccountName != SYSTEM AccountName = James`.

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761983277849.svg)

#### 6.1.3. Wildcards (Caracteres Curinga)

Usados para corresponder a padrões em strings.

|Símbolo|Exemplo|Explicação|
|---|---|---|
|`*`|`status = fail*`|Retorna eventos com valores como `failed`, `failure`, etc.|

**Exemplo prático:** Exibir apenas endereços `DestinationIp` que começam com `172`.

```
index = windowslogs DestinationIp = 172.*
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761983277642.svg)

### 6.2. Sintaxe de Busca e Ordem de Avaliação

#### 6.2.1. Aspas

Aspas `""` são usadas para definir frases exatas. Pesquisar `"failed login"` encontra a frase exata, enquanto `failed login` retorna resultados contendo qualquer uma das palavras.

#### 6.2.2. Parênteses

Parênteses agrupam condições e controlam a ordem de avaliação. A ordem de precedência do Splunk é:

1. `()` Expressões com parênteses
2. Cláusulas `NOT`
3. Cláusulas `OR`
4. Cláusulas `AND`

---
## ## 7. Filtrando Resultados com SPL

Em ambientes de rede, milhares de logs por minuto podem ser gerados. Filtrar resultados é essencial para focar em eventos relevantes. No Splunk, comandos são encadeados através do símbolo de barra vertical `|`, passando a saída de um comando para o próximo.

### 7.1. Comandos de Filtragem Úteis

#### 7.1.1. Search

O comando [`search`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/search) filtra eventos que contenham um termo específico.

```
index = windowslogs | search PowerShell
```

#### #### 7.1.2. Fields

O comando [`fields`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/fields) inclui ou exclui campos específicos dos resultados. Use `-` para excluir e `+` para incluir (opcional).
```
index = windowslogs | fields host User SourceIp
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761983835185.svg)

#### 7.1.3. Dedup

O comando [`dedup`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/dedup) remove valores duplicados.

```
index = windowslogs | fields EventID User Image Hostname SourceIp | dedup SourceIp
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761984385617.svg)

#### 7.1.4. Rename

O comando [`rename`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/regex) altera o nome de um campo.

```
index = windowslogs | fields EventID User Image Hostname SourceIp | rename User as Employee
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761984383616.svg)

#### 7.1.5. Regex

O comando [`regex`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/regex) filtra usando expressões regulares.

```
index = windowslogs | regex Image = "\.exe$"
```

A consulta retorna eventos onde o campo `Image` termina com `.exe`. O símbolo `$` indica o final da string.

---
## 8. Estruturando os Resultados da Pesquisa

### 8.1. Table

O comando [`table`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/table) seleciona campos específicos e os exibe em formato tabular.

```
index = windowslogs | table _time EventID Hostname SourceName
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761985298536.svg)

### 8.2. Outros Comandos de Estruturação

|Comando|Exemplo|Explicação|
|---|---|---|
|`head`|`index = windowslogs \| head 20`|Retorna os primeiros (mais recentes) eventos|
|`tail`|`index = windowslogs \| tail 20`|Retorna os últimos (mais antigos) eventos|
|`sort`|`index = windowslogs \| sort User`|Classifica em ordem alfabética pelo campo especificado|
|`reverse`|`index = windowslogs \| reverse`|Inverte a ordem dos eventos|

### 8.3. Linhas do Tempo e Correlação em Tabelas

O comando `table` pode ser combinado para criar linhas do tempo. No exemplo abaixo, filtramos eventos de logon (`EventID=4624`) e organizamos cronologicamente:

```
index = windowslogs EventID = 4624
| table _time Hostname LogonType LogonProcessName RecordNumber
| dedup _time
| reverse
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761985100960.svg)

### 8.4. Correlação de Eventos

Para correlacionar atividades em múltiplas fontes, podemos focar em um host específico:

```
index = windowslogs Hostname = Salena.Adam
| table _time Hostname EventID Category
| reverse
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761985100862.svg)

---
## 9. Comandos de Transformação

[Comandos de transformação](https://help.splunk.com/en/splunk-cloud-platform/search/search-manual/10.0.2503/create-statistical-tables-and-chart-visualizations/about-transforming-commands-and-searches) convertem dados brutos em resumos, estatísticas e visualizações.

### 9.1. Comandos Gerais de Transformação

|Comando|Exemplo|Explicação|
|---|---|---|
|`top`|`index = windowslogs \| top User limit=5`|Retorna os valores mais frequentes do campo|
|`rare`|`index = windowslogs \| rare User limit=5`|Retorna os valores menos frequentes do campo|

### 9.2. Highlight

O comando [`highlight`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/highlight) marca visualmente os valores selecionados. Altere o formato de visualização de `List` para `Raw` para visualizar os resultados.

```
index = windowslogs | highlight User EventID Image "Process accessed"
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761986974380.svg)

### 9.3. Stats

O comando [`stats`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/stats) calcula estatísticas agregadas.

|Função|Exemplo|Descrição|
|---|---|---|
|`avg`|`stats avg(ProcessCount)`|Valor médio|
|`max`|`stats max(Price)`|Valor máximo|
|`min`|`stats min(UserAge)`|Valor mínimo|
|`sum`|`stats sum(Cost)`|Soma dos valores|
|`count`|`stats count by SourceIp`|Número de ocorrências|

**Exemplo:** Contar ocorrências por EventID e ordenar:

```
index = windowslogs | stats count by EventID | sort EventID
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761986963935.svg)

### 9.4. Chart

O comando [`chart`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/chart) retorna resultados em formato tabular, ideal para visualizações.

```
index = windowslogs | chart count by User
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761986964932.svg)

### 9.5. Timechart

O comando [`timechart`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/timechart) visualiza como os dados mudam ao longo do tempo.

```
index = windowslogs Image != "" | timechart span=30m count by Image limit=5
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761986963771.svg)

### 9.6. Enriquecimento de Dados e Manipulação de Campos

#### 9.6.1. iplocation

O comando [`iplocation`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/iplocation) enriquece eventos com informações geográficas sobre endereços IP.

```
index = windowslogs | iplocation SourceIp | stats count by Country
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761986993701.svg)

#### 9.6.2. Lookup

O comando [`lookup`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/lookup) enriquece eventos usando fontes de dados externas (CSV, tabelas de pesquisa).

```
index = windowslogs
| lookup user_roles Hostname OUTPUT UserRole
| stats count by Hostname UserRole
```

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761986963613.svg)

#### #### 9.6.3. Eval

O comando [`eval`](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands/eval) é uma ferramenta versátil para criar novos campos, modificar campos existentes e realizar cálculos.

**Exemplo:** Criar um campo descritivo para valores numéricos de `LogonType`.

```
index = windowslogs
| eval LogonTypeDesc = case(LogonType == 3, "Network Logon", LogonType == 5, "Service")
| stats count by LogonType LogonTypeDesc
```

A consulta atribui:

- "Network Logon" quando `LogonType` é 3
- "Service" quando `LogonType` é 5

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1761986963855.svg)

---
## 10. Detecção de Anomalias

### Visão Geral

Ao investigar grandes conjuntos de dados (ex: logins de VPN, acessos a arquivos, conexões de rede), você frequentemente precisa identificar rapidamente **outliers** — eventos que parecem suspeitos em comparação com os demais.

**Cenário exemplo:** Um conjunto de dados com **2.000 logins de VPN** contendo apenas quatro campos:

- Timestamp do login
- Nome do usuário
- IP de origem
- País de origem

**Desafio:** Como identificar logins de países inesperados quando as estatísticas de campo não mostram anomalias óbvias?

![https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1774320082276.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1774320082276.png)
### 10.1 Detectando Outliers por País

**Contexto de negócio:** Para um usuário baseado nos EUA, login dos EUA é esperado. Mas para um usuário baseado na UE, login dos EUA pode ser um forte sinal de intrusão ou uso de VPN.

#### Comandos Splunk Utilizados

|Comando|Função|
|---|---|
|`eventstats`|Similar ao `stats`, mas **preserva os eventos brutos** para processamento posterior|
|`where`|Similar ao `search`, mas **mais poderoso** para filtros complexos|
|`eval`|Cria novos campos ou transforma valores existentes|
|`table`|Exibe apenas os campos especificados|

#### Consulta para Detecção por País

```text
index=vpnlogs
| eventstats count as logins_by_user by user 
| eventstats count as logins_by_user_country by user src_country 
| eval country_freq = logins_by_user_country / logins_by_user
| where country_freq < 0.1
| table _time user src_ip src_country country_freq
```

#### Explicação Passo a Passo

|Linha / Comando|Resultado|Exemplo (usuário kbrown)|
|---|---|---|
|**Linha 2:** `eventstats count as logins_by_user by user`|Total de logins por usuário|`logins_by_user = 200`|
|**Linha 3:** `eventstats count as logins_by_user_country by user src_country`|Logins por usuário **e** país de origem|Para kbrown + Áustria: `logins_by_user_country = 1`|
|**Linha 4:** `eval country_freq = logins_by_user_country / logins_by_user`|Frequência de logins por país (0 = raro, 1 = comum)|`country_freq = 1 ÷ 200 = 0,005` (muito raro!)|
|**Linha 5:** `where country_freq < 0.1`|Inclui apenas pares usuário-país **raros**|0,005 < 0,1 → **incluído**|
|**Linha 6:** `table ...`|Exibe os outliers|Apenas 2 eventos de 2.000!|

> **Definição de limiar:** O valor `0.1` (10%) é chamado de **limiar (threshold)**. Pares usuário-país com frequência abaixo deste valor são considerados anômalos.

#### Resultado Esperado

![https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1774320082246.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1774320082246.png)

**Interpretação:** Apenas **2 outliers** foram identificados em 2.000 eventos. Ambos os usuários comprometidos (`kbrown` e um segundo usuário) fizeram login em países anômalos **apenas uma vez** — um forte sinal de uso de VPN ou violação de credenciais.

### 10.2 Detectando Outliers por Horário

A detecção por horário é **mais complexa** que a detecção por país, pois você precisa considerar:

- **Diferentes fusos horários** dos funcionários    
- **Diferentes hábitos de trabalho** (horário comercial vs. noturno)

#### Metodologia: Z-Score

|Conceito|Definição|Exemplo|
|---|---|---|
|**Hora típica**|Hora média em que o funcionário faz login|13:30 UTC|
|**Desvio padrão**|Medida de previsibilidade (0 = mais previsível)|`stdev_hour = 2` → login esperado às 13:30 ± 2 horas|
|**Z-Score**|Número de desvios padrão entre a hora observada e a típica|`zscore = 3` → hora de login x3 anômala para este usuário|

#### Consulta para Detecção por Horário

```text
index=vpnlogs
| eval hour = tonumber(strftime(_time, "%H")) + tonumber(strftime(_time, "%M"))/60
| eventstats avg(hour) as typical_hour stdev(hour) as stdev_hour by user
| eval zscore = abs(hour - typical_hour) / stdev_hour
| where zscore > 3
| eval hour = round(hour, 2), typical_hour = round(typical_hour, 2)
| eval stdev_hour = round(stdev_hour, 2), zscore = round(zscore, 2)
| table _time user src_ip src_country hour typical_hour stdev_hour zscore
| sort - zscore
```

#### Explicação da Consulta

|Linha|Comando|Propósito|
|---|---|---|
|2|`eval hour = ...`|Converte timestamp em hora decimal (ex: 13:30 = 13,5)|
|3|`eventstats avg(...) stdev(...) by user`|Calcula média e desvio padrão **por usuário**|
|4|`eval zscore = ...`|Mede o quão anômala é a hora do login|
|5|`where zscore > 3`|Filtra apenas logins **altamente anômalos** (threshold = 3σ)|
|6-7|`eval ... round(...)`|Arredonda valores para melhor visualização|
|8-9|`table ... sort -zscore`|Exibe e ordena resultados por z-score (maior→menor)|

#### Resultado Esperado

![https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1774320082620.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1774320082620.png)

**Exemplo prático:** O usuário `jsmith` tem:

- Horário típico de login: **13:30**    
- Baixo desvio padrão (login consistente)
- Um login observado às **18:30** (5 horas após o normal)
- Z-Score elevado → **vale a pena investigar!**

### 10.3 Técnicas Avançadas

#### Viagem Impossível (Impossible Travel)

Detecções mais avançadas, como a [Viagem Impossível](https://lantern.splunk.com/Security_Use_Cases/Compliance/Running_common_GDPR_compliance_searches/Geographically_improbable_access_detected), são construídas sobre os mesmos comandos básicos abordados nesta sala.

**Conceito:** Um mesmo usuário não pode fazer login no Brasil e na Austrália com 10 minutos de diferença — isso violaria as leis da física (tempo de viagem de avião).

**Componentes necessários:**

- Conhecimento de **SPL** (Splunk Processing Language)
- **Matemática básica** (cálculo de distâncias geográficas)
- **Contexto de ameaças** (geolocalização de IPs, inteligência de ameaças)

#### Comandos Splunk Avançados para Detecção

|Comando|Função|Exemplo de Uso|
|---|---|---|
|`iplocation`|Geolocaliza endereços IP|`iplocation src_ip` → latitude, longitude, país, cidade|
|`lookup`|Enriquece dados com tabelas externas|`lookup threat_intel.csv ip OUTPUT threat_score`|
|`fit`|Treina modelos de machine learning|`fit StandardScaler` → padronização de dados|
|`apply`|Aplica modelos treinados a novos dados|`apply anomaly_detection_model` → detecta outliers futuros|

#### Exemplo: Detecção de Viagem Impossível (Conceitual)

```text
index=vpnlogs
| iplocation src_ip
| eventstats earliest(_time) as first_login, latest(_time) as last_login by user
| eval travel_time_hours = (last_login - first_login) / 3600
| eval distance_km = geo_distance(initial_lat, initial_lon, final_lat, final_lon)
| eval possible = if(distance_km / 800 < travel_time_hours, "POSSÍVEL", "IMPOSSÍVEL")
| where possible = "IMPOSSÍVEL"
```

#### Machine Learning no Splunk

O Splunk permite **treinar modelos** nos seus dados e **aplicá-los** a novos eventos:

|Fase|Comando|Descrição|
|---|---|---|
|**Treinamento**|`fit`|Cria um modelo baseado em dados históricos (ex: "horários normais do usuário")|
|**Aplicação**|`apply`|Usa o modelo treinado para classificar novos eventos (ex: "este login é anômalo?")|

**Exemplo conceitual:**

```text
index=vpnlogs
| fit IsolationForest anomaly_detection by user hour src_country
| apply anomaly_detection to new_logs
```

### Resumo dos Padrões de Detecção

|Tipo de Anomalia|Comandos Principais|Limiar Típico|Aplicação|
|---|---|---|---|
|**País raro**|`eventstats`, `eval`, `where`|`country_freq < 0.1`|VPNs suspeitas, contas comprometidas|
|**Horário anômalo**|`strftime`, `avg`, `stdev`, `zscore`|`zscore > 3`|Acesso fora do horário comercial|
|**Viagem impossível**|`iplocation`, `geo_distance`, `eval`|`travel_time < físico`|Roubo de sessão, conta comprometida|
|**ML - Anomalia geral**|`fit`, `apply`|Modelo-dependente|Detecção de padrões complexos|


> **Boas práticas:** 
> - Ajuste os **limiares** conforme a realidade da sua organização
> - Combine **múltiplos métodos** (país + horário) para maior precisão
> - Use **visualizações** (tabelas, gráficos de dispersão) para validar os outliers
> - Comece com regras simples antes de avançar para ML

---
## 11. Conclusão

O Splunk é uma ferramenta essencial no ecossistema de segurança e análise de dados, oferecendo uma plataforma robusta para coleta, indexação, pesquisa e visualização de logs. Seus três componentes principais — **Forwarder, Indexer e Search Head** — trabalham em conjunto para fornecer escalabilidade e eficiência no processamento de grandes volumes de dados.

A **SPL (Search Processing Language)** é a linguagem que potencializa a análise, permitindo que analistas filtrem, transformem e correlacionem eventos com precisão. Dominar os operadores relacionais e lógicos, os comandos de filtragem (`fields`, `dedup`, `regex`), os comandos de estruturação (`table`, `sort`) e os comandos de transformação (`stats`, `timechart`, `eval`) é fundamental para extrair _insights_ acionáveis dos dados.

Para profissionais de cibersegurança, o Splunk é uma ferramenta indispensável para:

- **Detecção de ameaças** através de correlação de eventos
- **Investigações forenses** com linhas do tempo detalhadas
- **Monitoramento operacional** de infraestrutura crítica
- **Conformidade** com relatórios e trilhas de auditoria    

Com a prática e o aprofundamento em SPL, o Splunk se torna um aliado poderoso na defesa e análise de ambientes corporativos.

---
## 12. Referências

|Tipo|Descrição|Link|
|---|---|---|
|**Documentação Oficial**|Navegação no Splunk|[docs.splunk.com/Documentation/Splunk/8.1.2/SearchTutorial/NavigatingSplunk](https://docs.splunk.com/Documentation/Splunk/8.1.2/SearchTutorial/NavigatingSplunk)|
|**Documentação Oficial**|Expressões e Predicados|[help.splunk.com/en/splunk-enterprise/search-manual/10.0/expressions-and-predicates/predicate-expressions](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.0/expressions-and-predicates/predicate-expressions)|
|**Documentação Oficial**|Caracteres Curinga|[help.splunk.com/en/splunk-enterprise/search-manual/9.4/search-primer/wildcards](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/search-primer/wildcards)|
|**Documentação Oficial**|Comandos de Pesquisa SPL|[help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands](https://help.splunk.com/en/splunk-enterprise/spl-search-reference/9.0/search-commands)|
|**Documentação Oficial**|Comandos de Transformação|[help.splunk.com/en/splunk-cloud-platform/search/search-manual/10.0.2503/create-statistical-tables-and-chart-visualizations/about-transforming-commands-and-searches](https://help.splunk.com/en/splunk-cloud-platform/search/search-manual/10.0.2503/create-statistical-tables-and-chart-visualizations/about-transforming-commands-and-searches)|
|**Splunk**|Página Oficial|[splunk.com](https://www.splunk.com)|
