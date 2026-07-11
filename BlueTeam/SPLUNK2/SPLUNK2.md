<!--
title: Splunk Dashboards & Reports
desc: Criação de painéis visuais, métricas de segurança e relatórios automatizados no Splunk para SOC.
tags: splunk, dashboard, reporting
readTime: 6 min
-->

<!-- ===================================== -->
<!--       SPLUNK SOC VISIBILITY GUIDE     -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Splunk-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Dashboards%20%7C%20Reports%20%7C%20Alerts-orange?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Domain-SIEM-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Operations-SOC-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Analysis-Log%20Monitoring-green?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Beginner%20%E2%86%92%20Intermediate-yellow?style=flat-square">
</p>

---

# 📊 Splunk: Dashboards e Relatórios
## Visualização, Monitoramento e Automação de Análises em um SOC

> Em um ambiente corporativo moderno, milhares — ou até milhões — de eventos são gerados diariamente.
>
> Logs de autenticação, acessos web, VPNs, firewalls, servidores, endpoints e aplicações produzem um fluxo constante de informações.
>
> Sem organização adequada, esse volume rapidamente se transforma em:
>
> - Ruído operacional
> - Sobrecarga de analistas
> - Falhas de visibilidade
> - Incidentes ignorados
>
> É exatamente nesse cenário que o **Splunk** se destaca.
>
> Mais do que apenas um mecanismo de busca para logs, o Splunk permite:
>
> - Centralizar eventos de múltiplas fontes
> - Criar visualizações inteligentes
> - Detectar comportamentos suspeitos
> - Automatizar monitoramento e resposta
> - Transformar dados brutos em inteligência operacional

---

# Splunk: Dashboards e Relatórios

## Introdução

Splunk é uma das soluções de **SIEM (Security Information and Event Management)** mais utilizadas em ambientes corporativos. Ele ajuda a agregar dados de várias fontes dentro de uma organização para melhorar o monitoramento de segurança. No entanto, grandes volumes de dados podem rapidamente sobrecarregar os analistas.

Nesta sala, você aprenderá maneiras práticas de **organizar, visualizar e gerenciar dados** no Splunk para tornar a análise mais rápida, clara e eficaz.

---

## Criando Relatórios para Pesquisas Recorrentes

Após carregar o Splunk, acesse `Search & Reporting` para inserir a primeira consulta:

```text
index = *
```

Defina o intervalo de tempo para `All time` para obter uma visão geral dos dados disponíveis.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763448296050.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763448296050.svg)

Na captura de tela, é possível observar que há **mais de 10.000 eventos** presentes nos dados. Vasculhar manualmente esses dados seria demorado e ineficiente. Visualizar dados brutos raramente é útil para avaliar a postura geral de segurança de uma organização, fornecendo pouca visão sobre ameaças potenciais ou ataques em andamento.

Felizmente, o Splunk oferece ferramentas para **agregar, visualizar e analisar dados** de forma eficiente.

### Construindo Relatórios

Em um ambiente SOC, **buscas recorrentes** são comuns. Por exemplo:

- Uma organização pode agendar uma pesquisa para ser executada a cada **oito horas** quando uma nova mudança de analistas começar ou terminar
- Criar um **relatório agendado** é eficiente, pois executa automaticamente a pesquisa e salva os resultados para revisão posterior

**Benefícios dos relatórios agendados:**

| Benefício                | Descrição                                                               |
| ------------------------ | ----------------------------------------------------------------------- |
| **Redução de carga**     | Diminui a carga no motor de pesquisa do Splunk                          |
| **Desempenho otimizado** | Agendar em intervalos curtos (5-10 minutos) garante execução mais suave |
| **Resultos rápidos**     | Evita execução manual de múltiplas pesquisas no início de cada turno    |

Navegando para a aba `Reports`, é possível observar uma lista de relatórios padrão. Clicar em qualquer relatório exibirá os resultados. Você também pode clicar em `Open in Search` para visualizar as configurações de consulta e tempo no aplicativo de pesquisa.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763448295841.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763448295841.svg)

### Criando Seu Primeiro Relatório

Vamos navegar de volta para **Search** e executar uma consulta para criar nosso primeiro relatório. Defina o intervalo de tempo para `All time`:

```text
index = vpn_server | stats count by Username | sort - count
```

**O que esta consulta faz:**

|Comando|Função|
|---|---|
|`index = vpn_server`|Pesquisa o índice de servidor VPN|
|`stats count by Username`|Agrupa e conta eventos por nome de usuário|
|`sort - count`|Ordena em ordem decrescente pela contagem|

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763354075304.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763354075304.svg)

**Observação:** Na captura de tela, temos um total de 86 eventos, e `Sarah` tem o maior número de eventos registrados.

Para salvar como relatório, clique em `Save As` → `Report`.

**Configurações do relatório:**

|Campo|Valor sugerido|
|---|---|
|**Título**|(escolha um título descritivo)|
|**Descrição**|(opcional, mas recomendado)|
|**Tipo de conteúdo**|`Statistics Table` (automático com `stats count`)|
|**Time Range Picker**|Ativo ou inativo conforme necessidade|

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763360609521.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763360609521.svg)

Após salvar, você verá seu relatório. A partir daqui, você pode:

- **Editar** o relatório   
- **Abrir na pesquisa** para ajustar a consulta
- **Adicionar a um dashboard**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763344072522.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763344072522.svg)

### Agendamento de um Relatório

Relatórios são poderosos por si só, mas seu **valor real aparece quando combinados com agendamento**.

**Considerações sobre licenciamento:**

|Licença|Agendamento disponível|
|---|---|
|**Splunk Free**|❌ Não disponível|
|**Splunk Enterprise**|✅ Disponível|

**Exemplo de configuração de agendamento:**

Conforme mostrado na captura de tela abaixo, você pode configurar relatórios para:

- Executar em **programação recorrente** (ex: diariamente à meia-noite)
- Usar as **24 horas anteriores de dados**
- Definir **janela de prioridade e agendamento** para coordenar múltiplos relatórios

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763433278902.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763433278902.svg)

---
## Detectando Alertas e Regras

Você aprendeu como criar relatórios básicos para exibir informações rapidamente. Mas e se você quisesse ser **notificado quando uma atividade específica ocorre**?

**Casos de uso comuns para alertas:**

- Múltiplas tentativas de login com falha em um único endpoint
- Endereço IP externo tentando acessar um portal interno de funcionários

Com alertas, o Splunk pode **detectar automaticamente** esses eventos e **notificar os analistas em tempo real**.

> **Nota:** Devido às limitações da licença gratuita do Splunk, não é possível praticar a configuração de alertas na instância anexa. No entanto, você pode acompanhar as consultas e capturas de tela para aprendizado.

### Construindo Alertas

Vamos explorar o índice `web_logs` e revisar os dados disponíveis. Temos **10.000 logs** disponíveis para análise. Verificando o campo `URI`, `/restricted.html` certamente parece interessante.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763354223251.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763354223251.svg)

**Cenário:** Suponha que `/restricted.html` normalmente só deve ser acessado a partir de **endereços IP da rede interna**.

**Consulta para identificar acesso não autorizado:**

```text
index = web_logs URI = /restricted.html NOT Source_IP IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
```

Esta consulta retorna eventos onde o `Source_IP` está **fora** dos intervalos internos esperados.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773197499135.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773197499135.svg)

**Configurações do alerta:**

Após inserir a consulta, clique em `Save As` → `Alert`.

|Configuração|Opção|Descrição|
|---|---|---|
|**Tipo de alerta**|Em tempo real|Funciona continuamente; aciona assim que um evento corresponde|
|**Alerta de gatilho quando**|Per-Result|Aciona toda vez que um único evento corresponde aos critérios|
|**Quando acionado**|Enviar e-mail|Ex: enviar para `soc@tryhackme.com`|

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763435682009.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763435682009.svg)

### Construindo uma Regra de Linha de Base e Limiar

Agora, vamos focar no `/payments.html` do índice `web_logs`.

```text
index = web_logs URI = /payments.html
```

Examinando o campo `status_code`, você pode ver que a página retorna uma variedade de respostas:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773197225798.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773197225798.svg)

**Cenário:** Queremos criar um alerta para **picos de respostas 404**. Mas o que consideramos um "pico"?

**Estabelecendo uma linha de base:**

A consulta abaixo:

1. Pesquisa `status_code = 404` no índice `web_logs`
2. Agrupa eventos em **intervalos de 1 hora**
3. Conta o número de eventos   
4. Calcula a média

```text
index = web_logs URI = /payments.html status_code = 404
| bin _time span=1h
| stats count AS hits BY _time
| eventstats avg(hits) AS avg_hits 
| eval avg_hits = round(avg_hits, 1)
```

**Resultado da linha de base:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773279577348.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773279577348.svg)

Com base nos eventos disponíveis, `/payments.html` gera uma **média de 7,6 respostas 404 por hora**.

**Definindo um limiar:**

|Consideração|Impacto|
|---|---|
|Fins de semana, feriados|Podem alterar a média|
|Campanhas de marketing|Aumentam temporariamente o tráfego|
|Número fixo (ex: 10)|Risco de falsos positivos ou falsos negativos|

**Consulta com limiar de >11 (aproximadamente 1,45× a média):**

```text
index = web_logs URI = /payments.html status_code = 404
| bin _time span=1h
| stats count AS hits BY _time
| where hits > 11
| eval alert = "HIGH 404s: ".hits." in 1h (normal: ~7.6/hr)"
```

**Comportamento do alerta:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773279268556.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1773279268556.svg)

Se a contagem exceder 11, o alerta exibe:

- Eventos dentro da janela de uma hora
- Número total de respostas recebidas

**Opções de notificação:**

- Notificação no aplicativo
- E-mail
- Ações adicionais configuráveis   
- Histórico de gatilhos do alerta

---
## Criando Dashboards para Resumir Resultados

No Splunk, **dashboards** fornecem acesso rápido a informações sobre os dados presentes. Dashboards são frequentemente criados para fornecer uma **visão geral resumida** de campos importantes e estatísticas de dados.

**Casos de uso:**

- Exibir número de incidentes em um período especificado
- Identificar picos ou quedas em eventos específicos

Navegando para a aba **Dashboards**, você verá uma lista de painéis padrão, incluindo o que usaremos: `Web Logs Overview`.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763451413208.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763451413208.svg)

### Criando um Novo Dashboard

Você tem duas opções:

|Opção|Características|
|---|---|
|**Dashboard Studio**|Mais recente; maiores opções de personalização; curva de aprendizado mais complexa|
|**Classic Dashboards**|Mais comum; suporta todas as visualizações padrão (**abordagem desta sala**)|

**Configurações iniciais:**

- Título (obrigatório)
- Descrição (opcional)
- Permissões
- Tipo de dashboard

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763451413367.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763451413367.svg)

### Editando um Dashboard Existente

Selecione o dashboard **Web Logs Overview**. Atualmente, possui um único painel que visualiza a contagem de eventos ao longo do tempo a partir do índice `web_logs`.

Para adicionar mais visualizações, clique em `Edit` → `+ Add Panel`.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763514341848.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763514341848.svg)

### Adicionando um Gráfico de Pizza

Vamos construir um gráfico de pizza que mostra a contagem de eventos para o campo `URI`:

 1. **Novo** → **Gráfico de Pizza**
 2. **Intervalo de tempo:** `All time`
 3. **Título:** (insira um título descritivo)
 4. **String de pesquisa:**

```text
index = web_logs | stats count by URI | sort - count
```

5. Clique em **Adicionar ao painel**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763451413304.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763451413304.svg)

### Adicionando uma Tabela de Estatísticas

Agora, vamos criar uma tabela de estatísticas para o campo `/restricted.html` mostrando:

- Códigos de status (`status_code`)
- Contagem de eventos
- Percentual de eventos
- Total geral de eventos

**String de pesquisa:**

```text
index = web_logs URI = /restricted.html
| stats count by status_code
| eventstats sum(count) as total
| eval percent = round(count * 100.0 / total, 2)
| sort - count
```

**Configuração:**

1. `+ Add Panel` → **Novo** → **Tabela de Estatísticas**
2. **Intervalo de tempo:** `All time`
3. Insira a consulta acima

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763452206083.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763452206083.svg)

---
## Estendendo as Funcionalidades do Splunk

Criar relatórios, alertas e dashboards são maneiras poderosas de analisar dados no Splunk. No entanto, a visibilidade por si só não é suficiente para um SOC moderno.

Para **transicionar de observar ameaças para gerenciá-las e mitigá-las ativamente**, o Splunk oferece soluções avançadas:

|Solução|Função|
|---|---|
|**Enterprise Security**|Detecção e investigação|
|**UEBA**|Análise de comportamento de usuários e entidades|
|**SOAR**|Resposta automatizada|

> **Nota:** As soluções Enterprise Security, UEBA e SOAR não estão instaladas neste ambiente de laboratório. Os exemplos são incluídos para ilustrar como organizações estendem o Splunk em ambientes SOC reais.

### Enterprise Security (ES)

**Enterprise Security (ES)** é o complemento premium de análise de segurança do Splunk, projetado para operar sobre o ambiente Splunk Enterprise ou Cloud. Ele fornece uma **estrutura completa de operações de segurança**.

**Principais recursos do ES:**

|Recurso|Benefício|
|---|---|
|**Visibilidade do SOC**|Métricas operacionais, distribuição de carga de trabalho|
|**Contexto e correlação**|Mapeamento para MITRE ATT&CK|
|**Pontuação de risco**|Agrega eventos para identificar ameaças reais|
|**Eventos notáveis**|Priorização de incidentes|
|**Integração de inteligência de ameaças**|Enriquecimento de dados|
|**Fluxos de trabalho de investigação**|Processos padronizados|

**Visão geral do SOC (Operações):**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763359982534.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763359982534.svg)

**Visão de detecção e risco:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763360154971.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763360154971.svg)

### Splunk UEBA (User and Entity Behavior Analytics)

O **UEBA** é uma ferramenta dentro do ES, criada para detectar:

- Ameaças internas
- Contas comprometidas
- Atividades suspeitas que podem passar despercebidas

**Como funciona:**

|Capacidade|Descrição|
|---|---|
|**Análise comportamental**|Usuários, hosts, servidores e aplicativos|
|**Pontuação de risco**|Avalia comportamento e eventos ao longo do tempo|
|**Agregação de eventos**|Logins incomuns, padrões de acesso anormal, atividade suspeita|
|**Mapeamento MITRE**|Identifica qual fase do ataque pode estar em andamento|

**Exemplo de análise UEBA:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763516170148.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763516170148.svg)

### Splunk SOAR (Security Orchestration, Automation and Response)

Anteriormente conhecido como **Splunk Phantom**, o SOAR traz **automação** para o SOC.

|Aspecto|Descrição|
|---|---|
|**Licenciamento**|Produto pago; **Edição Comunitária** gratuita disponível para implantações locais|
|**Download**|[Splunk Community Edition](https://www.splunk.com/en_us/download.html#security)|

**Benefícios do SOAR:**

|Benefício|Como funciona|
|---|---|
|**Redução do tempo de resposta**|Automação de ações repetitivas|
|**Consistência**|Playbooks padronizados para incidentes|
|**Integrações**|Conexão com ferramentas de segurança da indústria|

**Exemplo de fluxo de trabalho SOAR:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763516354007.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/616945d482ef350052080da1/room-content/616945d482ef350052080da1-1763516354007.svg)

**Características dos playbooks SOAR:**

- Condições ajustáveis
- Filtros
- Nós de decisão
- Adaptação baseada no tipo de artefato, gravidade ou resultados de enriquecimento

---
### Resumo das Soluções Splunk

|Solução|Finalidade|Público-alvo|
|---|---|---|
|**Search & Reporting**|Pesquisa e análise básica|Todos os usuários|
|**Dashboards**|Visualização e monitoramento|Equipes de operações|
|**Reports & Alerts**|Agendamento e notificações|Equipes SOC|
|**Enterprise Security**|Detecção e investigação avançada|SOCs maduros|
|**UEBA**|Detecção de anomalias comportamentais|Equipes de threat hunting|
|**SOAR**|Automação de resposta|Equipes de resposta a incidentes|
