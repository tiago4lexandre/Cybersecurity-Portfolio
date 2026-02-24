<!-- ===================================== -->
<!--        SOC SIMULATOR - PHISHING      -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Scenario-Phishing%20Investigation-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Environment-SOC%20Simulation-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Role-SOC%20Analyst%20L1-black?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Email%20Threat%20Analysis-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Framework-Triage%20%7C%20Correlation%20%7C%20Escalation-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Platform-TryHackMe-informational?style=flat-square">
</p>

---

# 🎣 SOC Simulator: Introduction to Phishing
## Investigação, Correlação de Eventos e Resposta Inicial a Incidentes

> Este documento apresenta a análise técnica completa do laboratório  
> **"SOC Simulator - Phishing Scenario"** da plataforma **TryHackMe**.
>
> O objetivo foi simular a atuação de um Analista de SOC Nível 1 em um ambiente corporativo, realizando:
>
> - Triagem de alertas de phishing
> - Correlação entre eventos de email e firewall
> - Validação de IOCs (Indicators of Compromise)
> - Classificação entre Falso Positivo e Verdadeiro Positivo
> - Decisão fundamentada de escalação para L2
>
> O foco não está apenas em identificar phishing, mas em **pensar como um analista operacional**, aplicando metodologia estruturada e documentação profissional.

---

## 🎯 Objetivo Técnico do Laboratório

Durante o cenário simulado, foram avaliadas as seguintes competências:

- 📩 Análise de emails suspeitos
- 🔗 Verificação de URLs e reputação de IP
- 🔍 Correlação entre múltiplos alertas
- 🧠 Aplicação do método 5W e raciocínio analítico
- 📝 Documentação estruturada de incidentes
- 🚨 Tomada de decisão sobre escalação

---
# SOC Simulator: Introduction to Phishing

## 1. Introdução ao Cenário Simulado

Este documento apresenta a resolução completa do laboratório **"SOC Simulator - Phishing Scenario"** da plataforma TryHackMe. O objetivo do laboratório é simular a atuação de um analista de SOC Nível 1 em um ambiente corporativo, monitorando alertas em tempo real, identificando atividades maliciosas e documentando cada caso de forma detalhada.

**Cenário Simulado:**

- Ambiente corporativo com employees ativos recebendo emails
- Sistema de segurança gerando alertas baseados em regras pré-definidas
- Ferramenta de análise `TryDetectThis` disponível para verificação de URLs e IPs
- Necessidade de triagem, documentação e escalação quando apropriado

![TryHackMe - Introduction to Phishing](https://assets.tryhackme.com/run-summary/684284babe30e49b4678c1e9.png)

---
## 2. Metodologia de Análise

Para cada alerta recebido, foi aplicado o seguinte fluxo de trabalho:

| Etapa                   | Descrição                                                                  | Ferramentas Utilizadas   |
| ----------------------- | -------------------------------------------------------------------------- | ------------------------ |
| **1. Recebimento**      | Identificação do alerta, gravidade e tipo                                  | Console do SIEM          |
| **2. Coleta de Dados**  | Extração de todos os campos relevantes (remetente, destinatário, URL, IPs) | Logs de email e firewall |
| **3. Verificação**      | Análise da URL/IP na ferramenta de reputação                               | TryDetectThis            |
| **4. Correlação**       | Verificação de conexões relacionadas nos logs de firewall/proxy            | Logs de firewall         |
| **5. Contextualização** | Análise do conteúdo, linguagem e padrões do email                          | Análise manual           |
| **6. Decisão**          | Classificação como Falso Positivo ou Verdadeiro Positivo                   | Julgamento analítico     |
| **7. Documentação**     | Registro completo da análise no formato padrão                             | Template de relatório    |
| **8. Ação**             | Encerramento ou escalação conforme veredito                                | Ticket system            |

---
## 3. Resumo dos Alertas Processados

Durante o laboratório, foram processados **3 alertas** no total:

| ID   | Tipo     | Gravidade | Veredito                      | Ação Tomada      |
| ---- | -------- | --------- | ----------------------------- | ---------------- |
| 8814 | Phishing | Média     | **Falso Positivo**            | Encerrado        |
| 8816 | Firewall | Alta      | **Falso Positivo (Mitigado)** | Encerrado        |
| 8815 | Phishing | Média     | **Verdadeiro Positivo**       | Escalado para L2 |

---
## 4. Caso 1: Onboarding Profile - Falso Positivo

### 4.1. Informações do Alerta

|Campo|Valor|
|---|---|
|**ID do Alerta**|8814|
|**Gravidade**|Média|
|**Tipo**|Phishing|
|**Data/Hora**|24/02/2026 19:35|
|**Fonte**|Email|

### 4.2. Detalhes do Email

|Campo|Valor|
|---|---|
|**Remetente**|`onboarding@hrconnex.thm`|
|**Destinatário**|`j.garcia@thetrydaily.thm`|
|**Assunto**|Action Required: Finalize Your Onboarding Profile|
|**Anexo**|Nenhum|
|**Direção**|Inbound|

**Conteúdo do Email:**

```text
Hi Ms. Garcia,

Welcome to TheTryDaily!

As part of your onboarding, please complete your final profile setup so we can configure your access.

Kindly please click the link below:

<a href="https://hrconnex.thm/onboarding/15400654060/j.garcia">Set Up My Profile</a>.

If you have questions, please reach out to the HR Onboarding Team.
```

### 4.3. Análise Realizada

1. **Verificação da URL:** A URL `https://hrconnex.thm/onboarding/15400654060/j.garcia` foi analisada na ferramenta `TryDetectThis`.
    
    ![](assets/Pasted%20image%2020260224201357.png)
    
    **Resultado:** CLEAN (Seguro)

2. **Verificação de Logs de Firewall/Proxy:**
    
    - Nenhuma conexão de saída maliciosa associada à URL foi identificada
    - O host de destino (`j.garcia`) não apresentou tentativas de acesso a domínios suspeitos

3. **Análise do Domínio Remetente:**
    - O domínio `hrconnex.thm` é consistente com comunicações internas de RH
    - Não foram identificados indicadores de spoofing ou anomalias nos cabeçalhos do email

4. **Análise de Contexto:**
    - O conteúdo do email está alinhado com procedimentos padrão de integração de novos funcionários
    - Ausência de características típicas de phishing (urgência financeira, formulários de coleta de credenciais, anexos suspeitos)
    - A URL é personalizada para o destinatário específico (`j.garcia`)

### 4.4. Veredito Final

```text
╔══════════════════════════════════════════════════════════════════╗
║                    FALSO POSITIVO (False Positive)               ║
╚══════════════════════════════════════════════════════════════════╝
```

**Justificativa:** O email contém um link legítimo de integração que foi verificado como seguro. A URL direciona para um domínio interno consistente com processos de RH, e não há evidências de atividade maliciosa associada ao alerta.

**Ações Tomadas:**

- ✓ Alerta encerrado
- ✓ Nenhuma ação de remediação necessária

---
## 5. Caso 2: Firewall Block - Falso Positivo (Mitigado)

### 5.1. Informações do Alerta

|Campo|Valor|
|---|---|
|**ID do Alerta**|8816|
|**Gravidade**|Alta|
|**Tipo**|Firewall|
|**Data/Hora**|24/02/2026 19:39|
|**Fonte**|Firewall/Proxy|

### 5.2. Detalhes da Conexão

|Campo|Valor|
|---|---|
|**IP de Origem**|10.20.2.17|
|**Porta de Origem**|34257|
|**IP de Destino**|67.199.248.11|
|**Porta de Destino**|80|
|**URL**|`http://bit.ly/3sHkX3da12340`|
|**Aplicação**|web-browsing|
|**Protocolo**|TCP|
|**Ação**|Blocked|
|**Regra do Firewall**|Blocked Websites|

### 5.3. Análise Realizada

1. **Verificação da URL e IP na Ferramenta TryDetectThis:**
    
    ![](assets/Pasted%20image%2020260224202725.png)
    
    - **URL:** `http://bit.ly/3sHkX3da12340` → **MALICIOUS**
    - **IP de Destino:** `67.199.248.11` → **MALICIOUS**

2. **Correlação com Outros Alertas:**    
    - A **mesma URL** foi identificada no **alerta 8815** (phishing)
    - Isto confirma que o link faz parte de uma campanha de phishing ativa direcionada à organização
    - O host 10.20.2.17 tentou acessar um IOC confirmado

3. **Verificação do Host de Origem (10.20.2.17):**    
    - Tentativa única de conexão foi registrada    
    - Sem comportamento de beaconing ou retentativas após o bloqueio
    - Verificação inicial do endpoint não revelou malware ou processos suspeitos
    - **Necessário determinar a identidade do usuário** associado ao IP 10.20.2.17

4. **Efetividade do Controle de Segurança:**
    - O firewall bloqueou a conexão com sucesso (Action: Blocked)
    - Nenhuma sessão foi estabelecida com o destino malicioso
    - A regra "Blocked Websites" operou conforme esperado

### 5.4. Análise de Risco

|Fator|Avaliação|Comentário|
|---|---|---|
|Ameaça é real?|✅ **SIM**|URL e IP confirmados como maliciosos|
|Ameaça foi executada?|❌ Não|Bloqueada pelo firewall|
|Host comprometido?|❌ Não|Sem evidências de execução|
|Dados exfiltrados?|❌ Não|Conexão bloqueada|
|Persistência estabelecida?|❌ Não||
|Controles funcionaram?|✅ Sim|Firewall bloqueou conforme esperado|

### 5.5. Veredito Final

```text
╔══════════════════════════════════════════════════════════════════╗
║             VERDADEIRO POSITIVO (True Positive)                  ║
║                 Mitigado - Sem Escalação Necessária              ║
╚══════════════════════════════════════════════════════════════════╝
```

**Justificativa da Classificação:**

Este alerta é classificado como **Verdadeiro Positivo** porque:

1. A URL e o IP de destino foram **confirmados como maliciosos** pela ferramenta TryDetectThis
2. Há **correlação direta** com o alerta de phishing 8815 (mesma URL)
3. Um host interno **tentou ativamente estabelecer comunicação** com um IOC conhecido
4. A tentativa representa **comportamento suspeito** que justifica investigação

**Justificativa para NÃO Escalação:**

Embora seja um verdadeiro positivo, **não há necessidade de escalação imediata para L2** porque:

1. O **firewall bloqueou a conexão** com sucesso (Action: Blocked)
2. **Nenhuma sessão foi estabelecida** com o destino malicioso
3. **Não há evidências de comprometimento** no host de origem
4. O comportamento foi **isolado** (tentativa única, sem retentativas)

**Diferença Crucial:**

- **Falso Positivo:** O alerta foi disparado por engano (atividade benigna)
- **Verdadeiro Positivo (Mitigado):** A ameaça era REAL, mas os CONTROLES funcionaram

### 5.6. Ações Recomendadas

|Ação|Prioridade|Responsável|Status|
|---|---|---|---|
|Identificar usuário do IP 10.20.2.17|🟡 Média|SOC L1|Pendente|
|Verificar se o usuário recebeu email phishing (correlação com alerta 8815)|🟡 Média|SOC L1|Pendente|
|Orientar usuário sobre o incidente|🟢 Baixa|SOC L1|Pendente|
|Monitorar host por 24-48 horas para atividade anômala|🟢 Baixa|SOC L1|Pendente|
|Atualizar registros com identidade do usuário|🟢 Baixa|SOC L1|Pendente|

### 5.7. Indicadores Identificados

| Tipo                | Valor                         | Fonte de Confirmação            |
| ------------------- | ----------------------------- | ------------------------------- |
| **URL Maliciosa**   | `http://bit.ly/3sHkX3da12340` | TryDetectThis / Correlação 8815 |
| **IP Malicioso**    | 67.199.248.11                 | TryDetectThis                   |
| **Host de Origem**  | 10.20.2.17                    | Log de firewall                 |
| **Regra Disparada** | Blocked Websites              | Firewall                        |
| **Ação Tomada**     | Blocked                       | Firewall                        |

### 5.9. Correlação com Alerta 8815

| Alerta | Tipo     | URL                           | Relação                     |
| ------ | -------- | ----------------------------- | --------------------------- |
| 8815   | Phishing | `http://bit.ly/3sHkX3da12340` | Email enviado ao usuário    |
| 8816   | Firewall | `http://bit.ly/3sHkX3da12340` | Tentativa de acesso ao link |

**Conclusão da Correlação:**

- O usuário do host 10.20.2.17 provavelmente recebeu o email de phishing (alerta 8815)
- O usuário clicou no link malicioso
- O firewall bloqueou a tentativa de acesso
- **Cadeia de eventos completa identificada:** Phishing → Clique → Bloqueio

---
## 6. Caso 3: Amazon Delivery - Verdadeiro Positivo

### 6.1. Informações do Alerta

|Campo|Valor|
|---|---|
|**ID do Alerta**|8815|
|**Gravidade**|Média|
|**Tipo**|Phishing|
|**Data/Hora**|24/02/2026 19:38|
|**Fonte**|Email|

### 6.2. Detalhes do Email - Análise dos 5Ws

|W|Resposta|Detalhes|
|---|---|---|
|**Who (Quem)**|Remetente e Destinatário|**De:** `urgents@amazon.biz`  <br>**Para:** `h.harris@thetrydaily.thm`|
|**What (O quê)**|Tentativa de phishing|Email fraudulento simulando comunicação da Amazon com link malicioso|
|**When (Quando)**|Data e hora do alerta|24/02/2026 19:38|
|**Where (Onde)**|**ORIGEM:** IP do servidor remetente (não disponível nos logs)  <br>**DESTINO:** URL maliciosa resolve para IP `67.199.248.11` (confirmado no alerta 8816)  <br>**INTERNO:** Destinatário `h.harris@thetrydaily.thm` (caixa postal corporativa)||
|**Why (Por quê)**|Razão do alerta|Regra de detecção de phishing - link externo com características suspeitas|

**Conteúdo do Email:**

```text
Dear Customer,

We were unable to deliver your package due to an incomplete address.

Please confirm your shipping information by clicking the link below:

http://bit.ly/3sHkX3da12340

If we don't hear from you within 48 hours, your package will be returned to sender.

Thank you,

Amazon Delivery
```

### 6.3. Análise Detalhada

#### 6.3.1. Bandeiras Vermelhas Identificadas

| Indicador de Phishing | Presente? | Análise                                                                                           |
| --------------------- | --------- | ------------------------------------------------------------------------------------------------- |
| Domínio suspeito      | ✅         | `amazon.biz` não é domínio oficial da Amazon (domínio legítimo: [amazon.com](https://amazon.com)) |
| URL encurtada         | ✅         | `bit.ly` usado para ocultar destino final - técnica comum em phishing                             |
| Urgência              | ✅         | "within 48 hours" - pressão psicológica para ação imediata                                        |
| Saudação genérica     | ✅         | "Dear Customer" em vez de nome específico do destinatário                                         |
| Solicitação de dados  | ✅         | "confirm your shipping information" - pretexto para coleta de credenciais                         |
| Anexo suspeito        | ❌         | Nenhum anexo presente                                                                             |

#### 6.3.2. Verificação da URL e IP de Destino

A URL `http://bit.ly/3sHkX3da12340` foi analisada na ferramenta `TryDetectThis`:

**Resultado:** MALICIOUS

|Elemento|Valor|Status|
|---|---|---|
|**URL Completa**|`http://bit.ly/3sHkX3da12340`|🔴 **MALICIOUS**|
|**IP de Destino (resolvido)**|`67.199.248.11`|🔴 **MALICIOUS** (confirmado no alerta 8816)|
|**Porta de Destino**|80 (HTTP)|-|

> **Nota Importante:** Esta é a **MESMA URL** identificada no Caso 2 (alerta de firewall 8816), confirmando a natureza maliciosa do link.

#### 6.3.3. Correlação com Outros Alertas

|Alerta Relacionado|Tipo|Relação|Status da Conexão|
|---|---|---|---|
|8816 (Firewall)|Tentativa de acesso bloqueada|Mesma URL maliciosa|🔒 **BLOQUEADA** pelo firewall|

Esta correlação é **crítica** porque:

1. Confirma que o link é reconhecido como ameaça pela inteligência de ameaças
2. Indica que **ALGUÉM** na rede tentou acessar o mesmo link malicioso
3. O host `10.20.2.17` (alerta 8816) tentou acessar o IOC, possivelmente relacionado a este mesmo phishing

#### 6.3.4. Verificação de Impacto Real (O que NÃO aconteceu)

|Verificação|Status|Evidência|
|---|---|---|
|Usuário `h.harris` clicou no link?|❌ **NÃO CONFIRMADO**|Logs de proxy/firewall precisam ser verificados para o IP do usuário|
|Credenciais foram fornecidas?|❌ **SEM EVIDÊNCIAS**|Nenhum alerta de login suspeito ou tráfego de saída para páginas de captura|
|Payload foi baixado?|❌ **SEM EVIDÊNCIAS**|Nenhum alerta de malware ou download suspeito associado|
|Host comprometido?|❌ **SEM EVIDÊNCIAS**|Nenhum IOC de comprometimento identificado até o momento|
|Dados exfiltrados?|❌ **SEM EVIDÊNCIAS**|Nenhum tráfego de saída anômalo detectado|

**⚠️ PONTO CRÍTICO:** Apesar de ser um verdadeiro positivo, **não há evidências de que o usuário interagiu com o link ou que qualquer comprometimento ocorreu**. O impacto real é **potencial**, não confirmado.

### 6.4. Análise de Risco vs. Impacto Real

|Cenário|Risco Potencial|Impacto Real Confirmado|
|---|---|---|
|Usuário clicou no link|🔴 ALTO|❌ **Não confirmado**|
|Usuário forneceu credenciais|🔴 CRÍTICO|❌ **Não confirmado**|
|Payload foi baixado/executado|🔴 ALTO|❌ **Não confirmado**|
|Host comprometido|🔴 CRÍTICO|❌ **Não confirmado**|
|**RISCO GERAL**|🔴 **ALTO (Potencial)**|🟢 **Nenhum impacto real confirmado**|

### 6.5. Veredito Final

```text
╔══════════════════════════════════════════════════════════════════╗
║              VERDADEIRO POSITIVO (True Positive)                 ║
║                        Escalação Necessária                      ║
╚══════════════════════════════════════════════════════════════════╝
```

**Justificativa:** O email apresenta múltiplos indicadores de phishing: domínio de remetente falso (`amazon.biz`), uso de URL encurtada, táticas de urgência, saudação genérica e pretexto de coleta de informações. A URL foi confirmada como maliciosa pela ferramenta de análise e correlacionada com um alerta de firewall bloqueado.

---
## Conclusão

Este laboratório da TryHackMe proporcionou uma experiência realista de atuação como analista SOC L1 em um cenário de phishing. Os três alertas processados representam situações comuns no dia a dia de um SOC:

|Tipo de Alerta|Classificação|Aprendizado|
|---|---|---|
|**Legítimo (FP)**|Email de onboarding|Nem todo link em email é phishing|
|**Bloqueado (Mitigado)**|Tentativa de acesso malicioso|Segurança em camadas funciona|
|**Phishing (TP)**|Email falso da Amazon|Reconhecer múltiplos indicadores|

