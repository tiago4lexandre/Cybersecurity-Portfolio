<!-- ===================================== -->
<!--         WAZUH SECURITY GUIDE          -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Wazuh-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-SIEM%20%7C%20EDR%20%7C%20Threat%20Detection-black?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Layer-Security%20Monitoring-red?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-SOC%20Operations-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Security-Threat%20Detection-green?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Intermediate%20%E2%86%92%20Advanced-yellow?style=flat-square">
</p>

---

# 🛡️ Wazuh: Monitoramento e Defesa de Ambientes
## Guia Técnico de SIEM, EDR, Coleta de Logs e Threat Detection

> Em ambientes corporativos modernos, ameaças digitais acontecem constantemente:
>
> tentativas de brute force, execução de malware, movimentação lateral, exploração de vulnerabilidades e vazamento de dados podem ocorrer em segundos.
>
> Porém, detectar essas atividades exige muito mais do que apenas armazenar logs.
>
> É necessário correlacionar eventos, monitorar endpoints, identificar comportamentos suspeitos e transformar telemetria em inteligência acionável.
>
> É exatamente nesse contexto que o **Wazuh** atua — oferecendo uma plataforma open source capaz de centralizar monitoramento, auditoria, detecção e resposta a incidentes de segurança.

---

# Wazuh

## Introdução

Vamos entender o que o **Wazuh** realmente é. Embora tenha começado como uma ferramenta focada em **EDR** (Endpoint Detection and Response), o Wazuh cresceu para se tornar uma **plataforma de segurança unificada** que combina:

- Detecção e resposta de endpoints
- Gerenciamento de eventos de segurança (SIEM)
- Avaliação de vulnerabilidades
- Monitoramento de segurança na nuvem

Tudo sob o mesmo teto. O Wazuh vai muito além do EDR tradicional, oferecendo:

|Funcionalidade|Descrição|
|---|---|
|**Auditoria de vulnerabilidades**|Verifica dispositivos em busca de vulnerabilidades comuns|
|**Monitoramento de atividades suspeitas**|Monitora endpoints em tempo real|
|**Visualização de dados**|Exibe eventos complexos em painéis e gráficos intuitivos|
|**Relatórios de conformidade**|Gera relatórios para frameworks como PCI DSS, HIPAA e NIST|

Fundada em 2015, a [Wazuh](https://wazuh.com) é utilizada por organizações de todos os tamanhos — desde pequenas empresas até grandes corporações e instituições governamentais.

### Arquitetura Wazuh: Modelo Manager-Agente

O Wazuh opera em um modelo de **gerente (manager)** e **agente (agent)**:

|Componente|Função|
|---|---|
|**Manager**|Servidor central que armazena e processa os dados|
|**Agentes**|Hosts (endpoints) que coletam e enviam dados ao manager|

O diagrama abaixo ilustra este modelo:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1772666888916.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1772666888916.png)

---

## Implantando o Servidor Wazuh

> **Importante:** Se você carregar o servidor de gerenciamento muito cedo, ele exibirá a mensagem "Servidor ainda não está pronto". Aguarde alguns minutos antes de atualizar a página e tentar novamente.

### Credenciais de Acesso

|Campo|Valor|
|---|---|
|**Nome de usuário**|`wazuh` (em minúsculas)|
|**Senha**|`eYa0M1-hG0e7rjGi-lRB2qGYVoonsG1K`|

Após o login bem-sucedido, selecione **"Global Tenant"** (Inquilino Global).

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e072a26a84886784f231585294f763dd.gif](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e072a26a84886784f231585294f763dd.gif)

> **Nota:** As perguntas dentro das tarefas desta sala **esperam os dados armazenados neste servidor Wazuh de gerenciamento**. É vital que você consiga se conectar a este servidor antes de continuar.
> 
> O servidor Wazuh de gerenciamento nesta sala mostrará os agentes como **desconectados** — isso é esperado.

---

## Agentes Wazuh

### O que são Agentes?

**Agentes** são os dispositivos que registram eventos e processos de um sistema. Eles monitoram:

- Autenticação e gerenciamento de usuários
- Processos do sistema
- Eventos de segurança
- Alterações em arquivos    

Os agentes enviam esses logs para um coletor central (o manager) para processamento.

### Implantando um Agente

Para que o Wazuh seja povoado com dados, os agentes precisam ser instalados nos dispositivos a serem monitorados. O Wazuh fornece um **assistente de implantação** que solicita:

|Pré-requisito|Descrição|
|---|---|
|**Sistema Operacional**|Windows, Linux, macOS|
|**Endereço do servidor**|IP ou DNS do manager Wazuh|
|**Grupo do agente**|Classificação opcional para organização|

### Como Acessar o Assistente

Navegue para o seguinte local no servidor Wazuh:

**Wazuh → Agents → Deploy New Agent**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/561a60f3973c417098e4381bc50f9252.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/561a60f3973c417098e4381bc50f9252.png)

### Instalação do Agente por Sistema Operacional

**Windows:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/5729622f750cdd7185c094ad09ce70f8.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/5729622f750cdd7185c094ad09ce70f8.png)

**Debian/Ubuntu:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e50f510af70b7cd247e5623cbd5f7e31.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e50f510af70b7cd247e5623cbd5f7e31.png)

No **Estágio 4**, você recebe um comando pronto para copiar e colar no dispositivo alvo, que instalará e configurará o agente automaticamente.

---

## Avaliação de Vulnerabilidades e Eventos de Segurança

### Scanner de Vulnerabilidades

O módulo de **Avaliação de Vulnerabilidades** do Wazuh é uma ferramenta poderosa que:

1. **Escaneia periodicamente** o sistema operacional do agente
2. **Identifica aplicações instaladas** e suas versões
3. **Compara com um banco de dados de CVEs** (Common Vulnerabilities and Exposures)
4. **Descobre potenciais vulnerabilidades**

**Exemplo:** O agente na captura de tela abaixo possui uma versão do Vim vulnerável a **CVE-2019-12735**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/1907912f601690e47d5e11d031461f4b.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/1907912f601690e47d5e11d031461f4b.png)

### Configuração do Scanner

O scanner realiza uma verificação completa quando o agente é instalado pela primeira vez e **deve ser configurado** para execução em intervalos definidos (padrão: 5 minutos quando ativado):

```xml
<vulnerability-detector>
	<enabled>no</enabled>
	<interval>5m</interval>
	<ignore_time>6h</ignore_time>
	<run_on_start>yes</run_on_start>
```

_Configuração em `/var/ossec/etc/ossec.conf` para auditoria de vulnerabilidades_

### Eventos de Segurança

O Wazuh é capaz de testar a configuração de um agente contra certos conjuntos de regras para verificar conformidade. No entanto, fora da caixa, ele é **indiscutivelmente sensível**.

**Exemplo:** Um host Linux executando o agente Wazuh pode gerar **769 eventos** apenas como parte de sua manutenção diária.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/55456a88291bf69e44a15e5a742faf1e.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/55456a88291bf69e44a15e5a742faf1e.png)

Ações frequentes (como remoção de arquivos) são frequentemente detectadas como eventos de segurança. Esses eventos e suas gravidades são determinados pelos **conjuntos de regras do Wazuh**.

### Analisando Eventos

Você pode analisar eventos individualmente selecionando o menu suspenso do evento e classificar com base em:

- Timestamp
- Táticas MITRE ATT&CK
- Descrição
- Nível de severidade

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/3a195f897882eee1b3151a3b5b167054.gif](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/3a195f897882eee1b3151a3b5b167054.gif)

---

## Política de Auditoria

O Wazuh é capaz de auditar e monitorar a configuração de um agente enquanto grava proativamente logs de eventos. Quando o agente é instalado, uma auditoria é realizada onde uma **métrica é fornecida** usando múltiplos frameworks e legislações.

### Frameworks Suportados

|Framework|Descrição|
|---|---|
|**MITRE ATT&CK**|Matriz de táticas e técnicas de adversários|
|**NIST**|Padrões do National Institute of Standards and Technology|
|**GDPR**|Regulamento Geral de Proteção de Dados da UE|
|**SCA**|Security Configuration Assessment|

### Exemplo de Pontuação

Veja como um agente (controlador de domínio Windows) se pontua contra MITRE, NIST e SCA:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/8780dc7af8c03529235e8e89bc23ae7c.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/8780dc7af8c03529235e8e89bc23ae7c.png)

### Benchmark do Agente

O Wazuh apresenta uma ampla ilustração dos logs. Podemos usar as visualizações para quebrar esses dados e explorá-los ainda mais:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/ac6454463eb96d632b951035e7599253.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/ac6454463eb96d632b951035e7599253.png)

### Acessando o Módulo de Políticas

Navegue para: **Wazuh → Módulos → Gerenciamento de Políticas**

![https://assets.tryhackme.com/additional/wazuh/navigate5.png](https://assets.tryhackme.com/additional/wazuh/navigate5.png)

---

## Monitorando Logons com Wazuh

O Wazuh monitora eventos de segurança e é capaz de gravar ativamente tanto **tentativas de autenticação bem-sucedidas quanto mal-sucedidas**.

### Exemplo: Falha de Autenticação SSH

A regra com ID **5710** detecta tentativas de conexão sem sucesso para o protocolo SSH.

**Cenário:** Alguém tentou fazer login no agente `ip-10-10-73-118` com o usuário `cmnatic` (que não existe).

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/b5ecf8381077df9822de51cd6e81f8ff.gif](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/b5ecf8381077df9822de51cd6e81f8ff.gif)

### Campos do Alerta

|Campo|Valor|Descrição|
|---|---|---|
|`agent.ip`|`10.10.73.118`|IP do agente onde o alerta foi acionado|
|`agent.name`|`ip-10-10-73-118`|Nome do host do agente|
|`rule.description`|`ssh: Tentativa de login usando usuário inexistente`|Breve descrição do evento|
|`rule.mitre.technique`|`Brute-Force`|Técnica MITRE ATT&CK|
|`rule.mitre.id`|`T1110`|ID MITRE ATT&CK|
|`rule.id`|`5710`|ID atribuído pelo conjunto de regras do Wazuh|
|`location`|`/var/log/auth.log`|Arquivo de log que gerou o alerta|

### Localização dos Alertas no Manager

Os alertas são armazenados no arquivo:

```text
/var/ossec/logs/alerts/alerts.log
```

Você pode usar comandos como `grep` ou `less` para pesquisar neste arquivo manualmente:

```bash
sudo less /var/ossec/logs/alerts/alerts.log
```

**Exemplo de saída para login bem-sucedido (su):**

```text
** Alert 1634284538.566764: - pam,syslog,authentication_success,pci_dss_10.2.5,gpg13_7.8,gpg13_7.9,gdpr_IV_32.2,hipaa_164.312.b,ni>
2021 Oct 15 07:55:38 ip-10-10-218-190->/var/log/auth.log
Rule: 5501 (level 3) -> 'PAM: Login session opened.'
User: root
Oct 15 07:55:37 ip-10-10-218-190 sudo: pam_unix(sudo:session): session opened for user root by ubuntu(uid=0)
uid: 0
```

### Gravidade dos Alertas

|Tipo de Evento|Gravidade|Observação|
|---|---|---|
|Login mal-sucedido|Mais alta|Indica possível ataque de força bruta|
|Login bem-sucedido|Menor (padrão)|Pode ser ajustada conforme necessidade|

> **Personalização:** Você pode configurar o Wazuh para atribuir maior gravidade a logins de usuários usados com pouca frequência.

### Filtragem de Eventos no Windows

O GIF abaixo mostra a redução de eventos de logon no Windows de **285 para 79** após aplicação de filtros:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/6c2d68f59482de413940f2d11913fae1.gif](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/6c2d68f59482de413940f2d11913fae1.gif)

---

## Coletando Logs do Windows com Wazuh

### Sysmon: O Coletor de Eventos do Windows

Todos os tipos de ações e eventos são capturados e registrados no Windows, incluindo:

- Tentativas de autenticação
- Conexões de rede
- Arquivos acessados
- Comportamentos de aplicativos e serviços

Essas informações são armazenadas no **Log de Eventos do Windows** usando uma ferramenta chamada **Sysmon** (System Monitor).

### Configuração do Sysmon

O Sysmon utiliza regras em formato **XML** para determinar quais eventos monitorar.

**Exemplo de configuração XML (monitorando PowerShell):**

```xml
<Sysmon schemaversion="3.30" 
         HashAlgorithms="md5">
  <EventFiltering>
    <!-- SYSMON EVENT ID 1 : PROCESS CREATION -->
    <ProcessCreate onmatch="include">
      <Image condition="contains">powershell.exe</Image>
    </ProcessCreate>
    <!-- SYSMON EVENT ID 2 : FILE CREATION TIME CHANGED -->
    <FileCreateTime onmatch="include" />
    <!-- SYSMON EVENT ID 3 : NETWORK CONNECTION -->
    <NetworkConnect onmatch="include" />
    <!-- SYSMON EVENT ID 5 : PROCESS ENDED -->
    <ProcessTerminate onmatch="include" />
    <!-- SYSMON EVENT ID 6 : DRIVER LOADED -->
    <DriverLoad onmatch="include" />
    <!-- SYSMON EVENT ID 7 : DLL LOADED -->
    <ImageLoad onmatch="include" />
    <!-- SYSMON EVENT ID 8 : REMOTE THREAD CREATED -->
    <CreateRemoteThread onmatch="include" />
    <!-- SYSMON EVENT ID 9 : RAW DISK ACCESS -->
    <RawAccessRead onmatch="include" />
    <!-- SYSMON EVENT ID 10 : INTER-PROCESS ACCESS -->
    <ProcessAccess onmatch="include" />
    <!-- SYSMON EVENT ID 11 : FILE CREATED -->
    <FileCreate onmatch="include" />
    <!-- SYSMON EVENT ID 12-14 : REGISTRY MODIFICATION -->
    <RegistryEvent onmatch="include" />
    <!-- SYSMON EVENT ID 15 : ALTERNATE DATA STREAM -->
    <FileCreateStreamHash onmatch="include" />
    <PipeEvent onmatch="include" />
  </EventFiltering>
</Sysmon>
```

### Instalando e Configurando o Sysmon

**Comando para instalar com arquivo de configuração:**

```cmd
Sysmon64.exe -accepteula -i detect_powershell.xml
```

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/8a1cf21e3a8fa4d7e42c8395a50973e6.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/8a1cf21e3a8fa4d7e42c8395a50973e6.png)

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e1605655cc49dd89016b1bdc87561561.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e1605655cc49dd89016b1bdc87561561.png)

### Verificando a Configuração do Sysmon

1. Abra o **Visualizador de Eventos** (Event Viewer)   
2. Navegue até **Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/8a05b23adeb562db0e3ed27b1ff31dca.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/8a05b23adeb562db0e3ed27b1ff31dca.png)

### Configurando o Agente Wazuh para Coletar Logs do Sysmon

1. Abra o arquivo de configuração do agente Wazuh:    

```text
C:\Program Files (x86)\ossec-agent\ossec.conf
```

2. Adicione o seguinte bloco:    

```xml
<localfile>
	<location>Microsoft-Windows-Sysmon/Operational</location>
	<log_format>eventchannel</log_format>
</localfile>
```

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/ea9e6fe95bb44847fc17c4096a1e8fe5.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/ea9e6fe95bb44847fc17c4096a1e8fe5.png)

**Resultado esperado:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/c6f7ce784d60c25cfcf58b36fa5be0f0.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/c6f7ce784d60c25cfcf58b36fa5be0f0.png)

3. **Reinicie o agente Wazuh** (ou reinicie o sistema operacional para garantir)

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/70dbe7115a64426e5648a169173a5d24.gif](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/70dbe7115a64426e5648a169173a5d24.gif)

### Configurando Regras no Manager

Para que o manager visualize os eventos do Sysmon, adicione uma regra em:

```text
/var/ossec/etc/rules/local_rules.xml
```

```xml
<group name="sysmon">
	<rule id="255000" level="12">
		<if_group>sysmon_event1</if_group>
		<field name="sysmon.image">\\powershell.exe||\\.ps1||\\.ps2</field>
		<description>Sysmon - Event 1: Bad exe: $(sysmon.image)</description>
		<group>sysmon_event1,powershell_execution</group>
	</rule>
</group>
```

> **Importante:** Reinicie o servidor Wazuh de gerenciamento para aplicar as alterações.

---

## Coletando Logs do Linux com Wazuh

A captura de logs de um agente Linux é um processo simples, similar à coleta de eventos no Windows.

### Configuração Básica

O Wazuh vem com muitas regras pré-definidas para análise de arquivos de log, localizadas em:

```text
/var/ossec/ruleset/rules
```

**Aplicações com suporte nativo (aproximadamente 900):**

|Categoria|Exemplos|
|---|---|
|**Contêineres**|Docker|
|**Servidores Web**|Apache, Nginx|
|**Bancos de Dados**|SQL Server, MongoDB|
|**Firewalls**|Firewalld|
|**CMS**|WordPress|
|**Protocolos**|FTP, SSH|

### Exemplo: Monitorando Logs do Apache2

Usaremos o conjunto de regras `0250-apache_rules.xml` para analisar logs do Apache2.

**Configuração no agente (`/var/ossec/etc/ossec.conf`):**

```xml
<!-- Apache2 Log Analysis -->
<localfile>
	<location>/var/log/apache2/access.log</location>
	<log_format>syslog</log_format>
</localfile>
<localfile>
	<location>/var/log/apache2/error.log</location>
	<log_format>syslog</log_format>
</localfile>
```

---

## Auditando Comandos no Linux com Wazuh

O Wazuh utiliza o pacote `auditd` para monitorar ações e eventos em sistemas Linux.

### Instalando o auditd

```bash
sudo apt-get install auditd audispd-plugins
sudo systemctl enable auditd.service
sudo systemctl start auditd.service
```

### Configurando Regras do auditd

As regras do `auditd` estão localizadas em:

```text
/etc/audit/rules.d/audit.rules
```

**Exemplo: Monitorar comandos executados como root**

Adicione a seguinte linha ao arquivo:

```bash
-a exit,always -F arch=b64 -F euid=0 -S execve -k audit-wazuh-c
```

**Arquivo completo de exemplo:**

```bash
## First rule - delete all
-D
## Increase the buffers to survive stress events.
-b 8192
## This determine how long to wait in burst of events
--backlog_wait_time 0
## Set failure mode to syslog
-f 1
-a exit,always -F arch=b64 -F euid=0 -S execve -k audit-wazuh-c
```

### Aplicando as Regras

```bash
sudo auditctl -R /etc/audit/rules.d/audit.rules
```

### Configurando o Agente Wazuh

No arquivo `/var/ossec/etc/ossec.conf`, adicione:

```xml
<localfile>
    <location>/var/log/audit/audit.log</location>
    <log_format>audit</log_format>
</localfile>
```

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/16f9a29cff90a5c7baefa980922f4066.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/16f9a29cff90a5c7baefa980922f4066.png)

### Estendendo para Outros Comandos

Você pode monitorar comandos específicos como:

|Comando|Razão para Monitorar|
|---|---|
|`tcpdump`|Captura de pacotes (exfiltração de dados)|
|`netcat`|Estabelecimento de backdoors|
|`cat /etc/passwd`|Leitura não autorizada de arquivos sensíveis|

---

## API Wazuh

### Visão Geral

O servidor Wazuh de gerenciamento apresenta uma **API RESTful extensa** que permite a interação com o manager via linha de comando.

### Autenticação

Como o servidor requer autenticação, primeiro devemos obter um **token**:

```bash
TOKEN=$(curl -u : -k -X GET "https://WAZUH_MANAGEMENT_SERVER_IP:55000/security/user/authenticate?raw=true")
```

_Substitua `WAZUH_MANAGEMENT_SERVER_IP` pelo IP do manager (ex: 10.65.144.133)_

### Verificando a Autenticação

```bash
curl -k -X GET "https://10.65.144.133:55000/" -H "Authorization: Bearer $TOKEN"
```

**Resposta esperada:**

```json
{
    "data": {
        "title": "Wazuh API",
        "api_version": "4.0.0",
        "revision": 4000,
        "license_name": "GPL 2.0",
        "license_url": "https://github.com/wazuh/wazuh/blob/master/LICENSE",
        "hostname": "wazuh-master",
        "timestamp": "2021-10-25T07:05:00+0000"
    },
    "error": 0
}
```

### Métodos HTTP Suportados

|Método|Uso|
|---|---|
|`GET`|Recuperar informações|
|`POST`|Criar recursos|
|`PUT`|Atualizar recursos|
|`DELETE`|Remover recursos|

### Exemplos de Consultas

**Listar status do manager:**

```bash
curl -k -X GET "https://10.65.144.133:55000/manager/status?pretty=true" -H "Authorization: Bearer $TOKEN"
```

**Listar configuração global:**

```bash
curl -k -X GET "https://10.65.144.133:55000/manager/configuration?pretty=true&section=global" -H "Authorization: Bearer $TOKEN"
```

**Resposta (serviços em execução):**

```json
{
  "data": {
    "affected_items": [
      {
        "wazuh-analysisd": "running",
        "wazuh-authd": "running",
        "wazuh-csyslogd": "running",
        "wazuh-execd": "running",
        "wazuh-logcollector": "running",
        "wazuh-remoted": "running",
        "wazuh-syscheckd": "running",
        "wazuh-clusterd": "running",
        "wazuh-modulesd": "running",
        "wazuh-db": "running"
      }
    ]
  },
  "error": 0
}
```

**Listar agentes ativos:**

```bash
curl -k -X GET "https://10.65.144.133:55000/agents?pretty=true&offset=1&limit=2&select=status%2Cid%2Cmanager%2Cname%2Cnode_name%2Cversion&status=active" -H "Authorization: Bearer $TOKEN"
```

### Console da API Integrado

O Wazuh possui um console de API integrado na interface web.

**Como acessar:**

1. Abra a categoria **"Tools"** (Ferramentas) no menu superior

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/676b0bc423d8692a96cca58f5d86605a.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/676b0bc423d8692a96cca58f5d86605a.png)

2. Selecione uma consulta de exemplo e pressione o botão de execução (seta verde)

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e3daa0e68fe454de9e61bde5cd87c8a1.gif](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e3daa0e68fe454de9e61bde5cd87c8a1.gif)

> **Documentação completa:** [Wazuh API Reference](https://documentation.wazuh.com/current/user-manual/api/reference.html)

---

## Gerando Relatórios com Wazuh

O Wazuh possui um **módulo de relatórios** que permite visualizar um resumo dos eventos ocorridos em um agente.

### Passo 1: Selecionar uma Visualização

Por exemplo, para gerar um relatório de eventos de segurança nas últimas 24 horas:

**Navegação:** Módulos → Eventos de Segurança

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/41d15d504f407acf744fdfdd00b152a9.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/41d15d504f407acf744fdfdd00b152a9.png)

### Passo 2: Gerar o Relatório

Se houver alertas no período selecionado, o botão de geração estará disponível:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/2710a93265a303595e8aefadf498f400.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/2710a93265a303595e8aefadf498f400.png)

> **Nota:** Se o botão estiver esmaecido (cinza), não há dados no período selecionado. Ajuste a consulta ou amplie o intervalo de datas.

### Passo 3: Acessar Relatórios Gerados

1. Clique no cabeçalho **"Wazuh"**
2. Selecione **"Management"**
3. Clique em **"Reports"** (sob "Status and Reports")

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/d5f90046e283c983f1f1ae0a6662c990.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/d5f90046e283c983f1f1ae0a6662c990.png)

### Passo 4: Baixar o Relatório

Pressione o ícone de **salvamento** à direita do relatório (coluna "Actions").

O relatório será baixado como um **arquivo PDF**.

**Exemplo de relatório de eventos de segurança:**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e6ea3d0724fe2cb241dc3c8a4ba08363.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/e6ea3d0724fe2cb241dc3c8a4ba08363.png)

> **Tempo de geração:** O relatório pode levar de alguns segundos a alguns minutos, dependendo da quantidade de dados processados.

---

## Carregando Dados de Amostra

O servidor Wazuh de gerenciamento vem com **dados de exemplo** empacotados na instalação.

> **Nota:** Os dados de exemplo não estão habilitados por padrão para melhorar o desempenho do servidor.

### Como Importar Dados de Amostra

1. Abra a guia **"Wazuh"** no cabeçalho
2. Passe o mouse sobre **"Settings"**
3. Selecione a guia **"Sample data"**
4. Pressione o botão **"Add data"** nos respectivos três cartões

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/b3915d96928cd3999a652155e21a88f2.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/b3915d96928cd3999a652155e21a88f2.png)

> **Aguarde:** Pode levar até um minuto para cada conjunto. Quando concluído, o botão mudará para "Remove data".

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/cdea39d294694de9ae762e086acc1e81.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/cdea39d294694de9ae762e086acc1e81.png)

### Visualizando os Dados Importados

Retorne ao dashboard do Wazuh. O módulo **"Eventos de Segurança"** agora terá muito mais dados para explorar.

> **Importante:** Ajuste o intervalo de datas para **"Últimos 7 dias+"** e atualize o painel para visualizar os dados.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/c3e72b11a3b6fc4acae20858c928e28e.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/c3e72b11a3b6fc4acae20858c928e28e.png)

---

## Resumo Rápido: Comandos e Configurações Úteis

| Tarefa                      | Comando/Arquivo                                                                                  |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| **Reiniciar Wazuh Manager** | `/opt/splunk/bin/splunk restart` (ou o caminho correspondente)                                   |
| **Logs de alerta**          | `/var/ossec/logs/alerts/alerts.log`                                                              |
| **Regras locais**           | `/var/ossec/etc/rules/local_rules.xml`                                                           |
| **Configuração do agente**  | `/var/ossec/etc/ossec.conf` (Linux) ou `C:\Program Files (x86)\ossec-agent\ossec.conf` (Windows) |
| **Regras do auditd**        | `/etc/audit/rules.d/audit.rules`                                                                 |
| **API Wazuh**               | `https://MANAGER_IP:55000`                                                                       |
| **Status dos serviços**     | `curl -k -X GET "https://MANAGER_IP:55000/manager/status" -H "Authorization: Bearer $TOKEN"`     |

