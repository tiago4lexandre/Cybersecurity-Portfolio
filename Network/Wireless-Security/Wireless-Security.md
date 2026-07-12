<!--
title: Wireless Security
desc: Fundamentos de segurança em redes sem fio, cobrindo Wi-Fi, Bluetooth, RFID, NFC e riscos em dispositivos IoT.
tags: network, wifi, wireless
readTime: 20 min
-->

<!-- ===================================== -->
<!--          WIRELESS SECURITY            -->
<!-- ===================================== -->
<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20%26%20Defensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Wireless%20Networks-blue?style=for-the-badge">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Wi--Fi%20%2F%20Bluetooth%20%2F%20RFID%20%2F%20NFC-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Network%20Security-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Beginner%20→%20Intermediate-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Lab%20Documentation-green?style=flat-square">
</p>

---

# 📚 Wireless Security
## Fundamentos e Riscos em Redes Sem Fio
> De Wi-Fi a Bluetooth, RFID, NFC e IoT: como a ausência de um meio físico controlado transforma o ar em superfície de ataque, e quais protocolos e medidas defensivas mitigam esses riscos.

---
# Wireless Security

## Introdução

### O Papel das Tecnologias Sem Fio na Segurança Moderna

As tecnologias sem fio desempenharam um papel fundamental ao viabilizar a conectividade entre dispositivos, permitindo a troca de dados em ambientes modernos **sem conexões físicas**. No entanto, é importante compreender que essas tecnologias podem introduzir **vulnerabilidades de segurança** que podem ser exploradas por atacantes para comprometer dados sensíveis.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1773913328853.svg)

### Por que as Tecnologias Sem Fio São Diferentes?

|Aspecto|Redes Cabeadas|Redes Sem Fio|
|---|---|---|
|**Meio de transmissão**|Físico (cabo)|Ar (ondas de rádio)|
|**Acesso físico**|Controlado|Disponível para qualquer pessoa no alcance|
|**Interceptação**|Requer acesso ao cabo|Possível com antena apropriada|
|**Visibilidade**|Limitada|Alta (sinais se propagam)|
|**Segurança**|Baseada em controle físico|Baseada em criptografia e autenticação|

> ⚠️ **Aviso:** O sinal sem fio **não respeita paredes** ou limites físicos. Ele se propaga para além das instalações da organização, tornando a rede potencialmente acessível a qualquer pessoa dentro do alcance.

### Objetivos de Aprendizagem

Ao final deste guia, você será capaz de:

1. ✅ Compreender os fundamentos das redes Wi-Fi e seus componentes
2. ✅ Identificar protocolos de segurança Wi-Fi e suas vulnerabilidades
3. ✅ Reconhecer os riscos de segurança em Bluetooth, RFID e NFC
4. ✅ Entender os desafios de segurança em tecnologias sem fio emergentes (IoT)
5. ✅ Aplicar medidas defensivas para proteger ambientes sem fio

---
## Fundamentos de Redes Wi-Fi

### O Que é Wi-Fi?

Hoje em dia, as pessoas se adaptaram ao uso do Wi-Fi para se conectar à internet. Ele está presente em:

- 🏠 Residências    
- 🏢 Escritórios
- ☕ Cafeterias
- ✈️ Aeroportos

O Wi-Fi permite que os dispositivos se comuniquem usando **sinais de rádio** em vez de cabos físicos, o que torna a conectividade flexível e conveniente.

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1773920336739.svg)

### Componentes Principais de uma Rede Wi-Fi

|Componente|Descrição|Exemplo|
|---|---|---|
|**Ponto de Acesso (AP)**|Dispositivo que transmite o sinal Wi-Fi - a ponte entre dispositivos sem fio e a rede cabeada|Roteador doméstico, AP empresarial|
|**Clientes**|Dispositivos que se conectam ao AP para acessar recursos|Smartphones, laptops, tablets, impressoras, IoT|
|**NIC (Network Interface Card)**|Placa de interface de rede sem fio que lida com sinais de rádio|Adaptador Wi-Fi integrado ou USB|

### Identificadores em Redes Wi-Fi

|Identificador|Definição|Exemplo|
|---|---|---|
|**SSID** (Service Set Identifier)|Nome da rede visível para usuários|`Office_WiFi`, `Home_Network`|
|**BSSID** (Basic Service Set Identifier)|Identificador único do AP (endereço MAC)|`00:1A:2B:3C:4D:5E`|

### Como os Dispositivos Sem Fio se Comunicam

Os dispositivos comunicam-se através da transmissão de ondas de rádio em um espaço aéreo compartilhado.

#### Bandas de Frequência

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1773915774873.svg)

| Característica       | 2.4 GHz                      | 5 GHz                     |
| -------------------- | ---------------------------- | ------------------------- |
| **Alcance**          | Maior (~45m indoor)          | Menor (~15m indoor)       |
| **Velocidade**       | Menor (até 600 Mbps)         | Maior (até 1300 Mbps)     |
| **Penetração**       | Melhor (atravessa paredes)   | Pior (obstáculos físicos) |
| **Congestionamento** | Alto (muitos dispositivos)   | Baixo                     |
| **Interferência**    | Micro-ondas, Bluetooth, etc. | Menos interferência       |

### Processo de Associação

Quando um dispositivo se conecta a uma rede Wi-Fi, o processo envolve várias etapas:

```text
1. Descoberta → 2. Seleção → 3. Autenticação → 4. Associação → 5. Troca de Dados
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1778873800742.svg)
#### Detalhamento das Etapas:

1. **Descoberta (Scanning):** Dispositivo verifica a área em busca de redes disponíveis (beacons)
2. **Seleção:** Usuário (ou dispositivo automaticamente) escolhe uma rede
3. **Autenticação:** Troca de detalhes de autenticação com o AP
    - **Open System Authentication:** AP não verifica credenciais (apenas "sim, pode se comunicar")
    - **WPA2-Personal:** Handshake de 4 vias para comprovar conhecimento da chave
    - **WPA2-Enterprise (802.1X):** Encaminhado para servidor RADIUS

4. **Associação:** Estabelecimento formal da conexão    
5. **Troca de Dados:** Negociação de chaves de criptografia para proteger o tráfego

> **Diferença Crítica:** No **WPA2-Personal**, a autenticação e associação usam o mesmo processo (handshake de 4 vias). No **WPA2-Enterprise**, a autenticação ocorre após a associação, através do servidor RADIUS.

### Fatores que Afetam Sinais e Cobertura

|Fator|Impacto|Mitigação|
|---|---|---|
|**Barreiras físicas**|Paredes, pisos e tetos enfraquecem o sinal|Posicionamento estratégico de APs|
|**Distância**|Quanto mais longe, mais fraco o sinal|APs adicionais, mesh|
|**Interferência**|Micro-ondas, Bluetooth, outras redes|Uso de 5 GHz, análise de canais|
|**Congestionamento**|Múltiplas redes em canais sobrepostos|Escolha de canais não sobrepostos (1,6,11)|
|**Vazamento de sinal**|Sinais se estendem além dos limites físicos|Controle de potência, direcionamento|

---
## Segurança Wi-Fi

### Padrões IEEE 802.11 e Gerações Wi-Fi

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1773996055257.svg)

|Geração|Padrão IEEE|Velocidade|Banda|Ano|
|---|---|---|---|---|
|Wi-Fi 1|802.11b|11 Mbps|2.4 GHz|1999|
|Wi-Fi 2|802.11a|54 Mbps|5 GHz|1999|
|Wi-Fi 3|802.11g|54 Mbps|2.4 GHz|2003|
|Wi-Fi 4|802.11n|600 Mbps|2.4/5 GHz|2009|
|**Wi-Fi 5**|**802.11ac**|**1.3 Gbps**|**5 GHz**|**2013**|
|**Wi-Fi 6**|**802.11ax**|**9.6 Gbps**|**2.4/5 GHz**|**2019**|
|Wi-Fi 7|802.11be|46 Gbps|2.4/5/6 GHz|2024 (em desenvolvimento)|

> 💡 **Dica:** A maioria das empresas implementa **Wi-Fi 5** e **Wi-Fi 6**, sendo estes os mais comuns em avaliações de segurança.

### Autenticação e Criptografia em Wi-Fi

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1773996055277.svg)

#### Evolução dos Protocolos de Segurança

|Protocolo|Ano|Status|Vulnerabilidades|
|---|---|---|---|
|**WEP** (Wired Equivalent Privacy)|1997|❌ Obsoleto|RC4 fraco, IV reutilização, quebra em minutos|
|**WPA** (Wi-Fi Protected Access)|2003|⚠️ Descontinuado|TKIP, ataques de chave, KRACK|
|**WPA2** (Wi-Fi Protected Access 2)|2004|✅ Atual|Vulnerável a KRACK, ataques de dicionário se senha fraca|
|**WPA3** (Wi-Fi Protected Access 3)|2018|✅ Moderno|SAE (Dragonfly), criptografia de 192 bits|

#### Comparação Detalhada

|Característica|WEP|WPA|WPA2|WPA3|
|---|---|---|---|---|
|**Criptografia**|RC4|TKIP/RC4|AES-CCMP|AES-GCMP|
|**Tamanho da chave**|40/104 bits|128 bits|128 bits|192 bits|
|**Proteção contra força bruta**|Não|Não|Não|Sim (SAE)|
|**Segurança em redes abertas**|Não|Não|Não|Sim (OWE)|
|**Status atual**|Obsoleto|Descontinuado|Em uso|Recomendado|

### Configurações Incorretas Comuns de Wi-Fi

|Configuração Incorreta|Risco|Mitigação|
|---|---|---|
|**Uso de WEP**|Quebra de criptografia em minutos|Migrar para WPA2 ou WPA3|
|**Senhas fracas**|Ataques de dicionário e força bruta|Senhas complexas (≥12 caracteres)|
|**WPS ativado**|Força bruta do PIN (8 dígitos)|Desativar WPS|
|**Credenciais padrão**|Acesso administrativo a APs|Alterar credenciais padrão|
|**SSID broadcast desativado**|Falsa sensação de segurança|Não confiar em obscuridade|
|**Ausência de segmentação**|Acesso a redes internas|VLANs, redes de convidados|

### Conceitos Comuns de Ataques Wi-Fi

|Tipo de Ataque|Descrição|Mitigação|
|---|---|---|
|**Ataques de senha**|Força bruta ou quebra de senhas|Senhas fortes, WPA3, monitoramento|
|**Rogue Access Points**|AP não autorizado conectado à rede|Detecção de APs, WIDS/WIPS|
|**Evil Twin**|AP falso com mesmo SSID|Certificados, WPA3-Enterprise|
|**Desautenticação**|Forçar desconexão de dispositivos|Proteção 802.11w, monitoramento|
|**Interceptação de tráfego**|Captura de tráfego não criptografado|Criptografia forte, VPN|

### Protegendo Redes Wi-Fi

#### Boas Práticas de Configuração

|Medida|Benefício|Implementação|
|---|---|---|
|**WPA2/WPA3 com senhas fortes**|Autenticação segura|Senhas ≥12 caracteres, complexidade|
|**Desativar WEP e protocolos obsoletos**|Elimina vulnerabilidades|Configurar apenas WPA2/WPA3|
|**Desativar WPS**|Remove vetor de ataque|Desabilitar WPS no AP|
|**Alterar credenciais padrão**|Impede acesso administrativo|Alterar senha padrão|
|**Segmentação de rede**|Limita acesso a sistemas internos|VLANs, redes de convidados|
|**Atualização de firmware**|Corrige vulnerabilidades conhecidas|Atualizações regulares|
|**Monitoramento de APs**|Detecta APs não autorizados|WIDS/WIPS|

#### Exemplo de Configuração Segura

```yaml
# Configuração segura para AP corporativo
network:
  ssid: "CORP-WIFI"
  security:
    type: WPA2-Enterprise  # ou WPA3-Enterprise
    encryption: AES-CCMP
    authentication: 802.1X
    radius_server: 10.0.0.5
    secret: "complex-secret-key-2024"
  features:
    wps: disabled
    broadcast_ssid: true  # NÃO esconder SSID
    client_isolation: false
    guest_network: true
    vlan: 100
  access_control:
    mac_filtering: false  # Não confiar em MAC filtering
    acl_rules:  # Lista de permissão de dispositivos
      - allow: 00:1A:2B:3C:4D:5E
      - deny: all
  monitoring:
    wids: enabled
    logging: enabled
    alerts: enabled
```

---
## Segurança Bluetooth

### O Que é Bluetooth?

O Bluetooth é uma tecnologia que permite a comunicação sem fio entre dispositivos por meio de **emparelhamento direto**. Opera na frequência de 2.4 GHz e foi projetado para comunicação de **curto alcance**.

**Dispositivos Comuns:**

- ⌨️ Teclados e mouses sem fio
- 🎧 Fones de ouvido e alto-falantes
- ⌚ Relógios inteligentes e rastreadores de fitness
- 🚗 Sistemas de infoentretenimento para veículos
- 🏠 IoT e dispositivos domésticos inteligentes

> ⚠️ **Alerta:** O Bluetooth é comumente ativado em dispositivos pessoais e corporativos, tornando-o um **alvo atraente para invasores**.

### Bluetooth Clássico vs. Bluetooth Low Energy (BLE)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6186e45a4c3e9a0043efd100/room-content/6186e45a4c3e9a0043efd100-1779362067496.svg)

|Característica|Bluetooth Clássico|BLE (Bluetooth Low Energy)|
|---|---|---|
|**Uso principal**|Streaming, transferência de arquivos|Envio ocasional de pequenos dados|
|**Consumo de energia**|Alto|Muito baixo|
|**Velocidade de dados**|2-24 Mbps|0.27-1.4 Mbps|
|**Alcance**|10-100m|10-50m|
|**Emparelhamento**|SSP (Secure Simple Pairing)|LE Secure Connections (4.2+)|
|**Segurança**|Mais robusta|Varia (depende do método)|
|**Exemplo**|Fones de ouvido|Rastreadores fitness, beacons|

**Analogia:** Bluetooth Clássico é uma **chamada telefônica** (conexão estável), enquanto BLE é uma **mensagem de texto** (rápido e leve).

### Como os Dispositivos Bluetooth Emparelham

#### Bluetooth Clássico

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774010392350.svg)

**Métodos de Emparelhamento:**

1. **PIN Code (Versões antigas):**
    - Código numérico simples (ex: 0000, 1234)
    - Vulnerável a força bruta
    - Interceptável

2. **Secure Simple Pairing (SSP - Bluetooth 2.1+):**    
    - Troca de chaves criptográficas
    - Métodos:
        - **Just Works** (sem verificação do usuário)
        - **Numeric Comparison** (comparar números nas telas)
        - **Passkey Entry** (inserir código)
        - **Out of Band (OOB)** (NFC, RFID)

#### Bluetooth Low Energy (BLE)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774010392401.svg)

**Métodos de Emparelhamento BLE:**

| Método                               | Descrição                                     | Nível de Segurança |
| ------------------------------------ | --------------------------------------------- | ------------------ |
| **LE Legacy Pairing (BLE 4.0-4.1)**  | PIN/Passkey, vulnerável a interceptação       | 🔴 Baixo           |
| **LE Secure Connections (BLE 4.2+)** | Diffie-Hellman, protegido contra MITM         | 🟢 Alto            |
| **Just Works**                       | Sem autenticação, "emparelhamento automático" | 🟠 Médio-Baixo     |

> ⚠️ **Crítico:** Muitos dispositivos IoT de baixo custo usam **"Just Works"** - NÃO envolvem verificação do usuário, permitindo que um invasor se interponha na conexão.

### Riscos Comuns de Segurança Bluetooth

|Risco|Descrição|Impacto|
|---|---|---|
|**Visibilidade desnecessária**|Dispositivos em modo de detecção|Atacantes os encontram|
|**Mecanismos de emparelhamento fracos**|PINs simples (0000, 1234)|Força bruta, interceptação|
|**Emparelhamento não autorizado**|Controles de aprovação fracos|Dispositivos maliciosos conectados|
|**Bluejacking**|Envio de mensagens não solicitadas|Spam, engenharia social|
|**Bluesnarfing**|Acesso a dados via Bluetooth|Roubo de dados|
|**Bluebugging**|Controle de funções do dispositivo|Comprometimento total|
|**Falta de atualizações**|Implementações desatualizadas|Vulnerabilidades conhecidas|

### Ataques Bluetooth na Prática

#### 1. Bluejacking (Envio de Mensagens)

```text
1. Atacante detecta dispositivo com Bluetooth
2. Envia mensagem não solicitada (vCard, texto)
3. Usuário recebe a mensagem (geralmente aceita)
4. Pode conter link malicioso ou engenharia social
```

#### 2. Bluesnarfing (Roubo de Dados)

```text
1. Atacante encontra dispositivo vulnerável
2. Explora vulnerabilidade para acessar:
   - Contatos
   - Mensagens
   - Fotos
   - Informações do dispositivo
3. Extrai dados sem conhecimento do usuário
```

#### 3. Bluebugging (Controle Remoto)

```text
1. Atacante explora vulnerabilidade na pilha Bluetooth
2. Obtém controle remoto do dispositivo
3. Pode realizar:
   - Realizar chamadas
   - Enviar mensagens
   - Acessar internet
   - Espionar conversas
```

### Considerações de Segurança para Bluetooth

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774007023234.svg)

|Medida|Bluetooth Clássico|BLE|
|---|---|---|
|**Desativar quando não em uso**|✅|✅|
|**Usar modo não detectável**|✅|✅|
|**Aceitar emparelhamento apenas de fontes confiáveis**|✅|✅|
|**Atualizar firmware regularmente**|✅|✅|
|**Usar "Just Works" com cuidado**|❌ N/A|⚠️ Apenas se necessário|
|**Implementar autenticação forte**|✅|✅|
|**Monitorar dispositivos conectados**|✅|✅|
|**Usar conexões seguras (BLE 4.2+)**|❌ N/A|✅|

> 💡 **Lembrete:** Um dispositivo vulnerável pode vazar dados confidenciais ou dar ao invasor acesso a uma rede maior. Pense nisso como deixar uma janela entreaberta no térreo - pequeno o suficiente para não preocupar, mas suficiente para alguém determinado entrar.

---
## Segurança RFID e NFC

### O Que são RFID e NFC?

**RFID** (Radio Frequency Identification) é uma tecnologia que utiliza campos eletromagnéticos para identificar e rastrear etiquetas fixadas a objetos.

**NFC** (Near Field Communication) é um padrão intimamente relacionado que permite a troca de dados entre dois dispositivos quando aproximados.

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774737597437.svg)

|Característica|RFID|NFC|
|---|---|---|
|**Alcance**|Até 100m (depende do tipo)|~5 cm (curta distância)|
|**Comunicação**|Unidirecional (leitor → etiqueta)|Bidirecional (leitor ↔ dispositivo)|
|**Frequência**|125 kHz, 13.56 MHz, 860-960 MHz|13.56 MHz (fixo)|
|**Tipos**|Passiva (sem bateria) e Ativa (com bateria)|Passiva e Ativa|
|**Uso comum**|Controle de acesso, inventário|Pagamentos, emparelhamento|

### Como Funcionam RFID e NFC

#### RFID

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774741867454.svg)

**Componentes:**

1. **Leitor (Interrogador):** Emite ondas de rádio
2. **Etiqueta (Tag):** Responde com dados armazenados

**Tipos de Etiquetas RFID:**

|Tipo|Energia|Alcance|Custo|Aplicação|
|---|---|---|---|---|
|**Passiva**|Do campo do leitor|Curto (até 10m)|Baixo|Controle de acesso, inventário|
|**Ativa**|Bateria interna|Longo (até 100m+)|Alto|Rastreamento de veículos, logística|
|**Semi-passiva**|Bateria + campo do leitor|Médio|Médio|Sensores, IoT|

#### NFC

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774741867519.svg)

**Modos de Operação NFC:**

|Modo|Descrição|Exemplo|
|---|---|---|
|**Leitor/Escritor**|Lê/escreve em etiquetas NFC|Leitura de cartão de transporte|
|**Peer-to-Peer**|Troca de dados bidirecional|Compartilhamento de arquivos|
|**Card Emulation**|Dispositivo atua como cartão|Pagamento com smartphone|

### Riscos Comuns de Segurança em RFID e NFC

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774735469184.svg)

|Risco|Descrição|Impacto|
|---|---|---|
|**Escuta telefônica (Eavesdropping)**|Interceptação da comunicação|Roubo de dados do cartão|
|**Clonagem**|Copiar dados de um cartão para outro|Acesso não autorizado|
|**Ataques de retransmissão (Relay)**|Encaminhamento da comunicação|Transações não autorizadas|
|**Leitura não autorizada**|Leitura secreta de cartão|Roubo de dados sem contato|
|**Cartões perdidos/roubados**|Uso indevido de crachá|Acesso físico a instalações|

#### Exemplo de Ataque de Retransmissão (Relay Attack)

```text
1. Vítima tem cartão de pagamento no bolso
2. Atacante #1 se aproxima com leitor móvel
3. Atacante #2 está próximo a um terminal de pagamento
4. Comunicação é retransmitida em tempo real
5. Terminal processa transação como se cartão estivesse presente
6. Vítima é cobrada sem saber
```

### Considerações de Segurança para RFID e NFC

|Medida|Como Implementar|Benefício|
|---|---|---|
|**Criptografia**|Usar cartões com criptografia forte|Protege dados durante transmissão|
|**Limitar dados sensíveis**|Armazenar apenas o necessário|Reduz exposição|
|**Tokenização**|Substituir dados sensíveis por tokens|Protege contra clonagem|
|**Desativação imediata**|Revogar cartões perdidos/roubados|Previne uso não autorizado|
|**Bolsas de Faraday**|Capas que bloqueiam sinais|Previne leitura não autorizada|
|**Atualização regular**|Revisão de controles de acesso|Mantém segurança atualizada|
|**Autenticação biométrica**|Adicionar fator adicional|Aumenta segurança|
|**Limite de transações**|Definir valor máximo sem PIN|Limita perdas|

### Exemplos de Aplicações e Riscos

|Aplicação|Tecnologia|Riscos|Mitigação|
|---|---|---|---|
|**Cracha de funcionário**|RFID 125 kHz|Clonagem, cartão perdido|Criptografia, desativação rápida|
|**Cartão de transporte**|RFID 13.56 MHz|Clonagem, leitura não autorizada|Criptografia, tokenização|
|**Pagamento sem contato**|NFC|Retransmissão, clonagem|Tokenização, limite de valor|
|**Chave de hotel**|RFID|Clonagem, leitura não autorizada|Criptografia, expiração|
|**Etiqueta de inventário**|RFID UHF|Leitura não autorizada, tracking|Criptografia, desativação|

---
## Outras Tecnologias Sem Fio

![697](https://tryhackme-images.s3.amazonaws.com/user-uploads/68f9e128ba199589d7ad0335/room-content/68f9e128ba199589d7ad0335-1774821749287.svg)

### Visão Geral das Tecnologias IoT

|Tecnologia|Frequência|Alcance|Velocidade|Uso Principal|
|---|---|---|---|---|
|**Zigbee**|2.4 GHz|Curto (10-100m)|250 kbps|Casa inteligente, sensores|
|**Z-Wave**|900 MHz|Médio (30-100m)|100 kbps|Automação residencial|
|**LoRa**|868/915 MHz|Longo (10+ km)|50 kbps|IoT, sensoriamento remoto|
|**LTE-M**|Celular|Longo|1 Mbps|IoT celular|
|**NB-IoT**|Celular|Longo|250 kbps|IoT de baixa potência|
|**Infravermelho**|Luz|Muito curto (<5m)|Baixo|Controles remotos|

### Riscos de Segurança por Tecnologia

#### Zigbee

**Características:**

- ✅ Baixo consumo
- ✅ Topologia em malha (cada dispositivo retransmite)
- ✅ Protocolo de rede

**Vulnerabilidades:**

|Riscos|Descrição|Exemplo|Mitigação|
|---|---|---|---|
|**Chave de rede padrão**|Coordenador transmite chave sem criptografia|Philips Hue (CVE-2020-6007)|Códigos de instalação únicos|
|**Comprometimento de dispositivos**|Dispositivo comprometido pode retransmitir malware|Controle de lâmpadas inteligentes|Atualizações regulares|
|**Downgrade de segurança**|Dispositivos mais antigos forçam protocolo vulnerável|Zigbee 3.0 vs Zigbee HA|Desativar compatibilidade retroativa|

#### Z-Wave

**Características:**

- ✅ Padronizado (mais que Zigbee)
- ✅ Maior alcance
- ✅ Dispositivos de diferentes fabricantes interoperam

**Vulnerabilidades:**

|Riscos|Descrição|Exemplo|Mitigação|
|---|---|---|---|
|**Emparelhamento S0**|Chave criptografada com zeros|Yale Conexis L1 (Z-Shave)|Desativar S0|
|**Ataque de downgrade**|Forçar S2 para S0|Handshake não autenticado|Configurar apenas S2|
|**Interceptação**|Captura de tráfego durante emparelhamento|Análise de pacotes|Usar S2 com Diffie-Hellman|

#### LoRa (Long Range)

**Características:**

- ✅ Longa distância (vários km)
- ✅ Muito baixo consumo
- ✅ Ideal para sensores remotos    

**Vulnerabilidades:**

|Riscos|Descrição|Exemplo|Mitigação|
|---|---|---|---|
|**ABP (Activation by Personalization)**|Chaves estáticas permanentes|Contador de quadros reiniciado|Usar OTAA (Over-The-Air Activation)|
|**Ataque de repetição**|Replay de mensagens antigas|LoRaWAN 1.0|Monitorar contadores, rotação de chaves|
|**Acesso físico**|Dispositivos em locais remotos|Extração de chaves|Hardware seguro, tamper detection|

#### Celular (LTE-M, NB-IoT)

**Características:**

- ✅ Usa infraestrutura celular existente
- ✅ Autenticação baseada em SIM
- ✅ Criptografia padronizada

**Vulnerabilidades:**

|Riscos|Descrição|Exemplo|Mitigação|
|---|---|---|---|
|**Acesso físico**|Dispositivos em locais remotos|Extração de firmware|Hardware seguro|
|**Interfaces de gerenciamento**|Credenciais padrão, injeção|IoT gateway|VPN, APNs privados|
|**Dificuldade de atualização**|Software limitado|Correção de vulnerabilidades|Atualizações OTA|

#### Infravermelho

**Características:**

- ✅ Simples
- ✅ Linha reta
- ✅ Muito curto alcance

**Vulnerabilidades:**

|Riscos|Descrição|Exemplo|Mitigação|
|---|---|---|---|
|**Sem autenticação**|Qualquer um pode enviar comandos|Controle de TV/AC|Desativar receptores não utilizados|
|**Sem criptografia**|Comandos em texto claro|Análise de protocolo|Isolar dispositivos|
|**Replay**|Captura e reprodução|Raspberry Pi + IR|Desativar IR em dispositivos de rede|

### Considerações de Segurança para IoT

|Medida|Zigbee|Z-Wave|LoRa|Celular|Infravermelho|
|---|---|---|---|---|---|
|**Códigos de instalação únicos**|✅|❌|❌|❌|❌|
|**Desativar compatibilidade retroativa**|✅|✅|❌|❌|❌|
|**OTAA (over-the-air activation)**|❌|❌|✅|❌|❌|
|**Rotação de chaves**|❌|❌|✅|✅|❌|
|**VPN/APNs privados**|❌|❌|❌|✅|❌|
|**Desativar receptores não utilizados**|❌|❌|❌|❌|✅|
|**Segmentação de rede**|✅|✅|✅|✅|✅|

### Segmentação de Rede para IoT

**Por que segmentar?**

```text
Rede Interna (Dados Sensíveis)
        │
        ├── Segmento IoT (Wi-Fi)
        │     └── Câmeras, lâmpadas, sensores
        │
        ├── Segmento Convidados (Wi-Fi)
        │     └── Visitantes, dispositivos pessoais
        │
        └── Segmento Operacional
              └── Impressoras, scanners, APs
```

**Benefícios da Segmentação:**

- 🔒 Limita o impacto de um dispositivo comprometido
- 🛡️ Isola dispositivos não confiáveis
- 📊 Facilita monitoramento e logging
- ✅ Reduz superfície de ataque

---
## Checklist do Pentester

### Fase 1: Wi-Fi

- **Identificar SSIDs e BSSIDs**

```bash
# Listar redes disponíveis
airodump-ng wlan0mon

# Identificar APs
wash -i wlan0mon
```

- **Verificar protocolos de segurança**

```bash
# Detectar WEP/WPA/WPA2/WPA3
airodump-ng -c <channel> --bssid <BSSID> wlan0mon
```

- **Testar senhas fracas**

```bash
# Capturar handshake
airodump-ng -c <channel> --bssid <BSSID> -w capture wlan0mon

# Força bruta
aircrack-ng capture.cap -w wordlist.txt
```

- **Verificar WPS**

```bash
# Escanear WPS
wash -i wlan0mon

# Força bruta PIN
bully <BSSID> -b wlan0mon
```

- **Detectar Rogue APs**

```bash
# Monitorar redes
airodump-ng wlan0mon

# Detectar Evil Twin
airbase-ng -a <BSSID> -e <SSID> wlan0mon
```

### Fase 2: Bluetooth

- **Escanear dispositivos**

```bash
# Escanear Bluetooth Clássico
hcitool scan

# Escanear BLE
hcitool lescan

# Detalhes do dispositivo
hcitool info <MAC>
```

- **Verificar visibilidade**

```bash
# Modo detectável
hciconfig hci0 piscan

# Modo não detectável
hciconfig hci0 noscan
```

- **Testar emparelhamento**

```bash
# Tentar emparelhar
bluetoothctl
pair <MAC>

# Tentar conectar
connect <MAC>
```

- **Verificar serviços**

```bash
# Listar serviços
sdptool browse <MAC>

# Verificar canais RFCOMM
sdptool records <MAC>
```

### Fase 3: RFID/NFC

- **Verificar existência de RFID**

```bash
# Detectar leitores
rfid-reader -d /dev/ttyUSB0

# Ler etiqueta
mfoc -O dump.mfd
```

- **Testar clonagem**

```bash
# Ler crachá
proxmark3 -p /dev/ttyACM0
lf search

# Clonar
lf clone <UID>
```

- **Verificar criptografia**
    - Cartão com criptografia? (Mifare Classic vs. Desfire)
    - Chaves padrão? (testar com chaves conhecidas)

### Fase 4: IoT e Outras Tecnologias

- **Zigbee**

```bash
# Escanear redes
zbd -g

# Capturar tráfego
zbd -c <channel> -d
```

- **Z-Wave**

```bash
# Escanear
zwave_scan -i /dev/ttyACM0

# Capturar
zwave_capture -f capture.zvs
```

- **LoRa**

```bash
# Detectar dispositivos
lora-scanner -f 868M

# Capturar pacotes
lora-capture -f 868M -o capture.pcap
```

### Ferramentas Recomendadas

|Tecnologia|Ferramentas|Uso|
|---|---|---|
|**Wi-Fi**|`aircrack-ng`, `airodump-ng`, `wash`, `bully`|Análise de redes, auditoria de segurança|
|**Bluetooth**|`hcitool`, `btmon`, `bettercap`, `bluetoothctl`|Escaneamento, emparelhamento|
|**RFID/NFC**|`mfoc`, `proxmark3`, `nfc-tools`, `mfcuk`|Leitura, clonagem, análise|
|**Zigbee**|`ZigBee Development Kit`, `Wireshark`|Análise de protocolo|
|**Z-Wave**|`Z-Wave Protocol Analyzer`|Captura de tráfego|
|**LoRa**|`LoRa Discovery Tool`|Detecção de dispositivos|

---
## Conclusão

### Principais Aprendizados

As tecnologias sem fio são onipresentes em ambientes modernos, mas introduzem vulnerabilidades únicas que os profissionais de segurança precisam compreender.

|Tecnologia|Principais Riscos|Principais Medidas de Segurança|
|---|---|---|
|**Wi-Fi**|WEP, WPS, senhas fracas, Rogue APs|WPA2/WPA3, senhas fortes, monitoramento|
|**Bluetooth**|Visibilidade, emparelhamento fraco, Bluejacking|Desativar quando não em uso, emparelhamento seguro|
|**RFID/NFC**|Clonagem, retransmissão, leitura não autorizada|Criptografia, tokenização, bolsas Faraday|
|**IoT (Zigbee, etc.)**|Chaves padrão, downgrade, falta de atualizações|Segmentação, códigos únicos, OTAA|

### A Importância da Segurança em Camadas

A segurança de redes sem fio deve ser abordada em **múltiplas camadas**:

```text
1. Medidas Físicas
   ├── Controle de acesso físico
   ├── Posicionamento estratégico de APs
   └── Isolamento de sinal

2. Medidas Técnicas
   ├── Criptografia forte
   ├── Autenticação robusta
   ├── Monitoramento contínuo
   └── Atualizações regulares

3. Medidas Administrativas
   ├── Políticas de segurança
   ├── Treinamento de usuários
   ├── Auditorias regulares
   └── Plano de resposta a incidentes
```

### Próximos Passos

1. **Praticar em Laboratórios:**
    - [TryHackMe - Wireless Security](https://tryhackme.com/room/wirelesssecurity)
    - [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/)

2. **Certificações:**    
    - [CWSP - Certified Wireless Security Professional](https://www.cwnp.com/certifications/cwsp)
    - [CEH - Certified Ethical Hacker (Wireless Module)](https://www.eccouncil.org/ceh/)
    - [OSCP - Offensive Security Certified Professional](https://www.offensive-security.com/pwk-oscp/)

3. **Ferramentas para Aprofundar:**
    - Kali Linux (pacotes completos de segurança sem fio)
    - Wireshark (análise de tráfego)
    - Bettercap (testes de segurança)
    - HackRF (SDR para análise de RF)

### O Futuro da Segurança Sem Fio

|Tendência|Impacto|Preparação|
|---|---|---|
|**Wi-Fi 7 (802.11be)**|Maior velocidade, mais complexidade|Atualização de conhecimentos|
|**WPA3**|Segurança aprimorada, transição gradual|Migração antecipada|
|**5G e IoT**|Mais dispositivos conectados|Segmentação, monitoramento|
|**IA em ataques**|Ataques mais sofisticados|Defesas baseadas em IA|

---
## Referências

### Documentação Oficial

**Wi-Fi:**

- [IEEE 802.11 Standards](https://standards.ieee.org/ieee/802.11/)
- [Wi-Fi Alliance](https://www.wi-fi.org/)
- [WPA3 Specification](https://www.wi-fi.org/discover-wi-fi/security)

**Bluetooth:**

- [Bluetooth SIG](https://www.bluetooth.com/)
- [Bluetooth Core Specification](https://www.bluetooth.com/specifications/specs/)
- [BLE Security](https://www.bluetooth.com/security/)

**RFID/NFC:**

- [ISO 14443 Standard](https://www.iso.org/standard/39693.html)
- [NFC Forum](https://nfc-forum.org/)
- [FIDO Alliance](https://fidoalliance.org/)

### Vulnerabilidades e CVE

- [CVE-2020-6007 - Philips Hue Zigbee](https://nvd.nist.gov/vuln/detail/CVE-2020-6007)
- [CVE-2017-13078 - WPA2 KRACK](https://nvd.nist.gov/vuln/detail/CVE-2017-13078)
- [CVE-2019-18662 - Bluetooth](https://nvd.nist.gov/vuln/detail/CVE-2019-18662)

### Ferramentas

**Wi-Fi:**

- [Aircrack-ng](https://www.aircrack-ng.org/)
- [Wifite](https://github.com/derv82/wifite2)
- [Wireshark](https://www.wireshark.org/)

**Bluetooth:**

- [Bettercap](https://www.bettercap.org/)
- [Btlejack](https://github.com/virtualabs/btlejack)
- [Ubertooth](https://github.com/greatscottgadgets/ubertooth)

**RFID/NFC:**

- [Proxmark3](https://proxmark.com/)
- [MFOC](https://github.com/nfc-tools/mfoc)
- [libnfc](https://github.com/nfc-tools/libnfc)

**IoT:**

- [Zigbee Development Kit](https://www.digi.com/products/iot-platform/zigbee)
- [LoRa Discovery Tool](https://github.com/Allterco/LoRa-discovery-tool)

### Recursos de Aprendizado

**Cursos:**

- [SANS SEC617 - Wireless Penetration Testing](https://www.sans.org/cyber-security-courses/wireless-penetration-testing-ethical-hacking/)
- [TryHackMe - Wireless](https://tryhackme.com/room/wirelesshacking)
- [HackTheBox - Wireless](https://www.hackthebox.com/)

**Livros:**

- "Wireless Security Architecture" - Jennifer Minella
- "Hacking Wireless Networks" - Michael T. Raggo
- "The Wireless Penetration Tester's Guide" - David Kennedy

**Blogs e Artigos:**

- [OWASP Wireless Attacks](https://owasp.org/www-community/attacks/Wireless_attacks)
- [Kali Linux Wireless Documentation](https://www.kali.org/docs/wireless/)
- [SANS Wireless Security Blog](https://www.sans.org/blog/tag/wireless-security/)

### Padrões de Segurança

- [NIST SP 800-153 - Wireless Network Security](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-153.pdf)
- [ISO/IEC 27002 - Wireless Security Controls](https://www.iso.org/standard/54533.html)
- [PCI DSS v3.2.1 - Wireless Guidelines](https://www.pcisecuritystandards.org/)
