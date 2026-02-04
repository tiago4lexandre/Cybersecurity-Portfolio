<!-- ===================================== -->
<!--        Hydra Authentication Guide     -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Tool-THC--Hydra-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Category-Password%20Attacks-red?style=flat-square">
  <img src="https://img.shields.io/badge/Scope-Network%20%26%20Web-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Offense-Red%20Team-black?style=flat-square">
  <img src="https://img.shields.io/badge/Defense-Hardening%20%26%20Detection-informational?style=flat-square">
</p>

---

# 🔐 Hydra — Guia Prático de Ataques de Autenticação

> Documentação técnica e prática sobre o **THC-Hydra**, uma das principais ferramentas de **força bruta e testes de credenciais** utilizadas em **testes de penetração (Pentest)**.
>
> Este guia aborda o uso do Hydra dentro de uma **metodologia ofensiva estruturada**, desde a **identificação de serviços autenticados**, passando pela **execução controlada de ataques online**, até a **análise de impacto e medidas de mitigação**, sempre em **ambientes autorizados**.

---

## 📌 Metadados

- **Categoria:** Pentest · Red Team · Offensive Security  
- **Escopo:** Web · Network · Linux · Windows  
- **Técnicas:** Password Spraying · Brute Force · Credential Testing  
- **Ferramenta:** THC-Hydra  
- **Protocolos:** HTTP · SSH · FTP · RDP · MySQL · SMB  
- **Ambiente:** Labs controlados · CTFs · Estudos educacionais  

---

## 🏷️ Tags

`#Hydra` `#THCHydra` `#Pentest` `#RedTeam`  
`#PasswordAttacks` `#CredentialTesting`  
`#WebPentest` `#NetworkPentest`  
`#BruteForce` `#CyberSecurity`

---

## ⚠️ Aviso Legal

> Todo o conteúdo apresentado neste documento deve ser utilizado **exclusivamente em ambientes autorizados**, como **laboratórios, CTFs ou sistemas sob permissão explícita**.  
> A execução de ataques de autenticação sem autorização é **ilegal** e passível de sanções legais.

---

# Introdução

O **Hydra** ou (THC-Hydra) é uma ferramenta avançada de **força bruta** e **testes de credenciais** utilizadas para realizar ataques de autenticação em diversos protocolos, como **HTTP, SSH, FTP, RDP, entre outros**. Desenvolvido pelo grupo **The Hacker's Choice (THC)**, o Hydra é amplamente utilizado por pentesters, auditores de segurança e pesquisadores para testar a robustez do sistemas contra ataques de senha.

![Hydra Logo](https://www.kali.org/tools/hydra/images/hydra-logo.svg)

---
# O que é o Hydra?

O Hydra é um **cracker de senhas online**, ou seja, ele testa combinações de usuários e senhas diretamente contra um serviço ativo (diferente de ferramentas como **John the Ripper**, que trabalham offline). Ele suporta múltiplos protocolos e permite ataques **paralelizados** tornando-o eficiente contra sistemas vulneráveis.

## Principais Características

- Suporte a **mais de 50 protocolos** (HTTP, SSH, FTP, MySQL, RDP, etc.).
- Ataques de **força bruta** e **dicionário**.
- **Multi-Thereading** (acelera tentativas de login).
- Opções para evitar **lockout de contas** (delay entre tentativas).
- Integração com proxies e **TOR** para anonimato.

---
# Casos de Uso do Hydra

O Hydra pode ser usado para:

- Testar a resistência de **logins web** (painéis admin, WordPress, etc.).
- Quebrar credenciais de **SSH, FTP, RDP**.
- Auditar bancos de dados (**MySQL, PostgreSQL**).
- Verificar vulnerabilidades em **redes corporativas**.
- Pesquisa em segurança cibernética (com autorização legal).

---
# Instalação do Hydra

## Linux (Debian/Ubuntu)

```bash
sudo apt update && sudo apt install hydra
```

## Linux (RedHat/CentOS)

```bash
sudo yum install hydra
```

## MacOS (via Homebrew)

```bash
brew install hydra
```

## Windows (via WSL ou compilação manual)

- Usar WSL *(Windows Subsystem for Linux)* ou baixar do [site oficial](https://www.github.com/vanhauser-thc/thc-hydra).

---
# Sintaxe Básica do Hydra

```bash
hydra -l <usuário> -P <wordlist> <protocolo>://<IP> -s <porta> -t <threads> -vV
```


| **Argumento** | **Descrição**                                      |
| ------------- | -------------------------------------------------- |
| `-l`          | Define um **usuário específico**                   |
| `-L`          | Define uma **lista de usuários**                   |
| `-p`          | Define uma **senha específica**                    |
| `-P`          | Define uma **wordlist de senhas**                  |
| `-t`          | Número de **threads** (acelera o ataque)           |
| `-s`          | Porta do serviço (útil se não for a padrão)        |
| `-vV`         | Modo **verbose** (mostra tentativas em tempo real) |
| `-f`          | Para após encontrar a primera credencial válida.   |

---
# Exemplos Práticos de Uso

## 1. Ataque a Login HTTP (formulário web)

**Alvo:** Painel de login WordPress (`http://10.0.0.1/wp-login.php`).
**Wordlist:** `rockyou.txt`.
**Usuário:** `admin`.

```bash
hydra -l admin -P rockyou.txt 10.0.0.1 http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username" -t 20 -vV
```

- `http-post-form`: Indica um formulário **HTTP POST**.
- `log=^USER^&pwd=^PASS^`: Campos do formulário (substituídos por credenciais).
- `F=Invalid username`: Filtro para detectar falha no login.

## 2. Ataque a SSH

**Alvo:** Servidor SSH (`10.0.0.1:22`).
**Wordlist:** `passwords.txt`.
**Usuários:** `userlist.txt`

```bash
hydra -L userlist.txt -P passwords.txt ssh://10.0.0.1 -s 22 -t 10 -vV
```

## 3. Ataque a FTP

**Alvo:** Servidor FTP (`10.0.0.1:21`).
**Senha padrão:** `password123`.

```bash
hydra -l anonymous -p password123 ftp://10.0.0.1 -vV
```

## 4. Ataque a RDP (Windows)

**Alvo:** Servidor RDP (`10.0.0.2:3389`).
**Wordlist:** `common-passwords.txt`.

```bash
hydra -L users.txt -P common-passwords.txt rdp://10.0.0.2 -t 5 -vV
```

## 5. Ataque a MySQL

**Alvo:** Banco de dados MySQL (`10.0.0.3:3306`).
**Usuários:** `root`.

```bash
hydra -l root -P rockyou.txt mysql://10.0.0.3 -vV
```

---
# Otimizando Ataques com Hydra

## 1. Evitando Lockout de Contas

- Use `-w` para definir um **delay entre tentativas**:

```bash
hydra -l admin -P passwords.txt ssh://10.0.0.1 -w 10 -vV
```

## 2. Usando Proxies (Para Anonimato)

```bash
hydra -l user -P pass.txt http-get://site.com -e nsr -t 10 -s 8000 -vV x- socks5://127.0.0.1:9050
```

- `-x socks5://127.0.0.1:900`:
	- Roteia o tráfego através de um **proxy SOCKS5** (ex.: Tor).
	- `127.0.0.1:9050` = Endereço padrão do Tor.
	- Objetivo: **Ocultar o IP de origem**.

## 3. Ataques com Regras (Hashcat-style)

- Use `-e` para tentar variações:
	- `n` = tentar login vazio
	- `s` = tentar senha = usuário
	- `r` = tenta senha invertida (`user:resu`)

```bash
hydra -L users.txt -P passwords.txt ftp://10.0.0.1 -e ns -vV
```

---
# Mitigação contra Ataques do Hydra

- **Limite de tentativas de login** (ex: fail2ban no Linux).
- **Autenticação de dois fatores** (2FA).
- **Senhas fortes e únicas** (evitar wordlists comuns).
- **Bloqueio de IP após múltiplas falhas**.

---
# Conclusão

O **Hydra** é uma ferramenta poderosa para testes de força bruta em diversos protocolos. Seu uso deve ser **ético e legal**, aplicado apenas em sistemas com permissão explícita. Pentesters e administradores de rede podem utilizá-lo para **auditar vulnerabilidades** e fortalecer a segurança de sistemas.

>[!warning] Atenção
>O uso não autorizado do Hydra é **ilegal** e pode resultar em consequências criminais. Sempre obtenha permissão antes de testar sistemas.

---
# Referências

[Site Oficial do Hydra](https://github.com/vanhauser-thc/thc-hydra)
[OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

