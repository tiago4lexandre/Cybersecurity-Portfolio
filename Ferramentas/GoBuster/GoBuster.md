<!--
title: Gobuster
desc: Fuzzing de diretórios, subdomínios e DNS em servidores web utilizando a ferramenta Gobuster escrita em Go.
tags: tools, gobuster, recon
readTime: 4 min
-->

<!-- ===================================== -->
<!--     Web Enumeration with Gobuster     -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Topic-Web%20Enumeration-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Attack-Reconnaissance-red?style=flat-square">
  <img src="https://img.shields.io/badge/Web-HTTP%2FHTTPS-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Tool-Gobuster-black?style=flat-square">
  <img src="https://img.shields.io/badge/Phase-Information%20Gathering-informational?style=flat-square">
</p>

---

# 🌐 Web Enumeration com Gobuster

> Documentação técnica e prática sobre **enumeração ativa em aplicações web**, utilizando a ferramenta **Gobuster** para descoberta de **diretórios, arquivos sensíveis, subdomínios e virtual hosts**, etapa fundamental durante a fase de **reconhecimento (Recon)** em testes de penetração.

---

### 📌 Metadados

- **Data:** 2025-07-22  
- **Status:** `#developed`  
- **Categoria:** Web Security · Reconnaissance · Enumeration  
- **Ferramentas:** Gobuster · SecLists · Linux CLI  
- **Ambiente:** Linux · Web Applications · CTF Labs  

---

### 🏷️ Tags

`#CyberSecurity` `#WebSecurity` `#Reconnaissance` `#Enumeration`  
`#Gobuster` `#DirBruteForce` `#DNSBruteForce`  
`#Pentest` `#RedTeam`

---

# Introdução

**Gobuster** é uma ferramenta de linha de comando (CLI) escrita em Go, utilizada para **enumeração de diretórios, arquivos, subdomínios e DNS** em servidores web.

É uma alternativa mais rápida e eficiente ao **Dirb** ou **Dirbuster**, sendo amplamente utilizada em testes de penetração e auditorias de segurança.

![[Pasted image 20250722212549.png]]

----
# Principais Recursos

- **Enumeração de diretórios e arquivos** (via brute-force)
- **Busca de subdomínios** (DNS brute-force)
- **Suporte a múltiplos protocolos** (HTTP, HTTPS, FTP)
- **Opções de filtragem por status code, tamanho de resposta, etc.**
- **Alta velocidade devido à concorrência em Go**

---
# Instalação do Gobuster

## 1. Instalação no Linux (Debian/Ubuntu/Kali)

```sh
sudo apt update
sudo apt install gobuster
```

## 2. Instalação via Go (se não estiver nos repositórios)

```sh
go install github.com/OJ/gobuster/V3@latest
```

## 3. Instalação no Windows (via Chocolatey)

```sh
choco install gobuster
```

## 4. Verificação da instalação

```sh
gobuster --version
```

- Saída esperada: `Gobuster v3.x`

---
# Modos de Uso do Gobuster

O Gobuster possui três modos principais:

| **Modo** | **Comando**      | **Descrição**                     |
| -------- | ---------------- | --------------------------------- |
| dir      | `gobuster dir`   | Enumeração de diretórios/arquivos |
| dns      | `gobuster dns`   | Enumeração de subdomínios         |
| vhost    | `gobuster vhost` | Busca de hosts virtuais           |

---
# Enumeração de Diretórios (`dir` mode)

## 1. Sintaxe Básica

```sh
gobuster dir -u http://alvo.com -w /caminho/worlist.txt
```

## 2. Parâmetros Comuns

| **Parâmetro** | **Descrição**           | **Exemplo**                              |
| ------------- | ----------------------- | ---------------------------------------- |
| `-u`          | URL alvo                | `-u http://10.0.0.1`                     |
| `-w`          | Wordlist                | `-w /usr/share/worlists/dirb/common.txt` |
| `-x`          | Extensões a procurar    | `-x php,html,txt`                        |
| `-t`          | Threads (padrão: 10)    | `-t 50`                                  |
| `-o`          | Salvar saída em arquivo | `-o resultado.txt`                       |
| `-k`          | Ignorar certificado SSL | `-k`                                     |
| `-s`          | Status codes válidos    | `-s 200,204,301`                         |
| `-b`          | Blacklist de status     | `-b 404,403`                             |

## 3. Exemplo Prático

```sh
gobuster dir -u http://alvo.com -w /usr/share/worldlists/dirb/common.txt -x php, html -t 30 -o scan.txt
```

![[Pasted image 20250603063802.png]]

**Saída:**

```
/admin                (Status: 301)  
/login.php            (Status: 200)  
/backup.zip           (Status: 200)  
```

![[Pasted image 20250603063821.png]]

---
# Enumeração de Subdomínios (`dns` mode)

## 1. Sintaxe Básica

```sh
gobuster dns -d alvo.com -w subdomains-wordlist.txt
```

## 2. Parâmetros Comuns

| **Parâmetro** | **Descrição**           |
| ------------- | ----------------------- |
| `-d`          | Domínio alvo            |
| `-w`          | Wordlist de subdomínios |
| `-t`          | Threads                 |
| `-i`          | Mostrar IPs encontrados |

## 3. Exemplo Prático

```sh
gobuster dns -d alvo.com -w /usr/share/wordlists/subdomains-top1.mtxt -t 50 -i
```

**Saída:**

```
Found: admin.alvo.com (IP: 10.0.0.1)  
Found: dev.alvo.com (IP: 10.0.0.2)  
```

---
# Busca de Virtual Hosts (`vhost` mode)

Útil para descobrir hosts virtuais em um mesmo IP.

## 1. Sintaxe Básica

```sh
gobuster vhost -u http://alvo.com -w worldlist.txt
```

## 2. Exemplo Prático

```sh
gobuster vhost -u http://10.0.0.1 -w /usr/share/wordlists/vhosts.txt -t 30
```

**Saída:**

```
Found: internal.alvo.com (Status: 200)  
```

---
# Wordlists Recomendadas

- **Diretórios/Arquivos:**
    - `/usr/share/wordlists/dirb/common.txt`
    - `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`

- **Subdomínios:**
    - `/usr/share/wordlists/subdomains-top1m.txt`
    - `https://github.com/danielmiessler/SecLists`

---
# Dicas Avançadas

✅ **Use `-k` para ignorar erros de SSL**  
✅ **Combine com `-s 200,301,302` para filtrar resultados**  
✅ **Aumente threads (`-t 100`) para maior velocidade**  
✅ **Use `-q` para modo silencioso (apenas resultados)**

---

# Conclusão

O **Gobuster** é uma ferramenta essencial para pentesters e red teams, permitindo enumeração rápida de diretórios, subdomínios e vhosts.

**Próximos passos:**  
🔹 Testar em máquinas CTF (TryHackMe, Hack The Box)  
🔹 Automatizar com scripts Bash/Python  
🔹 Explorar outras ferramentas como **Dirsearch** e **FFuF**
