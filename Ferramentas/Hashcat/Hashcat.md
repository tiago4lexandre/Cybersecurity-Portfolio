<!--
title: Hashcat
desc: Quebra de hashes de senhas acelerada por GPU utilizando as regras e ataques de dicionário do Hashcat.
tags: tools, hashcat, cracking, passwords
readTime: 7 min
-->

<!-- ===================================== -->
<!--         Password Cracking Guide       -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Tool-Hashcat-black?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Category-Password%20Auditing-critical?style=flat-square">
  <img src="https://img.shields.io/badge/Hardware-GPU%20Accelerated-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Red%20Team-red?style=flat-square">
  <img src="https://img.shields.io/badge/Environment-Linux%20%7C%20Windows-informational?style=flat-square">
</p>

---

# 🔐 Hashcat — Guia Completo de Password Cracking

> Documento técnico voltado para **auditoria de senhas, recuperação de credenciais e testes de robustez criptográfica**, utilizando o Hashcat como principal ferramenta.
>
> Este material cobre desde **instalação e configuração**, passando por **identificação de hashes**, até **ataques avançados com regras, máscaras e otimização por GPU**.
>
> O objetivo é fornecer uma abordagem **metodológica, prática e orientada a performance**, adequada para **Pentest, Red Team, CTFs e perícia digital**.

---

## 📌 Metadados

- **Categoria:** Password Auditing · Offensive Security · Cryptography  
- **Escopo:** Hash Cracking · Wordlists · Mask Attack · Rule-Based Attack  
- **Hardware:** CPU · GPU (NVIDIA CUDA / AMD ROCm)  
- **Ambiente:** Kali Linux · Ubuntu · Laboratórios Controlados  

---

## 🏷️ Tags

`#Hashcat` `#PasswordCracking` `#Cryptography`  
`#RedTeam` `#Pentest` `#GPU` `#Wordlists`  
`#BruteForce` `#MaskAttack` `#Rules`

---

## ⚠️ Aviso Legal

> O uso do Hashcat para quebrar hashes sem autorização explícita é **ilegal**.  
> Este guia destina-se exclusivamente a **ambientes autorizados, auditorias de segurança e fins educacionais**.
>
> Utilize apenas em sistemas próprios ou com permissão formal do responsável.

---
# HashCat

## 1. Introdução

O **Hashcat** é autoproclamado a ferramenta de recuperação de senhas mais avançada e rápida do mundo. Diferente de ferramentas tradicionais que usam apenas a CPU, o Hashcat é projetado para aproveitar o poder massivo de processamento paralelo das **GPUs (Unidades de Processamento Gráfico)** , como as da NVIDIA e AMD, além de CPUs e outros aceleradores de hardware. Isso o torna incrivelmente eficiente para realizar ataques de força bruta e dicionário contra mais de **300 algoritmos de hash altamente otimizados**.

**Casos de Uso Éticos e Legais:**

- **Testes de Penetração:** Avaliar a força das políticas de senhas em uma organização.
- **Perícia Digital (Forense):** Recuperar credenciais de sistemas comprometidos para investigação.
- **CTF (Capture The Flag):** Resolver desafios de segurança que envolvem a quebra de hashes).
- **Recuperação de Dados:** Recuperar o acesso a seus próprios sistemas ou arquivos protegidos por senha.


> **⚠️ AVISO LEGAL:** O uso do Hashcat para quebrar hashes sem autorização explícita é **ilegal**. Este guia é para fins educacionais e de testes de segurança autorizados. Utilize-o apenas em sistemas seus ou com permissão por escrito do proprietário.

![Hashcat](https://media.licdn.com/dms/image/v2/D4D12AQG05slsufo3sQ/article-cover_image-shrink_600_2000/B4DZYoOJlZGwAQ-/0/1744431520679?e=2147483647&v=beta&t=h3wrTgIaAepwvNSiPexO2oCrb7l1MopbnkUVZaa_qbY)

---
## 2. Instalação e Primeiros Passos

### 2.1. Instalação no Linux (Kali/Ubuntu/Debian)

O Hashcat está amplamente disponível nos repositórios das principais distribuições Linux.

```bash
# Atualize os repositórios
sudo apt update

# Instale o hashcat
sudo apt install hashcat -y

# Verifique a instalação
hashcat --version
```

No Kali Linux, ele geralmente já vem pré-instalado.

### 2.2. Verificando o Hardware (GPUs)

Para garantir que o Hashcat está utilizando sua GPU, use o comando `-I` (info). Isso é crucial, pois o desempenho da GPU é ordens de magnitude superior ao da CPU para a maioria dos algoritmos.

```bash
hascat -I
```

A saída deve listar suas plataformas OpenCL e dispositivos (CPUs e GPUs). Se sua GPU não aparecer, pode ser necessário instalar drivers proprietários (NVIDIA CUDA / AMD ROCm).

## 3. Anatomia de um Comando Hashcat

A sintaxe fundamental de um comando Hashcat é:

```bash
hashcat [opções]... [hash|arquivo_hash] [dicionário|mascara|diretorio]...
```

Os parâmetros mais críticos são `-m` (tipo de hash) e `-a` (modo de ataque).

### 3.1 Opções Essenciais

| **Opção Curta** | **Opção Longa**             | **Descrição**                                                                     | **Exemplo**                   |
| --------------- | --------------------------- | --------------------------------------------------------------------------------- | ----------------------------- |
| `-m`            | `--hash-type`               | Código numérico do tipo de hash.                                                  | `-m 0` (para MD5)             |
| `-a`            | `--attack-mode`             | Modo de ataque.                                                                   | `-a 0` (ataque de dicionário) |
| `-o`            | `--output`                  | Arquivo para salvar as senhas encontradas.                                        | `-o cracked.txt`              |
| `--show`        | `--show`                    | Mostra as senhas já quebras (do potfile).                                         | `--show`                      |
| `-O`            | `--optimazed-kernal-enable` | Habilita kernels otimizados (mais rápido, mas limitam o tamanho máximo da senha). | `-O`                          |
| `-w`            | `--workload-profile`        | Perfil de carga de trabalho (de 1 a 4, sendo 4 o máximo desempenho).              | `-w 3`                        |
| `-r`            | `--rules-file`              | Arquivo de regras para mangle de palavras.                                        | `-r best64.rule`              |
| `--force`       | `--force`                   | Ignora avisos (útil em ambientes virtuais, mas pode reduzir performance).         | `--force`                     |
| `--session`     | `--session`                 | Nomeia uma sessão para poder pausar e restaurar depois.                           | `--session meuscan`           |
| `--restore`     | `--restore`                 | Restaura uma sessão salva.                                                        | `--restore --session meuscan` |

----
## 4. Fase 1: Identificando o Tipo do Hash (Obtendo o `-m`)

Antes de quebrar, você precisa saber qual algoritmo gerou o hash. Usar o modo errado (`-m`) resultará em falha.

### 4.1. Identificação Manual

Muitas vezes, o tamanho e o formato do hash entregam pistas.

| **Comprimento** | **Exemplo de Hash**                                                | **Provável Tipo** | **Modo Hashcat (`-m`)** |
| --------------- | ------------------------------------------------------------------ | ----------------- | ----------------------- |
| 32 caracteres   | `5f4dcc3b5aa765d61d8327deb882cf99`                                 | MD5               | `0`                     |
| 40 caracteres   | `b7a875fc1ea228b9061041b7cec4bd3c52ab3ce3`                         | SHA-1             | `100`                   |
| 64 caracteres   | `8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918` | SHA-256           | `1400`                  |

### 4.2. Usando Ferramentas Auxiliares (hashid)

Ferramentas como `hashid` ou `hash-identifier` automatizam esse processo.

```bash
# Instale o hashid (se não tiver)
sudo apt install hashid -y

# Identifique um hash
hashid -m '$1$uOM6WNc4$r3ZGeSB11q6UUSILqek3J1'
```

A saída mostrará o tipo (ex: md5crypt) e, com a flag `-m`, o provável modo para o Hashcat (`-m 500`).

### 4.3. Consultando o Help do Hashcat

Você pode buscar diretamente no manual do Hashcat.

```bash
# Lista todos os modos (use | grep para filtrar)
hashcat --help | grep -i "ntlm"
```

Isso mostrará que o modo para NTLM é o `1000`.

---
## 5. Fase 2: Principais Modos de Ataque (`-a`)

O Hashcat oferece diversos modos de ataque para cobrir diferentes cenários.

### 5.1. Ataque de Dicionário (`-a 0`)

É o ataque mais comum. Ele percorre cada linha de um ou mais arquivos de wordlist (lista de palavras).

```bash
# Sintaxe básica
hashcat -m <modo> -a 0 hash.txt wordlist.txt

# Exemplo prático: Quebrar MD5 com rockyou.txt
hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Wordlists Famosas:**

- `rockyou.txt`: A mais famosa, extraída de uma breach da empresa RockYou.
- `SecLists`: Uma coleção massiva de listas para diversas finalidades.

### 5.2. Ataque de Força Bruta / Mask Attack (`-a 3`)

Tenta **todas as combinações possíveis** de caracteres dentro de um espaço definido. É útil quando não se sabe nada sobre a senha, mas é computacionalmente caro. Para otimizar, usamos **Máscaras**.

**Conjuntos de Caracteres (Charsets) Predefinidos:**

- `?l` = letras minúsculas (a-z)
- `?u` = letras maiúsculas (A-Z)
- `?d` = dígitos (0-9)
- `?s` = caracteres especiais (!@#$% etc.)
- `?a` = todos os anteriores (`?l?u?d?s`)
- `?b` = binário (0x00 - 0xff)

**Exemplos:**

```bash
# Força bruta para senha de 4 dígitos (de 0000 a 9999)
hashcat -m 0 -a 3 hash.txt ?d?d?d?d

# Força bruta para senha de 8 caracteres (letras min e maiúsculas + dígitos)
hashcat -m 0 -a 3 hash.txt ?a?a?a?a?a?a?a?a

# Ataque de máscara com parte conhecida: "Flamengo" + 2 dígitos (ex: Flamengo01)
hashcat -m 0 -a 3 hash.txt Flamengo?d?d
```

### 5.3. Ataque Híbrido (`-a 6` e `-a 7`)

Combina wordlist + máscara (híbrido) ou máscara + wordlist. Reflete como muitos usuários criam senhas: uma palavra base seguida de números ou símbolos.

- **Modo `-a 6` (Wordlist + Mask):** Adiciona a máscara ao final de cada palavra da lista.
- **Modo `-a 7` (Mask + Wordlist):** Adiciona a máscara ao início de cada palavra.

```bash
# Exemplo: Procurar por palavras do rockyou.txt seguidas de 2 dígitos (ex: password99)
hashcat -m 0 -a 6 hash.txt rockyou.txt ?d?d
```


### 5.4. Ataque de Combinação (`-a 1`)

Combina palavras de duas wordlists diferentes (list1 + list2).

```bash
hashcat -m 0 -a 1 hash.txt list1.txt list2.txt
```

### 5.5. Ataque Baseado em Regras

É uma das técnicas mais poderosas. As **regras** "manglam" as palavras da wordlist, aplicando modificações como adicionar números no final, trocar letras por símbolos (leet), capitalizar letras, etc., sem a necessidade de ter essas variações no arquivo.

```bash
# Usando a regra best64.rule
hashcat -m 0 -a 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Exemplo de Funcionamento de uma Regra:**

- Palavra original: `senha`
- Regra: `c` (capitaliza primeira letra) + `$1 $2 $3` (adiciona "123" no final)
- Senha testada: `Senha123`

O Hashcat já vem com diversas regras em seu diretório `rules/` (ex: `best64.rule`, `d3ad0ne.rule`, `rockyou-30000.rule`).

---
## 6. Exemplos Práticos Detalhados

### 6.1. Cenário 1: Quebra de MD5 (Modo Mais Simples)

**Arquivo `hashes.txt`:**

```text
5f4dcc3b5aa765d61d8327deb882cf99
```

**Comando:**

```bash
hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Explicação:** `-m 0` para MD5, `-a 0` para ataque de dicionário. Se a senha for "password", ela será encontrada e exibida.

### 6.2. Cenário 2: Quebra de NTLM (Active Directory)

**Hash NTLM (modo 1000):**

```text
b4b9b02e6f09a9bd760f388b67351e2b
```

**Comando com Otimização:**

```bash
hashcat -m 1000 -a 0 -O -w 3 hashes.txt rockyou.txt
```

**Explicação:** Usamos `-O` (kernel otimizado) e `-w 3` (alta performance) para maximizar a velocidade, já que NTLM é um hash rápido.

### 6.3. Cenário 3: Quebra de SHA256 com Regras

**Hash SHA256 (modo 1400):**

```text
f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2
```

**Comando:**

```bash
hashcat -m 1400 -a 0 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

**Explicação:** Se a senha for uma variação de uma palavra comum (ex: "Princesa@1"), o ataque de dicionário puro falharia, mas o ataque com regras provavelmente teria sucesso.

### 6.4. Cenário 4: Quebra de Hash com Sal (`SHA256(Salt.Pass)`)

Hashes com "sal" (salt) são mais complexos. É crucial usar o modo correto e o formato adequado (`hash:salt` ou `salt:hash`). Supondo um hash no formato `sha256(pass.salt)`.  

**Arquivo `hash_salt.txt` (formato `hash:salt`):**

```text
f8058e53de0c05da0c1ac6d04c0cac6b9eb36378ff0fbe4eac3ed5b25fcc11f7:mysalt123
```

**Comando (usando modo 1420 - sha256`($salt.$pass)`):**

```bash
hashcat -m 1420 -a 0 hash_salt.txt rockyou.txt
```

---
## 7. Gerenciamento e Otimização

### 7.1. Benchmark

Teste a velocidade da sua máquina para diferentes tipos de hash sem precisar de um hash de exemplo.

```bash
# Benchmark de todos os hashes
hashcat -b

# Benchmark apenas para um modo específico
hashcat -b -m 2500
```

### 7.2. Sessões (Pausar/Retomar)

Para ataques que podem levar dias, as sessões são essenciais.

```bash
# Iniciar uma sessão chamada "ataque1"
hashcat -m 0 -a 0 hashes.txt rockyou.txt --session ataque1

# Para pausar: Ctrl+C
# Para restaurar:
hashcat --restore --session ataque1
```

### 7.3. O Potfile (Arquivo de Resultados)

Por padrão, todas as senhas quebradas são armazenadas em `~/.hashcat/hashcat.potfile`. Para ver as senhas já quebradas de um arquivo de hashes, use:

```bash
hashcat -m 0 --show hashes.txt
```

### 7.4. Aumentando a Performance

- **Use GPUs:** Prefira máquinas com GPUs dedicadas.
- **`-O` (Optimized Kernels):** Sempre que possível, use esta flag, mas lembre-se que ela pode limitar o tamanho máximo da senha testada.
- **`-w` (Workload):** Use `-w 3` ou `-w 4` se sua máquina estiver dedicada apenas ao cracking.
- **Evite o `--force`:** Usar `--force` ignora verificações de compatibilidade e pode resultar em performance extremamente baixa, especialmente em máquinas virtuais.

---
## 8. Conclusão

O Hashcat é uma ferramenta indispensável no arsenal de um profissional de segurança. Sua eficiência vem da combinação de três fatores: **identificação correta do hash (`-m`)** , **escolha do ataque adequado (`-a`)** e **otimização do hardware (`-O`, `-w`)** .

---
## Referências 

- Documentação Oficial: [hashcat.net/wiki/](https://hashcat.net/wiki/)
- Lista de Exemplos de Hashes: [hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
