<!--
title: CVE-2026-31431 — Copy-Fail
desc: Análise técnica detalhada da vulnerabilidade Copy-Fail de 2026, cobrindo causa raiz, impacto e correção.
tags: cve, vulnerability, exploit
readTime: 6 min
-->

<!-- ===================================== -->
<!--         COPY FAIL RESEARCH GUIDE      -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/CVE-2026--31431-black?style=for-the-badge">
  <img src="https://img.shields.io/badge/Linux-Kernel%20LPE-red?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Exploit-Page%20Cache%20Corruption-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Subsystem-AF__ALG-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Impact-Privilege%20Escalation-critical?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Advanced-orange?style=flat-square">
</p>

---

# CVE-2026-31431 — Copy-Fail
## Análise Técnica da Corrupção de Page Cache e Escalonamento Root no Linux

> Algumas vulnerabilidades exigem race conditions complexas, offsets específicos do kernel ou exploits instáveis.
>
> O **Copy-Fail** não.
>
> Uma simples execução em Python, feita por um usuário sem privilégios, é suficiente para adulterar o **Page Cache do kernel Linux** e transformar um processo comum em **root** em segundos.
>
> O mais perigoso:
>
> - Nenhum arquivo no disco é alterado
> - Ferramentas de integridade continuam mostrando hashes válidos
> - O payload existe apenas na memória
>
> Isso transforma o Copy-Fail em uma vulnerabilidade extremamente silenciosa, confiável e difícil de detectar.

---

## 🎯 Objetivo do Documento

Este documento foi desenvolvido para:

- Explicar tecnicamente a vulnerabilidade CVE-2026-31431
- Demonstrar como o exploit manipula o Page Cache do Linux
- Analisar a interação entre `AF_ALG`, `splice()` e `authencesn`
- Entender por que ferramentas de integridade falham contra essa técnica
- Demonstrar a exploração prática do bug
- Identificar estratégias de detecção e mitigação

---

# CVE-2026-31431: Copy-Fail

## Introdução

A maioria das vulnerabilidades de escalonamento de privilégios locais são frágeis. Elas dependem de offsets precisos de versão do kernel, exigem vencer uma condição de corrida de forma confiável ou travam o sistema quando ocorre uma falha de sincronização. **CVE-2026-31431**, apelidado de **Copy Fail**, não se enquadra em nenhuma dessas categorias. Um script Python de **732 bytes**, sem pacotes externos, executado por qualquer usuário local sem privilégios, retorna um shell root em segundos.

A descrição do pesquisador sobre a vulnerabilidade primitiva a define de forma concisa:

> _"Um usuário local sem privilégios pode escrever quatro bytes controlados no cache de páginas de qualquer arquivo legível em um sistema Linux e usar isso para obter acesso root."_

![](https://ametropolesorocabana.com.br/wp-content/uploads/2026/05/copy-1024x430.jpg)
### Status da Vulnerabilidade

|Propriedade|Valor|
|---|---|
|**CVE**|CVE-2026-31431|
|**Pontuação CVSS v3.1**|7.8 (Alta)|
|**Pesquisador**|Taeyang Lee (Theori)|
|**Ferramenta utilizada**|Xint Code (análise de código assistida)|
|**Data da notificação**|23 de março de 2026|
|**Divulgação pública**|29 de abril de 2026|
|**Período de exposição**|9 anos (desde otimização do kernel em 2017 até correção em abril de 2026)|

### Comparação com Dirty Pipe (CVE-2022-0847)

Se você está familiarizado com o exploit **CVE-2022-0847 (Dirty Pipe)** , a classe de primitivas que causa o Copy Fail já lhe será familiar. Ambos os exploits escrevem no cache de páginas em memória de um arquivo sem acessar o conteúdo em disco e, como resultado, ambos **burlam o monitoramento de integridade de arquivos**.

| Propriedade                      | Dirty Pipe (CVE-2022-0847)   | Copy Fail (CVE-2026-31431)                  |
| -------------------------------- | ---------------------------- | ------------------------------------------- |
| Subsistema do kernel             | pipe / splice                | AF_ALG crypto / splice                      |
| Primitiva de escrita             | Arbitrária via pipe flag bug | Controlada (4 bytes) via authencesn scratch |
| Condição de corrida necessária   | Sim (originalmente)          | **Não**                                     |
| Offsets de kernel necessários    | Não                          | Não                                         |
| Arquivo em disco alterado        | Não                          | Não                                         |
| Bypass de integridade de arquivo | Sim                          | Sim                                         |

O **"Não"** na linha da condição de corrida é o que torna o Copy Fail **substancialmente mais confiável** como arma. Um exploit baseado em condição de corrida pode falhar em um quinto das vezes, exigir um loop de repetição ou travar o sistema em uma tentativa malsucedida. A escrita do Copy Fail é **determinística**: ou ela é concluída sem erros ou ocorre um erro sem efeitos colaterais.

Essa confiabilidade impulsionou a rápida instrumentalização observada após a divulgação, com **múltiplas reimplementações públicas surgindo em 24 horas**.

### Objetivos de Aprendizagem

Ao final deste estudo, você será capaz de:

- **Explicar** a primitiva de escrita no cache de páginas que torna o Copy Fail explorável e por que ela ignora o monitoramento de integridade de arquivos
- **Identificar** os quatro componentes do kernel (`page cache`, `AF_ALG`, `authencesn`, `splice`) que se combinam para criar a vulnerabilidade
- **Executar** a prova de conceito como um usuário sem privilégios e obter um shell root
- **Descrever** os principais sinais de detecção e aplicar a mitigação `modprobe` em sistemas Ubuntu e Debian

---
## A Vulnerabilidade

A vulnerabilidade Copy Fail surge da **interação de quatro componentes independentes** do kernel Linux, cada um dos quais se comporta corretamente isoladamente. A vulnerabilidade **não existe em nenhum componente individual**. Ela reside no que acontece quando eles se encontram — especificamente, quando uma otimização de 2017, destinada a tornar um deles mais rápido, falhou ao não considerar um caminho de dados que não havia sido levado em conta na época.

### Visão Geral dos Componentes

| Componente     | Função                                      | Papel na vulnerabilidade                         |
| -------------- | ------------------------------------------- | ------------------------------------------------ |
| **Page Cache** | Armazena cópias de arquivos em memória      | Alvo da escrita; compartilhado entre processos   |
| **AF_ALG**     | Interface de socket criptográfico do kernel | Expõe o subsistema criptográfico ao usuário      |
| **authencesn** | Modelo AEAD para IPsec com ESN              | Realiza escrita temporária de 4 bytes            |
| **splice()**   | Move dados sem cópia (zero-copy)            | Permite referenciar páginas do cache diretamente |

### 1. O Cache de Páginas (Page Cache)

O **cache de páginas** é uma região da memória do kernel que armazena cópias do conteúdo de arquivos lidos recentemente para evitar leituras repetidas do disco.

**Comportamento:**

- Quando qualquer processo lê um arquivo, o kernel o lê do disco **uma única vez** para o cache de páginas
- Cada leitura subsequente desse arquivo por **qualquer processo** é atendida a partir da cópia em cache
- O cache é **compartilhado** entre todos os processos no mesmo sistema (incluindo containers que compartilham o kernel do host)    

**Consequência crítica:**

- A cópia em cache pode ser modificada diretamente **sem que nenhuma alteração seja gravada de volta no disco**    

**Analogia útil:**

Uma fotocopiadora com buffer de impressão interno. O documento original permanece no vidro, mas cada impressão é reproduzida a partir do buffer, não do vidro. Se o buffer for adulterado, **todas as impressões estarão incorretas**, mas a inspeção do documento original no vidro não revela nenhuma anomalia.

**Impacto para monitoramento de integridade:**

Ferramentas como **AIDE, Tripwire e IMA** funcionam calculando o hash do arquivo em disco. Elas leem do disco, não da memória. Se o cache de páginas estiver corrompido, mas o disco intacto:

- ✅ Todas as verificações de integridade serão aprovadas
- ❌ O binário que o kernel carrega quando o arquivo é executado é a **versão corrompida na memória**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/645b19f5d5848d004ab9c9e2-1778047341514.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/645b19f5d5848d004ab9c9e2-1778047341514.svg)

### 2. AF_ALG: O Socket Criptográfico do Kernel

`AF_ALG` (Address Family: Algorithm, número da família de sockets **38**) é uma interface de socket do Linux que expõe o subsistema criptográfico do kernel ao espaço do usuário. Introduzido no kernel 2.6.38, ele permite que programas solicitem operações criptográficas por meio de chamadas de socket padrão (`bind()`, `sendmsg()`, `recvmsg()`).

**Propriedade crítica para o exploit:**

O `AF_ALG` está disponível para **usuários sem privilégios por padrão**. Nenhuma permissão especial (`CAP_SYS_ADMIN`) é necessária.

**Aplicações legítimas que utilizam AF_ALG:**

|Aplicação|Descrição|
|---|---|
|`cryptsetup`|Configuração de volumes criptografados|
|`systemd-cryptsetup`|Integração systemd para criptografia|
|`kcapi-enc`, `kcapi-dgst`, `kcapi-mac`|Ferramentas de benchmark criptográfico|
|`kcapi-speed`|Teste de performance|
|`charon`, `charon-systemd`|Daemons strongSwan para IPsec|

Esta lista é a base para **detecção do uso anômalo** de `AF_ALG`.

### 3. authencesn e a Escrita de Dados Temporária

`authencesn` é um modelo **AEAD** do kernel Linux usado para IPsec com suporte a Número de Sequência Estendido (ESN). Durante uma operação de descriptografia AEAD, o `authencesn` escreve **4 bytes** (os 32 bits menos significativos do ESN, armazenados como `seqno_lo`) no deslocamento `assoclen + cryptlen` dentro do buffer de saída.

**O detalhe crítico: a ordem das operações**

|Ordem|Operação|
|---|---|
|1º|Escrita temporária dos 4 bytes no buffer de saída|
|2º|Verificação da tag HMAC|

Se a verificação HMAC falhar (e no exploit ela é **deliberadamente induzida a falhar**):

- Um erro é retornado ao espaço do usuário
- **A escrita já foi concluída**
- Não há rollback, limpeza do buffer ou mecanismo para desfazer a escrita

> **Ponto de confusão comum:** Uma falha na verificação HMAC **NÃO** implica que toda a operação foi revertida. Os 4 bytes escritos já estão no buffer de saída no momento em que o resultado do HMAC é avaliado.

**Controle do atacante:**

| Aspecto                     | Controle do atacante | Mecanismo                                 |
| --------------------------- | -------------------- | ----------------------------------------- |
| **Valor escrito**           | Sim                  | Parâmetro `seqno_lo` derivado da mensagem |
| **Deslocamento da escrita** | Sim                  | Parâmetros `assoclen` e `cryptlen`        |

### 4. splice() e Referências de Página

`splice()` é uma chamada de sistema do Linux que move dados entre dois descritores de arquivo **transferindo referências de página** em vez de copiar os dados (zero-copy).

**Comportamento normal:**

- `splice()` de um arquivo regular para um socket: o kernel passa uma referência **às mesmas páginas de memória** já utilizadas pelo cache de páginas do arquivo    

**Consequência para o exploit:**

Após um `splice()` de `/usr/bin/su` para um socket `AF_ALG`, o pipeline `AF_ALG` mantém uma **referência às páginas do cache de páginas** que dão suporte a `/usr/bin/su`. Essas páginas **ainda são páginas do cache de páginas pertencentes ao kernel**, não uma cópia controlada pelo usuário.

### 5. A Otimização de 2017 (A Causa Raiz)

**Antes de 2017:**  
O `algif_aead` (implementação do AEAD no subsistema `AF_ALG`) mantinha listas de dispersão (scatter-gather lists) de origem e destino **separadas** para operações criptográficas.

**O commit problemático: `72548b093ee3` (kernel 4.14)**

A otimização **in-place** fundiu as listas e definiu `req->src = req->dst`.

|Cenário|Segurança|
|---|---|
|Dados fornecidos por gravação normal|✅ Seguro (ambos referenciam memória controlada pelo usuário)|
|Dados via `splice()` (páginas do cache)|❌ **Inseguro** - lista de dispersão de "saída" aponta para páginas do cache de páginas do arquivo|

**O que foi negligenciado:** O caminho de dados do `splice()` não foi considerado na época da otimização.

### Primitiva Resultante

A combinação dos quatro componentes produz:

> **Uma escrita controlada de 4 bytes em um deslocamento arbitrário dentro do cache de páginas de qualquer arquivo que o atacante possa abrir para leitura.**

|Controle|Mecanismo|
|---|---|
|**Valor escrito**|`seqno_lo` (através da mensagem construída)|
|**Deslocamento**|Posição de `splice()` + `assoclen` + `cryptlen`|

**Processo do exploit:**

1. O atacante repete essa primitiva aproximadamente **40 vezes**
2. Cada iteração escreve blocos sucessivos de **4 bytes** de shellcode
3. Cada iteração abre um novo socket `AF_ALG`, realiza `splice()` no arquivo alvo no próximo deslocamento e chama `recvmsg()` para acionar a escrita
4. A verificação HMAC falha e retorna erro, mas a **escrita já foi concluída**

**Características do exploit:**

- ✅ **Sem condição de corrida**
- ✅ **Sem tabela de offsets específica da versão do kernel**
- ✅ **Sem dependência de ferramentas externas**

**Kernels afetados:** 4.14 até 6.18.21 (série 6.18) e 6.19.0 até 6.19.11 (série 6.19) — **nove anos de distribuições**

---
## Exploração

A prova de conceito (PoC) tem como alvo `/usr/bin/su`. Ela substitui a cópia em cache desse binário com shellcode, após o qual qualquer execução de `su` executa esse shellcode com **privilégios de root setuid**.

> O exploit completo está disponível em: [GitHub - Copy-Fail-Exploit-CVE-2026-31431](https://github.com/painoob/Copy-Fail-Exploit-CVE-2026-31431)

### Passo 1: Confirme Seu Contexto

Confirme que o usuário atual não tem privilégios elevados:

```bash
karen@ubuntu:~$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)
```

### Passo 2: Inspecione a Prova de Conceito

O script de exploração está em `/home/karen/exploit.py`. Antes de executá-lo, observe sua estrutura de alto nível:

```bash
head -30 /home/karen/exploit.py
```

Este é o contexto inicial que a exploração requer. Sem privilégios elevados, sem grupos especiais, apenas um usuário local comum.

**Dependências:** O script usa apenas módulos da biblioteca padrão Python:

- `os` → `splice()` e `execve()`
- `socket` → chamadas `AF_ALG`
- `zlib` → cálculos de CRC para o blob de chave de autenticação

**Fluxo de execução do exploit:**

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/645b19f5d5848d004ab9c9e2/room-content/645b19f5d5848d004ab9c9e2-1778048131326.svg)

**Etapas:**

| Etapa | Ação                                                                             |
| ----- | -------------------------------------------------------------------------------- |
| 1     | Abre socket `AF_ALG` vinculado a `authencesn(hmac(sha256),cbc(aes))`             |
| 2     | Calcula o deslocamento de destino dentro de `/usr/bin/su`                        |
| 3     | Constrói o AAD para que bytes 4-7 carreguem o valor do shellcode como `seqno_lo` |
| 4     | Chama `splice()` para alimentar páginas do cache de `/usr/bin/su` no socket      |
| 5     | Chama `recvmsg()` para acionar a descriptografia AEAD (escrita de 4 bytes)       |
| 6     | Repete ~40 vezes para escrever todos os blocos de shellcode                      |
| 7     | Chama `os.execve("/usr/bin/su")` → kernel carrega do cache corrompido            |

### Passo 3: Execute a Prova de Conceito

```bash
karen@ubuntu:~$ python3 /home/karen/exploit.py
```

O script imprime o progresso à medida que escreve cada bloco de 4 bytes. Após a conclusão, o prompt muda para **root**:

```bash
# whoami
uid=0(root) gid=0(root) groups=0(root)
```

### Passo 4: Leia a Flag

```bash
root@ubuntu:~# cat /root/flag.txt
THM{xxxxxxxxxxxxxxxxxxxxxxxxxxx}
```

### Passo 5: O Momento `sha256sum`

Ainda no shell root, verifique o hash do binário explorado:

```bash
root@ubuntu:~# sha256sum /usr/bin/su
c4d2e053445c5f89d13b68bb54de8d67358e1aa20a2b8f0688cb8a47a32edbdf  /usr/bin/su
```

Este hash corresponde a um sistema **recém-instalado e não modificado**. Ferramentas como AIDE, Tripwire e IMA relatariam este arquivo como **não modificado**.

> **Por quê?** O exploit modificou **apenas a cópia em cache** na memória. O binário no disco nunca foi escrito. Ferramentas de integridade leem do disco, calculam o hash do disco e comparam com uma baseline do disco. **Nada disso toca o cache de páginas.**

**Propriedade central:** A corrupção usada para ganhar root é **invisível para cada verificação de integridade baseada em sistema de arquivos**.

> **Nota:** Copy Fail não é o primeiro exploit a ignorar monitoramento de integridade dessa forma. Dirty Pipe (CVE-2022-0847) tinha a mesma propriedade. O que distingue o Copy Fail é a **confiabilidade** — a ausência de condição de corrida significa que o atacante pode executá-lo uma vez e esperar que funcione.

### Passo 6: Saia do Shell Root

```bash
exit
```

**Mecanismo de limpeza:** O PoC chama `posix_fadvise(POSIX_FADV_DONTNEED)` sobre `/usr/bin/su`, sugerindo ao kernel que essas páginas não são mais necessárias. O kernel as **despeja do cache de páginas**. Na próxima leitura, o kernel recarrega o binário original e limpo do disco.

**Para o defensor:** Isso significa que a **janela de exploração é extremamente estreita** — medida em segundos. No momento em que um alerta baseado em sistema de arquivos dispara, o cache de páginas já mostra o binário original.

----
## Detecção e Remediação

### Desafios da Detecção

|Desafio|Descrição|
|---|---|
|**Arquivo em disco nunca é modificado**|Ferramentas de integridade de arquivo não detectam|
|**Cache de página é limpo rapidamente**|`posix_fadvise(DONTNEED)` despeja as páginas|
|**Bibliotecas padrão**|Chamadas se misturam com atividade normal|

**O que permanece detectável:** O **comportamento do processo** — especificamente a sequência de chamadas de sistema que nenhum aplicativo legítimo produz.

### Detecção

#### Sinal Primário: Criação de Socket AF_ALG

O exploit chama `socket(AF_ALG, SOCK_SEQPACKET, 0)` aproximadamente **40 vezes** em rápida sucessão.

**Detalhe crítico para precisão da detecção:**

|Tipo de socket|Uso comum|Fidelidade para detecção|
|---|---|---|
|`SOCK_DGRAM`|Hash e criptografia simétrica|Baixa (ruído de fundo)|
|`SOCK_SEQPACKET`|Operações AEAD|**Alta** (muito menos comum)|

**Lista de processos legítimos que abrem sockets AEAD:**

```text
cryptsetup, systemd-cryptsetup, kcapi-enc, kcapi-dgst, kcapi-mac, 
kcapi-speed, bluez, iwd, charon, charon-systemd
```

> **Qualquer processo fora desta lista** criando um socket `AF_ALG` com `SOCK_SEQPACKET` é incomum. Um processo criando **40 ou mais** desses sockets em segundos é quase certamente o exploit.

#### Principais Syscalls para Monitorar

|Syscall|O que observar|Relevância|
|---|---|---|
|`socket(AF_ALG, ...)`|Qualquer processo fora da lista de permissões|Sinal primário (dispara antes da corrupção)|
|`splice()`|Emenda de FD binário setuid em socket FD|Páginas do cache entram no pipeline criptográfico|
|`recvmsg()` (AF_ALG)|~40 chamadas em segundos do mesmo PID|Cada chamada escreve 4 bytes de shellcode|
|`posix_fadvise(DONTNEED)`|Chamado em binário setuid logo após atividade AF_ALG|Limpeza do atacante|

#### Regras Auditd

O socket `AF_ALG` usa valor de domínio **38**:

```text
-a always,exit -F arch=b64 -S socket -F a0=38 -k copy_fail_af_alg
-a always,exit -F arch=b64 -S splice -k copy_fail_splice
```

#### Esboço de Regra Falco

```bash
- macro: expected_af_alg_processes
  condition: >
    proc.name in (kcapi-enc, kcapi-dgst, kcapi-mac, cryptsetup,
                  kcapi-speed, charon, charon-systemd)

- rule: Potential Copy Fail Exploit (AF_ALG Socket Creation)
  desc: >
    Detects AF_ALG socket creation (family 38) by unexpected processes.
    Primary vector for CVE-2026-31431 (Copy Fail) LPE.
  condition: >
    evt.type = socket and
    evt.arg.domain = AF_ALG and
    evt.res >= 0 and
    not expected_af_alg_processes
  output: >
    Anomalous AF_ALG socket created
    (user=%user.name uid=%user.loginuid command=%proc.cmdline
     pid=%proc.pid container_id=%container.id image=%container.image.repository)
  priority: CRITICAL
  tags: [host, container, exploit, privilege_escalation, cve_2026_31431]
```

**Observação importante:** A regra dispara no **primeiro** `socket()` de qualquer processo não autorizado. Neste ponto, **nenhuma corrupção de cache ocorreu ainda**.

#### Correlação de Alta Confiança

Um IDS ou SIEM que correlaciona:

- Múltiplos alertas `AF_ALG` do mesmo PID
- Seguido por `execve()` de um binário setuid
- Na mesma janela de tempo curta

Tem um **indicador de cadeia de exploração de alta confiança**.

#### MITRE ATT&CK Mapeamento

| Técnica                                           | MITRE ID  | Sinal Primário                                            |
| ------------------------------------------------- | --------- | --------------------------------------------------------- |
| Escalação de Privilégio Local via falha do kernel | T1068     | Criação de socket AF_ALG por processo inesperado          |
| Fuga para o host do container                     | T1611     | ID do container no alerta + subsequente atividade no host |
| Abuso de binário setuid                           | T1548.001 | `execve` de binário setuid após atividade AF_ALG          |
| Remoção de Indicador via despejo de página        | T1070     | `posix_fadvise(DONTNEED)` chamado em binário setuid       |

### Remediação

A vulnerabilidade está no módulo `algif_aead`. Desativá-lo remove a capacidade do exploit de abrir socket `AF_ALG` vinculado a `authencesn`.

#### Correção Permanente

Atualização do kernel para:

- **6.18.22** ou superior (série 6.18)
- **6.19.12** ou superior (série 6.19)
- **7.0** ou superior

O patch foi incorporado à linha principal como commit `a664bf3d603d` em 1º de abril de 2026.

#### Mitigação Temporária: modprobe (Ubuntu/Debian)

**Passo 1: Verifique se o módulo é carregável**

```bash
modinfo algif_aead
```

**Passo 2: Aplique a lista negra**

```bash
echo "install algif_aead /bin/false" | sudo tee /etc/modprobe.d/disable-algif-aead.conf
sudo rmmod algif_aead 2>/dev/null || true
```

**Passo 3: Verifique o bloqueio**

```bash
sudo modprobe algif_aead
# Deve retornar erro
```

**Passo 4: Confirme que o PoC falha**

```bash
python3 /home/karen/exploit.py
# Deve falhar no primeiro passo
```

#### Mitigação para RHEL/CentOS/AlmaLinux

Nestas distribuições, `algif_aead` é **compilado diretamente no kernel** (`CONFIG_CRYPTO_USER_API_AEAD=y`). O arquivo `modprobe` é ignorado.

**Abordagem grubby:**

```bash
sudo grubby --update-kernel=ALL --args="initcall_blacklist=algif_aead_init"
sudo reboot
```

**Verificação:**

```bash
sudo grubby --info=ALL | grep initcall_blacklist
```

**Reverter (após patch do kernel):**

```bash
sudo grubby --update-kernel=ALL --remove-args="initcall_blacklist=algif_aead_init"
```

### Status de Patch na Divulgação (29 de abril de 2026)

|Distribuição|Status no dia da divulgação|
|---|---|
|**AlmaLinux**|Primeiro a lançar kernel corrigido (1º de maio de 2026)|
|Ubuntu, Debian|Seguiram nos dias e semanas seguintes|
|RHEL, SUSE|Seguiram nos dias e semanas seguintes|

---
## Conclusão

### Principais Takeaways

1. **O cache de páginas do Linux é infraestrutura compartilhada**
    - Uma escrita de um processo afeta **todos os processos** que compartilham o mesmo kernel
    - Inclui containers que parecem isolados por namespace — o isolamento não se estende ao cache de páginas

2. **Exploit sem condição de corrida = baixo risco operacional**    
    - Reimplementações públicas surgiram em **C, Rust, Go e arm64** dentro de dias
    - Armas confiáveis são usadas rapidamente, não gradualmente

3. **Ferramentas de integridade de arquivo são insuficientes**
    - Elas fazem hash do disco; este exploit escreve na **memória**
    - Para esta classe de vulnerabilidade, a detecção requer **monitoramento de nível syscall**

4. **A janela de detecção é extremamente curta**    
    - `posix_fadvise(DONTNEED)` despeja as páginas corrompidas
    - No momento da resposta, o cache está limpo e o disco está limpo
    - Nada para encontrar em uma análise post-mortem tradicional

### Recomendações para Defensores

|Ação|Prioridade|Descrição|
|---|---|---|
|Atualizar kernel|**Alta**|Para 6.18.22+, 6.19.12+ ou 7.0+|
|Aplicar lista negra `modprobe`|**Média**|Mitigação temporária (Ubuntu/Debian)|
|Implementar monitoramento de syscall|**Média**|`auditd` rules ou Falco para `socket(AF_ALG)`|
|Revisar lista de processos legítimos|**Baixa**|Documentar usos autorizados de AF_ALG|

> **Lembrete:** O `modprobe` blacklist é um **controle provisório eficaz** no Ubuntu e Debian, mas **não é um substituto para o patch**. A correção permanente é a atualização do kernel.

----
## Referências

1. Lee, T. (2026). _Copy Fail: Four bytes to root_. Xint Research Blog. [https://xint.io/blog/copy-fail-linux-distributions](https://xint.io/blog/copy-fail-linux-distributions)
2. The Linux Kernel Archives. (2026). *Commit a664bf3d603d: algif_aead: fix in-place crypto for splice() paths*. [kernel.org](https://kernel.org)
3. MITRE Corporation. (2026). *CVE-2026-31431*. National Vulnerability Database. [https://nvd.nist.gov/vuln/detail/CVE-2026-31431](https://nvd.nist.gov/vuln/detail/CVE-2026-31431)
4. MITRE ATT&CK®. (2026). _Techniques_. Enterprise Matrix. [https://attack.mitre.org/techniques/](https://attack.mitre.org/techniques/)
    - T1068: Exploitation for Privilege Escalation
    - T1548.001: Setuid and Setgid (Abuse Elevation Control Mechanism)
    - T1611: Escape to Host
    - T1070: Indicator Removal (File Deletion)

5. TryHackMe. (2026). *CVE-2026-31431: Copy-Fail* [Interactive lab]. [https://tryhackme.com/room/cve202631341](https://tryhackme.com/room/cve202631341)
6. Docker, Inc. (2026). _Falco Runtime Security_. [https://falco.org/docs/rules/](https://falco.org/docs/rules/)
7. Linux Audit Project. (2026). *auditd(8) - Linux manual page*. [man7.org](https://man7.org)
8. Corbet, J. (2017, November 13). _The 4.14 kernel is released_. [LWN.net](https://LWN.net). [https://lwn.net/Articles/737902/](https://lwn.net/Articles/737902/) (Contexto sobre o commit 72548b093ee3 – otimização in-place no algif_aead)
9. Google Cloud Threat Intelligence. (2024, January 30). _UNC4990 Evolution: Uncovering the Hidden Depths of USB Malware_. Google Cloud Blog. (Contexto sobre ataques via dispositivos USB, mencionado na introdução do seu documento original)
10. Falco Project. (2026). _Falco Rules Reference_. [https://falco.org/docs/rules/supported-fields/](https://falco.org/docs/rules/supported-fields/)
