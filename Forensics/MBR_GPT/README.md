# 🔍 Análise de MBR e GPT

> _"Antes mesmo do sistema operacional existir, já existe um ponto de confiança — ou de comprometimento."_  

## 🧠 Visão Geral

Toda interação com um sistema computacional começa muito antes da interface gráfica, dos arquivos ou até mesmo do login do usuário. Existe uma camada invisível, crítica e frequentemente negligenciada: **a estrutura de inicialização do disco**.

É nesse nível que residem dois componentes fundamentais:

- **MBR (Master Boot Record)**
- **GPT (GUID Partition Table)**

Eles não apenas organizam o armazenamento — eles **definem como o sistema nasce**.

---

## ⚠️ Perspectiva de Segurança

Por operar em um nível tão baixo, o MBR/GPT se torna um dos pontos mais sensíveis do sistema:

- Executado **antes do sistema operacional**
- Fora do alcance de muitas ferramentas de segurança
- Ideal para persistência avançada de ameaças

Isso os torna alvos clássicos de:

- **Bootkits**
- **Ransomware de baixo nível**
- **Ataques de corrupção estrutural**

---
# Análise de MBR e GPT

## Introdução

Imagine seu disco rígido como um grande prédio que armazena todos os seus dados. Esses dados são guardados em formato binário (0s e 1s) para que os computadores possam entendê-los. Sem uma organização adequada, esses dados se tornariam uma bagunça completa no disco.

Para resolver esse problema, o disco é dividido em **múltiplas partições** — como cômodos em um prédio — onde cada partição contém dados específicos:

- Arquivos do sistema operacional em uma partição
- Arquivos pessoais em outra
- E assim por diante

No Windows, essas partições são representadas por letras de unidade (C:, D:, E:). Outros sistemas operacionais podem usar diferentes formas de referenciar essas partições.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110541741.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110541741.svg)

A divisão em partições resolve o problema de organização dos dados. No entanto, o computador ainda precisa de um **mapa** que o ajude a navegar por essas partições, indicando:

- Onde cada partição começa e termina
- O que cada partição contém

**MBR (Master Boot Record)** e **GPT (GUID Partition Table)** são esquemas de particionamento que funcionam como esse mapa. Ambos estão localizados no primeiro setor do disco e contêm informações sobre a estrutura e as partições do disco. Eles também desempenham um papel fundamental durante o processo de inicialização do sistema.

Devido a essa importância, o MBR/GPT tornou-se um alvo atraente para atacantes que buscam:

- Manipular o processo de inicialização com malwares (Bootkits)
- Adulterar o mapa para tornar o sistema não inicializável

---
## Processo de Inicialização

O processo de inicialização ativa todo o sistema, desde os componentes de hardware até a interface do usuário. O fluxograma abaixo ilustra as etapas principais:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666165.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666165.svg)

### 1. Ligando o Sistema

Ao pressionar o botão liga/desliga, sinais elétricos são enviados para a placa-mãe, inicializando todos os componentes. O CPU é o primeiro componente a receber esses sinais e precisa de instruções para prosseguir.

O CPU busca essas instruções de um chipset presente na placa-mãe, conhecido como **BIOS** ou **UEFI**. Este chipset contém as instruções sobre como iniciar o processo de inicialização.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666101.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666101.svg)

**BIOS vs UEFI:**

|Característica|BIOS|UEFI|
|---|---|---|
|Tempo de uso|Décadas (ainda em uso)|Substituto moderno|
|Modo de operação|16 bits|32/64 bits|
|Tamanho máximo de disco|2 TB|9 ZB|
|Esquema de particionamento|MBR|GPT|
|Inicialização segura|Não|Sim (Secure Boot)|
|Redundância|Não|Sim (recuperação por backup)|

**Como verificar seu firmware no Windows:**

1. Pressione `Windows + R` para abrir "Executar"
2. Digite `msinfo32` e pressione Enter
3. Verifique o campo **BIOS Mode**:
    - **Legacy** = BIOS
    - **UEFI** = UEFI

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731683551194.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731683551194.png)

### 2. Autoteste de Inicialização (POST)

Com o sistema ligado e o CPU executando as instruções do firmware, o BIOS/UEFI inicia o **Power-On Self Test (POST)** para verificar se todos os componentes de hardware estão funcionando corretamente.

Durante este processo, você pode ouvir bipes — cada sequência de bipes indica um tipo específico de erro de hardware.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666092.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666092.svg)

### 3. Localizando o Dispositivo Inicializável

Após o POST, a BIOS/UEFI procura por dispositivos inicializáveis (SSDs, HDDs, pen drives) com sistema operacional instalado.

Quando o dispositivo inicializável é encontrado, a BIOS/UEFI começa a ler seu primeiro setor. É aqui que o **MBR** ou **GPT** assume o controle do processo de inicialização.

> **Dica:** No Windows PowerShell, você pode digitar `Get-Disk` para verificar o esquema de particionamento dos seus discos.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666094.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110666094.svg)

---

## Cenário 1: Sistema com MBR

### Analisando o MBR

O MBR foi usado por décadas e ainda está presente em alguns sistemas. Um disco é dividido em setores de **512 bytes cada**. O MBR ocupa o **primeiro setor** do disco.

Para visualizar o MBR, usaremos o **HxD**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1733912342396.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1733912342396.png)

O MBR ocupa exatamente **512 bytes** (as primeiras 32 linhas × 16 bytes por linha). Você pode identificá-lo pela assinatura final `55 AA`.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731917826750.png)

### Estrutura do MBR

Os 512 bytes do MBR são divididos em três partes:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110716769.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110716769.svg)

#### Componente 1: Código do Bootloader (Bytes 0-445)

O código do bootloader ocupa **446 bytes** e contém o **Bootloader Inicial** — o primeiro código executado no MBR. Sua função principal é localizar a partição inicializável na tabela de partições.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731920146062.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731920146062.png)

> **Nota técnica:** O código do bootloader pode ser desmontado em linguagem assembly, mas isso está além do escopo desta análise.

#### Componente 2: Tabela de Partições (Bytes 446-509)

A tabela de partições ocupa **64 bytes** e armazena detalhes de até **4 partições** (16 bytes por partição).

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731920146057.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731920146057.png)

Comparação com o Gerenciamento de Disco do Windows:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1733741844707.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1733741844707.png)

**Estrutura de uma entrada de partição (16 bytes):**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731927561284.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731927561284.png)

|Posição|Bytes|Campo|Descrição|
|---|---|---|---|
|0|1|Indicador de Inicialização|`80` = inicializável / `00` = não inicializável|
|1-3|3|Endereço CHS Inicial|Posição física inicial (menos importante)|
|4|1|Tipo de Partição|`07` = NTFS, `0B` = FAT32, etc.|
|5-7|3|Endereço CHS Final|Posição física final (menos importante)|
|8-11|4|Endereço LBA Inicial|Posição lógica inicial (importante!)|
|12-15|4|Número de Setores|Quantidade de setores na partição|

**Como localizar uma partição usando o LBA Inicial:**

Suponha o LBA Inicial `00 08 00 00`:

1. **Inverta os bytes** (little-endian → big-endian): `00 00 08 00`
2. **Converta para decimal**: `2.048`

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731950113978.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731950113978.png)

3. **Multiplique pelo tamanho do setor** (512 bytes):

$$
2048 \times 512 = 1{.}048{.}576
$$

4. **Pesquise** este valor no HxD (Pesquisar → Ir para → decimal)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731950875219.png)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731950875220.png)

**Como calcular o tamanho da partição:**

Com os bytes `00 B0 23 03`:

1. Inverta: `03 23 B0 00`
2. Converta para decimal: `52.670.464` setores
3. Multiplique por 512:

$$
52.670.464 \times 512 = 26{.}967{.}277{.}568 \space bytes
$$

#### Componente 3: Assinatura do MBR (Bytes 510-511)

Os dois bytes finais `55 AA` (Número Mágico) marcam o fim do MBR. Se corrompidos (por malware ou setor defeituoso), o sistema **não inicializa**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731920146058.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1731920146058.png)

### Resumo do Processo de Inicialização com MBR

1. Bootloader Inicial é executado a partir do código do MBR
2. Localiza a partição inicializável na tabela de partições
3. Carrega o segundo bootloader a partir dessa partição
4. O segundo bootloader carrega o kernel do SO
5. Drivers, serviços e sistemas de arquivos são carregados na memória
6. Usuário recebe o controle da interface    

---
## Ameaças Direcionadas ao MBR

Mesmo com a substituição pelo GPT, o MBR ainda representa uma superfície de ataque significativa:

### Bootkits

Malware que se infiltra no MBR para executar **antes do sistema operacional**, burlando mecanismos de proteção. Mesmo a reinstalação do SO não remove o bootkit.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110798085.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110798085.svg)

### Ransomware (ex: Petya, Bad Rabbit)

Em vez de criptografar arquivos individuais, o ransomware criptografa o MBR, exibindo mensagens de resgate na tela.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737236441165.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737236441165.png)

### Malware de Limpeza (ex: Shamoon)

Corrompe o MBR com caracteres aleatórios, tornando o sistema não inicializável.

---
## Estudo de Caso: Adulteração do MBR

### Cenário

O servidor de banco de dados de uma organização tornou-se inoperante após um funcionário abrir um anexo de e-mail malicioso. A análise aponta para **corrupção deliberada do MBR**.

O MBR corrompido apresenta dois problemas:

1. Endereço lógico da primeira partição alterado (era `00 08 00 00`)    
2. Um componente crítico do MBR corrompido (deveria ser igual em todos os MBRs)

### Ferramentas Utilizadas

**HxD** (Editor hexadecimal)

- Comando: Abrir `C:\Analysis\MBR_Corrupted_Disk.001`
- Clique no byte corrompido e digite o valor correto
- Salve: `File` → `Save`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737107623828.png)

> ⚠️ **Aviso:** O HxD pode mostrar "espaço insuficiente" ao salvar. Isso é normal — clique "Sim" para continuar.

**FTK Imager** (Visualização forense)

1. `File` → `Add Evidence Item`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1733910121279.png)

2. Selecione `Image File` → `Next`

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1733910121296.png)

3. Insira o caminho da imagem corrigida → `Finish`

**Antes da correção:** O FTK Imager exibe "Unrecognized file system"  
**Após a correção:** Todo o conteúdo do disco fica acessível

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737107623829.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737107623829.png)

---
## Cenário 2: Sistema com GPT

O GPT substituiu o MBR devido a limitações significativas:

|Característica|MBR|GPT|
|---|---|---|
|Tamanho máximo|2 TB|9 ZB|
|Número máximo de partições|4|128|
|Redundância|Não|Sim (backup)|
|Firmware|BIOS|UEFI|

### Estrutura do GPT

Diferente do MBR (apenas 512 bytes), o GPT possui **5 componentes** distribuídos por vários setores:

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110838398.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110838398.svg)

### Componente 1: MBR de Proteção

Localizado no primeiro setor (setor 0), sinaliza ao sistema BIOS que o disco usa GPT, evitando alterações acidentais.

**Características:**

- Código do bootloader: geralmente zeros (`00`)
- Tabela de partições: contém UMA partição com byte tipo `EE` (disco GPT)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1732018952352.png)

- Assinatura: `55 AA`

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1734943004432.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1734943004432.png)

### Componente 2: Cabeçalho GPT Primário

Localizado no setor 1, ocupando 92 bytes (os bytes restantes são preenchidos com `00`).

|Posição|Bytes|Campo|Valor típico|
|---|---|---|---|
|0-7|8|Assinatura|`45 46 49 20 50 41 52 54` ("EFI PART")|
|8-11|4|Revisão|`00 00 01 00` (versão 1.0)|
|12-15|4|Tamanho do Cabeçalho|`5C 00 00 00` (92 bytes)|
|16-19|4|CRC32 do Cabeçalho|Checksum de integridade|
|20-23|4|Reservado|Para uso futuro|
|24-31|8|LBA Atual|Localização do cabeçalho (setor 1)|
|32-39|8|LBA de Backup|Último setor do disco|
|40-47|8|Primeiro LBA Utilizável|Início das partições|
|48-55|8|Último LBA Utilizável|Fim das partições|
|56-71|16|GUID do Disco|Identificador único do disco|
|72-79|8|LBA da Matriz de Partições|Início das entradas de partição|
|80-83|4|Número de Entradas|`128` (em decimal)|
|84-87|4|Tamanho por Entrada|`128` bytes|
|88-91|4|CRC32 da Matriz|Checksum da matriz|

### Componente 3: Matriz de Entradas de Partição

Começa no setor 2 e contém até **128 partições**, cada uma com **128 bytes**. Na captura abaixo, apenas 6 partições estão em uso (as demais são `00`):

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1732103336630.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1732103336630.png)

**Estrutura de uma entrada de partição (128 bytes):**

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1732104106344.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1732104106344.png)

|Posição|Bytes|Campo|Descrição|
|---|---|---|---|
|0-15|16|GUID do Tipo|Identifica o tipo de partição|
|16-31|16|GUID Único|Identificador exclusivo da partição|
|32-39|8|LBA Inicial|Início da partição|
|40-47|8|LBA Final|Fim da partição|
|48-55|8|Atributos|Flags (inicializável, oculta, etc.)|
|56-127|72|Nome da Partição|Nome em UTF-16|

**Convertendo GUIDs (formato mixed-endian):**

Para o GUID `28 73 2A C1 1F F8 D2 11 BA 4B 00 A0 C9 3E C9 3B`:

1. Inverta os primeiros 4 bytes: `C1 2A 73 28`
2. Inverta os próximos 2 bytes: `F8 1F`
3. Inverta os próximos 2 bytes: `11 D2`
4. Mantenha os próximos 2 bytes: `BA 4B`
5. Mantenha os últimos 6 bytes: `00 A0 C9 3E C9 3B`

**Resultado:** `C12A7328-F81F-11D2-BA4B-00A0C93EC93B` → **EFI System Partition (ESP)**

### Componente 4: Cabeçalho GPT de Backup

Localizado no **último setor do disco**, contém as mesmas informações do cabeçalho primário. Permite recuperação caso o cabeçalho primário seja corrompido.

### Componente 5: Matriz de Entradas de Partição de Backup

Localizada antes do cabeçalho de backup, é uma cópia da matriz primária de entradas de partição.

---
## Ameaças Direcionadas ao GPT

### Bootkits

Atacantes substituem arquivos `.efi` na **Partição do Sistema EFI (ESP)** por bootkits maliciosos. O **Secure Boot** do UEFI pode prevenir isso através de assinaturas digitais.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110912111.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110912111.svg)

### Ransomware

Mais difícil que no MBR devido à redundância do GPT, mas malwares avançados podem criptografar a ESP, interrompendo o boot.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110912120.svg](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110912120.svg)

### Malware de Limpeza

Malwares sofisticados podem criptografar tanto o cabeçalho primário quanto o backup, além da ESP, tornando a recuperação extremamente difícil.

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/6645aa8c024f7893371eb7ac/room-content/6645aa8c024f7893371eb7ac-1737110912117.svg)

---
## Conclusão

|Aspecto|MBR|GPT|
|---|---|---|
|**Tamanho do código**|512 bytes (único setor)|Múltiplos setores|
|**Número máximo de partições**|4|128|
|**Capacidade máxima**|2 TB|9 ZB|
|**Redundância**|❌|✅ (backup)|
|**Firmware requerido**|BIOS|UEFI|
|**Inicialização segura**|❌|✅ (Secure Boot)|
|**Resiliência a ataques**|Baixa|Média-Alta|

O conhecimento da estrutura interna do MBR e GPT é essencial para:

- **Análise forense** de discos corrompidos
- **Recuperação** de sistemas após ataques
- **Investigação** de incidentes envolvendo bootkits 
- **Compreensão** profunda do processo de inicialização
