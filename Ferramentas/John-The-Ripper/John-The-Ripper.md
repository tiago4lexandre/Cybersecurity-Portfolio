<!--
title: John The Ripper
desc: Quebra de senhas e hashes localmente utilizando o utilitário flexível John The Ripper.
tags: tools, john, cracking, passwords
readTime: 6 min
-->

<!-- ===================================== -->
<!--  John The Ripper — Password Auditing  -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Developed-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Category-Password%20Auditing-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Tool-John%20The%20Ripper-black?style=flat-square">
  <img src="https://img.shields.io/badge/Cryptography-Hashes-blue?style=flat-square">
  <img src="https://img.shields.io/badge/Offensive%20Security-Cracking-red?style=flat-square">
  <img src="https://img.shields.io/badge/Defensive%20Security-Auditing-informational?style=flat-square">
</p>

---

# 🔐 John The Ripper — Password Auditing & Hash Cracking

> Documentação técnica completa sobre o **John The Ripper**, abordando fundamentos de hashing, identificação de formatos, modos de ataque, regras personalizadas, cracking de hashes Linux e Windows, otimização de desempenho e boas práticas em **auditoria de segurança de senhas**.

---

### 📌 Metadados

- **Ferramenta:** John The Ripper (Jumbo)  
- **Categoria:** Password Auditing · Hash Cracking  
- **Sistema:** Linux · Windows  
- **Área:** Criptografia Aplicada · Segurança Ofensiva  

---

### 🏷️ Tags

`#JohnTheRipper` `#PasswordCracking` `#Hashing` `#Cryptography`  
`#CyberSecurity` `#Pentest` `#RedTeam` `#BlueTeam`  
`#LinuxSecurity` `#WindowsSecurity` `#NTLM` `#ShadowFile`

---
## Introdução

### 1. O que é Jonh The Ripper

John The Ripper é uma ferramenta de auditoria de segurança e recuperação de senhas de código aberto, originalmente desenvolvida para sistemas Unix, mas agora disponível para múltiplas plataformas. É amplamente utilizada por profissionais de segurança para testar a robustez de senhas em sistemas computacionais.

![John The Ripper](https://blog.solyd.com.br/wp-content/uploads/2024/09/0_AUUchPlRknqYeQhP.jpg)

### 2. Principais Características

- Suporte a múltiplos formatos de hash
- Modos de ataque diversificados
- Capacidade de personalizada via regras
- Suporte a processamento distribuído (MPI)
- Interface GPU para aceleração
- Modo incremental automático

---
## O que são Hashes?

Hash é uma forma de pegar algum dado de qualquer comprimento e representá-lo em outra forma de comprimento fixo. Este processo mascara o valor original dos dados. O valor do hash é obtido executando os dados originais através de um algoritmo de hash. Existem diversos algoritmos de hashing populares como MD4, MD5, SHA1 e NTLM.

Se usarmos a palavra "polo" como exemplo, uma sequência de quatro caracteres, e o executarmos através de um algoritmo de hash MD5, acabamos com uma saída de `b53759f3ce692de7aff1b5779d3964da` um hash padrão de 32 caracteres MD5.

![hashing](https://upload.wikimedia.org/wikipedia/commons/2/2b/Cryptographic_Hash_Function.svg)


### O que tornas os hashes seguros?

As funções de hash são projetadas como funções unidirecionais. Em outras palavras, é fácil calcular o valor de hash de uma determinada entrada; no entanto, é um problema difícil encontrar a entrada original, dado o valor de hash. Em termos simples, um problema difícil rapidamente se torna computacionalmente inviável na ciência da computação. Este problema computacional tem suas raízes na matemática com P vs NP.

Em ciência da computação, P e NP são duas classes de problemas que nos ajudam a entender a eficiência dos algoritmos:

- **P (Tempo Polinomial**): A classe P cobre os problemas cuja solução pode ser encontrada no tempo polinomial. Considere classificar uma lista em ordem crescente. Quanto mais longa a lista, mais tempo levaria para classificar; no entanto, o aumento no tempo não é exponencial.
- **NP (Tempo Polinomial Não Determinístico**): Problemas na classe NP são aqueles para os quais uma determinada solução pode ser verificada rapidamente, mesmo que encontrar a solução em si possa ser difícil. Na verdade, não sabemos se há um algoritmo rápido para encontrar a solução em primeiro lugar.

Embora este seja um conceito matemático fascinante que se mostra fundamental para a computação e a criptografia, ele está inteiramente fora do escopo desta sala. Mas, abstratamente, o algoritmo para hash o valor será “P” e pode, portanto, ser calculado razoavelmente. No entanto, um algoritmo “un-hashing” seria “NP” e intratável de resolver, o que significa que ele não pode ser computado em um tempo razoável usando computadores padrão.

---
## Onde o John entra

Mesmo que o algoritmo não seja viávelmente reversível, isso não significa que quebrar os hashes seja impossível. Se você tem a versão hash de uma senha, por exemplo, e você conhece o algoritmo de hash, você pode usar esse algoritmo de hash para um grande número de palavras, chamado de dicionário. Você pode então comparar esses hashes com aquele que você está tentando quebrar para ver se eles combinam.Caso seja encontrada uma combinação, você sabe que palavra corresponde a esse hash e você o quebrou!

Este processo é chamado de **ataque de dicionário**, e a ferramenta John The Ripper ou John, como é comumente encurtado, é uma ferramenta para a realização de ataques de força bruta rápida em vários tipos de hash.

---
## Instalação e Configuração

### 1. Instalação em diferentes sistemas

#### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install john -y
```

#### Compilação a partir do código-fonte

```bash
git clone https://github.com/openwall/john -b bleeding-jumbo john
cd john/src
./configure
make -s clean && make -sj4
```

#### Windows

- Download do binário pré-compilado do site oficial
- Versão JtR "jumbo" inclui formatos de hash

### 2. Verificação da instalação

```bash
john --help
john --list=formats
```

---
## Formatos de Hash Suportados

### Lista de principais formatos

```bash
john --list=formats | head -20

# Principais formatos:
# - md5crypt, MD5 (Unix)
# - sha256crypt, sha512crypt
# - NTLM (Windows)
# - LM (Windows antigo)
# - bcrypt
# - descrypt (DES tradicional)
# - mysql, mssql, oracle
# - PDF, ZIP, RAR
# - Bitcoin/Litecoin wallets
```

---
## Sintaxe Básica

A sintaxe básica dos comandos John the Ripper é a seguinte:

```bash
john [options] [file path]
```

- `john`: Invoca o programa John the Ripper
- `[options]`: Especifica as opções que você deseja usar
- `[file path]`: O arquivo que contém o hash que você está tentando quebrar; se estiver no mesmo diretório, você não precisará nomear um caminho, apenas o arquivo.

### Cracking automático

John tem recursos embutidos para detectar que tipo de hash está sendo dado e selecionar regras e formatos apropriados para decifrá-lo para você; Esta nem sempre é a melhor ideia, pois pode ser não confiável, mas se você não consegue identificar com que tipo de hash está trabalhando e deseja tentar quebrá-lo, pode ser uma boa opção! Para fazer isso, usamos a seguinte sintaxe:

```bash
john --wordlist=[path to wordlist] [path to file]
```

- `--wordlist=`: Especifica o uso do modo wordlist, leitura do arquivo que você fornece no caminho fornecido
- `[path to wordlist]`: O caminho para a lista de palavras que você está usando, conforme descrito na tarefa anterior

**Exemplo de uso:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

---
## Identificando Hashes

Às vezes, John não vai bem com o reconhecimento automático e carregamento de hashes, mas tudo bem! Podemos usar outras ferramentas para identificar o hash e, em seguida, definir John para um formato específico. Existem várias maneiras de fazer isso, como usar um identificador de hash on-line como [este site](https://hashes.com/en/tools/hash_identifier). Uma das ferramentas mais usadas é o [hash-identifier](https://gitlab.com/kalilinux/packages/hash-identifier/-/tree/kali/master), uma ferramenta Python que é super fácil de usar e lhe dirá quais tipos diferentes de hashes o que você insere provavelmente será, dando-lhe mais opções se o primeiro falhar.

Para usar hash-identifier, você pode usar `wget`ou `curl`para baixar o arquivo Python `hash-id.py`da sua [página](https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py) no GitLab. Então, lance-o com `python3 hash-id.py`e entre no hash que você está tentando identificar. Ele lhe dará uma lista dos formatos mais prováveis. 

```bash
wget https://gitlab.com/kalilinux/packages/hash-identifier/-/raw/kali/master/hash-id.py

python3 hash-id.py

HASH: 2e728dd31fb5949bc39cac5a9f066498

# Saída
Possible Hashs:
[+] MD5
[+] Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))
```

---
## Cracking específicos de formato

Depois de identificar o hash com o qual você está lidando, você pode dizer a John para usá-lo enquanto quebra o hash fornecido usando a seguinte sintaxe:

```bash
john --format=[format] --wordlist=[path to wordlist] [path to file]
```

- `--format=`: Esta é a bandeira para dizer a John que você está dando-lhe um hash de um formato específico e usar o seguinte formato para quebrá-lo
- `[format]`: O formato em que o hash está

**Exemplo de uso:**

```bash
john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash_to_crack.txt
```

>[!note] Uma nota sobre formatos:
>Quando você diz a John para usar formatos, se você está lidando com um tipo de hash padrão, por exemplo, md5 como no exemplo acima, você tem que prefixá-lo com `raw-`para dizer a John que você está apenas lidando com um tipo de hash padrão, embora isso nem sempre se aplique. Para verificar se você precisa adicionar o prefixo ou não, você pode listar todos os formatos de John usando `john --list=formats`e verifique manualmente ou agregue seu tipo de hash usando algo como `john --list=formats | grep -iF "md5"`.

---
## Modos de Ataque

### 1. Modo de Ataque de Dicionário (Wordlist)

```bash
# Ataque básico com dicionário
john --wordlist=/usr/share/wordlists/rocky.txt hashfile.txt

# Especificar formato de hash
john --wordlist=lista.txt --format=raw-md5 hashes_md5.txt

# Com sessão nomeada para continuar posteriormente
john --wordlist=lista.txt --session=minhasessao hashfile.txt
```

### 2. Modo de Ataque Incremental

```bash
# Usa todas as combinações de caracteres possíveis
john --incremental hashfile.txt

# Modo incremental específico
john --incremental:Alpha hashfile.txt
```

### 3. Modo de Ataque com Regras

```bash
# Usar regras padrão
john --wordlist=lista.txt --rules hashfile.txt

# Usar arquivo de regras personalizado
john --wordlist=listas.txt --rules=customrules hashfile.txt
```

### 4. Modo de Ataque Máscara (Mask Attack)

```bash
# Ataque com máscara personalizada
john --mask=?l?l?l?l?l?l hashfile.txt  # 6 letras minúsculas

# Exemplos de máscaras:
john --mask=?u?l?l?l?d?d?d hashfile.txt  # Maiúscula + 3 minúsculas + 3 dígitos
john --mask=password?d?d?d hashfile.txt  # "password" + 3 dígitos

# Lista de placeholders:
# ?l = letra minúscula [a-z]
# ?u = letra maiúscula [A-Z]
# ?d = dígito [0-9]
# ?s = caractere especial [!@#$%^&*()]
# ?a = todos os caracteres acima
# ?h = hexadecimal [0-9a-f]
# ?H = hexadecimal [0-9A-F]
```

### 5. Modo Single Crack (Modo Único)

Neste modo, John usa apenas as informações fornecidas no nome de usuário para tentar elaborar possíveis senhas heuristicamente, alterando ligeiramente as letras e números contidos no nome de usuário.

#### Word Mangling

A melhor maneira de explicar o modo Single Crack e a manipulação de palavras é passar por um exemplo:

Considere o nome de usuário “Markus”.

Algumas senhas possíveis podem ser:

- Markus1, Markus2, Markus3 (etc.)
- MARkus, Markus, MARKus (etc.)
- Markus!, Markus$, Markus* (etc.)

Essa técnica é chamada de *word mangling*. John está construindo seu dicionário com base nas informações que foi alimentado e usa um conjunto de regras chamadas “regras de mangleing”, que definem como ele pode mutar a palavra com a qual começou para gerar uma lista de palavras com base em fatores relevantes para o alvo que você está tentando quebrar. Isso explora como as senhas pobres podem ser baseadas em informações sobre o nome de usuário ou o serviço em que estão entrando.

#### GECOS

A implementação de manipulação de palavras de John também apresenta compatibilidade com o campo GECOS do sistema operacional UNIX, bem como outros sistemas operacionais semelhantes ao UNIX, como o Linux. A GECOS significa General Electric Comprehensive Operating System. Na última tarefa, analisamos as entradas para ambos `/etc/shadow`e `/etc/passwd`. Olhando atentamente, você notará que os campos estão separados por um cólon `:`. O quinto campo no registro da conta de usuário é o campo GECOS. Ele armazena informações gerais sobre o usuário, como o nome completo do usuário, número de escritório e número de telefone, entre outras coisas. John pode levar informações armazenadas nesses registros, como nome completo e nome do diretório inicial, para adicionar à lista de palavras que gera ao rachar `/etc/shadow`hashes com modo de rachadura única.

#### Usando o modo Single Crack

```bash
john --single --format=[format] [path to file]
```

- `--single`: Esta bandeira permite que John saiba que você deseja usar o modo de travamento de hash único
- `--format=[format]`: Como sempre, é vital identificar o formato adequado.

**Exemplo de uso:**

```bash
# Usa informações do usuário para gerar senhas
john --single hashfile.txt

# Usando formato específico
john --single --format=raw-sha256 hashes.txt

# Formato específico para /etc/shadow
unshadow /etc/passwd /etc/shadow > combined.txt
john --single combined.txt
```

>[!note] Nota sobre formatos de arquivos no modo Single Crack
>Se você estiver quebrando hashes no modo de rachadura única, você precisa alterar o formato de arquivo que você está alimentando John para ele para entender de que dados criar uma lista de palavras. Você faz isso preparando o hash com o nome de usuário ao qual o hash pertence, então, de acordo com o exemplo acima, mudaríamos o arquivo hashes.txt
>
>De: `1efee03cdcb96d90ad48ccc7b8666033`
>
Para: `mike:1efee03cdcb96d90ad48ccc7b8666033`

---
## Windows e Autenticação de Hashes

### NTHash / NTLM

NThash é o formato de hash moderno Windows máquinas de sistema operacional usar para armazenar senhas de usuário e serviço. Também é comumente referido como NTLM, que faz referência à versão anterior do formato Windows para hash de senhas conhecidas como LM, portanto NT/LM.

![NTLM Hassh Attack](https://www.redlings.com/content/media/guide-ntlm-authentication3.png)

Um pouco de história: a designação NT para produtos Windows originalmente significava Nova Tecnologia. Ele foi usado começando com o Windows NT para denotar produtos não construídos a partir do Sistema Operacional MS-DOS. Eventualmente, a linha “NT” tornou-se o tipo padrão do Sistema Operacional a ser lançado pela Microsoft, e o nome foi descartado, mas ainda vive nos nomes de algumas tecnologias da Microsoft.

No Windows, o SAM (Security Account Manager) é usado para armazenar informações de conta de usuário, incluindo nomes de usuário e senhas hash. Você pode adquirir hashes NTHash / NTLM despejando o banco de dados SAM em uma máquina Windows, usando uma ferramenta como o Mimikatz ou usando o banco de dados do Active Directory: `NTDS.dit`. Você pode não ter que quebrar o hash para continuar a escalada de privilégios, pois muitas vezes você pode realizar um ataque de “passar no hash”, mas às vezes, o hash cracking é uma opção viável se houver uma política de senha fraca.

### Na prática

```bash
john --format=nt --wordlist=[wordlist path] [hash file]
```

---
## Cracking `/etc/shadow`

O `/etc/shadow`arquivo é o arquivo em máquinas Linux onde hashes de senha são armazenados. Ele também armazena outras informações, como a data da última alteração de senha e informações de expiração de senha. Ele contém uma entrada por linha para cada usuário ou conta de usuário do sistema. Esse arquivo geralmente só é acessível pelo usuário root, portanto, você deve ter privilégios suficientes para acessar os hashes. No entanto, se você fizer isso, há uma chance de que você será capaz de quebrar alguns dos hashes.

### `unshadow`

John pode ser muito particular sobre os formatos em que precisa de dados para poder trabalhar com ele; por esse motivo, para quebrar as senhas em `/etc/shadow`, é necessário combiná-lo com o comando `unshadow` para que John entenda os dados que estão sendo dados. A sintaxe básica de `unshadow`é como segue:

```bash
unshadow [path to passwd] [path to shadow]
```

- `unshadow`: Invoca a ferramenta de dessombra
- `[path to passwd]`: O arquivo que contém a cópia do `/etc/passwd`arquivo que você tirou da máquina de destino
- `[path to shadow]`: O arquivo que contém a cópia do `/etc/shadow`arquivo que você tirou da máquina de destino

**Exemplo de uso:**

```bash
unshadow local_passwd local_shadow > unshadowed.txt
```

>[!note] Nota sobre os arquivos:
>Ao usar `unshadow`, você pode usar o todo `/etc/passwd`e `/etc/shadow`arquivos, supondo que você os tenha disponíveis, ou você pode usar a linha relevante de cada um, por exemplo:
>
>**ARQUIVO 1 - local_passwd**
>
>Contém o `/etc/passwd`linha para o usuário root:
>
>```text
>root:x:0:0::/root:/bin/bash
>```
>
>**ARQUIVO 2 - local_shadow**
>
>Contém o `/etc/shadow`linha para o usuário root: `root:$6$2nwjN454g.dv4HN/$m9Z/r2xVfweYVkrr.v5Ft8Ws3/YYksfNwq96UL1FX0OJjY1L6l.DS3KEVsZ9rOVLB/ldTeEL/OIhJZ4GMFMGA0:18576::::::`

### Crackeando o hash

Podemos então alimentar a saída de `unshadow`, no nosso exemplo caso de uso chamado `unshadowed.txt`, diretamente em João. Não devemos precisar especificar um modo aqui, pois fizemos a entrada especificamente para John; no entanto, em alguns casos, você precisará especificar o formato como fizemos anteriormente usando: `--format=sha512crypt`

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt --format=sha512crypt unshadowed.txt
```

---
## Exemplos Práticos

### 1. Quebrando senhas do `/etc/shadow`

```bash
# Passo 1: Preparar arquivo combinado
unshadow /etc/passwd /etc/shadow > senhas.txt

# Passo 2: Executar ataque
john --wordlist=/usr/share/wordlists/rockyou.txt senhas.txt

# Passo 3: Ver senhas recuperadas
john --show senhas.txt
```

### 2. Quebrando hashes NTLM

```bash
# Arquivo com hashes NTLM (usuário:hash)
echo "admin:32ED87BDB5FDC5E9CBA88547376818D4" > ntlm_hashes.txt

# Executar ataque
john --format=nt --wordlist=lista.txt ntlm_hashes.txt
```

### 3. Quebrando hash MD5

```bash
# Criar arquivo com hash MD5
echo "5f4dcc3b5aa765d61d8327deb882cf99" > md5_hash.txt

# Atacar com dicionário
john --format=raw-md5 --wordlist=rockyou.txt md5_hash.txt

# Ou usar modo incremental
john --format=raw-md5 --incremental md5_hash.txt
```

### 4. Quebrando arquivo ZIP protegido

Similarmente ao `unshadow`ferramenta que usamos anteriormente, usaremos o `zip2john`ferramenta para converter o arquivo Zip em um formato hash que John pode entender e espero que crack. O uso primário é assim:

```bash
zip2john [options] [zip file] > [output file]
```

- `[options]`: Permite que você passe opções específicas de soma de verificação para `zip2john`; isso não deve ser necessário muitas vezes
- `[zip file]`: O caminho para o arquivo Zip que você deseja obter o hash de
- `>`: Isso redireciona a saída deste comando para outro arquivo
- `[output file]`: Este é o arquivo que irá armazenar a saída

**Exemplo de Uso**

```bash
zip2john zipfile.zip > zip_hash.txt
```

#### Na prática

```bash
# Extrair hash do arquivo ZIP
zip2john arquivo.zip > zip_hash.txt

# Quebrar o hash
john --wordlist=lista.txt zip_hash.txt
```

#### `rar2john`

O mesmo pode ser feito em arquivos `.rar` usando o comando `rar2john`

**Exemplo:**

```bash
rar2john rarfile.rar > rar_hash.txt
```

### 5. Quebrando arquivo PDF

```bash
# Extrair hash do PDF
pdf2john documento.pdf > pdf_hash.txt

# Executar ataque
john pdf_hash.txt
```

### 6. Quebrando chave SSH

#### `ssh2john`

Como o nome sugere, `ssh2john`converte o `id_rsa`chave privada, que é usada para fazer login na sessão SSH, em um formato de hash com o qual John pode trabalhar.

```bash
ssh2john [id_rsa private key file] > [output file]
```

- `ssh2john`: Invoca o `ssh2john`ferramenta
- `[id_rsa private key file]`: O caminho para o arquivo id_rsa que você deseja obter o hash de
- `>`: Este é o diretor de produção. Estamos usando-o para redirecionar a saída deste comando para outro arquivo.
- `[output file]`: Este é o arquivo que irá armazenar a saída de

---
## Arquivo de Configuração (`john.conf`)

## 1. Estrutura do arquivo de configuração

```ini
# Exemplo de seções do john.conf

# Configurações gerais
[Options]
# Wordlist = $JOHN/password.lst
# Save = 500

# Definições de listas de palavras
[List.Rules:Wordlist]
# Regras aplicadas durante ataques de dicionário

[List.Rules:Single]
# Regras para modo single crack

[List.Rules:Jumbo]
# Regras adicionais incluídas na versão jumbo

[Incremental:All]
# Configuração para modo incremental
File = $JOHN/all.chr
MinLen = 0
MaxLen = 8
CharCount = 95
```

### 2. Configuração do modo incremental personalizado

```ìni
[Incremental:Custom8]
File = $JOHN/password.chr
MinLen = 6
MaxLen = 8
CharCount = 36
Charset1 = ?l?d                   # letras minúsculas e dígitos
Charset2 = ?u?l?d?s               # todos os caracteres
Charset3 = ?l                     # apenas letras minúsculas
```

---
## Regras Personalizadas

### O que são regras personalizadas?

À medida que exploramos o que John pode fazer no Single Crack Mode, você pode ter algumas ideias sobre alguns bons padrões de mutilação ou quais padrões suas senhas costumam usar que podem ser replicados com um padrão de mutilação específico. A boa notícia é que você pode definir suas regras, que John usará para criar senhas de forma dinâmica. A capacidade de definir tais regras é benéfica quando você sabe mais informações sobre a estrutura de senha de qualquer que seja o seu alvo.

### Regras Personalizadas Comuns

Muitas organizações exigirão um certo nível de complexidade de senha para tentar combater ataques de dicionário. Em outras palavras, ao criar uma nova conta ou alterar sua senha, se você tentar uma senha como `polopassword`, muito provavelmente não vai funcionar. A razão seria a complexidade da senha imposta. Como resultado, você pode receber um prompt informando que as senhas devem conter pelo menos um caractere de cada um dos seguintes:

- Letra minúscula
- Letra maiúscula
- Número
- Símbolo

A complexidade da senha é boa! No entanto, podemos explorar o fato de que a maioria dos usuários será previsível na localização desses símbolos. Para os critérios acima, muitos usuários usarão algo como o seguinte:

`Polopassword1!`

Considere a senha com uma letra maiúscula primeiro e um número seguido por um símbolo no final. Esse padrão familiar da senha, anexado e pré-pendido por modificadores (como letras maiúsculas ou símbolos), é um padrão memorável que as pessoas usam e reutilizam ao criar senhas. Esse padrão pode nos permitir explorar a previsibilidade da complexidade da senha.

Agora, isso atende aos requisitos de complexidade de senha; no entanto, como invasores, podemos explorar o fato de que sabemos a posição provável desses elementos adicionados para criar senhas dinâmicas de nossas listas de palavras.

### Como criar regras personalizadas

As regras personalizadas são definidas no arquivo `john.conf`. Este arquivo pode ser encontrado em `/opt/john/john.conf`, geralmente está localizado em `/etc/john/john.conf`se você instalou o John usando um gerenciador de pacotes ou construído a partir da fonte com `make`.

Vamos analisar a sintaxe dessas regras personalizadas, usando o exemplo acima como nosso padrão de destino. Observe que você pode definir um nível maciço de controle granular nessas regras. Sugiro olhar para a wiki [aqui](https://www.openwall.com/john/doc/RULES.shtml) para obter uma visão completa dos modificadores que você pode usar e mais exemplos de implementação de regras.

A primeira linha:

`[List.Rules:nome da regra]`é usado para definir o nome de sua regra; é isso que você usará para chamar sua regra personalizada de argumento de John.

Em seguida, usamos uma correspondência de padrões de estilo regex para definir onde a palavra será modificada; novamente, cobriremos apenas os modificadores primários e mais comuns aqui:

- `Az`: Pega a palavra e a anexa com os caracteres que você define
- `A0`: Pega a palavra e a prepara com os caracteres que você define
- `c`: Capitaliza o caráter posicionalmente

Estes podem ser usados em combinação para definir onde e o que na palavra que você deseja modificar.

Por fim, devemos definir quais caracteres devem ser anexados, prependidos ou de outra forma incluídos. Fazemos isso adicionando conjuntos de caracteres em colchetes quadrados `[ ]`onde devem ser utilizados. Estes seguem os padrões modificadores dentro de citações duplas `" "`. Aqui estão alguns exemplos comuns:

- `[0-9]`: Incluirá os números 0-9  
    
- `[0]`: Incluirá apenas o número 0
- `[A-z]`: Incluirá tanto a maiúscula quanto a minúscula  
    
- `[A-Z]`: Incluirá apenas letras maiúsculas
- `[a-z]`: Incluirá apenas letras minúsculas

Por favor, note que:

- `[a]`: Incluirá apenas `a`
- `[!£$%@]`: Incluirá os símbolos `!`, `£`, `$`, `%`, e `@`

Juntando tudo isso, para gerar uma lista de palavras a partir das regras que corresponderiam à senha de exemplo `Polopassword1!`(assumindo a palavra `polopassword`estava em nossa lista de palavras), criaríamos uma entrada de regra que se parece com isso:

```text
[List.Rules:PoloPassword]

cAz"[0-9] [!£$%@]"
```

Utiliza o seguinte:

- `c`: Capitaliza a primeira carta
- `Az`: Anexa até o fim da palavra
- `[0-9]`: Um número na faixa 0-9
- `[!£$%@]`: A senha é seguida por um desses símbolos

### Usando a Regra Personalizada

Poderíamos então chamar essa regra personalizada de argumento de John usando :

```bash
john --wordlist=[path to wordlist] --rule=PoloPassword [path to file]
```

Como nota, acho útil falar sobre os padrões se você estiver escrevendo uma regra; como mostrado acima, o mesmo se aplica a escrever padrões RegEx.

Jumbo John já tem uma extensa lista de regras personalizadas contendo modificadores para uso em quase todos os casos. Se você ficar preso, tente olhar para essas regras [em torno da linha 678] se sua sintaxe não estiver funcionando corretamente.

### 1. Sintaxe básica de regras

```bash
# Comandos básicos:
# :     Nenhuma operação (mantém a palavra original)
# l     Converter para minúsculo
# u     Converter para maiúsculo
# c     Capitalizar (primeira letra maiúscula, resto minúsculo)
# r     Inverter a string
# d     Duplicar a palavra
# f     Duplicar e inverter (palindromo)
# $X    Adicionar caractere X no final
# ^X    Adicionar caractere X no início
# sXY   Substituir X por Y
```

### 2. Exemplo de regras

```bash
# Arquivo: customrules.conf

# Regra 1: Adicionar números no final
$0 $1 $2 $3 $4 $5 $6 $7 $8 $9

# Regra 2: Capitalizar e adicionar números
c
$0 $1 $2 $3

# Regra 3: Toggle case e adicionar símbolos
T0 T1 T2
$! $@ $#

# Regra 4: Múltiplas transformações
l $1 $2 $3
u $1 $2 $3
c $1 $2 $3

# Regra 5: Adicionar ano atual
$2 $0 $2 $3  # 2023
```

### 3. Regras avançadas com pré-processamento

```bash
# Aplicar regra apenas se palavra atender a condição
>6 <8      # Apenas palavras com 7 caracteres
>3         # Mais de 3 caracteres

# Exemplo completo:
>6 <9      # Palavras com 7 ou 8 caracteres
l          # Converter para minúsculo
$1 $2 $3   # Adicionar números 1, 2, 3
```

---
## Otimização de Desempenho

### 1. Utilização de GPU

```bash
# Verificar suporte a OpenCL
john --list=opencl-devices

# Executar com GPU
john --format=raw-md5 --device=0,1 hashfile.txt

# Especificar plataforma OpenCL
john --format=nt --device=0 hashfile.txt
```
### 2. Processamento distribuído com MPI

```bash
# Configurar ambiente MPI
mpiexec -n 4 john --format=sha512crypt hashfile.txt
```

### 3. Configuração de desempenho

```bash
# Usar múltiplas threads (CPU)
john --fork=4 --format=bcrypt hashfile.txt

# Limitar uso de memória
john --format=sha512crypt --max-mem=2048 hashfile.txt
```

---
## Gerenciamento de Sessões

### 1. Trabalhando com sessões

```bash
# Iniciar sessão nomeada
john --session=meuataque --wordlist=lista.txt hashfile.txt

# Continuar sessão interrompida
john --restore=meuataque

# Ver sessões ativas
john --status=meuataque

# Parar sessão
john --session=meuataque --max-run-time=2h
```

### 2. Agendamento de ataques

```bash
# Executar apenas por 30 minutos
john --wordlist=lista.txt --max-run-time=30m hashfile.txt

# Parar após encontrar 10 senhas
john --wordlist=lista.txt --max-cands=10 hashfile.txt
```

---
## Extração e Gerenciamento de Resultados

### 1. Mostrar senhas recuperadas

```bash
# Ver conteúdo do arquivo pot
cat ~/.john/john.pot

# Limpar arquivo pot
rm ~/.john/john.pot

# Converter formato do pot
john --pot=novo.pot --format=raw-md5 hashfile.txt
```

### 2. Arquivo de pot (`john.pot`)

```bash
# Ver conteúdo do arquivo pot
cat ~/.john/john.pot

# Limpar arquivo pot
rm ~/.john/john.pot

# Converter formato do pot
john --pot=novo.pot --format=raw-md5 hashfile.txt
```

---
## Scripts de Automação

### 1. Script básico de auditoria

```bash
#!/bin/bash
# audit_passwords.sh

HASH_FILE="$1"
WORDLIST="/usr/share/wordlists/rockyou.txt"
RULES_FILE="customrules.conf"
SESSION_NAME="audit_$(date +%Y%m%d_%H%M%S)"

echo "[*] Iniciando auditoria de senhas..."
echo "[*] Arquivo de hash: $HASH_FILE"
echo "[*] Sessão: $SESSION_NAME"

# Fase 1: Ataque com dicionário básico
echo "[*] Fase 1: Ataque de dicionário básico"
john --wordlist=$WORDLIST --session=$SESSION_NAME $HASH_FILE

# Fase 2: Ataque com regras
echo "[*] Fase 2: Ataque com regras personalizadas"
john --wordlist=$WORDLIST --rules=$RULES_FILE --session=$SESSION_NAME $HASH_FILE

# Fase 3: Ataque com máscara
echo "[*] Fase 3: Ataque com máscara (8 caracteres alfanuméricos)"
john --mask=?l?l?l?l?l?l?l?l --session=$SESSION_NAME $HASH_FILE

# Mostrar resultados
echo "[*] Resultados encontrados:"
john --show $HASH_FILE
```

### 2. Monitoramento de progresso

```bash
#!/bin/bash
# monitor_john.sh

SESSION="$1"

while true; do
    clear
    echo "=== Monitoramento John the Ripper ==="
    echo "Sessão: $SESSION"
    echo "Data/Hora: $(date)"
    echo ""
    
    # Status da sessão
    john --status=$SESSION 2>/dev/null || echo "Sessão não encontrada"
    
    # Últimas senhas encontradas
    echo ""
    echo "=== Últimas senhas recuperadas ==="
    tail -20 ~/.john/john.pot 2>/dev/null || echo "Nenhuma senha encontrada ainda"
    
    sleep 30
done
```

---
## Melhores Práticas e Considerações Legais

### 1. Considerações Legais

- **Só utilize em sistemas que você possui autorização explícita**
- Obtenha autorização por escrito antes de testar
- Conheça as leis locais sobre teste de segurança
- Use apenas em ambientes controlados/laboratórios

### 2. Boas Práticas Técnicas

1. **Comece com ataques de dicionário** antes de ataques brutos
2. **Use regras personalizadas** baseadas na política de senhas
3. **Priorize formatos fracos** primeiro
4. **Documente todos os testes** realizados
5. **Mantenha logs** detalhados das atividades

### 3. Otimização de Recursos

```bash
# Ordem recomendada de ataques:
# 1. Dicionário sem regras
john --wordlist=lista.txt hashfile.txt

# 2. Dicionário com regras leves
john --wordlist=lista.txt --rules=Wordlist hashfile.txt

# 3. Dicionário com regras pesadas
john --wordlist=lista.txt --rules=Jumbo hashfile.txt

# 4. Modo single crack
john --single hashfile.txt

# 5. Ataque com máscara (curtas)
john --mask=?l?l?l?l?l?l hashfile.txt

# 6. Modo incremental (último recurso)
john --incremental hashfile.txt
```

---
## Solução de Problemas Comuns

### 1. Problemas de formato

```bash
# Erro: "No password hashes loaded"
# Solução: Especificar formato corretamente
john --format=sha512crypt --wordlist=lista.txt hashfile.txt

# Verificar se o hash é reconhecido
john --test --format=raw-md5
```

### 2. Problemas de desempenho

```bash
# Se estiver muito lento:
# 1. Reduzir threads
john --fork=2 hashfile.txt

# 2. Usar ataque mais direcionado
john --mask=?l?l?l?l?d?d hashfile.txt  # 4 letras + 2 dígitos
```

### 3. Problemas com sessão

```bash
# Se sessão não restaurar:
# Remover arquivos de sessão corrompidos
rm ~/.john/john.rec
rm ~/.john/john.log
```

---
## Referências

### 1. Documentação Oficial

- Site: [https://www.openwall.com/john/](https://www.openwall.com/john/)
- Repositório GitHub: [https://github.com/openwall/john](https://github.com/openwall/john)
- Wiki: [https://openwall.info/wiki/john](https://openwall.info/wiki/john)

### 2. Listas de palavras recomendadas

- RockYou: `/usr/share/wordlists/rockyou.txt`
- SecLists: [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)
- CrackStation: [https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm)

### 3. Comunidade e Suporte

- Lista de emails: john-users@openwall.com
- Fóruns de segurança como Hashcat/John the Ripper communities
- Stack Exchange Information Security

---

**Aviso Legal:** Este documento é apenas para fins educacionais e de pesquisa autorizada. O uso não autorizado de John the Ripper ou qualquer ferramenta de cracking de senhas é ilegal e antiético. Sempre obtenha permissão explícita por escrito antes de testar sistemas que não são de sua propriedade.
