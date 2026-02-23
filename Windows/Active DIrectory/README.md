<!-- ===================================== -->
<!--   WINDOWS ACTIVE DIRECTORY - GUIDE   -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Technical%20Guide-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Platform-Windows%20Server-informational?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Scope-Enterprise%20Infrastructure-black?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Administration%20%7C%20Security-red?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Foundation%20%E2%86%92%20Advanced-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Domain-Identity%20Management-purple?style=flat-square">
</p>

---

# 🏰 Windows Active Directory (AD)
## Arquitetura, Administração e Segurança em Ambientes Corporativos

> O **Active Directory (AD)** é o núcleo da infraestrutura de identidade em ambientes Windows corporativos.
>
> Mais do que um simples serviço de diretório, ele é o **pilar central de autenticação, autorização, controle de políticas e segurança** em redes empresariais modernas.
>
> Este documento apresenta uma visão completa da arquitetura do AD, seus componentes lógicos e físicos, mecanismos de autenticação e implicações diretas na cibersegurança ofensiva e defensiva.

---

## 🎯 Objetivo do Documento

- Compreender a arquitetura interna do Active Directory
- Entender o funcionamento de domínios, florestas e trusts
- Explorar gerenciamento de usuários, grupos e computadores
- Analisar autenticação (Kerberos e NTLM)
- Entender riscos, ataques comuns e boas práticas de hardening
- Construir base sólida para Pentest em ambientes Windows

---
# Windows Active Directory (AD)

## 1. Introdução

O **Active Directory (AD)** é o serviço de diretório da Microsoft para redes Windows Server, presente na maioria das empresas de médio e grande porte. Ele funciona como uma lista telefônica centralizada que armazena informações sobre todos os recursos da rede — usuários, computadores, impressoras, servidores e aplicativos — e permite que administradores gerenciem esses recursos de forma unificada.

Em vez de criar uma conta para cada usuário em cada computador, o AD permite criar uma conta uma única vez e conceder acesso a todos os recursos que o usuário precisa. Da mesma forma, políticas de segurança podem ser definidas centralmente e aplicadas automaticamente a centenas ou milhares de computadores.

![Windows Active Directory](https://www.vivantio.com/wp-content/uploads/MSAD.png)

**Principais Características:**

- **Centralização administrativa:** Gerenciamento de usuários, permissões e dispositivos em um único ponto
- **Segurança baseada em políticas:** Aplicação consistente de regras em toda a organização
- **Alta disponibilidade:** Múltiplos controladores de domínio para redundância
- **Escalabilidade:** Suporte desde pequenas empresas até ambientes enterprise com milhares de objetos

---
## 2. Domínios do Windows

### 2.1 O que é um Domínio?

Um **domínio Windows** é um agrupamento lógico de recursos de rede (usuários, computadores, servidores) que compartilham um banco de dados centralizado de diretório e políticas de segurança. Pense em um domínio como um "reino" onde o Active Directory é o "rei" que governa todos os recursos.

![Windows Domains](https://spca.education/wp-content/uploads/2024/01/WSDADS.webp)

**Características principais:**

- **Banco de dados centralizado:** Todas as contas e configurações ficam armazenadas em controladores de domínio
- **Autenticação única (Single Sign-On/SSO):** Usuários fazem login uma vez e acessam todos os recursos autorizados
- **Gerenciamento unificado:** Administradores gerenciam todo o domínio a partir de ferramentas centrais
- **Namespace DNS:** Utiliza nomes de domínio DNS (ex: empresa.local)

### 2.2 Controladores de Domínio (Domain Controllers)

Um **Controlador de Domínio (DC)** é um servidor que executa o Active Directory e armazena uma cópia do banco de dados do domínio. Suas funções incluem:

- **Autenticação:** Verifica credenciais de usuários que fazem login
- **Autorização:** Determina quais recursos os usuários podem acessar
- **Replicação:** Sincroniza alterações com outros controladores de domínio
- **Serviços de diretório:** Responde a consultas sobre objetos no domínio

**Práticas recomendadas:**

- Ter pelo menos dois controladores de domínio por domínio para redundância
- Distribuir controladores em locais físicos diferentes para resiliência    
- Manter os controladores atualizados e com configurações de segurança reforçadas

### 2.3 Estrutura de Nomes de Domínio

Os domínios Windows usam o mesmo formato de nomenclatura da internet (DNS):

```text
exemplo.com
filial.exemplo.com
departamento.filial.exemplo.com
```

---
## 3. Active Directory (AD)

### 3.1 Definição e Arquitetura

O **Active Directory Domain Services (AD DS)** é o serviço principal que fornece os métodos para armazenar dados de diretório e disponibilizá-los para usuários e administradores da rede. O AD DS armazena informações como:

- **Contas de usuário:** Nomes, senhas, grupos, permissões
- **Contas de computador:** Nomes, endereços IP, localização
- **Compartilhamentos e impressoras:** Recursos disponíveis na rede
- **Políticas de grupo:** Configurações que controlam o comportamento de usuários e computadores

### 3.2 Componentes Lógicos

Os componentes lógicos ajudam a organizar os recursos do AD:

|Componente|Descrição|Exemplo|
|---|---|---|
|**Domínio**|Unidade administrativa principal|`empresa.local`|
|**Unidade Organizacional (OU)**|Contêiner para organizar objetos|`Vendas`, `TI`, `RH`|
|**Árvore**|Conjunto de domínios com namespace contíguo|`vendas.empresa.local`, `ti.empresa.local`|
|**Floresta**|Conjunto de árvores que compartilham esquema e catálogo global|`empresa.local`, `filial.com`|

### 3.3 Componentes Físicos

- **Controlador de Domínio (DC):** Servidor que armazena o AD
- **Site:** Conjunto de sub-redes IP bem conectadas (geralmente uma localização física)
- **Catálogo Global (GC):** Índice de todos os objetos da floresta para buscas rápidas

---
## 4. Gerenciando Usuários no AD

### 4.1 Contas de Usuário

Cada usuário em um domínio precisa de uma conta para acessar recursos. Uma conta de usuário contém:

- **Nome de login:** `joao.silva` ou `joao.silva@empresa.local`
- **Informações pessoais:** Nome completo, cargo, departamento
- **Credenciais:** Senha (armazenada com hash)
- **Associações de grupo:** Grupos aos quais o usuário pertence
- **Perfil:** Caminho para perfil, script de login, pasta home

### 4.2 Criando Usuários

**Pelo Console AD (Interface Gráfica):**

1. Abra "Usuários e Computadores do Active Directory"

![Active Directory Users and Computers](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/11d01963392078c1450300d2881f9160.png)

2. Navegue até a OU desejada
3. Clique com botão direito → "Novo" → "Usuário"
4. Preencha as informações e defina a senha

**Pelo PowerShell:**

```powershell
New-ADUser -Name "João Silva" `
    -SamAccountName "joao.silva" `
    -UserPrincipalName "joao.silva@empresa.local" `
    -Path "OU=Funcionarios,DC=empresa,DC=local" `
    -AccountPassword (ConvertTo-SecureString "Senha@123" -AsPlainText -Force) `
    -Enabled $true
```

### 4.3 Grupos de Usuários

Grupos simplificam a administração ao permitir atribuir permissões a vários usuários de uma vez.

**Tipos de grupo:**

| Tipo             | Escopo                           | Descrição                                            |
| ---------------- | -------------------------------- | ---------------------------------------------------- |
| **Segurança**    | Domínio local, Global, Universal | Usado para atribuir permissões                       |
| **Distribuição** | Domínio local, Global, Universal | Usado para listas de e-mail (não atribui permissões) |

**Escopos de grupo:**

| Escopo            | Características                            | Uso típico                            |
| ----------------- | ------------------------------------------ | ------------------------------------- |
| **Global**        | Contém usuários do mesmo domínio           | Agrupar usuários por função           |
| **Domínio Local** | Contém grupos globais de qualquer domínio  | Atribuir permissões a recursos locais |
| **Universal**     | Contém usuários/grupos de qualquer domínio | Permissões em múltiplos domínios      |

**Prática recomendada (AGDLP):**

1. **A**dicionar usuários a **G**rupos globais (por função)
2. Adicionar grupos globais a **D**omínio **L**ocal (por recurso)
3. Atribuir **P**ermissões aos grupos domínio local

![Grupo de usuários](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1751295060689.png)

### 4.4 Contas de Computador

Assim como usuários, computadores também têm contas no AD. Quando um computador ingressa no domínio, uma conta é criada e estabelece um relacionamento de confiança com o controlador de domínio.

O nome da conta da máquina é o nome do computador seguido de um cifrão (`$`). Por exemplo, uma máquina chamada `DC01` terá uma conta de máquina chamada `DC01$`.

> **Observação:** as senhas das contas de máquina são rotacionadas automaticamente e geralmente são compostas por 120 caracteres aleatórios.

### 4.5 Excluindo UOs e usuários extras

#### Proteção Contra Exclusão Acidental

O Active Directory implementa um mecanismo de segurança denominado **"Proteger objeto contra exclusão acidental"** como padrão para todas as Unidades Organizacionais. Esta proteção é fundamental para evitar remoções não intencionais de estruturas organizacionais que podem conter centenas ou milhares de objetos.

Ao tentar excluir uma OU sem desabilitar esta proteção, o sistema retorna a seguinte mensagem de erro:

![Mensagem de erro](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/38edaf4a8665c257c62556096c69cb6f.png)

A mensagem indica que o objeto está protegido e não pode ser removido enquanto esta configuração permanecer ativa.

#### Habilitando Recursos Avançados

Para modificar a proteção contra exclusão, é necessário primeiro habilitar os **Recursos Avançados** no console "Usuários e Computadores do Active Directory":

![Recursos Avançados](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/15b282b6e3940f4c26c477a8c21f8266.png)

**Passos:**

1. No menu superior, clique em **Exibir (View)**
2. Selecione a opção **Recursos Avançados (Advanced Features)**

Esta ação revela contêineres de sistema adicionais e abas de configuração normalmente ocultas, incluindo a aba **Objeto** nas propriedades.

#### Desabilitando a Proteção

Com os Recursos Avançados ativados:

1. Clique com o botão direito na OU que deseja excluir
2. Selecione **Propriedades (Properties)**
3. Navegue até a aba **Objeto (Object)**

![Guia de objetos](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/ad6b6d886c0448d14ce4ec8c62250256.png)

Na aba **Objeto**, localize a opção:

- **"Proteger objeto contra exclusão acidental"** (ou "Protect object from accidental deletion")

Desmarque esta caixa de seleção e confirme com **OK**.

#### Exclusão da OU e Consequências

Após desabilitar a proteção:

1. Clique com o botão direito na OU
2. Selecione **Excluir (Delete)**
3. O sistema solicitará confirmação da exclusão

**⚠️ Atenção:** A exclusão de uma Unidade Organizacional é uma operação **recursiva e irreversível** através da interface gráfica padrão. Todos os objetos contidos na OU serão permanentemente removidos, incluindo:

- **Usuários** (contas de usuário) 
- **Grupos** (de segurança e distribuição)
- **Computadores** (contas de máquina)
- **Sub-OUs** (toda a hierarquia abaixo)

#### Alternativa via PowerShell

Para ambientes que exigem automação ou exclusão em massa, é possível utilizar o PowerShell com o módulo Active Directory:

```powershell
# Verificar proteção atual
Get-ADOrganizationalUnit -Identity "OU=Vendas,DC=empresa,DC=local" -Properties ProtectedFromAccidentalDeletion

# Desabilitar proteção via PowerShell
Set-ADOrganizationalUnit -Identity "OU=Vendas,DC=empresa,DC=local" -ProtectedFromAccidentalDeletion $false

# Excluir OU e todo seu conteúdo
Remove-ADOrganizationalUnit -Identity "OU=Vendas,DC=empresa,DC=local" -Recursive -Confirm:$false
```

**Parâmetros importantes:**

- `-Recursive`: Remove todos os objetos contidos na hierarquia
- `-Confirm:$false`: Suprime confirmações (uso com cautela)

#### Recuperação de OUs Excluídas

Em caso de exclusão acidental, a recuperação é possível através da **Lixeira do Active Directory** (se habilitada):

```powershell
# Verificar objetos excluídos
Get-ADObject -Filter 'isDeleted -eq $true -and name -like "*Vendas*"' -IncludeDeletedObjects

# Restaurar OU excluída
Restore-ADObject -Identity "DN_do_objeto_excluído"
```

> **Nota:** A Lixeira do AD deve estar habilitada **antes** da exclusão e só está disponível em níveis funcionais de floresta Windows Server 2008 R2 ou superiores.

### 4.6 Delegação de Controle

#### Conceito de Delegação

A **delegação** é um mecanismo fundamental do Active Directory que permite atribuir privilégios administrativos específicos a usuários ou grupos sem conceder direitos de Administrador de Domínio. Este recurso implementa o princípio do menor privilégio, onde cada usuário recebe apenas as permissões necessárias para executar suas funções.

**Principais aplicações da delegação:**

- Reset de senhas para departamentos específicos 
- Gerenciamento de associações a grupos
- Criação/exclusão de contas em UOs determinadas
- Modificação de atributos específicos (telefone, endereço, cargo)
- Bloqueio/desbloqueio de contas de usuário

#### Cenário Prático: Delegação de Reset de Senha

Em nosso cenário, Phillip é responsável pelo suporte de TI e precisa redefinir senhas dos usuários nos departamentos de Vendas, Marketing e Gerenciamento. Em vez de conceder privilégios de administrador, delegaremos a ele o controle específico sobre a UO de Vendas.

##### Passo 1: Acessar o Assistente de Delegação

Para iniciar o processo, localize a UO desejada no console **Usuários e Computadores do Active Directory**, clique com o botão direito e selecione **"Delegar Controle..."**:


![Delegate Control](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/74f8d615658a03aeb1cfdb6767d0a0a3.png)

##### Passo 2: Selecionar Usuários ou Grupos

O assistente exibirá uma janela para especificar quais usuários ou grupos receberão os privilégios delegados:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2814715e1dbadaef334973028e02da69.png)

**Procedimento:**

1. Digite o nome do usuário (ex: "phillip")
2. Clique no botão **"Verificar Nomes"** (Check Names)
3. O Windows validará e completará automaticamente o nome com o formato correto (DOMÍNIO\nome)
4. Clique em **OK** para confirmar

##### Passo 3: Definir Tarefas a Serem Delegadas

Na próxima tela, selecione as permissões específicas que serão concedidas:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/3f81df2b38e35ca5729aee7a76c6b220.png)

**Opção recomendada para este cenário:**

- **"Redefinir senhas de usuários e forçar alteração no próximo logon"**

Alternativamente, você pode selecionar **"Criar uma tarefa personalizada"** para delegar permissões mais granulares, como:

- Criar/excluir contas de usuário
- Modificar associações a grupos
- Ler todas as informações do usuário

##### Passo 4: Concluir a Delegação

Avance pelas telas restantes clicando em **"Avançar"** e finalize com **"Concluir"**. A delegação será aplicada imediatamente.

#### Verificação e Teste da Delegação

Após a delegação, é importante testar se as permissões foram corretamente aplicadas.

#### Utilizando PowerShell para Testar

Phillip não possui permissão para abrir o console gráfico "Usuários e Computadores do Active Directory". Em vez disso, deve utilizar o módulo PowerShell do Active Directory:

```Powershell
# Redefinir senha da usuária Sophie (na UO Vendas)
Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose

# Saída esperada:
New Password: *********
VERBOSE: Performing the operation "Set-ADAccountPassword" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".
```

##### Forçar Alteração de Senha no Próximo Logon

Após redefinir a senha, é recomendável forçar o usuário a alterá-la no próximo acesso, garantindo que apenas o próprio usuário conheça sua nova senha:

```Powershell
# Forçar alteração de senha no próximo logon
Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose

# Saída esperada:
VERBOSE: Performing the operation "Set" on target "CN=Sophie,OU=Sales,OU=THM,DC=thm,DC=local".
```

#### Verificando Delegações Existentes

Para auditar quais delegações foram aplicadas a uma UO:

1. **Via Interface Gráfica:**
    - Ative **Recursos Avançados** (Exibir → Recursos Avançados)
    - Acesse Propriedades da UO → Aba **Segurança**
    - Clique em **Avançado** para visualizar permissões específicas

2. **Via PowerShell:**

```powershell
# Visualizar permissões delegadas na UO Vendas
Get-Acl -Path "AD:OU=Vendas,DC=empresa,DC=local" | 
    Select-Object -ExpandProperty Access | 
    Where-Object {$_.IdentityReference -like "*phillip*"}
```

#### Boas Práticas em Delegação

1. **Grupos em vez de usuários:** Delegue para grupos de segurança, não para usuários individuais (facilita manutenção)
2. **Escopo mínimo:** Delegue apenas as permissões estritamente necessárias
3. **Documentação:** Mantenha registro de todas as delegações implementadas
4. **Revisão periódica:** Audite delegações trimestralmente para remover privilégios obsoletos
5. **Separação de funções:** Evite delegar poderes conflitantes ao mesmo usuário

#### Removendo Delegações

Caso necessário, as delegações podem ser removidas:

```powershell
# Remover permissões específicas de Phillip na UO Vendas
$ouPath = "AD:OU=Vendas,DC=empresa,DC=local"
$acl = Get-Acl $ouPath
$acl.Access | Where-Object {$_.IdentityReference -like "*phillip*"} | 
    ForEach-Object { $acl.RemoveAccessRule($_) }
Set-Acl -Path $ouPath -AclObject $acl
```

> **Nota:** A remoção de delegações deve ser realizada com cautela e preferencialmente durante janelas de manutenção programada.

---
## 5. Gerenciando Computadores no AD

Por padrão, todas as máquinas que ingressam em um domínio (exceto os controladores de domínio) serão colocadas no contêiner chamado "Computadores". Se verificarmos nosso controlador de domínio, veremos que alguns dispositivos já estão lá:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/a1d41d5437e73d62ede10f2015dc4dfc.png)

Podemos ver alguns servidores, alguns laptops e alguns PCs correspondentes aos usuários da nossa rede. Ter todos os nossos dispositivos juntos não é a melhor ideia, já que é muito provável que você queira políticas diferentes para seus servidores e para as máquinas que os usuários comuns utilizam diariamente.

Embora não exista uma regra de ouro sobre como organizar suas máquinas, um excelente ponto de partida é segregar os dispositivos de acordo com seu uso.

### 5.1 Ingressando Computadores no Domínio

**Windows 10/11:**

1. Configurações → Sistema → Sobre
2. Clique em "Renomear este PC (avançado)"
3. Em "Membro de", selecione "Domínio" e digite o nome do domínio
4. Forneça credenciais de administrador do domínio
5. Reinicie o computador

**PowerShell:**

```powershell
Add-Computer -DomainName "empresa.local" -Credential EMPRESA\Administrador -Restart
```

### 5.2 Movendo Computadores entre OUs

Computadores podem ser organizados em OUs para facilitar a aplicação de políticas:

```powershell
# Mover computador para OU específica
Move-ADObject -Identity "CN=PC-123,CN=Computers,DC=empresa,DC=local" -TargetPath "OU=SetorVendas,DC=empresa,DC=local"
```

### 5.3 Gerenciamento Remoto

Com o AD, administradores podem gerenciar computadores remotamente usando ferramentas como:

- **Gerenciamento de Computador** (conexão remota)    
- **PowerShell Remoto** (`Enter-PSSession`)
- **Conexão de Área de Trabalho Remota** (RDP)

### 5.3 Controladores de Domínio

Os Controladores de Domínio são o terceiro dispositivo mais comum em um domínio do Active Directory. Eles permitem gerenciar o domínio do Active Directory. Esses dispositivos são frequentemente considerados os mais sensíveis da rede, pois contêm as senhas criptografadas de todas as contas de usuário no ambiente.

### 5.4 Estações de trabalho

As estações de trabalho são um dos dispositivos mais comuns em um domínio do Active Directory. Cada usuário do domínio provavelmente fará login em uma estação de trabalho. Este é o dispositivo que eles usarão para realizar seu trabalho ou atividades normais de navegação. Esses dispositivos nunca devem ter um usuário com privilégios de administrador conectado a eles.

### 5.6 Servidores

Os servidores são o segundo tipo de dispositivo mais comum em um domínio do Active Directory. Os servidores geralmente são usados ​​para fornecer serviços a usuários ou outros servidores.

---
## 6. Políticas de Grupo (Group Policy)

### 6.1 O que são Políticas de Grupo?

**Política de Grupo (Group Policy)** é um recurso do Windows que permite definir configurações e regras para usuários e computadores em um ambiente Active Directory. As configurações são agrupadas em **Objetos de Política de Grupo (GPOs)** e aplicadas a usuários e computadores com base em sua localização no AD.

A Política de Grupo é essencial porque permite:

- **Controle centralizado:** Gerencie configurações de milhares de computadores de um único local
- **Consistência:** Garanta que todos os sistemas sigam os mesmos padrões
- **Segurança:** Aplique políticas de senha, bloqueios de conta e restrições de software
- **Automação:** Implante software, scripts e configurações sem intervenção manual

### 6.2 Componentes da Política de Grupo

| Componente                                 | Descrição                                                     |
| ------------------------------------------ | ------------------------------------------------------------- |
| **GPO (Group Policy Object)**              | Contêiner que armazena as configurações de política           |
| **Link**                                   | Associação entre um GPO e um contêiner AD (domínio, OU, site) |
| **GPMC (Group Policy Management Console)** | Ferramenta para criar e gerenciar GPOs                        |
| **ADMX/ADML**                              | Arquivos de modelo que definem as configurações disponíveis   |

### 6.3 Configurações de Computador vs. Usuário

Cada GPO tem duas seções principais:

| Configuração                   | Quando aplicada          | Exemplos                                                                    |
| ------------------------------ | ------------------------ | --------------------------------------------------------------------------- |
| **Configuração do Computador** | Inicialização do sistema | Configurações de firewall, scripts de inicialização, políticas de segurança |
| **Configuração do Usuário**    | Login do usuário         | Mapeamento de unidades, configurações de área de trabalho, scripts de logon |

### 6.4 Políticas vs. Preferências

É importante entender a diferença:

|Aspecto|Políticas (Policies)|Preferências (Preferences)|
|---|---|---|
|**Aplicação**|Obrigatória, não pode ser alterada pelo usuário|Opcional, usuário pode modificar|
|**Uso típico**|Segurança, conformidade (senhas, restrições)|Experiência do usuário (drives mapeados, impressoras)|
|**Reaplicação**|Sim, em intervalos regulares|Apenas no login (a menos que configurado)|

### 6.5 Criando e Gerenciando GPOs (Group Policy Objects)

#### Instalando a Console de Gerenciamento de Política de Grupo (GPMC)

A **Group Policy Management Console (GPMC)** é a ferramenta principal para administrar GPOs em um ambiente Active Directory. Sua instalação varia conforme o sistema operacional.

##### No Windows Server

A GPMC está disponível como um recurso instalável via Server Manager:

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/b19052c41e27fbbb2651038cede63e11.png)

**Procedimento:**

1. Abra o **Server Manager**
2. Navegue até **Manage** → **Add Roles and Features**
3. Avance até a seção **Features**
4. Localize e selecione **Group Policy Management**
5. Complete o assistente para finalizar a instalação

##### No Windows 10/11 (Estações de Trabalho)

Para gerenciar GPOs a partir de estações de trabalho, instale as **Ferramentas de Administração de Servidor Remoto (RSAT)**:

**Procedimento:**

1. Acesse **Configurações** → **Aplicativos** → **Recursos opcionais**
2. Clique em **Adicionar um recurso**
3. Pesquise e selecione **RSAT: Group Policy Management Tools**
4. Aguarde a instalação e reinicie se necessário

#### Criação de Objetos de Política de Grupo

##### Via Interface Gráfica (GPMC)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d82cb9440894c831f6f3d58a2b0538ed.png)

**Passos para criar e vincular um GPO:**

1. Abra a **Group Policy Management Console**
2. Expanda a floresta e o domínio desejado
3. Navegue até **Group Policy Objects** (para criação) ou diretamente na OU (para criação com vínculo)
4. Clique com botão direito na OU onde o GPO será aplicado
5. Selecione **Create a GPO in this domain, and Link it here...**
6. Atribua um nome descritivo ao GPO (ex: "Política de Segurança - Estações de Trabalho")
7. Clique em **OK**

**Estrutura visualizada na imagem acima:**

- **Default Domain Policy:** Vinculada ao domínio `thm.local` (configurações globais)
- **RDP Policy:** Vinculada ao domínio `thm.local` (configurações de Remote Desktop)
- **Default Domain Controllers Policy:** Vinculada à OU "Domain Controllers" (específica para DCs)

##### Via PowerShell

```powershell
# Criar um novo GPO (sem vínculo)
New-GPO -Name "Política de Senhas Fortes" `
    -Comment "Define requisitos de complexidade e comprimento mínimo de senha"

# Vincular o GPO a uma OU específica
New-GPLink -Name "Política de Senhas Fortes" `
    -Target "OU=Funcionarios,DC=empresa,DC=local"

# Criar e vincular em um único comando (versão simplificada)
New-GPO -Name "Restrição de Acesso" | 
    New-GPLink -Target "OU=Servidores,DC=empresa,DC=local"
```

#### Anatomia de um GPO

##### Aba Escopo (Scope)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/06d5e70fbfa648f73e4598e18c8e9527.png)

A aba **Escopo** exibe três informações críticas:

**1. Links:** Onde o GPO está vinculado na hierarquia do AD

- Domínio, OUs específicas ou sites
- Ordem de link (prioridade)

**2. Filtragem de Segurança:** Quem recebe as configurações do GPO

- Por padrão: grupo **Authenticated Users** (todos os usuários e computadores autenticados)
- Recomendação: Remover "Authenticated Users" e adicionar grupos específicos (ex: "Domain Computers", "Vendas_Users")

**3. Filtragem WMI:** Aplica o GPO apenas a sistemas que atendem a determinadas condições

- Exemplo: Apenas Windows 10 ou superior
- Exemplo: Apenas laptops

##### Aba Configurações (Settings)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/c9293853549d5126b77bf2de8086e076.png)

Esta aba exibe o conteúdo real do GPO, dividido em duas seções principais:

**Configurações do Computador:**

- Aplicadas durante a inicialização do sistema
- Políticas de segurança, configurações de firewall, scripts de inicialização

**Configurações do Usuário:**

- Aplicadas durante o logon do usuário
- Mapeamento de unidades, redirecionamento de pastas, scripts de logon

Na imagem, a **Default Domain Policy** contém apenas configurações de computador, especificamente políticas de conta (senha e bloqueio).

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/a5f4c2605062934579c64f2cfa025308.png)

#### Edição de GPOs

##### Acessando o Editor

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/b71d8de9e74d129d0ad4142863deadc4.png)

Para modificar um GPO:

1. Localize o GPO na GPMC
2. Clique com botão direito sobre ele
3. Selecione **Edit...**
4. O **Group Policy Management Editor** será aberto

##### Exemplo Prático: Alterando Política de Senha

Navegue até o caminho:

```text
Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/bd3665c2569aa8fbe4f7482a5750f018.png)

**Configurações disponíveis:**

- **Enforce password history:** Número de senhas únicas antes de reutilizar
- **Maximum password age:** Dias até expiração (recomendado: 60-90)
- **Minimum password age:** Dias mínimos antes de alterar (recomendado: 1-2)
- **Minimum password length:** Caracteres mínimos (recomendado: 14+)
- **Password must meet complexity requirements:** Exige maiúsculas, minúsculas, números, especiais
- **Store passwords using reversible encryption:** Desabilitado (alto risco)

##### Utilizando a Guia Explicar

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/de35e7c03fafcb5b9df5457181e32652.png)

Para cada configuração, a guia **Explicar** (Explain) fornece:

- Descrição técnica detalhada
- Impacto da configuração
- Recomendações de implementação
- Requisitos de versão do Windows

### 6.6 Hierarquia e Prioridade de GPOs

#### Ordem de Aplicação

Os GPOs são aplicados na seguinte ordem (do menor para o maior precedência):

1. **Política Local** (aplicada no computador individual)
2. **Site** (todos os computadores em um site do AD)
3. **Domínio** (todos os usuários/computadores do domínio)
4. **Unidade Organizacional (OU)** (objetos na OU específica)
5. **Sub-OU** (objetos em OUs aninhadas)

**Regra geral:** O último a ser aplicado "ganha" em caso de conflito.

#### Herança

Por padrão, GPOs aplicados a um contêiner pai são herdados pelos contêineres filhos. Por exemplo, um GPO vinculado ao domínio afeta todas as OUs e sub-OUs dentro dele.

#### Modificadores de Prioridade

| Modificador           | Efeito                                        | Ícone na GPMC       |
| --------------------- | --------------------------------------------- | ------------------- |
| **Forced (Enforced)** | Impede que GPOs filhos substituam este GPO    | Cadeado             |
| **Block Inheritance** | Bloqueia herança de GPOs de níveis superiores | Ponto de exclamação |

**Nota:** GPOs marcados como **Forced** têm prioridade máxima e não são bloqueados por **Block Inheritance**.

### 6.7 Filtragem de GPOs

#### Filtro de Segurança (Security Filtering)

Permite aplicar o GPO apenas a grupos de segurança específicos:

1. Na GPMC, selecione o GPO
2. Na aba **Scope**, em **Security Filtering**
3. Adicione ou remova grupos/usuários

Por padrão, o grupo **Authenticated Users** recebe o GPO. É recomendável remover este grupo e adicionar grupos específicos.

#### Filtros WMI

Permite aplicar GPOs com base em atributos do sistema, como:

- Versão do Windows
- Memória disponível
- Tipo de processador
- Se é notebook ou desktop    

**Exemplo de filtro WMI para Windows 10:**

```text
SELECT * FROM Win32_OperatingSystem WHERE Version LIKE "10.%"
```

### 6.8 Exemplos Práticos de Políticas

#### Política de Senhas Fortes

```text
Computer Configuration → Policies → Windows Settings → Security Settings → Account Policies → Password Policy
```

Configurações comuns:

- **Maximum password age:** 60 dias
- **Minimum password length:** 8 caracteres
- **Password must meet complexity requirements:** Enabled

#### Mapeamento Automático de Unidades

```text
User Configuration → Preferences → Windows Settings → Drive Maps
```

Criar uma nova unidade mapeada:

- **Action:** Create
- **Location:** `\\servidor\compartilhamento`
- **Drive Letter:** `Z:`    
- **Label:** "Documentos Compartilhados"

#### Restringindo Acesso ao Painel de Controle

```text
User Configuration → Policies → Administrative Templates → Control Panel
```

- **Prohibit access to Control Panel and PC settings:** Enabled    

#### Script de Logon

```text
User Configuration → Policies → Windows Settings → Scripts → Logon
```

Adicionar script `logon.bat` que será executado quando o usuário fizer login.

### 6.9 Atualização e Diagnóstico de GPOs

#### Atualização Manual

```text
# Forçar atualização de política
gpupdate /force

# Atualizar e reiniciar (para configurações de computador)
gpupdate /force /boot
```

#### Diagnosticando Políticas Aplicadas

```shell
# Visualizar políticas aplicadas (resumo)
gpresult /r

# Visualizar políticas aplicadas (detalhado)
gpresult /h C:\relatorio.html

# Modo RSoP (Resultant Set of Policy)
rsop.msc
```

### 6.10 Boas Práticas com GPOs

1. **Nomeie GPOs descritivamente:** "Política de Senha - Domínio" em vez de "GPO123"
2. **Desabilite configurações não usadas:** Se um GPO só tem configurações de computador, desabilite a parte de usuário para melhor performance
3. **Use OUs para organizar:** Vincule GPOs ao nível mais baixo possível
4. **Documente alterações:** Mantenha um registro de mudanças em GPOs
5. **Teste antes de aplicar:** Use uma OU de teste com poucos usuários
6. **Faça backups regulares:** Backup dos GPOs via GPMC ou PowerShell

### 6.11 Distribuição de GPO

As GPOs são distribuídas na rede por meio de um compartilhamento de rede chamado SYSVOL, armazenado no Controlador de Domínio (DC). Normalmente, todos os usuários de um domínio devem ter acesso a esse compartilhamento pela rede para sincronizar suas GPOs periodicamente. O compartilhamento SYSVOL aponta, por padrão, para o diretório C:\Windows\SYSVOL\sysvol\ em cada um dos DCs da nossa rede.

Após uma alteração em qualquer GPO, pode levar até 2 horas para que os computadores sejam atualizados. Se você quiser forçar a sincronização imediata das GPOs de um computador específico, você pode executar o seguinte comando no computador desejado:

```powershell
gpupdate /force
```

---
## 7. Métodos de Autenticação

### 7.1 Kerberos

O **Kerberos** é o protocolo de autenticação primário no Active Directory desde o Windows 2000, substituindo o NTLM como mecanismo padrão. Baseado no modelo MIT Kerberos versão 5, oferece autenticação mútua robusta através de criptografia e tickets com validade temporal.
#### Arquitetura e Componentes

**Componentes Fundamentais:**

| Componente                  | Sigla | Descrição                                                  |
| --------------------------- | ----- | ---------------------------------------------------------- |
| **Key Distribution Center** | KDC   | Serviço central no DC que emite tickets (combina AS + TGS) |
| **Authentication Service**  | AS    | Autentica usuários e emite TGTs                            |
| **Ticket Granting Service** | TGS   | Emite tickets para serviços específicos                    |
| **Ticket Granting Ticket**  | TGT   | Ticket de autenticação inicial                             |
| **Service Ticket**          | TGS   | Ticket para acesso a um serviço específico                 |
| **Service Principal Name**  | SPN   | Identificador único do serviço no formato `SERVICE/HOST`   |
| **krbtgt account**          | -     | Conta cujo hash é usado para criptografar TGTs             |

#### Fluxo de Autenticação Kerberos

##### Fase 1: Aquisição do TGT (Authentication Service Exchange)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/d36f5a024c20fb480cdae8cd09ddc09f.png)

**Processo detalhado:**

1. **AS-REQ (Authentication Service Request):**
    - Cliente envia ao KDC (no DC) uma mensagem contendo:
        - Identificador do usuário (sAMAccountName)
        - Timestamp criptografado com a chave derivada da senha do usuário
        - Informações sobre o serviço solicitado (inicialmente, o próprio TGT)

2. **AS-REP (Authentication Service Reply):**    
    - KDC valida o timestamp (prova de conhecimento da senha)
    - KDC gera:
        - **TGT:** Contém identificador do usuário, chave de sessão, timestamps de validade
        - Criptografado com o hash da conta **krbtgt** (não com a senha do usuário)
    - KDC retorna:
        - TGT (não legível pelo usuário)
        - Chave de sessão (criptografada com a senha do usuário)

> **Nota técnica:** O TGT contém internamente uma cópia da chave de sessão, permitindo que o KDC recupere esta informação sem armazenamento persistente, simplesmente descriptografando o TGT quando necessário.

##### Fase 2: Aquisição do TGS (Ticket Granting Service Exchange)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/84504666e78373c613d3e05d176282dc.png)

**Processo detalhado:**

1. **TGS-REQ (Ticket Granting Service Request):**
    - Cliente envia ao KDC:
        - **TGT** (criptografado com chave do krbtgt)
        - **Autenticador:** Timestamp criptografado com a chave de sessão
        - **SPN:** Identificador do serviço desejado (ex: `cifs/servidor.empresa.local`)

2. **TGS-REP (Ticket Granting Service Reply):**    
    - KDC descriptografa o TGT com hash do krbtgt, recuperando a chave de sessão
    - KDC valida o autenticador com a chave de sessão
    - KDC localiza a conta do serviço pelo SPN
    - KDC gera:
        - **TGS (Service Ticket):** Contém identificador do usuário, chave de sessão de serviço
        - Criptografado com o hash da conta do serviço (não com chave do usuário)
    - KDC retorna:
        - TGS (não legível pelo usuário)
        - Chave de sessão de serviço (criptografada com a chave de sessão original)

##### Fase 3: Apresentação ao Serviço (Application Service Exchange)

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/8fbf08d03459c1b792f3b6efa4d7f285.png)

**Processo detalhado:**

1. **AP-REQ (Application Request):**
    - Cliente envia ao servidor de destino:
        - **TGS** (criptografado com hash da conta do serviço)
        - **Autenticador:** Timestamp criptografado com chave de sessão de serviço

2. **AP-REP (Application Reply):**
    - Serviço descriptografa o TGS com seu próprio hash
    - Serviço recupera a chave de sessão de serviço do TGS
    - Serviço valida o autenticador com esta chave
    - Opcionalmente, serviço retorna autenticador próprio (autenticação mútua)

#### Características de Segurança do Kerberos

| Característica           | Descrição                                           | Benefício                         |
| ------------------------ | --------------------------------------------------- | --------------------------------- |
| **Autenticação Mútua**   | Cliente e servidor provam identidade reciprocamente | Previne ataques man-in-the-middle |
| **Tickets com Validade** | TGT: 10h (padrão), TGS: 8h                          | Limita janela de reutilização     |
| **Timestamps**           | Prevenção contra replay attacks                     | Não reutilização de tickets       |
| **Criptografia**         | AES-256, AES-128, RC4, DES                          | Confidencialidade                 |
| **Senhas não trafegam**  | Apenas hashes e tickets criptografados              | Proteção de credenciais           |

#### SPN (Service Principal Name)

O SPN é um identificador único que mapeia um serviço a uma conta específica:

**Formato:** `SERVICE_CLASS/HOST:PORTA/NOME_DO_SERVIDOR`

**Exemplos comuns:**

- `cifs/srv-files.empresa.local` - Compartilhamento de arquivos
- `http/web.empresa.local` - IIS/Web
- `MSSQLSvc/sql.empresa.local:1433` - SQL Server
- `ldap/dc01.empresa.local` - LDAP sobre TCP
- `host/estacao123.empresa.local` - Serviços diversos da máquina

### 7.2 NTLM

O **NT LAN Manager (NTLM)** é um protocolo de autenticação desafio-resposta, mantido principalmente para compatibilidade com sistemas legados e cenários onde Kerberos não é suportado.

#### Arquitetura NTLM

**Componentes:**

- **NTLM Hash:** Hash da senha do usuário (MD4 do Unicode da senha)
- **SAM (Security Account Manager):** Banco de dados local de credenciais
- **Netlogon Service:** Responsável pela comunicação com o DC

#### Fluxo de Autenticação NTLM

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/2eab5cacbd0d3e9dc9afb86169b711ec.png)

**Processo detalhado (autenticação de domínio):**

| Etapa | Descrição                | Detalhamento Técnico                                  |
| ----- | ------------------------ | ----------------------------------------------------- |
| **1** | Cliente inicia conexão   | Solicitação de autenticação ao servidor de recursos   |
| **2** | Servidor envia desafio   | Gera nonce (8 bytes aleatórios) e envia ao cliente    |
| **3** | Cliente calcula resposta | `Resposta = MD4(Desafio + NTLM_Hash + Outros dados)`  |
| **4** | Servidor encaminha       | Desafio + Resposta são enviados ao DC via Netlogon    |
| **5** | DC valida                | DC recupera NTLM hash do usuário, recalcula e compara |
| **6** | DC responde              | Resultado da autenticação (sucesso/fracasso)          |
| **7** | Servidor informa         | Resultado é repassado ao cliente                      |

**Cenário com conta local:**

- Etapas 4-6 são omitidas    
- Servidor consulta seu próprio banco SAM local
- Validação ocorre localmente sem contato com DC

#### Comparativo: Kerberos vs NTLM

| Aspecto                | Kerberos                            | NTLM                                    |
| ---------------------- | ----------------------------------- | --------------------------------------- |
| **Tipo**               | Ticket-based                        | Desafio-resposta                        |
| **Autenticação mútua** | Sim                                 | Não (apenas servidor autentica cliente) |
| **Delegação**          | Suporta (via S4U2Proxy)             | Não suporta                             |
| **Criptografia**       | Simétrica (AES, RC4)                | Hash MD4 + desafio                      |
| **Vulnerabilidades**   | Pass-the-ticket, Golden ticket      | Pass-the-hash, relay attacks            |
| **Performance**        | Alta (cache de tickets)             | Baixa (múltiplas viagens)               |
| **Proxy/Firewall**     | Requer portas específicas (88, 464) | Funciona via SMB (porta 445)            |

### 7.3 Autenticação Moderna

- **Azure AD / Microsoft Entra ID:** Autenticação em nuvem
- **MFA (Multi-Factor Authentication):** Autenticação de múltiplos fatores
- **Windows Hello for Business:** Autenticação biométrica e PIN
- **Certificados Digitais:** Autenticação baseada em PKI

---
## 8. Árvores, Florestas e Confianças (Trusts)

### 8.1 Árvores de Domínio

Uma **árvore de domínios** é uma coleção de domínios que compartilham um namespace contíguo e o mesmo esquema.

**Exemplo:**

```text
empresa.local (domínio raiz)
├── vendas.empresa.local (domínio filho)
├── ti.empresa.local (domínio filho)
└── rh.empresa.local (domínio filho)
```

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/abea24b7979676a1dcc0c568054544c8.png)

### 8.2 Florestas

Uma **floresta** é o contêiner de nível mais alto no Active Directory. Ela contém uma ou mais árvores de domínio que compartilham:

- **Esquema comum:** Definições de objetos e atributos
- **Catálogo global:** Índice de todos os objetos da floresta
- **Configuração:** Informações sobre a estrutura da floresta

**Floresta de domínio único:** A configuração mais comum em pequenas/médias empresas.

**Múltiplas florestas:** Usado em cenários de:

- Separação administrativa (departamentos independentes)
- Fusões e aquisições
- Ambientes de teste/desenvolvimento isolados

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/03448c2faf976db890118d835000bab7.png)

### 8.3 Relações de Confiança (Trusts)

**Trusts** permitem que usuários de um domínio acessem recursos em outro domínio. As confianças podem ser:

|Tipo|Direção|Descrição|
|---|---|---|
|**Unidirecional**|Domínio A confia em B, mas não o contrário|Acessos em uma direção apenas|
|**Bidirecional**|Confiança mútua|Usuários de ambos acessam recursos de ambos|
|**Transitiva**|Se A confia em B e B confia em C, então A confia em C|Confiança automática em árvores/florestas|
|**Não transitiva**|Confiança limitada aos domínios explicitamente configurados|Usado em confianças externas|

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5ed5961c6276df568891c3ea/room-content/af95eb1a4b6c672491d8989f79c00200.png)

**Tipos comuns de confiança:**

- **Parent-child:** Automática e transitiva entre domínios pai e filho
- **Tree-root:** Automática e transitiva entre domínios raiz de árvores na mesma floresta
- **External:** Manual e não transitiva entre domínios de florestas diferentes
- **Forest:** Manual e transitiva entre florestas inteiras
- **Realm:** Entre domínio Windows e Kerberos não-Windows
- **Shortcut:** Atalho manual para otimizar autenticação entre domínios

---
## 9. Active Directory e Cibersegurança

### 9.1 Por que o AD é Crítico para Segurança?

O Active Directory é frequentemente chamado de "o reino dos castelos" na segurança da informação porque:

1. **Controla tudo:** Quem acessa o quê, quando e como    
2. **É alvo principal:** Atacantes visam o AD para dominar toda a rede
3. **Erros são catastróficos:** Uma configuração incorreta pode comprometer toda a organização

### 9.2 Vulnerabilidades Comuns do AD

#### Grupos Padrão com Privilégios Excessivos

Alguns grupos built-in têm permissões que podem ser abusadas:

| Grupo                 | Risco                                     | Recomendação                                             |
| --------------------- | ----------------------------------------- | -------------------------------------------------------- |
| **Account Operators** | Pode modificar contas privilegiadas       | Manter vazio, delegar individualmente                    |
| **Backup Operators**  | Pode copiar o banco de dados do AD        | Apenas contas de serviço específicas                     |
| **DNSAdmins**         | Pode executar código no DC                | Usar com moderação                                       |
| **Print Operators**   | Pode fazer login no DC e instalar drivers | Manter vazio (a menos que DC seja servidor de impressão) |
| **Schema Admins**     | Pode modificar o esquema do AD            | Manter vazio, adicionar apenas durante alterações        |

#### Configurações Inseguras

- **GPOs com permissões fracas:** Usuários comuns podem modificar políticas
- **Delegação excessiva:** Muitos usuários com direitos administrativos
- **Contas de serviço com privilégios altos:** Contas usadas para serviços com direitos de domínio
- **Senhas fracas ou nunca expiram:** Especialmente em contas de serviço    

#### Falhas de Patch

- **MS14-068:** Vulnerabilidade que permitia elevação de privilégios no Kerberos
- **Zerologon (CVE-2020-1472):** Falha crítica no Netlogon
- **PrintNightmare:** Execução remota de código via spooler de impressão

### 9.3 Métodos de Ataque ao Active Directory

#### 1. Reconhecimento e Enumeração

Atacantes primeiro coletam informações sobre o AD:

```powershell
# Comandos comuns de enumeração (já no domínio)
whoami /groups          # Ver grupos do usuário
net group "Domain Admins" /domínio  # Listar admins
nltest /dclist:empresa   # Listar controladores de domínio

# Ferramentas de ataque (BloodHound, PowerView)
# BloodHound mapeia relações de confiança e caminhos de ataque
```

#### 2. Ataques de Credenciais

- **Pass-the-Hash:** Usar hash NTLM em vez da senha
- **Pass-the-Ticket:** Roubar tickets Kerberos para acesso
- **Overpass-the-Hash:** Converter hash em ticket Kerberos
- **Kerberoasting:** Solicitar tickets de serviço e quebrar offline
- **AS-REP Roasting:** Capturar hashes de usuários sem pré-autenticação

#### 3. Elevação de Privilégios

- **Abuso de grupos privilegiados:** Adicionar usuário a grupos como Domain Admins
- **AdminSDHolder:** Modificar template de segurança para controlar contas privilegiadas
- **ACL abuse:** Modificar permissões em objetos do AD
- **SID History injection:** Adicionar SIDs de grupos privilegiados

#### 4. Movimentação Lateral

- **PsExec, WMI, WinRM:** Execução remota
- **Pass-the-Hash em serviços:** Usar hashes para acessar outros sistemas
- **LSA Secrets:** Extrair credenciais da memória

#### 5. Persistência

- **Criação de contas de backup:** Contas "invisíveis" com privilégios
- **Modificação de GPOs:** Adicionar scripts maliciosos em GPOs existentes
- **Skeleton Key:** Injetar backdoor no LSASS do DC
- **DCSync:** Simular replicação do AD para obter hashes de senha

#### 6. Exfiltração de Dados

- **ntds.dit:** O banco de dados do AD contém todos os hashes de senha
- **Group Policy Preferences:** Arquivos XML que podem conter senhas    
- **SYSVOL:** Pasta que pode conter scripts com credenciais

### 9.4 Exemplo de Ataque Simples: Kerberoasting

**Passo a passo:**

1. **Atacante compromete uma conta comum no domínio**    
2. **Enumera contas de serviço (SPNs):**

```powershell
# Com PowerView
Get-NetUser -SPN | Select name, serviceprincipalname
```

3. **Solicita tickets TGS para esses serviços:**

```powershell
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/servidor.empresa.local"
```

4. **Extrai tickets da memória:**

```powershell
# Com Mimikatz
kerberos::list /export
```

5. **Quebra a senha offline:**

```bash
# Com John the Ripper ou Hashcat
john ticket.kirbi
hashcat -m 13100 ticket.kirbi wordlist.txt
```

6. **Usa a senha descoberta para acessar o serviço como o usuário privilegiado**

### 9.5 Boas Práticas de Segurança para AD

#### Hardening Básico

1. **Princípio do menor privilégio:**
    - Usuários comuns não precisam ser administradores locais
    - Contas de serviço com permissões mínimas necessárias
    - Delegue tarefas, não grupos inteiros

2. **Proteção de controladores de domínio:**    
    - Isolamento de rede (firewall)
    - Acesso físico restrito
    - Atualizações regulares
    - Desabilitar serviços desnecessários

3. **Políticas de senha robustas:**
    - Comprimento mínimo (14+ caracteres)        
    - Complexidade (quando não usar passphrases)
    - Troca periódica (60-90 dias)
    - Bloqueio após tentativas falhas

4. **Monitoramento contínuo:**    
    - Logs de segurança do AD
    - Alertas para alterações em grupos privilegiados
    - Auditoria de acesso ao AD

#### Ferramentas de Segurança

- **Microsoft LAPS (Local Administrator Password Solution):** Senhas únicas e rotacionadas para administradores locais
- **JEA (Just Enough Administration):** Administração com privilégios limitados
- **PAM (Privileged Access Management):** Controle de acesso just-in-time
- **Azure AD Connect Health:** Monitoramento em nuvem
- **ATP (Advanced Threat Protection):** Detecção de ameaças da Microsoft

#### Checklist de Segurança

- Remover membros desnecessários de grupos privilegiados
- Implementar LAPS para administradores locais
- Desabilitar NTLM quando possível
- Configurar política de auditoria abrangente
- Revisar delegações de permissões regularmente
- Backup seguro do AD (incluindo System State)
- Plano de resposta a incidentes específico para AD

---
## 10. Conclusão

O Active Directory é a espinha dorsal da infraestrutura de TI em organizações Windows. Ele fornece:

- **Gerenciamento centralizado** de usuários, computadores e recursos    
- **Autenticação segura** com Kerberos e integração com nuvem
- **Controle granular** através de Políticas de Grupo (GPOs)
- **Escalabilidade** de pequenas empresas a grandes corporações

No entanto, seu papel central também o torna um **alvo prioritário para atacantes**. Compreender não apenas como configurar o AD, mas também como protegê-lo, é essencial para qualquer profissional de TI ou segurança.

**Principais aprendizados:**

1. **Estrutura:** Domínios, árvores e florestas organizam recursos logicamente
2. **GPOs:** Ferramenta poderosa para configurar e proteger sistemas em massa
3. **Confianças:** Permitem colaboração entre domínios, mas aumentam a superfície de ataque
4. **Segurança:** Deve ser proativa (hardening) e reativa (monitoramento)
5. **Ameaças:** Conhecer os métodos de ataque é o primeiro passo para se defender

---
