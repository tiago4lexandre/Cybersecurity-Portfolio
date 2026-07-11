<!--
title: CVE-2025-6861 — n8n
desc: Estudo sobre a falha de segurança descoberta na plataforma de automação n8n, permitindo bypass de autenticação.
tags: cve, vulnerability, n8n
readTime: 5 min
-->

<!-- ===================================== -->
<!--   N8N - CVE-2025-68613 (RCE)          -->
<!-- ===================================== -->
<p align="center">
  <img src="https://img.shields.io/badge/Category-Offensive%20%26%20Defensive%20Security-red?style=for-the-badge">
  <img src="https://img.shields.io/badge/Focus-Remote%20Code%20Execution-blue?style=for-the-badge">
</p>
<p align="center">
  <img src="https://img.shields.io/badge/Platform-Node.js%20%2F%20Linux-black?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Purple%20Team-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Intermediate-yellow?style=flat-square">
  <img src="https://img.shields.io/badge/Status-CVE%20Analysis-green?style=flat-square">
</p>

---

# 📚 n8n — CVE-2025-68613
## Injeção de Expressão Levando a Execução Remota de Código
> Do escape do sandbox de expressões JavaScript à execução de comandos no sistema hospedeiro: análise completa da falha, exploração passo a passo e estratégias de detecção via proxy reverso e regras Sigma.

---
# n8n: CVE-2025-68613

## Introdução

O **n8n** é uma plataforma de automação de fluxo de trabalho de código aberto, projetada para conectar visualmente aplicativos e serviços, automatizando tarefas repetitivas e processos operacionais. Os usuários criam fluxos de trabalho compostos por **nós**, onde cada nó representa uma ação específica, como realizar uma requisição a uma API, processar dados ou enviar e-mails.

O n8n é amplamente utilizado para automatizar tarefas operacionais e integrar ferramentas de segurança e plataformas SaaS. Abaixo, um exemplo simples de fluxo de trabalho que:
1. Agenda uma requisição **HTTPS GET** para a API do NVD CVE;
2. Formata a saída utilizando JavaScript;
3. Envia o relatório por e-mail e para um canal do Slack.

![Exemplo de fluxo de trabalho n8n](https://tryhackme-images.s3.amazonaws.com/user-uploads/62ff64c3c859dc0042b2b9f6/room-content/62ff64c3c859dc0042b2b9f6-1766583898233.png)

A plataforma n8n é geralmente implementada em três configurações principais:

- **Instâncias auto-hospedadas**: Organizações implementam o n8n localmente ou em ambientes de nuvem privada, garantindo controle total e soberania dos dados.
- **Hospedagem na nuvem (n8n.cloud)**: Oferta de serviço gerenciado com infraestrutura compartilhada.
- **Ferramentas de automação interna**: Implementadas em redes corporativas para automatizar processos de negócios entre sistemas internos e externos.

As versões **0.211.0 a 1.120.3** contêm uma vulnerabilidade crítica de **Execução Remota de Código (RCE)** no sistema de avaliação de expressões de fluxo de trabalho. Quando explorada, essa falha permite que um atacante autenticado execute comandos em nível de sistema, podendo levar a violações de dados, interrupções de serviço ou comprometimento total do sistema, com os privilégios atribuídos ao processo n8n.

A vulnerabilidade foi corrigida nas versões **1.120.4**, **1.121.1** e **1.122.0**. Para garantir a segurança do sistema, é essencial atualizar para uma dessas versões corrigidas.

---
## Formação Técnica

Antes de explorarmos a vulnerabilidade, vamos analisar a arquitetura do n8n. A plataforma é construída em **Node.js**, utilizando JavaScript tanto para a lógica interna quanto para a execução de fluxos de trabalho. Sua arquitetura inclui:

- **Mecanismo de Execução de Fluxo de Trabalho**: Componente computacional central responsável por orquestrar a execução de fluxos de trabalho baseados em nós.
- **Sistema de Avaliação de Expressões**: Processa expressões dinâmicas entre chaves duplas (`{{ }}`), que são avaliadas como código JavaScript durante a execução do fluxo de trabalho.
- **Nós de Código**: Permitem que os usuários escrevam código JavaScript ou Python personalizado como etapas do fluxo de trabalho, ampliando as capacidades da plataforma.
- **Mais de 400 integrações nativas**: Conectores pré-construídos para diversas APIs e serviços que formam os nós nos fluxos de trabalho.

A vulnerabilidade reside no **sistema de avaliação de expressões**, onde expressões fornecidas por usuários autenticados durante a configuração do fluxo de trabalho são avaliadas em um contexto de execução inseguro. A principal falha de segurança é uma **vulnerabilidade de injeção de expressão**, que permite que atacantes autenticados executem código JavaScript arbitrário com os privilégios do processo n8n. Especificamente:

- O n8n processa a entrada do usuário envolta em chaves duplas (`{{ }}`) como código JavaScript, sem o devido isolamento ou validação de entrada.
- O avaliador de expressões carece de isolamento de contexto adequado, permitindo que atacantes escapem do ambiente de avaliação isolado (*sandbox*) pretendido.
- A autenticação não oferece proteção significativa contra essa vulnerabilidade, pois qualquer usuário autenticado pode explorá-la.

Considere o seguinte *payload* do [wioui](https://github.com/wioui/n8n-CVE-2025-68613-explot):

{% raw %}
```text
{{ (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}
```
{% endraw %}


Dentro de todas essas camadas de chaves, é possível identificar o padrão `(function(){ ... })()`. Esse padrão cria e executa imediatamente uma função anônima. O atacante tenta encapsular lógica complexa mantendo o contexto de execução. Para facilitar a leitura, a função anônima é apresentada abaixo:

```javascript
function () {
    return this.process.mainModule.require('child_process').execSync('id').toString()
}
```

Vamos analisar mais de perto para entender melhor essa vulnerabilidade. Quando a função é chamada, ela executa a instrução `return`. Se você não está familiarizado com funções, a instrução `return` retorna um valor, o que requer a avaliação da expressão que a acompanha. Nesse caso, a avaliação começa com `this`.

O exploit utiliza `this.process.mainModule`. Vamos detalhar cada parte:

- **`this`**: Refere-se ao objeto global no contexto de execução do Node.js.
- **`process`**: É um objeto global do Node.js que fornece acesso a informações e controle sobre o processo atual.
- **`mainModule`**: Faz referência ao módulo raiz da aplicação Node.js.

O objetivo é contornar as restrições típicas do _sandbox_ do JavaScript, acessando os componentes internos do Node.js (o módulo raiz), que não deveriam estar disponíveis para expressões de usuário. Vale ressaltar que, se o _sandbox_ estiver configurado corretamente, o contexto de execução da expressão ficaria isolado do ambiente de execução do Node.js.

Agora que o objeto `mainModule` foi alcançado, vemos `.require('child_process')`. Isso utiliza `require()`, a função de carregamento de módulos do Node.js, para carregar `child_process` — um módulo central que permite executar comandos do sistema. É importante notar que expressões de usuário nunca deveriam ter acesso ao sistema de módulos do Node.js, especialmente a módulos perigosos como `child_process`.

Chegando a este ponto, executar funções do sistema é trivial. Este exemplo de _payload_ utiliza `.execSync('id')` para executar o comando `id` no sistema hospedeiro. Lembre-se de que o comando `id` exibe informações de identidade do usuário (UID, GID, grupos).

Após executar o comando `id` no sistema alvo, é necessário recuperar a saída. Este _payload_ utiliza `.toString()` para converter a saída do buffer retornado por `execSync()` em uma string legível, ou seja, a saída do comando `id`.

**Violação de segurança**: Expressões de usuário nunca deveriam ter acesso ao sistema de módulos do Node.js, especialmente a módulos perigosos como `child_process`.

Agora você entende por que mencionamos que o atacante encapsula lógica complexa dentro da função anônima — isso envolve uma chamada após a outra, até que ele esteja literalmente executando comandos no sistema vulnerável. Em resumo, a cadeia de escalonamento de contexto ocorreu da seguinte forma:

1. **Início**: Dentro do ambiente de teste pretendido pelo avaliador de expressões.
2. **Escalonamento para o contexto global do Node.js**: Através de `this`.
3. **Escalonamento para acesso ao sistema de módulos**: Através de `process.mainModule.require`.
4. **Execução de comandos do sistema**: Através de `child_process`.

---
## Exploração

Agora é hora de explorar a vulnerabilidade. Utilizaremos o _payload_ disponível no navegador, disponível [aqui](https://github.com/wioui/n8n-CVE-2025-68613-exploit). Para sua conveniência, o código de exploração está reproduzido abaixo:

```text
{{ (function(){ return this.process.mainModule.require('child_process').execSync('id').toString() })() }}
```

### Passo a Passo para Exploração

1. **Inicie um novo fluxo de trabalho**. Dependendo do que você vir após fazer login, talvez seja necessário clicar em **"Começar do zero"**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585922631.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585922631.png)

2. Para executar as instruções descritas na prova de conceito original, clique em **"Adicionar primeiro passo"**.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585926569.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585926569.png)

3. Procure e adicione o nó **"Manual Trigger"** (Acionador Manual).

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585922680.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585922680.png)

4. Em conjunto com o gatilho manual, adicione a opção **"Edit Fields (Set)"** (Editar Campos).

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585922719.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766585922719.png)

5. Clique em **"Add Field"** e defina um nome (ex.: "resultado" ou "exploit") e cole o _payload_ no campo de valor.

6. Clique em **"Execute Step"** (Executar etapa). Você verá a saída do comando sendo executada. Na captura de tela abaixo, podemos ver a saída do comando `id`.

![https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766586080441.png](https://tryhackme-images.s3.amazonaws.com/user-uploads/5f04259cf9bf5b57aed2c476/room-content/5f04259cf9bf5b57aed2c476-1766586080441.png)

---
## Detecção

Esta seção fornece detalhes sobre como detectar a execução remota de código por injeção de expressão no n8n (CVE-2025-68613) dentro do seu **SIEM** ou outra solução de detecção.

Infelizmente, a solução n8n não fornece um nível de registro detalhado o suficiente para que seja possível detectar esse ataque apenas com seus logs. Se você quiser explorar os logs mais a fundo, consulte a [documentação oficial de referência de logs](https://docs.n8n.io/hosting/logging-monitoring/logging/).

Considerando essa limitação, a melhor maneira de detectar esse ataque é configurar uma solução de **proxy** para gerenciar as requisições que chegam ao aplicativo n8n. Com essa abordagem, você pode enviar os logs do proxy para sua solução de detecção e analisar o conteúdo do corpo das requisições web para identificar a exploração.

Abaixo, um exemplo de configuração do **nginx** para registrar o conteúdo do corpo da requisição (`'Request-Body: "$request_body"'`). Observe que isso pode variar dependendo da solução de proxy escolhida:

```nginx
http {
    # Carrega o módulo Lua
    lua_package_path "/etc/nginx/lua/?.lua;;";
    
    # Formato de log personalizado
    log_format detailed '$remote_addr - $remote_user [$time_local] '
                       '"$request" $status $body_bytes_sent '
                       '"$http_referer" "$http_user_agent" '
                       'Request-Body: "$request_body" '
                       'Content-Type: "$http_content_type" '
                       'Duration: $request_time s';
    
    # ... restante do bloco http ...
}
```

### Regra Sigma

Para detectar essa vulnerabilidade utilizando **Sigma**, podemos usar a seguinte regra:

```yaml
title: N8N Workflow RCE Attempt
status: experimental
description: Detects attempts to inject JavaScript expressions into n8n workflow payloads that execute OS commands via "this.process.mainModule.require('child_process').execSync(...)"
author: TryHackMe Content Engineering Team
references:
  - https://github.com/wioui/n8n-CVE-2025-68613-exploit
date: 2025-12-23
tags:
  - attack.execution
  - attack.t1059.007
logsource:
  category: webserver
  product: generic
detection:
  selection:
    cs-method: POST
    cs-uri-stem|endswith: /rest/workflows
  keywords:
    # Fortes indicadores de injeção de expressão para RCE no n8n
    - "this.process.mainModule.require('child_process')"
    - ".execSync("
    - "={{ (function(){"
    - "toString() })()"
  condition: selection and all of keywords
falsepositives:
  - Testes de segurança / simulações de equipe vermelha
  - Desenvolvedores armazenando essas strings exatas em campos registrados
level: high
```

Em resumo, esta regra Sigma:

- Seleciona apenas requisições para o caminho `/rest/workflows` com o método `POST`;
- Procura por palavras-chave no conteúdo do corpo relacionadas à exploração do CVE-2025-68613.

### Monitoramento de Execuções de Comandos Suspeitos

Além da regra Sigma anterior, é fundamental continuar monitorando os **eventos de criação de processos** para detectar atividades de invasores após a exploração.

Isso é crucial, pois um atacante que possua apenas credenciais válidas do n8n pode abusar completamente dessa RCE para realizar uma ampla gama de ações maliciosas, tais como:

- **Estabelecer um shell reverso** para obter acesso interativo ao sistema ([Exemplo de regra Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/linux/process_creation/proc_creation_lnx_netcat_reverse_shell.yml));
- **Baixar e executar payloads maliciosos** para manter persistência ou agravar o impacto ([Exemplo de regra Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_curl_download_direct_ip_exec.yml));
- **Executar comandos de reconhecimento** para enumerar o ambiente que hospeda o aplicativo n8n ([Exemplo de regra Sigma](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_nltest_recon.yml)).

Por esse motivo, a detecção não deve se basear em um único sinal. Em vez disso, **correlacione a detecção de logs da web com outras regras de criação de processos** para identificar de forma confiável o comportamento pós-exploração associado a este CVE e aumentar a confiança geral na detecção.

---
## Conclusão

Este _payload_ exemplifica por que os recursos de avaliação de expressões exigem extrema cautela no projeto de aplicações. A vulnerabilidade não se resume à validação inadequada de entrada; trata-se de falhas fundamentais na relação de confiança entre o código fornecido pelo usuário e o ambiente de execução da aplicação.

Do ponto de vista de uma equipe **Purple Team**, entender essa cadeia de exploração ajuda tanto as equipes ofensivas a testar vulnerabilidades semelhantes quanto as equipes defensivas a desenvolver estratégias de detecção mais eficazes, focadas em **padrões de escalonamento de contexto** em vez de apenas assinaturas de _payload_ específicas.

Por fim, lembre-se de **atualizar seus servidores** para uma versão com os patches de segurança aplicados.
