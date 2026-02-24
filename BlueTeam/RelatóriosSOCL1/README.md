<!-- ===================================== -->
<!--         SOC L1 ALERT REPORT GUIDE    -->
<!-- ===================================== -->

<p align="center">
  <img src="https://img.shields.io/badge/Status-Operational%20Guide-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Environment-24x7%20SOC-critical?style=for-the-badge">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Role-SOC%20Analyst%20L1-black?style=flat-square">
  <img src="https://img.shields.io/badge/Focus-Triage%20%7C%20Escalation%20%7C%20Reporting-red?style=flat-square">
  <img src="https://img.shields.io/badge/Discipline-Incident%20Response-purple?style=flat-square">
  <img src="https://img.shields.io/badge/Level-Entry%20%E2%86%92%20Operational-yellow?style=flat-square">
</p>

---

# 🚨 Relatório de Alerta para SOC L1
## Guia Operacional de Triagem, Escalação e Comunicação

> Em um Security Operations Center (SOC), cada alerta representa uma possível ameaça.
>  
> O Analista L1 não é apenas um "fechador de tickets" — ele é o **filtro crítico entre ruído operacional e incidentes reais de segurança**.
>
> Este documento apresenta um guia prático e estruturado para:
>
> - Realizar triagem eficiente
> - Produzir relatórios claros e acionáveis
> - Escalar corretamente para L2
> - Melhorar métricas operacionais (MTTD, MTTR, FP Rate)
>
> A qualidade da análise no nível 1 define a eficiência de toda a cadeia de resposta a incidentes.

---

## 🎯 Objetivo do Documento

Este guia foi desenvolvido para:

- Padronizar o processo de análise de alertas
- Reduzir falsos positivos e falsos negativos
- Melhorar a qualidade da documentação
- Otimizar a comunicação entre L1 e L2
- Aumentar a maturidade operacional do SOC

---
# Relatório de Alerta para SOC L1

## 1. Introdução: O Papel do Analista L1 como Primeiro Respondente

Como analista de SOC L1, você é a primeira linha de defesa, o "primeiro respondente" dos incidentes de segurança. Em um ambiente 24x7, sua principal função é monitorar e analisar um fluxo constante de alertas gerados por ferramentas como SIEM, EDR e IDS. A qualidade do seu trabalho de triagem determina diretamente a eficiência de toda a operação de segurança. Uma triagem falha pode levar a duas situações críticas: **falsos positivos que desperdiçam o tempo de analistas seniores** e, pior, **falsos negativos que permitem que ataques reais progridam sem serem detectados**.

---
## 2. O Funil de Alerta: Transformando Ruído em Sinal

O fluxo de trabalho de um analista L1 pode ser visualizado como um funil, onde o objetivo é separar o "sinal" (ameaças reais) do "ruído" (atividade benigna).

Primeiro, os analistas L1 recebem os alertas em um SIEM, EDR ou uma plataforma de gerenciamento de tickets. A maioria dos alertas são fechados como falsos positivos ou são tratados no nível L1, mas os complexos e ameaçadores são enviados para L2 que remediam a maioria das violações. E para enviar os alertas ainda mais, você precisa aprender três novos termos: relatórios, escalação e comunicação.

![Alert Funil](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1743606354595.svg)

### 2.1 Relatórios de Alerta (A Matéria Prima)

Um alerta é o ponto de partida. Ele é gerado por uma regra ou correlação no SIEM que identificou um ou mais eventos potencialmente suspeitos. O relatório de alerta, dentro da plataforma (ticket), contém as informações cruciais para o início da investigação:

- **Nome do Alerta:** Ex.: "Execução de ferramenta de acesso remoto suspeita".
- **Gravidade (Severity):** Crítica, Alta, Média, Baixa. Ajuda na priorização.
- **Fonte do Alerta:** Qual ativo (IP, hostname) gerou o alerta.
- **Usuário Associado:** Conta de usuário envolvida no evento.
- **Descrição Curta:** Um resumo de porque a regra foi disparada.
- **Timestamp (Data/Hora):** Quando o evento ocorreu. Fundamental para a linha do tempo.
- **Indicadores Chave (IOCs):** IP de destino, hashes de arquivos, URLs envolvidas.

### 2.2 Escalação de Alerta: O Processo Decisório

A escalação é o ato de transferir um alerta que você classificou como um **possível incidente (True Positive)** para analista de Nível 2 (L2) para investigação aprofundada e resposta. O alerta só deve ser escalado após uma triagem cuidadosa.

### 2.3 Comunicação: A Espinha Dorsal do SOC

Uma comunicação clara e objetiva é tão importante quanto o conhecimento técnico. Suas anotações no ticket e a comunicação durante a escalação devem permitir que qualquer outro membro da equipe (L2, L3 ou gestor) entenda exatamente o que aconteceu, o que você já vez  e qual o próximo passo lógico.

---
## 3. Guia de Reportagem: Como Documentar um Alerta (Formato de Relatório)

### 3.1 Método STAR

A documentação não é uma formalidade; é uma prova do seu raciocínio e um guia para os próximos passos. Ao analisar um ticket, siga um formato consistente. Uma boa prática é utilizar o método **STAR (Situação, Tarefa, Ação, Resultado)** adaptado:

1. **Título/Sumário da Análise:**
	- Seja conciso, mas descritivo. Ex.: "Análise de Alerta de Acesso Suspeito a Share Administrativo - Usuário João Silva".

2. **Descrição da Situação (O que disparou o alerta?):**
	- "O alerta foi disparado devido a um evento de ID 5140 no servidor 'SRV-FIN-01', indicando uma conexão bem sucedida ao share administrativo 'ADMIN$' pelo usuário 'JOAO.S' a partir do IP 192.168.100.50."

3. **Ações de Investigação (O que você fez para validar?):**
	- "Verificado o horário do login (14:32:15) com o horário de trabalho do usuário (dentro do expediente)."
	- "Confirmado no ativo de origem (WS-JOAO-01) que não havia processos anômalos em execução no momento do evento (usando logs do EDR)."
	- "Validado que o usuário 'JOAO.S' é o administrador local da estação de trabalho e possui privilégios legítimos para acessar o servidor para tarefas de manutenção."

4. **Análise de Contexto e Verificação:**
	- **Normalidade:** "O usuário realiza tarefas de manutenção em servidores todas as terças-feiras, o que coincide com a data de hoje."
	- **Anomalia:** (Caso fosse um falso positivo) N/A. (Caso fosse uma ameaça, descrever a anomalia).

5. **Verdict (Veredito):**
	- **"Veredito: Falso Positivo (Benigno)"** . Justificativa: A atividade foi validada como parte de um procedimento legítimo de manutenção do usuário.

6. **Ações de Resolução/Encaminhamento:**
	- **Se Falso Positivo:** "Alerta encerrado. Nenhuma ação adicional necessária. Considere ajustar a regra para ignorar o usuário 'JOAO.S' ou o horário comercial para reduzir ruído."
	- **Se True Positive:** "Alerta escalado para L2 para investigação de possível comprometimento de conta."

### 3.2 Outros Formatos de Relatório

Imagine-se como um analista de nível 2, um membro de uma equipe de DFIR (Digital Forensics and Incident Response) ou um profissional de TI que precisa entender o alerta. O que você gostaria de ver no relatório? Recomendamos que você siga a abordagem dos 5**Ws (Quem, O quê, Quando, Onde e Porquê)** e inclua pelo menos estes itens no relatório:

- **Quem:** Qual usuário fez login, executou o comando ou baixou o arquivo?
- **O quê:** Qual ação ou sequência de eventos exata foi realizada?
- **Quando:** Quando exatamente a atividade suspeita começou e terminou?
- **Onde:** Qual dispositivo, IP ou site estava envolvido no alerta?
- **Por quê:** O W mais importante, o raciocínio por trás do seu veredicto final.

![Report Format](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1743611080297.svg)

### 3.3  Importância do Relatório

É essencial esclarecer por que alguém desejaria que analistas de nível 1 redigissem relatórios além de classificá-los como Verdadeiros ou Falsos Positivos, e por que esse tópico não pode ser subestimado. A elaboração de relatórios de alerta por analistas de nível 1 serve a vários propósitos importantes:

| **Finalidade do relatório de alerta**   | **Explicação**                                                                                                                                                                                                       |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Forneça contexto para escalonamento     | Um relatório bem escrito economiza muito tempo para os analistas de nível 2.<br>Além disso, ajuda-os a entender rapidamente o que aconteceu.                                                                         |
| Salve as descobertas para registro      | Os logs brutos do SIEM são armazenados por 3 a 12 meses, mas os alertas são mantidos indefinidamente.<br>Portanto, é melhor manter todo o contexto dentro do alerta, por precaução.                                  |
| Aprimore as habilidades de investigação | Se você não consegue explicar algo de forma simples, é porque não o compreende bem o suficiente.<br><br>A elaboração de relatórios é uma ótima maneira de aprimorar as habilidades de nível 1, resumindo os alertas. |

---
# 4. Guia de Escalação: Quando e Como Passar o Bastão

Após emitir um veredito e redigir seu relatório de alerta, é necessário decidir se o alerta será encaminhado para o Nível 2 (L2). Novamente, a resposta pode variar de equipe para equipe, mas as seguintes recomendações geralmente se aplicam à maioria das equipes de SOC. Você deve encaminhar os alertas se:

1. O alerta indicar um ataque cibernético grave que exija uma investigação mais aprofundada ou DFIR (Digital Forensics and Incident Response).
2. Forem necessárias ações de remediação, como remoção de malware, isolamento de host ou redefinição de senha.
3. For necessária a comunicação com clientes, parceiros, gerência ou autoridades policiais.
4. Você simplesmente não entender completamente o alerta e precisar da ajuda de analistas mais experientes.

![Escalation Steps](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1743520297119.svg)
### 4.1 Passos de Escalação (Antes de Clicar em "Escalar")

1. **Pesquise:** Você já esgotou todos os recursos de investigação ao seu alcance (logs disponíveis no SIEM, consultas rápidas no EDR, documentação interna)?

2. **Contextualize:** Você entende o que é "normal" para o ativo e o usuário em questão? A atividade foge desse padrão?

3. **Mapeie:** Você consegue relacionar este alerta a uma tática ou técnica específica do **MITRE ATT&CK**? Isso ajuda o L2 a entender o estágio do ataque.

4. **Formule uma Hipótese:** Com base nos dados, qual é a sua suspeita? "Suspeito que seja um True Positive porque..."

### 4.2 Solicitando Suporte L2 (A Arte da Comunicação Clara)

Quando você escala, não diga apenas "Olha isso". Forneça um pacote de informações. Use a estrutura **PIL (Problema, Impacto, Levantamento)**:

- **Problema (O quê?):** "Alerta de 'PowerShell Executando Script Ofuscado' no host 'HR-DEPT-02'."

- **Impacto (Quem? Por que é importante?):** "O host pertence ao departamento de Recursos Humanos e contém dados pessoais de funcionários. O usuário não é da área de TI e não possui histórico de uso de scripts."

- **Levantamento (O que você já fez?):** "Confirmei que o processo `powershell.exe` foi iniciado por `winword.exe`. O script baixou um arquivo de um domínio recém-registado ( `malicious-site[.]xyz` ). A análise inicial do hash do arquivo no VirusTotal retornou 5/60 detecções como 'trojan'."

- **Solicitação (O que você precisa?):** "Solicito análise aprofundada do L2 para determinar a intenção do script, realizar a contenção do host e verificar se houve exfiltração de dados."

![Resquestin L2 Support](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1743520519371.svg)

---
## 5. Comunicação no SOC

- **Casos de Comunicação:** Você se comunicará em diversos momentos:
	- **Nos comentários do ticket:** Para documentar sua análise (como vimos acima).
	- **No Chat da Equipe:** Para escalações urgentes ou para pedir ajuda rápida.
	- **Em Reuniões de Passagem de Turno (Handoff):** Para resumir o estado da fila e alertas críticos para o próximo analista.

- **Comunicação com L2:** Como detalhado no item 4.2, seja direto, forneça contexto e evite linguagem ambígua.

![Communication By L2](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1743610529685.svg)

---
## 6. Métricas de Desempenho: Medindo a Eficácia da Triagem

O SOC é orientado por métricas. Seu desempenho como L1 impacta diretamente essas métricas. A tabela abaixo ilustra as principais métricas e a relação com seus trabalho.

| **Métrica**                         | **Definição**                                                                    | **Impacto do Trabalho do L1**                                                                                                                                                                                      | **Fórmula / Referência**                                                        | **Meta (exemplo)**                     |
| ----------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------- | -------------------------------------- |
| **Contagem de Alertas**             | Número total de alertas processados em um período.                               | Um L1 eficiente ajuda a "achatar a curva", processando um grande volume de alertas de baixo nível.                                                                                                                 | Soma total de alertas fechados + escalados                                      | Processar 100% dos alertas atribuídos. |
| **Taxa de Falsos Positivos (FP)**   | Percentual de alertas que foram incorretamente disparados por atividade benigna. | Uma taxa de FP alta indica que o L1 pode estar fechando alertas sem investigar profundamente, ou que as regras precisam ser ajustadas. A **ação de "fechar como falso positivo" é responsabilidade direta do L1**. | (Nº de alertas classificados como FP) / (Nº total de alertas processados) * 100 | < 30% - 40%                            |
| **Taxa de Escalações de Alerta**    | Percentual de alertas que foram encaminhados para o L2.                          | Uma taxa de escalação muito alta pode significar que o L1 está "jogando tudo para cima" sem tentar entender. Uma taxa muito baixa pode significar que ele está deixando passar ameaças reais.                      | (Nº de alertas escalados) / (Nº total de alertas processados) * 100             | 5% - 15%                               |
| **Taxa de Detecação de Ameaças**    | Mede a eficácia das regras em detectar ameaças reais.                            | Um L1 que identifica e escala corretamente um True Positive contribui para uma taxa de detecção saudável. É a prova de que o trabalho valeu a pena.                                                                | (Nº de alertas True Positive) / (Nº total de alertas) * 100                     | Varia conforme o ambiente.             |
| **Métricas de Triagem (MTTD/MTTR)** | **MTTD:** Tempo médio para detectar.<br>**MTTR:** Tempo médio para responder.    | Um L1 que faz uma triagem rápida e precisa reduz drasticamente o MTTD, entregando o incidente para resposta o mais cedo possível.                                                                                  | Soma do tempo de detecção ou resposta / Nº de incidentes.                       | O mais baixo possível.                 |

### 6.1 Contagem de Alertas

Imagine começar seu turno e ver 80 alertas não resolvidos na fila. Isso é definitivamente avassalador e propenso a deixar passar ameaças reais escondidas por trás do ruído e do spam. Por outro lado, considere uma semana inteira sem nenhum alerta. Parece melhor à primeira vista, mas também preocupante, já que uma contagem muito baixa de alertas pode indicar um problema no SIEM ou falta de visibilidade, levando a violações não detectadas. O valor ideal dessa métrica depende do tamanho da empresa, mas, em geral, de 5 a 30 alertas por dia por analista de nível 1 é uma boa métrica.

### 6.2 Taxa de Falsos Positivos

Se 75 dos 80 alertas (94%) forem confirmados como falsos positivos, como ruído do sistema ou atividade típica de TI, isso é um mau sinal para sua equipe. Com mais ruído, os analistas tendem a ficar menos vigilantes e mais propensos a ignorar a ameaça, tratando todos os alertas como "apenas mais um spam". Uma taxa de falsos positivos de 0% é um ideal inatingível, mas 80% ou mais é um problema sério, geralmente resolvido com o ajuste de ferramentas e regras de detecção, frequentemente chamado de "Remediação de Falsos Positivos".

![Falsos Positivos](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1746187204113.svg)

### 6.3 Taxa de Escalonamento de Alertas

Uma lupa apontada para uma única ameaça enquanto outras ameaças permanecem ocultas devido a problemas no SIEM ou à falta de experiência do SOC.

Os analistas de nível 2 dependem do nível 1 para filtrar o ruído e escalar apenas os alertas acionáveis ​​e ameaçadores. Ao mesmo tempo, como analista de nível 1, você não deve ter excesso de confiança e priorizar alertas que não compreende totalmente sem o suporte de um analista sênior. A taxa de escalonamento de alertas é útil para avaliar a experiência e a independência dos analistas de nível 1 e a frequência com que decidem escalar um alerta. Geralmente, o objetivo é que essa taxa seja inferior a 50%, ou ainda melhor, inferior a 20%.

### 6.4 Taxa de Detecção de Ameaças

Imagine que, de seis ataques previstos para 2025, sua equipe do SOC detectou e impediu quatro, o quinto não foi detectado devido a uma falha na regra de detecção e o sexto foi detectado porque um dos analistas de nível 1 classificou erroneamente a violação como falso positivo. A métrica resultante é TDR = 4 / 6 = 67%, um resultado muito ruim. A taxa de detecção de ameaças deve ser sempre de 100%, pois cada ameaça não detectada pode ter consequências devastadoras, como infecção por ransomware e exfiltração de dados.

![Detecção de Ameaças](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1746187204011.svg)

### 6.5 Métricas de Triagem

Os requisitos para garantir a detecção e remediação rápidas da ameaça são geralmente agrupados em um **Acordo de Nível de Serviço (SLA)** – um documento assinado entre a equipe interna do SOC e a administração da empresa, ou pelo provedor de SOC gerenciado (MSSP) e seus clientes. O acordo geralmente exige detecção rápida da ameaça (medida pelo **MTTD**), reconhecimento oportuno do alerta por analistas de nível 1 (medido pelo **MTTA**) e, finalmente, resposta imediata à ameaça, como isolar o dispositivo ou proteger a conta comprometida (medido pelo **MTTR**).

![Métricas de Triagem](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1746642255233.svg)

Observe que diferentes equipes podem ter definições ou fórmulas diferentes para as métricas SOC, dependendo do que desejam medir.

| **Métrica**                         | **SLA comum** | **Descrição**                                                                                                                                |
| ----------------------------------- | ------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| Disponibilidade da Equipe do SOC    | 24/7          | Horário de trabalho da equipe do SOC, geralmente de segunda a sexta (8h às 17h) ou em regime de plantão 24 horas por dia, 7 dias por semana. |
| Tempo Médio para Detecção (MTTD)    | 5 minutos     | Tempo médio entre o ataque e sua detecção pelas ferramentas do SOC                                                                           |
| Tempo Médio para Confirmação (MTTA) | 10 minutos    | Tempo médio para analistas de nível 1 iniciarem a triagem do novo alerta.                                                                    |
| Tempo Médio para Resposta (MTTR)    | 60 minutos    | Tempo médio que o SOC leva para impedir efetivamente a propagação da violação.                                                               |

### 6.6 Melhorando Métricas

Primeiro, é importante entender que as métricas foram criadas para tornar o SOC mais eficiente e, consequentemente, reduzir significativamente o sucesso dos ataques. Segundo, as métricas são frequentemente usadas para avaliar seu desempenho, e bons resultados levam ao crescimento na carreira e à promoção para cargos mais seniores, como analista de nível 2 (L2). Então, como você pode melhorar suas métricas?

![Melhorando Métricas](https://tryhackme-images.s3.amazonaws.com/user-uploads/678ecc92c80aa206339f0f23/room-content/678ecc92c80aa206339f0f23-1746186772909.svg)

| **Problema**                                       | **Recomendações**                                                                                                                                                                                                                                                                                                         |
| -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Taxa de Falsos Positivos acima de 80%              | **Sua equipe recebe muito ruído nos alertas. Tente:**<br><br>1. Excluir atividades confiáveis, como atualizações de sistema, das regras de detecção do seu EDR ou SIEM.<br>2. Considere automatizar a triagem de alertas para os alertas mais comuns usando SOAR ou scripts personalizados.                               |
| Tempo médio de detecção mais de 30 minutos         | **Sua equipe detectou uma ameaça com um atraso considerável. Tente:**<br><br>1. Contatar os engenheiros do SOC para que as regras de detecção sejam executadas mais rapidamente ou com uma taxa de amostragem maior.<br>2. Verificar se os logs do SIEM estão sendo coletados em tempo real, sem um atraso de 10 minutos. |
| Tempo médio para reconhecimento mais de 30 minutos | **Os analistas de nível 1 iniciam a triagem de alertas com um atraso considerável. Tente:**<br><br>1. Garantir que os analistas sejam notificados em tempo real quando um novo alerta surgir.<br>2. Tentar distribuir os alertas na fila de forma uniforme entre os analistas de plantão.                                 |
| Tempo médio de resposta mais de 4 horas            | **A equipe do SOC não consegue impedir a invasão a tempo. Tente:**<br><br>1. Como L1, faça todo o possível para escalar rapidamente as ameaças para o L2.<br>2. Certifique-se de que sua equipe tenha documentado o que fazer em diferentes cenários de ataque.                                                           |



---
## 7. Conclusão

Dominar a criação de relatórios de alerta e o processo de escalação é o que separa um operador de um analista de segurança. Ao seguir um processo **estruturado, documentado e orientado por contexto**, você não apenas aumenta sua eficiência, mas também constrói uma reputação de confiabilidade dentro da equipe.

Lembre-se sempre: a triagem não é sobre ler logs, mas sobre contar a história de um evento e tomar a decisão certa com base nas evidências.  Ao aplicar os conceitos deste guia no simulador SOC e nos estudos para a certificação SAL1, você estará construindo a base sólida necessária para uma carreira de sucesso na cibersegurança.
