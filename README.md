# 🖥️ Cybersecurity Portfolio & Document Hub

<p align="center">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/Aesthetics-Premium-blueviolet?style=for-the-badge">
  <img src="https://img.shields.io/badge/Automation-Python-blue?style=for-the-badge&logo=python">
</p>

Este repositório contém o código-fonte do meu **site/portfólio técnico em Cibersegurança**. Desenvolvido com foco total no conteúdo técnico, o site funciona como uma central inteligente e interativa de visualização e busca para todas as minhas documentações, writeups de laboratórios e análises de segurança baseadas em arquivos Markdown (`.md`).

---

## ✨ Recursos & Funcionalidades

### 1. 🔍 Central de Documentos & Busca Global
* **Busca Instantânea:** Filtre relatórios por título, descrição, categoria ou tags em tempo real através da Central ou da barra persistente no menu lateral.
* **Filtros por Tags e Categoria:** Nuvem de tags dinâmicas (`#web-sec`, `#privesc`, `#exploit`) e botões de categoria que preenchem parâmetros na URL hash para facilitar o compartilhamento de buscas.
* **Ordenação Inteligente:** Ordene por ordem alfabética (A-Z/Z-A) ou pelo tempo estimado de leitura.

### 2. 📚 Experiência de Leitura Avançada
* **Índice Lateral Flutuante (TOC):** Um painel dinâmico construído a partir dos títulos (`h2` e `h3`) do documento. Destaca o tópico ativo na tela automaticamente conforme você rola a página (*scroll tracking* com `IntersectionObserver`).
* **Botão "Copiar" nos Blocos de Código:** Botão flutuante que copia comandos e payloads do terminal com apenas um clique e fornece feedback visual imediato.
* **Modo Foco (Focus Mode):** Oculte a barra lateral clicando no botão `◀` para focar inteiramente nos guias de estudo sem distrações.

---

## 📂 Estrutura do Projeto

A organização de pastas foi padronizada para evitar conflitos de caminhos em ambientes de produção (remoção de caracteres especiais e acentos) e para facilitar o trabalho de edição (arquivos de documentação renomeados com nomes descritivos em vez de múltiplos `README.md` genéricos).

```text
.
├── BlueTeam/
│   ├── RelatoriosSOCL1/
│   │   └── RelatoriosSOCL1.md          # Sem acentos na pasta e com nome descritivo
│   └── WAZUH1/
│       └── WAZUH1.md
├── Ferramentas/
│   └── MSFvenom/
│       └── MSFvenom.md
├── Vulnerabilidades/
│   └── React2Shell/
│       └── React2Shell.md
├── generate_index.py                  # Script de automação em Python
├── documents.json                     # Banco de dados indexado dinamicamente
├── index.html                         # Interface de visualização frontend
├── script.js                          # Lógica do site e renderização AJAX
├── style.css                          # Estilos visuais e transições neon
└── README.md                          # Esta documentação principal
```

---

## ⚙️ Automação com Python (`generate_index.py`)

Para reduzir a manutenção manual a zero ao adicionar novas documentações, o projeto conta com um script de auto-indexação automatizado. 

### Como Funciona a Indexação?
O script [generate_index.py](generate_index.py) funciona varrendo recursivamente as pastas de categorias do projeto. Em vez de você precisar registrar manualmente cada novo artigo no frontend, o script lê o próprio arquivo Markdown e gera um banco de dados estruturado em JSON ([documents.json](documents.json)).

O script obtém as informações de cada arquivo a partir de um **bloco de comentário de metadados** posicionado obrigatoriamente na primeira linha de cada arquivo `.md`.

#### Estrutura do Bloco de Metadados (no topo do seu arquivo `.md`):
```html
<!--
title: SQL Injections
desc: Guia prático de SQLi (Blind, Time-based) com foco em extração manual de dados.
tags: web-sec, sqli, database, owasp-top10
readTime: 7 min
-->

# 💉 SQL Injections
... conteúdo do seu relatório aqui ...
```

O script analisa esse bloco:
1. Extrai o **título oficial** (`title`), **descrição do card** (`desc`) e o **tempo estimado de leitura** (`readTime`).
2. Converte a linha de `tags` em uma array de strings no JSON.
3. Se o tempo de leitura não for especificado no bloco, o script analisa o corpo do arquivo e **calcula dinamicamente o tempo estimado** com base na quantidade de palavras (velocidade média de 180 palavras por minuto).
4. Caso o arquivo Markdown não tenha o bloco de comentários, o script infere o título com base no nome do arquivo e cria tags e descrições genéricas padrão.

### Como Atualizar o Portfólio (Fluxo de Trabalho):

Ao criar ou editar um documento no seu repositório, o fluxo para colocá-lo no ar é extremamente simples:

1. **Crie a pasta e o arquivo Markdown** sob a categoria apropriada (ex: `RedTeam/meu-novo-exploit/meu-novo-exploit.md`).
2. **Insira o cabeçalho de comentários** no topo do arquivo (com `title`, `desc`, `tags`).
3. **Execute o script de indexação** na raiz do projeto:
   ```bash
   python3 generate_index.py
   ```
4. **Pronto!** O script atualizará o arquivo `documents.json` instantaneamente. O frontend lerá o arquivo gerado e renderizará o novo card de forma automática no site.

---

## 🚀 Como Executar o Projeto Localmente

O frontend foi desenvolvido com tecnologias nativas (HTML5, Vanilla CSS e Javascript moderno) dispensando compiladores ou builders complexos.

Você pode testar localmente abrindo diretamente o arquivo `index.html` no navegador ou iniciando um servidor HTTP local simples:

```bash
# Navegue até a pasta do projeto
cd Cybersecurity-Portfolio

# Inicie o servidor embutido do Python
python3 -m http.server 8000
```
Agora, acesse `http://localhost:8000` em seu navegador para explorar o portfólio.

---

## ⚠️ Aviso Legal

Todo o conteúdo apresentado neste site é utilizado **exclusivamente para fins educacionais** e em **ambientes controlados e autorizados**.  
Nenhuma técnica deve ser aplicada em sistemas de terceiros sem permissão explícita por escrito.

---

## 📫 Contato

* 🔗 **LinkedIn:** https://www.linkedin.com/in/tiago-alexandre2001
* 💻 **GitHub:** https://github.com/tiago4lex
