const content = document.getElementById("content");
const menuToggle = document.querySelector(".menu-toggle");
const menu = document.querySelector(".menu");

let data = {};

const categoriesInfo = {
  redteam: { name: "Red Team", icon: "🔴", colorClass: "cat-redteam" },
  blueteam: { name: "Blue Team", icon: "🔵", colorClass: "cat-blueteam" },
  forensics: { name: "Forensics", icon: "🛡️", colorClass: "cat-forensics" },
  cves: { name: "CVEs (Vulnerabilidades)", icon: "⚠️", colorClass: "cat-cves" },
  linux: { name: "Linux Security", icon: "🐧", colorClass: "cat-linux" },
  windows: { name: "Windows Security", icon: "🪟", colorClass: "cat-windows" },
  network: { name: "Network Security", icon: "🌐", colorClass: "cat-network" },
  tools: { name: "Ferramentas", icon: "🛠️", colorClass: "cat-tools" },
  labs: { name: "Laboratórios", icon: "🧪", colorClass: "cat-labs" }
};

let explorerState = {
  searchQuery: "",
  selectedCategory: "all",
  selectedTags: new Set(),
  sortBy: "title-asc"
};

// Configuração do marked para usar highlight.js
marked.setOptions({
  highlight: function (code, lang) {
    if (lang === "mermaid") {
      return code;
    }
    if (lang && hljs.getLanguage(lang)) {
      return hljs.highlight(code, { language: lang }).value;
    }
    return hljs.highlightAuto(code).value;
  },
  breaks: true,
  gfm: true,
});

if (typeof mermaid !== "undefined") {
  mermaid.initialize({ startOnLoad: false, theme: "dark" });
}

function aplicarSyntaxHighlighting() {
  document.querySelectorAll("pre code").forEach((block) => {
    if (block.classList.contains("language-mermaid")) return;
    if (!block.classList.contains("hljs")) {
      hljs.highlightElement(block);
    }
  });
}

function renderizarMermaid() {
  if (typeof mermaid === "undefined") {
    console.warn("Mermaid.js não foi carregado na página.");
    return;
  }

  const blocos = document.querySelectorAll(
    "#content pre code.language-mermaid",
  );

  blocos.forEach((bloco) => {
    const pre = bloco.parentElement;
    const div = document.createElement("div");
    div.classList.add("mermaid");
    div.textContent = bloco.textContent;
    pre.replaceWith(div);
  });

  if (blocos.length > 0) {
    mermaid.run({ querySelector: "#content .mermaid" });
  }
}

function toggleMenu() {
  if (menu) {
    menu.classList.toggle("open");
    if (menu.classList.contains("open")) {
      menuToggle.textContent = "✕ Fechar";
    } else {
      menuToggle.textContent = "☰ Menu";
    }
  }
}

function closeMenu() {
  if (window.innerWidth <= 768 && menu) {
    menu.classList.remove("open");
    menuToggle.textContent = "☰ Menu";
  }
}

function fixImages() {
  const images = document.querySelectorAll("#content img");
  images.forEach((img) => {
    img.removeAttribute("width");
    img.removeAttribute("height");
    img.style.maxWidth = "100%";
    img.style.height = "auto";
    img.style.display = "block";
    img.style.marginLeft = "auto";
    img.style.marginRight = "auto";
    if (!img.hasAttribute("loading")) {
      img.setAttribute("loading", "lazy");
    }
    if (!img.hasAttribute("alt")) {
      img.setAttribute("alt", "Imagem de documento de segurança");
    }
  });
}

function updateActiveSidebarItem(activeId) {
  document.querySelectorAll(".menu button").forEach(btn => {
    btn.classList.remove("active");
  });
  if (activeId) {
    const activeBtn = document.getElementById(activeId);
    if (activeBtn) {
      activeBtn.classList.add("active");
    }
  }
}

function loadHome() {
  document.title = "Tiago | Cybersecurity Portfolio";
  updateActiveSidebarItem("menu-home");
  hideTOC();

  // Sync sidebar search input
  const sidebarSearch = document.getElementById("sidebarSearchInput");
  if (sidebarSearch) {
    sidebarSearch.value = "";
  }

  const highlights = [
    { ...data.redteam[0], category: "redteam" },
    { ...data.blueteam[0], category: "blueteam" },
    { ...data.cves[2], category: "cves" }, // React2Shell
    { ...data.labs[5], category: "labs" }, // PwnLab: Init
  ];

  let projectsHtml = "";
  highlights.forEach((project) => {
    const catInfo = categoriesInfo[project.category] || { icon: "📁", colorClass: "" };
    projectsHtml += `
			<div class="project-card ${catInfo.colorClass}" onclick="navigateTo('${project.category}', '${project.slug}')">
				<div>
					<span class="category-tag ${catInfo.colorClass}">${catInfo.icon} ${project.category.toUpperCase()}</span>
					<h3>${project.title}</h3>
					<p>${project.desc || "Clique para ver os detalhes da documentação técnica."}</p>
				</div>
				<div style="font-size: 0.8rem; color: #00ff00; margin-top: 15px; font-weight: bold;">Ver mais →</div>
			</div>
		`;
  });

  content.innerHTML = `
		<h1>Olá, eu sou o Tiago 👋</h1>

		<p>
			Estudante de <strong>Engenharia de Software</strong> com foco em
			<strong>Cibersegurança</strong>, especialmente em segurança ofensiva,
			análise de vulnerabilidades, aplicações web, redes e ambientes Linux.
		</p>

		<p>
			Este site funciona como meu <strong>portfólio técnico</strong>, onde organizo
			documentações de estudo, análises de <strong>CVEs reais</strong>,
			laboratórios práticos de pentest e anotações técnicas.
		</p>

		<hr />

		<h2>🚀 Projetos em Destaque</h2>
		<div class="project-grid">
			${projectsHtml}
		</div>

		<hr />

		<h2>🛠️ Ferramentas e Tecnologias</h2>
		<ul>
			<li><strong>Sistemas:</strong> Linux, Windows</li>
			<li><strong>Web:</strong> HTTP, REST, Next.js, React</li>
			<li><strong>Linguagens:</strong> Python, Bash, JavaScript, C, Java</li>
			<li><strong>Ferramentas:</strong> Nmap, Burp Suite, Gobuster, FFUF, Hydra, SQLMap, Metasploit</li>
			<li><strong>Ambientes:</strong> TryHackMe, VulnHub, Labs locais</li>
		</ul>

		<hr />

		<h2>📢 Últimas publicações no LinkedIn:</h2>
		<ul style="margin-top: 40px; border-top: 1px solid #222; padding-top: 20px;">
			<div class="linkedin-slider">
				<iframe src="https://www.linkedin.com/embed/feed/update/urn:li:ugcPost:7463620284965851137?collapsed=1" frameborder="0" allowfullscreen="" title="Publicação 1"></iframe>
				<iframe src="https://www.linkedin.com/embed/feed/update/urn:li:share:7461081288083472384?collapsed=1" frameborder="0" allowfullscreen="" title="Publicação 2"></iframe>
				<iframe src="https://www.linkedin.com/embed/feed/update/urn:li:ugcPost:7274451392851816449?collapsed=1" frameborder="0" allowfullscreen="" title="Publicação 3"></iframe>
			</div>			
		</ul>

		<hr />

		<h2>📫 Contato</h2>
		<ul>
			<li>🔗 <a href="https://www.linkedin.com/in/tiago-alexandre2001" target="_blank">LinkedIn</a></li>
			<li>💻 <a href="https://github.com/tiago4lex" target="_blank">GitHub</a></li>
		</ul>
		
		<footer>
			<p style="margin-top: 20px;">Conteúdo educacional • Ambientes autorizados • © Tiago Alexandre</p>
		</footer>
	`;

  closeMenu();
}

function navigateCategory(category) {
  location.hash = `/explorer?cat=${category}`;
  closeMenu();
}

function navigateTo(category, slug) {
  location.hash = `/${category}/${slug}`;
  closeMenu();
}

// Global search handling from sidebar
function handleSidebarSearch(event) {
  const query = event.target.value.trim();
  const hash = location.hash.replace("#", "");
  
  if (hash === "/explorer" || hash.startsWith("/explorer") || hash.startsWith("explorer")) {
    const mainSearchInput = document.getElementById("mainSearchInput");
    if (mainSearchInput && mainSearchInput.value !== query) {
      mainSearchInput.value = query;
    }
    explorerState.searchQuery = query;
    updateUrlParams();
    updateExplorerResults();
  } else {
    if (event.key === "Enter" || event.type === "change") {
      location.hash = `/explorer?q=${encodeURIComponent(query)}`;
    }
  }
}

// Extract query parameters from URL hash
function getQueryParams() {
  const hash = location.hash;
  const index = hash.indexOf('?');
  if (index === -1) return {};
  const search = hash.substring(index + 1);
  const params = {};
  search.split('&').forEach(pair => {
    const [key, value] = pair.split('=');
    if (key) params[decodeURIComponent(key)] = decodeURIComponent(value || '');
  });
  return params;
}

// Get all unique tags
function getAllTags() {
  const tags = new Set();
  Object.keys(data).forEach(cat => {
    data[cat].forEach(doc => {
      if (doc.tags) {
        doc.tags.forEach(t => tags.add(t));
      }
    });
  });
  return Array.from(tags).sort();
}

// Check if any filters are active
function isFiltersActive() {
  return explorerState.searchQuery !== "" || 
         explorerState.selectedCategory !== "all" || 
         explorerState.selectedTags.size > 0;
}

// Handle document explorer page
function loadExplorer() {
  document.title = "Explorar Documentos | Tiago Cybersecurity";
  updateActiveSidebarItem("menu-explorer");
  hideTOC();

  const params = getQueryParams();
  explorerState.searchQuery = params.q || "";
  explorerState.selectedCategory = params.cat || "all";
  explorerState.selectedTags.clear();
  if (params.tag) {
    params.tag.split(',').filter(Boolean).forEach(t => explorerState.selectedTags.add(t));
  }
  explorerState.sortBy = params.sort || "title-asc";

  // Sync sidebar search input
  const sidebarSearch = document.getElementById("sidebarSearchInput");
  if (sidebarSearch) {
    sidebarSearch.value = explorerState.searchQuery;
  }

  renderExplorerUI();
  updateExplorerResults();
  closeMenu();
}

// Render Document Explorer Interface
function renderExplorerUI() {
  const allTags = getAllTags();
  
  let categoriesHtml = `
    <button class="explorer-cat-btn ${explorerState.selectedCategory === 'all' ? 'active' : ''}" onclick="setExplorerCategory('all')">
      📁 Todos
    </button>
  `;
  
  Object.keys(categoriesInfo).forEach(cat => {
    const info = categoriesInfo[cat];
    categoriesHtml += `
      <button class="explorer-cat-btn ${explorerState.selectedCategory === cat ? 'active' : ''}" onclick="setExplorerCategory('${cat}')">
        ${info.icon} ${info.name}
      </button>
    `;
  });

  let tagsHtml = "";
  allTags.forEach(tag => {
    const isActive = explorerState.selectedTags.has(tag);
    tagsHtml += `
      <button class="explorer-tag-btn ${isActive ? 'active' : ''}" onclick="toggleExplorerTag('${tag}')">
        #${tag}
      </button>
    `;
  });

  content.innerHTML = `
    <div class="explorer-container">
      <div class="explorer-search-row">
        <div class="explorer-search-wrapper">
          <input type="text" id="mainSearchInput" placeholder="Busque por título, descrição, tags ou comandos..." value="${explorerState.searchQuery}" onkeyup="handleMainSearch(event)">
          <button class="explorer-search-clear" id="btnSearchClear" onclick="clearMainSearch()">✕</button>
        </div>
        <div class="explorer-sort-wrapper">
          <select class="explorer-sort-select" onchange="setExplorerSort(this.value)">
            <option value="title-asc" ${explorerState.sortBy === 'title-asc' ? 'selected' : ''}>🔤 Título (A-Z)</option>
            <option value="title-desc" ${explorerState.sortBy === 'title-desc' ? 'selected' : ''}>🔤 Título (Z-A)</option>
            <option value="read-asc" ${explorerState.sortBy === 'read-asc' ? 'selected' : ''}>⏱️ Tempo de Leitura (Menor)</option>
            <option value="read-desc" ${explorerState.sortBy === 'read-desc' ? 'selected' : ''}>⏱️ Tempo de Leitura (Maior)</option>
          </select>
        </div>
      </div>

      <div class="explorer-categories">
        ${categoriesHtml}
      </div>

      <div class="explorer-tags-section">
        <div class="explorer-tags-title">
          <span>Filtrar por Tags (#)</span>
          ${explorerState.selectedTags.size > 0 ? `<a href="javascript:void(0)" onclick="clearTagsFilter()" style="font-size: 11px; text-decoration: none; color: #888;">limpar tags</a>` : ""}
        </div>
        <div class="explorer-tags-container">
          ${tagsHtml}
        </div>
      </div>

      <div class="explorer-results-info">
        <span id="resultsCount">Encontrando documentos...</span>
        <a href="javascript:void(0)" onclick="resetExplorerFilters()" style="font-size: 12px; color: #00ff00; text-decoration: none; display: ${isFiltersActive() ? 'inline' : 'none'};" id="resetAllLink">Limpar todos os filtros</a>
      </div>

      <div class="explorer-grid" id="explorerGrid">
        <!-- Cards loaded dynamically -->
      </div>
    </div>
  `;

  toggleSearchClearBtn();
}

function toggleSearchClearBtn() {
  const btn = document.getElementById("btnSearchClear");
  if (btn) {
    btn.style.display = explorerState.searchQuery ? "block" : "none";
  }
}

function handleMainSearch(event) {
  const value = event.target.value;
  explorerState.searchQuery = value;
  
  const sidebarSearch = document.getElementById("sidebarSearchInput");
  if (sidebarSearch) {
    sidebarSearch.value = value;
  }
  
  toggleSearchClearBtn();
  updateUrlParams();
  updateExplorerResults();
}

function clearMainSearch() {
  const mainSearchInput = document.getElementById("mainSearchInput");
  if (mainSearchInput) mainSearchInput.value = "";
  
  const sidebarSearch = document.getElementById("sidebarSearchInput");
  if (sidebarSearch) sidebarSearch.value = "";
  
  explorerState.searchQuery = "";
  toggleSearchClearBtn();
  updateUrlParams();
  updateExplorerResults();
}

function updateUrlParams() {
  const params = [];
  if (explorerState.searchQuery) params.push(`q=${encodeURIComponent(explorerState.searchQuery)}`);
  if (explorerState.selectedCategory !== "all") params.push(`cat=${explorerState.selectedCategory}`);
  if (explorerState.selectedTags.size > 0) params.push(`tag=${Array.from(explorerState.selectedTags).join(',')}`);
  if (explorerState.sortBy !== "title-asc") params.push(`sort=${explorerState.sortBy}`);
  
  const queryString = params.length > 0 ? `?${params.join('&')}` : '';
  
  window.removeEventListener("hashchange", router);
  location.hash = `/explorer${queryString}`;
  setTimeout(() => {
    window.addEventListener("hashchange", router);
  }, 50);
}

function updateExplorerResults() {
  const grid = document.getElementById("explorerGrid");
  const countSpan = document.getElementById("resultsCount");
  const resetLink = document.getElementById("resetAllLink");
  
  if (!grid) return;

  let items = [];
  Object.keys(data).forEach(cat => {
    data[cat].forEach(doc => {
      items.push({
        ...doc,
        category: cat
      });
    });
  });

  if (explorerState.selectedCategory !== "all") {
    items = items.filter(doc => doc.category === explorerState.selectedCategory);
  }

  if (explorerState.selectedTags.size > 0) {
    items = items.filter(doc => {
      if (!doc.tags) return false;
      return Array.from(explorerState.selectedTags).every(t => doc.tags.includes(t));
    });
  }

  if (explorerState.searchQuery) {
    const q = explorerState.searchQuery.toLowerCase();
    items = items.filter(doc => {
      const titleMatch = doc.title && doc.title.toLowerCase().includes(q);
      const descMatch = doc.desc && doc.desc.toLowerCase().includes(q);
      const categoryMatch = doc.category && doc.category.toLowerCase().includes(q);
      const tagsMatch = doc.tags && doc.tags.some(t => t.toLowerCase().includes(q));
      return titleMatch || descMatch || categoryMatch || tagsMatch;
    });
  }

  items.sort((a, b) => {
    if (explorerState.sortBy === "title-asc") {
      return a.title.localeCompare(b.title);
    } else if (explorerState.sortBy === "title-desc") {
      return b.title.localeCompare(a.title);
    } else if (explorerState.sortBy === "read-asc") {
      const tA = parseInt(a.readTime) || 5;
      const tB = parseInt(b.readTime) || 5;
      return tA - tB;
    } else if (explorerState.sortBy === "read-desc") {
      const tA = parseInt(a.readTime) || 5;
      const tB = parseInt(b.readTime) || 5;
      return tB - tA;
    }
    return 0;
  });

  countSpan.textContent = `${items.length} ${items.length === 1 ? 'documento encontrado' : 'documentos encontrados'}`;
  
  if (resetLink) {
    resetLink.style.display = isFiltersActive() ? 'inline' : 'none';
  }

  if (items.length === 0) {
    grid.innerHTML = `
      <div class="no-results">
        <span class="error-icon">⚠️</span>
        <h3>Nenhum documento coincide com a busca</h3>
        <p>Tente remover filtros ou pesquisar termos diferentes.</p>
        <button class="btn-reset" onclick="resetExplorerFilters()">Limpar Filtros</button>
      </div>
    `;
    return;
  }

  let html = "";
  items.forEach(doc => {
    const catInfo = categoriesInfo[doc.category] || { name: doc.category, icon: "📁", colorClass: "" };
    
    let tagsHtml = "";
    if (doc.tags) {
      doc.tags.forEach(t => {
        tagsHtml += `<span class="explorer-card-tag" onclick="event.stopPropagation(); filterByTag('${t}')">#${t}</span>`;
      });
    }

    html += `
      <div class="explorer-card ${catInfo.colorClass}" onclick="navigateTo('${doc.category}', '${doc.slug}')">
        <div>
          <div class="explorer-card-meta">
            <span class="explorer-card-cat ${catInfo.colorClass}">${catInfo.icon} ${catInfo.name}</span>
            <span class="explorer-card-time">${doc.readTime || '5 min'}</span>
          </div>
          <h3 class="explorer-card-title">${doc.title}</h3>
          <p class="explorer-card-desc">${doc.desc || 'Clique para ver os detalhes da documentação técnica.'}</p>
        </div>
        <div class="explorer-card-tags">
          ${tagsHtml}
        </div>
      </div>
    `;
  });

  grid.innerHTML = html;
}

function filterByTag(tag) {
  explorerState.selectedTags.clear();
  explorerState.selectedTags.add(tag);
  updateUrlParams();
  renderExplorerUI();
  updateExplorerResults();
}

function toggleExplorerTag(tag) {
  if (explorerState.selectedTags.has(tag)) {
    explorerState.selectedTags.delete(tag);
  } else {
    explorerState.selectedTags.add(tag);
  }
  updateUrlParams();
  renderExplorerUI();
  updateExplorerResults();
}

function clearTagsFilter() {
  explorerState.selectedTags.clear();
  updateUrlParams();
  renderExplorerUI();
  updateExplorerResults();
}

function setExplorerCategory(cat) {
  explorerState.selectedCategory = cat;
  updateUrlParams();
  renderExplorerUI();
  updateExplorerResults();
}

function setExplorerSort(sort) {
  explorerState.sortBy = sort;
  updateUrlParams();
  updateExplorerResults();
}

function resetExplorerFilters() {
  explorerState.searchQuery = "";
  explorerState.selectedCategory = "all";
  explorerState.selectedTags.clear();
  
  const sidebarSearch = document.getElementById("sidebarSearchInput");
  if (sidebarSearch) sidebarSearch.value = "";
  
  updateUrlParams();
  renderExplorerUI();
  updateExplorerResults();
}

function router() {
  let hash = location.hash.replace("#", "");

  if (hash.endsWith("/")) {
    hash = hash.slice(0, -1);
  }

  // Handle Document Explorer routing
  if (hash === "/explorer" || hash === "explorer" || hash.startsWith("/explorer?") || hash.startsWith("explorer?")) {
    loadExplorer();
    return;
  }

  if (!hash || hash === "/") {
    loadHome();
    return;
  }

  const parts = hash.split("/").filter(Boolean);

  if (parts.length === 1) {
    const category = parts[0];
    if (data[category]) {
      // Redirect to the new explorer with category parameter
      location.hash = `/explorer?cat=${category}`;
      return;
    }
  }

  if (parts.length === 2) {
    const [category, slug] = parts;
    const cleanSlug = slug.split('?')[0];
    const item = data[category]?.find((doc) => doc.slug === cleanSlug);

    if (!item) {
      content.innerHTML = "<h2>Documento não encontrado</h2>";
      return;
    }

    // Set sidebar item active highlight
    updateActiveSidebarItem(`menu-${category}`);

    document.title = `${item.title} | Tiago Cybersecurity`;
    loadMarkdown(item.file);
  }
}

async function loadMarkdown(path) {
  content.innerHTML = "<p>Carregando documentação...</p>";

  try {
    const res = await fetch(path);
    let markdown = await res.text();

    const basePath = path.substring(0, path.lastIndexOf("/") + 1);

    markdown = markdown.replace(
      /!\[(.*?)\]\((?!http)(.*?)\)/g,
      (_, alt, src) => `![${alt}](${basePath}${src})`,
    );

    content.innerHTML = marked.parse(markdown);
    aplicarSyntaxHighlighting();
    addCodeCopyButtons();
    renderizarMermaid();
    buildTOC();
    setTimeout(fixImages, 100);
  } catch {
    content.innerHTML = "<p>Erro ao carregar o documento.</p>";
  }

  closeMenu();
}

window.addEventListener("hashchange", router);

document.addEventListener("click", (event) => {
  if (window.innerWidth <= 768 && menu && menuToggle) {
    const isClickInsideMenu = menu.contains(event.target);
    const isClickOnToggle = menuToggle.contains(event.target);

    if (
      !isClickInsideMenu &&
      !isClickOnToggle &&
      menu.classList.contains("open")
    ) {
      closeMenu();
    }
  }
});

window.addEventListener("resize", () => {
  if (window.innerWidth > 768 && menu) {
    menu.classList.remove("open");
    menuToggle.textContent = "☰ Menu";
  }
});

document.querySelectorAll(".menu button").forEach((button) => {
  button.addEventListener("click", closeMenu);
});

const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    if (mutation.type === "childList") {
      aplicarSyntaxHighlighting();
      addCodeCopyButtons();
    }
  });
});

if (content) {
  observer.observe(content, { childList: true, subtree: true });
}

// ===== NOVOS RECURSOS: TOC, MODO FOCO, COPY CODE =====

function hideTOC() {
  const tocPanel = document.getElementById("tocPanel");
  if (tocPanel) {
    tocPanel.classList.add("hidden");
  }
}

let tocObserver = null;
function setupTocScrollTracking() {
  if (tocObserver) tocObserver.disconnect();
  
  const headings = Array.from(document.querySelectorAll("#content h2, #content h3"));
  const tocLinks = document.querySelectorAll(".toc-link");
  
  if (headings.length === 0 || tocLinks.length === 0) return;
  
  tocObserver = new IntersectionObserver((entries) => {
    let activeId = "";
    
    const visibleHeadings = entries.filter(e => e.isIntersecting);
    if (visibleHeadings.length > 0) {
      const sorted = visibleHeadings.sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
      activeId = sorted[0].target.id;
    } else {
      const topHeadings = headings.filter(h => h.getBoundingClientRect().top < 100);
      if (topHeadings.length > 0) {
        activeId = topHeadings[topHeadings.length - 1].id;
      }
    }
    
    if (activeId) {
      tocLinks.forEach(link => {
        link.classList.remove("active");
        if (link.getAttribute("href") === `#${activeId}`) {
          link.classList.add("active");
        }
      });
    }
  }, {
    rootMargin: "-20px 0px -80% 0px",
    threshold: 0.1
  });
  
  headings.forEach(h => tocObserver.observe(h));
}

function buildTOC() {
  const tocPanel = document.getElementById("tocPanel");
  const tocLinks = document.getElementById("tocLinks");
  if (!tocPanel || !tocLinks) return;

  const headings = Array.from(document.querySelectorAll("#content h2, #content h3"));
  
  if (headings.length < 2) {
    tocPanel.classList.add("hidden");
    return;
  }

  tocPanel.classList.remove("hidden");
  
  let html = "";
  headings.forEach((h, index) => {
    if (!h.id) {
      // Slugify title to create clean ID
      h.id = h.textContent
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/(^-|-$)/g, "");
    }
    
    const indentClass = h.tagName.toLowerCase() === "h3" ? "toc-indent" : "";
    html += `
      <a href="#${h.id}" class="toc-link ${indentClass}" onclick="scrollToHeading(event, '${h.id}')">
        ${h.textContent}
      </a>
    `;
  });
  
  tocLinks.innerHTML = html;
  setupTocScrollTracking();
}

function scrollToHeading(event, id) {
  event.preventDefault();
  const el = document.getElementById(id);
  if (el) {
    el.scrollIntoView({ behavior: "smooth", block: "start" });
    
    // Update active state in URL manually if desired without routing reload
    window.removeEventListener("hashchange", router);
    const cleanHash = location.hash.split('?')[0];
    location.hash = `${cleanHash}#${id}`;
    setTimeout(() => {
      window.addEventListener("hashchange", router);
    }, 50);
  }
}

function toggleFocusMode() {
  const sidebar = document.querySelector(".sidebar");
  const focusBtn = document.querySelector(".focus-mode-btn");
  const focusIcon = document.querySelector(".focus-icon");
  
  if (!sidebar) return;
  
  sidebar.classList.toggle("collapsed");
  
  const isCollapsed = sidebar.classList.contains("collapsed");
  
  if (isCollapsed) {
    focusIcon.textContent = "▶";
    focusBtn.setAttribute("title", "Sair do Modo Foco (Mostrar Sidebar)");
    focusBtn.classList.add("collapsed");
  } else {
    focusIcon.textContent = "◀";
    focusBtn.setAttribute("title", "Modo Foco (Ocultar Sidebar)");
    focusBtn.classList.remove("collapsed");
  }
}

function addCodeCopyButtons() {
  const codeBlocks = document.querySelectorAll("pre");
  
  codeBlocks.forEach(pre => {
    if (pre.querySelector(".copy-code-btn")) return;
    
    const code = pre.querySelector("code");
    if (!code) return;
    
    const btn = document.createElement("button");
    btn.className = "copy-code-btn";
    btn.innerHTML = "Copiar";
    btn.type = "button";
    
    btn.addEventListener("click", () => {
      const codeText = code.innerText;
      navigator.clipboard.writeText(codeText).then(() => {
        btn.innerHTML = "Copiado!";
        btn.classList.add("success");
        setTimeout(() => {
          btn.innerHTML = "Copiar";
          btn.classList.remove("success");
        }, 2000);
      }).catch(err => {
        console.error("Erro ao copiar: ", err);
        btn.innerHTML = "Erro";
      });
    });
    
    pre.appendChild(btn);
  });
}

async function init() {
  try {
    const res = await fetch("documents.json");
    data = await res.json();
    router();
  } catch (err) {
    console.error("Erro ao carregar banco de dados de documentos:", err);
    content.innerHTML = "<h2>Erro crítico</h2><p>Não foi possível carregar os documentos.</p>";
  }
}

init();
