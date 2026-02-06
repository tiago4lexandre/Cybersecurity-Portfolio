const content = document.getElementById('content');

const data = {
	checklists: [
		{ title: 'Pentest Checklist', file: 'Checklists/Pentest-Checklist/README.md' },
	],
	cves: [
		{ title: 'React2Shell — CVE-2025-55182', file: 'Vulnerabilidades/React2Shell/README.md' },
		{ title: 'Dirty Pipe — CVE-2022-0847', file: 'Vulnerabilidades/DirtyPipez/README.md' },
		{ title: 'Pwnkit — CVE-2021-4034', file: 'Vulnerabilidades/Pwnkit/README.md'},
	],
	linux: [
		{ title: 'Linux Privilege Escalation', file: 'Linux/Linux-Privilege-Escalation/README.md' },
		{ title: 'Stable Reverse Shell', file: 'Linux/Stable-ReverseShell/README.md' },
	],
	network: [
		{ title: 'ARP Spoofing & MITM', file: 'Network/ARP-Spoofing-MITM/README.md' },
	],
	tools: [
		{ title: 'Gobuster', file: 'Ferramentas/GoBuster/README.md' },
		{ title: 'FFUF', file: 'Ferramentas/FFUF/README.md' },
		{ title: 'Hydra', file: 'Ferramentas/Hydra/README.md' },
		{ title: 'John The Ripper', file: 'Ferramentas/John-The-Ripper/README.md' },
	],
	labs: [
		{ title: 'Linux Privilege Escalation — TryHackMe', file: 'Laboratorios/THM-LinuxPrivilegeEscalation/README.md' },
		{ title: 'Mr. Robot — TryHackMe', file: 'Laboratorios/THM-MrRobot/README.md' },
		{ title: 'Gallery — TryHackMe', file: 'Laboratorios/THM-Gallery/README.md' },
		{ title: 'Break Out The Cage — TryHackMe', file: 'Laboratorios/THM-BreakOutTheCage/README.md' },
		{ title: 'PwnLab: Init', file: 'Laboratorios/PWNLAB/README.md' },
	],
};

function loadHome() {
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
			laboratórios práticos de pentest e anotações técnicas voltadas a compreender
			como os ataques funcionam, suas causas e formas adequadas de mitigação.
		</p>

		<hr />

		<h2>🛠️ Ferramentas e Tecnologias</h2>

		<ul>
			<li><strong>Sistemas:</strong> Linux, Windows</li>
			<li><strong>Web:</strong> HTTP, REST, Next.js, React</li>
			<li><strong>Linguagens:</strong> Python, Bash, JavaScript, C, Java</li>
			<li>
				<strong>Ferramentas:</strong>
				Nmap, Burp Suite, Netcat, Socat, Gobuster, FFUF, Hydra,
				John The Ripper, Nikto, SQLMap, Metasploit
			</li>
			<li><strong>Ambientes:</strong> TryHackMe, VulnHub, Labs locais</li>
		</ul>

		<hr />

		<h2>🎯 Áreas de Interesse</h2>

		<ul>
			<li>Web Pentest & AppSec</li>
			<li>Linux Privilege Escalation</li>
			<li>Exploração de vulnerabilidades (CVE)</li>
			<li>Pós-exploração e movimentação lateral</li>
			<li>Hardening e boas práticas defensivas</li>
		</ul>

		<hr />

		<h2>📫 Contato</h2>

		<ul>
			<li>
				🔗 <strong>LinkedIn:</strong>
				<a href="https://www.linkedin.com/in/tiago-alexandre2001" target="_blank">
					linkedin.com/in/tiago-alexandre2001
				</a>
			</li>
			<li>
				💻 <strong>GitHub:</strong>
				<a href="https://github.com/tiago4lex" target="_blank">
					github.com/tiago4lex
				</a>
			</li>
		</ul>

		<footer>
			Conteúdo educacional • Ambientes autorizados • © Tiago Alexandre
		</footer>
	`;
}

function toggleMenu() {
  document.querySelector('.menu').classList.toggle('open');
}


function loadCategory(category) {
	const items = data[category];

	let html = `<h2>${category.toUpperCase()}</h2><div class="doc-list">`;

	items.forEach((item) => {
		html += `
			<div class="doc-item" onclick="loadMarkdown('${item.file}')">
				${item.title}
			</div>
		`;
	});

	html += '</div>';
	content.innerHTML = html;
}

async function loadMarkdown(path) {
	content.innerHTML = '<p>Carregando documentação...</p>';

	try {
		const res = await fetch(path);
		let markdown = await res.text();

		// 🔧 Correção de paths relativos das imagens
		const basePath = path.substring(0, path.lastIndexOf('/') + 1);

		markdown = markdown.replace(
			/!\[(.*?)\]\((?!http)(.*?)\)/g,
			(match, alt, src) => {
				return `![${alt}](${basePath}${src})`;
			}
		);

		// MARKED: Markdown → HTML correto
		const html = marked.parse(markdown);
		content.innerHTML = html;

	} catch (e) {
		content.innerHTML = '<p>Erro ao carregar o documento.</p>';
	}
}


loadHome();


