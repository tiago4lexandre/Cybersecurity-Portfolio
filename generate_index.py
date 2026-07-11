import os
import re
import json

# Mapeamento de pastas físicas para chaves de categoria no frontend
category_mapping = {
    "RedTeam": "redteam",
    "BlueTeam": "blueteam",
    "Forensics": "forensics",
    "Vulnerabilidades": "cves",
    "Linux": "linux",
    "Windows": "windows",
    "Network": "network",
    "Ferramentas": "tools",
    "Laboratorios": "labs"
}

def slugify(text):
    text = text.lower()
    text = re.sub(r'[^a-z0-9\s-]', '', text)
    text = re.sub(r'[\s_]+', '-', text)
    return text.strip('-')

def parse_metadata(content, default_title, default_category):
    meta = {
        "title": default_title,
        "desc": f"Documentação técnica sobre {default_title}.",
        "tags": [default_category.lower()],
        "readTime": "5 min"
    }
    
    # Busca por blocos de comentário HTML <!-- ... --> no início do arquivo
    comment_pattern = re.compile(r'^<!--\s*(.*?)\s*-->', re.DOTALL)
    match = comment_pattern.search(content.strip())
    
    if match:
        block = match.group(1)
        for line in block.split('\n'):
            if ':' in line:
                key, val = line.split(':', 1)
                key = key.strip()
                val = val.strip()
                
                if key == 'tags':
                    meta['tags'] = [t.strip() for t in val.split(',') if t.strip()]
                elif key in ['title', 'desc', 'readTime']:
                    meta[key] = val
                    
    # Estimativa de tempo de leitura se não estiver definido
    if 'readTime' not in meta or not meta['readTime']:
        words = len(content.split())
        minutes = max(1, round(words / 180))
        meta['readTime'] = f"{minutes} min"
        
    return meta

def generate_index():
    print("Iniciando geração de índice automatizada...")
    
    final_documents = {cat: [] for cat in category_mapping.values()}
    total_docs = 0
    
    for root_dir, cat_key in category_mapping.items():
        if not os.path.exists(root_dir):
            continue
            
        # Percorre subdiretórios da categoria
        for sub_dir in sorted(os.listdir(root_dir)):
            sub_path = os.path.join(root_dir, sub_dir)
            if not os.path.isdir(sub_path):
                continue
                
            # Procura por arquivos .md no subdiretório
            for file_name in os.listdir(sub_path):
                if file_name.endswith('.md'):
                    file_path = os.path.join(sub_path, file_name)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        # Título padrão caso não encontre
                        default_title = file_name[:-3].replace('-', ' ').title()
                        
                        # Extrair metadados
                        meta = parse_metadata(content, default_title, root_dir)
                        slug = slugify(meta.get("title", default_title))
                        
                        final_documents[cat_key].append({
                            "title": meta.get("title", default_title),
                            "file": file_path,
                            "slug": slug,
                            "desc": meta.get("desc", ""),
                            "tags": meta.get("tags", []),
                            "readTime": meta.get("readTime", "5 min")
                        })
                        
                        total_docs += 1
                        print(f"Indexado [{root_dir}]: {file_path} -> {meta.get('title')}")
                        
                    except Exception as e:
                        print(f"Erro ao indexar arquivo {file_path}: {e}")
                        
    # Grava o documents.json final
    with open("documents.json", "w", encoding="utf-8") as f:
        json.dump(final_documents, f, indent=2, ensure_ascii=False)
        
    print(f"Processo concluído! Total de {total_docs} documentos indexados em documents.json.")

if __name__ == "__main__":
    generate_index()
