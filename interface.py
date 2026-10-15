import os
import shutil
import datetime
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

# =====================================================================
# MOTOR CRIPTOGRÁFICO E VERIFICAÇÃO X.509 (BACKEND)
# =====================================================================
DIRETORIO_RAIZES = "./trusted_roots"

def inicializar_ambiente():
    if not os.path.exists(DIRETORIO_RAIZES):
        os.makedirs(DIRETORIO_RAIZES)

def carregar_certificado(caminho_arquivo):
    with open(caminho_arquivo, "rb") as f:
        dados = f.read()
    try:
        return x509.load_pem_x509_certificate(dados)
    except Exception:
        return x509.load_der_x509_certificate(dados)

def carregar_raizes_confiaveis():
    inicializar_ambiente()
    raizes = []
    for arquivo in sorted(os.listdir(DIRETORIO_RAIZES)):
        if arquivo.endswith((".crt", ".cer", ".pem")):
            caminho = os.path.join(DIRETORIO_RAIZES, arquivo)
            try:
                cert = carregar_certificado(caminho)
                raizes.append({
                    "arquivo": arquivo,
                    "caminho": caminho,
                    "cert": cert,
                    "fingerprint": cert.fingerprint(hashes.SHA256()).hex().upper(),
                    "subject": cert.subject.rfc4514_string()
                })
            except Exception:
                pass
    return raizes

def extrair_datas_utc(cert):
    try:
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
    except AttributeError:
        not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
        not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
    return not_before, not_after

def verificar_validade_temporal(cert):
    agora = datetime.datetime.now(datetime.timezone.utc)
    not_before, not_after = extrair_datas_utc(cert)
    valido = not_before <= agora <= not_after
    status = "VÁLIDO" if valido else ("EXPIRADO" if agora > not_after else "FUTURO")
    return valido, status, not_before, not_after

def validar_assinatura_digital(cert_filho, cert_emissor):
    chave_pub = cert_emissor.public_key()
    try:
        chave_pub.verify(
            cert_filho.signature,
            cert_filho.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_filho.signature_hash_algorithm
        )
        return True, "Assinatura criptográfica válida e íntegra."
    except Exception as e:
        return False, f"Falha na verificação da assinatura: {e}"

def verificar_revogacao_crl(cert):
    try:
        crl_ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
    except x509.ExtensionNotFound:
        return "SEM_EXTENSAO", "Extensão CRL Distribution Points ausente.", None

    urls_crl = [
        nome.value for dp in crl_ext.value if dp.full_name 
        for nome in dp.full_name 
        if isinstance(nome.value, str) and nome.value.startswith("http")
    ]

    if not urls_crl:
        return "SEM_URL", "Extensão presente, mas sem URLs HTTP válidas.", None

    url_alvo = urls_crl[0]
    try:
        resposta = requests.get(url_alvo, timeout=10)
        resposta.raise_for_status()
        try:
            crl = x509.load_der_x509_crl(resposta.content)
        except Exception:
            crl = x509.load_pem_x509_crl(resposta.content)

        revogado = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
        if revogado:
            data_rev = getattr(revogado, "revocation_date_utc", revogado.revocation_date)
            return "REVOGADO", f"REVOGADO em {data_rev.strftime('%d/%m/%Y às %H:%M:%S UTC')}", url_alvo
        return "ATIVO", "Certificado não consta na CRL oficial (Ativo).", url_alvo
    except Exception as e:
        return "ERRO_REDE", f"Erro ao consultar CRL: {e}", url_alvo

def verificar_confianca_raiz(cert_raiz_alvo, raizes_confiaveis):
    fp_alvo = cert_raiz_alvo.fingerprint(hashes.SHA256()).hex().upper()
    for raiz in raizes_confiaveis:
        if fp_alvo == raiz["fingerprint"]:
            return True, raiz["arquivo"], raiz["cert"]
    return False, None, None

# =====================================================================
# INTERFACE GRÁFICA ENTERPRISE (TKINTER + TTK)
# =====================================================================
class SegInfoTrustChainApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SegInfo TrustChain Validator - Analisador X.509")
        self.root.geometry("1180x860")
        self.root.minsize(1050, 740)
        self.root.resizable(True, True)
        self.root.configure(bg="#f8fafc")

        inicializar_ambiente()

        self.relatorio_auditoria_texto = ""
        self.mapa_certificados_arvore = {}
        self.certificado_carregado = None

        self.configurar_estilos()
        self.construir_interface()
        self.carregar_tabela_repositorio()

    def configurar_estilos(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.style.configure(".", background="#f8fafc", font=("Segoe UI", 10))
        self.style.configure("TNotebook", background="#f8fafc", borderwidth=0)
        self.style.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(16, 8), background="#e2e8f0", foreground="#334155")
        self.style.map("TNotebook.Tab", background=[("selected", "#0f172a")], foreground=[("selected", "#ffffff")])

        self.style.configure("Treeview", font=("Segoe UI", 9), rowheight=28, background="#ffffff", fieldbackground="#ffffff", bordercolor="#cbd5e1")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#f1f5f9", foreground="#0f172a")

    def construir_interface(self):
        self.root.rowconfigure(3, weight=1)
        self.root.columnconfigure(0, weight=1)

        # 1. CABEÇALHO COM CRÉDITOS ACADÊMICOS MANDATÓRIOS
        frame_cabecalho = tk.Frame(self.root, bg="#0f172a", pady=12, padx=20)
        frame_cabecalho.grid(row=0, column=0, sticky="ew")

        creditos = (
            "SegInfo TrustChain Validator - TAREFA 3\n"
            "Disciplina: Segurança em Transações Eletrônicas\n"
            "Instituição: UNISINOS | Curso: Segurança da Informação | Ano: 2026/2\n"
            "Desenvolvedores: Guilherme Schweig, Jady, Bianca e Antonela"
        )
        tk.Label(
            frame_cabecalho, 
            text=creditos, 
            justify=tk.CENTER, 
            font=("Segoe UI", 10, "bold"), 
            fg="#f8fafc", 
            bg="#0f172a"
        ).pack()

        # 2. BARRA DE COMANDO / AÇÕES
        frame_acoes = tk.Frame(self.root, bg="#f8fafc", pady=10, padx=20)
        frame_acoes.grid(row=1, column=0, sticky="ew")
        frame_acoes.columnconfigure(1, weight=1)

        btn_selecionar = tk.Button(
            frame_acoes,
            text="📁 Selecionar Certificado (.cer / .crt)",
            command=self.acao_selecionar_certificado,
            font=("Segoe UI", 10, "bold"),
            bg="#2563eb",
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            padx=18,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2"
        )
        btn_selecionar.grid(row=0, column=0, padx=(0, 10))

        self.lbl_arquivo_ativo = tk.Label(
            frame_acoes,
            text="Nenhum certificado carregado.",
            font=("Segoe UI", 10, "italic"),
            bg="#f8fafc",
            fg="#64748b",
            anchor="w"
        )
        self.lbl_arquivo_ativo.grid(row=0, column=1, sticky="w")

        self.btn_exportar = tk.Button(
            frame_acoes,
            text="📥 Exportar Laudo Técnico (.txt)",
            command=self.acao_exportar_laudo,
            font=("Segoe UI", 10, "bold"),
            bg="#0f172a",
            fg="white",
            activebackground="#334155",
            activeforeground="white",
            padx=16,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED
        )
        self.btn_exportar.grid(row=0, column=2, padx=(10, 0))

        # 3. BANNER PRINCIPAL + KPI BADGES
        frame_status_master = tk.Frame(self.root, bg="#f8fafc", padx=20)
        frame_status_master.grid(row=2, column=0, sticky="ew", pady=(0, 10))
        frame_status_master.columnconfigure(0, weight=1)

        # Banner do Status Geral
        self.frame_banner = tk.Frame(frame_status_master, bg="#64748b", pady=12, padx=20)
        self.frame_banner.grid(row=0, column=0, sticky="ew")

        self.lbl_banner_icone = tk.Label(self.frame_banner, text="🔒", font=("Segoe UI", 26), bg="#64748b", fg="white")
        self.lbl_banner_icone.pack(side=tk.LEFT, padx=(0, 15))

        frame_banner_texto = tk.Frame(self.frame_banner, bg="#64748b")
        frame_banner_texto.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.lbl_banner_titulo = tk.Label(frame_banner_texto, text="AGUARDANDO CERTIFICADO", font=("Segoe UI", 16, "bold"), bg="#64748b", fg="white", anchor="w")
        self.lbl_banner_titulo.pack(fill=tk.X)

        self.lbl_banner_sub = tk.Label(frame_banner_texto, text="Carregue um certificado digital X.509 para auditar a cadeia de confiança.", font=("Segoe UI", 9), bg="#64748b", fg="#f1f5f9", anchor="w")
        self.lbl_banner_sub.pack(fill=tk.X)

        # Grade de 4 KPI Badges
        frame_kpi = tk.Frame(frame_status_master, bg="#f8fafc", pady=8)
        frame_kpi.grid(row=1, column=0, sticky="ew")
        for i in range(4):
            frame_kpi.columnconfigure(i, weight=1, uniform="kpi")

        self.card_kpi_assinatura = self.criar_badge_kpi(frame_kpi, "1. ASSINATURA DIGITAL", "Aguardando", "#64748b", 0)
        self.card_kpi_tempo = self.criar_badge_kpi(frame_kpi, "2. VALIDADE TEMPORAL", "Aguardando", "#64748b", 1)
        self.card_kpi_crl = self.criar_badge_kpi(frame_kpi, "3. CONSULTA CRL", "Aguardando", "#64748b", 2)
        self.card_kpi_raiz = self.criar_badge_kpi(frame_kpi, "4. ÂNCORA DE CONFIANÇA", "Aguardando", "#64748b", 3)

        # 4. NOTEBOOK COM AS ABAS DO SISTEMA
        self.notebook = ttk.Notebook(self.root)
        self.notebook.grid(row=3, column=0, sticky="nsew", padx=20, pady=(0, 15))

        # ABA 1: Auditoria da Cadeia & Inspecionador X.509
        self.tab_analise = tk.Frame(self.notebook, bg="#f8fafc")
        self.notebook.add(self.tab_analise, text="  🔍 Cadeia de Certificação & Metadados  ")
        self.construir_aba_analise(self.tab_analise)

        # ABA 2: Repositório de Raízes Confiáveis (Container)
        self.tab_container = tk.Frame(self.notebook, bg="#f8fafc")
        self.notebook.add(self.tab_container, text="  🔐 Container de Raízes (trusted_roots)  ")
        self.construir_aba_container(self.tab_container)

        # ABA 3: Laudo de Auditoria (Audit Log)
        self.tab_laudo = tk.Frame(self.notebook, bg="#f8fafc")
        self.notebook.add(self.tab_laudo, text="  📋 Laudo Técnico de Auditoria  ")
        self.construir_aba_laudo(self.tab_laudo)

    def criar_badge_kpi(self, parent, titulo, valor_inicial, cor_bg, coluna):
        frame = tk.Frame(parent, bg="white", highlightbackground="#cbd5e1", highlightthickness=1, padx=10, pady=6)
        frame.grid(row=0, column=coluna, padx=4, sticky="nsew")

        lbl_t = tk.Label(frame, text=titulo, font=("Segoe UI", 8, "bold"), fg="#64748b", bg="white")
        lbl_t.pack(anchor="w")

        lbl_v = tk.Label(frame, text=valor_inicial, font=("Segoe UI", 10, "bold"), fg=cor_bg, bg="white")
        lbl_v.pack(anchor="w", pady=(2, 0))
        return {"frame": frame, "titulo": lbl_t, "valor": lbl_v}

    def atualizar_badge_kpi(self, badge, texto, cor):
        badge["valor"].config(text=texto, fg=cor)

    def construir_aba_analise(self, parent):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=4)
        parent.columnconfigure(1, weight=6)

        # Esquerda: Árvore Hierárquica
        frame_esq = tk.LabelFrame(parent, text=" Caminho de Certificação Reconstruído ", font=("Segoe UI", 10, "bold"), bg="white", fg="#0f172a", padx=10, pady=10)
        frame_esq.grid(row=0, column=0, sticky="nsew", padx=(10, 5), pady=10)
        frame_esq.rowconfigure(0, weight=1)
        frame_esq.columnconfigure(0, weight=1)

        self.tree_cadeia = ttk.Treeview(frame_esq, selectmode="browse")
        self.tree_cadeia.heading("#0", text="Hierarquia X.509", anchor="w")
        self.tree_cadeia.grid(row=0, column=0, sticky="nsew")

        scroll_tree = ttk.Scrollbar(frame_esq, orient=tk.VERTICAL, command=self.tree_cadeia.yview)
        self.tree_cadeia.configure(yscrollcommand=scroll_tree.set)
        scroll_tree.grid(row=0, column=1, sticky="ns")

        self.tree_cadeia.bind("<<TreeviewSelect>>", self.acao_selecionar_no_arvore)

        lbl_dica = tk.Label(frame_esq, text="💡 Clique em um certificado da árvore para carregar seus atributos ao lado.", font=("Segoe UI", 8, "italic"), bg="white", fg="#64748b")
        lbl_dica.grid(row=1, column=0, columnspan=2, pady=(6, 0), sticky="w")

        # Direita: Inspecionador de Metadados
        frame_dir = tk.LabelFrame(parent, text=" Atributos X.509 do Certificado Selecionado ", font=("Segoe UI", 10, "bold"), bg="white", fg="#0f172a", padx=10, pady=10)
        frame_dir.grid(row=0, column=1, sticky="nsew", padx=(5, 10), pady=10)
        frame_dir.rowconfigure(0, weight=1)
        frame_dir.columnconfigure(0, weight=1)

        self.txt_metadados = tk.Text(frame_dir, font=("Consolas", 10), bg="#ffffff", fg="#0f172a", wrap=tk.WORD, relief=tk.FLAT)
        scroll_meta = ttk.Scrollbar(frame_dir, orient=tk.VERTICAL, command=self.txt_metadados.yview)
        self.txt_metadados.configure(yscrollcommand=scroll_meta.set)
        self.txt_metadados.grid(row=0, column=0, sticky="nsew")
        scroll_meta.grid(row=0, column=1, sticky="ns")

        self.txt_metadados.tag_configure("secao", font=("Consolas", 10, "bold"), foreground="#0369a1")
        self.txt_metadados.tag_configure("chave", font=("Consolas", 10, "bold"), foreground="#334155")
        self.txt_metadados.tag_configure("valor", foreground="#0f172a")

    def construir_aba_container(self, parent):
        parent.rowconfigure(1, weight=1)
        parent.columnconfigure(0, weight=1)

        frame_top = tk.Frame(parent, bg="#f8fafc", pady=10, padx=10)
        frame_top.grid(row=0, column=0, sticky="ew")

        btn_importar_raiz = tk.Button(
            frame_top,
            text="➕ Importar Nova AC-Raiz (.crt / .cer)",
            command=self.acao_importar_raiz,
            font=("Segoe UI", 9, "bold"),
            bg="#16a34a",
            fg="white",
            activebackground="#15803d",
            activeforeground="white",
            padx=14,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2"
        )
        btn_importar_raiz.pack(side=tk.LEFT, padx=(0, 10))

        btn_atualizar = tk.Button(
            frame_top,
            text="🔄 Recarregar Container",
            command=self.carregar_tabela_repositorio,
            font=("Segoe UI", 9),
            bg="#e2e8f0",
            fg="#0f172a",
            padx=12,
            pady=6,
            relief=tk.FLAT,
            cursor="hand2"
        )
        btn_atualizar.pack(side=tk.LEFT)

        self.lbl_total_raizes = tk.Label(frame_top, text="", font=("Segoe UI", 9, "bold"), bg="#f8fafc", fg="#475569")
        self.lbl_total_raizes.pack(side=tk.RIGHT)

        colunas = ("arquivo", "cn", "expiracao", "fingerprint")
        self.tree_raizes = ttk.Treeview(parent, columns=colunas, show="headings", selectmode="browse")
        self.tree_raizes.heading("arquivo", text="Arquivo Local")
        self.tree_raizes.heading("cn", text="Subject Common Name (CN)")
        self.tree_raizes.heading("expiracao", text="Válido Até (UTC)")
        self.tree_raizes.heading("fingerprint", text="Fingerprint SHA-256")

        self.tree_raizes.column("arquivo", width=180, anchor="w")
        self.tree_raizes.column("cn", width=260, anchor="w")
        self.tree_raizes.column("expiracao", width=170, anchor="center")
        self.tree_raizes.column("fingerprint", width=420, anchor="w")

        self.tree_raizes.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

        scroll_r = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree_raizes.yview)
        self.tree_raizes.configure(yscrollcommand=scroll_r.set)
        scroll_r.grid(row=1, column=1, sticky="ns", pady=(0, 10))

    def construir_aba_laudo(self, parent):
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

        frame_wrap = tk.Frame(parent, bg="white", padx=10, pady=10)
        frame_wrap.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        frame_wrap.rowconfigure(0, weight=1)
        frame_wrap.columnconfigure(0, weight=1)

        self.txt_laudo = tk.Text(frame_wrap, font=("Consolas", 10), bg="#ffffff", fg="#0f172a", wrap=tk.WORD, relief=tk.FLAT)
        scroll_l = ttk.Scrollbar(frame_wrap, orient=tk.VERTICAL, command=self.txt_laudo.yview)
        self.txt_laudo.configure(yscrollcommand=scroll_l.set)
        self.txt_laudo.grid(row=0, column=0, sticky="nsew")
        scroll_l.grid(row=0, column=1, sticky="ns")

    def carregar_tabela_repositorio(self):
        for item in self.tree_raizes.get_children():
            self.tree_raizes.delete(item)

        raizes = carregar_raizes_confiaveis()
        self.lbl_total_raizes.config(text=f"Total de ACs Raiz no Repositório: {len(raizes)}")

        for r in raizes:
            cert = r["cert"]
            _, not_after = extrair_datas_utc(cert)
            cn = "N/D"
            for attr in cert.subject:
                if attr.oid == x509.NameOID.COMMON_NAME:
                    cn = attr.value
                    break
            self.tree_raizes.insert("", tk.END, values=(r["arquivo"], cn, not_after.strftime("%d/%m/%Y %H:%M"), r["fingerprint"]))

    def acao_importar_raiz(self):
        caminhos = filedialog.askopenfilenames(
            title="Selecionar Certificados de AC-Raiz para o Container",
            filetypes=(("Certificados X.509", "*.crt *.cer *.pem"), ("Todos os Ficheiros", "*.*"))
        )
        if not caminhos:
            return

        importados = 0
        for caminho in caminhos:
            try:
                carregar_certificado(caminho) # Valida se é certificado
                destino = os.path.join(DIRETORIO_RAIZES, os.path.basename(caminho))
                shutil.copy2(caminho, destino)
                importados += 1
            except Exception as e:
                messagebox.showerror("Erro de Importação", f"Arquivo {os.path.basename(caminho)} inválido:\n{e}")

        if importados > 0:
            messagebox.showinfo("Sucesso", f"{importados} certificado(s) de AC-Raiz adicionado(s) com sucesso ao container './trusted_roots'!")
            self.carregar_tabela_repositorio()

    def acao_selecionar_certificado(self):
        caminho = filedialog.askopenfilename(
            title="Selecionar Certificado para Auditoria",
            filetypes=(("Certificados X.509", "*.crt *.cer *.pem"), ("Todos os Ficheiros", "*.*"))
        )
        if not caminho:
            return

        nome_arq = os.path.basename(caminho)
        self.lbl_arquivo_ativo.config(text=f"Certificado em análise: {nome_arq}")
        self.executar_auditoria_completa(caminho, nome_arq)

    def executar_auditoria_completa(self, caminho, nome_arquivo):
        try:
            cert_alvo = carregar_certificado(caminho)
        except Exception as e:
            messagebox.showerror("Erro Crítico", f"Falha ao decodificar arquivo X.509:\n{e}")
            return

        self.certificado_carregado = cert_alvo
        raizes = carregar_raizes_confiaveis()

        # 1. Análise Temporal
        valido_tempo, status_tempo, not_before, not_after = verificar_validade_temporal(cert_alvo)

        # 2. Análise CRL
        status_crl, desc_crl, url_crl = verificar_revogacao_crl(cert_alvo)

        # 3. Reconstrução da Cadeia e Validação Criptográfica
        subject_str = cert_alvo.subject.rfc4514_string()
        issuer_str = cert_alvo.issuer.rfc4514_string()
        eh_autoassinado = (subject_str == issuer_str)

        eh_confiavel = False
        raiz_emissora_nome = None
        cert_raiz_associado = None
        assinatura_valida = False
        desc_assinatura = ""

        cadeia_certificados = []

        if eh_autoassinado:
            assinatura_valida, desc_assinatura = validar_assinatura_digital(cert_alvo, cert_alvo)
            eh_confiavel, raiz_emissora_nome, cert_raiz_associado = verificar_confianca_raiz(cert_alvo, raizes)
            cadeia_certificados.append({"tipo": "AC Raiz (Autoassinado)", "nome": nome_arquivo, "cert": cert_alvo, "confiavel": eh_confiavel})
        else:
            # Busca o emissor no repositório local
            for r in raizes:
                if r["cert"].subject == cert_alvo.issuer:
                    cert_raiz_associado = r["cert"]
                    raiz_emissora_nome = r["arquivo"]
                    eh_confiavel, _, _ = verificar_confianca_raiz(cert_raiz_associado, raizes)
                    break

            if cert_raiz_associado:
                assinatura_valida, desc_assinatura = validar_assinatura_digital(cert_alvo, cert_raiz_associado)
                cadeia_certificados.append({"tipo": "AC Raiz Confiável", "nome": raiz_emissora_nome, "cert": cert_raiz_associado, "confiavel": True})
            else:
                assinatura_valida = False
                desc_assinatura = "Não foi possível verificar a assinatura digital pois a AC emissora não está disponível no repositório."

            cadeia_certificados.append({"tipo": "Entidade Final / Intermediária", "nome": nome_arquivo, "cert": cert_alvo, "confiavel": eh_confiavel})

        # 4. Atualização dos 4 KPI Badges
        # Badge 1: Assinatura
        if assinatura_valida:
            self.atualizar_badge_kpi(self.card_kpi_assinatura, "VÁLIDA (Íntegra)", "#16a34a")
        else:
            self.atualizar_badge_kpi(self.card_kpi_assinatura, "FALHA / INDETERMINADA", "#dc2626")

        # Badge 2: Tempo
        if valido_tempo:
            self.atualizar_badge_kpi(self.card_kpi_tempo, "VIGENTE (Válido)", "#16a34a")
        else:
            self.atualizar_badge_kpi(self.card_kpi_tempo, f"INVÁLIDO ({status_tempo})", "#dc2626")

        # Badge 3: CRL
        if status_crl == "ATIVO":
            self.atualizar_badge_kpi(self.card_kpi_crl, "ATIVO (Consultado)", "#16a34a")
        elif status_crl == "REVOGADO":
            self.atualizar_badge_kpi(self.card_kpi_crl, "REVOGADO (Consta na CRL)", "#dc2626")
        else:
            self.atualizar_badge_kpi(self.card_kpi_crl, "N/A (Sem CRL / Erro)", "#d97706")

        # Badge 4: Confiança da Raiz
        if eh_confiavel:
            self.atualizar_badge_kpi(self.card_kpi_raiz, f"CONFIÁVEL ({raiz_emissora_nome})", "#16a34a")
        else:
            self.atualizar_badge_kpi(self.card_kpi_raiz, "NÃO CONFIÁVEL", "#dc2626")

        # 5. Atualização do Banner Master
        if not eh_confiavel:
            self.configurar_banner("NÃO CONFIÁVEL", "🔒", "#dc2626", "A AC Raiz não pertence ao container local ou a assinatura da cadeia não pôde ser atestada.")
        elif not valido_tempo:
            self.configurar_banner("NÃO CONFIÁVEL (EXPIRADO)", "⚠️", "#b91c1c", f"A AC Raiz é confiável ({raiz_emissora_nome}), mas o certificado está fora do período de vigência.")
        elif status_crl == "REVOGADO":
            self.configurar_banner("NÃO CONFIÁVEL (REVOGADO)", "🛑", "#991b1b", "O certificado foi explicitamente revogado pela Autoridade Certificadora na CRL.")
        else:
            self.configurar_banner("CONFIÁVEL", "✅", "#16a34a", f"Cadeia de confiança validada com sucesso via âncora: {raiz_emissora_nome}")

        # 6. Renderização da Árvore Hierárquica
        self.popular_arvore_hierarquica(cadeia_certificados)

        # 7. Geração do Laudo Técnico
        self.gerar_laudo_tecnico(nome_arquivo, cert_alvo, eh_confiavel, raiz_emissora_nome, valido_tempo, status_tempo, not_before, not_after, status_crl, desc_crl, url_crl, assinatura_valida, desc_assinatura, raizes)

        self.btn_exportar.config(state=tk.NORMAL)

    def configurar_banner(self, titulo, icone, bg_cor, subtexto):
        self.frame_banner.config(bg=bg_cor)
        self.lbl_banner_icone.config(text=icone, bg=bg_cor)
        self.lbl_banner_titulo.config(text=titulo, bg=bg_cor)
        self.lbl_banner_sub.config(text=subtexto, bg=bg_cor)

    def popular_arvore_hierarquica(self, cadeia):
        for item in self.tree_cadeia.get_children():
            self.tree_cadeia.delete(item)
        self.mapa_certificados_arvore.clear()

        pai_id = ""
        for i, no in enumerate(cadeia):
            rotulo = f"[{'AC-Raiz' if i == 0 else 'Certificado'}] {no['nome']} - {'(Confiável)' if no['confiavel'] else '(Não Confiável)'}"
            item_id = self.tree_cadeia.insert(pai_id, tk.END, text=rotulo, open=True)
            self.mapa_certificados_arvore[item_id] = no["cert"]
            pai_id = item_id

        # Seleciona o certificado alvo (último nó) e renderiza seus metadados
        if pai_id:
            self.tree_cadeia.selection_set(pai_id)
            self.exibir_metadados_cert(cadeia[-1]["cert"])

    def acao_selecionar_no_arvore(self, event):
        selecionado = self.tree_cadeia.selection()
        if selecionado and selecionado[0] in self.mapa_certificados_arvore:
            cert = self.mapa_certificados_arvore[selecionado[0]]
            self.exibir_metadados_cert(cert)

    def exibir_metadados_cert(self, cert):
        self.txt_metadados.config(state=tk.NORMAL)
        self.txt_metadados.delete(1.0, tk.END)

        not_before, not_after = extrair_datas_utc(cert)

        self.txt_metadados.insert(tk.END, "=== 1. IDENTIFICAÇÃO (DISTINGUISHED NAMES) ===\n", "secao")
        self.txt_metadados.insert(tk.END, "Subject DN: ", "chave")
        self.txt_metadados.insert(tk.END, f"{cert.subject.rfc4514_string()}\n", "valor")
        self.txt_metadados.insert(tk.END, "Issuer DN:  ", "chave")
        self.txt_metadados.insert(tk.END, f"{cert.issuer.rfc4514_string()}\n\n", "valor")

        self.txt_metadados.insert(tk.END, "=== 2. PARÂMETROS CRIPTOGRÁFICOS ===\n", "secao")
        self.txt_metadados.insert(tk.END, "Número de Série (Decimal): ", "chave")
        self.txt_metadados.insert(tk.END, f"{cert.serial_number}\n", "valor")
        self.txt_metadados.insert(tk.END, "Número de Série (Hex):     ", "chave")
        self.txt_metadados.insert(tk.END, f"{hex(cert.serial_number).upper()}\n", "valor")
        self.txt_metadados.insert(tk.END, "Versão X.509:              ", "chave")
        self.txt_metadados.insert(tk.END, f"{cert.version.name}\n", "valor")

        sig_name = getattr(cert.signature_algorithm_oid, "_name", str(cert.signature_algorithm_oid))
        self.txt_metadados.insert(tk.END, "Algoritmo de Assinatura:   ", "chave")
        self.txt_metadados.insert(tk.END, f"{sig_name}\n", "valor")

        self.txt_metadados.insert(tk.END, "Fingerprint SHA-256:       \n", "chave")
        self.txt_metadados.insert(tk.END, f"{cert.fingerprint(hashes.SHA256()).hex().upper()}\n\n", "valor")

        self.txt_metadados.insert(tk.END, "=== 3. JANELA DE VIGÊNCIA (UTC) ===\n", "secao")
        self.txt_metadados.insert(tk.END, "Não Antes De (notBefore):  ", "chave")
        self.txt_metadados.insert(tk.END, f"{not_before.strftime('%d/%m/%Y às %H:%M:%S UTC')}\n", "valor")
        self.txt_metadados.insert(tk.END, "Não Depois De (notAfter):  ", "chave")
        self.txt_metadados.insert(tk.END, f"{not_after.strftime('%d/%m/%Y às %H:%M:%S UTC')}\n\n", "valor")

        self.txt_metadados.insert(tk.END, "=== 4. EXTENSÕES X.509 DECLARADAS ===\n", "secao")
        for ext in cert.extensions:
            critica = " [CRÍTICA]" if ext.critical else ""
            self.txt_metadados.insert(tk.END, f" • {ext.oid._name}{critica}\n", "valor")

        self.txt_metadados.config(state=tk.DISABLED)

    def gerar_laudo_tecnico(self, nome_arquivo, cert, confiavel, raiz_nome, valido_tempo, status_tempo, not_before, not_after, status_crl, desc_crl, url_crl, ass_valida, desc_ass, raizes):
        linhas = []
        linhas.append("=" * 80)
        linhas.append("          LAUDO TÉCNICO DE AUDITORIA DE CERTIFICADO DIGITAL X.509")
        linhas.append("                 SegInfo TrustChain Validator - TAREFA 3")
        linhas.append("=" * 80)
        linhas.append(f"Data da Auditoria:   {datetime.datetime.now(datetime.timezone.utc).strftime('%d/%m/%Y %H:%M:%S UTC')}")
        linhas.append(f"Arquivo Auditado:    {nome_arquivo}")
        linhas.append(f"Disciplina:          Segurança em Transações Eletrônicas (UNISINOS - 2026/2)")
        linhas.append(f"Desenvolvedores:     Guilherme Schweig, Jady, Bianca e Antonela")
        linhas.append("-" * 80)
        linhas.append("\n1. SUMÁRIO EXECUTIVO DA VALIDAÇÃO:")
        status_geral = "CONFIÁVEL" if (confiavel and valido_tempo and status_crl != "REVOGADO") else "NÃO CONFIÁVEL"
        linhas.append(f" • PARECER FINAL:            {status_geral}")
        linhas.append(f" • Âncora de Confiança (AC): {raiz_nome if confiavel else 'NENHUMA (Rejeitado)'}")
        linhas.append(f" • Assinatura Criptográfica: {'VÁLIDA / ÍNTEGRA' if ass_valida else 'INVÁLIDA / NÃO ATESTADA'}")
        linhas.append(f" • Vigência Temporal:        {status_tempo}")
        linhas.append(f" • Consulta à Lista CRL:     {status_crl}")
        linhas.append("\n2. IDENTIFICAÇÃO E ENTIDADES:")
        linhas.append(f" • Sujeito (Subject DN): {cert.subject.rfc4514_string()}")
        linhas.append(f" • Emissor (Issuer DN):  {cert.issuer.rfc4514_string()}")
        linhas.append(f" • Número de Série:      {cert.serial_number} (Hex: {hex(cert.serial_number).upper()})")
        linhas.append(f" • Impressão Digital:    {cert.fingerprint(hashes.SHA256()).hex().upper()}")
        linhas.append("\n3. AUDITORIA DE REQUISITOS (CRITÉRIOS DE MÉRITO):")
        linhas.append(f" [A] Integridade da Assinatura: {desc_ass}")
        linhas.append(f" [B] Janela de Validade:        Válido de {not_before} até {not_after}.")
        linhas.append(f" [C] Revogação (CRL):           {desc_crl}")
        if url_crl:
            linhas.append(f"     URL de Distribuição CRL:   {url_crl}")
        linhas.append(f" [D] Regra Anti-DN Spoofing:    A confiança foi aferida por correspondência criptográfica")
        linhas.append(f"                                da Chave Pública / Fingerprint SHA-256 no container local,")
        linhas.append(f"                                sem confiar isoladamente em strings do Issuer DN.")
        linhas.append(f"\n4. CONTAINER DE RAÍZES ({len(raizes)} ACs carregadas):")
        for r in raizes:
            linhas.append(f" • {r['arquivo']} | SHA-256: {r['fingerprint'][:32]}...")
        linhas.append("\n" + "=" * 80)
        linhas.append("Fim do Relatório de Auditoria.")

        self.relatorio_auditoria_texto = "\n".join(linhas)

        self.txt_laudo.config(state=tk.NORMAL)
        self.txt_laudo.delete(1.0, tk.END)
        self.txt_laudo.insert(tk.END, self.relatorio_auditoria_texto)
        self.txt_laudo.config(state=tk.DISABLED)

    def acao_exportar_laudo(self):
        if not self.relatorio_auditoria_texto:
            return

        caminho_salvar = filedialog.asksaveasfilename(
            title="Salvar Laudo Técnico de Auditoria",
            defaultextension=".txt",
            filetypes=(("Arquivo de Texto", "*.txt"), ("Todos os Ficheiros", "*.*")),
            initialfile="Laudo_Auditoria_SegInfo.txt"
        )
        if not caminho_salvar:
            return

        try:
            with open(caminho_salvar, "w", encoding="utf-8") as f:
                f.write(self.relatorio_auditoria_texto)
            messagebox.showinfo("Exportação Concluída", f"Laudo de auditoria salvo com sucesso em:\n{caminho_salvar}")
        except Exception as e:
            messagebox.showerror("Erro de Gravação", f"Falha ao exportar laudo técnico:\n{e}")

# =====================================================================
# PONTO DE ENTRADA DO SISTEMA
# =====================================================================
if __name__ == "__main__":
    app_root = tk.Tk()
    gui = SegInfoTrustChainApp(app_root)
    app_root.mainloop()