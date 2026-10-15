# SegInfo TrustChain Validator

Aplicação para auditoria de Infraestrutura de Chaves Públicas (ICP/PKI), reconstrução de caminhos de certificação X.509 e validação ativa de revogação via CRL. O projeto foi desenvolvido como requisito avaliativo da **Tarefa 3** da disciplina de **Segurança em Transações Eletrônicas** da **UNISINOS**.

---

## Visão Geral

O **SegInfo TrustChain Validator** processa certificados digitais nos formatos `.cer`, `.crt` ou `.pem`, reconstitui a cadeia hierárquica até a AC-Raiz e afere o status de confiança com base em âncoras locais arbitradas pelo usuário.

A implementação adota linguagem de programação de alto nível (Python 3) e bibliotecas criptográficas nativas (`cryptography`), atendendo aos critérios de **Mérito** acadêmico ao dispensar rotinas estruturadas puramente em scripts de terminal.

---

## Funcionalidades

* **Reconstrução da Cadeia de Certificação:** Processa certificados de entidade final ou subordinadas e remonta a árvore hierárquica até a AC-Raiz.


* **Aferição de Confiança sem DN Spoofing:** A verificação de confiança da AC-Raiz não utiliza o *Distinguished Name* (DN) do emissor como critério de decisão. A correspondência é realizada comparando a impressão digital criptográfica (*Fingerprint* SHA-256) e a chave pública com os certificados presentes no container.


* **Container de Raízes Confiáveis (`./trusted_roots`):** Estrutura local em diretório onde o usuário armazena e gerencia as autoridades em que confia. A interface conta com aba dedicada para listar, inspecionar e importar novos certificados raiz.


* **Verificação Ativa de Revogação via CRL:** Extrai o ponto de distribuição ASN.1 *CRL Distribution Points* (OID `2.5.29.31`), realiza requisição de rede HTTP/HTTPS para download da lista e inspeciona se o número de série (*Serial Number*) consta nos registros de revogação.


* **Auditoria de Validade Temporal:** Compara as datas `notBefore` e `notAfter` em UTC com o relógio do sistema, identificando certificados vigentes, expirados ou com vigência futura.


* **Interface Gráfica Responsiva (Tkinter/TTK):** Interface com suporte a tela cheia e redimensionamento dinâmico. Inclui árvore interativa (`ttk.Treeview`) para navegação em cada elo da cadeia, cartões métricos de status (KPI Badges) e inspetor de metadados X.509 completos.


* **Exportação de Laudo Técnico:** Módulo de geração de relatórios formais de auditoria estruturados em formato `.txt` para fins de registro e conformidade.



---

## Arquitetura e Tecnologias

* **Linguagem:** Python 3.


* **Núcleo Criptográfico:** `cryptography` (módulos `x509`, `hashes`, `padding.PKCS1v15`) para análise estrutural ASN.1, cálculo de hashes e validação matemática de assinaturas.


* **Comunicação de Rede:** `requests` para requisições de download de CRLs em formato binário (DER) ou Base64 (PEM).


* **Interface do Usuário:** `tkinter` e `tkinter.ttk` estruturados em layout responsivo com gerenciador de geometria em grid.



---

## Estrutura do Diretório

```text
SegInfo-TrustChain-Validator/
├── interface.py              # Aplicação principal (GUI Tkinter e motor criptográfico)
├── requirements.txt          # Dependências externas do projeto
├── README.md                 # Documentação técnica do sistema
├── trusted_roots/            # Container local de ACs Raiz confiadas pelo usuário
│   └── SegInfoRoot.crt       # Certificado da AC Raiz local gerado em laboratório EJBCA
└── certificados_teste/       # Amostras para homologação e testes de bancada
    ├── SegInfoRSA.crt        # Certificado emitido pela ICP da equipe (Cadeia Válida)
    ├── revoked_badssl.crt    # Certificado revogado para validação de CRL
    └── expired_badssl.crt    # Certificado expirado para teste de vigência temporal

```

---

## Instalação e Execução

### Pré-requisitos

* Python 3.10 ou superior instalado no sistema operacional.


* Gerenciador de pacotes `pip` atualizado.



### 1. Clonar o Repositório

```bash
git clone https://github.com/SEU_USUARIO/SegInfo-TrustChain-Validator.git
cd SegInfo-TrustChain-Validator

```

### 2. Configurar o Ambiente Virtual (Opcional, mas Recomendado)

```bash
# Criar o ambiente virtual
python -m venv .venv

# Ativar no Windows (PowerShell)
.venv\Scripts\Activate.ps1

# Ativar no Linux / macOS
source .venv/bin/activate

```

### 3. Instalar Dependências

```bash
pip install -r requirements.txt

```

*(Caso prefira instalar diretamente: `pip install cryptography requests`)*

### 4. Executar a Aplicação

```bash
python interface.py

```

---

## Metodologia de Testes e Validação Experimental

Os testes práticos foram executados com certificados da hierarquia laboratorial própria (`SegInfo`) e certificados de referência do repositório público [BadSSL](https://badssl.com/):

| Cenário de Teste | Certificado Analisado | Configuração do Container | Comportamento Observado | Status Final |
| --- | --- | --- | --- | --- |
| **Cadeia Confiável Interna** | `SegInfoRSA.crt`<br> | `SegInfoRoot.crt` presente em `./trusted_roots`<br> | Assinatura íntegra; âncora identificada por chave pública/hash SHA-256; período de vigência regular.

 | `CONFIÁVEL`<br> |
| **Revogação via CRL** | `revoked.badssl.com.crt`<br> | Qualquer configuração | Extensão CRL lida; download efetuado via HTTP; serial identificado na lista da AC Let's Encrypt com timestamp exato.

 | `NÃO CONFIÁVEL (REVOGADO)`<br> |
| **Validade Expirada** | `expired.badssl.com.crt`<br> | Raiz cadastrada no container | Comparação com relógio do sistema indicando data posterior ao campo `notAfter`.

 | `NÃO CONFIÁVEL (EXPIRADO)`<br> |
| **Raiz Não Confiável** | `untrusted-root.badssl.com.crt`<br> | Apenas `SegInfoRoot.crt` no container

 | Rejeição por ausência da âncora de confiança no container local, mesmo com estrutura ASN.1 íntegra.

 | `NÃO CONFIÁVEL`<br>
 
---

## Conformidade com os Critérios de Mérito

1. **Análise de Confiança da AC-Raiz:** Não utiliza strings de texto do emissor (*Subject/Issuer DN*), operando exclusivamente via correspondência criptográfica da chave pública e *fingerprint* SHA-256 no container arbitrado pelo usuário.


2. **Análise de Validade e Revogação:** Efetua a checagem temporal em UTC e consulta ativamente a lista CRL remota por meio de requisições de rede.


3. **Implementação Estruturada:** Construída em Python com a biblioteca `cryptography`, dispensando chamadas a binários ou *shell scripts*.


4. **Créditos e Metadados Acadêmicos:** Cabeçalho estático integrado à interface e aos relatórios exportados com identificação institucional completa.



---

## Autoria e Dados Acadêmicos

Trabalho desenvolvido para a disciplina de **Segurança em Transações Eletrônicas** da **Universidade do Vale do Rio dos Sinos (UNISINOS)** — Turma **2026/2**.

* **Docente:** Prof. Luciano Ignaczak


* **Curso:** Segurança da Informação
