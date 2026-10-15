# SegInfo TrustChain Validator

Aplicação de auditoria de Infraestrutura de Chaves Públicas (ICP/PKI) desenvolvida para reconstrução e inspeção do caminho de certificação de certificados digitais X.509 (`.cer`, `.crt`, `.pem`), com consulta ativa de revogação via CRL e validação criptográfica de confiança contra âncoras locais[cite: 1].

Trabalho prático desenvolvido para a **Tarefa 3** da disciplina de **Segurança em Transações Eletrônicas** da **Universidade do Vale do Rio dos Sinos (UNISINOS)**[cite: 1, 10].

---

## Funcionalidades Principais

* **Reconstrução Visual da Cadeia de Certificação:** Árvore hierárquica interativa (`ttk.Treeview`) que mapeia a relação emissor-sujeito da AC Raiz até o certificado da entidade final[cite: 1]. Ao selecionar qualquer certificado na árvore, seus metadados específicos são inspecionados em tempo real.
* **Aferição de Confiança sem DN Spoofing (Critério de Mérito):** A confiança da AC Raiz **não** é arbitrada pelo texto do Emissor (*Issuer DN*)[cite: 1]. O sistema calcula a impressão digital criptográfica (*Fingerprint* SHA-256) e extrai a chave pública do certificado, cruzando-a matematicamente com os certificados contidos no container de confiança[cite: 1].
* **Container de Raízes Arbitrado pelo Usuário:** Estrutura local (`./trusted_roots`) gerenciada pela aplicação[cite: 1]. Conta com aba dedicada na interface para listar, inspecionar e importar novas autoridades de certificação raiz diretamente pelo sistema[cite: 1].
* **Consulta Ativa de Revogação via CRL:** Análise sintática da extensão ASN.1 *CRL Distribution Points* (OID `2.5.29.31`)[cite: 1]. A aplicação efetua o download HTTP/HTTPS da lista de revogação da AC emissora em formato DER/PEM e busca o número de série (*Serial Number*) do certificado analisado[cite: 1].
* **Validação Temporal UTC:** Comparação aritmética estrita dos campos `notBefore` e `notAfter` contra o relógio do sistema em UTC, detectando certificados expirados ou com vigência futura[cite: 1].
* **Painel de Indicadores Rápidos (KPI Badges):** Quatro cartões com status visual imediato para:
1. Integridade da Assinatura Digital
2. Validade Temporal
3. Status na Lista CRL (Ativo/Revogado)[cite: 1]
4. Âncora de Confiança (Confiável/Não Confiável)[cite: 1]


* **Exportação de Laudo Técnico:** Geração automática e exportação de relatório formal de auditoria em formato `.txt`.

---

## Arquitetura e Tecnologias

A aplicação foi desenvolvida em conformidade com o padrão **RFC 5280 (X.509 v3)**[cite: 11] utilizando uma linguagem de programação estruturada e bibliotecas criptográficas nativas, atendendo aos requisitos estipulados para nota de mérito (dispensando scripts de terminal puros)[cite: 1, 2]:

* **Linguagem:** Python 3
* **Criptografia & ASN.1:** `cryptography` (módulos `x509`, `hashes`, `padding`)
* **Requisições de Rede (CRL):** `requests`
* **Interface Gráfica:** `tkinter` e `tkinter.ttk` (layout responsivo com suporte a redimensionamento e tela cheia)

---

## Estrutura do Projeto

```text
SegInfo-TrustChain-Validator/
│
├── interface.py              # Código-fonte principal (GUI Tkinter + Motor Criptográfico)
├── requirements.txt          # Dependências do projeto (cryptography, requests)
├── README.md                 # Documentação técnica do sistema
│
├── trusted_roots/            # Container local de ACs Raiz confiadas pelo usuário
│   └── SegInfoRoot.crt       # Certificado da AC Raiz local gerado no laboratório EJBCA
│
└── certificados_teste/       # Amostras para testes práticos de validação
    ├── SegInfoRSA.crt        # Certificado emitido pela ICP laboratorial (Cadeia Válida)
    ├── revoked_badssl.crt    # Certificado revogado para validação de CRL
    └── expired_badssl.crt    # Certificado fora da vigência temporal

```

---

## Instalação e Execução

### 1. Clonar o Repositório

```bash
git clone https://github.com/guilhermeschweig/SegInfo-TrustChain-Validator.git
cd SegInfo-TrustChain-Validator

```

### 2. Configurar o Ambiente e Instalar Dependências

Recomenda-se o uso de um ambiente virtual Python:

```bash
# Criar ambiente virtual
python -m venv .venv

# Ativar ambiente virtual
# No Windows (PowerShell):
.venv\Scripts\Activate.ps1
# No Linux/macOS:
source .venv/bin/activate

# Instalar dependências
pip install -r requirements.txt

```

> **Nota:** Caso não utilize ambiente virtual, execute diretamente: `pip install cryptography requests`

### 3. Executar a Aplicação

```bash
python interface.py

```

---

## Metodologia de Testes e Validação Experimental

Os cenários de teste foram baseados em certificados laboratoriais da ICP da equipe (gerados via EJBCA) e certificados de referência disponibilizados pela plataforma [BadSSL](https://badssl.com/)[cite: 1]:

| Cenário de Teste | Certificado Analisado | Configuração do Container | Comportamento Observado | Status Final |
| --- | --- | --- | --- | --- |
| **Cadeia Confiável Interna** | `SegInfoRSA.crt`[cite: 6, 7] | `SegInfoRoot.crt` presente em `./trusted_roots`[cite: 7] | Assinatura íntegra; âncora localizada por chave pública/hash; temporalidade regular[cite: 7]. | `CONFIÁVEL`[cite: 7] |
| **Revogação via CRL** | `revoked.badssl.com`[cite: 8, 9] | Qualquer configuração | Extensão CRL localizada; download HTTP efetuado; serial identificado na lista de revogados[cite: 9]. | `NÃO CONFIÁVEL (REVOGADO)`[cite: 9] |
| **Temporalidade Expirada** | `expired.badssl.com`[cite: 1] | Raiz adicionada ao container | Horário UTC atual além do campo `notAfter`; bloqueio por expiração[cite: 1]. | `NÃO CONFIÁVEL (EXPIRADO)` |
| **Raiz Não Confiável** | `untrusted-root.badssl.com`[cite: 1] | Container mantendo apenas a raiz local `SegInfoRoot`[cite: 7] | Chave pública da AC emissora ausente do container; bloqueio mesmo com assinatura íntegra[cite: 1]. | `NÃO CONFIÁVEL` |
