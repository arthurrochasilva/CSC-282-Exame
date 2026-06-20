# Triagem de Segurança — DVPWA

Relatórios analisados: **Bandit**, **Semgrep**, **pip-audit** e **Gitleaks**.

Resumo: `pip-audit` e `Gitleaks` não retornaram achados (0 dependências vulneráveis, 0 segredos vazados). Os achados acionáveis vêm de Bandit e Semgrep e concentram-se em **dois problemas reais** (injeção de SQL e hash de senha fraco), além de hardening de container e falsos positivos em biblioteca de terceiros.

## 1. Tabela de triagem

| id | ferramenta | arquivo | linha | severidade | decisao | justificativa |
|----|-----------|---------|-------|-----------|---------|---------------|
| B608 | Bandit | sqli/dao/student.py | 42 | MEDIUM | corrigir | SQL montado com formatação de string (`INSERT ... VALUES ('%(name)s')`). Injeção de SQL real e explorável. Mesma causa-raiz que os achados Semgrep em student.py. |
| SG-formatted-sql | Semgrep | sqli/dao/student.py | 45 | WARNING (HIGH impact) | corrigir | `formatted-sql-query`: query SQL formatada por string. Duplicado/equivalente ao B608 e ao SG-sqlalchemy-raw — mesmo arquivo, mesma classe (CWE-89). |
| SG-sqlalchemy-raw | Semgrep | sqli/dao/student.py | 45 | ERROR | corrigir | `sqlalchemy-execute-raw-query`: concatenação em query crua. Achado de maior severidade do Semgrep; agrupa com B608/SG-formatted-sql. |
| B324 | Bandit | sqli/dao/user.py | 41 | HIGH | corrigir | Uso de MD5 para verificar senha (`pwd_hash == md5(password)`). Algoritmo quebrado para senhas (CWE-327). |
| SG-md5-password | Semgrep | sqli/dao/user.py | 41 | WARNING | corrigir | `md5-used-as-password`. Duplicado do B324 — mesmo arquivo/linha, mesma causa-raiz. |
| SG-no-new-privileges | Semgrep | docker-compose.yml | 11 | WARNING | ignorar | Hardening do serviço `redis` (falta `no-new-privileges`). Não explorável no contexto do DVPWA; subcategoria "audit", likelihood LOW. Recomendação de boas práticas, não vulnerabilidade. |
| SG-writable-filesystem | Semgrep | docker-compose.yml | 11 | WARNING | ignorar | Hardening do serviço `redis` (filesystem raiz gravável). Mesma natureza do acima — defesa em profundidade, não falha explorável. |
| SG-unsafe-fmt-1 | Semgrep | sqli/static/js/materialize.js | 645 | INFO | falso_positivo | `unsafe-formatstring` em biblioteca de terceiros (Materialize, JS minificado/vendado). Não é código da aplicação; INFO; sem caminho de exploração. |
| SG-unsafe-fmt-2 | Semgrep | sqli/static/js/materialize.js | 661 | INFO | falso_positivo | Mesmo caso — biblioteca vendada de terceiros. |
| SG-unsafe-fmt-3 | Semgrep | sqli/static/js/materialize.js | 699 | INFO | falso_positivo | Mesmo caso — biblioteca vendada de terceiros. |
| pip-audit | pip-audit | requirements.txt (todas deps) | — | INFO | ignorar | Nenhuma dependência vulnerável reportada. Nada a corrigir. |
| gitleaks | Gitleaks | (repositório) | — | INFO | ignorar | Nenhum segredo detectado. Nada a corrigir. |

### Notas de agrupamento e falsos positivos

- **Injeção de SQL em `student.py`** é reportada três vezes (Bandit B608 + dois rules do Semgrep). São **o mesmo problema** — construção de SQL por formatação de string no DAO de estudantes — e devem ser tratadas como um único item de correção.
- **MD5 para senha em `user.py`** aparece duas vezes (Bandit B324 + Semgrep `md5-used-as-password`). Mesmo problema, contado uma vez.
- **`materialize.js` (3x)** são **falsos positivos** para a aplicação: o achado é de `console.log`/format string dentro de uma biblioteca front-end de terceiros minificada, severidade INFO, sem entrada controlada pelo atacante de forma significativa. O analisador inclusive registrou timeout de taint analysis nesse arquivo, reforçando que é ruído.
- **Hardening do `redis` no docker-compose** são recomendações de configuração (audit), não vulnerabilidades exploráveis do DVPWA; marcadas como `ignorar` no escopo desta triagem (podem ser aplicadas como defesa em profundidade).

## 2. Vulnerabilidades selecionadas para remediação

### 2.1 Injeção de SQL no DAO de estudantes (`sqli/dao/student.py`)

- **Evidência:** Bandit B608 (linha 42) — `"INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name}`; Semgrep `formatted-sql-query` e `sqlalchemy-execute-raw-query` (linha 45, ERROR).
- **Arquivo/linha:** `sqli/dao/student.py:42` (INSERT) e `:45` (query subsequente formatada).
- **Causa raiz provável:** queries SQL construídas por interpolação/formatação de string com entrada controlada pelo usuário (nome/identificador do estudante), em vez de parâmetros vinculados. Permite ao atacante quebrar o contexto da string e injetar SQL arbitrário (CWE-89).
- **Estratégia de correção:** usar **queries parametrizadas** do driver — passar os valores como parâmetros para `cur.execute()` em vez de formatar a string. Exemplo:

  ```python
  # Em vez de:
  q = "INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name}
  await cur.execute(q)

  # Usar placeholders e deixar o driver fazer o escaping:
  await cur.execute(
      "INSERT INTO students (name) VALUES (%(name)s)",
      {"name": name},
  )
  ```

  Aplicar o mesmo padrão à query da linha 45 (e revisar os demais DAOs por consistência). Nunca concatenar/formatar entrada do usuário em SQL.

### 2.2 Hash de senha com MD5 (`sqli/dao/user.py`)

- **Evidência:** Bandit B324 (HIGH, linha 41) e Semgrep `md5-used-as-password` — `return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()`.
- **Arquivo/linha:** `sqli/dao/user.py:41`.
- **Causa raiz provável:** uso de **MD5** (rápido, sem salt, quebrável) para armazenar/verificar senhas. Em caso de vazamento do banco, as senhas são recuperáveis trivialmente por rainbow tables/força bruta (CWE-327). A comparação direta `==` também é suscetível a timing attacks.
- **Estratégia de correção:** migrar para uma **função de hash de senha dedicada com salt e custo ajustável** — por exemplo `bcrypt`, `argon2` (argon2-cffi) ou `hashlib.scrypt`. Armazenar o hash resultante e verificar com a função de comparação da própria biblioteca (constante no tempo). Exemplo com bcrypt:

  ```python
  import bcrypt

  # Ao definir a senha:
  pwd_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

  # Ao verificar:
  def check_password(self, password: str) -> bool:
      return bcrypt.checkpw(password.encode("utf-8"), self.pwd_hash)
  ```

  Forçar re-hash das senhas existentes no próximo login (não é possível converter MD5→bcrypt sem a senha em claro).

### 2.3 Hardening do container Redis (`docker-compose.yml`)

- **Evidência:** Semgrep `no-new-privileges` e `writable-filesystem-service` (linha 11, serviço `redis`).
- **Arquivo/linha:** `docker-compose.yml:11`.
- **Causa raiz provável:** o serviço `redis` roda sem `no-new-privileges` e com filesystem raiz gravável, ampliando o impacto caso um atacante já tenha execução no container (escalonamento via binários setuid/setgid e gravação de payloads). É **defesa em profundidade**, de severidade/likelihood baixas — incluída como terceiro item de remediação de menor prioridade.
- **Estratégia de correção:** adicionar opções de segurança ao serviço:

  ```yaml
  redis:
    image: redis:...
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp   # caso precise de escrita temporária
  ```

---

*Triagem gerada a partir dos relatórios Bandit, Semgrep, pip-audit e Gitleaks sobre o DVPWA. As decisões de `falso_positivo`/`ignorar` referem-se ao contexto desta aplicação e podem ser revistas conforme a política de segurança.*
