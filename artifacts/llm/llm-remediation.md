# Remediação de Segurança — DVPWA

Documento de remediação gerado a partir da triagem (`llm-triage.md`) dos relatórios
**Bandit**, **Semgrep**, **pip-audit** e **Gitleaks** sobre o DVPWA (*Damn Vulnerable
Python Web Application*).

Foram selecionadas para correção as três vulnerabilidades de `decisao = corrigir`
(agrupando os achados duplicados) mais o item de hardening de container de menor
prioridade. Os achados marcados como `falso_positivo`/`ignorar` na triagem
(`materialize.js`, `pip-audit`, `gitleaks`) não são tratados aqui.

| # | Vulnerabilidade | Arquivo | Achados agrupados | CWE | Prioridade |
|---|-----------------|---------|-------------------|-----|------------|
| 1 | Injeção de SQL no DAO de estudantes | `sqli/dao/student.py` | B608, SG-formatted-sql, SG-sqlalchemy-raw | CWE-89 | Alta |
| 2 | Hash de senha com MD5 | `sqli/dao/user.py` | B324, SG-md5-password | CWE-327 / CWE-916 | Alta |
| 3 | Hardening do container Redis | `docker-compose.yml` | SG-no-new-privileges, SG-writable-filesystem | CWE-250 / def. em profundidade | Baixa |

---

## 1. Injeção de SQL no DAO de estudantes (`sqli/dao/student.py`)

### Vulnerabilidade
`Student.create()` monta a query `INSERT` interpolando o nome do estudante na
string SQL com o operador `%`, e executa a string já formatada sem parâmetros.
A entrada chega diretamente do formulário web (`views.py:57` →
`await Student.create(conn, data['name'])`), portanto é **controlada pelo atacante**
e a injeção é real e explorável (CWE-89).

Código vulnerável atual (`sqli/dao/student.py:40-45`):

```python
@staticmethod
async def create(conn: Connection, name: str):
    q = ("INSERT INTO students (name) "
         "VALUES ('%(name)s')" % {'name': name})
    async with conn.cursor() as cur:
        await cur.execute(q)
```

Exploit (campo `name` do formulário em `POST /students`):

```
Robert'); DROP TABLE students; --
```

O valor quebra a string literal e injeta um comando arbitrário, pois a query é
formatada **antes** de chegar ao driver.

### Causa raiz
A query é construída por **formatação de string** (`%`) com a entrada do usuário,
em vez de usar **parâmetros vinculados** (*bind parameters*). O driver nunca recebe
o valor separado da instrução SQL, então não há escaping nem separação de
código/dado. As aspas literais `'...'` ao redor de `%(name)s` denunciam o
anti-padrão: o desenvolvedor estava delegando a citação à formatação de string em
vez de ao driver.

> Observação: `get()` e `get_many()` no mesmo arquivo **já** usam parâmetros
> corretamente (`cur.execute(sql, params)`). Apenas `create()` está vulnerável —
> a correção alinha `create()` ao padrão já existente no próprio arquivo.

### Patch proposto
Passar o valor como **parâmetro** para `cur.execute()` e remover as aspas literais
(o driver `psycopg2`/`aiopg` faz a citação/escaping com segurança):

```python
@staticmethod
async def create(conn: Connection, name: str):
    async with conn.cursor() as cur:
        await cur.execute(
            "INSERT INTO students (name) VALUES (%(name)s)",
            {"name": name},
        )
```

Pontos do patch:
- O placeholder `%(name)s` **não** fica entre aspas — quem cita é o driver.
- A SQL é uma **constante**; nenhum dado do usuário é concatenado/formatado nela.
- O segundo argumento (`{"name": name}`) leva o valor por *bind*, eliminando o
  caminho de injeção.

### Teste de regressão
Teste de unidade que falha com o código antigo e passa com o patch, verificando que
a SQL enviada ao driver é constante e que o payload viaja **apenas** como parâmetro,
nunca interpolado na string (não requer banco real):

```python
# tests/test_student_sqli_regression.py
import pytest
from sqli.dao.student import Student


class FakeCursor:
    def __init__(self):
        self.executed = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, query, params=None):
        self.executed.append((query, params))


class FakeConn:
    def __init__(self, cur):
        self._cur = cur

    def cursor(self):
        return self._cur


@pytest.mark.asyncio
async def test_create_uses_bound_parameters_not_string_format():
    cur = FakeCursor()
    payload = "Robert'); DROP TABLE students; --"

    await Student.create(FakeConn(cur), payload)

    query, params = cur.executed[0]
    # A SQL é constante e parametrizada...
    assert "%(name)s" in query
    # ...e o payload malicioso NUNCA aparece na string SQL:
    assert "DROP TABLE" not in query
    assert "Robert" not in query
    # ...ele só existe como valor vinculado:
    assert params == {"name": payload}
```

Opcional (teste de integração com Postgres): criar um estudante cujo `name` seja
`x'); DROP TABLE students; --`, depois consultar `SELECT count(*) FROM students` e
confirmar que a tabela continua existindo e que há um estudante com **exatamente**
aquele nome literal.

### Como confirmar a correção no segundo scan
- **Bandit:** `bandit -r sqli/` não deve mais reportar **B608** em
  `sqli/dao/student.py`.
- **Semgrep:** `semgrep --config auto sqli/` não deve mais reportar
  `formatted-sql-query` nem `sqlalchemy-execute-raw-query` nesse arquivo.
- Diff esperado: desaparece o `... % {'name': name}`; a chamada passa a ter dois
  argumentos em `cur.execute(...)`.

---

## 2. Hash de senha com MD5 (`sqli/dao/user.py`)

### Vulnerabilidade
A verificação de senha compara o hash armazenado com o **MD5** da senha fornecida:

```python
# sqli/dao/user.py:40-41
def check_password(self, password: str):
    return self.pwd_hash == md5(password.encode('utf-8')).hexdigest()
```

As fixtures armazenam exatamente esse hash (`migrations/001-fixtures.sql`):

```sql
VALUES
  ('Super', NULL, 'Admin', 'superadmin', md5('superadmin'), TRUE),
  ('John', 'William', 'Doe', 'j.doe', md5('password'), FALSE),
  ...
```

MD5 é um hash **rápido, sem salt e criptograficamente quebrado** para senhas
(CWE-327 / CWE-916). Em caso de vazamento do banco, as senhas são recuperáveis
trivialmente por *rainbow tables*/força bruta. Além disso, a comparação direta com
`==` sobre strings é suscetível a **timing attack** (CWE-208).

### Causa raiz
Uso de uma função de hash de propósito geral (MD5), de execução rápida e sem fator
de custo nem salt, como mecanismo de armazenamento de senha — em vez de uma
**função de derivação de senha dedicada** (bcrypt/argon2/scrypt), que é lenta por
projeto, usa salt por usuário e oferece comparação em tempo constante.

### Patch proposto
Migrar para **bcrypt** (salt embutido + custo ajustável + verificação em tempo
constante). Três alterações coordenadas:

**(a) `sqli/dao/user.py`** — verificar com `bcrypt.checkpw`:

```python
import bcrypt
from typing import NamedTuple, Optional

from aiopg import Connection


class User(NamedTuple):
    id: int
    first_name: str
    middle_name: Optional[str]
    last_name: str
    username: str
    pwd_hash: str
    is_admin: bool

    # ... from_raw / get / get_by_username inalterados ...

    def check_password(self, password: str) -> bool:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            self.pwd_hash.encode("utf-8"),
        )

    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt(),
        ).decode("utf-8")
```

- Removido o `from hashlib import md5` (e o uso de MD5).
- `bcrypt.checkpw` é **constante no tempo**, eliminando também o timing attack.
- `hash_password` centraliza a geração de hash para um futuro fluxo de cadastro/
  troca de senha.

**(b) `requirements.txt`** — adicionar a dependência:

```diff
+ bcrypt==4.1.2
```

**(c) `migrations/001-fixtures.sql`** — semear hashes **bcrypt** em vez de MD5, para
que os logins de teste continuem funcionando. Usando a extensão `pgcrypto` (incluída
na imagem oficial do Postgres), `crypt(..., gen_salt('bf'))` gera hash no formato
bcrypt (`$2a$...`), compatível com `bcrypt.checkpw`:

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO users (
  first_name, middle_name, last_name, username, pwd_hash, is_admin
)
VALUES
  ('Super', NULL, 'Admin', 'superadmin', crypt('superadmin', gen_salt('bf')), TRUE),
  ('John', 'William', 'Doe', 'j.doe', crypt('password', gen_salt('bf')), FALSE),
  ('Stephen', NULL, 'King', 's.king', crypt('password', gen_salt('bf')), FALSE),
  ('Peter', NULL, 'Parker', 'p.parker', crypt('spidey', gen_salt('bf')), FALSE);
```

> Para um banco **já populado** com hashes MD5 legados, não é possível converter
> MD5→bcrypt sem a senha em claro. Estratégia recomendada: tratar `check_password`
> com *fallback* temporário que detecta o hash legado (32 hex), valida via MD5
> apenas nessa transição e **re-hasheia para bcrypt no login bem-sucedido**,
> removendo o fallback após a migração. Para o DVPWA (banco recriado pelas
> fixtures), basta o item (c).

### Quais testes funcionais devem continuar passando
- Login com as credenciais semeadas continua válido:
  `superadmin`/`superadmin`, `j.doe`/`password`, `p.parker`/`spidey`
  (fluxo `POST /` em `views.py:41`).
- Login com senha errada continua sendo rejeitado (`Invalid username or password`).

### Teste de regressão
Demonstra que (1) bcrypt valida corretamente e (2) o caminho MD5 deixou de
autenticar — ou seja, fornecer o **hexdigest MD5** como "senha" não funciona mais:

```python
# tests/test_password_hash_regression.py
import bcrypt
from hashlib import md5
from sqli.dao.user import User


def _user(pwd_hash: str) -> User:
    return User(1, "T", None, "U", "tester", pwd_hash, False)


def test_bcrypt_password_roundtrip():
    h = User.hash_password("s3cret")
    assert h.startswith("$2")                 # formato bcrypt, não MD5 hex
    assert _user(h).check_password("s3cret") is True
    assert _user(h).check_password("wrong") is False


def test_md5_digest_is_no_longer_accepted():
    # No esquema antigo, pwd_hash == md5(pwd); aqui o hash é bcrypt,
    # então passar o digest MD5 como senha NÃO deve autenticar.
    h = User.hash_password("password")
    legacy_md5 = md5(b"password").hexdigest()
    assert _user(h).check_password(legacy_md5) is False
```

### Como confirmar a correção no segundo scan
- **Bandit:** `bandit -r sqli/` não deve mais reportar **B324**
  (`hashlib`/MD5 inseguro) em `sqli/dao/user.py`.
- **Semgrep:** não deve mais reportar `md5-used-as-password`.
- Diff esperado: some `from hashlib import md5`; `check_password` passa a chamar
  `bcrypt.checkpw`; `bcrypt` aparece em `requirements.txt`.

---

## 3. Hardening do container Redis (`docker-compose.yml`)

### Vulnerabilidade
O serviço `redis` roda sem `no-new-privileges` e com **filesystem raiz gravável**,
ampliando o impacto caso um atacante já tenha execução no container (escalonamento
via binários setuid/setgid, gravação de payloads/persistência). É **defesa em
profundidade** (subcategoria *audit*, likelihood baixa) — não uma falha explorável
isoladamente, mas recomendada como camada extra.

Código atual (`docker-compose.yml:11-12`):

```yaml
  redis:
    image: redis:alpine
```

### Causa raiz
Configuração de container com privilégios e superfície de escrita padrão
(permissivos), sem aplicar o princípio do menor privilégio: ausência de
`no-new-privileges` permite ganho de privilégios via setuid; raiz gravável permite
ao atacante alterar binários/escrever artefatos.

### Patch proposto
Adicionar opções de segurança ao serviço, mantendo um `tmpfs` para a escrita
temporária que o Redis possa precisar:

```yaml
  redis:
    image: redis:alpine
    read_only: true
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /tmp
    # Se a persistência estiver habilitada, mapear um volume gravável dedicado
    # apenas para o diretório de dados, p.ex.:
    # volumes:
    #   - redis-data:/data
```

### Quais testes funcionais devem continuar passando
- `docker compose up` sobe o serviço `redis` normalmente.
- A aplicação (`sqli`) continua conectando ao Redis (sessões — `aioredis`),
  ou seja, login/`last_visited` seguem funcionando.

### Teste de regressão
Verifica que as opções de hardening estão presentes na composição (falha se alguém
reverter o endurecimento):

```python
# tests/test_compose_hardening_regression.py
import yaml


def test_redis_service_is_hardened():
    with open("docker-compose.yml") as f:
        compose = yaml.safe_load(f)
    redis = compose["services"]["redis"]
    assert redis.get("read_only") is True
    assert "no-new-privileges:true" in redis.get("security_opt", [])
```

### Como confirmar a correção no segundo scan
- **Semgrep:** não deve mais reportar `no-new-privileges` nem
  `writable-filesystem-service` para o serviço `redis` em `docker-compose.yml`.

---

## Resumo das alterações

| Arquivo | Mudança |
|---------|---------|
| `sqli/dao/student.py` | `create()` passa a usar query parametrizada (`%(name)s` + dict) |
| `sqli/dao/user.py` | Remove MD5; `check_password` via `bcrypt.checkpw`; novo `hash_password` |
| `requirements.txt` | `+ bcrypt==4.1.2` |
| `migrations/001-fixtures.sql` | `pgcrypto` + `crypt(..., gen_salt('bf'))` no lugar de `md5(...)` |
| `docker-compose.yml` | `redis`: `read_only`, `no-new-privileges`, `tmpfs` |

**Princípio aplicado:** todas as correções atacam a **causa raiz** (separar dado de
código no SQL; usar KDF de senha com salt/custo/comparação constante; aplicar menor
privilégio no container) — nenhuma apenas silencia o alerta da ferramenta
(ex.: não foram usados `# nosec` / `# nosemgrep`).
