# Prompt de Triagem — DVPWA

Você é um analista de segurança de software. Estou anexando os relatórios de
Bandit, Semgrep, pip-audit e Gitleaks executados sobre o DVPWA (Damn Vulnerable
Python Web Application).

## Tarefas

1. Agrupe achados duplicados ou equivalentes.
2. Identifique prováveis falsos positivos e explique brevemente.
3. Priorize achados que parecem exploráveis no DVPWA.
4. Escolha pelo menos três vulnerabilidades candidatas para correção.
5. Para cada vulnerabilidade escolhida, indique evidência, arquivo/linha se
   houver, causa raiz provável e estratégia de correção.

## Formato de saída

Gere um arquivo para download chamado `llm-triage.md` contendo:

1. Uma tabela com as colunas: id, ferramenta, arquivo, linha, severidade,
   decisao, justificativa. Onde "decisao" deve ser um valor entre: corrigir,
   falso_positivo, ignorar.

2. Uma seção chamada "Vulnerabilidades selecionadas para remediação", listando
   as pelo menos três vulnerabilidades escolhidas, cada uma com: evidência,
   arquivo/linha, causa raiz provável e estratégia de correção.