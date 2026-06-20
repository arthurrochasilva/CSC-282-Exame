# Prompt de Remediação — DVPWA

Você é um engenheiro de segurança de software. Estou anexando a triagem dos
achados mais relevantes do DVPWA (Damn Vulnerable Python Web Application), junto
com os trechos de código correspondentes. Proponha correções seguras.

## Tarefas

1. Para cada vulnerabilidade selecionada, explique a causa raiz.
2. Proponha um patch mínimo e seguro.
3. Indique quais testes funcionais devem continuar passando.
4. Indique um teste de regressão que demonstre que o exploit não funciona mais.
5. Evite correções que apenas escondem o alerta da ferramenta sem corrigir a
   causa.

## Formato de saída

Gere um arquivo para download chamado `llm-remediation.md` contendo, para cada
vulnerabilidade selecionada, uma seção com:

- Vulnerabilidade
- Causa raiz
- Patch proposto (com o trecho de código corrigido)
- Teste de regressão
- Como confirmar a correção no segundo scan
