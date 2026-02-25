Anti-Phishing API
Este projeto nasceu da necessidade de proteger usuários finais (especialmente familiares e pessoas leigas) contra golpes de WhatsApp, SMS e e-mail. Em vez de ser apenas um classificador que diz "sim" ou "não", o foco aqui é a explicabilidade: mostrar ao usuário os sinais de perigo que o modelo detectou.

A Estrutura
O projeto foi separado para garantir que a inteligência de segurança não fique misturada com o código da API (FastAPI).

src/main.py: A porta de entrada. Recebe os dados e entrega a resposta.

src/analyzer.py: Onde o trabalho pesado acontece. Aqui tratamos a limpeza de texto e rodamos o modelo.

src/models.py: Define exatamente como os dados entram e saem do sistema.

models/: Pasta que guarda os arquivos treinados (.joblib).

Como a análise funciona
Seguindo boas práticas de segurança, a mensagem passa por três etapas antes de gerar um veredito:

Normalização Unicode: Golpistas costumam usar caracteres visualmente parecidos (ex: um "o" grego no lugar de um "o" latino) para enganar filtros. O código normaliza o texto (NFKC) para garantir que a IA leia a mensagem real, sem truques visuais.

Extração de Sinais: O sistema busca padrões de comportamento típicos de golpistas, como o uso de links encurtados, termos de urgência ("bloqueio", "expira") e solicitações de dados sensíveis.

Cálculo de Risco: O resultado não é apenas "fraude". O sistema entrega níveis de risco (Baixo, Moderado, Alto) baseados na probabilidade estatística do modelo.

Por que não é apenas um modelo binário?
Fraude é um espectro. Mensagens reais do governo ou de bancos podem usar termos sérios que confundem IAs simples. Ao entregar "Sinais" e "Nível de Risco", permitimos que o usuário final aprenda a identificar o golpe por conta própria, criando uma camada extra de segurança humana.

Como rodar o ambiente
Para evitar erros de importação no Python, o servidor deve ser iniciado sempre da raiz do projeto:

Bash
uvicorn src.main:app --reload
A documentação interativa (Swagger) ficará disponível em: http://127.0.0.1:8000/docs

O que vem pela frente
O projeto está em constante evolução técnica:

Melhorar a calibração das notas para reduzir falsos positivos em mensagens do governo.

Implementar logs estruturados para monitorar quando novos tipos de golpes surgirem (Data Drift).

Refinar os pré-processadores para lidar com técnicas de evasão mais complexas.