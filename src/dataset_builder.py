import pandas as pd

def build_ptbr_dataset():
    public_spam_data = {
        'message_text': [
            'Voce ganhou um premio da operadora, ligue agora para resgatar',
            'Emprestimo pre-aprovado para negativados, clique aqui',
            'Seu nome foi protestado no serasa, pague o boleto',
            'Desconto de 90% em smartphones na loja oficial'
        ],
        'is_fraud': [1, 1, 1, 1]
    }
    df_public = pd.DataFrame(public_spam_data)

    modern_br_scams = {
        'message_text': [
            'Sua chave PIX foi cadastrada em outro aparelho. Caso nao reconheca, acesse o link',
            'Receita Federal: Seu CPF esta irregular. Pague a taxa de regularizacao imediatamente',
            'Correios: Sua encomenda foi taxada na alfandega. Clique aqui para liberar',
            'Oi mae, meu numero mudou, salva esse novo aqui e apaga o velho',
            'Nubank: Compra aprovada no valor de R$ 4.500. Se nao foi voce, ligue para a central'
        ],
        'is_fraud': [1, 1, 1, 1, 1]
    }
    df_modern_scams = pd.DataFrame(modern_br_scams)

    normal_daily_messages = {
        'message_text': [
            'Amanha a gente termina aquele projeto da faculdade',
            'Amor, como estao os estudos e os plantoes ai?',
            'Professor, a aula de engenharia de software vai ter chamada?',
            'Que horas voce chega do trabalho hoje?',
            'Ja mandei a minha parte do PIX do lanche',
            'Mae, comprei o creme de cabelo que voce pediu',
            'Bora jogar uma partida mais tarde?'
        ],
        'is_fraud': [0, 0, 0, 0, 0, 0, 0]
    }
    df_normal = pd.DataFrame(normal_daily_messages)

    df_final = pd.concat([df_public, df_modern_scams, df_normal], ignore_index=True)
    df_final = df_final.sample(frac=1, random_state=42).reset_index(drop=True)

    return df_final

if __name__ == '__main__':
    dataset = build_ptbr_dataset()
    print("Dataset generated successfully. Shape:", dataset.shape)
    print(dataset.head(10))