# Birthday API

Uma API simples para gerenciar registros de aniversários e funcionalidades relacionadas.

## Funcionalidades

- Adicionar um novo aniversário
- Listar todos os aniversários
- Obter um aniversário específico
- Atualizar um aniversário
- Deletar um aniversário
- Enviar notificações de aniversários próximos
- Listar aniversários próximos

## Instalação

1. Clone o repositório:
    ```sh
    git clone https://github.com/JoaoVitor-Mendes/api-birthday.git
    ```
2. Vá para o diretório do projeto:
    ```sh
    cd birthday-api
    ```
3. Instale as dependências:
    ```sh
    npm install
    ```

## Uso

1. Inicie o servidor:
    ```sh
    npm start
    ```
2. A API estará acessível em `http://localhost:3000`.

## Endpoints

### Adicionar um novo aniversário

- **URL**: `/api/birthdays`
- **Método**: `POST`
- **Corpo**: 
    ```json
    {
      "name": "João Silva",
      "date": "1990-01-01"
    }
    ```

### Listar todos os aniversários

- **URL**: `/api/birthdays`
- **Método**: `GET`

### Obter um aniversário específico

- **URL**: `/api/birthdays/:id`
- **Método**: `GET`

### Atualizar um aniversário

- **URL**: `/api/birthdays/:id`
- **Método**: `PUT`
- **Corpo**: 
    ```json
    {
      "name": "João Silva",
      "date": "1990-01-01"
    }
    ```

### Deletar um aniversário

- **URL**: `/api/birthdays/:id`
- **Método**: `DELETE`

### Enviar notificações de aniversários próximos

- **URL**: `/api/birthdays/notify`
- **Método**: `POST`

### Listar aniversários próximos

- **URL**: `/api/birthdays/upcoming`
- **Método**: `GET`

## Contribuição

1. Faça um fork do repositório.
2. Crie uma nova branch: `git checkout -b minha-nova-funcionalidade`
3. Faça suas alterações.
4. Commit suas mudanças: `git commit -m 'Adiciona nova funcionalidade'`
5. Faça um push para a branch: `git push origin minha-nova-funcionalidade`
6. Envie um pull request.

## Licença

Este projeto está licenciado sob a Licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.
