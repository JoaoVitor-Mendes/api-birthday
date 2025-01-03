# Use uma imagem base do Node.js
FROM node:latest

# Defina o diretório de trabalho
WORKDIR /birthday-api 

# Instale o TypeScript globalmente
RUN npm install -g typescript

# Copie o arquivo package.json e instale as dependências
COPY package.json .
RUN rm -rf node_modules
RUN npm install

# Copie os arquivos de código fonte
COPY . .

# Compile o código TypeScript para JavaScript
RUN tsc

# Exponha a porta que a aplicação usa
EXPOSE 3000

# Comando para iniciar a aplicação
CMD ["npm", "start"]
