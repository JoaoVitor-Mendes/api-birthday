import { Sequelize } from 'sequelize';
import dotenv from 'dotenv';

dotenv.config();

// Crie uma instância do Sequelize com as configurações do banco de dados
export const sequelize = new Sequelize({
  dialect: 'mysql', // Ou 'mysql', 'postgres', dependendo do seu banco de dados
  host: process.env.DB_HOST || 'localhost',
  port: Number(process.env.DB_PORT) || 1433,  // 1433 para SQL Server
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  logging: false,  // Pode ser `true` se quiser ver as queries do Sequelize no console
});

// Verifique a conexão com o banco de dados
sequelize.authenticate()
  .then(() => {
    console.log('Conexão com o banco de dados foi bem-sucedida!');
  })
  .catch((err) => {
    console.error('Erro ao conectar ao banco de dados:', err);
  });
