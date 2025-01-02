import express from 'express';7
import cors from 'cors';
import dotenv from 'dotenv';
import userRoutes from './routes/userRoutes';
import birthdayRoutes from './routes/birthdayRoutes';
import { sequelize } from './config/database';

dotenv.config();

const app = express();

app.use(express.json());

app.use(cors());

app.use('/api', userRoutes);
app.use('/api', birthdayRoutes);

const port = process.env.PORT || 3000;

app.listen(port, async () => {
  console.log(`Servidor rodando na porta ${port}`);
  try {
    await sequelize.sync(); // Sincroniza o banco de dados
    console.log('Banco de dados sincronizado');
  } catch (error) {
    console.error('Erro ao sincronizar o banco de dados:', error);
  }
});
