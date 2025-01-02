import { Response } from 'express';
import { UserRequest } from '../middleware/authMiddleware';  // Interface para tipar req.user
import { Birthday } from '../models/birthday';// Modelo de Birthday (Sequelize ou qualquer outro ORM)

// Criar um novo aniversário
export const createBirthday = async (req: UserRequest, res: Response): Promise<any> => {
  try {
    const { date, description } = req.body;  // Dados do aniversário enviados no corpo da requisição
    const userId = req.user?.userId;  // Obtém o userId do usuário autenticado

    if (!userId) {
      return res.status(401).json({ error: 'Usuário não autenticado.' });
    }

    // Verifica se a data de aniversário foi fornecida
    if (!date) {
      return res.status(400).json({ error: 'Data do aniversário é obrigatória.' });
    }

    // Verifica se a descrição do aniversário foi fornecida
    if (!description) {
      return res.status(400).json({ error: 'Descrição do aniversário é obrigatória.' });
    }

    // Cria o aniversário no banco de dados
    const birthday = await Birthday.create({
      userId,
      date,
      description
    });

    res.status(201).json(birthday);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar o aniversário.' });
  }
};

// Obter todos os aniversários do usuário
export const getAllBirthdays = async (req: UserRequest, res: Response): Promise<any> => {
  try {
    const userId = req.user?.userId;  // Obtém o userId do usuário autenticado

    if (!userId) {
      return res.status(401).json({ error: 'Usuário não autenticado.' });
    }

    // Busca todos os aniversários do usuário autenticado
    const birthdays = await Birthday.findAll({
      where: { userId }
    });

    res.status(200).json(birthdays);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar aniversários.' });
  }
};

// Obter um aniversário específico
export const getBirthdayById = async (req: UserRequest, res: Response): Promise<any> => {
  try {
    const { id } = req.params;  // ID do aniversário a ser buscado
    const userId = req.user?.userId;  // Obtém o userId do usuário autenticado

    if (!userId) {
      return res.status(401).json({ error: 'Usuário não autenticado.' });
    }

    // Busca o aniversário no banco de dados
    const birthday = await Birthday.findOne({
      where: { id, userId }
    });

    if (!birthday) {
      return res.status(404).json({ error: 'Aniversário não encontrado.' });
    }

    res.status(200).json(birthday);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar o aniversário.' });
  }
};

// Atualizar um aniversário existente
export const updateBirthday = async (req: UserRequest, res: Response): Promise<any> => {
  try {
    const { id } = req.params;  // ID do aniversário a ser atualizado
    const { date, description } = req.body;  // Dados a serem atualizados
    const userId = req.user?.userId;  // Obtém o userId do usuário autenticado

    if (!userId) {
      return res.status(401).json({ error: 'Usuário não autenticado.' });
    }

    // Busca o aniversário no banco de dados
    const birthday = await Birthday.findOne({
      where: { id, userId }
    });

    if (!birthday) {
      return res.status(404).json({ error: 'Aniversário não encontrado.' });
    }

    // Atualiza os dados do aniversário
    birthday.date = date ?? birthday.date;
    birthday.description = description ?? birthday.description;
    await birthday.save();

    res.status(200).json(birthday);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao atualizar o aniversário.' });
  }
};

// Deletar um aniversário
export const deleteBirthday = async (req: UserRequest, res: Response): Promise<any> => {
  try {
    const { id } = req.params;  // ID do aniversário a ser deletado
    const userId = req.user?.userId;  // Obtém o userId do usuário autenticado

    if (!userId) {
      return res.status(401).json({ error: 'Usuário não autenticado.' });
    }

    // Busca o aniversário no banco de dados
    const birthday = await Birthday.findOne({
      where: { id, userId }
    });

    if (!birthday) {
      return res.status(404).json({ error: 'Aniversário não encontrado.' });
    }

    // Deleta o aniversário
    await birthday.destroy();

    res.status(200).json({ message: 'Aniversário deletado com sucesso.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao deletar o aniversário.' });
  }
};
