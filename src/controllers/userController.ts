import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import User from '../models/user';

export const registerUser = async (req: Request, res: Response): Promise<void> => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await User.hashPassword(password);
    await User.create({ username, password: hashedPassword });
    res.status(201).json({ message: 'Usuário registrado com sucesso' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao registrar usuário.' });
  }
};

export const loginUser = async (req: Request, res: Response): Promise<void> => {
  const { username, password } = req.body;

  try {
    const user = await User.findOne({ where: { username } });

    if (!user) {
      res.status(400).json({ error: 'Usuário não encontrado.' });
      return;
    }

    const hash = await bcrypt.hash(password, 10);
    const validPassword = await bcrypt.compare(password, hash);

    if (!validPassword) {
      res.status(400).json({ error: 'Senha inválida.' });
      return;
    }

    const token = jwt.sign({ userId: user.id, username:  user.username }, process.env.JWT_SECRET!, {
      expiresIn: process.env.JWT_EXPIRES_IN,
    });

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao fazer login.' });
  }
};
