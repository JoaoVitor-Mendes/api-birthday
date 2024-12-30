import { UserRequest } from '../middleware/authMiddleware';
import { Response } from 'express';

export const someController = (req: UserRequest, res: Response): void => {
  const userId = req.user?.userId;
  const username = req.user?.username;

  if (userId) {
    res.json({ message: `Usuário ${username} encontrado!`, userId });
  } else {
    res.status(400).json({ error: 'Usuário não autenticado.' });
  }
};
