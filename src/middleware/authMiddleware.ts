import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';

export interface UserRequest extends Request {
  user?: {
    userId: number;
    username: string;
  };
}

const authMiddleware = (req: UserRequest, res: Response, next: NextFunction): any => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Acesso negado. Token não fornecido.' });
  }

  try {
    const decoded: any = jwt.verify(token, process.env.JWT_SECRET!);
    // Adiciona os dados do usuário à requisição
    req.user = { userId: decoded.userId, username: decoded.username };
    next();
  } catch (err) {
    res.status(400).json({ error: 'Token inválido.' });
  }
};

export default authMiddleware;
