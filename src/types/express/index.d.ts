// src/types/express/index.d.ts
import { UserRequest } from '../../middleware/authMiddleware'; // Certifique-se de que o caminho esteja correto

declare global {
  namespace Express {
    export interface Request {
      user?: {
        userId: number;
        username: string;
      };
    }
  }
}
