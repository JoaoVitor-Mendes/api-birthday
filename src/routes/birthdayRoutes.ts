import { Router } from 'express';
import * as birthdayController from '../controllers/birthdayController';
import authMiddleware from '../middleware/authMiddleware';

const birthdayRouter = Router();

// Rotas para o CRUD de aniversários
birthdayRouter.post('/birthdays', authMiddleware, birthdayController.createBirthday);
birthdayRouter.get('/birthdays', authMiddleware, birthdayController.getAllBirthdays);
birthdayRouter.get('/birthdays/:id', authMiddleware, birthdayController.getBirthdayById);
birthdayRouter.put('/birthdays/:id', authMiddleware, birthdayController.updateBirthday);
birthdayRouter.delete('/birthdays/:id', authMiddleware, birthdayController.deleteBirthday);

export default birthdayRouter;
