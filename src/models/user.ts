import { DataTypes, Model } from 'sequelize';
import { sequelize } from '../config/database';
import bcrypt from 'bcryptjs';

interface UserAttributes {
  id?: number;
  username: string;
  password: string;
}

class User extends Model<UserAttributes> implements UserAttributes {
  public id!: number;
  public username!: string;
  public password!: string;

  // Método para criptografar a senha antes de salvar o usuário
  static async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }
}

User.init(
  {
    username: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    password: {
      type: DataTypes.STRING(60),
      allowNull: false,      
    },
  },
  {
    sequelize,
    modelName: 'User',
    tableName: 'Users',
  }
);

export default User;
