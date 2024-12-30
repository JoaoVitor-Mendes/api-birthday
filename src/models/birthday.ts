
import { sequelize } from '../config/database';  // Importando a instância do Sequeliz
import { Model, DataTypes } from 'sequelize';

export class Birthday extends Model {
  public id!: number;
  public userId!: number;
  public date!: string;
  public description!: string | null;
  public createdAt!: Date;
  public updatedAt!: Date;
}

Birthday.init(
  {
    id: {
      type: DataTypes.INTEGER,
      primaryKey: true,
      autoIncrement: true,
    },
    userId: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    date: {
      type: DataTypes.STRING,
      allowNull: false,
    },
    description: {
      type: DataTypes.STRING,
      allowNull: true,
    },
  },
  {
    sequelize,
    tableName: 'birthdays',
  }
);
