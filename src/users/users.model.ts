import { Document, Model, Schema, model } from "mongoose";
import bcrypt from "bcrypt";

export interface IUser {
  email: string;
  password: string;
  tokens?: {
    token: string;
    expires: Date;
    isValid: boolean;
  }[];
}

interface IUserDocument extends IUser, Document {
  checkPassword(password: string): Promise<boolean>;
}

interface IUserModel extends Model<IUserDocument> {
  getUsers(): Promise<IUserDocument[]>;
  getUserByEmail(email: string): Promise<IUserDocument>;
  getUserById(id: string): Promise<IUserDocument>;
  createUser(values: Record<string, any>): Promise<IUserDocument>;
  deleteUserById(id: string): Promise<IUserDocument>;
  updateUserById(
    id: string,
    values: Record<string, any>
  ): Promise<IUserDocument>;
}

const TokenSchema = new Schema({
  token: { type: String, required: true },
  expires: { type: Date, required: true },
  isValid: { type: Boolean, required: true },
});

const UserSchema: Schema<IUserDocument> = new Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, select: false },
  tokens: [TokenSchema],
});

UserSchema.pre("save", async function (next) {
  const user = this as IUser;

  const hash = await bcrypt.hash(user.password, 10);

  user.password = hash;
  next();
});

UserSchema.methods.checkPassword = async function (password: string) {
  const user = this as IUser;
  const compare = await bcrypt.compare(password, user.password);

  return compare;
};

UserSchema.statics.getUsers = function getUsers() {
  return this.find();
};

UserSchema.statics.getUserByEmail = function getUserByEmail(email: string) {
  return this.findOne({ email });
};

UserSchema.statics.getUserById = function getUserById(id: string) {
  return this.findById(id);
};

UserSchema.statics.createUser = function createUser(
  values: Record<string, any>
) {
  return new this(values).save().then((user) => user.toObject());
};

UserSchema.statics.deleteUserById = function deleteUserById(id: string) {
  return this.findByIdAndDelete(id);
};

UserSchema.statics.updateUserById = function updateUserById(
  id: string,
  values: Record<string, any>
) {
  return this.findByIdAndUpdate(id, values);
};

export const UserModel = model<IUserDocument, IUserModel>("User", UserSchema);
