import { NextFunction, Request, Response } from "express";
import User from "../../models/User";
import jwt, { SignOptions } from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";
const SALT = 10;

dotenv.config();

const generateToken = (id: string, username: string) => {
  const token = jwt.sign(
    { userId: id, username },
    process.env.JWT_SECRET as string,
    {
      expiresIn: process.env.JWT_SK as SignOptions["expiresIn"],
    }
  );
  return token;
};

export const signup = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const { username, password } = req.body;
    // Check if email already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      res.status(400).json({ message: "username already in use" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create and save the user
    const newUser = await User.create({ username, password: hashedPassword });

    // Generate token
    const token = generateToken(newUser!._id.toString(), newUser?.username!);

    res.status(201).json({ token });
  } catch (err) {
    next(err);
  }
};

export const signin = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { username, password } = req.body;

  try {
    // Find the user
    const user = await User.findOne({ username });
    if (!user) {
      res.status(400).json({ message: "Invalid credentials" });
    }

    // Compare provided password with stored hash
    const isMatch = await bcrypt.compare(password, user?.password!);
    if (!isMatch) {
      res.status(400).json({ message: "Invalid credentials" });
    }

    // Generate token
    const token = generateToken(user!._id.toString(), user?.username!);
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};

export const getUsers = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    const users = await User.find().populate("urls");
    res.status(201).json(users);
  } catch (err) {
    next(err);
  }
};
