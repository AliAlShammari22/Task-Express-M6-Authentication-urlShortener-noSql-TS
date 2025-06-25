import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

export function authorize(req: Request, res: Response, next: NextFunction) {
  //1. extract the token from the Authorization header(req.headers.authorization)
  const header = req.headers.authorization;
  console.log(header);
  if (!header) {
    res.status(401).json({ message: "No token provided" });
  }

  const [authType, token] = header?.split(" ") || [];
  if (authType !== "Bearer" || !token) {
    res.status(401).json({ message: "Invalid auth format" });
  }

  try {
    //2. verify the token using jwt.verify & get payload
    const payload = jwt.verify(token, process.env.JWT_SECRET as string);

    //3. attach the payload to the request object(req.user)
    (req as any).user = payload;
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
}
