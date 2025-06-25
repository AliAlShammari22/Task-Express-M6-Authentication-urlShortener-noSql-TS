import express from "express";

const router = express.Router();

import { signup, signin, getUsers } from "./users.controllers";
import { authorize } from "../../middlewares/authorize";

router.post("/signup", signup);
router.post("/signin", signin);
router.get("/users", authorize, getUsers);

export default router;
