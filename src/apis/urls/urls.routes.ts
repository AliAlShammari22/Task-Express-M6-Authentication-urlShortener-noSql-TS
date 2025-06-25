import express from "express";

const router = express.Router();

import { shorten, redirect, deleteUrl } from "./urls.controllers";
import { authorize } from "../../middlewares/authorize";

router.post("/shorten/:userId", authorize, shorten);
router.get("/:code", redirect);
router.delete("/:code", authorize, deleteUrl);

export default router;
