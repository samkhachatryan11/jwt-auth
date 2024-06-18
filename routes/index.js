import express from 'express';
import { createUserRequest, loginRequest } from '../requests/index.js';
import { createUser, deleteUser, getusers, login, logout, tokenRefresh } from '../controllers/index.js';
import cookieVerify from '../middlewares/cookieVerify.js';

const router = express.Router();

router.post('/registration', createUserRequest, createUser);
router.get('/getusers', cookieVerify, getusers);
router.post('/login', loginRequest, login);
router.post('/logout', cookieVerify, logout);
router.delete('/deleteuser', cookieVerify, deleteUser);
router.post('/refresh-token', tokenRefresh)

export default router;