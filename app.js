import 'dotenv/config';
import express from 'express';
import bodyParser from 'body-parser';
import './db/index.js';
import authRouter from './routes/index.js';
import cookieParser from 'cookie-parser';

const app = express();

app.use(bodyParser.json());
app.use(cookieParser());
app.use('/api', authRouter);

app.listen(process.env.PORT, () => {
    try {
        console.log(`Server is running on port ${process.env.PORT}`);
    } catch (error) {
        console.log(error);
    }
});