import User from "../db/User.js";
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import client from "../db/redis.js";

export async function createUser(req, res) {
    bcrypt.hash(req.body.password, 8, async function(err, hash) {
        const user = await User.create({username: req.body.username, email: req.body.email, password: hash});
        const { email } = req.body;
    
        const accessToken = jwt.sign({id: user._id, username: user.username, email: user.email}, process.env.JWT_ACCESS_SECRET, { expiresIn: '1h' });
        const refreshToken = jwt.sign({id: user._id, username: user.username, email: user.email}, process.env.JWT_REFRESH_SECRET, {expiresIn: '30d'});
    
        client.set(`token_${user._id}`, refreshToken, { EX: 3600 });
    
        return res
            .cookie('access_token', accessToken, {
                httpOnly: process.env.COOKIE_HTTP_ONLY,
                secure: process.env.COOKIE_SECURE,
                sameSite: process.env.COOKIE_SAME_SITE,
                maxAge: process.env.COOKIE_MAX_AGE,})
            .cookie('refresh_token', refreshToken, {
                httpOnly: process.env.COOKIE_HTTP_ONLY,
                secure: process.env.COOKIE_SECURE,
                sameSite: process.env.COOKIE_SAME_SITE,
                maxAge: process.env.COOKIE_MAX_AGE,
            }).json({ message: 'User successfully created!' });
    });

    
};

export async function getusers(req, res) {
    const users = await User.find({});

    if (!users) {
        res.send('No users found :(')
    }

    res.send(users)
};

export async function login(req, res) {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if(!bcrypt.compareSync(req.body.password, user.password)) {
        return res.status(401).json({message: 'Wrong password!'})
    }

    const accessToken = jwt.sign({id: user._id, username: user.username, email: user.email}, process.env.JWT_ACCESS_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({id: user._id, username: user.username, email: user.email}, process.env.JWT_REFRESH_SECRET, {expiresIn: '30d'});
        
    client.set(`token_${user._id}`, refreshToken);
        
    return res
        .cookie('access_token', accessToken, {
            httpOnly: process.env.COOKIE_HTTP_ONLY,
            secure: process.env.COOKIE_SECURE,
            sameSite: process.env.COOKIE_SAME_SITE,
            maxAge: process.env.COOKIE_MAX_AGE,})
        .cookie('refresh_token', refreshToken, {
            httpOnly: process.env.COOKIE_HTTP_ONLY,
            secure: process.env.COOKIE_SECURE,
            sameSite: process.env.COOKIE_SAME_SITE,
            maxAge: process.env.COOKIE_MAX_AGE,
    }).send({ message: 'Successfuly loged in!' });
};

export async function deleteUser(req, res) {
    const deleteUser = await User.findOneAndDelete({ _id: req.user.id });

    if(!deleteUser) {
        res.status(400).send({message: 'User not found :('});
    }

    client.del(`token_${req.user.id}`);

    res.clearCookie('access_token').clearCookie('refresh_token').json({message: 'User has been successfully deleted!'});
};

export async function logout(req, res) {
    client.del(`token_${req.user.id}`);

    res.clearCookie('access_token').clearCookie('refresh_token').json({message: 'Successfully logged out!'});
};

export async function tokenRefresh(req, res) {
    const user = jwt.verify(req.body.refreshToken, process.env.JWT_REFRESH_SECRET)
    const token = await client.get(`token_${user.id}`)
    if(!user || req.body.refreshToken !== token) {
        res.status(401).send('Unauthorized')
    }
    const accessToken = jwt.sign({id: user.id, username: user.id, email: user.id}, process.env.JWT_ACCESS_SECRET, { expiresIn: '1h' });
    const refreshToken = jwt.sign({id: user.id, username: user.id, email: user.id}, process.env.JWT_REFRESH_SECRET, {expiresIn: '30d'});
        
    client.set(`token_${user.id}`, refreshToken);
        
    return res
        .cookie('access_token', accessToken, {
            httpOnly: process.env.COOKIE_HTTP_ONLY,
            secure: process.env.COOKIE_SECURE,
            sameSite: process.env.COOKIE_SAME_SITE,
            maxAge: process.env.COOKIE_MAX_AGE,})
        .cookie('refresh_token', refreshToken, {
            httpOnly: process.env.COOKIE_HTTP_ONLY,
            secure: process.env.COOKIE_SECURE,
            sameSite: process.env.COOKIE_SAME_SITE,
            maxAge: process.env.COOKIE_MAX_AGE,
    }).send({ message: 'Success!' });
};