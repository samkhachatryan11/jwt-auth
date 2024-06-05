import jwt from 'jsonwebtoken';

async function cookieVerify(req, res, next) {
    try {
        const token = req.cookies.access_token;
        if(!token) {
            return res.status(401).send({message: 'Not authorized'});
        }

        const verifyToken = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
        req.user = verifyToken
        if(verifyToken) {
            next();
        } else res.status(401).send({message: 'Access denied!'});
    } catch (error) {
        console.log(error);
        res.status(500).json({message: error.message});
    }
};
  
export default cookieVerify;