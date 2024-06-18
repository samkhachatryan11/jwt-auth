import Joi from "joi";
import User from "../db/User.js";

export async function createUserRequest(req, res, next) {
    const Schema = Joi.object({

        username: Joi.string()
        .alphanum()
        .min(3)
        .max(30)
        .required(),

        email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
        .external(async(email) => {
            const user = await User.findOne({ email });
            
            if(user) {
                throw new Joi.ValidationError('User with this email already exists!');
            }

            return email;
        }),

        password: Joi.string()
        .pattern(new RegExp('^[a-zA-Z0-9]{3,30}$'))
        .min(8)
        .max(32)
        .required()

    });

    try {
        await Schema.validateAsync(req.body, {abortEarly: false});
        next();
    } catch (error) {
        return res.status(400).json(error.message)
    }
};

export async function loginRequest(req, res, next) {
    const Schema = Joi.object({

        email: Joi.string()
        .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
        .external(async(email) => {
            const user = await User.findOne({ email });
            
            if(!user) {
                throw new Joi.ValidationError('User with this email does not exist!');
            }

            return email;
        }),

        password: Joi.string()
        .pattern(new RegExp('^[a-zA-Z0-9]{3,30}$'))
        .min(8)
        .max(32)
        .required()

    });

    try {
        await Schema.validateAsync(req.body, {abortEarly: false});
        next();
    } catch (error) {
        return res.status(400).json(error.message)
    }
};