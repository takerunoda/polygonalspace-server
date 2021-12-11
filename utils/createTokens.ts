import  jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config()

//create json web token
    const maxAge = 14 * 24 * 60 * 60
    const maxAgeTwo = 60 * 60
    const refreshSecret = process.env.REFRESH_SECRET
    const accessSecret = process.env.ACCESS_SECRET
    const confirmationSecret = process.env.CONFIRMATION_SECRET
    const passwordResetSecret = process.env.PASSWORD_RESET_SECRET

interface FunctionProps {
    userId: string
    userEmail: string
    userStatus: string
    loginType: string
}
    
export const createRefreshToken = ({userId, userEmail, userStatus, loginType, 
} : FunctionProps) => {
    
    return refreshSecret && jwt.sign(
            {   userId:         userId, 
                userEmail:      userEmail,
                userStatus:     userStatus,
                loginType:      loginType,
             }, 
            refreshSecret, 
            {expiresIn: maxAge}
        );
}

export const createRefreshTokenGuest = ({userId, userEmail, userStatus, loginType, 
} : FunctionProps) => {
    
    return refreshSecret && jwt.sign(
            {   userId:         userId, 
                userEmail:      userEmail,
                userStatus:     userStatus,
                loginType:      loginType,
             }, 
            refreshSecret, 
            {expiresIn: maxAgeTwo}
        );
}

export const createAccessToken = ({userId, userEmail, userStatus, loginType, 
} : FunctionProps) => {
    return accessSecret &&  jwt.sign(
            {   userId:         userId, 
                userEmail:      userEmail,
                userStatus:     userStatus,
                loginType:      loginType,
             }, 
            accessSecret, 
            {expiresIn: maxAgeTwo}
        );
}

export const createConfirmationToken = (userId: string) => {
    return confirmationSecret && jwt.sign(
            { userId: userId }, 
            confirmationSecret, 
            {expiresIn: 48 * 60 * 60}
        );
}

export const createPasswordResetToken = (
    {userId, userEmail} : {userId: string, userEmail: string}
    ) => {
    return passwordResetSecret && jwt.sign(
            { userId, userEmail}, 
            passwordResetSecret, 
            {expiresIn: 10 * 60}
        );
}