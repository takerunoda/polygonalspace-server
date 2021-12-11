import jwt from 'jsonwebtoken'
import cookie from 'cookie'
import dotenv from 'dotenv';
import { NextFunction, Request, Response } from "express"
import { createAccessToken } from '../utils/createTokens';
import process from "process";
import { returnAddress } from '../utils/returnAddress';
dotenv.config()


//Get a new access token
//server accesses a refresh token in Cookie
//Then create a new access token and send it back to front-end
const sendNewAccessToken = async (req: Request, res: Response, next: NextFunction) => {
    
    try {
            const refreshToken: string = req.cookies.jwt && JSON.parse(req.cookies.jwt);
            if( typeof req.cookies.jwt == 'undefined' ||!refreshToken || !process.env.REFRESH_SECRET){
                            throw new Error("No refresh token")
            };
            jwt.verify(
                    refreshToken, 
                    process.env.REFRESH_SECRET, 
                     async (err: any, 
                            decodedToken: any) => {
            if(err){ 
                console.log(err.message, err);
                res.status(401)
                return;
            } else {
                if(!decodedToken) {
                    throw new Error("Authentication failed")
                }
                const decodedTokenId: string = decodedToken.userId
                const decodedTokenEmail: string = decodedToken.userEmail
                const decodedTokenStatus: string = decodedToken.userStatus
                const decodedTokenLoginType: string = decodedToken.loginType

                const accessToken = createAccessToken({
                        userId:     decodedTokenId, 
                        userEmail:  decodedTokenEmail, 
                        userStatus: decodedTokenStatus, 
                        loginType:  decodedTokenLoginType,
                    })
                
                const maxAgeTwo = 60 * 60
                res.status(201)
                accessToken && res.setHeader(
                "Set-Cookie",
                [
                    cookie.serialize(
                    "accessToken",
                    JSON.stringify(accessToken), 
                        { 
                    httpOnly: true,
                    maxAge: maxAgeTwo,
                    sameSite: "lax",
                    domain: process.env.NODE_ENV === "production" ? 
                            process.env.DOMAIN : process.env.DOMAIN_2,
                    path: "/"
                        })
                    ])
                res.status(200).json({
                        ok: true, 
                        accessToken: accessToken,
                        userId: decodedTokenId,
                        userStatus: decodedTokenStatus,
                        loginType: decodedTokenLoginType,
                        // userEmail: user?.userEmail
                    })                    
            }
        })
    } catch(err) {
        console.log(err); 
        return  
    } 
}

const verifyAccessToken = async (req: Request, res: Response, next: NextFunction) => {
    const tokenFromBrowser = req.headers.authorization;
    const sentAccessToken = tokenFromBrowser ? tokenFromBrowser.replace("Bearer ","") : "";
    const accessToken: string = req.cookies.accessToken ? JSON.parse(req.cookies.accessToken): sentAccessToken;
    try {
        if( typeof accessToken === 'undefined' || !process.env.ACCESS_SECRET){
                throw new Error("No access token")
            }  
            jwt.verify(
                    accessToken, 
                    process.env.ACCESS_SECRET, 
                         async (err: any,      
                                decodedToken: any) => {
                if(err){
                    console.log(err);
                    throw new Error(`jwt error: ${err}`)
                } else {    
                    res.locals.decodedToken = decodedToken
                    next();
                }
            })        
    } catch (err) {
        console.log(err);
        res.status(401)
        return;        
    } 
}

export { 
        sendNewAccessToken, 
        verifyAccessToken,
    }