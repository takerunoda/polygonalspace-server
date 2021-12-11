import cookie from 'cookie';
import { Response } from "express";

interface FunctionProps {
    res: Response
    refreshToken: string | undefined
    maxAge: number | undefined
    maxAgeTwo: number | undefined
    accessToken: string | undefined
    isLoggedin: boolean | undefined
    userStatus: string | undefined
    loginType: string | undefined
    userId: string | undefined
    userEmail: string    | undefined 
}

export const setCookieAuth = ({
    res, refreshToken, maxAge, maxAgeTwo, accessToken, isLoggedin, userStatus, loginType, userId, userEmail} : FunctionProps) => {
    const domain =          process.env.NODE_ENV === "production" ? 
                            process.env.DOMAIN : process.env.DOMAIN_2
       res.setHeader(
           "Set-Cookie",
           [
               cookie.serialize(
               "jwt",
                JSON.stringify(refreshToken), 
                { 
                    httpOnly: true,
                    maxAge: maxAge,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               cookie.serialize(
               "accessToken",
                JSON.stringify(accessToken), 
                { 
                    httpOnly: true,
                    maxAge: maxAgeTwo,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               cookie.serialize(
               "isLoggedin",
                JSON.stringify(isLoggedin), 
                { 
                    // httpOnly: true,
                    maxAge: maxAge,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               cookie.serialize(
               "userStatus",
                JSON.stringify(userStatus), 
                { 
                    httpOnly: true,
                    maxAge: maxAge,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               cookie.serialize(
               "loginType",
                JSON.stringify(loginType), 
                { 
                    httpOnly: true,
                    maxAge: maxAge,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               cookie.serialize(
               "userId",
                JSON.stringify(userId), 
                { 
                    // httpOnly: true,
                    maxAge: maxAge,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               cookie.serialize(
               "userEmail",
                JSON.stringify(userEmail), 
                { 
                    // httpOnly: true,
                    maxAge: maxAge,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
                ]
            ) 
    }