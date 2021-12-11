import { User } from '../models/User';
import { Post } from '../models/Post';
import { SharedBookmark } from '../models/SharedBookmark';
import {GuestInterface, 
        BookmarkItemInterface, 
        NASAMyBookmakData, 
        nasaOriginalDataTwo, 
        nasaStateDataInterface, 
        PostInterface, 
        UserInterface, 
        MyBookmarkInterface,
        UserBookmarkInterface} from "../Interfaces";
import axios, { CancelTokenSource } from 'axios';
import jwt from 'jsonwebtoken'
import cookie from 'cookie';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { Request, Response } from "express";
import validator from "email-validator"
import { removeDuplicates } from '../utils/removeDuplicates';
import { toLowerCaseAndConcat } from '../utils/toLowerCaseAndConcat';
import { createAccessToken, createConfirmationToken, createPasswordResetToken, createRefreshToken, createRefreshTokenGuest } from '../utils/createTokens';
import { returnAddress } from '../utils/returnAddress';
import { handleErrors } from '../utils/handleErrors';
import { Confirmation } from '../models/Confirmation';
import { sendEmail } from '../utils/sendEmail';
import { Guest } from '../models/Guest';
import { BookmarkItem } from '../models/BookmarkItem';
import { handleMediaType } from '../utils/handleMediaType';
import { MyBookmark } from '../models/MyBookmark';
import { googleVerify } from '../utils/googleVerify';
import { PasswordReset } from '../models/PasswordReset';
import { handleErrorsGeneral } from '../utils/handleErrorsGeneral';
import { emailTextPasswordReset, emailTextSignup } from '../utils/emailTexts';
import { handlePostItems } from '../utils/handlePostItems';
import { handleOnePost } from '../utils/handleOnePostItem';
import { returnMyBookmarks } from '../utils/returnMyBookmarks';
import { returnMyBookmarkIds } from '../utils/returnMyBookmarkIds';
import { findMyBookmark } from '../utils/findMyBookmark';
import { setCookieAuth } from '../utils/setCookieAuth';
import { clearCookieAuth } from '../utils/clearCookieAuth';
dotenv.config()

const serverAddress =   process.env.NODE_ENV === "production" ? 
                        process.env.SERVER_URL : process.env.SERVER_URL_2
const domain =          process.env.NODE_ENV === "production" ? 
                        process.env.DOMAIN : process.env.DOMAIN_2
const corsOrigin =      process.env.NODE_ENV === "production" ? 
                        process.env.CORS_ORIGIN : process.env.CORS_ORIGIN_2
const refreshSecret = process.env.REFRESH_SECRET ?? ""                    

let cancelSourceSearch: CancelTokenSource | undefined

//controller actions
 const signupPost = async(req: Request, res: Response) => {
    const { userEmail, password, passwordConfirmation, language }  = req.body

    const address  = returnAddress(req)
    const sameAddress = await User.find({address: address})
    const status = sameAddress.map(item => item.userStatus)

    const emailValidation = validator.validate(userEmail)
        
try {     
    if(!emailValidation){
        throw new Error("not an email address")
    }
    if(password.length < 8){
        throw new Error("password length")
    }
    if(!status.includes("admin") 
    && sameAddress.length >= 3){ 
        throw new Error("account number limit")
    }
    if (password !== passwordConfirmation){ 
        throw new Error("passwords do not match")
    }
    const countUser = await User.countDocuments({ userEmail })
    if(countUser > 0) {
        const userObject = await User.findOne({ userEmail })
        const isVerified = userObject && userObject.verified
        const isPasswordLogin = userObject && userObject.passwordLogin
        const isGoogleLogin = userObject && userObject.googleLogin

        if(isVerified){
            throw new Error("password user exists")
        }
        if(isGoogleLogin && isPasswordLogin && !isVerified){
            throw new Error("confirmation not completed")
        }
        if(!isGoogleLogin && isPasswordLogin && !isVerified){
            throw new Error("confirmation not completed")
        }
        if(isGoogleLogin && !isPasswordLogin && !isVerified){
            throw new Error("update in mypage")            
        }
        if(!isGoogleLogin && !isPasswordLogin && !isVerified){
            throw new Error("unexpected error occured")            
        }
    }
        const user = await User.create({ 
            userEmail, 
            password,
            address,
            passwordLogin: true,
            })  
        const userId: string = user._id
        const myBookmarkArray: UserBookmarkInterface[] = []
            const bookmarkTable: MyBookmarkInterface = 
            await MyBookmark.create({ 
                userId: userId, 
                bookmark: myBookmarkArray
            })        
            const confirmationToken = createConfirmationToken(userId)
            const confirmation = await Confirmation.create({
                userId,
                confirmationToken
            })
            
            const linkText = `${corsOrigin}/confirmation?id=${userId}&token=${confirmationToken}`
    
            userEmail && linkText && 
            await sendEmail({
                        emailAddress: userEmail, 
                        ipAddress: address,
                        linkText, 
                        language,
                        emailText: emailTextSignup})
                .then((result : any) => {console.log("Email has been sent"), result;})
                .catch((err) => {
                console.log(err.message)
                throw new Error("sendingEmailFailed")
            })
            res.status(201).json({ok: true})
            return
        } catch (err) {
            const errors = await handleErrors(err);
             res.status(400).send({errors});
        }
    }

 const signupPostGuest = async(req: Request, res: Response) => {
    const randomName = Math.random().toString(36).substring(2,11);
    const userEmail = `Guest-${randomName}`
    const address  = returnAddress(req)
    const sameAddress: GuestInterface[] = await Guest.find({address: address})
    const sameAddressUser: UserInterface[] = await User.find({address: address})
    const status: string[] = sameAddressUser.map(item => item.userStatus)
    const maxAge = 60 * 60
    const maxAgeTwo = 60 * 60
        try { 
                if(sameAddress.length > 50 && !status.includes("admin")){ 
                    throw new Error("account number limit")}  
        const user: GuestInterface = await Guest.create({ 
            userEmail, 
            address})
            
        const userId = user._id           
        const userStatus = user.userStatus          
        const loginType = "guest"
        const refreshToken = userId && createRefreshTokenGuest({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const accessToken = userId && createAccessToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const isLoggedin = true
        const bookmarkTable: MyBookmarkInterface = await MyBookmark.create({ userId: user._id, bookmark: []})

        const userBookmarkIds: UserBookmarkInterface[] = []

            setCookieAuth({res: res, refreshToken, maxAge, maxAgeTwo, accessToken, isLoggedin, userStatus, loginType, userId, userEmail})
                        res.status(200).json({
                            ok: true, 
                            accessToken: accessToken,
                            userId: userId,
                            userEmail: userEmail,
                            userStatus: userStatus,
                            loginType: loginType,
                            passwordLogin: false,
                            googleLogin: false,
                            userBookmarkIds: userBookmarkIds
                        })
                    return
              
        } catch (err) {
            const errors = await handleErrors(err);
            res.status(400).send({errors});
        }   
}

 const resendConfirmation = async(req: Request, res: Response) => {
    const { userEmail, language }  = req.body
    const address  = returnAddress(req)
    try {
        const user = await User.findOne({userEmail})
        if(!user){
            throw new Error("user does not exist")
        }
        if(user.verified){
            throw new Error("user already verified")
        }
                     const userId = user._id
                     const confirmationToken = userId && createConfirmationToken(userId)
                     const confirmation = await Confirmation.create({
                         userId,
                         confirmationToken
                     })                     
            const linkText = `${corsOrigin}/confirmation?id=${userId}&token=${confirmationToken}`
             
                      userEmail && linkText && 
                        await sendEmail({
                                    emailAddress: userEmail, 
                                    ipAddress: address,
                                    linkText, 
                                    language,
                                    emailText: emailTextSignup
                                })
                                      .then((result : any) => {console.log("Email has been sent"), result;})
                                      .catch((err) => {
                                          console.log(err.message);})

                     res.status(201).json({ok: true})
                     return
    } catch (err) {
            const errors = await handleErrorsGeneral(err);
            res.status(400).send({errors});
    }
}

const userConfirmation = async (req: Request, res: Response) => {
    const maxAge = 14 * 24 * 60 * 60
    const maxAgeTwo = 60 * 60

    try {
         const user = await User.findOne({ _id: req.params.id })
         if(!user) {
             throw new Error("Invalid link")
         }
        const userId = user._id           
        const userEmail = user.userEmail           
        const userStatus = user.userStatus          
        const loginType = "password"
        const passwordLogin = user.passwordLogin          
        const googleLogin = user.googleLogin
        const token = await Confirmation.findOne({ 
             userId: userId, 
             confirmationToken: req.params.token
         })
         if(!token){
             throw new Error("Invalid link")
         }

         await User.findByIdAndUpdate(user._id, { verified: true })
         await Confirmation.findByIdAndRemove(token._id)

        const myBookmark = await findMyBookmark({userId})
        const userBookmarkIds = myBookmark.map((item: UserBookmarkInterface) => item.bookmarkId)

        const refreshToken = userId && createRefreshToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const accessToken = userId && createAccessToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const isLoggedin = true

        setCookieAuth({res: res, refreshToken, maxAge, maxAgeTwo, accessToken, isLoggedin, userStatus, loginType, userId, userEmail: user.userEmail})
        
        res.status(201).json({
            ok: true, 
            accessToken: accessToken,
            userId: userId,
            userEmail: userEmail,
            userStatus: userStatus,
            loginType: loginType,
            passwordLogin: passwordLogin,
            googleLogin: googleLogin,
            userBookmarkIds: userBookmarkIds
        })
    } catch (err) {
        console.log(err);
        res.sendStatus(400);
        return 
    }
}

 const passwordResetRequest = async(req: Request, res: Response) => {
    const { userEmail, language} :{userEmail: string, language: boolean} = req.body
    const address  = returnAddress(req)
    
    try {
        const user = await User.findOne({userEmail})
                    if(!user){
                        throw new Error("user does not exist")
                    }
                     const passwordLogin: boolean = user.passwordLogin
                     if(!passwordLogin){
                        throw new Error("password login not set")
                     }
                     const userId: string = user._id
                     const passwordResetToken = userId && userEmail && createPasswordResetToken({userId, userEmail})
                     const passwordReset = await PasswordReset.create({
                            userId,
                            userEmail,
                            passwordResetToken
                     })                     
                     const linkText = `${corsOrigin}/password-reset?id=${userId}&email=${userEmail}&token=${passwordResetToken}`
             
                      userEmail && linkText && 
                        await sendEmail({
                                    emailAddress: userEmail, 
                                    ipAddress: address,
                                    linkText, 
                                    language, 
                                    emailText: emailTextPasswordReset
                                })
                                      .then((result : any) => {console.log("Email has been sent"), result;})
                                      .catch((err) => {
                                          console.log(err.message);})

                    res.status(201).json({ok: true})
                     return
    } catch (err) {
            const errors = await handleErrors(err);
            res.status(400).send({errors});
        }
    }


 const passwordResetSubmit = async(req: Request, res: Response) => {
    const { userEmail, password, passwordConfirmation, passwordResetToken } 
     = req.body
    const passwordResetSecret: string = process.env.PASSWORD_RESET_SECRET ?? ""
    const maxAge = 14 * 24 * 60 * 60
    const maxAgeTwo = 60 * 60
            jwt.verify(
                    passwordResetToken, 
                    passwordResetSecret, 
                         async (err: any,      
                                decodedToken: any) => {
                if(err){
                    console.log(err);
                    throw new Error(`jwt error: ${err}`)
                } else {                
                    res.locals.decodedToken = decodedToken
                    const decodedTokenUserId = decodedToken.userId
                    const decodedTokenEmail = decodedToken.userEmail
                    const userId = decodedTokenUserId
            try {
                    if(decodedTokenEmail !== userEmail){
                        throw new Error("Email and Token are inconsistent")
                    }
                    if(password.length < 8){
                        throw new Error("password length")
                    }
                    if (password !== passwordConfirmation){ 
                        throw new Error("passwords do not match")
                    }
                    const counstPasswordReset = await PasswordReset.countDocuments({
                        passwordResetToken: passwordResetToken 
                    })
                    if(counstPasswordReset === 0){
                        throw new Error("Token does not exist")
                    }
                    const tokenObject = await PasswordReset.findOne({ 
                        passwordResetToken: passwordResetToken 
                     })
                    const passwordResetTokenId = tokenObject && tokenObject._id && tokenObject._id
                    if (password !== passwordConfirmation){
                        throw new Error("passwords do not match")
                    }
                    const salt = await bcrypt.genSalt();
                    const passwordSalted = await bcrypt.hash(password, salt)
                    const user = await User.findByIdAndUpdate( 
                        userId, {password: passwordSalted}
                      )
                    if(!user){
                        throw new Error("Password Update failed")
                    }
                    const userStatus = user.userStatus
                    const loginType = "password"

        passwordResetTokenId && await PasswordReset.findByIdAndRemove(passwordResetTokenId)
        const userBookmarkIds = await returnMyBookmarkIds({userId: userId})
        const refreshToken = userId && createRefreshToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const accessToken = userId && createAccessToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const isLoggedin = true
        setCookieAuth({res: res, refreshToken, maxAge, maxAgeTwo, accessToken, isLoggedin, userStatus, loginType, userId: user._id, userEmail: user.userEmail})
        
        res.status(201).json({
            ok: true, 
            accessToken: accessToken,
            userId: user._id,
            userEmail: user.userEmail,
            userStatus: user.userStatus,
            loginType: user.loginType,
            userBookmarkIds: userBookmarkIds
        })

        return
            } catch (err) {
                const errors = await handleErrors(err);
                res.status(400).send({errors});
            }    
        }
    })
}

const loginPost = async (req: Request, res: Response) => {
    const { userEmail, password } = req.body;
    const maxAge = 14 * 24 * 60 * 60
    const maxAgeTwo = 60 * 60



    try {
        //STEP 1
        //login method checks if userEmail and password match the ones in database.
        const user: UserInterface = await User.login(userEmail, password);
        //STEP 2
        //Create brand new refresh token and access token.
        //server will store the refresh token in cookies and send back the access token as a response to the front-end app.
        //react app will store the access token in memory, say in state. 
        const userId = user._id
        const userStatus = user.userStatus
        const loginType = "password"
        const isPasswordLogin = user.passwordLogin
        const isGoogleLogin = user.googleLogin
        if(!isPasswordLogin && isGoogleLogin){
            throw new Error("update in mypage")
        }
        if(!isPasswordLogin && !isGoogleLogin){
            throw new Error("not signed up")
        }

        const refreshToken = userId && createRefreshToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const accessToken = userId && createAccessToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const isLoggedin = true
        const bookmarkArray:UserBookmarkInterface[] = []
        const countBookmarkTable = await MyBookmark.countDocuments({ userId: userId })
        if(countBookmarkTable === 0){
                await MyBookmark.create({ 
                    userId: userId, 
                    bookmark: bookmarkArray
                })
            }
        const userBookmarkIds = userId && await returnMyBookmarkIds({ userId: userId })

        setCookieAuth({res: res, refreshToken, maxAge, maxAgeTwo, accessToken, isLoggedin, userStatus, loginType, userId, userEmail})        
        res.status(200).json({
            ok: true, 
            accessToken: accessToken,
            userId: userId,
            userEmail: userEmail,
            userStatus: userStatus,
            loginType: loginType,
            userBookmarkIds: userBookmarkIds
        })
        return

    } catch (err) {
        if(err)
        {const errors = handleErrors(err);
        res.status(400).send({errors});}
        return
    }   
}

const googleSignupPost = async (req: Request, res: Response) => {
    const { googleToken } = req.body;
    const maxAge = 14 * 24 * 60 * 60
    const maxAgeTwo = 60 * 60
    const googleObject = await googleVerify(googleToken)

    try {
        if(!googleObject){
            throw new Error("google not verified")
        }
        const googleId = googleObject.googleId
        const userEmail = googleObject.userEmail
        const userName = googleObject.userName
        if(!googleId || !userEmail || !userName){
            throw new Error("google not verified")
        }
        const countUser =  await User.countDocuments({ 
            userEmail: userEmail })
            
        let user: UserInterface | null
        let bookmarkTable: MyBookmarkInterface | null = null            
        let userId: string = ""
        let userStatus: string = ""
        let loginType: string = ""
        let alreadySignedUp: boolean = false

        const address  = returnAddress(req)
        const sameAddress = await User.find({address: address})
        const status = sameAddress.map(item => item.userStatus)
        const randomCharacters = Math.random().toString(36);
        const salt = await bcrypt.genSalt();
        const SaltedRandomCharacters = await bcrypt.hash(randomCharacters, salt)

        if(countUser === 0) {
            if(!status.includes("admin")
             && sameAddress.length >= 3){ 
                                throw new Error("account number limit")
                            } 
                    user = await User.create({
                        googleId,
                        userEmail,
                        password: SaltedRandomCharacters,
                        userName,
                        googleLogin: true,
                    })
                    userId = user._id ?? ""
                    userStatus = user.userStatus
                    loginType = "google"
                    bookmarkTable = await MyBookmark.create({ 
                        userId: user._id, 
                        bookmark: []})              
        } else {
            user = await User.findOne({ userEmail})
        if(!user){
            throw new Error("auth error")
        }
        if(!user.passwordLogin && !user.googleLogin){
            throw new Error("auth error-2")
        }
        if(user.passwordLogin && !user.googleLogin){
            throw new Error("update in mypage for google")            
        }
        if(user.googleLogin){
                    userId = user._id ?? ""
                    userStatus = user.userStatus
                    loginType = "google"
                    alreadySignedUp = true
                }
            }
        const refreshToken = userId && createRefreshToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const accessToken = userId && createAccessToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const isLoggedin = true

        const userBookmarkIds: UserBookmarkInterface[] = []

        setCookieAuth({res: res, refreshToken, maxAge, maxAgeTwo, accessToken, isLoggedin, userStatus, loginType, userId: user._id, userEmail: userEmail})

        res.status(200).json({
            ok: true, 
            accessToken: accessToken,
            userId: userId,
            userEmail: userEmail,
            userStatus: userStatus,
            loginType: loginType,
            userBookmarkIds: userBookmarkIds,
            alreadySignedUp: alreadySignedUp,
        })
        return
    } catch (err) {
        if(err)
        {const errors = handleErrors(err);
        res.status(400).send({errors});}
        return
    } 
}

const googleLoginPost = async (req: Request, res: Response) => {
    const { googleToken } = req.body;
    const maxAge = 14 * 24 * 60 * 60
    const maxAgeTwo = 60 * 60
    const googleObject = await googleVerify(googleToken)

    try {
        if(!googleObject){
            throw new Error("google not verified")
        }
        const googleId = googleObject.googleId
        const userEmail = googleObject.userEmail
        const userName = googleObject.userName
        if(!googleId || !userEmail || !userName){
            throw new Error("google not verified")
        }
        const countUser =  await User.countDocuments({ 
            userEmail: userEmail })
        let user: UserInterface | null
        let bookmarkTable: MyBookmarkInterface | null
        let userId: string = ""
        let userStatus: string = ""
        let loginType: string = ""

        if(countUser === 0) {
            throw new Error("not signed up google")
        } else {
        user = await User.findOne({ userEmail })
        if(!user){
            throw new Error("user does not exist")
        }
        const isGoogleLogin = user.googleLogin
        const isPasswordLogin = user.passwordLogin
        if(isPasswordLogin && !isGoogleLogin){
            throw new Error("update in mypage for google")
        }
        if(!isPasswordLogin && !isGoogleLogin){
            throw new Error("not signed up google")
        }
                    userId = user._id ?? ""
                    userStatus = user.userStatus
                    loginType = "google"
        const bookmarkArray:UserBookmarkInterface[] = []
        const  countBookmarkTable = await MyBookmark.countDocuments({ userId: userId })
        if(countBookmarkTable === 0){
                await MyBookmark.create({ 
                    userId: userId, 
                    bookmark: bookmarkArray
                })
            }
        }
        
        const refreshToken = userId && createRefreshToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const accessToken = userId && createAccessToken({
            userId, 
            userEmail, 
            userStatus, 
            loginType,
        })
        const isLoggedin = true

        const userBookmarkIds = userId && await returnMyBookmarks({userId: userId})
        setCookieAuth({res: res, refreshToken, maxAge, maxAgeTwo, accessToken, isLoggedin, userStatus, loginType, userId: user._id, userEmail: userEmail})
        res.status(200).json({
            ok: true, 
            accessToken: accessToken,
            userId: userId,
            userEmail: userEmail,
            userStatus: userStatus,
            loginType: loginType,
            userBookmarkIds: userBookmarkIds
        })
        return
    } catch (err) {
        if(err)
        {const errors = handleErrors(err);
        res.status(400).send({errors});}
        return
    } 
}

const enableGoogleSignin = async (req: Request, res: Response) => {
    const { googleToken } = req.body;
    const userEmailAccessToken = res.locals.decodedToken.userEmail
    const userIdAccessToken = res.locals.decodedToken.userId
    const googleObject = await googleVerify(googleToken)

    try {
        if(!googleObject){
            throw new Error("google not verified")
        }
        const googleId = googleObject.googleId
        const userEmail = googleObject.userEmail
        const userName = googleObject.userName

        if(!googleId || !userEmail || !userName){
            throw new Error("google not verified")
        }
        if(userEmail !== userEmailAccessToken){
            throw new Error("emails do not match google")
        }

        await User.findByIdAndUpdate(userIdAccessToken, {googleLogin: true, googleId: googleId})
        res.status(200).json({
            ok: true,
            googleLogin: true,
        })
        return
    } catch (err) {
        if(err)
        {const errors = handleErrors(err);
        res.status(400).send({errors});}
        return
    } 
}

const logoutPost = (req: Request, res: Response) => {
    try {
        clearCookieAuth({res: res})
        res.status(200).json({
            ok: true, 
        })
        return
    } catch (err) {
        console.log(err);
        res.sendStatus(400)
        return    
    }
}

const changePassword = async (req: Request, res: Response) => {
    const { userEmail, currentPassword, newPassword, newPasswordConfirmation } = req.body;
    const decodedUserEmail = res.locals.decodedToken.userEmail
    
    try {
        const user: UserInterface | undefined = await User.login(decodedUserEmail, currentPassword);
        const userId = user && user._id

        if (newPassword !== newPasswordConfirmation){ 
            throw new Error("passwords do not match")
        }
        if(newPassword.length < 8){
            throw new Error("password length")
        }

        const salt = await bcrypt.genSalt();
        const passwordSalted = await bcrypt.hash(newPassword, salt)

        const userWithNewPassword = await User.findByIdAndUpdate( 
            userId, {password: passwordSalted}
            )
        
        if(!userWithNewPassword){
            throw new Error("Password Update failed")
        }

        res.status(200).json({
            ok: true, 
        })
        return
    } catch (err) {
        if(err){
            const errors = handleErrors(err);
            res.status(400).send({errors});
        }
        return
    }
}

const enablePasswordSignin = async (req: Request, res: Response) => {
    const { password, passwordConfirmation } = req.body;
    const userId = res.locals.decodedToken.userId
    
    try {
        if (password !== passwordConfirmation){ 
            throw new Error("passwords do not match")}
        if(password.length < 8){
            throw new Error("password length")}

        const salt = await bcrypt.genSalt();
        const passwordSalted = await bcrypt.hash(password, salt)

        const userWithNewPassword = await User.findByIdAndUpdate( 
            userId, {password: passwordSalted, passwordLogin: true, verified: true}
            )

        if(!userWithNewPassword){
            throw new Error("password update failed")}

        res.status(200).json({
            ok: true, 
            passwordLogin: true
        })
        return
    } catch (err) {
        if(err){
            const errors = handleErrors(err);
            res.status(400).send({errors})
        }
        return
    }
}

const deleteUser = async (req: Request, res: Response) => {
    const { userEmail, password, language } = req.body;
    const userId = res.locals.decodedToken.userId
    const userStatus = res.locals.decodedToken.userStatus

    try {
       if(userStatus === "guest"){
            throw new Error("guest cannot be deleted")
        } 
        if(!userId){
            throw new Error("asscessToken not verified")
        }  
        const user = await User.login(userEmail, password);
        const x = await user._id
        const userIdTwo = x.toString()
        if(userId !== userIdTwo){
            throw new Error("user identification failed")
        }

        await User.findByIdAndDelete(userId)
        await MyBookmark.deleteMany({ userId })
        clearCookieAuth({res: res})
        res.status(200).json({ 
            ok: true
        })
        
    return
    } catch (err) {
        if(err)
        {const errors = handleErrors(err);
        res.status(400).send({errors});}
        return
    }
}

const deleteUserGoogle = async (req: Request, res: Response) => {
    const { userEmail, googleToken } = req.body;
    const googleObject = await googleVerify(googleToken)

    try {
        if(!googleObject){
            throw new Error("user identification failed")
        }
        const googleUserEmail = googleObject.userEmail
        if(userEmail !== googleUserEmail){
            throw new Error("emails do not match")
        }
        const googleId = googleObject.googleId

        const user = await User.findOne({ googleId: googleId })
        
        if(!user){
            throw new Error("user does not exist")
        }
        const userId = user._id
                await User.findByIdAndDelete(userId)
                await MyBookmark.deleteMany({ userId })
                clearCookieAuth({res: res})

                res.status(200).json({ 
                    ok: true
                })                
        return
    } catch (err) {
        if(err)
        {const errors = handleErrors(err);
        res.status(400).send({errors});}
        return
    }
}

const bookmarkAdd = async(req: Request, res: Response) => {
    try {
    const decodedUserId = res.locals.decodedToken.userId
    const { imageId, mediaType, imageUrl } : {imageId: string, mediaType: string, imageUrl: string} 
    = req.body;
    const countMyBookmark =  await MyBookmark.countDocuments({ userId: decodedUserId })
    const countBookmarkItem =  await BookmarkItem.countDocuments({ imageId: imageId })
    const myBookmarkIds = await returnMyBookmarkIds({userId: decodedUserId}) 
    if(myBookmarkIds && myBookmarkIds.includes(imageId)){ 
        throw new Error("already bookmarked")
    }
    const returnNewBookmark = async () => {
        const newId = { bookmarkId: imageId }
                    if(countMyBookmark === 0){
                    const newBookmarkTable: MyBookmarkInterface 
                    = await MyBookmark.create({ 
                        userId: decodedUserId, 
                        bookmark: []})
                    }
        const myBookmark = await findMyBookmark({userId: decodedUserId})
        const newBookmark: UserBookmarkInterface[] | null = myBookmark && [...myBookmark, newId]
        return newBookmark
    }

    const createBookmark = async (imageId: string) => {
        const url_1 = process.env.NASA_URL_MY_BOOKMARK_1
        const url_2 = process.env.NASA_URL_MY_BOOKMARK_2
        const url_3 = process.env.NASA_URL_MY_BOOKMARK_3
        const response = await axios.get(encodeURI(`${url_1}/${mediaType}/${imageId}/${url_2}`))
        const responseTwo = await axios.get(encodeURI(`${url_3}/${imageId}`))
        
        const x: NASAMyBookmakData = await response.data
        const y1 = await responseTwo.data.collection.items
        const y2: string[] = await y1.map((y: any) => y.href.replace("http:", "https:"))
        const availTitle = 'AVAIL:Title'
        const availDescription = 'AVAIL:Description'
        const availMediaType = 'AVAIL:MediaType'
        const availKeywords = 'AVAIL:Keywords'
        const availDateCreated = 'AVAIL:DateCreated'
        const platform = "NASA"
        const categoryValue: string[] = x[availKeywords].map((x: string) => toLowerCaseAndConcat(x))
        const object = {
                    imageId:                imageId,
                    imageTitle:             x[availTitle],
                    imageUrl:               handleMediaType({ 
                                                item: y2, 
                                                mediaType: x[availMediaType],
                                                imageUrl
                                            }),
                    imageDescription:       x[availDescription],
                    mediaType:              x[availMediaType],
                    category:               x[availKeywords],
                    categoryValue:          categoryValue,
                    originallyCreatedAt:    x[availDateCreated],
                    platform:               platform,
            }
       const createdItem = await BookmarkItem.create(object)
       return createdItem
    }
    
    if(!decodedUserId){
        throw new Error("not verified")
    } else {
        if(countBookmarkItem === 0){
            const MakeBookmarkTable = await createBookmark(imageId)
        }
        
        const newBookmarkData = await returnNewBookmark()
        const filter = {userId: decodedUserId}
        const update = {bookmark: newBookmarkData}
        if(!update || update === null){
            throw new Error("update failed")
        }
        await MyBookmark.findOneAndUpdate(filter, update)

        const userBookmarkIds = await returnMyBookmarkIds({ userId: decodedUserId})
            res.status(200).json({ 
                ok: true,
                userBookmarkIds: userBookmarkIds
            })
    }
        return

    } catch (err) {
                const errors = await handleErrorsGeneral(err);
                res.status(400).send({errors});
       return
    }
}

const bookmarkDelete = async(req: Request, res: Response) => {
    try {
    const decodedUserId = res.locals.decodedToken.userId
    const { imageId } : {imageId: string} 
    = req.body;
    
    const returnNewBookmark = async () => {
        const myBookmark = await findMyBookmark({ userId: decodedUserId })
        const newBookmark: UserBookmarkInterface[] 
        = myBookmark.filter((x: UserBookmarkInterface) => x.bookmarkId !== imageId)
        return newBookmark
    }

    if(!decodedUserId){
        throw new Error("not verified")
    } else {   
        const newBookmarkData = await returnNewBookmark()
        const filter = { userId: decodedUserId}
        const update = {bookmark: newBookmarkData}
        if(!update.bookmark || update.bookmark == null){
            throw new Error("update failed")
        }
               newBookmarkData && update &&
               await MyBookmark.findOneAndUpdate(filter, update)
            const userBookmarkIds = decodedUserId && await returnMyBookmarkIds({ userId: decodedUserId})
            res.status(200).json({ 
                ok: true,
                userBookmarkIds: userBookmarkIds
            })
        }
        return
    } catch (err) {
            console.log(err);
       return
    }
}

const postPost = async(req: Request, res: Response) => {
    interface FunctionProps {
        userPostData: PostInterface
    }    
    const decodedAuthorId = res.locals.decodedToken.userId    
    const {userPostData} : FunctionProps = req.body;
    const x = req.cookies.userStatus
    const userStatus = JSON.parse(x)

    try {
    if(!decodedAuthorId){
        throw new Error("not verified")
    }  
    if (userStatus !== "admin"){
        throw new Error("not admin")
    }
    const post: PostInterface = await Post.create({ 
                        authorId: decodedAuthorId,
                        imageTitle: userPostData.imageTitle,
                        imageUrl: userPostData.imageUrl,
                        sharedUrl: userPostData.sharedUrl,
                        // description: userPostData.description,
                        category: userPostData.category,
                        categoryValue: userPostData.categoryValue,
                        originallyCreatedAt: userPostData.originallyCreatedAt,
                        platform: userPostData.platform,
                        article: userPostData.article,
                        articleTitle: userPostData.articleTitle,
                        user: userPostData.user,
                        like: 0,
                        createdAt: userPostData.createdAt,
                        updatedAt: userPostData.updatedAt
                    })
                    res.status(201).json({ 
                        ok: true,
                        postData: post
                    })    
                return
                } catch (err) {
                        console.log(err);
                    return
                }   
            }
const updatePost = async(req: Request, res: Response) => {
    interface FunctionProps {
        userPostData: any
    }
    const decodedAuthorId = res.locals.decodedToken.userId    
    const {userPostData} : FunctionProps = req.body;
    const x = req.cookies.userStatus
    const userStatus = JSON.parse(x)
    const article = userPostData.article
    const articleTitle = userPostData.articleTitle
    const _id = userPostData._id

    try {
        if(!decodedAuthorId){
            throw new Error("not verified")
        } 
        if (userStatus !== "admin"){
            throw new Error("not admin")
        }
        const post: PostInterface | null 
        = await Post.findByIdAndUpdate(_id, { 
            article: article, 
            articleTitle: articleTitle, 
            updatedAt: new Date(),
        })
                    res.status(201).json({ 
                        ok: true,
                        postData: post
                    })
                return
                } catch (err) {
                console.log(err);
                return
                }   
            }

const postPutNoAuth = async(req: Request, res: Response) => {
 const {postId, updateItem} = req.body;
    try {
        await Post.findByIdAndUpdate(postId, updateItem)
        res.status(201).json({ 
            ok: true
        })
        return
    } catch (err) {
       console.log(err);
       return
    }
}

const bookmarkPutNoAuth = async(req: Request, res: Response) => {
 const { bookmarkId, updateItem } = req.body;
    try {
        await BookmarkItem.findByIdAndUpdate(bookmarkId, updateItem)
        res.status(201).json({ 
            ok: true
        })
        return
    } catch (err) {
       console.log(err);
       return
    }
}

const postDelete = async (req: Request, res: Response) => {
const { postId, authorId } = req.body;
const decodedAuthorId = res.locals.decodedToken.userId

            try {
                if((decodedAuthorId !== authorId)) return
                 await Post.findByIdAndDelete(postId)
                res.status(200).json({ 
                    ok: true,
                    message: "post has been deleted"
                })
                return
            } catch (err) {
            console.log(err);
            return
            }
}

const sharedBookmarkDelete = async (req: Request, res: Response) => {
const {postId, authorId} = req.body;
const decodedAuthorId = res.locals.decodedToken.userId

            try {
                if((decodedAuthorId !== authorId)) return
                 await SharedBookmark.findByIdAndDelete(postId)
                res.status(200).json({ 
                    ok: true,
                    message: "post has been deleted"
                })
                return
            } catch (err) {
            console.log(err);
            return
            }
        }

const getOnePostPost = async (req: Request, res: Response) => {
 const { postId } = req.body;

    try {
        const post = await Post.findById(postId)
        const modifiedPost = post && handleOnePost({onePost: post})
        res.status(200).send({ 
            ok: true,
            postData: modifiedPost
        })
    } catch (err) {
       console.log(err);
       return
    }
}

const getOneBookmarkPost = async (req: Request, res: Response) => {
 const { bookmarkId: bookmarkId } = req.body;

    try {
        const bookmark = await BookmarkItem.findById(bookmarkId)
        res.status(200).send({ 
            ok: true,
            postData: bookmark
        })
    } catch (err) {
       console.log(err);
       return
    }
}
      
const sendBookmarkByPage = async (req: Request, res: Response) => {
    const decodedToken = res.locals.decodedToken
    const decodedUserId = decodedToken.userId
    const { currentPage } = req.body
    const postsPerPage = 12
        try {
            if(!decodedToken){
                throw new Error("not authenticated")
            } else {
        const myBookmark = await returnMyBookmarks({userId: decodedUserId})
        let sortMyBookmark: UserBookmarkInterface[]
            sortMyBookmark = myBookmark ? myBookmark.sort((a, b) => {
            if(!a.createdAt || !b.createdAt) return 0
            const A = a.createdAt ? new Date(a.createdAt).getTime() : 0
            const B = b.createdAt ? new Date(b.createdAt).getTime() : 0
            return B - A
        }) : []       
                        let bookmark: BookmarkItemInterface[] = []
                      
                        if(myBookmark &&  myBookmark.length === 0){                            
                            const randomId = "randomId" as string
                            const object: BookmarkItemInterface = {
                                            _id: randomId,
                                            imageId: randomId ,
                                            imageTitle:"",
                                            imageUrl:"",
                                            imageDescription:"",
                                            like: 0,
                                            platform:""}
                            bookmark = [ object ]
                        } else {
                            const indexOfLastPost = currentPage * postsPerPage;
                            const indexOfFirstPost = indexOfLastPost - (postsPerPage);
                            const currentMyBookmark = sortMyBookmark.slice(indexOfFirstPost, indexOfLastPost);

                            let bookmarkArray: BookmarkItemInterface[] = []
                            await Promise.all(
                                currentMyBookmark.filter(x => x.bookmarkId !== "randomId").map(
                                    async (item : UserBookmarkInterface) => {
                                        const count = await BookmarkItem.countDocuments({ imageId: item.bookmarkId })
                                        if(count === 0){
                                                return bookmarkArray
                                        } else  {
                                            const myBookmarkItem = 
                                            await BookmarkItem.findOne({ imageId: item.bookmarkId })
                                            if(!myBookmarkItem) {
                                                return bookmarkArray
                                            } 
                                            else {
                                    const object_Id = myBookmarkItem._id ?? "randomId"
                                    const objectImageId = myBookmarkItem.imageId
                                    const objectTitle = myBookmarkItem.imageTitle
                                    const objectUrl = myBookmarkItem.imageUrl
                                    const objectDescription = myBookmarkItem.imageDescription
                                    const objectComment = myBookmarkItem.comment ?? ""
                                    const objectLike = myBookmarkItem.like
                                    const objectPublic = myBookmarkItem.public
                                    const objectConfirm = false
                                    const objectMediaType = myBookmarkItem.mediaType ?? "NASA"
                                    const objectCategory = myBookmarkItem.category ?? []
                                    const objectCategoryValue = myBookmarkItem.categoryValue ?? []
                                    const objectOriginallyCreatedAt = myBookmarkItem.originallyCreatedAt ?? new Date()
                                    const objectPlatform = myBookmarkItem.platform
                                    const objectCreatedAt = myBookmarkItem.createdAt ?? new Date()
                                    const objectUpdatedAt = myBookmarkItem.updatedAt ?? new Date()
                                    const objectDateAdded = item.createdAt ?? new Date()
                                    
                                    const object: BookmarkItemInterface = {
                                    _id:                 object_Id,
                                    imageId:             objectImageId,
                                    imageTitle:          objectTitle,
                                    imageUrl:            objectUrl,
                                    imageDescription:    objectDescription,
                                    comment:             objectComment,
                                    like:                objectLike,
                                    public:              objectPublic,
                                    confirm:             objectConfirm,
                                    mediaType:           objectMediaType,
                                    category:            objectCategory,
                                    categoryValue:       objectCategoryValue,
                                    originallyCreatedAt: objectOriginallyCreatedAt,
                                    platform:            objectPlatform,
                                    createdAt:           objectCreatedAt,
                                    updatedAt:           objectUpdatedAt,
                                    dateAdded:           objectDateAdded,
                                }                                
                                    bookmarkArray.push(object)
                                    return bookmarkArray    
                                }
                            }
                        }))

            bookmark = bookmarkArray.sort((a, b) => {
            if(!a.dateAdded || !b.dateAdded) return 0
            const A = a.dateAdded ? new Date(a.dateAdded).getTime() : 0
            const B = b.dateAdded ? new Date(b.dateAdded).getTime() : 0
            return B - A
        })
                            }
                            const totalPosts: number = sortMyBookmark.length
                            const totalPages = Math.ceil(totalPosts / postsPerPage)
                            
                            res.status(200).send({
                                    ok: true,
                                    items: bookmark,
                                    totalPosts: totalPosts,
                                    totalPages: totalPages,})
                } 
        } catch (err) {
            console.log(err);
            let errorMessage = "Failed to do something exceptional"
            if(err instanceof Error) {
                errorMessage = err.message
            }
            res.status(400).send({
                ok: false,
                error: errorMessage
            })
            return  
        }
    }
      
const sendAllPosts = async (req: Request, res: Response) => {
    await Post.find({}, function(err: any, post: PostInterface[]) {
    const modifyedPosts = handlePostItems({postItems: post})
    if (err) {
            res.status(400)
            console.log(err);
            return
    } else {

            res.status(200).send({
                ok: true,
                userPost: modifyedPosts})
    }
  })
}

const sendPostsByPage = async (req: Request, res: Response) => {
    const { currentPage } = req.body
    const postsPerPage = 12
    await Post.find({}, function(err: Error, post: PostInterface[]) {
    if (err) {
        res.status(400)
        console.log(err);
        return
    } else {
        const modifyedPosts = handlePostItems({postItems: post})

        const postSorted = modifyedPosts.sort((a, b) => {return (new Date(b.createdAt as any).valueOf() - new Date(a.createdAt as any).valueOf())})
        const indexOfLastPost = currentPage * postsPerPage;
        const indexOfFirstPost = indexOfLastPost - (postsPerPage);
        const currentPosts: PostInterface[] = postSorted.slice(indexOfFirstPost, indexOfLastPost);
        const totalPosts: number = modifyedPosts.length
        const totalPages = Math.ceil(totalPosts / postsPerPage)

        res.status(200).send({
            ok: true,
            items: currentPosts,
            totalPosts: totalPosts,
            totalPages: totalPages,
        })
    }
  })
}

const sendCategoryPostsByPage = async (req: Request, res: Response) => {
    const { currentPage, categoryValue } = req.body
    const postsPerPage = 12
    await Post.find({categoryValue: categoryValue}, function(err: Error, post: PostInterface[]) {
    if (err) {
        res.status(400)
        console.log(err);
        return
    } else {
        const modifyedPosts = handlePostItems({postItems: post})

        const postSorted = modifyedPosts.sort((a, b) => {return -1 * (new Date(a.createdAt as any).valueOf() - new Date(b.createdAt as any).valueOf())})
        const indexOfLastPost = currentPage * postsPerPage;
        const indexOfFirstPost = indexOfLastPost - (postsPerPage);
        const currentPosts: PostInterface[] = postSorted.slice(indexOfFirstPost, indexOfLastPost);
        const totalPosts: number = modifyedPosts.length
        const totalPages = Math.ceil(totalPosts / postsPerPage)
    
        res.status(200).send({
            ok: true,
            items: currentPosts,
            totalPosts: totalPosts,
            totalPages: totalPages,
        })
    }
  })
}

const sendUserPostsByPage = async (req: Request, res: Response) => {
    const { currentPage, userId} = req.body
    const postsPerPage = 12
    
    await Post.find({authorId: userId}, function(err: Error, post: PostInterface[]) {
    if (err) {
        res.status(400)
        console.log(err);
        return
    } else {
        const modifyedPosts = handlePostItems({postItems: post})

        const postSorted = modifyedPosts.sort((a, b) => {return -1 * (new Date(a.createdAt as any).valueOf() - new Date(b.createdAt as any).valueOf())})
        const indexOfLastPost = currentPage * postsPerPage;
        const indexOfFirstPost = indexOfLastPost - (postsPerPage);
        const currentPosts: PostInterface[] = postSorted.slice(indexOfFirstPost, indexOfLastPost);
        const totalPosts: number = modifyedPosts.length
        const totalPages = Math.ceil(totalPosts / postsPerPage)
        

        res.status(200).send({
            ok: true,
            items: currentPosts,
            totalPosts: totalPosts,
            totalPages: totalPages,
        })
    }
  })
}

const sendAllSharedBookmarks = async (req: Request, res: Response) => {
    await BookmarkItem.find({}, function(err: Error, bookmark: BookmarkItemInterface[]) {
    if (err) {
        res.status(400)
        console.log(err);
        return
    } else {
        res.status(200).send({
            ok: true,
            BookmarkItems: bookmark
        })
    }
  })
}

const sendSharedBookmarksByPage = async (req: Request, res: Response) => {
    const { currentPage } = req.body
    const postsPerPage = 12
    await BookmarkItem.find({}, function(err: Error, bookmark: BookmarkItemInterface[]) {
    if (err) {
        res.status(400)
        console.log(err);
        return
    } else {
        const onlyTrue = bookmark.filter(item =>  item.public === true)
        const bookmarkSorted = onlyTrue.sort((a, b) => {return (new Date(b.createdAt as any).valueOf() - new Date(a.createdAt as any).valueOf())})
        const indexOfLastPost = currentPage * postsPerPage;
        const indexOfFirstPost = indexOfLastPost - (postsPerPage);
        const currentPosts: BookmarkItemInterface[] = bookmarkSorted.slice(indexOfFirstPost, indexOfLastPost);
        const totalPosts: number = onlyTrue.length
        const totalPages = Math.ceil(totalPosts / postsPerPage)

        res.status(200).send({
            ok: true,
            items: currentPosts,
            totalPosts: totalPosts,
            totalPages: totalPages,
        })
    }
  })
}

const sendSharedBookmarksByPageAdmin = async (req: Request, res: Response) => {
    const { currentPage } = req.body
    const postsPerPage = 12
    await BookmarkItem.find({}, function(err: Error, bookmark: BookmarkItemInterface[]) {
    if (err) {
        res.status(400)
        console.log(err);
        return
    } else {
        const bookmarkSorted = bookmark.sort((a, b) => {return (new Date(b.createdAt as any).valueOf() - new Date(a.createdAt as any).valueOf())})
        const indexOfLastPost = currentPage * postsPerPage;
        const indexOfFirstPost = indexOfLastPost - (postsPerPage);
        const currentPosts: BookmarkItemInterface[] = bookmarkSorted.slice(indexOfFirstPost, indexOfLastPost);
        const totalPosts: number = bookmark.length
        const totalPages = Math.ceil(totalPosts / postsPerPage)

        res.status(200).send({
            ok: true,
            items: currentPosts,
            totalPosts: totalPosts,
            totalPages: totalPages,
        })
    }
  })
}

const changePublicStatus = async (req: Request, res: Response) => {
    const { itemId, publicStatus } = req.body
    const newPublicStatus = publicStatus === true ? false : true
    const decodedStatus = res.locals.decodedToken.userStatus

    try {
        if(decodedStatus === "admin"){
            const respone = await BookmarkItem.findByIdAndUpdate(itemId, { public: newPublicStatus }) 
            res.status(200).send({
                ok: true,
            })            
        } else {
            throw new Error("not authorized")
        }        
    } catch (err) {
        console.log(err);
        res.status(400)
    } 
 }

const sendCategorySharedBookmarksByPage = async (req: Request, res: Response) => {
    const { currentPage, categoryValue } = req.body
    const postsPerPage = 12
    await BookmarkItem.find({categoryValue: categoryValue}, function(err: Error, bookmark: BookmarkItemInterface[]) {
    if (err) {
        res.status(400)
        console.log(err);
        return
    } else {
        const bookmarkSorted = bookmark.sort((a, b) => {return -1 * (new Date(a.createdAt as any).valueOf() - new Date(b.createdAt as any).valueOf())})
        const indexOfLastPost = currentPage * postsPerPage;
        const indexOfFirstPost = indexOfLastPost - (postsPerPage);
        const currentPosts: BookmarkItemInterface[] = bookmarkSorted.slice(indexOfFirstPost, indexOfLastPost);
        const totalPosts: number = bookmark.length
        const totalPages = Math.ceil(totalPosts / postsPerPage)

        res.status(200).send({
            ok: true,
            items: currentPosts,
            totalPosts: totalPosts,
            totalPages: totalPages,
        })
    }
  })
}

const sendCategoryPosts = async (req: Request, res: Response) => {
       try {
        const { categoryValue } = req.body
        const posts = await Post.find(
            {categoryValue: categoryValue})
        res.status(200).send({
            ok: true,
            posts: posts})
    } catch (err) {
            res.status(400)
            console.log(err);
            return
    }
}

const sendAllUserIds = async (req: Request, res: Response) => {
    await Post.find({}, function(err: Error, posts: PostInterface[]) {
    if (err) {
      console.log(err);
      return
    } else {
    const x = posts.map(post => post.authorId && post.authorId)
    const userIds = [...new Set(x)]
    res.status(200).send({
        ok: true,
        userIds: userIds
    })
    }
  })
}

const sendUserBookmarkIds = async (req: Request, res: Response) => {
    try {
        const userId = res.locals.decodedToken.userId
        const userBookmarkIds = await returnMyBookmarkIds({ userId: userId})
        res.status(200).send({
            ok: true,
            userBookmarkIds: userBookmarkIds
        })
    } catch (err) {
        res.status(400)
        console.log(err);
        return        
    }
}

const sendAllCategoriesBookmarks = async (req: Request, res: Response) => {
    await BookmarkItem.find({}, function(err: Error, bookmarks: BookmarkItemInterface[]) {
    if (err) {
      console.log(err);
      return
    } else {
        const x = bookmarks.filter(item => item.category && item.category.length > 0)

        const y = x.map(bookmark => bookmark.category)

        let array : any[] = []

        y.map(categoryArray => categoryArray && categoryArray.map((item : any) => array.push(item)))

        const bookmarkCategory = removeDuplicates(array)
        
        const bookmarkCategoryObject = bookmarkCategory.map(
            item => ({  category: item, 
                        categoryValue: toLowerCaseAndConcat(item)
                    })) 
    res.status(200).send({
        ok: true,
        bookmarkCategory: bookmarkCategory, 
        bookmarkCategoryObject: bookmarkCategoryObject
    })
    }
  })
}

const sendAllCategoriesPosts = async (req: Request, res: Response) => {
    await Post.find({}, function(err: Error, posts: PostInterface[]) {
    if (err) {
      console.log(err);
      return
    } else {
    const modifyedPosts = handlePostItems({postItems: posts})

        const x = modifyedPosts.filter(item => item.category && item.category.length > 0)

        const y = x.map(post => post.category)

        let array : any[] = []

        y.map(categoryArray => categoryArray && categoryArray.map((item : any) => array.push(item)))

        const postCategory = removeDuplicates(array)
        
        const postCategoryObject = postCategory.map(
            item => ({  category: item, 
                        categoryValue: toLowerCaseAndConcat(item)
                    })) 
    res.status(200).send({
        ok: true,
        postCategory: postCategory, 
        postCategoryObject: postCategoryObject
    })
    }
  })
}

const sendLoginStatus = async (req: Request, res: Response) => {
    const userId = res.locals.decodedToken.userId
    const loginType = res.locals.decodedToken.loginType
    try {
        const user = await User.findById(userId)
        if(!user){
            throw new Error("can not find user")
        }
        const passwordLogin = user.passwordLogin
        const googleLogin = user.googleLogin
        const createdAt = user.createdAt
        res.status(200).send({
            ok: true,
            passwordLogin: passwordLogin,
            googleLogin: googleLogin,
            loginType: loginType,
            createdAt: createdAt,
        })
    } catch (err) {
        console.log(err);  
    }
}

const nasaSearch = async(req: Request, res: Response) => {
    const { query, currentPage, mediaPreference, sortPreference } = req.body
    const searchNumber = req.cookies.searchNumber ? JSON.parse(req.cookies.searchNumber) : 0
    const refreshToken = req.cookies.jwt ? JSON.parse(req.cookies.jwt) : undefined
    const postsPerPage = 12
    const nasaApiKey = process.env.NASA_API_KEY
    const nasaUrl = process.env.NASA_URL    
        try {
            if(cancelSourceSearch && cancelSourceSearch !== undefined && currentPage === 1){
                cancelSourceSearch.cancel("Canceled due to a new search")
            }
            const source = axios.CancelToken.source()
            cancelSourceSearch = source
                jwt.verify(
                        refreshToken, 
                        refreshSecret, 
                         async (err: any, 
                                decodedToken: any) => {
                                    if(err && searchNumber >= 50){
                                        throw new Error("search number limit")
                                    }
                                    if(decodedToken && searchNumber >= 500){
                                        throw new Error("search number limit loggedin")
                                    }
                                })
            const getHref = async (url: string) => {
                const encodedURI = encodeURI(`${url}?api_key=${nasaApiKey}`);
                const x = await axios.get(`${encodedURI}`);
                const y = await x.data
                return y
            }
            const handleCategory = (item: nasaOriginalDataTwo) => {
                const keywords : string[] = item.data[0].keywords
                const keywordsTwo =  keywords && keywords.map(z => z.includes(",") ? z.split(",") : z).flat()
                const keywordsThree = keywordsTwo && keywordsTwo.map(z => z.includes(";") ? z.split(";") : z).flat()
                return keywordsThree
            }
            const url = `${nasaUrl}${escape(query)}`
            const response = 
            await axios({
                method: 'GET',
                url: url,
                cancelToken: source.token
            })
    
            const x = await response.data.collection.items
            const responseTwo: any[] = await x.filter((item: any) => 
            !item.data[0].description?.toLowerCase().includes("copyright") && 
            !item.data[0].secondary_creator?.toLowerCase().includes("copyright") &&
            !item.data[0].title?.toLowerCase().includes("copyright") &&
            !handleCategory(item)?.some(x => x.toLowerCase().includes("copyright")))
            
            let responseSorted: any[]

            if(mediaPreference === 1){
                responseSorted = responseTwo.filter(item => item.data[0].media_type === "image")
            } else if(mediaPreference === 2){
                responseSorted = responseTwo.filter(item => item.data[0].media_type === "video")

            } else if(mediaPreference === 3){
                responseSorted = responseTwo.filter(item => item.data[0].media_type === "audio")

            } else if(mediaPreference === 4){
                responseSorted = responseTwo.filter(item => 
                    item.data[0].media_type === "image" || item.data[0].media_type === "video")

            } else if(mediaPreference === 5){
                responseSorted = responseTwo.filter(item => 
                    item.data[0].media_type === "image" || item.data[0].media_type === "audio")

            } else if(mediaPreference === 6){
                responseSorted = responseTwo.filter(item => 
                    item.data[0].media_type === "video" || item.data[0].media_type === "audio")
            } else if (mediaPreference === 7){
                responseSorted = responseTwo
            } else {
                responseSorted = responseTwo
            }

            if(sortPreference === true) {
                responseSorted = responseSorted.sort((a, b) => {
                if(!a.data[0].date_created || !b.data[0].date_created) return 0
                const A = a.data[0].date_created ? new Date(a.data[0].date_created).getTime() : 0
                const B = b.data[0].date_created ? new Date(b.data[0].date_created).getTime() : 0
                return B - A
            })
            } else {
                responseSorted = responseSorted.sort((a, b) => {
                if(!a.data[0].date_created || !b.data[0].date_created) return 0
                const A = a.data[0].date_created ? new Date(a.data[0].date_created).getTime() : 0
                const B = b.data[0].date_created ? new Date(b.data[0].date_created).getTime() : 0
                return A - B
            })
            }
                
            const totalPosts: number = responseSorted.length
            const indexOfLastPost = currentPage * postsPerPage;
            const indexOfFirstPost = indexOfLastPost - postsPerPage;
            const currentPosts: nasaOriginalDataTwo[] = responseSorted.slice(indexOfFirstPost, indexOfLastPost);
            const totalPages = Math.ceil(totalPosts / postsPerPage)
    
                let arrayOne: nasaStateDataInterface[] = [] 
                await Promise.all(currentPosts.map(async item => {
                    const x = await getHref(item.href)
                    const imageUrl = x.map((item : any) => item.replace("http:", "https:"))
                    const object: nasaStateDataInterface = {
                        key: item.data[0].nasa_id,
                        dateCreated: item.data[0].date_created,
                        title: item.data[0].title,
                        description: item.data[0].description,
                        keywords: handleCategory(item),
                        mediaType: item.data[0].media_type,
                        href: imageUrl
                    }
                    arrayOne.push(object)
                })).catch(error => {
                    console.error(`error: ${error}`)
                    return
                    });
                const newSearchNumber = searchNumber + 1
                currentPage === 1 && res.setHeader(
                        "Set-Cookie",
                        [
                            cookie.serialize(
                            "searchNumber",
                                JSON.stringify(newSearchNumber), 
                                { 
                                    httpOnly: true,
                                    maxAge: 24 * 60 * 60,
                                    sameSite: "lax",
                                    domain: domain,
                                    path: "/",
                                })
                            ])       
                res.status(200).send({
                    ok: true,
                    nasaStateData: arrayOne,
                    nasaQuery: query,
                    nasaCurrentPage: currentPage,
                    totalPosts: totalPosts,
                    totalPages: totalPages,
                })
        } catch (err: any) {
                    if (axios.isCancel(err)) {
                        console.log("canceled due to a new request: ", err.message);   
                    }
                const errors = await handleErrorsGeneral(err);
                res.status(400).send({errors});
        }
    }

export {            signupPost,
                    signupPostGuest,
                    resendConfirmation,
                    userConfirmation,
                    passwordResetRequest,
                    passwordResetSubmit,
                    loginPost,
                    googleSignupPost,
                    googleLoginPost,
                    enableGoogleSignin,
                    enablePasswordSignin,
                    logoutPost,
                    changePassword,
                    deleteUser,
                    deleteUserGoogle,
                    bookmarkAdd,
                    bookmarkDelete,
                    postPost,
                    updatePost,
                    postPutNoAuth,
                    bookmarkPutNoAuth,
                    postDelete,
                    sharedBookmarkDelete,
                    getOnePostPost,
                    getOneBookmarkPost,
                    sendAllPosts,
                    sendAllSharedBookmarks,
                    sendAllUserIds,
                    nasaSearch,
                    sendAllCategoriesBookmarks,
                    sendAllCategoriesPosts,
                    sendCategoryPosts,
                    sendSharedBookmarksByPage,
                    sendSharedBookmarksByPageAdmin,
                    changePublicStatus,
                    sendCategorySharedBookmarksByPage,
                    sendPostsByPage,
                    sendCategoryPostsByPage,
                    sendUserPostsByPage,
                    sendBookmarkByPage,
                    sendLoginStatus,
                    sendUserBookmarkIds,
                }