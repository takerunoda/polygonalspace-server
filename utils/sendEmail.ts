import sgMail from '@sendgrid/mail';
import { google } from 'googleapis';
import nodemailer from 'nodemailer';

interface ChildProps {
    emailAddress: string
    ipAddress: string
    linkText: string
    language: boolean
}

interface FunctionProps extends ChildProps {
        emailText: ({ emailAddress, ipAddress, linkText, language }: ChildProps) => {
                subject: string
                text: string
                html: string
            }
        }

const clientId = process.env.EMAIL_CLIENT_ID
const clientSecret = process.env.EMAIL_CLIENT_SECRET
const redirectUri = process.env.REDIRECT_URI
const emailRefreshToken = process.env.EMAIL_REFRESH_TOKEN
const transportService = process.env.TRANSPORT_SERVICE
const sender = process.env.EMAIL_SENDER ?? ""
const senderAs = process.env.EMAIL_SENDER_AS ?? ""
const siteName = process.env.SITE_NAME ?? ""

export const sendEmail = async ({emailAddress, ipAddress, linkText, language, emailText} : FunctionProps) => {
            const api = process.env.SENDGRID_API_KEY ?? ""
            sgMail.setApiKey(api)
            const emailObject = emailText({emailAddress, ipAddress, linkText, language})
                try {   const mailOptions = {
                                    from: {
                                        name: siteName,
                                        email: senderAs
                                    },
                                    to: emailAddress,
                                    subject: 
                                    emailObject.subject,
                                    text: 
                                    emailObject.text,
                                    html: 
                                    emailObject.html
                                        }
                    const result = await sgMail.send(mailOptions)
                    return result
                } catch (err: any) {
                    console.log(`sendGrid: err.message: ${err.message}`);
                    if(err){
                            const oAuth2Client = new google.auth.OAuth2(clientId, clientSecret, redirectUri)

                            oAuth2Client.setCredentials({ refresh_token: emailRefreshToken })

                         try {
                            const accessToken =  oAuth2Client.getAccessToken().toString()

                            const transport = nodemailer.createTransport({
                                service: transportService, // no need to set host or port etc.
                                auth: {
                                    type: "OAuth2",
                                    user: sender,
                                    clientId: clientId,
                                    clientSecret: clientSecret,
                                    refreshToken: emailRefreshToken,
                                    accessToken: accessToken
                                }
                            });

                            const mailOptions = {
                                from: {
                                    name: siteName,
                                    address: senderAs
                                },
                                to: emailAddress,
                                subject: 
                                emailObject.subject,
                                text: 
                                emailObject.text,
                                html: 
                                emailObject.html
                            }

                            const result = await transport.sendMail(mailOptions)
                            console.log("Sent by Google")
                            return result
                            
                        } catch (err: any) {
                            if(err){
                                console.log(`Google: err.message: ${err.message}`);
                                throw new Error("sendingEmailFailed")
                            }
                        }
                     }
                }
            }