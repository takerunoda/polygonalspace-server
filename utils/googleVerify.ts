import { OAuth2Client } from 'google-auth-library';

const clientId = process.env.GOOGLE_LOGIN_CLIENT_ID ?? ""
const client = new OAuth2Client(clientId);

export const googleVerify = async (googleToken: string) => {
    try {
        const ticket = await client.verifyIdToken({
            idToken: googleToken,
            audience: clientId,  
        });
        const payload = ticket.getPayload();
        if(!payload){
            throw new Error("no payload")
        }
        const googleObject = {
            googleId: payload.sub,
            userEmail: payload.email,
            userName: payload.name,
        }
        return googleObject;  
    } catch (err) {
        console.log(err);
    }
}