import { Document, Model, model, Schema }  from 'mongoose'

export interface GuestDocument extends Document {
        _id?:                   string,
        userName?:              string,
        userEmail:              string,
        address?:               string,
        userStatus:             string,
        loginType:              string,
        passwordLogin:          boolean,
        googleLogin:            boolean,
        createdAt?:             Date,
        updatedAt?:             Date,
}

export interface GuestModel extends Model<GuestDocument>{}

const GuestSchema = new Schema <GuestDocument, GuestModel>({
    userName: {
        type: String,
    },
    userEmail: {
        type: String,
        required: true,
        unique :true,
        lowercase: true,
    },
    address: {
        type: String,
    }, 
    userStatus: { type: String, default: "guest" },
    loginType:  { type: String, default: "guest" },
    passwordLogin: { type: Boolean, default: "false" },
    googleLogin: { type: Boolean, default: "false" },
    createdAt:  { type: Date, default: Date.now, expires: 60 * 60 },
    updatedAt:  { type: Date, default: Date.now }

});

export const Guest = model <GuestDocument, GuestModel>('guest', GuestSchema);
