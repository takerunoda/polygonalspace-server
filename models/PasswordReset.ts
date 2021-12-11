import { Document, Model, model, Schema }  from 'mongoose'

export interface PasswordResetDocument extends Document {
        _id?:                   string,
        userId:                 string,
        userEmail:              string,
        passwordResetToken:     string,
        updatedAt?:             Date,
        dateAdded?:             Date,
}

export interface PasswordResetModel extends Model<PasswordResetDocument>{}

const PasswordResetSchema = new Schema({
        userId:         { 
            type: Schema.Types.ObjectId,
            required: true,
         },
        userEmail:         { 
            type: String,
            required: true,
         },
        passwordResetToken: { 
            type: String,
            required: true,
         },
        createdAt:  { 
            type: Date, default: Date.now, expires: 10 * 60 },
        updatedAt:  { 
            type: Date, default: Date.now }
    });

export const PasswordReset = model <PasswordResetDocument, PasswordResetModel>('passwordreset', PasswordResetSchema);
