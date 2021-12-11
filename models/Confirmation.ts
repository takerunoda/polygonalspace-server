import { Document, Model, model, Schema }  from 'mongoose'

export interface ConfirmationDocument extends Document {
        _id?:                   string,
        userId:                 string,
        confirmationToken:      string,
        updatedAt?:             Date,
        // dateAdded?:             Date,
}

export interface ConfirmationModel extends Model<ConfirmationDocument>{}

const confirmationSchema = new Schema({
        userId:         { 
            type: Schema.Types.ObjectId,
            required: true,
         },
        confirmationToken: { 
            type: String,
            required: true,
         },
        createdAt:  { 
            type: Date, default: Date.now, expires: 24 * 60 * 60 },
        // updatedAt:  { 
        //     type: Date, default: Date.now }
    });

export const Confirmation = model <ConfirmationDocument, ConfirmationModel>('confirmation', confirmationSchema);
