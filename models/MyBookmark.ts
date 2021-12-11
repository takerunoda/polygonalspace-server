import { Document, Model, model, Schema }  from 'mongoose'
import { UserBookmarkInterface } from '../Interfaces';

export interface MyBookmarkDocument extends Document {
        _id?:                   string,
        userId:                 string,
        bookmark:               UserBookmarkInterface[]
}

export interface MyBookmarkModel extends Model<MyBookmarkDocument>{}

const MyBookmarkSchema = new Schema <MyBookmarkDocument, MyBookmarkModel>({
    userId:                 { type: String },
    bookmark: {
            type:[{
                bookmarkId: { type: String },
                createdAt:  { type: Date, default: Date.now },
                // updatedAt:  { type: Date, default: Date.now }
            }]
    },
    });

export const MyBookmark = model <MyBookmarkDocument, MyBookmarkModel>('mybookmark', MyBookmarkSchema);