import { Document, Model, model, Schema }  from 'mongoose'

export interface PostDocument extends Document {
        _id?:                       string,
        imageId:                    string,
        authorId?:                  string,
        imageTitle?:                string,
        imageUrl:                   string,
        sharedUrl?:                 string,
        imageDescription?:          string,
        like:                       number,
        public?:                    boolean,
        confirm?:                   boolean,
        mediaType?:                 string,
        category?:                  string[],
        categoryValue?:             string[],
        platform:                   string,
        article?:                   string | HTMLTextAreaElement,
        articleTitle?:              string | HTMLInputElement,
        user?:                      string,
        likeStatus?:                boolean,
        originallyCreatedAt?:       Date | string,
        createdAt?:                 Date,
        updatedAt?:                 Date
}

export interface PostModel extends Model<PostDocument>{}

const PostSchema = new Schema({
        authorId:           { type: String},
        imageTitle:              { type: String},
        imageUrl:                { type: String},
        sharedUrl:          { type: String},
        imageDescription:        { type: String},
        category:           {
                                type:[{
                                    type: String
                                }]
                            },
        categoryValue:      {
                                type:[{
                                    type: String
                                }]
                            },
        originallyCreatedAt:{ type: String},
        platform:           { type: String},
        article:            { type: String},
        articleTitle:       { type: String},
        user:               { type: String},
        like:               { type: Number, default: 0 },
        public:             { type: Boolean, default: true},
        confirm:            { type: Boolean, default: false },
        createdAt:          { type: Date, default: Date.now },
        updatedAt:          { type: Date, default: Date.now }
    });

export const Post = model <PostDocument, PostModel>('post', PostSchema);
