import { Document, Model, model, Schema }  from 'mongoose'

export interface BookmarkItemDocument extends Document {
        _id?:                   string,
        imageId:                string,
        imageTitle:             string,
        imageUrl:               string,
        imageDescription:       string,
        comment?:               string,
        like:                   number,
        public?:                boolean,
        confirm?:               boolean,
        mediaType?:             string,
        category?:              string[],
        categoryValue?:         string[],
        platform:               string,
        likeStatus?:            boolean,
        originallyCreatedAt?:   Date | string,
        createdAt?:             Date,
        updatedAt?:             Date,
        dateAdded?:             Date,
      }

export interface BookmarkItemModel extends Model<BookmarkItemDocument>{}

const BookmarkItemSchema = new Schema({
            imageId:             { type: String },
            imageTitle:          { type: String },
            imageUrl:            { type: String },
            imageDescription:    { type: String },
            comment:             { type: String },
            like:                { type: Number, default: 0 },
            public:              { type: Boolean, default: false},
            confirm:             { type: Boolean, default: false },
            mediaType:           { type: String },
            category:            {
                                    type:[{
                                            type: String
                                          }]
                                        },
            categoryValue:       {
                                    type:[{
                                            type: String
                                          }]
                                        },
            originallyCreatedAt: { type: String },
            platform:            { type: String },
            createdAt:           { type: Date, default: Date.now },
            updatedAt:           { type: Date, default: Date.now }
});

export const BookmarkItem = model <BookmarkItemDocument, BookmarkItemModel>('bookmarkitem', BookmarkItemSchema);
