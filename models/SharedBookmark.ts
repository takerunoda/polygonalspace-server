import { model, Schema }  from 'mongoose'

const SharedBookmarkSchema = new Schema({
        id:         { 
            type: String,
         },
        authorId:         { 
            type: String,
         },
        title:      { 
            type: String,
         },
        url:        { 
            type: String,
         },
        description:{ 
            type: String,
         },
        category: {
            type:[{
                type: String
            }]
        },
        categoryValue: {
            type:[{
                type: String
            }]
        },
        originallyCreatedAt:{ 
            type: Date,
         },
        platform:   { 
            type: String,
         },
        user:       { 
            type: String,
         },
        like:       { 
            type: Number,
         },
        confirm:         { 
            type: Boolean, default: false },
        createdAt:  { 
            type: String, default: Date.now },
        updatedAt:  { 
            type: String, default: Date.now }

    });

export const SharedBookmark = model('bookmark', SharedBookmarkSchema);