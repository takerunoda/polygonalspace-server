import { MyBookmarkInterface, UserBookmarkInterface } from "../Interfaces"
import { MyBookmark } from "../models/MyBookmark"

interface FunctionProps {
    userId: string
}

export const returnMyBookmarks = async ({userId} : FunctionProps) => {
        const countMyBookmark =  await MyBookmark.countDocuments({ userId: userId })
        if(countMyBookmark === 0){
        const newBookmarkTable: MyBookmarkInterface 
        = await MyBookmark.create({ 
            userId: userId, 
            bookmark: []})
        }
        const myBookmarkObject = await MyBookmark.findOne({userId: userId})
        const myBookmark = myBookmarkObject && myBookmarkObject.bookmark
        return myBookmark
    }