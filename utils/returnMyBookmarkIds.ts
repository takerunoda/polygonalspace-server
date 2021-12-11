// import { MyBookmarkInterface, UserBookmarkInterface } from "../Interfaces"
import { MyBookmark } from "../models/MyBookmark"

interface FunctionProps {
    userId: string
}

export const returnMyBookmarkIds = async ({userId} : FunctionProps) => {
        const myBookmarkObject = await MyBookmark.findOne({userId: userId})
        const myBookmark = myBookmarkObject && myBookmarkObject.bookmark
        const userBookmarkIds = myBookmark && myBookmark.map(item => item.bookmarkId)        
        return userBookmarkIds
}