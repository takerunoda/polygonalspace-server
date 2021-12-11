import { MyBookmarkInterface, UserBookmarkInterface } from "../Interfaces"
import { MyBookmark } from "../models/MyBookmark"

interface FunctionProps {
    userId: string
}
export const findMyBookmark = async ({userId} : FunctionProps) => {
                    let bookmarkTable
                      const  bookmarkTable_A = await MyBookmark.findOne({ userId: userId })
                        if(bookmarkTable_A){
                            bookmarkTable = bookmarkTable_A
                        } else {
                            const myBookmarkArray: UserBookmarkInterface[] = []
                            const bookmarkTable_B: MyBookmarkInterface = 
                                await MyBookmark.create({ 
                                    userId: userId, 
                                    bookmark: myBookmarkArray
                                })
                                bookmarkTable = bookmarkTable_B
                         }
                        const myBookmark = bookmarkTable.bookmark
                        return myBookmark
}