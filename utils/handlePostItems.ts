import { PostInterface } from "../Interfaces"

interface FunctionProps {
    postItems: PostInterface[];
}

export const handlePostItems = ({postItems: postItems} : FunctionProps) => {
    let array: PostInterface[] = [] 
    postItems.filter(x => x.public === true).map(item =>  {
        const object = {
            _id:                   item._id ?? "",
            imageId:               item.imageId,
            authorId:              item.authorId ?? "",
            imageTitle:            item.imageTitle ?? "",
            imageUrl:              item.imageUrl,
            sharedUrl:             item.sharedUrl ?? undefined,
            imageDescription:      item.imageDescription ?? "",
            like:                  item.like,
            public:                item.public ?? undefined,
            confirm:               item.confirm ?? undefined,
            mediaType:             item.mediaType ?? "",
            category:              item.category ?? [],
            categoryValue:         item.categoryValue ?? [],
            platform:              item.platform,
            article:               item.article ?? "",
            articleTitle:          item.articleTitle ?? "",
            user:                  "",
            likeStatus:            item.likeStatus ?? undefined,
            originallyCreatedAt:   item.originallyCreatedAt ?? undefined,
            createdAt:             item.createdAt ?? undefined,
            updatedAt:             item.updatedAt ?? undefined,
        }
            array.push(object)
        }
    )
    return array
}