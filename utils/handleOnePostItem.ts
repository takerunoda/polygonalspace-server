import { PostInterface } from "../Interfaces"
import { PostDocument } from "../models/Post"

interface FunctionProps {
    onePost: PostInterface | PostDocument;
}

export const handleOnePost = ({onePost: post} : FunctionProps) => {
        const object = {
            _id:                   post._id ?? "",
            imageId:               post.imageId,
            authorId:              post.authorId ?? "",
            imageTitle:            post.imageTitle ?? "",
            imageUrl:              post.imageUrl,
            sharedUrl:             post.sharedUrl ?? undefined,
            imageDescription:      post.imageDescription ?? "",
            like:                  post.like,
            public:                post.public ?? undefined,
            confirm:               post.confirm ?? undefined,
            mediaType:             post.mediaType ?? "",
            category:              post.category ?? [],
            categoryValue:         post.categoryValue ?? [],
            platform:              post.platform,
            article:               post.article ?? "",
            articleTitle:          post.articleTitle ?? "",
            user:                  "",
            likeStatus:            post.likeStatus ?? undefined,
            originallyCreatedAt:   post.originallyCreatedAt ?? undefined,
            createdAt:             post.createdAt ?? undefined,
            updatedAt:             post.updatedAt ?? undefined,
        }
        return object
}