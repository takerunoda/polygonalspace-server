
interface FunctionProps {
    item: string[]
    mediaType: string
    imageUrl: string
}

export const handleMediaType = ({item , mediaType, imageUrl} : FunctionProps) => {
        let url
        if(item.includes(imageUrl)){
          url = imageUrl
        } else if (mediaType === "image"){
          url = item[1]
        } else if (mediaType === "video" && item[1].endsWith("jpg")) {
            url = item[1]
        } else if (mediaType === "video" && item[0].endsWith("mp4")) {
            url = item[0]
        } else if (mediaType === "video" && item[0].endsWith("mov")) {
            url = item[0]
        } else if (mediaType === "audio") {
            url = item[0]
        } else {
            url = item[1]
        }
        return url
    }        
