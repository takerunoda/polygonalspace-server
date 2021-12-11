export interface PostInterface {
        _id?:                   string,
        imageId:                string,
        authorId?:              string,
        imageTitle?:             string,
        imageUrl:               string,
        sharedUrl?:             string,
        imageDescription?:       string,
        like:                  number,
        public?:                boolean,
        confirm?:               boolean,
        mediaType?:             string,
        category?:              string[],
        categoryValue?:         string[],
        platform:               string,
        article?:               string | HTMLTextAreaElement,
        articleTitle?:          string | HTMLInputElement,
        user?:                  string,
        likeStatus?:            boolean,
        originallyCreatedAt?:   Date | string,
        createdAt?:             Date,
        updatedAt?:             Date
}


export interface BookmarkItemInterface {
        _id?:                   string,
        imageId:                string,
        imageTitle:             string,
        imageUrl:               string,
        imageDescription:       string,
        comment?:               string,
        like:                  number,
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

export interface ImageInterface {
        _id?:                   string,
        imageId:                string,
        imageTitle:             string,
        imageUrl:               string,
        imageDescription:       string,
        comment?:               string,
        confirm?:               boolean,
        mediaType?:             string,
        category?:              string[],
        categoryValue?:         string[],
        originallyCreatedAt?:   Date | string,
        platform:               string,
        createdAt?:             Date,
        updatedAt?:             Date
}

export interface UserInterface {
        _id?:                   string,
        userName?:              string,
        userEmail:              string,
        googleId?:              string,
        password:               string,
        verified:               boolean,
        address?:               string,
        userStatus:             string,
        passwordLogin:          boolean,
        googleLogin:            boolean,
        loginType:              string,
        createdAt?:             Date,
        updatedAt?:             Date,
}

export interface GoogleUserInterface {
        _id?:                   string,
        userName?:              string,
        userEmail:              string,
        googleId:               string,
        address?:               string,
        userStatus:             string,
        loginType:              string,
        createdAt?:             Date,
        updatedAt?:             Date
}

 export interface GuestInterface{
        _id?:                   string,
        userName?:              string,
        userEmail:              string,
        address?:               string,
        userStatus:             string,
        loginType:              string,
        passwordLogin:          boolean,
        googleLogin:            boolean,
        createdAt?:             Date,
        updatedAt?:             Date,
}


export interface UserBookmarkInterface {
        bookmarkId:             string
        createdAt?:             Date,
        // updatedAt?:             Date
}

export interface MyBookmarkInterface {
        _id?:                   string,
        userId:                 string,
        // bookmarkNumber:         number, 
        // full:                   boolean, 
        bookmark:               UserBookmarkInterface[]
}


export interface DraftInterface {
        id:                      string,
        title:                   string,
        url:                     string,
        sharedUrl?:              string,
        description:             string,
        platform:                string,
        category?:               string[],
        categoryValue?:          string[],
        originallyCreatedAt?:   Date | string,
}

export interface nasaOriginalDataOne {
    nasa_id: string,
    date_created: Date | string,
    title: string,
    description: string,
    keywords:    string[],
    media_type:string,

}

export interface nasaOriginalDataTwo { 
    data: nasaOriginalDataOne[],
    href: string
}


export interface nasaDataInterface { 
    key:                         string,
    dateCreated:                 Date | string,
    title:                       string,
    description:                 string,
    keywords:                    string[],
    mediaType:                   string
}

export interface nasaStateDataInterface extends nasaDataInterface{ 
    href:                         any,
}


export interface NASAMyBookmakData {
        'AVAIL:Title':          string,
        'AVAIL:Description':    string,
        'AVAIL:MediaType':      string,
        'AVAIL:Keywords':       string[],
        'AVAIL:DateCreated':    string,
}


export interface ConfirmationInterface {
        _id?:                   string,
        userId:                 string,
        confirmationToken:      string,
        updatedAt?:             Date,
        // dateAdded?:             Date,
}

export interface PasswordResetInterface {
        _id?:                   string,
        userId:                 string,
        userEmail:              string,
        passwordResetToken:     string,
        updatedAt?:             Date,
        dateAdded?:             Date,
}