//handle errors
export const handleErrorsGeneral = (err: any) => { 
    console.log(`***${err}`);
    console.log(`***${err.message}`);
    
    let errors: any

    if(err.message === "search number limit") {
        console.log("searchNumber");        
        errors ="searchNumber"
    }
    if(err.message === "search number limit loggedin") {
        console.log("searchNumberLoggedin");        
        errors ="searchNumberLoggedin"
    }
    if(err.message === "already bookmarked") {
        errors = 'alreadyBookmarked' 
    }
    if(err.message === "user already verified") {
        errors = 'alreadyVerified' 
    }
    if(err.message === "user does not exist") {
        errors = 'userDoesNotExist' 
    }

    return errors;
} 

