//handle errors
export const handleErrors = (err: any) => { 
    let errors: any
    errors = { userEmail: '', password: '' };
    //incorrect userEmail or password (for Login)
    if(err.message === "user does not exist") {
        errors.userEmail = 'userNotExist' 
    }
    if(err.message === "incorrect password") {
        errors.password = 'incorrectPassword' 
    }
    if(err.message === "account number limit") {
        errors.userEmail ="accountNumberLimit"
    }
    if(err.message === "not an email address") {
        errors.userEmail ="invalidEmailAddress"
    }
    if(err.message === "confirmation not completed") {
        errors.userEmail ="confirmationNotCompleted"
    }
    if(err.message === "emails do not match") {
        errors.userEmail ="emailsDoNotMatch"
    }
    if(err.message === "passwords do not match") {
        errors.password ="passwordsDoNotMatch"
    }
    if(err.message === "password length") {
        errors.password ="passwordLength"
    }
    if(err.message === "password user exists") {
        errors.userEmail ="passowrdUserExists"
    }
    if(err.message === "not signed up google") {
            errors.userEmail ="notSignedUpGoogle"
    }
    if(err.message === "update in mypage") {
        errors.userEmail ="updateInMypage"
    }
    if(err.message === "update in mypage for google") {
        errors.userEmail ="updateInMypageForGoogle"
    }
    if(err.message === "emails do not match google") {
        errors.userEmail ="emailsDoNotMatchGoogle"
    }
    if(err.message === "google not verified") {
        errors.userEmail ="googleNotVerified"
    }
    if(err.message === "password login not set") {
        errors.userEmail ="passwordLoginNotSet"
    }            
    if(err.message === "sendingEmailFailed") {
        errors.userEmail ="sendingEmailFailed"
    }            
    //duplicate userEmail error
    if(err.code === 11000) {
        errors.userEmail = 'userExists'
    }
    //validation errors
    // err.errors is a bunch of objects, which need to be converted into an array, an array with bunch of objects, then circled through with forEach loop.
    if(err.message.includes('user validation failed')) {
        (Object.values(err.errors) as any[])
        .forEach(({ properties}) => 
        {
            (errors[properties.path]) = properties.message
        })
    }
    return errors;
} 

