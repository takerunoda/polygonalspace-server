import { Document, Model, model, Schema }  from 'mongoose'
import bcrypt from 'bcrypt';

export interface UserDocument extends Document {
    userName?:                          string,
    userEmail:                          string,
    googleId?:                          string,
    password:                           string,
    verified:                           boolean,
    address?:                           string,
    userStatus:                         string,
    passwordLogin:                      boolean,
    googleLogin:                        boolean,
    loginType:                          string,
    createdAt?:                         Date,
    updatedAt?:                         Date,
}

export interface UserModel extends Model<UserDocument> {
    login (userEmail: string, password: string) : any;
}

const UserSchema = new Schema <UserDocument, UserModel>({
    userName: {
        type: String,
    },
    userEmail: {
        type: String,
        required: [true, 'Please enter a userEmail'],
        unique :true,
        lowercase: true,
        // validate: [isEmail, 'Please enter a valid email']
    },
    password: {
        type: String,
        required: [true, 'Please enter a password'],
        minlength: [8, 'Password length must be at least 8 characters']
    }, 
    verified: { 
        type: Boolean, 
        default: false 
    },
    address: {
        type: String,
    }, 
    googleId: {
        type: String,
        unique :true,
        lowercase: true,
    },
    userStatus: { type: String, default: "member" },
    passwordLogin: { type: Boolean, default: "false" },
    googleLogin: { type: Boolean, default: "false" },
    loginType:  { type: String, default: "none" },
    createdAt:  { type: Date, default: Date.now },
    updatedAt:  { type: Date, default: Date.now }

});

//Fire a function before doc saved in database
UserSchema.pre<UserDocument> ('save', async function (next){
    if(this.password){
        const salt = await bcrypt.genSalt();
        this.password = await bcrypt.hash(this.password, salt)
    }
    next();
})


//static method to login user
UserSchema.statics.login = async function(userEmail, password)  {
    const user = await this.findOne({ userEmail });
    if(user) {
        if(!user.password){
            throw new Error('')
        }
        const auth = await bcrypt.compare(password, user.password);
        if(auth){
            if(user.verified){
                return user;
            }
            throw Error('confirmation not completed')
        }
        throw Error('incorrect password')
    }
    throw Error('user does not exist')
}
export const User = model <UserDocument, UserModel>('user', UserSchema);
