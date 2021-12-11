interface FunctionProps {
    emailAddress: string
    ipAddress: string
    linkText: string
    language: boolean
}

const corsOrigin =  process.env.CORS_ORIGIN
const style = `<head>
                    <style>
                        * {
                            list-style-type: none;
                        }
                        ul, li {
                            margin: 0;
                            padding: 0;
                        }
                        .siteTitle:hover {
                            opacity:0.8;
                        }
                        .siteTitle img {
                            width: 200px;
                        }
                        .completeSignup {
                            margin-top:30px;
                        }
                        .completeSignup:hover {
                            opacity:0.8;
                        }
                        .ipTitle {
                            color: green;
                        }
                        .ipAddress {
                            color: blue;
                            padding-left:80px;
                        }
                    </style>
                </head>`


export const emailTextSignup = ({emailAddress, linkText, language, ipAddress} : FunctionProps) => {
    return {
        subject: language ? 
        "ユーザー登録の確認メール " : 
        "Email Address Confirmation ",
        text: language ? 
        `ユーザー登録を受け付けました。 &#13;&#10; メールアドレス: ${emailAddress} &#13;&#10; IP アドレス: ${ipAddress}  &#13;&#10; 以下のリンクをクリックすると登録が完了します。 &#13;&#10; ${linkText}` :
        `Request has been sent for account registration. &#13;&#10; Email Address: ${emailAddress} &#13;&#10; IP Address: ${ipAddress}  &#13;&#10; Please complete signup by clicking the link below. &#13;&#10; ${linkText}`,
        html: language ? 
                `${style}
                <div class="siteTitle">
                    <a href="${corsOrigin}">
                        <img src="${corsOrigin}/siteTitle.png" />
                    </a>
                </div>
                <div class="">
                    <p>ユーザー登録を受け付けました。 </p>
                </div> 
                <div style="margin-top:20px;margin-bottom:30px;">
                    <p style="color: green;">
                        メールアドレス: ${emailAddress}
                    </p>
                    <ul>
                        <li class="ipTitle">
                        リクエストしたデバイスのIPアドレス: 
                        </li>
                        <li class="ipAddress">
                            ${ipAddress}
                        </li>
                    </ul>
                    <p style="font-weight:bold; margin-bottom: 30px;">下のボタンをクリックすると登録が完了します 🚀✨</p>
                </div>
                <div class="completeSignup">
                   <a style="color:white; background-color:rgba(16, 185, 129); width:8rem; border-radius: 0.25rem; cursor:pointer; padding:1rem; font-size: 0.75rem; outline: 1px solid transparent; outline-offset: 1px; text-decoration:none; font-weight:bold;" href="${linkText}">
                       ユーザー登録を完了する
                    </a>
                </div>
                <div style="color: gray; margin-top:30px;margin-bottom:30px;">
                    リンクの有効期間は48時間です。期間経過後は、ログインページから確認メールを再度リクエストください。
                </div>
                ` : 
                `${style}
                <div class="siteTitle">
                    <a href="${corsOrigin}">
                        <img src="${corsOrigin}/siteTitle.png" />
                    </a>
                </div>
                <div class="">
                   <p>This is an automatic reply based on your signup request.</p> 
                </div> 
                <div style="margin-top:20px;margin-bottom:30px;">
                    <p style="color: green;">
                        Email Address: ${emailAddress}
                    </p>
                    <ul>
                        <li class="ipTitle">
                        This request was made from the device with IP Address of: 
                        </li>
                        <li class="ipAddress">
                            ${ipAddress}
                        </li>
                    </ul>
                   <p style="font-weight:bold; margin-bottom: 30px;">Click the button below for verification 🚀✨</p>
                </div>
                <div class="completeSignup">
                    <a style="color:white; background-color:rgba(16, 185, 129); width:8rem; border-radius: 0.25rem; cursor:pointer; padding:1rem; font-size: 0.75rem; outline: 1px solid transparent; outline-offset: 1px; text-decoration:none; font-weight:bold;" href="${linkText}">
                        Complete Signup
                    </a>
                </div>
                <div style="color: gray; margin-top:30px;margin-bottom:30px;">
                    This link will be active for 48 hours. After that, you will need to make another request.
                </div>
                `                
    }
}

export const emailTextPasswordReset= ({emailAddress, linkText, language, ipAddress} : FunctionProps) => {
    return {
            subject: language ? "パスワード再設定を受け付けました" : "Password Reset",
            text: language ? 
            `パスワード再設定のリクエストを受け付けました。 &#13;&#10; メールアドレス: ${emailAddress} &#13;&#10; IP アドレス: ${ipAddress}  &#13;&#10; 以下のリンク先にアクセスすると、パスワードリセット画面が表示されます 🚀✨ &#13;&#10; ${linkText}` :
            `We received your password reset request. &#13;&#10; email: ${emailAddress} &#13;&#10; IP Address: ${ipAddress}  &#13;&#10; Please click the link below to proceed 🚀✨ &#13;&#10; ${linkText}`,
            html: language ? 
                `${style}
                <div class="siteTitle">
                    <a href="${corsOrigin}">
                        <img src="${corsOrigin}/siteTitle.png" />
                    </a>
                </div>
                    <div>
                        <p>パスワード再設定のリクエストを受け付けました。</p> 
                        <p>以下のリンク先にアクセスすると、パスワードリセット画面が表示されます 🚀✨</p> 
                    </div> 
                <div style="margin-top:20px;margin-bottom:30px;">
                    <p style="color: green;">
                        メールアドレス: ${emailAddress}
                    </p>
                    <ul>
                        <li class="ipTitle">
                            リクエストしたデバイスのIPアドレス:
                        </li>
                        <li class="ipAddress">
                            ${ipAddress}
                        </li>
                    </ul>
                </div>
                <div clss="completeSignup">
                    <a style="color:white; background-color:rgba(16, 185, 129); width:8rem; border-radius: 0.25rem; cursor:pointer; padding:1rem; font-size: 0.75rem; outline: 1px solid transparent; outline-offset: 1px; text-decoration:none; font-weight:bold;" href="${linkText}">
                            パスワードの再設定
                        </a>
                    </div>
                   <div style="color: gray; margin-top:30px;margin-bottom:30px;">
                        リンクの有効期間は10分間です。
                    </div>
                    ` : 
                `${style}
                    <div class="siteTitle">
                        <a href="${corsOrigin}">
                            <img src="${corsOrigin}/siteTitle.png" />
                        </a>
                    </div>
                    <div>
                        <p>This is an automatic reply based on your request.</p> 
                        <p>Please click the link below to proceed 🚀✨</p>
                    </div> 
                <div style="margin-top:20px;margin-bottom:30px;">
                    <p style="color: green;">
                        Email Address: ${emailAddress}
                    </p>
                    <ul>
                        <li class="ipTitle">
                        This request was made from the device with IP Address of: 
                        </li>
                        <li class="ipAddress">
                            ${ipAddress}
                        </li>
                    </ul>
                </div>
                <div clss="completeSignup">
                    <a style="color:white; background-color:rgba(16, 185, 129); width:8rem; border-radius: 0.25rem; cursor:pointer; padding:1rem; font-size: 0.75rem; outline: 1px solid transparent; outline-offset: 1px; text-decoration:none; font-weight:bold;" href="${linkText}">
                            Update Your Password
                        </a>
                    </div>
                    <div style="color: gray; margin-top:30px;margin-bottom:30px;">
                        This link will be active for 10 minutes. After that you will need to make another request.
                    </div>
                    `                    
    }
}