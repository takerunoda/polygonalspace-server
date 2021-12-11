import { Router } from "express";
import {signupPost,
        signupPostGuest,
        resendConfirmation,
        userConfirmation,
        loginPost,
        googleLoginPost,
        logoutPost,
        deleteUser,
        deleteUserGoogle,
        postPost,
        getOnePostPost,
        postDelete,
        postPutNoAuth,
        getOneBookmarkPost,
        sharedBookmarkDelete,
        bookmarkPutNoAuth,
        bookmarkAdd,
        bookmarkDelete,
        sendAllPosts,
        sendAllSharedBookmarks,
        sendAllUserIds,
        nasaSearch,
        sendAllCategoriesBookmarks,
        sendAllCategoriesPosts,
        sendCategoryPosts,
        passwordResetRequest,
        passwordResetSubmit,
        sendSharedBookmarksByPage,
        sendPostsByPage,
        sendCategorySharedBookmarksByPage,
        sendCategoryPostsByPage,
        sendUserPostsByPage,
        sendBookmarkByPage,
        changePassword,
        sendSharedBookmarksByPageAdmin,
        changePublicStatus,
        googleSignupPost,
        enableGoogleSignin,
        sendLoginStatus,
        enablePasswordSignin,
        sendUserBookmarkIds,
        updatePost,
        } from "../controllers/controller";
        
import { 
        verifyAccessToken, 
        sendNewAccessToken,
       } from '../middleware/authMiddleware';
import { data, login, nasa } from "../utils/urls";
import { enable_password_singin } from "../utils/urls";
import { send_login_status } from "../utils/urls";
import { google_login_post } from "../utils/urls";
import { logout } from "../utils/urls";
import { delete_account_google } from "../utils/urls";
import { send_userbookmark_ids } from "../utils/urls";
import { send_posts_by_page } from "../utils/urls";
import { send_user_posts_by_page } from "../utils/urls";
import { verify_access_token_delete_post } from "../utils/urls";
import { post_update_no_auth } from "../utils/urls";
import { send_category_posts } from "../utils/urls";
import { send_shared_bookmarks_by_page } from "../utils/urls";
import { change_public_status } from "../utils/urls";
import { verify_access_token_delete_shared_bookmark } from "../utils/urls";
import { my_bookmark_delete } from "../utils/urls";
import { bookmark_update_no_auth } from "../utils/urls";
import { verify_access_token_send_bookmark_by_page } from "../utils/urls";
import { send_all_category_bookmarks } from "../utils/urls";
import { get_one_bookmark_post } from "../utils/urls";
import { my_bookmark_add } from "../utils/urls";
import { send_category_sharedbookmarks_by_page } from "../utils/urls";
import { send_shared_bookmarks_by_page_admin } from "../utils/urls";
import { send_all_shared_bookmarks } from "../utils/urls";
import { send_all_category_posts } from "../utils/urls";
import { get_one_post_post } from "../utils/urls";
import { post } from "../utils/urls";
import { update_post } from "../utils/urls";
import { send_category_posts_by_page } from "../utils/urls";
import { send_all_posts } from "../utils/urls";
import { send_all_userIds } from "../utils/urls";
import { access_token } from "../utils/urls";
import { delete_account } from "../utils/urls";
import { guest_login } from "../utils/urls";
import { google_signup_post } from "../utils/urls";
import { enable_google_signin } from "../utils/urls";
import { change_password } from "../utils/urls";
import { password_reset_submit } from "../utils/urls";
import { confirmation } from "../utils/urls";
import { password_reset_request } from "../utils/urls";
import { resend_confirmation } from "../utils/urls";
import { signup } from "../utils/urls";

       export const mainRoutes = Router();
       
//Authentication
mainRoutes.post(`/${signup}`, signupPost)

mainRoutes.post(`/${resend_confirmation}`, resendConfirmation)

mainRoutes.post(`/${confirmation}/:id/:token`, userConfirmation)

mainRoutes.post(`/${password_reset_request}`, passwordResetRequest)

mainRoutes.put(`/${password_reset_submit}`, passwordResetSubmit)

mainRoutes.post(`/${login}`, loginPost)

mainRoutes.post(`/${change_password}`, verifyAccessToken, changePassword)

mainRoutes.post(`/${enable_password_singin}`, verifyAccessToken, enablePasswordSignin)

mainRoutes.post(`/${enable_google_signin}`, verifyAccessToken, enableGoogleSignin)

mainRoutes.post(`/${send_login_status}`, verifyAccessToken, sendLoginStatus)

mainRoutes.post(`/${google_signup_post}`, googleSignupPost)

mainRoutes.post(`/${google_login_post}`, googleLoginPost)

mainRoutes.post(`/${guest_login}`, signupPostGuest)

mainRoutes.post(`/${logout}`, logoutPost)

mainRoutes.delete(`/${delete_account}`, verifyAccessToken, deleteUser)

mainRoutes.delete(`/${delete_account_google}`, verifyAccessToken, deleteUserGoogle)



//Access Token
mainRoutes.post(`/${access_token}`, sendNewAccessToken)

//User Data
mainRoutes.post(`/${send_all_userIds}`, sendAllUserIds)

mainRoutes.post(`/${send_userbookmark_ids}`, verifyAccessToken, sendUserBookmarkIds)

//Post
mainRoutes.post(`/${send_all_posts}`, sendAllPosts)

mainRoutes.post(`/${send_posts_by_page}`, sendPostsByPage)

mainRoutes.post(`/${send_category_posts_by_page}`, sendCategoryPostsByPage)

mainRoutes.post(`/${send_user_posts_by_page}`, sendUserPostsByPage)

mainRoutes.post(`/${post}`, verifyAccessToken, postPost)

mainRoutes.post(`/${update_post}`, verifyAccessToken, updatePost)

mainRoutes.delete(`/${verify_access_token_delete_post}`, verifyAccessToken, postDelete)

mainRoutes.post(`/${get_one_post_post}`, getOnePostPost)

mainRoutes.put(`/${post_update_no_auth}`, postPutNoAuth)

mainRoutes.post(`/${send_all_category_posts}`, sendAllCategoriesPosts)

mainRoutes.post(`/${send_category_posts}`, sendCategoryPosts)


//Shared Bookmark
mainRoutes.post(`/${send_all_shared_bookmarks}`, sendAllSharedBookmarks)

mainRoutes.post(`/${send_shared_bookmarks_by_page}`, sendSharedBookmarksByPage)

//***** */
mainRoutes.post(`/${send_shared_bookmarks_by_page_admin}`, sendSharedBookmarksByPageAdmin)

mainRoutes.post(`/${change_public_status}`, verifyAccessToken, changePublicStatus)

mainRoutes.post(`/${send_category_sharedbookmarks_by_page}`, sendCategorySharedBookmarksByPage)

mainRoutes.delete(`/${verify_access_token_delete_shared_bookmark}`, verifyAccessToken, sharedBookmarkDelete)

mainRoutes.put(`/${my_bookmark_add}`, verifyAccessToken, bookmarkAdd)

mainRoutes.put(`/${my_bookmark_delete}`, verifyAccessToken, bookmarkDelete)

mainRoutes.post(`/${get_one_bookmark_post}`, getOneBookmarkPost)

mainRoutes.put(`/${bookmark_update_no_auth}`, bookmarkPutNoAuth)

mainRoutes.post(`/${send_all_category_bookmarks}`, sendAllCategoriesBookmarks)


//My Bookmark
mainRoutes.post(`/${verify_access_token_send_bookmark_by_page}`, verifyAccessToken, sendBookmarkByPage)

//NASA API
mainRoutes.post(`/${nasa}/${data}`, nasaSearch)
