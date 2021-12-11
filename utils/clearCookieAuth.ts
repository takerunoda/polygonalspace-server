import { Response } from "express";

interface FunctionProps {
    res: Response
}

export const clearCookieAuth = ({res} : FunctionProps) => {
        const domain =          process.env.NODE_ENV === "production" ? 
                                process.env.DOMAIN : process.env.DOMAIN_2
               res.clearCookie(
               "jwt",
                { 
                    httpOnly: true,
                    sameSite: "lax",
                    domain: domain,
                    path: "/",
                }),
               res.clearCookie(
               "accessToken",
                { 
                    httpOnly: true,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "accessToken",
                { 
                    httpOnly: true,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "isLoggedin",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "userStatus",
                { 
                    httpOnly: true,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "loginType",
                { 
                    httpOnly: true,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "userId",
                { 
                    // httpOnly: true,
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "userEmail",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "loginType",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "userBookmarkIds",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                }),
               res.clearCookie(
               "currentPagePost",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "currentPagePostCategory",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "currentPagePostUser",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "currentPageShared",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "currentPageSharedCategory",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "currentPageSharedUser",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "prevePagePath",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "currentPageMyBookmark",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "searchTotalPages",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "postScroll",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "sharedScroll",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "sharedCategoryScroll",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "searchCurrentPage",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "totalPagesMyBookmark",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "totalPagesPostUser",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "myBookmarkScroll",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "totalPagesSharedCategory",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "nasaSearchScroll",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
               res.clearCookie(
               "prevePageDetails",
                { 
                    sameSite: "lax",
                    domain: domain,
                    path: "/"
                })
                //Google
               res.clearCookie(
               "SAPISID")
               res.clearCookie(
               "APISID")
}