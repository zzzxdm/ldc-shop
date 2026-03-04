import NextAuth from "next-auth"

export const { handlers, signIn, signOut, auth } = NextAuth({
    providers: [
        {
            id: "linuxdo",
            name: "Linux DO",
            type: "oauth",
            authorization: "https://connect.linux.do/oauth2/authorize",
            token: {
                url: "https://connect.linux.do/oauth2/token",
                async conform(response: Response) {
                    const contentType = response.headers.get("content-type") || ""
                    if (contentType.includes("application/json")) return response

                    const body = await response.clone().text()
                    const bodyPreview = body.slice(0, 1000)

                    console.error("[auth-temp][linuxdo-token]", {
                        status: response.status,
                        contentType,
                        bodyPreview,
                    })

                    // Some providers return JSON with an unexpected content-type.
                    if (bodyPreview.trim().startsWith("{")) {
                        return new Response(body, {
                            status: response.status,
                            statusText: response.statusText,
                            headers: { "content-type": "application/json" },
                        })
                    }

                    return response
                },
            },
            userinfo: "https://connect.linux.do/api/user",
            issuer: "https://connect.linux.do/",
            clientId: process.env.OAUTH_CLIENT_ID,
            clientSecret: process.env.OAUTH_CLIENT_SECRET,
            profile(profile) {
                return {
                    id: String(profile.id),
                    name: profile.username || profile.name,
                    email: profile.email, // Check if Linux DO returns email
                    image: profile.avatar_url,
                    trustLevel: profile.trust_level
                }
            },
        }
    ],
    callbacks: {
        async jwt({ token, user, profile }) {
            if (profile) {
                token.id = String(profile.id)
                token.username = profile.username
                token.trustLevel = profile.trust_level
                token.avatar_url = profile.avatar_url
            }
            return token
        },
        async session({ session, token }) {
            if (token) {
                session.user.id = token.id as string
                // @ts-ignore
                session.user.username = token.username
                // @ts-ignore
                session.user.trustLevel = token.trustLevel
                // @ts-ignore
                session.user.avatar_url = token.avatar_url
            }
            return session
        }
    },
    pages: {
        signIn: "/login"
    },
    // Temporary diagnostics: keep this until OAuth callback issue is resolved.
    logger: {
        error(error) {
            console.error("[auth-temp]", {
                name: error.name,
                message: error.message,
                // Auth.js puts provider details under error.cause when available.
                cause: (error as Error & { cause?: unknown }).cause,
                stack: error.stack,
            })
        },
    },
    // Use OAUTH_CLIENT_SECRET as fallback if NEXTAUTH_SECRET is not set
    secret: process.env.AUTH_SECRET || process.env.NEXTAUTH_SECRET || process.env.OAUTH_CLIENT_SECRET,
    trustHost: true,

})
