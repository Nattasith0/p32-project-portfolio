export function createLoginCsrfController({
    loginCsrfProtection,
    loginCsrfCookie,
}) {
    if (typeof loginCsrfProtection?.createChallenge !== 'function') {
        throw new TypeError('Login CSRF protection is required')
    }

    if (typeof loginCsrfCookie?.setChallengeCookie !== 'function') {
        throw new TypeError('A login CSRF cookie helper is required')
    }

    function getLoginCsrf(request, response) {
        response.set('Cache-Control', 'no-store')

        const challenge = loginCsrfProtection.createChallenge()

        loginCsrfCookie.setChallengeCookie(response, {
            cookieValue: challenge.cookieValue,
            expiresAt: challenge.expiresAt,
        })

        return response.status(200).json({
            csrfToken: challenge.csrfToken,
        })
    }

    return { getLoginCsrf }
}