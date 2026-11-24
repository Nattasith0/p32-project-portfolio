export function getCurrentUser(request, response) {
    // request.auth มาจาก middleware ที่ตรวจ session แล้ว
    const { userId, username, displayName } = request.auth

    return response.status(200).json({
        user: {
            userId,
            username,
            displayName,
        },
    })
}