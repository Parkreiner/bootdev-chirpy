-- name: CreateNewRefreshToken :one
INSERT INTO refresh_tokens
    (
        token,
        created_at,
        updated_at,
        user_id,
        expires_at,
        revoked_at
    )
VALUES
    (
        $1,
        NOW(),
        NOW(),
        $2,
        NOW() + INTERVAL '60 days',
        NULL
    )
RETURNING *;

-- name: RevokeRefreshToken :exec
UPDATE refresh_tokens
SET revoked_at = COALESCE(revoked_at, NOW())
WHERE token = $1
RETURNING *;

-- name: GetRefreshToken :one
SELECT *
FROM refresh_tokens
WHERE token = $1;

-- name: DeleteAllRefreshTokens :exec
DELETE FROM refresh_tokens
RETURNING *;