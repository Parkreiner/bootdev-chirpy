-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE users.email = $1;

-- name: CreateUser :one
INSERT INTO users
    (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
-- Cannot return *, because that would send back the hashed password and be big
-- security risk
RETURNING
    id,
    created_at,
    updated_at,
    email;

-- name: DeleteAllUsers :exec
DELETE FROM users
RETURNING *;