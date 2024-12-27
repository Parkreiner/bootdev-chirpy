-- name: GetChirp :one
SELECT *
FROM chirps
WHERE id = $1;

-- name: GetChirps :many
SELECT *
FROM chirps
WHERE
    CASE
        WHEN sqlc.narg(user_id)::uuid IS NULL THEN true
        ELSE user_id = sqlc.narg(user_id)::uuid
    END
ORDER BY
    CASE WHEN sqlc.arg(order_by)::text = 'ASC' THEN created_at END ASC,
    CASE WHEN sqlc.arg(order_by)::text = 'DESC' THEN created_at END DESC;

-- name: GetChirpsByAuthor :many
SELECT *
FROM chirps
WHERE user_id = $1
ORDER BY created_at ASC;

-- name: CreateChirp :one
INSERT INTO chirps (
    id,
    created_at,
    updated_at,
    body,
    user_id
)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
)
RETURNING *;

-- name: DeleteChirp :one
DELETE FROM chirps
WHERE id = $1 AND user_id = $2
RETURNING *;

-- name: DeleteAllChirps :exec
DELETE FROM chirps
RETURNING *;