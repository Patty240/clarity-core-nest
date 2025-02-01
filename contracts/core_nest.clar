;; CoreNest - Decentralized Personal Data Management System

;; Data structures
(define-map data-store 
    { owner: principal, data-id: uint } 
    { encrypted-reference: (string-utf8 256), 
      encryption-key-hash: (optional (string-utf8 64)),
      timestamp: uint })

(define-map access-permissions
    { data-id: uint, granted-to: principal }
    { can-access: bool, 
      encrypted-key: (optional (string-utf8 256)),
      granted-at: uint })

(define-map data-access-log
    { data-id: uint, accessor: principal }
    { access-count: uint, last-access: uint })

;; Data variables
(define-data-var next-data-id uint u1)

;; Error codes
(define-constant err-not-owner (err u100))
(define-constant err-no-permission (err u101))
(define-constant err-invalid-data (err u102))
(define-constant err-already-exists (err u103))
(define-constant err-no-key (err u104))

;; Store new data reference with optional encryption key hash
(define-public (store-data 
    (encrypted-ref (string-utf8 256))
    (key-hash (optional (string-utf8 64))))
    (let
        ((data-id (var-get next-data-id)))
        (begin
            (map-set data-store
                { owner: tx-sender, data-id: data-id }
                { encrypted-reference: encrypted-ref,
                  encryption-key-hash: key-hash,
                  timestamp: block-height }
            )
            (var-set next-data-id (+ data-id u1))
            (ok data-id)
        )
    )
)

;; Grant access to data with optional encrypted key
(define-public (grant-access 
    (data-id uint) 
    (grantee principal)
    (encrypted-key (optional (string-utf8 256))))
    (let
        ((data-entry (map-get? data-store { owner: tx-sender, data-id: data-id })))
        (if (is-some data-entry)
            (begin
                (map-set access-permissions
                    { data-id: data-id, granted-to: grantee }
                    { can-access: true,
                      encrypted-key: encrypted-key,
                      granted-at: block-height }
                )
                (ok true)
            )
            err-not-owner
        )
    )
)

;; Revoke access
(define-public (revoke-access (data-id uint) (revokee principal))
    (let
        ((data-entry (map-get? data-store { owner: tx-sender, data-id: data-id })))
        (if (is-some data-entry)
            (begin
                (map-set access-permissions
                    { data-id: data-id, granted-to: revokee }
                    { can-access: false,
                      encrypted-key: none,
                      granted-at: block-height }
                )
                (ok true)
            )
            err-not-owner
        )
    )
)

;; Access data and get encryption key if available
(define-public (access-data (data-id uint))
    (let
        ((permission (map-get? access-permissions 
            { data-id: data-id, granted-to: tx-sender }))
         (data-entry (map-get? data-store 
            { owner: tx-sender, data-id: data-id })))
        (if (and
                (is-some permission)
                (get can-access (unwrap-panic permission)))
            (begin
                (log-access data-id tx-sender)
                (ok {
                    reference: (get encrypted-reference (unwrap-panic data-entry)),
                    key: (get encrypted-key (unwrap-panic permission))
                })
            )
            err-no-permission
        )
    )
)

;; Private function to log access
(define-private (log-access (data-id uint) (accessor principal))
    (let
        ((current-log (map-get? data-access-log 
            { data-id: data-id, accessor: accessor })))
        (if (is-some current-log)
            (map-set data-access-log
                { data-id: data-id, accessor: accessor }
                { access-count: (+ (get access-count (unwrap-panic current-log)) u1),
                  last-access: block-height }
            )
            (map-set data-access-log
                { data-id: data-id, accessor: accessor }
                { access-count: u1, last-access: block-height }
            )
        )
    )
)

;; Read only functions
(define-read-only (get-data-access-log (data-id uint) (accessor principal))
    (ok (map-get? data-access-log { data-id: data-id, accessor: accessor }))
)

(define-read-only (check-access (data-id uint) (accessor principal))
    (ok (map-get? access-permissions 
        { data-id: data-id, granted-to: accessor }))
)

(define-read-only (get-key-hash (data-id uint))
    (let ((data-entry (map-get? data-store { owner: tx-sender, data-id: data-id })))
        (if (is-some data-entry)
            (ok (get encryption-key-hash (unwrap-panic data-entry)))
            err-not-owner
        )
    )
)
