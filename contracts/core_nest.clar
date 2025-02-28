;; CoreNest - Decentralized Personal Data Management System

;; Data structures
(define-map data-store 
    { owner: principal, data-id: uint } 
    { encrypted-reference: (string-utf8 256), 
      encryption-key-hash: (optional (string-utf8 64)),
      timestamp: uint,
      version: uint })

(define-map data-versions
    { owner: principal, data-id: uint, version: uint }
    { encrypted-reference: (string-utf8 256),
      timestamp: uint })

(define-map access-permissions
    { data-id: uint, granted-to: principal }
    { can-access: bool, 
      encrypted-key: (optional (string-utf8 256)),
      granted-at: uint,
      expires-at: (optional uint) })

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
(define-constant err-access-expired (err u105))

;; Events
(define-data-var event-counter uint u0)

(define-private (emit-event (event-type (string-utf8 24)) (data-id uint))
    (begin
        (var-set event-counter (+ (var-get event-counter) u1))
        (print { event-id: (var-get event-counter),
                type: event-type,
                data-id: data-id,
                timestamp: block-height })))

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
                  timestamp: block-height,
                  version: u1 }
            )
            (emit-event "data-stored" data-id)
            (var-set next-data-id (+ data-id u1))
            (ok data-id)
        )
    ))

;; Update existing data with version tracking
(define-public (update-data
    (data-id uint)
    (encrypted-ref (string-utf8 256))
    (key-hash (optional (string-utf8 64))))
    (let ((data-entry (map-get? data-store { owner: tx-sender, data-id: data-id })))
        (if (is-some data-entry)
            (let ((current-version (get version (unwrap-panic data-entry))))
                (begin
                    (map-set data-versions
                        { owner: tx-sender, data-id: data-id, version: current-version }
                        { encrypted-reference: (get encrypted-reference (unwrap-panic data-entry)),
                          timestamp: (get timestamp (unwrap-panic data-entry)) })
                    (map-set data-store
                        { owner: tx-sender, data-id: data-id }
                        { encrypted-reference: encrypted-ref,
                          encryption-key-hash: key-hash,
                          timestamp: block-height,
                          version: (+ current-version u1) })
                    (emit-event "data-updated" data-id)
                    (ok true)))
            err-not-owner)))

;; Grant access to data with optional encrypted key and expiry
(define-public (grant-access 
    (data-id uint) 
    (grantee principal)
    (encrypted-key (optional (string-utf8 256)))
    (expires-at (optional uint)))
    (let
        ((data-entry (map-get? data-store { owner: tx-sender, data-id: data-id })))
        (if (is-some data-entry)
            (begin
                (map-set access-permissions
                    { data-id: data-id, granted-to: grantee }
                    { can-access: true,
                      encrypted-key: encrypted-key,
                      granted-at: block-height,
                      expires-at: expires-at }
                )
                (emit-event "access-granted" data-id)
                (ok true)
            )
            err-not-owner
        )
    ))

;; Batch grant access
(define-public (batch-grant-access
    (data-ids (list 20 uint))
    (grantee principal)
    (encrypted-keys (list 20 (optional (string-utf8 256))))
    (expires-at (optional uint)))
    (fold check-err
        (map grant-access-internal data-ids (map to-tuple 
            (list grantee encrypted-keys expires-at)))
        (ok true)))

(define-private (grant-access-internal 
    (data-id uint) 
    (params { grantee: principal, key: (optional (string-utf8 256)), expires: (optional uint) }))
    (grant-access data-id 
        (get grantee params) 
        (get key params)
        (get expires params)))

(define-private (check-err (result (response bool uint)) (prior (response bool uint)))
    (match prior
        success (match result
            success-inner (ok true)
            error-inner error-inner)
        error error))

;; Helper function for batch operations
(define-private (to-tuple (item (string-utf8 256)))
    { grantee: tx-sender, key: (some item), expires: none })

;; Access data with expiry check
(define-public (access-data (data-id uint))
    (let
        ((permission (map-get? access-permissions 
            { data-id: data-id, granted-to: tx-sender }))
         (data-entry (map-get? data-store 
            { owner: tx-sender, data-id: data-id })))
        (if (and
                (is-some permission)
                (get can-access (unwrap-panic permission))
                (or
                    (is-none (get expires-at (unwrap-panic permission)))
                    (< block-height (unwrap! (get expires-at (unwrap-panic permission)) err-access-expired))))
            (begin
                (log-access data-id tx-sender)
                (emit-event "data-accessed" data-id)
                (ok {
                    reference: (get encrypted-reference (unwrap-panic data-entry)),
                    key: (get encrypted-key (unwrap-panic permission))
                }))
            err-no-permission)))

[... remaining functions unchanged ...]
