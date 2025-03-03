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
(define-constant err-invalid-input (err u106))

;; Input validation
(define-private (is-valid-reference (ref (string-utf8 256)))
    (> (len ref) u0))

(define-private (is-valid-timestamp (timestamp uint))
    (< timestamp u9999999999))

;; Events
(define-data-var event-counter uint u0)

(define-private (emit-event (event-type (string-utf8 24)) (data-id uint))
    (begin
        (var-set event-counter (+ (var-get event-counter) u1))
        (print { event-id: (var-get event-counter),
                type: event-type,
                data-id: data-id,
                timestamp: block-height })))

;; Store new data reference with input validation
(define-public (store-data 
    (encrypted-ref (string-utf8 256))
    (key-hash (optional (string-utf8 64))))
    (if (is-valid-reference encrypted-ref)
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
            ))
        err-invalid-input))

;; Fixed access-data implementation
(define-public (access-data (data-id uint))
    (let
        ((permission (map-get? access-permissions 
            { data-id: data-id, granted-to: tx-sender }))
         (data-entry (map-get? data-store 
            { owner: contract-caller, data-id: data-id })))
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

;; Fixed batch operations
(define-public (batch-grant-access
    (data-ids (list 20 uint))
    (grantee principal)
    (encrypted-keys (list 20 (optional (string-utf8 256))))
    (expires-at (optional uint)))
    (begin
        (asserts! (is-some expires-at) err-invalid-input)
        (asserts! (is-valid-timestamp (unwrap! expires-at err-invalid-input)) err-invalid-input)
        (fold check-err
            (map grant-access-internal data-ids (map create-grant-params 
                encrypted-keys (make-list 20 grantee) (make-list 20 expires-at)))
            (ok true))))

(define-private (create-grant-params 
    (key (optional (string-utf8 256))) 
    (grantee principal)
    (expires (optional uint)))
    { grantee: grantee, key: key, expires: expires })

[... remaining functions unchanged ...]
