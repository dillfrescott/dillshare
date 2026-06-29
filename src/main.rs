use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Path, State, Multipart},
    http::header::{CONTENT_DISPOSITION, CONTENT_TYPE, CONTENT_LENGTH},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::{get, post, delete},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Clone)]
struct AppState {
    s3_client: aws_sdk_s3::Client,
    bucket: String,
    jwt_secret: Vec<u8>,
}

#[tokio::main]
async fn main() {
    // Load .env file if it exists
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "s3_share=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Load S3 Configuration
    let bucket = std::env::var("AWS_S3_BUCKET")
        .or_else(|_| std::env::var("S3_BUCKET"))
        .expect("AWS_S3_BUCKET or S3_BUCKET environment variable is required");

    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());
    
    if let Ok(endpoint) = std::env::var("AWS_ENDPOINT_URL") {
        tracing::info!("Using custom S3 endpoint URL: {}", endpoint);
        config_loader = config_loader.endpoint_url(endpoint);
    }
    
    let config = config_loader.load().await;
    let mut s3_config_builder = aws_sdk_s3::config::Builder::from(&config);
    
    if let Ok(force_path_style) = std::env::var("AWS_S3_FORCE_PATH_STYLE") {
        if force_path_style == "true" {
            tracing::info!("Forcing S3 path-style addressing.");
            s3_config_builder = s3_config_builder.force_path_style(true);
        }
    }
    
    let s3_client = aws_sdk_s3::Client::from_conf(s3_config_builder.build());

    // Verify S3 Connection
    tracing::info!("Validating S3 connection to bucket '{}'...", bucket);
    match s3_client.list_objects_v2().bucket(&bucket).max_keys(1).send().await {
        Ok(_) => tracing::info!("S3 connection verified successfully."),
        Err(e) => {
            tracing::error!("WARNING: S3 bucket validation failed! S3 calls may fail. Error: {:?}", e);
            tracing::error!("Please check your AWS credentials (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION).");
        }
    }

    // Get JWT secret from environment or load/generate in S3
    let jwt_secret = match std::env::var("JWT_SECRET") {
        Ok(secret_str) => secret_str.into_bytes(),
        Err(_) => {
            let secret_key = "config/jwt_secret.bin";
            match s3_client.get_object().bucket(&bucket).key(secret_key).send().await {
                Ok(output) => {
                    if let Ok(bytes) = output.body.collect().await {
                        bytes.to_vec()
                    } else {
                        generate_and_save_jwt_secret(&s3_client, &bucket, secret_key).await
                    }
                }
                Err(_) => {
                    generate_and_save_jwt_secret(&s3_client, &bucket, secret_key).await
                }
            }
        }
    };

    let state = AppState {
        s3_client: s3_client.clone(),
        bucket: bucket.clone(),
        jwt_secret,
    };

    // Spawn background cleanup worker (runs every hour)
    tokio::spawn(run_cleanup_worker(s3_client, bucket));

    // Setup routes
    let app = Router::new()
        // API routes
        .route("/api/upload", post(upload_files))
        .route("/api/upload/init", post(upload_init))
        .route("/api/upload/:uuid", post(upload_chunk_or_file).delete(upload_abort))
        .route("/api/upload/:uuid/multipart/init", post(upload_multipart_init))
        .route("/api/upload/:uuid/multipart/part", post(upload_multipart_part))
        .route("/api/upload/:uuid/multipart/complete", post(upload_multipart_complete))
        .route("/api/upload/:uuid/finish", post(upload_finish))
        .route("/api/upload/:uuid/abort", post(upload_abort))
        .route("/api/upload/:uuid/ping", post(upload_ping))
        .route("/api/share/:uuid", get(get_share).delete(delete_share))
        .route("/api/share/:uuid/file/*filename", get(download_file))
        // Service worker for streaming decrypted media preview
        .route("/sw.js", get(serve_service_worker))
        // Self-hosted vendored frontend assets (embedded at compile time so the
        // binary runs fully offline with no CDN dependency for jszip, fflate,
        // streamsaver or the Plus Jakarta Sans webfont).
        .route("/assets/streamsaver.js", get(serve_asset_streamsaver))
        .route("/assets/streamsaver-sw.js", get(serve_asset_streamsaver_sw))
        .route("/assets/streamsaver-mitm.html", get(serve_asset_streamsaver_mitm_html))
        .route("/assets/jszip.js", get(serve_asset_jszip))
        .route("/assets/fflate.js", get(serve_asset_fflate))
        .route("/assets/marked.js", get(serve_asset_marked))
        .route("/assets/fonts-inline.css", get(serve_asset_fonts_inline_css))
        // Authentication routes
        .route("/api/register", post(register_user))
        .route("/api/login", post(login_user))
        .route("/api/user/shares", get(get_user_shares).post(save_user_shares))
        .route("/api/user/profile", get(get_user_profile).post(save_user_profile))
        .route("/api/user/change_password", post(user_change_password))
        .route("/api/user/account", delete(user_delete_account))
        .route("/api/user/sessions", get(get_user_sessions))
        .route("/api/user/sessions/:id", delete(revoke_user_session).put(rename_user_session))
        // Admin routes
        .route("/api/admin/login", post(admin_login))
        .route("/api/admin/sessions", get(admin_get_sessions))
        .route("/api/admin/sessions/:id", delete(admin_revoke_session).put(admin_rename_session))
        .route("/api/admin/stats", get(admin_get_stats))
        .route("/api/admin/share/:uuid", delete(admin_delete_share))
        .route("/api/admin/user/:username", delete(admin_delete_user))
        .route("/api/admin/user/:username/sessions", get(admin_get_user_sessions))
        .route("/api/admin/user/:username/sessions/:id", delete(admin_revoke_user_session))
        // Static assets/routing (all fallback to SPA index.html)
        .route("/", get(serve_index))
        .route("/shares", get(serve_index))
        .route("/share/:uuid", get(serve_index))
        .route("/admin", get(serve_index))
        .route("/profile", get(serve_index))
        .fallback(serve_index)
        // Router configurations
        .layer(DefaultBodyLimit::disable()) // Disable Axum's default 2MB multipart limit
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(8000);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Dill Share server running at http://localhost:{}", port);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

// Serve embedded single page app index.html
async fn serve_index() -> impl IntoResponse {
    Html(include_str!("index.html"))
}

// Serve the streaming-preview service worker. The browser requires this to be
// served from the same origin with an explicit JavaScript content type and a
// scope that allows it to control the SPA routes (e.g. /share/<uuid>).
async fn serve_service_worker() -> impl IntoResponse {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "application/javascript; charset=utf-8")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .header("service-worker-allowed", "/")
        .body(Body::from(include_str!("sw.js")))
        .unwrap()
}

// --- Embedded vendored frontend assets ---
//
// Every asset is embedded via include_str!/include_bytes! so the compiled
// binary is completely self-contained and runs offline without reaching out to
// any CDN. Long cache (1y immutable) since the bytes never change for a given
// binary build.

fn text_response(bytes: &'static str, content_type: &'static str) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CACHE_CONTROL, "public, max-age=31536000, immutable")
        .header(CONTENT_TYPE, content_type)
        .body(Body::from(bytes))
        .unwrap()
}

async fn serve_asset_streamsaver() -> impl IntoResponse {
    text_response(include_str!("vendor/streamsaver.min.js"), "application/javascript; charset=utf-8")
}

async fn serve_asset_streamsaver_sw() -> impl IntoResponse {
    text_response(include_str!("vendor/streamsaver_sw.js"), "application/javascript; charset=utf-8")
}

async fn serve_asset_streamsaver_mitm_html() -> impl IntoResponse {
    text_response(include_str!("vendor/mitm.html"), "text/html; charset=utf-8")
}

async fn serve_asset_jszip() -> impl IntoResponse {
    text_response(include_str!("vendor/jszip.min.js"), "application/javascript; charset=utf-8")
}

async fn serve_asset_fflate() -> impl IntoResponse {
    text_response(include_str!("vendor/fflate.umd.js"), "application/javascript; charset=utf-8")
}

async fn serve_asset_fonts_inline_css() -> impl IntoResponse {
    text_response(include_str!("vendor/fonts_inline.css"), "text/css; charset=utf-8")
}

async fn serve_asset_marked() -> impl IntoResponse {
    text_response(include_str!("vendor/marked.min.js"), "application/javascript; charset=utf-8")
}

// Multipart file uploader - requires authentication
async fn upload_files(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let uuid = uuid::Uuid::new_v4().to_string();

    let result: Result<axum::Json<serde_json::Value>, (StatusCode, String)> =
        upload_files_inner(&state, &username, &uuid, multipart).await;

    match result {
        Ok(json) => Ok(json),
        Err(err) => {
            // Upload failed or aborted — remove anything already written for this share.
            let prefix = format!("uploads/{}/", uuid);
            tracing::warn!(
                "Upload {} failed ({:?}); cleaning up S3 prefix '{}'",
                uuid,
                err,
                prefix
            );
            if let Err(cleanup_err) = delete_s3_prefix(&state.s3_client, &state.bucket, &prefix).await {
                tracing::error!(
                    "Failed to clean up aborted upload {}: {:?}",
                    uuid,
                    cleanup_err
                );
            }
            Err(err)
        }
    }
}

async fn upload_files_inner(
    state: &AppState,
    username: &str,
    uuid: &str,
    mut multipart: Multipart,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let mut uploaded_files = Vec::new();
    let mut total_size = 0;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let file_path = match field.file_name() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if file_path.trim().is_empty() {
            continue;
        }

        let content_type = mime_guess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();

        let bytes = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        total_size += bytes.len() as i64;

        let key = format!("uploads/{}/{}", uuid, file_path);
        tracing::info!("Uploading {} to S3 bucket '{}'...", file_path, state.bucket);

        state.s3_client
            .put_object()
            .bucket(&state.bucket)
            .key(&key)
            .content_type(content_type)
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| {
                tracing::error!("S3 PutObject error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to upload to S3: {:?}", e),
                )
            })?;

        uploaded_files.push(file_path);
    }

    if uploaded_files.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "No files uploaded".to_string()));
    }

    // Write owner record
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    state.s3_client
        .put_object()
        .bucket(&state.bucket)
        .key(&owner_key)
        .content_type("text/plain")
        .body(aws_sdk_s3::primitives::ByteStream::from(username.as_bytes().to_vec()))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save owner: {:?}", e)))?;

    // Actual user files count (excluding metadata.enc)
    let files_count = uploaded_files.iter().filter(|f| *f != "metadata.enc").count();

    // Update user's public shares index in S3
    let public_shares_key = format!("users/{}/public_shares.json", username);
    let mut shares = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&public_shares_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice::<Vec<serde_json::Value>>(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    shares.push(serde_json::json!({
        "uuid": uuid,
        "files_count": files_count,
        "total_size": total_size,
        "created_at": chrono::Utc::now().to_rfc3339()
    }));

    let shares_bytes = serde_json::to_vec(&shares)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.s3_client.put_object()
        .bucket(&state.bucket)
        .key(&public_shares_key)
        .content_type("application/json")
        .body(aws_sdk_s3::primitives::ByteStream::from(shares_bytes))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save public shares list: {:?}", e)))?;

    Ok(axum::Json(serde_json::json!({
        "uuid": uuid,
        "files": uploaded_files
    })))
}

async fn upload_init(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let uuid = uuid::Uuid::new_v4().to_string();
    
    // Write initial active heartbeat marker
    let active_key = format!("uploads/{}/.active", uuid);
    let _ = state.s3_client
        .put_object()
        .bucket(&state.bucket)
        .key(&active_key)
        .content_type("text/plain")
        .body(aws_sdk_s3::primitives::ByteStream::from(b"active".to_vec()))
        .send()
        .await;

    Ok(axum::Json(serde_json::json!({
        "uuid": uuid
    })))
}

async fn upload_ping(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let active_key = format!("uploads/{}/.active", uuid);
    state.s3_client
        .put_object()
        .bucket(&state.bucket)
        .key(&active_key)
        .content_type("text/plain")
        .body(aws_sdk_s3::primitives::ByteStream::from(b"active".to_vec()))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update heartbeat: {:?}", e)))?;

    Ok(axum::Json(serde_json::json!({ "status": "ok" })))
}

async fn upload_chunk_or_file(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    mut multipart: Multipart,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let mut uploaded_files = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
    {
        let file_path = match field.file_name() {
            Some(name) => name.to_string(),
            None => continue,
        };

        if file_path.trim().is_empty() {
            continue;
        }

        let content_type = mime_guess::from_path(&file_path)
            .first_or_octet_stream()
            .to_string();

        let bytes = field
            .bytes()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let key = format!("uploads/{}/{}", uuid, file_path);
        tracing::info!("Uploading {} to S3 bucket '{}'...", file_path, state.bucket);

        state.s3_client
            .put_object()
            .bucket(&state.bucket)
            .key(&key)
            .content_type(content_type)
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| {
                tracing::error!("S3 PutObject error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Failed to upload to S3: {:?}", e),
                )
            })?;

        uploaded_files.push(file_path);
    }

    // Refresh active heartbeat timestamp on chunk/file activity asynchronously
    let active_key = format!("uploads/{}/.active", uuid);
    let s3_client = state.s3_client.clone();
    let bucket = state.bucket.clone();
    tokio::spawn(async move {
        let _ = s3_client
            .put_object()
            .bucket(&bucket)
            .key(&active_key)
            .content_type("text/plain")
            .body(aws_sdk_s3::primitives::ByteStream::from(b"active".to_vec()))
            .send()
            .await;
    });

    Ok(axum::Json(serde_json::json!({
        "status": "ok",
        "uploaded": uploaded_files
    })))
}

#[derive(serde::Deserialize)]
struct UploadFinishReq {
    files_count: Option<usize>,
    total_size: Option<i64>,
}

async fn upload_finish(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<UploadFinishReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    // Write owner record
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    state.s3_client
        .put_object()
        .bucket(&state.bucket)
        .key(&owner_key)
        .content_type("text/plain")
        .body(aws_sdk_s3::primitives::ByteStream::from(username.as_bytes().to_vec()))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save owner: {:?}", e)))?;

    // List files under uploads/{uuid}/ to count and check uploaded files
    let prefix = format!("uploads/{}/", uuid);
    let mut uploaded_files = Vec::new();
    let mut s3_total_size: i64 = 0;

    let list_res = state.s3_client.list_objects_v2()
        .bucket(&state.bucket)
        .prefix(&prefix)
        .send()
        .await;

    if let Ok(out) = list_res {
        if let Some(objects) = out.contents {
            for obj in objects {
                if let Some(k) = obj.key {
                    let rel_path = k.strip_prefix(&prefix).unwrap_or(&k).to_string();
                    if rel_path != "owner.txt" && rel_path != ".active" {
                        uploaded_files.push(rel_path.clone());
                    }
                    if rel_path != "owner.txt" && rel_path != ".active" && rel_path != "metadata.enc" && !rel_path.ends_with(".thumb.enc") {
                        s3_total_size += obj.size.unwrap_or(0);
                    }
                }
            }
        }
    }

    let files_count = payload.files_count.unwrap_or_else(|| {
        uploaded_files.iter().filter(|f| *f != "metadata.enc" && !f.ends_with(".thumb.enc")).count()
    });
    let total_size = payload.total_size.unwrap_or(s3_total_size);

    // Update user's public shares index in S3
    let public_shares_key = format!("users/{}/public_shares.json", username);
    let mut shares = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&public_shares_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice::<Vec<serde_json::Value>>(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    shares.push(serde_json::json!({
        "uuid": uuid,
        "files_count": files_count,
        "total_size": total_size,
        "created_at": chrono::Utc::now().to_rfc3339()
    }));

    let shares_bytes = serde_json::to_vec(&shares)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.s3_client.put_object()
        .bucket(&state.bucket)
        .key(&public_shares_key)
        .content_type("application/json")
        .body(aws_sdk_s3::primitives::ByteStream::from(shares_bytes))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save public shares list: {:?}", e)))?;

    Ok(axum::Json(serde_json::json!({
        "uuid": uuid,
        "files": uploaded_files
    })))
}

async fn upload_abort(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let prefix = format!("uploads/{}/", uuid);
    tracing::info!("Aborting upload session {}; cleaning up S3 prefix '{}'", uuid, prefix);
    delete_s3_prefix(&state.s3_client, &state.bucket, &prefix).await?;

    Ok(axum::Json(serde_json::json!({ "status": "aborted" })))
}

#[derive(serde::Deserialize)]
struct MultipartInitReq {
    file_name: String,
}

async fn upload_multipart_init(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<MultipartInitReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let key = format!("uploads/{}/{}", uuid, payload.file_name);
    let content_type = mime_guess::from_path(&payload.file_name)
        .first_or_octet_stream()
        .to_string();

    let res = state.s3_client
        .create_multipart_upload()
        .bucket(&state.bucket)
        .key(&key)
        .content_type(content_type)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create S3 multipart upload: {:?}", e)))?;

    let upload_id = res.upload_id().ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, "No upload_id returned from S3".to_string())
    })?.to_string();

    Ok(axum::Json(serde_json::json!({ "upload_id": upload_id })))
}

#[derive(serde::Deserialize)]
struct MultipartPartQuery {
    upload_id: String,
    part_number: i32,
    file_name: String,
}

async fn upload_multipart_part(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    axum::extract::Query(query): axum::extract::Query<MultipartPartQuery>,
    headers: axum::http::HeaderMap,
    bytes: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let key = format!("uploads/{}/{}", uuid, query.file_name);

    let res = state.s3_client
        .upload_part()
        .bucket(&state.bucket)
        .key(&key)
        .upload_id(&query.upload_id)
        .part_number(query.part_number)
        .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to upload part: {:?}", e)))?;

    let e_tag = res.e_tag().unwrap_or("").to_string();

    // Refresh active heartbeat timestamp on part activity asynchronously
    let active_key = format!("uploads/{}/.active", uuid);
    let s3_client = state.s3_client.clone();
    let bucket = state.bucket.clone();
    tokio::spawn(async move {
        let _ = s3_client
            .put_object()
            .bucket(&bucket)
            .key(&active_key)
            .content_type("text/plain")
            .body(aws_sdk_s3::primitives::ByteStream::from(b"active".to_vec()))
            .send()
            .await;
    });

    Ok(axum::Json(serde_json::json!({
        "part_number": query.part_number,
        "e_tag": e_tag
    })))
}

#[derive(serde::Deserialize)]
struct CompletedPartReq {
    part_number: i32,
    e_tag: String,
}

#[derive(serde::Deserialize)]
struct MultipartCompleteReq {
    upload_id: String,
    file_name: String,
    parts: Vec<CompletedPartReq>,
}

async fn upload_multipart_complete(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<MultipartCompleteReq>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (_username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let key = format!("uploads/{}/{}", uuid, payload.file_name);

    let mut completed_parts = Vec::new();
    for p in payload.parts {
        let completed_part = aws_sdk_s3::types::CompletedPart::builder()
            .part_number(p.part_number)
            .e_tag(p.e_tag)
            .build();
        completed_parts.push(completed_part);
    }

    let multipart_upload = aws_sdk_s3::types::CompletedMultipartUpload::builder()
        .set_parts(Some(completed_parts))
        .build();

    state.s3_client
        .complete_multipart_upload()
        .bucket(&state.bucket)
        .key(&key)
        .upload_id(&payload.upload_id)
        .multipart_upload(multipart_upload)
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to complete S3 multipart upload: {:?}", e)))?;

    Ok(axum::Json(serde_json::json!({ "status": "ok" })))
}


// Get details of a single share UUID
async fn get_share(
    State(state): State<AppState>,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let prefix = format!("uploads/{}/", uuid);

    let mut response = state.s3_client
        .list_objects_v2()
        .bucket(&state.bucket)
        .prefix(&prefix)
        .into_paginator()
        .send();

    #[derive(serde::Serialize)]
    struct ShareFile {
        name: String,
        size: i64,
    }

    #[derive(serde::Serialize)]
    struct ShareDetails {
        uuid: String,
        upload_time: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
        files: Vec<ShareFile>,
        owner: String,
        owner_pfp: Option<String>,
    }

    let mut files = Vec::new();
    let mut latest_upload_time = chrono::Utc::now();
    let mut has_objects = false;

    while let Some(result) = response.next().await {
        let page = result.map_err(|e| {
            tracing::error!("S3 ListObjectsV2 error: {:?}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("S3 list error: {:?}", e))
        })?;

        for object in page.contents() {
            if let (Some(key), Some(size), Some(last_modified)) = (object.key(), object.size(), object.last_modified()) {
                let file_name = key.strip_prefix(&prefix).unwrap_or(key).to_string();
                if file_name == "owner.txt" || file_name == ".active" {
                    continue;
                }

                let last_mod_secs = last_modified.secs();
                let upload_time = chrono::DateTime::<chrono::Utc>::from_timestamp(last_mod_secs, 0)
                    .unwrap_or_else(|| chrono::Utc::now());

                if !has_objects {
                    latest_upload_time = upload_time;
                    has_objects = true;
                } else if upload_time > latest_upload_time {
                    latest_upload_time = upload_time;
                }

                files.push(ShareFile {
                    name: file_name,
                    size,
                });
            }
        }
    }

    if !has_objects {
        return Err((StatusCode::NOT_FOUND, "Share not found or expired".to_string()));
    }

    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&owner_key)
        .send()
        .await;

    let owner = match owner_res {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                String::from_utf8(bytes.to_vec()).unwrap_or_default().trim().to_string()
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    };

    let owner_pfp = None;

    let expires_at = latest_upload_time + chrono::Duration::days(90);

    Ok(axum::Json(ShareDetails {
        uuid,
        upload_time: latest_upload_time,
        expires_at,
        files,
        owner,
        owner_pfp,
    }))
}

// Download/stream a file from S3 share
// Supports HTTP Range requests so that a Service Worker can fetch individual
// encrypted chunks on demand for streaming preview of large media files.
async fn download_file(
    State(state): State<AppState>,
    Path((uuid, filename)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let key = format!("uploads/{}/{}", uuid, filename);

    // Parse a single HTTP range (start-end). Multi-range is not supported and
    // we respond with the full body (200) in that case, which is spec-compliant.
    let range_header = headers.get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("bytes="))
        .and_then(|spec| {
            // Accept only a single range; ignore multiple ranges / suffix forms.
            if spec.contains(',') { return None; }
            let mut it = spec.split('-');
            let start_str = it.next()?.trim();
            let end_str = it.next().map(|s| s.trim()).unwrap_or("");
            let start: u64 = start_str.parse().ok()?;
            let end: Option<u64> = if end_str.is_empty() { None } else { end_str.parse().ok() };
            Some((start, end))
        });

    let mut get_object = state.s3_client.get_object().bucket(&state.bucket).key(&key);

    if let Some((start, end)) = &range_header {
        let range_value = match end {
            Some(e) => format!("bytes={}-{}", start, e),
            None => format!("bytes={}-", start),
        };
        get_object = get_object.range(range_value);
    }

    let res = match get_object.send().await {
        Ok(output) => output,
        Err(e) => {
            tracing::error!("S3 GetObject error: {:?}", e);
            return Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::from("File not found"))
                .unwrap();
        }
    };

    let body = Body::from_stream(tokio_util::io::ReaderStream::new(res.body.into_async_read()));

    let status = if range_header.is_some() {
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    let mut builder = Response::builder().status(status);

    if let Some(content_type) = res.content_type {
        builder = builder.header(CONTENT_TYPE, content_type);
    } else {
        let guessed = mime_guess::from_path(&filename)
            .first_or_octet_stream()
            .to_string();
        builder = builder.header(CONTENT_TYPE, guessed);
    }

    if let Some(content_length) = res.content_length {
        builder = builder.header(CONTENT_LENGTH, content_length);
    }

    if let Some(content_range) = res.content_range {
        builder = builder.header(
            axum::http::header::CONTENT_RANGE,
            content_range.as_str().to_string(),
        );
    }

    // Advertise range support so media engines will issue range requests.
    builder = builder.header(axum::http::header::ACCEPT_RANGES, "bytes");

    let encoded_filename = percent_encoding::utf8_percent_encode(
        &filename,
        percent_encoding::NON_ALPHANUMERIC
    ).to_string();

    builder = builder.header(
        CONTENT_DISPOSITION,
        format!("inline; filename*=UTF-8''{}", encoded_filename)
    );

    builder.body(body).unwrap()
}

// Delete an entire share from S3
// Delete share - requires ownership verification
async fn delete_share(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    // Check ownership
    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&owner_key)
        .send()
        .await;

    let owner = match owner_res {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                String::from_utf8(bytes.to_vec()).unwrap_or_default().trim().to_string()
            } else {
                return Err((StatusCode::FORBIDDEN, "Share has no valid owner recorded".to_string()));
            }
        }
        Err(_) => {
            return Err((StatusCode::FORBIDDEN, "Cannot verify ownership".to_string()));
        }
    };

    if owner != username {
        return Err((StatusCode::FORBIDDEN, "You do not own this share".to_string()));
    }

    // Delete objects from S3
    delete_share_objects(&state.s3_client, &state.bucket, &uuid).await?;

    // Remove from owner's public shares index in S3
    remove_share_from_user_index(&state.s3_client, &state.bucket, &username, &uuid).await;

    Ok(axum::Json(serde_json::json!({ "status": "deleted" })))
}

async fn remove_share_from_user_index(s3_client: &aws_sdk_s3::Client, bucket: &str, username: &str, uuid: &str) {
    if username.is_empty() { return; }
    let public_shares_key = format!("users/{}/public_shares.json", username);
    if let Ok(output) = s3_client.get_object()
        .bucket(bucket)
        .key(&public_shares_key)
        .send()
        .await
    {
        if let Ok(bytes) = output.body.collect().await {
            if let Ok(mut shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes.into_bytes()) {
                shares.retain(|s| s.get("uuid").and_then(|u| u.as_str()) != Some(uuid));
                if let Ok(shares_bytes) = serde_json::to_vec(&shares) {
                    let _ = s3_client.put_object()
                        .bucket(bucket)
                        .key(&public_shares_key)
                        .content_type("application/json")
                        .body(aws_sdk_s3::primitives::ByteStream::from(shares_bytes))
                        .send()
                        .await;
                }
            }
        }
    }
}

// Background cleanup worker thread - deletes S3 objects older than 90 days or abandoned partial uploads older than 1 hour
async fn run_cleanup_worker(s3_client: aws_sdk_s3::Client, bucket: String) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // check every hour
    loop {
        interval.tick().await;
        tracing::info!("Running S3 cleanup worker for expired shares and abandoned partial uploads...");
        if let Err(e) = perform_cleanup(&s3_client, &bucket).await {
            tracing::error!("Error during cleanup execution: {:?}", e);
        }
    }
}

struct ShareGroup {
    has_owner: bool,
    latest_modified_secs: i64,
    keys: Vec<String>,
}

async fn perform_cleanup(s3_client: &aws_sdk_s3::Client, bucket: &str) -> Result<(), Box<dyn std::error::Error>> {
    let now = chrono::Utc::now().timestamp();
    
    let share_expiry_days = std::env::var("SHARE_EXPIRY_DAYS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(90); // Default to 90 days for completed shares
    let share_expire_limit = share_expiry_days * 24 * 60 * 60;
    
    let partial_timeout_hours = std::env::var("PARTIAL_UPLOAD_TIMEOUT_HOURS")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(12); // Default to 12 hours for incomplete / cancelled / abandoned uploads
    let partial_upload_limit = partial_timeout_hours * 60 * 60;

    // 1. Abort old incomplete multipart uploads in S3
    if let Ok(mp_out) = s3_client.list_multipart_uploads().bucket(bucket).prefix("uploads/").send().await {
        if let Some(uploads) = mp_out.uploads {
            for u in uploads {
                if let (Some(key), Some(upload_id), Some(initiated)) = (u.key(), u.upload_id(), u.initiated()) {
                    let init_secs = initiated.secs();
                    if now - init_secs > partial_upload_limit {
                        tracing::info!("Aborting abandoned S3 multipart upload '{}' (upload_id: {})...", key, upload_id);
                        let _ = s3_client.abort_multipart_upload()
                            .bucket(bucket)
                            .key(key)
                            .upload_id(upload_id)
                            .send()
                            .await;
                    }
                }
            }
        }
    }

    let mut response = s3_client
        .list_objects_v2()
        .bucket(bucket)
        .prefix("uploads/")
        .into_paginator()
        .send();

    let mut groups: std::collections::HashMap<String, ShareGroup> = std::collections::HashMap::new();

    while let Some(result) = response.next().await {
        let page = result?;
        for object in page.contents() {
            if let (Some(key), Some(last_modified)) = (object.key(), object.last_modified()) {
                let mod_secs = last_modified.secs();
                let rel = key.strip_prefix("uploads/").unwrap_or(key);
                let parts: Vec<&str> = rel.splitn(2, '/').collect();
                let uuid = if !parts.is_empty() { parts[0].to_string() } else { "root".to_string() };

                let entry = groups.entry(uuid).or_insert_with(|| ShareGroup {
                    has_owner: false,
                    latest_modified_secs: 0,
                    keys: Vec::new(),
                });

                if rel.ends_with("/owner.txt") || rel == "owner.txt" {
                    entry.has_owner = true;
                }
                if mod_secs > entry.latest_modified_secs {
                    entry.latest_modified_secs = mod_secs;
                }
                entry.keys.push(key.to_string());
            }
        }
    }

    let mut keys_to_delete = Vec::new();
    let mut expired_share_uuids = Vec::new();

    for (uuid, group) in groups {
        let age = now - group.latest_modified_secs;
        if group.has_owner {
            if age > share_expire_limit {
                tracing::info!("Completed share '{}' is older than {} days (age: {}s). Marking for deletion.", uuid, share_expiry_days, age);
                keys_to_delete.extend(group.keys);
                expired_share_uuids.push(uuid);
            }
        } else {
            if age > partial_upload_limit {
                tracing::info!("Partial/cancelled upload '{}' has no owner record and is inactive (age: {}s). Marking for cleanup.", uuid, age);
                keys_to_delete.extend(group.keys);
            }
        }
    }

    // Prune expired shares from owner index files before deleting S3 objects
    for uuid in &expired_share_uuids {
        let owner_key = format!("uploads/{}/owner.txt", uuid);
        if let Ok(res) = s3_client.get_object().bucket(bucket).key(&owner_key).send().await {
            if let Ok(bytes) = res.body.collect().await {
                let owner = String::from_utf8(bytes.to_vec()).unwrap_or_default().trim().to_string();
                if !owner.is_empty() {
                    remove_share_from_user_index(s3_client, bucket, &owner, uuid).await;
                }
            }
        }
    }

    if !keys_to_delete.is_empty() {
        tracing::info!("Deleting {} expired/partial S3 objects...", keys_to_delete.len());
        for chunk in keys_to_delete.chunks(1000) {
            let mut delete_builder = aws_sdk_s3::types::Delete::builder();
            for key in chunk {
                let obj_id = aws_sdk_s3::types::ObjectIdentifier::builder()
                    .key(key)
                    .build()?;
                delete_builder = delete_builder.objects(obj_id);
            }
            let delete = delete_builder.build()?;
            s3_client
                .delete_objects()
                .bucket(bucket)
                .delete(delete)
                .send()
                .await?;
        }
        tracing::info!("Cleanup sweep finished successfully.");
    } else {
        tracing::info!("Cleanup sweep completed. No expired or partial objects found.");
    }

    Ok(())
}


use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};


#[derive(serde::Deserialize)]
struct AuthRequest {
    username: String,
    auth_key: String,
}

#[derive(serde::Deserialize)]
struct SaveSharesRequest {
    shares_enc: String,
}

async fn register_user(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<AuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username = payload.username.trim();
    if username.is_empty() || username.len() < 3 || username.len() > 30 {
        return Err((StatusCode::BAD_REQUEST, "Username must be between 3 and 30 characters".to_string()));
    }

    if !username.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err((StatusCode::BAD_REQUEST, "Username can only contain letters, numbers, dashes, and underscores".to_string()));
    }

    let user_key = format!("users/{}.json", username);

    // Check if user already exists
    let user_exists = state.s3_client.head_object()
        .bucket(&state.bucket)
        .key(&user_key)
        .send()
        .await
        .is_ok();

    if user_exists {
        return Err((StatusCode::BAD_REQUEST, "Username is already taken".to_string()));
    }

    // Hash the auth_key with a server salt
    let mut hasher = Sha256::new();
    hasher.update(payload.auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let password_hash = format!("{:02x}", hasher.finalize());

    let user_data = serde_json::json!({
        "password_hash": password_hash
    });
    let user_bytes = serde_json::to_vec(&user_data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Save to S3
    state.s3_client.put_object()
        .bucket(&state.bucket)
        .key(&user_key)
        .content_type("application/json")
        .body(aws_sdk_s3::primitives::ByteStream::from(user_bytes))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save user: {:?}", e)))?;

    Ok(StatusCode::OK)
}

async fn login_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<AuthRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let username = payload.username.trim();
    let user_key = format!("users/{}.json", username);

    // Retrieve user data from S3
    let res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&user_key)
        .send()
        .await
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid username or password".to_string()))?;

    let bytes = res.body.collect().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_bytes();

    let user_json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stored_hash = user_json.get("password_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid user profile data in S3".to_string()))?;

    // Check password hash
    let mut hasher = Sha256::new();
    hasher.update(payload.auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let computed_hash = format!("{:02x}", hasher.finalize());

    if computed_hash != stored_hash {
        return Err((StatusCode::UNAUTHORIZED, "Invalid username or password".to_string()));
    }

    // Generate token with a unique session id (sessions never expire)
    let session_id = uuid::Uuid::new_v4().to_string();
    let expiry = 0;
    let token = generate_token(username, &state.jwt_secret, expiry, &session_id);

    // Extract user agent and IP
    let user_agent = headers.get("user-agent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .or_else(|| headers.get("x-real-ip").and_then(|v| v.to_str().ok()))
        .unwrap_or("Unknown")
        .to_string();

    let new_session = UserSession {
        id: session_id,
        created_at: chrono::Utc::now().timestamp(),
        user_agent,
        ip,
        expires_at: expiry,
        name: None,
    };

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    sessions.push(new_session);

    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        let _ = state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(&sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await;
    }

    let pfp_enc = fetch_user_pfp_enc(&state, username).await;

    Ok(axum::Json(serde_json::json!({
        "token": token,
        "pfp_enc": pfp_enc,
        "pfp": pfp_enc
    })))
}

async fn get_user_shares(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let shares_key = format!("users/{}/shares.enc", username);

    // Fetch from S3
    let res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&shares_key)
        .send()
        .await;

    match res {
        Ok(output) => {
            let bytes = output.body.collect().await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                .into_bytes();
            
            // Hex encode to send in JSON
            let shares_hex = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
            Ok(axum::Json(serde_json::json!({ "shares_enc": shares_hex })))
        }
        Err(_) => {
            // S3 NoSuchKey means no shares yet
            Ok(axum::Json(serde_json::json!({ "shares_enc": "" })))
        }
    }
}

async fn save_user_shares(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<SaveSharesRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    // Decode hex string back to bytes
    let mut bytes = Vec::new();
    let shares_hex = payload.shares_enc.trim();
    for i in (0..shares_hex.len()).step_by(2) {
        if i + 2 > shares_hex.len() { break; }
        let byte_str = &shares_hex[i..i+2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid encrypted payload hex encoding".to_string()))?;
        bytes.push(byte);
    }

    let shares_key = format!("users/{}/shares.enc", username);

    // Write to S3
    state.s3_client.put_object()
        .bucket(&state.bucket)
        .key(&shares_key)
        .content_type("application/octet-stream")
        .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save shares to S3: {:?}", e)))?;

    Ok(StatusCode::OK)
}

fn extract_token(headers: &axum::http::HeaderMap) -> Result<String, (StatusCode, String)> {
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Authorization header is missing".to_string()))?;
    
    let auth_str = auth_header.to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid authorization header characters".to_string()))?;

    if !auth_str.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, "Authorization scheme must be Bearer".to_string()));
    }

    Ok(auth_str[7..].to_string())
}

type HmacSha256 = Hmac<Sha256>;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct UserSession {
    id: String,
    created_at: i64,
    user_agent: String,
    ip: String,
    expires_at: i64,
    #[serde(default)]
    name: Option<String>,
}

fn generate_token(username: &str, secret: &[u8], expiry_timestamp: i64, session_id: &str) -> String {
    let payload = format!("{}:{}:{}", username, expiry_timestamp, session_id);
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(payload.as_bytes());
    let signature = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    let username_hex = username.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    format!("{}.{}.{}.{}", username_hex, expiry_timestamp, session_id, signature)
}

fn verify_token_signature(token: &str, secret: &[u8]) -> Option<(String, i64, String)> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let username_hex = parts[0];
    let expiry_str = parts[1];
    let session_id = parts[2];
    let signature = parts[3];
    
    let expiry_timestamp = expiry_str.parse::<i64>().ok()?;
    
    let mut username_bytes = Vec::new();
    for i in (0..username_hex.len()).step_by(2) {
        if i + 2 > username_hex.len() { break; }
        let byte_str = &username_hex[i..i+2];
        let byte = u8::from_str_radix(byte_str, 16).ok()?;
        username_bytes.push(byte);
    }
    let username = String::from_utf8(username_bytes).ok()?;
    
    let payload = format!("{}:{}:{}", username, expiry_timestamp, session_id);
    let mut mac = HmacSha256::new_from_slice(secret).ok()?;
    mac.update(payload.as_bytes());
    let expected_sig = mac.finalize().into_bytes().iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    if expected_sig == signature {
        Some((username, expiry_timestamp, session_id.to_string()))
    } else {
        None
    }
}

async fn verify_session(token: &str, state: &AppState) -> Option<(String, String)> {
    let (username, _expiry, session_id) = verify_token_signature(token, &state.jwt_secret)?;
    
    let sessions_key = format!("users/{}/sessions.json", username);
    let res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await;
        
    match res {
        Ok(output) => {
            let bytes = output.body.collect().await.ok()?.into_bytes();
            let sessions: Vec<UserSession> = serde_json::from_slice(&bytes).ok()?;
            
            let exists = sessions.iter().any(|s| s.id == session_id);
            if exists {
                Some((username, session_id))
            } else {
                None
            }
        }
        Err(_) => None,
    }
}

// --- ADMIN HANDLERS ---

async fn admin_get_stats(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let mut response = state.s3_client
        .list_objects_v2()
        .bucket(&state.bucket)
        .prefix("users/")
        .into_paginator()
        .send();

    let mut users_list = Vec::new();

    while let Some(result) = response.next().await {
        let page = result.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        for object in page.contents() {
            if let Some(key) = object.key() {
                if key.starts_with("users/") && key.ends_with(".json") {
                    let relative = key.strip_prefix("users/").unwrap_or(key);
                    if !relative.contains('/') {
                        let username = relative.strip_suffix(".json").unwrap_or(relative).to_string();
                        users_list.push(username);
                    }
                }
            }
        }
    }

    let mut stats = Vec::new();

    for username in users_list {
        let public_shares_key = format!("users/{}/public_shares.json", username);
        let shares = match state.s3_client.get_object()
            .bucket(&state.bucket)
            .key(&public_shares_key)
            .send()
            .await
        {
            Ok(output) => {
                if let Ok(bytes) = output.body.collect().await {
                    serde_json::from_slice::<Vec<serde_json::Value>>(&bytes.into_bytes()).unwrap_or_default()
                } else {
                    Vec::new()
                }
            }
            Err(_) => Vec::new(),
        };

        let total_size: i64 = shares.iter()
            .map(|s| s.get("total_size").and_then(|sz| sz.as_i64()).unwrap_or(0))
            .sum();

        stats.push(serde_json::json!({
            "username": username,
            "total_size": total_size,
            "shares": shares
        }));
    }

    Ok(axum::Json(stats))
}

async fn admin_delete_share(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(uuid): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let owner_key = format!("uploads/{}/owner.txt", uuid);
    let owner_res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&owner_key)
        .send()
        .await;

    let owner = match owner_res {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                String::from_utf8(bytes.to_vec()).unwrap_or_default().trim().to_string()
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    };

    delete_share_objects(&state.s3_client, &state.bucket, &uuid).await?;

    if !owner.is_empty() {
        remove_share_from_user_index(&state.s3_client, &state.bucket, &owner, &uuid).await;
    } else {
        if let Ok(response) = state.s3_client.list_objects_v2().bucket(&state.bucket).prefix("users/").send().await {
            for object in response.contents() {
                if let Some(key) = object.key() {
                    if key.ends_with("/public_shares.json") {
                        if let Some(user_part) = key.strip_prefix("users/").and_then(|k| k.strip_suffix("/public_shares.json")) {
                            remove_share_from_user_index(&state.s3_client, &state.bucket, user_part, &uuid).await;
                        }
                    }
                }
            }
        }
    }

    Ok(StatusCode::OK)
}

async fn admin_delete_user(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(username): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let username = username.trim();
    if username.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Username is empty".to_string()));
    }

    let public_shares_key = format!("users/{}/public_shares.json", username);
    if let Ok(output) = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&public_shares_key)
        .send()
        .await
    {
        if let Ok(bytes) = output.body.collect().await {
            if let Ok(shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes.into_bytes()) {
                for share in shares {
                    if let Some(uuid) = share.get("uuid").and_then(|u| u.as_str()) {
                        let _ = delete_share_objects(&state.s3_client, &state.bucket, uuid).await;
                    }
                }
            }
        }
    }

    let user_profile_key = format!("users/{}.json", username);
    let user_folder_prefix = format!("users/{}/", username);

    let _ = state.s3_client.delete_object().bucket(&state.bucket).key(&user_profile_key).send().await;
    let _ = delete_s3_prefix(&state.s3_client, &state.bucket, &user_folder_prefix).await;

    Ok(StatusCode::OK)
}

async fn verify_admin_session(token: &str, state: &AppState) -> bool {
    let (username, _expiry, session_id) = match verify_token_signature(token, &state.jwt_secret) {
        Some(val) => val,
        None => return false,
    };
    
    if username != "admin" {
        return false;
    }
    
    let sessions_key = "admin/sessions.json";
    let res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(sessions_key)
        .send()
        .await;
        
    match res {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                let sessions: Vec<UserSession> = match serde_json::from_slice(&bytes.into_bytes()) {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                sessions.iter().any(|s| s.id == session_id)
            } else {
                false
            }
        }
        Err(_) => false,
    }
}

async fn verify_admin(headers: &axum::http::HeaderMap, state: &AppState) -> Result<(), (StatusCode, String)> {
    let admin_token_env = std::env::var("ADMIN_TOKEN")
        .map_err(|_| (StatusCode::FORBIDDEN, "Admin panel is disabled".to_string()))?;
    
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Authorization header missing".to_string()))?;
    
    let auth_str = auth_header.to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid authorization characters".to_string()))?;

    if !auth_str.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, "Authorization scheme must be Bearer".to_string()));
    }

    let token = &auth_str[7..];
    if token == admin_token_env {
        return Ok(());
    }

    if verify_admin_session(token, state).await {
        return Ok(());
    }

    Err((StatusCode::FORBIDDEN, "Invalid admin token".to_string()))
}

async fn delete_s3_prefix(s3_client: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> Result<(), (StatusCode, String)> {
    if let Ok(mp_out) = s3_client.list_multipart_uploads().bucket(bucket).prefix(prefix).send().await {
        if let Some(uploads) = mp_out.uploads {
            for u in uploads {
                if let (Some(key), Some(upload_id)) = (u.key(), u.upload_id()) {
                    let _ = s3_client.abort_multipart_upload()
                        .bucket(bucket)
                        .key(key)
                        .upload_id(upload_id)
                        .send()
                        .await;
                }
            }
        }
    }

    let mut response = s3_client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .into_paginator()
        .send();

    let mut keys_to_delete = Vec::new();

    while let Some(result) = response.next().await {
        let page = result.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        for object in page.contents() {
            if let Some(key) = object.key() {
                keys_to_delete.push(key.to_string());
            }
        }
    }

    if !keys_to_delete.is_empty() {
        for chunk in keys_to_delete.chunks(1000) {
            let mut delete_builder = aws_sdk_s3::types::Delete::builder();
            for key in chunk {
                let obj_id = aws_sdk_s3::types::ObjectIdentifier::builder()
                    .key(key)
                    .build()
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
                delete_builder = delete_builder.objects(obj_id);
            }
            let delete = delete_builder.build()
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

            s3_client
                .delete_objects()
                .bucket(bucket)
                .delete(delete)
                .send()
                .await
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        }
    }

    Ok(())
}

async fn delete_share_objects(s3_client: &aws_sdk_s3::Client, bucket: &str, uuid: &str) -> Result<(), (StatusCode, String)> {
    let prefix = format!("uploads/{}/", uuid);
    delete_s3_prefix(s3_client, bucket, &prefix).await
}

async fn fetch_user_pfp_enc(state: &AppState, username: &str) -> String {
    let pfp_key = format!("users/{}/pfp.enc", username);
    match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&pfp_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                let vec = bytes.into_bytes().to_vec();
                vec.iter().map(|b| format!("{:02x}", b)).collect::<String>()
            } else {
                String::new()
            }
        }
        Err(_) => String::new(),
    }
}

async fn get_user_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let pfp_enc = fetch_user_pfp_enc(&state, &username).await;

    Ok(axum::Json(serde_json::json!({
        "username": username,
        "pfp_enc": pfp_enc,
        "pfp": pfp_enc
    })))
}

#[derive(serde::Deserialize)]
struct SaveProfileRequest {
    #[serde(default)]
    pfp_enc: String,
    #[serde(default)]
    pfp: String,
}

async fn save_user_profile(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<SaveProfileRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    // Clean up legacy base64 pfp from users/{username}.json if present
    let user_key = format!("users/{}.json", username);
    if let Ok(res) = state.s3_client.get_object().bucket(&state.bucket).key(&user_key).send().await {
        if let Ok(bytes) = res.body.collect().await {
            if let Ok(mut user_json) = serde_json::from_slice::<serde_json::Value>(&bytes.into_bytes()) {
                if let Some(obj) = user_json.as_object_mut() {
                    if obj.remove("pfp").is_some() {
                        if let Ok(user_bytes) = serde_json::to_vec(&user_json) {
                            let _ = state.s3_client.put_object()
                                .bucket(&state.bucket)
                                .key(&user_key)
                                .content_type("application/json")
                                .body(aws_sdk_s3::primitives::ByteStream::from(user_bytes))
                                .send()
                                .await;
                        }
                    }
                }
            }
        }
    }

    let hex_data = if !payload.pfp_enc.is_empty() {
        payload.pfp_enc
    } else {
        payload.pfp
    };

    let pfp_key = format!("users/{}/pfp.enc", username);

    if hex_data.trim().is_empty() {
        let _ = state.s3_client.delete_object()
            .bucket(&state.bucket)
            .key(&pfp_key)
            .send()
            .await;
    } else {
        let mut bytes = Vec::new();
        let hex_str = hex_data.trim();
        for i in (0..hex_str.len()).step_by(2) {
            if i + 2 > hex_str.len() { break; }
            let byte_str = &hex_str[i..i+2];
            let byte = u8::from_str_radix(byte_str, 16)
                .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid encrypted payload hex encoding".to_string()))?;
            bytes.push(byte);
        }

        if bytes.len() > 12_000_000 {
            return Err((StatusCode::BAD_REQUEST, "Profile picture too large".to_string()));
        }

        state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(&pfp_key)
            .content_type("application/octet-stream")
            .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update profile picture: {:?}", e)))?;
    }

    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
struct ChangePasswordRequest {
    current_auth_key: String,
    new_auth_key: String,
    new_shares_enc: String,
    #[serde(default)]
    new_pfp_enc: Option<String>,
}

async fn user_change_password(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, current_session_id) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let user_key = format!("users/{}.json", username);

    let res = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&user_key)
        .send()
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "User profile not found".to_string()))?;

    let bytes = res.body.collect().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .into_bytes();

    let mut user_json: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let stored_hash = user_json.get("password_hash")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Invalid user profile data in S3".to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(payload.current_auth_key.as_bytes());
    hasher.update(b"server-salt-dill-share");
    let computed_hash = format!("{:02x}", hasher.finalize());

    if computed_hash != stored_hash {
        return Err((StatusCode::UNAUTHORIZED, "Incorrect current password".to_string()));
    }

    let mut new_hasher = Sha256::new();
    new_hasher.update(payload.new_auth_key.as_bytes());
    new_hasher.update(b"server-salt-dill-share");
    let new_password_hash = format!("{:02x}", new_hasher.finalize());

    if let Some(obj) = user_json.as_object_mut() {
        obj.insert("password_hash".to_string(), serde_json::Value::String(new_password_hash));
    }

    let user_bytes = serde_json::to_vec(&user_json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    state.s3_client.put_object()
        .bucket(&state.bucket)
        .key(&user_key)
        .content_type("application/json")
        .body(aws_sdk_s3::primitives::ByteStream::from(user_bytes))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update profile: {:?}", e)))?;

    let mut enc_bytes = Vec::new();
    let shares_hex = payload.new_shares_enc.trim();
    for i in (0..shares_hex.len()).step_by(2) {
        if i + 2 > shares_hex.len() { break; }
        let byte_str = &shares_hex[i..i+2];
        let byte = u8::from_str_radix(byte_str, 16)
            .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid encrypted payload hex encoding".to_string()))?;
        enc_bytes.push(byte);
    }

    let shares_key = format!("users/{}/shares.enc", username);
    state.s3_client.put_object()
        .bucket(&state.bucket)
        .key(&shares_key)
        .content_type("application/octet-stream")
        .body(aws_sdk_s3::primitives::ByteStream::from(enc_bytes))
        .send()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save new shares: {:?}", e)))?;

    if let Some(ref new_pfp) = payload.new_pfp_enc {
        let pfp_key = format!("users/{}/pfp.enc", username);
        if new_pfp.trim().is_empty() {
            let _ = state.s3_client.delete_object()
                .bucket(&state.bucket)
                .key(&pfp_key)
                .send()
                .await;
        } else {
            let mut bytes = Vec::new();
            let hex_str = new_pfp.trim();
            for i in (0..hex_str.len()).step_by(2) {
                if i + 2 > hex_str.len() { break; }
                let byte_str = &hex_str[i..i+2];
                if let Ok(byte) = u8::from_str_radix(byte_str, 16) {
                    bytes.push(byte);
                }
            }
            let _ = state.s3_client.put_object()
                .bucket(&state.bucket)
                .key(&pfp_key)
                .content_type("application/octet-stream")
                .body(aws_sdk_s3::primitives::ByteStream::from(bytes))
                .send()
                .await;
        }
    }

    // Revoke all OTHER sessions of this user upon password change (forces relogin on other devices)
    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    sessions.retain(|s| s.id == current_session_id);

    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        let _ = state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(&sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await;
    }

    Ok(StatusCode::OK)
}

async fn user_delete_account(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let public_shares_key = format!("users/{}/public_shares.json", username);
    if let Ok(output) = state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&public_shares_key)
        .send()
        .await
    {
        if let Ok(bytes) = output.body.collect().await {
            if let Ok(shares) = serde_json::from_slice::<Vec<serde_json::Value>>(&bytes.into_bytes()) {
                for share in shares {
                    if let Some(uuid) = share.get("uuid").and_then(|u| u.as_str()) {
                        let _ = delete_share_objects(&state.s3_client, &state.bucket, uuid).await;
                    }
                }
            }
        }
    }

    let user_profile_key = format!("users/{}.json", username);
    let user_folder_prefix = format!("users/{}/", username);

    let _ = state.s3_client.delete_object().bucket(&state.bucket).key(&user_profile_key).send().await;
    let _ = delete_s3_prefix(&state.s3_client, &state.bucket, &user_folder_prefix).await;

    Ok(StatusCode::OK)
}

async fn generate_and_save_jwt_secret(s3_client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> Vec<u8> {
    let secret = [
        uuid::Uuid::new_v4().into_bytes().to_vec(),
        uuid::Uuid::new_v4().into_bytes().to_vec(),
    ].concat();

    let _ = s3_client.put_object()
        .bucket(bucket)
        .key(key)
        .content_type("application/octet-stream")
        .body(aws_sdk_s3::primitives::ByteStream::from(secret.clone()))
        .send()
        .await;

    secret
}

async fn get_user_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, current_session_id) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let mut response_sessions = Vec::new();

    for s in sessions {
        let is_current = s.id == current_session_id;
        response_sessions.push(serde_json::json!({
            "id": s.id,
            "created_at": s.created_at,
            "user_agent": s.user_agent,
            "ip": s.ip,
            "expires_at": s.expires_at,
            "is_current": is_current,
            "name": s.name,
        }));
    }

    Ok(axum::Json(response_sessions))
}

async fn revoke_user_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _current_session_id) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let original_len = sessions.len();
    sessions.retain(|s| s.id != session_id);

    if sessions.len() < original_len {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(&sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update sessions: {:?}", e)))?;
    }

    Ok(StatusCode::OK)
}

#[derive(serde::Deserialize)]
struct RenameSessionRequest {
    name: String,
}

async fn rename_user_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<RenameSessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let token = extract_token(&headers)?;
    let (username, _current_session_id) = verify_session(&token, &state)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Invalid or expired session".to_string()))?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let clean_name = payload.name.trim();
    let truncated_name: String = clean_name.chars().take(32).collect();
    let new_name_opt = if truncated_name.is_empty() { None } else { Some(truncated_name) };

    let mut updated = false;
    for s in sessions.iter_mut() {
        if s.id == session_id {
            s.name = new_name_opt.clone();
            updated = true;
            break;
        }
    }

    if updated {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(&sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update session: {:?}", e)))?;
    }

    Ok(StatusCode::OK)
}

async fn admin_get_user_sessions(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let mut response_sessions = Vec::new();

    for s in sessions {
        response_sessions.push(serde_json::json!({
            "id": s.id,
            "created_at": s.created_at,
            "user_agent": s.user_agent,
            "ip": s.ip,
            "expires_at": s.expires_at,
            "is_current": false,
            "name": s.name,
        }));
    }

    Ok(axum::Json(response_sessions))
}

async fn admin_revoke_user_session(
    State(state): State<AppState>,
    Path((username, session_id)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = format!("users/{}/sessions.json", username);
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(&sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let original_len = sessions.len();
    sessions.retain(|s| s.id != session_id);

    if sessions.len() < original_len {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(&sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update sessions: {:?}", e)))?;
    }

    Ok(StatusCode::OK)
}

async fn admin_login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let admin_token_env = std::env::var("ADMIN_TOKEN")
        .map_err(|_| (StatusCode::FORBIDDEN, "Admin panel is disabled".to_string()))?;
        
    let auth_header = headers.get(axum::http::header::AUTHORIZATION)
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "Authorization header missing".to_string()))?;
    
    let auth_str = auth_header.to_str()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid authorization characters".to_string()))?;

    if !auth_str.starts_with("Bearer ") {
        return Err((StatusCode::UNAUTHORIZED, "Authorization scheme must be Bearer".to_string()));
    }

    let token = &auth_str[7..];
    if token != admin_token_env {
        return Err((StatusCode::FORBIDDEN, "Invalid admin token".to_string()));
    }
    
    let expiry = 0;
    let session_id = uuid::Uuid::new_v4().to_string();
    let session_token = generate_token("admin", &state.jwt_secret, expiry, &session_id);
    
    let ip = headers.get("x-forwarded-for")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
    let user_agent = headers.get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("Unknown")
        .to_string();
        
    let new_session = UserSession {
        id: session_id,
        created_at: chrono::Utc::now().timestamp(),
        user_agent,
        ip,
        expires_at: expiry,
        name: None,
    };
    
    let sessions_key = "admin/sessions.json";
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };
    
    sessions.push(new_session);
    
    if let Ok(session_bytes) = serde_json::to_vec(&sessions) {
        state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save admin session: {:?}", e)))?;
    }
    
    Ok(axum::Json(serde_json::json!({ "token": session_token })))
}

async fn admin_get_sessions(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = "admin/sessions.json";
    let sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let mut response_sessions = Vec::new();

    let current_session_id = if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                verify_token_signature(token, &state.jwt_secret)
                    .map(|(_, _, session_id)| session_id)
            } else { None }
        } else { None }
    } else { None };

    for s in sessions {
        let is_current = current_session_id.as_ref() == Some(&s.id);
        response_sessions.push(serde_json::json!({
            "id": s.id,
            "created_at": s.created_at,
            "user_agent": s.user_agent,
            "ip": s.ip,
            "expires_at": s.expires_at,
            "is_current": is_current,
            "name": s.name,
        }));
    }

    Ok(axum::Json(response_sessions))
}

async fn admin_revoke_session(
    State(state): State<AppState>,
    Path(session_id): Path<String>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = "admin/sessions.json";
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let original_len = sessions.len();
    sessions.retain(|s| s.id != session_id);

    if sessions.len() < original_len {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update sessions: {:?}", e)))?;
    }

    Ok(StatusCode::OK)
}

async fn admin_rename_session(
    State(state): State<AppState>,
    axum::extract::Path(session_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    axum::Json(payload): axum::Json<RenameSessionRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    verify_admin(&headers, &state).await?;

    let sessions_key = "admin/sessions.json";
    let mut sessions: Vec<UserSession> = match state.s3_client.get_object()
        .bucket(&state.bucket)
        .key(sessions_key)
        .send()
        .await
    {
        Ok(output) => {
            if let Ok(bytes) = output.body.collect().await {
                serde_json::from_slice(&bytes.into_bytes()).unwrap_or_default()
            } else {
                Vec::new()
            }
        }
        Err(_) => Vec::new(),
    };

    let clean_name = payload.name.trim();
    let truncated_name: String = clean_name.chars().take(32).collect();
    let new_name_opt = if truncated_name.is_empty() { None } else { Some(truncated_name) };

    let mut updated = false;
    for s in sessions.iter_mut() {
        if s.id == session_id {
            s.name = new_name_opt.clone();
            updated = true;
            break;
        }
    }

    if updated {
        let session_bytes = serde_json::to_vec(&sessions)
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        state.s3_client.put_object()
            .bucket(&state.bucket)
            .key(sessions_key)
            .content_type("application/json")
            .body(aws_sdk_s3::primitives::ByteStream::from(session_bytes))
            .send()
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update admin session: {:?}", e)))?;
    }

    Ok(StatusCode::OK)
}
