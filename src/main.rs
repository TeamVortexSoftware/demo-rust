use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Json},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_cookies::{Cookie, CookieManagerLayer, Cookies};
use tower_http::services::ServeDir;
use vortex_sdk::{Group, Identifier, InvitationTarget, VortexClient};

#[derive(Clone)]
struct AppState {
    vortex: Arc<VortexClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DemoUser {
    id: String,
    email: String,
    #[serde(skip_serializing, default)]
    password: String,
    name: String,
    role: String,
    groups: Vec<UserGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserGroup {
    #[serde(rename = "type")]
    group_type: String,
    id: String,
    name: String,
}

fn demo_users() -> Vec<DemoUser> {
    vec![
        DemoUser {
            id: "user-1".to_string(),
            email: "admin@example.com".to_string(),
            password: "password123".to_string(),
            name: "Admin User".to_string(),
            role: "admin".to_string(),
            groups: vec![
                UserGroup {
                    group_type: "team".to_string(),
                    id: "team-1".to_string(),
                    name: "Engineering".to_string(),
                },
                UserGroup {
                    group_type: "organization".to_string(),
                    id: "org-1".to_string(),
                    name: "Acme Corp".to_string(),
                },
            ],
        },
        DemoUser {
            id: "user-2".to_string(),
            email: "user@example.com".to_string(),
            password: "userpass".to_string(),
            name: "Regular User".to_string(),
            role: "user".to_string(),
            groups: vec![UserGroup {
                group_type: "team".to_string(),
                id: "team-1".to_string(),
                name: "Engineering".to_string(),
            }],
        },
    ]
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    success: bool,
    user: DemoUser,
}

#[derive(Deserialize)]
struct GetInvitationsQuery {
    #[serde(rename = "targetType")]
    target_type: String,
    #[serde(rename = "targetValue")]
    target_value: String,
}

#[derive(Deserialize)]
struct AcceptInvitationsRequest {
    #[serde(rename = "invitationIds")]
    invitation_ids: Vec<String>,
    target: InvitationTarget,
}

// Auth handlers
async fn login(cookies: Cookies, Json(req): Json<LoginRequest>) -> impl IntoResponse {
    eprintln!("login: attempting login for {}", req.email);
    let users = demo_users();
    let user = users
        .iter()
        .find(|u| u.email == req.email && u.password == req.password);

    match user {
        Some(user) => {
            eprintln!("login: user found, setting cookie");
            let user_json = serde_json::to_string(user).unwrap();
            eprintln!("login: user_json = {}", user_json);
            let mut cookie = Cookie::new("session", user_json);
            cookie.set_path("/");
            cookie.set_http_only(true);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Lax);
            // Don't set secure in development
            cookies.add(cookie);
            eprintln!("login: cookie added successfully");
            Json(LoginResponse {
                success: true,
                user: user.clone(),
            })
            .into_response()
        }
        None => (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid credentials"})),
        )
            .into_response(),
    }
}

async fn logout(cookies: Cookies) -> impl IntoResponse {
    let mut cookie = Cookie::named("session");
    cookie.set_path("/");
    cookies.remove(cookie);
    Json(serde_json::json!({"success": true}))
}

async fn get_me(cookies: Cookies) -> impl IntoResponse {
    eprintln!("get_me: checking cookies...");
    if let Some(cookie) = cookies.get("session") {
        eprintln!("get_me: found session cookie");
        match serde_json::from_str::<DemoUser>(cookie.value()) {
            Ok(user) => {
                eprintln!("get_me: successfully parsed user: {}", user.email);
                return Json(user).into_response();
            }
            Err(e) => {
                eprintln!("get_me: failed to parse user: {}", e);
            }
        }
    } else {
        eprintln!("get_me: no session cookie found");
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Not authenticated"})),
    )
        .into_response()
}

async fn get_users() -> impl IntoResponse {
    let users = demo_users();
    let user_info: Vec<_> = users
        .iter()
        .map(|u| {
            serde_json::json!({
                "id": u.id,
                "email": u.email,
                "role": u.role,
                "groups": u.groups
            })
        })
        .collect();

    Json(user_info)
}

// Vortex handlers
async fn generate_jwt(State(state): State<AppState>, cookies: Cookies) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("session") {
        if let Ok(user) = serde_json::from_str::<DemoUser>(cookie.value()) {
            let identifiers = vec![Identifier::new("email", &user.email)];
            let groups = user
                .groups
                .iter()
                .map(|g| Group::new(&g.group_type, &g.id, &g.name))
                .collect();

            match state
                .vortex
                .generate_jwt(&user.id, identifiers, groups, Some(&user.role))
            {
                Ok(jwt) => {
                    return Json(serde_json::json!({"jwt": jwt})).into_response();
                }
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": e.to_string()})),
                    )
                        .into_response();
                }
            }
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Not authenticated"})),
    )
        .into_response()
}

async fn get_invitations(
    State(state): State<AppState>,
    cookies: Cookies,
    Query(query): Query<GetInvitationsQuery>,
) -> impl IntoResponse {
    if cookies.get("session").is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state
        .vortex
        .get_invitations_by_target(&query.target_type, &query.target_value)
        .await
    {
        Ok(invitations) => Json(serde_json::json!({"invitations": invitations})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_invitation_by_id(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if cookies.get("session").is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state.vortex.get_invitation(&id).await {
        Ok(invitation) => Json(invitation).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn delete_invitation(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if cookies.get("session").is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state.vortex.revoke_invitation(&id).await {
        Ok(_) => Json(serde_json::json!({"success": true})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn accept_invitations(
    State(state): State<AppState>,
    cookies: Cookies,
    Json(req): Json<AcceptInvitationsRequest>,
) -> impl IntoResponse {
    if cookies.get("session").is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state
        .vortex
        .accept_invitations(req.invitation_ids, req.target)
        .await
    {
        Ok(invitation) => Json(invitation).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn get_invitations_by_group(
    State(state): State<AppState>,
    cookies: Cookies,
    Path((group_type, group_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if cookies.get("session").is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state
        .vortex
        .get_invitations_by_group(&group_type, &group_id)
        .await
    {
        Ok(invitations) => Json(serde_json::json!({"invitations": invitations})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn delete_invitations_by_group(
    State(state): State<AppState>,
    cookies: Cookies,
    Path((group_type, group_id)): Path<(String, String)>,
) -> impl IntoResponse {
    if cookies.get("session").is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state
        .vortex
        .delete_invitations_by_group(&group_type, &group_id)
        .await
    {
        Ok(_) => Json(serde_json::json!({"success": true})).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn reinvite(
    State(state): State<AppState>,
    cookies: Cookies,
    Path(id): Path<String>,
) -> impl IntoResponse {
    if cookies.get("session").is_none() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Not authenticated"})),
        )
            .into_response();
    }

    match state.vortex.reinvite(&id).await {
        Ok(invitation) => Json(invitation).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

async fn protected_route(cookies: Cookies) -> impl IntoResponse {
    if let Some(cookie) = cookies.get("session") {
        if let Ok(user) = serde_json::from_str::<DemoUser>(cookie.value()) {
            return Json(serde_json::json!({
                "message": "This is a protected route!",
                "user": user,
                "timestamp": chrono::Utc::now().to_rfc3339()
            }))
            .into_response();
        }
    }

    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error": "Not authenticated"})),
    )
        .into_response()
}

async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "vortex": {
            "configured": true,
            "routes": [
                "/api/vortex/jwt",
                "/api/vortex/invitations",
                "/api/vortex/invitations/:id",
                "/api/vortex/invitations/accept",
                "/api/vortex/invitations/by-group/:type/:id",
                "/api/vortex/invitations/:id/reinvite"
            ]
        }
    }))
}

#[tokio::main]
async fn main() {
    // Initialize Vortex client
    let api_key = std::env::var("VORTEX_API_KEY").unwrap_or_else(|_| "demo-api-key".to_string());
    let vortex = Arc::new(VortexClient::new(api_key.clone()));

    println!("🚀 Demo Rust server running on port 31337");
    println!("📱 Visit http://localhost:31337 to try the demo");
    println!("🔧 Vortex API routes available at http://localhost:31337/api/vortex");
    println!("📊 Health check: http://localhost:31337/health");
    println!();
    println!("Demo users:");
    println!("  - admin@example.com / password123 (admin role)");
    println!("  - user@example.com / userpass (user role)");

    let state = AppState { vortex };

    // Build routes
    let app = Router::new()
        // Auth routes
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/me", get(get_me))
        .route("/api/auth/users", get(get_users))
        // Vortex routes
        .route("/api/vortex/jwt", post(generate_jwt))
        .route("/api/vortex/invitations", get(get_invitations))
        .route("/api/vortex/invitations/accept", post(accept_invitations))
        .route(
            "/api/vortex/invitations/by-group/:type/:id",
            get(get_invitations_by_group),
        )
        .route(
            "/api/vortex/invitations/by-group/:type/:id",
            delete(delete_invitations_by_group),
        )
        .route("/api/vortex/invitations/:id/reinvite", post(reinvite))
        .route("/api/vortex/invitations/:id", get(get_invitation_by_id))
        .route("/api/vortex/invitations/:id", delete(delete_invitation))
        // Demo routes
        .route("/api/demo/protected", get(protected_route))
        .route("/api/demo/users", get(get_users))
        // Health check
        .route("/health", get(health_check))
        .nest_service("/", ServeDir::new("public"))
        .layer(CookieManagerLayer::new())
        .with_state(state);

    // Start server
    let listener = tokio::net::TcpListener::bind("127.0.0.1:31337")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}
