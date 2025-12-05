# Vortex Rust SDK Demo

A demo application showcasing the Vortex Rust SDK integration with Axum web framework.

## Features

- 🔐 **Authentication System**: Cookie-based auth with JWT tokens
- ⚡ **Vortex Integration**: Full Vortex API integration for invitation management
- 🎯 **JWT Generation**: Generate Vortex JWTs for authenticated users
- 📧 **Invitation Management**: Get, accept, revoke, and reinvite functionality
- 👥 **Group Management**: Handle invitations by group type and ID
- 🌐 **Interactive Frontend**: Complete HTML interface to test all features

## Prerequisites

- Rust 1.70 or later
- The Vortex Rust SDK (automatically linked via workspace)

## Installation

1. Navigate to the demo directory:

   ```bash
   cd apps/demo-rust
   ```

2. Build the project:
   ```bash
   cargo build
   ```

## Running the Demo

1. Set your Vortex API key (optional - defaults to demo key):

   ```bash
   export VORTEX_API_KEY=your-api-key-here
   ```

2. Run the server:

   ```bash
   cargo run
   ```

3. Open your browser and visit: `http://localhost:3000`

## Demo Users

The demo includes two pre-configured users:

| Email             | Password    | Autojoin Admin |
| ----------------- | ----------- | --------------- |
| admin@example.com | password123 | Yes             |
| user@example.com  | userpass    | No              |

## API Endpoints

### Authentication

- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/logout` - Logout current user
- `GET /api/auth/me` - Get current user info
- `GET /api/auth/users` - Get demo users list

### Vortex Integration

- `POST /api/vortex/jwt` - Generate Vortex JWT for current user
- `GET /api/vortex/invitations` - Get invitations by target
- `GET /api/vortex/invitations/:id` - Get a specific invitation by ID
- `DELETE /api/vortex/invitations/:id` - Revoke an invitation
- `POST /api/vortex/invitations/accept` - Accept invitations
- `GET /api/vortex/invitations/by-group/:type/:id` - Get invitations for a group
- `DELETE /api/vortex/invitations/by-group/:type/:id` - Delete invitations for a group
- `POST /api/vortex/invitations/:id/reinvite` - Reinvite a user

### Demo Routes

- `GET /api/demo/protected` - Protected route example
- `GET /api/demo/users` - Get demo users list

### Health Check

- `GET /health` - Server health status

## JWT Format

This demo uses Vortex's **new JWT format with User builder pattern**:

```rust
// Create a user with the builder pattern
let user = vortex_sdk::User::new(&user_id, &user_email)
    .with_admin_scopes(vec!["autojoin".to_string()]);

// Generate JWT
let jwt = vortex_client.generate_jwt(&user, None)?;

// Or with extra properties
let extra = std::collections::HashMap::from([
    ("role".to_string(), serde_json::json!("admin")),
    ("department".to_string(), serde_json::json!("Engineering")),
]);
let jwt = vortex_client.generate_jwt(&user, Some(extra))?;
```

The JWT payload includes:

- `userId`: User's unique ID
- `userEmail`: User's email address
- `userIsAutojoinAdmin`: Set to `true` when `adminScopes` contains `"autojoin"`
- Any additional properties from the `extra` parameter

This replaces the legacy format with identifiers, groups, and role fields.

## Project Structure

```
demo-rust/
├── src/
│   └── main.rs                # Main application
├── public/
│   └── index.html             # Demo frontend
├── Cargo.toml                 # Dependencies
└── README.md                  # This file
```

## Development

To run in development mode with auto-reload (using cargo-watch):

```bash
cargo install cargo-watch
cargo watch -x run
```

## License

MIT
