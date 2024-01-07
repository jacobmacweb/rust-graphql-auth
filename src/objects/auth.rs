use bcrypt::{hash, verify, DEFAULT_COST};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use juniper::{FieldError, FieldResult};
use juniper_compose::{composable_object, composite_object};
use serde::{Deserialize, Serialize};
use sqlx::{query, Executor, SqlitePool};

use crate::{db::models::User, schema::Context};
use chrono::{Duration, Utc};

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    exp: usize,
}

#[derive(GraphQLObject)]
#[graphql(description = "Response with token")]
struct AuthResponse {
    token: String,
}

#[derive(GraphQLObject)]
#[graphql(description = "Response with username")]
struct IdentityResponse {
    username: String,
}

#[derive(GraphQLInputObject)]
#[graphql(description = "Login details")]
struct LoginVariables {
    username: String,
    password: String,
}

#[derive(GraphQLInputObject)]
#[graphql(description = "Login details")]
struct AuthVariables {
    token: String,
}

#[derive(Default)]
pub struct AuthQueries;

#[composable_object]
#[juniper::graphql_object(Context = Context)]
impl AuthQueries {
    fn who_am_i(ctx: &Context) -> FieldResult<IdentityResponse> {
        let user = ctx.require_user()?;

        Ok(IdentityResponse {
            username: user.username.clone(),
        })
    }
}

#[derive(Default)]
pub struct AuthMutations;

#[composable_object]
#[juniper::graphql_object(Context = Context)]
impl AuthMutations {
    async fn login(ctx: &Context, cred: LoginVariables) -> FieldResult<AuthResponse> {
        // Get user from db and compare password
        let res = sqlx::query_as::<_, User>(
            r#"
                SELECT * FROM users WHERE username = $1;
                "#,
        )
        .bind(&cred.username)
        .fetch_one(&ctx.pool)
        .await?;

        let valid = verify(cred.password, &res.password)?;

        if !valid {
            return Err(FieldError::from("Invalid password"));
        }

        let now = Utc::now();
        let thirty_days_from_now = now + Duration::days(30);

        let claims = Claims {
            sub: res.id.to_string(),
            exp: thirty_days_from_now.timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(
                std::env::var("SECRET")
                    .expect("SECRET must be set")
                    .as_ref(),
            ),
        )?;

        Ok(AuthResponse { token })
    }

    async fn register(ctx: &Context, cred: LoginVariables) -> FieldResult<AuthResponse> {
        let mut tx = ctx.pool.begin().await?;

        // insert values and return user
        let hashed = hash(cred.password, DEFAULT_COST)?;
        // TODO: encrypt password
        let res = sqlx::query_as::<_, User>(
            r#"
                INSERT INTO users (username, password)
                VALUES ($1, $2);
                SELECT * FROM users WHERE id = last_insert_rowid();
                "#,
        )
        .bind(&cred.username)
        .bind(&hashed)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;

        let now = Utc::now();
        let thirty_days_from_now = now + Duration::days(30);

        let claims = Claims {
            sub: res.id.to_string(),
            exp: thirty_days_from_now.timestamp() as usize,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(
                std::env::var("SECRET")
                    .expect("SECRET must be set")
                    .as_ref(),
            ),
        )?;

        Ok(AuthResponse { token })
    }
}

pub async fn check_authorization_header(token: Option<&str>, pool: &SqlitePool) -> Option<User> {
    if token.is_none() || token.unwrap().is_empty() {
        return None;
    }

    let token = decode::<Claims>(
        &token.unwrap(),
        &DecodingKey::from_secret(
            std::env::var("SECRET")
                .expect("SECRET must be set")
                .as_ref(),
        ),
        &Validation::default(),
    );

    match token {
        Ok(token) => {
            let user_id = token.claims.sub.parse::<i32>().unwrap();
            let user = sqlx::query_as::<_, User>(
                r#"
                SELECT * FROM users WHERE id = $1;
                "#,
            )
            .bind(user_id)
            .fetch_one(pool)
            .await
            .unwrap();

            Some(user)
        }
        Err(_) => None,
    }
}
