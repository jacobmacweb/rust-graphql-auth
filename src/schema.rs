use juniper::{EmptySubscription, FieldError, FieldResult, RootNode};
use juniper::{GraphQLInputObject, GraphQLObject};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use juniper_compose::{composable_object, composite_object};
use serde::{Deserialize, Serialize};

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

// Testing juniper compose
#[derive(Default)]
pub struct TestQueries;

#[composable_object]
#[juniper::graphql_object]
impl TestQueries {
    fn api_version() -> &'static str {
        "1.0"
    }
}

#[derive(Default)]
pub struct AuthQueries;

#[composable_object]
#[juniper::graphql_object]
impl AuthQueries {
    fn who_am_i(cred: AuthVariables) -> FieldResult<IdentityResponse> {
        // Decode cred.token
        let token = decode::<Claims>(
            &cred.token,
            &DecodingKey::from_secret("secret".as_ref()),
            &Validation::default(),
        );

        match token {
            Ok(token) => Ok(IdentityResponse {
                username: token.claims.sub,
            }),
            Err(_) => Err(FieldError::from("Invalid token")),
        }
    }
}

#[derive(Default)]
pub struct AuthMutations;

#[composable_object]
#[juniper::graphql_object]
impl AuthMutations {
    fn login(cred: LoginVariables) -> FieldResult<AuthResponse> {
        // Just make a fake token
        let claims = Claims {
            sub: cred.username,
            exp: 10000000000,
        };

        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret("secret".as_ref()),
        )?;

        Ok(AuthResponse { token })
    }
}

composite_object!(pub RootQuery(TestQueries, AuthQueries));
composite_object!(pub RootMutation(AuthMutations));

pub type Schema = RootNode<'static, RootQuery, RootMutation, EmptySubscription>;

pub fn create_schema() -> Schema {
    Schema::new(RootQuery, RootMutation, EmptySubscription::new())
}
