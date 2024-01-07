use juniper::{EmptySubscription, FieldError, FieldResult, RootNode};
use juniper_compose::{composable_object, composite_object};
use sqlx::SqlitePool;

use crate::db::models::User;

pub struct Context {
    pub pool: SqlitePool,
    pub user: Option<User>,
}

impl juniper::Context for Context {}

impl Context {
    /**
     * This will return a user if the token is valid, otherwise it will abort the request. Use
     * context.user to get the user and not abort the request, this will be None if the
     * token is invalid.
     */

    pub fn require_user(&self) -> FieldResult<&User> {
        self.user
            .as_ref()
            .ok_or_else(|| FieldError::from("Unauthorized, valid token required"))
    }
}

// Testing juniper compose
#[derive(Default)]
pub struct TestQueries;

#[composable_object]
#[juniper::graphql_object(Context = Context)]
impl TestQueries {
    fn api_version() -> &'static str {
        "1.0"
    }
}

composite_object!(pub RootQuery<Context = Context>(TestQueries, crate::objects::auth::AuthQueries));
composite_object!(pub RootMutation<Context = Context>(crate::objects::auth::AuthMutations));

pub type Schema = RootNode<'static, RootQuery, RootMutation, EmptySubscription<Context>>;

pub fn create_schema() -> Schema {
    Schema::new(RootQuery, RootMutation, EmptySubscription::new())
}
