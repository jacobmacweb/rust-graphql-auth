use std::{io, sync::Arc};

use actix_cors::Cors;
use actix_web::{
    get, middleware, route,
    web::{self, Data},
    App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use actix_web_lab::respond::Html;
use juniper::http::{graphiql::graphiql_source, GraphQLRequest};
use sqlx::{Pool, Sqlite};
#[macro_use]
extern crate juniper;
mod db;
mod objects;
mod schema;
use crate::{
    objects::auth::check_authorization_header,
    schema::{create_schema, Context, Schema},
};
use dotenv::dotenv;

#[get("/graphiql")]
async fn graphql_playground() -> impl Responder {
    Html(graphiql_source("/graphql", None))
}

/// GraphQL endpoint
#[route("/graphql", method = "GET", method = "POST")]
async fn graphql(
    st: web::Data<Schema>,
    pool: web::Data<Pool<Sqlite>>,
    data: web::Json<GraphQLRequest>,
    // Use to get header to mark user as authenticated or not
    req: HttpRequest,
) -> impl Responder {
    let user = check_authorization_header(
        req.headers()
            .get("Authorization")
            .map(|header| header.to_str().unwrap_or("")),
        pool.get_ref(),
    )
    .await;
    let ctx = Context {
        pool: pool.get_ref().clone(),
        user,
    };

    let user = data.execute(&st, &ctx).await;
    HttpResponse::Ok().json(user)
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    dotenv().ok();
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    // Create Juniper schema
    let schema = Arc::new(create_schema());
    let pool = db::create_connection().await.unwrap();

    log::info!("Starting HTTP server on port 8080");
    log::info!("GraphiQL playground: http://localhost:8080/graphiql");

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(Data::from(schema.clone()))
            .app_data(Data::new(pool.clone()))
            .service(graphql)
            .service(graphql_playground)
            // the graphiql UI requires CORS to be enabled
            .wrap(Cors::permissive())
            .wrap(middleware::Logger::default())
    })
    .workers(2)
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
