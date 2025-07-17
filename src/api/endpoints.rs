use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{self, Path},
};

use crate::{api::state::AppState, model::apperror::ApplicationError};

/**
 * Endpoint to retrieve a list of statistics types.
 */
#[get("/statistics")]
pub async fn statistics_list(http_request: HttpRequest, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    app_state.jwt_service.validate(&http_request)?;
    Err(ApplicationError::new(crate::model::apperror::ErrorType::NotImplementedError, "Not implemented".to_string()))
}

/**
 * Add a new statistics type.
 */
#[post("/statistics")]
pub async fn statistics_add() -> &'static str {
    "statistics add"
}

/**
 * Delete statistics type.
 */
#[delete("/statistics/{statisticsId}")]
pub async fn statistics_delete(path: Path<u64>) -> &'static str {
    "statistics delete"
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[get("/municipalities")]
pub async fn municipalities_list() -> &'static str {
    "municipalities list"
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[post("/municipalities")]
pub async fn municipalities_add() -> &'static str {
    "municipalities add"
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[delete("/municipalities/{municipalityId}")]
pub async fn municipalities_delete(path: Path<u64>) -> &'static str {
    "municipalities delete"
}

/**
 * Endpoint to add values.
 */
#[get("/values:list")]
pub async fn values_list() -> &'static str {
    "values list"
}

/**
 * Endpoint to add values.
 */
#[post("/values")]
pub async fn value_add() -> &'static str {
    "value add"
}

/**
 * Endpoint to delete values.
 */
#[delete("/values/{valueId}")]
pub async fn value_delete(path: Path<u64>) -> &'static str {
    "value delete"
}

/**
 * Endpoint to delete values.
 */
#[put("/values/{valueId}")]
pub async fn value_update(path: Path<u64>) -> &'static str {
    "value update"
}
