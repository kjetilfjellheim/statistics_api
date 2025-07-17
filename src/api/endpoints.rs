use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{self, Path},
};

use crate::{api::{rest::StatisticsListResponse, state::AppState}, model::apperror::ApplicationError};

/**
 * Endpoint to retrieve a list of statistics types.
 */
#[get("/api/services/v1_0/statistics")]
pub async fn statistics_list(http_request: HttpRequest, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    app_state.jwt_service.validate(&http_request)?;
    let statistics = app_state.statistics_service.get_statistics_list().await?;
    Ok(HttpResponse::Ok().json(StatisticsListResponse::from(statistics)))
}

/**
 * Add a new statistics type.
 */
#[post("/api/services/v1_0/statistics")]
pub async fn statistics_add() -> &'static str {
    "statistics add"
}

/**
 * Delete statistics type.
 */
#[delete("/api/services/v1_0/statistics/{statisticsId}")]
pub async fn statistics_delete(_path: Path<u64>) -> &'static str {
    "statistics delete"
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[get("/api/services/v1_0/municipalities")]
pub async fn municipalities_list() -> &'static str {
    "municipalities list"
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[post("/api/services/v1_0/municipalities")]
pub async fn municipalities_add() -> &'static str {
    "municipalities add"
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[delete("/api/services/v1_0/municipalities/{municipalityId}")]
pub async fn municipalities_delete(_path: Path<u64>) -> &'static str {
    "municipalities delete"
}

/**
 * Endpoint to add values.
 */
#[get("/api/services/v1_0/values:list")]
pub async fn values_list() -> &'static str {
    "values list"
}

/**
 * Endpoint to add values.
 */
#[post("/api/services/v1_0/values")]
pub async fn value_add() -> &'static str {
    "value add"
}

/**
 * Endpoint to delete values.
 */
#[delete("/api/services/v1_0/values/{valueId}")]
pub async fn value_delete(_path: Path<u64>) -> &'static str {
    "value delete"
}

/**
 * Endpoint to delete values.
 */
#[put("/api/services/v1_0/values/{valueId}")]
pub async fn value_update(_path: Path<u64>) -> &'static str {
    "value update"
}
