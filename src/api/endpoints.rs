use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{self, Path},
};

use crate::{
    api::{
        rest::{PaginationQuery, ValuesListRequest, ValuesListResponse},
        state::AppState,
    },
    model::{
        apperror::ApplicationError,
        models::{PaginationInput, ValuesListInputType},
    },
};

/**
 * Endpoint to retrieve a list of statistics types.
 */
#[get("/api/services/v1_0/statistics")]
pub async fn statistics_list(http_request: HttpRequest, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    app_state.jwt_service.validate(&http_request)?;
    Ok(HttpResponse::Ok().finish())
}

/**
 * Add a new statistics type.
 */
#[post("/api/services/v1_0/statistics")]
pub async fn statistics_add() -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::Created().finish())
}

/**
 * Delete statistics type.
 */
#[delete("/api/services/v1_0/statistics/{statisticsId}")]
pub async fn statistics_delete(_path: Path<u64>) -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::NoContent().finish())
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[get("/api/services/v1_0/municipalities")]
pub async fn municipalities_list() -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::Ok().finish())
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[post("/api/services/v1_0/municipalities")]
pub async fn municipalities_add() -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::Created().finish())
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[delete("/api/services/v1_0/municipalities/{municipalityId}")]
pub async fn municipalities_delete(_path: Path<u64>) -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::NoContent().finish())
}

/**
 * Endpoint to add values.
 */
#[post("/api/services/v1_0/values:list")]
pub async fn values_list(
    http_request: HttpRequest,
    request_body: web::Json<ValuesListRequest>,
    pagination: web::Query<PaginationQuery>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, ApplicationError> {
    app_state.jwt_service.validate(&http_request)?;
    let pagination_input = PaginationInput::from(pagination);
    let filter_params = ValuesListInputType::from(request_body);
    let output_values = app_state.statistics_service.get_values_list(pagination_input, filter_params).await?;
    Ok(HttpResponse::Ok().json(ValuesListResponse::from(output_values)))
}

/**
 * Endpoint to add values.
 */
#[post("/api/services/v1_0/values")]
pub async fn value_add() -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::Created().finish())
}

/**
 * Endpoint to delete values.
 */
#[delete("/api/services/v1_0/values/{valueId}")]
pub async fn value_delete(_path: Path<u64>) -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::NoContent().finish())
}

/**
 * Endpoint to delete values.
 */
#[put("/api/services/v1_0/values/{valueId}")]
pub async fn value_update(_path: Path<u64>) -> Result<HttpResponse, ApplicationError> {
    Ok(HttpResponse::Ok().finish())
}
