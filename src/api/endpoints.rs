use actix_web::{
    HttpRequest, HttpResponse, delete, get, post, put,
    web::{self, Path},
};

use crate::{
    api::{
        rest::{PaginationQuery, StatisticsAddRequest, StatisticsListRequest, StatisticsListResponse, ValuesListRequest, ValuesListResponse},
        state::AppState,
    },
    model::{
        apperror::ApplicationError,
        models::{PaginationInput, StatisticAddInputType, StatisticsListOutputType, ValuesListInputType},
    },
};

/**
 * Endpoint to retrieve a list of statistics types.
 */
#[post("/api/services/v1_0/statistics:list")]
pub async fn statistics_list(
    http_request: HttpRequest,
    _request_body: web::Json<StatisticsListRequest>,
    pagination: web::Query<PaginationQuery>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, ApplicationError> {
    let _ = app_state.jwt_service.validate(&http_request)?;
    let pagination_input = PaginationInput::from(pagination);
    let output_values: StatisticsListOutputType = app_state.statistics_service.get_statistics_list(pagination_input).await?;
    Ok(HttpResponse::Ok().json(StatisticsListResponse::from(output_values)))
}

/**
 * Add a new statistics type.
 */
#[post("/api/services/v1_0/statistics")]
pub async fn statistics_add(http_request: HttpRequest, request_body: web::Json<StatisticsAddRequest>, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let claim = app_state.jwt_service.validate(&http_request)?;
    let statistics_add_input = StatisticAddInputType::from((request_body, claim.name));
    app_state.statistics_service.add_statistic(statistics_add_input).await?;
    Ok(HttpResponse::Created().finish())
}

/**
 * Delete statistics type.
 */
#[delete("/api/services/v1_0/statistics/{statisticsId}")]
pub async fn statistics_delete(path: Path<i64>, http_request: HttpRequest, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let _ = app_state.jwt_service.validate(&http_request)?;
    let statistics_id = path.into_inner();
    app_state.statistics_service.delete_statistics(statistics_id).await?;
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
