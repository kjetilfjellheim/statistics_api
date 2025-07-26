use actix_web::{
    delete, post, put, web::{self, Path}, HttpRequest, HttpResponse
};
use tracing::{instrument, Instrument};

use crate::{
    api::{
        rest::{MunicipalityAddRequest, MunicipalityListResponse, PaginationQuery, StatisticsAddRequest, StatisticsListRequest, StatisticsListResponse, ValuesAddUpdateRequest, ValuesListRequest, ValuesListResponse},
        state::AppState,
    },
    model::{
        apperror::ApplicationError,
        models::{MunicipalityAddInputType, PaginationInput, StatisticAddInputType, StatisticsListOutputType, ValuesAddUpdateInputType, ValuesListInputType},
    },
};

/**
 * Endpoint to retrieve a list of statistics types.
 */
#[instrument(level = "info", skip(http_request, app_state), fields(service = "listStatistics", trace_id = get_trace_id(&http_request), result))]
#[post("/api/services/v1_0/statistics:list")]
pub async fn statistics_list(
    http_request: HttpRequest,
    request_body: web::Json<StatisticsListRequest>,
    pagination: web::Query<PaginationQuery>,
    app_state: web::Data<AppState>
) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let _ = app_state.jwt_service.validate(&http_request)?;
    let pagination_input = PaginationInput::from(pagination).validate()?;
    let output_values: StatisticsListOutputType = app_state.statistics_service.get_statistics_list(pagination_input).instrument(span).await?;
    Ok(HttpResponse::Ok().json(StatisticsListResponse::from(output_values)))
}

/**
 * Add a new statistics type.
 */
#[instrument(level = "info", skip(http_request, app_state), fields(service = "addStatistics", trace_id = get_trace_id(&http_request), result))]
#[post("/api/services/v1_0/statistics")]
pub async fn statistics_add(http_request: HttpRequest, request_body: web::Json<StatisticsAddRequest>, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let claim = app_state.jwt_service.validate(&http_request)?;
    let statistics_add_input = StatisticAddInputType::from((request_body, claim.name)).validate()?;
    app_state.statistics_service.add_statistic(statistics_add_input).instrument(span).await?;
    Ok(HttpResponse::Created().finish())
}

/**
 * Delete statistics type.
 */
#[instrument(skip(http_request, app_state), fields(service = "deleteStatistics", trace_id = get_trace_id(&http_request), result))]
#[delete("/api/services/v1_0/statistics/{statisticsId}")]
pub async fn statistics_delete(path: Path<i64>, http_request: HttpRequest, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let _ = app_state.jwt_service.validate(&http_request)?;
    let statistics_id = path.into_inner();
    app_state.statistics_service.delete_statistics(statistics_id).instrument(span).await?;
    Ok(HttpResponse::NoContent().finish())
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[instrument(skip(http_request, app_state), fields(service = "listMunicipalities", trace_id = get_trace_id(&http_request), result))]
#[post("/api/services/v1_0/municipalities:list")]
pub async fn municipalities_list(
    http_request: HttpRequest, 
    request_body: web::Json<StatisticsListRequest>,
    pagination: web::Query<PaginationQuery>,
    app_state: web::Data<AppState>
) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let _ = app_state.jwt_service.validate(&http_request)?;
    let pagination_input = PaginationInput::from(pagination).validate()?;
    let output_values = app_state.statistics_service.get_municipality_list(pagination_input).instrument(span).await?;
    Ok(HttpResponse::Ok().json(MunicipalityListResponse::from(output_values)))
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[instrument(skip(http_request, app_state), fields(service = "addMunicipality", trace_id = get_trace_id(&http_request), result))]
#[post("/api/services/v1_0/municipalities")]
pub async fn municipalities_add(http_request: HttpRequest, request_body: web::Json<MunicipalityAddRequest>, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let claim = app_state.jwt_service.validate(&http_request)?;
    let municipality_add_input = MunicipalityAddInputType::from((request_body, claim.name)).validate()?;
    app_state.statistics_service.add_municipality(municipality_add_input).instrument(span).await?;
    Ok(HttpResponse::Created().finish())
}

/**
 * Endpoint to retrieve a list of municipalities.
 */
#[instrument(skip(http_request, app_state), fields(service = "deleteMunicipality", trace_id = get_trace_id(&http_request), result))]
#[delete("/api/services/v1_0/municipalities/{municipalityId}")]
pub async fn municipalities_delete(path: Path<i64>, http_request: HttpRequest, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let _ = app_state.jwt_service.validate(&http_request)?;
    let municipality_id = path.into_inner();
    app_state.statistics_service.delete_municipality(municipality_id).instrument(span).await?;
    Ok(HttpResponse::NoContent().finish())
}

/**
 * Endpoint to add values.
 */
#[instrument(skip(http_request, app_state), fields(service = "listValues", trace_id = get_trace_id(&http_request), result))]
#[post("/api/services/v1_0/values:list")]
pub async fn values_list(
    http_request: HttpRequest,
    request_body: web::Json<ValuesListRequest>,
    pagination: web::Query<PaginationQuery>,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    app_state.jwt_service.validate(&http_request)?;
    let pagination_input = PaginationInput::from(pagination).validate()?;
    let filter_params = ValuesListInputType::from(request_body).validate()?;
    let output_values = app_state.statistics_service.get_values_list(pagination_input, filter_params).instrument(span).await?;
    Ok(HttpResponse::Ok().json(ValuesListResponse::from(output_values)))
}

/**
 * Endpoint to add values.
 */
#[instrument(skip(http_request, app_state), fields(service = "addValue", trace_id = get_trace_id(&http_request), result))]
#[post("/api/services/v1_0/values")]
pub async fn value_add(http_request: HttpRequest, request_body: web::Json<ValuesAddUpdateRequest>, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let claim = app_state.jwt_service.validate(&http_request)?;
    let values_add_input = ValuesAddUpdateInputType::from((request_body, claim.name)).validate()?;
    app_state.statistics_service.add_value(values_add_input).instrument(span).await?;
    Ok(HttpResponse::Created().finish())
}

/**
 * Endpoint to delete values.
 */
#[instrument(skip(http_request, app_state), fields(service = "deleteValue", trace_id = get_trace_id(&http_request), result))]
#[delete("/api/services/v1_0/values/{valueId}")]
pub async fn value_delete(path: Path<i64>, http_request: HttpRequest, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let _ = app_state.jwt_service.validate(&http_request)?;
    let value_id = path.into_inner();
    app_state.statistics_service.delete_value(value_id).instrument(span).await?;
    Ok(HttpResponse::NoContent().finish())
}

/**
 * Endpoint to delete values.
 */
#[instrument(skip(http_request, app_state), fields(service = "updateValue", trace_id = get_trace_id(&http_request), result))]
#[put("/api/services/v1_0/values/{valueId}")]
pub async fn value_update(path: Path<i64>, http_request: HttpRequest, request_body: web::Json<ValuesAddUpdateRequest>, app_state: web::Data<AppState>) -> Result<HttpResponse, ApplicationError> {
    let span = tracing::Span::current();
    let claim = app_state.jwt_service.validate(&http_request)?;
    let value_id = path.into_inner();
    let values_add_update_input = ValuesAddUpdateInputType::from((request_body, claim.name)).validate()?;
    app_state.statistics_service.update_value(value_id, values_add_update_input).instrument(span).await?;
    Ok(HttpResponse::Ok().finish())
}

/**
 * Retrieves the trace ID from the HTTP request headers.
 * If the trace ID is not present, a new UUID is generated.
 */
fn get_trace_id(http_request: &HttpRequest) -> String {
    http_request.headers().get("X-Trace-ID")
        .and_then(|v| v.to_str().ok().map(std::string::ToString::to_string))
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

#[cfg(test)]
mod test {
    use actix_web::test::TestRequest;

    use super::*;

    #[actix_web::test]
    async fn test_get_trace_id_exists() {
        let request = TestRequest::default()
            .insert_header(("X-Trace-ID", "test"))
            .to_http_request();
        let trace_id = get_trace_id(&request);
        assert_eq!(trace_id, "test");
    }


    #[actix_web::test]
    async fn test_get_trace_id_not_exists() {
        let request = TestRequest::default()
            .to_http_request();
        let trace_id = get_trace_id(&request);
        assert!(!trace_id.is_empty());
    }
}