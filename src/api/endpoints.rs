use actix_web::{
    HttpRequest, HttpResponse, delete,
    http::header::{HeaderName, HeaderValue},
    post, put,
    web::{self, Bytes, Path},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tracing::{debug, error, info, instrument, warn, Instrument};

use crate::{
    api::{
        httpsignatures::DeriveInputElements,
        rest::{
            MunicipalityAddRequest, MunicipalityListResponse, PaginationQuery, StatisticsAddRequest, StatisticsListResponse, ValuesAddUpdateRequest, ValuesListRequest, ValuesListResponse,
            convert_headers_to_lowercase, generate_digest,
        },
        state::AppState,
    },
    model::{
        apperror::{ApplicationError, ErrorType},
        models::{MunicipalityAddInputType, PaginationInput, StatisticAddInputType, StatisticsListOutputType, ValuesAddUpdateInputType, ValuesListInputType},
    },
};

/**--------------Endpoints -------------------- */
/**
 * Endpoint to get a list of statistics types.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "listStatistics", trace_id = get_trace_id(&http_request), result), name = "api:list_statistics")]
#[post("/api/services/v1_0/statistics:list")]
pub async fn list_statistics(http_request: HttpRequest, payload: web::Payload, pagination: web::Query<PaginationQuery>, app_state: web::Data<AppState>) -> HttpResponse {
    let _ = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let statistics_list_response = match do_list_statistics(&pagination, &app_state).instrument(tracing::Span::current()).await {
        Ok(response) => response,
        Err(err) => {
            return add_signature_headers(HttpResponse::from_error(err), &app_state);
        }
    };
    let response = match serde_json::to_vec_pretty(&statistics_list_response) {
        Ok(response) => response,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let http_response: HttpResponse = HttpResponse::Ok().append_header(("Content-Digest", format!("sha-512=:{}:", generate_digest(&response)))).body(response);
    add_signature_headers(http_response, &app_state)
}

/**
 * Add a new statistics type.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "addStatistics", trace_id = get_trace_id(&http_request), result), name = "api:add_statistics")]
#[post("/api/services/v1_0/statistics")]
pub async fn add_statistic(http_request: HttpRequest, payload: web::Payload, app_state: web::Data<AppState>) -> HttpResponse {
    let payload = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let request_body = match convert_payload_body(&payload).instrument(tracing::Span::current()).await {
        Ok(body) => body,
        Err(err_response) => return HttpResponse::from_error(err_response),
    };
    match do_add_statistics(http_request, request_body, app_state.clone()).instrument(tracing::Span::current()).await {
        Ok(_) => (),
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    add_signature_headers(HttpResponse::Created().finish(), &app_state)
}

/**
 * Handles the deletion of a statistics type.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "deleteStatistics", trace_id = get_trace_id(&http_request), result), name = "api:delete_statistics")]
#[delete("/api/services/v1_0/statistics/{statisticsId}")]
pub async fn delete_statistics(path: Path<i64>, payload: web::Payload, http_request: HttpRequest, app_state: web::Data<AppState>) -> HttpResponse {
    let _ = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    match do_delete_statistics(&path, &app_state).instrument(tracing::Span::current()).await {
        Ok(_) => (),
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    add_signature_headers(HttpResponse::NoContent().finish(), &app_state)
}

/**
 * List municipalities.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "listMunicipalities", trace_id = get_trace_id(&http_request), result), name = "api:list_municipalities")]
#[post("/api/services/v1_0/municipalities:list")]
pub async fn list_municipalities(pagination: web::Query<PaginationQuery>, payload: web::Payload, http_request: HttpRequest, app_state: web::Data<AppState>) -> HttpResponse {
    let span = tracing::Span::current();
    let _ = match get_payload_and_verify(&http_request, payload, &app_state).instrument(span.clone()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let values_list_response = match do_list_municipalities(&pagination, &app_state).instrument(span.clone()).await {
        Ok(response) => response,
        Err(err) => {
            return add_signature_headers(HttpResponse::from_error(err), &app_state);
        }
    };
    let response = match serde_json::to_vec_pretty(&values_list_response) {
        Ok(response) => response,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let http_response: HttpResponse = HttpResponse::Ok().append_header(("Content-Digest", format!("sha-512=:{}:", generate_digest(&response)))).body(response);
    add_signature_headers(http_response, &app_state)
}

/**
 * Adds a new municipality.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "addMunicipality", trace_id = get_trace_id(&http_request), result), name = "api:add_municipality")]
#[post("/api/services/v1_0/municipalities")]
pub async fn add_municipality(http_request: HttpRequest, payload: web::Payload, app_state: web::Data<AppState>) -> HttpResponse {
    let payload: Bytes = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let request_body = match convert_payload_body(&payload).instrument(tracing::Span::current()).await {
        Ok(body) => body,
        Err(err_response) => return add_signature_headers(HttpResponse::from_error(err_response), &app_state),
    };
    match do_add_municipality(&http_request, &request_body, &app_state).instrument(tracing::Span::current()).await {
        Ok(_) => (),
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    add_signature_headers(HttpResponse::Created().finish(), &app_state)
}

/**
 * Handles the deletion of a municipality.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "deleteMunicipality", trace_id = get_trace_id(&http_request), result), name = "api:delete_municipality")]
#[delete("/api/services/v1_0/municipalities/{municipalityId}")]
pub async fn delete_municipality(path: Path<i64>, payload: web::Payload, http_request: HttpRequest, app_state: web::Data<AppState>) -> HttpResponse {
    let _ = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    match do_delete_municipality(&path, &app_state).instrument(tracing::Span::current()).await {
        Ok(_) => (),
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    add_signature_headers(HttpResponse::NoContent().finish(), &app_state)
}

/**
 * Endpoint to retrieve a list of values.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "listValues", trace_id = get_trace_id(&http_request), result), name = "api:list_values")]
#[post("/api/services/v1_0/values:list")]
pub async fn list_values(http_request: HttpRequest, payload: web::Payload, pagination: web::Query<PaginationQuery>, app_state: web::Data<AppState>) -> HttpResponse {
    let payload = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let request_body = match convert_payload_body(&payload).instrument(tracing::Span::current()).await {
        Ok(body) => body,
        Err(err_response) => return add_signature_headers(HttpResponse::from_error(err_response), &app_state),
    };
    let values_list_response: ValuesListResponse = match do_list_values(&request_body, &pagination, &app_state).instrument(tracing::Span::current()).await {
        Ok(response) => response,
        Err(err) => {
            return add_signature_headers(HttpResponse::from_error(err), &app_state);
        }
    };
    let response = match serde_json::to_vec_pretty(&values_list_response) {
        Ok(response) => response,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let http_response: HttpResponse = HttpResponse::Ok().append_header(("Content-Digest", format!("sha-512=:{}:", generate_digest(&response)))).body(response);
    add_signature_headers(http_response, &app_state)
}

/**
 * Endpoint to add a new value.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "addValue", trace_id = get_trace_id(&http_request), result), name = "api:add_value")]
#[post("/api/services/v1_0/values")]
pub async fn add_value(http_request: HttpRequest, payload: web::Payload, app_state: web::Data<AppState>) -> HttpResponse {
    let payload = match get_payload_and_verify(&http_request, payload, &app_state).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let request_body = match convert_payload_body(&payload).instrument(tracing::Span::current()).await {
        Ok(body) => body,
        Err(err_response) => return add_signature_headers(HttpResponse::from_error(err_response), &app_state),
    };
    match do_add_value(&http_request, &request_body, &app_state).instrument(tracing::Span::current()).await {
        Ok(_) => (),
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    add_signature_headers(HttpResponse::Created().finish(), &app_state)
}

/**
 * Endpoint to delete values.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "deleteValue", trace_id = get_trace_id(&http_request), result), name = "api:delete_value")]
#[delete("/api/services/v1_0/values/{valueId}")]
pub async fn delete_value(path: Path<i64>, payload: web::Payload, http_request: HttpRequest, app_state: web::Data<AppState>) -> HttpResponse {
    let _ = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    match do_delete_value(&path, &app_state).instrument(tracing::Span::current()).await {
        Ok(_) => (),
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    add_signature_headers(HttpResponse::NoContent().finish(), &app_state)
}

/**
 * Endpoint to update values.
 */
#[instrument(level = "debug", skip(http_request, app_state, payload), fields(service = "updateValue", trace_id = get_trace_id(&http_request), result), name = "api:update_value")]
#[put("/api/services/v1_0/values/{valueId}")]
pub async fn update_value(path: Path<i64>, http_request: HttpRequest, payload: web::Payload, app_state: web::Data<AppState>) -> HttpResponse {
    let payload = match get_payload_and_verify(&http_request, payload, &app_state).instrument(tracing::Span::current()).await {
        Ok(payload) => payload,
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    let request_body = match convert_payload_body(&payload).instrument(tracing::Span::current()).await {
        Ok(body) => body,
        Err(err_response) => return add_signature_headers(HttpResponse::from_error(err_response), &app_state),
    };
    match do_update_value(&path, &http_request, &request_body, &app_state).instrument(tracing::Span::current()).await {
        Ok(_) => (),
        Err(err) => return add_signature_headers(HttpResponse::from_error(err), &app_state),
    };
    add_signature_headers(HttpResponse::Ok().finish(), &app_state)
}

/**--------------Request handler functions------------------ */
/**
 * Endpoint to retrieve a list of statistics types.
 *
 * # Arguments
 * `pagination` - The pagination query parameters.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<StatisticsListResponse, ApplicationError>` - The HTTP response containing the list of statistics types or an error.
 */
async fn do_list_statistics(pagination: &web::Query<PaginationQuery>, app_state: &web::Data<AppState>) -> Result<StatisticsListResponse, ApplicationError> {
    let span = tracing::Span::current();
    let pagination_input = PaginationInput::from(pagination).validate()?;
    let output_values: StatisticsListOutputType = app_state.statistics_service.get_statistics_list(pagination_input).instrument(span).await?;
    Ok(StatisticsListResponse::from(output_values))
}

/**
 * Adds a new statistic.
 *
 * # Arguments
 * `http_request` - The HTTP request containing user information.
 * `request_body` - The JSON request body containing the statistic details.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<(), ApplicationError>` - The HTTP response indicating the result of the addition operation.
 */
async fn do_add_statistics(http_request: HttpRequest, request_body: web::Json<StatisticsAddRequest>, app_state: web::Data<AppState>) -> Result<(), ApplicationError> {
    let span = tracing::Span::current();
    let statistics_add_input = StatisticAddInputType::from((request_body, get_userid(&http_request)?)).validate()?;
    app_state.statistics_service.add_statistic(statistics_add_input).instrument(span).await?;
    Ok(())
}

/**
 * Handles the deletion of statistics.
 *
 * # Arguments
 * `path` - The path parameters containing the statistics ID.
 * `http_request` - The HTTP request containing user information.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<(), ApplicationError>` - The application error indicating the result of the deletion operation.
 */
async fn do_delete_statistics(path: &Path<i64>, app_state: &web::Data<AppState>) -> Result<(), ApplicationError> {
    let span = tracing::Span::current();
    let statistics_id = path.as_ref();
    app_state.statistics_service.delete_statistics(*statistics_id).instrument(span).await?;
    Ok(())
}

/**
 * Lists all municipalities.
 *
 * # Arguments
 * `pagination` - The pagination query parameters.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<MunicipalityListResponse, ApplicationError>` - The HTTP response containing the list of municipalities or an error.
 */
async fn do_list_municipalities(pagination: &web::Query<PaginationQuery>, app_state: &web::Data<AppState>) -> Result<MunicipalityListResponse, ApplicationError> {
    let span = tracing::Span::current();
    let pagination_input = PaginationInput::from(pagination).validate()?;
    let output_values = app_state.statistics_service.get_municipality_list(pagination_input).instrument(span).await?;
    Ok(MunicipalityListResponse::from(output_values))
}

/**
 * Adds a new municipality.
 *
 * # Arguments
 * `http_request` - The HTTP request containing user information.
 * `request_body` - The JSON request body containing the municipality details.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<(), ApplicationError>` - The application error indicating the result of the addition operation.
 */
async fn do_add_municipality(http_request: &HttpRequest, request_body: &web::Json<MunicipalityAddRequest>, app_state: &web::Data<AppState>) -> Result<(), ApplicationError> {
    let span = tracing::Span::current();
    let municipality_add_input = MunicipalityAddInputType::from((request_body, get_userid(http_request)?)).validate()?;
    app_state.statistics_service.add_municipality(municipality_add_input).instrument(span).await?;
    Ok(())
}

/**
 * Handles the deletion of a municipality.
 *
 * # Arguments
 * `path` - The path parameters containing the municipality ID.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<(), ApplicationError>` - The application error indicating the result of the deletion operation.
 */
async fn do_delete_municipality(path: &Path<i64>, app_state: &web::Data<AppState>) -> Result<(), ApplicationError> {
    let span = tracing::Span::current();
    let municipality_id = path.as_ref();
    app_state.statistics_service.delete_municipality(*municipality_id).instrument(span).await?;
    Ok(())
}

/**
 * Handles the retrieval of a list of values.
 *
 * # Arguments
 * `http_request` - The HTTP request containing user information.
 * `request_body` - The JSON request body containing the filter parameters.
 * `pagination` - The query parameters for pagination.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<ValuesListResponse, ApplicationError>` - The HTTP response containing the list of values or an error.
 */
async fn do_list_values(request_body: &web::Json<ValuesListRequest>, pagination: &web::Query<PaginationQuery>, app_state: &web::Data<AppState>) -> Result<ValuesListResponse, ApplicationError> {
    let span = tracing::Span::current();
    let pagination_input = PaginationInput::from(pagination).validate()?;
    let filter_params = ValuesListInputType::from(request_body).validate()?;
    let output_values = app_state.statistics_service.get_values_list(pagination_input, filter_params).instrument(span).await?;
    Ok(ValuesListResponse::from(output_values))
}

/**
 * Handles the addition of a new value.
 *
 * # Arguments
 * `http_request` - The HTTP request containing user information.
 * `request_body` - The JSON request body containing the new value information.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<HttpResponse, ApplicationError>` - The application error indicating the result of the addition operation.
 */
pub async fn do_add_value(http_request: &HttpRequest, request_body: &web::Json<ValuesAddUpdateRequest>, app_state: &web::Data<AppState>) -> Result<(), ApplicationError> {
    let span = tracing::Span::current();
    let values_add_input = ValuesAddUpdateInputType::from((request_body, get_userid(http_request)?)).validate()?;
    app_state.statistics_service.add_value(values_add_input).instrument(span).await?;
    Ok(())
}

/**
 * Handles the deletion of a value.
 *
 * # Arguments
 * `path` - The path parameters containing the value ID.
 * `http_request` - The HTTP request containing user information.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<HttpResponse, ApplicationError>` - The HTTP response indicating the result of the deletion operation.
 */
pub async fn do_delete_value(path: &Path<i64>, app_state: &web::Data<AppState>) -> Result<(), ApplicationError> {
    let span = tracing::Span::current();
    let value_id = path.as_ref();
    app_state.statistics_service.delete_value(*value_id).instrument(span).await?;
    Ok(())
}

/**
 * Endpoint to update value.
 *
 * # Arguments
 * `path` - The path parameters containing the value ID.
 * `http_request` - The HTTP request containing user information.
 * `request_body` - The JSON request body containing the updated value information.
 * `app_state` - The application state containing shared services and configuration.
 *
 * # Returns
 * `Result<HttpResponse, ApplicationError>` - The HTTP response indicating the result of the update operation.
 */
pub async fn do_update_value(path: &Path<i64>, http_request: &HttpRequest, request_body: &web::Json<ValuesAddUpdateRequest>, app_state: &web::Data<AppState>) -> Result<(), ApplicationError> {
    let span = tracing::Span::current();
    let value_id = path.as_ref();
    let values_add_update_input = ValuesAddUpdateInputType::from((request_body, get_userid(http_request)?)).validate()?;
    app_state.statistics_service.update_value(*value_id, values_add_update_input).instrument(span).await?;
    Ok(())
}

/**--------------Support functions --------------------*/
/**
 * Retrieves the trace ID from the HTTP request headers.
 * If the trace ID is not present, a new UUID is generated.
 *
 * # Arguments
 * `http_request` - The HTTP request from which to extract the trace ID.
 *
 * # Returns
 * `String` - The trace ID if found, or a new UUID.
 */
fn get_trace_id(http_request: &HttpRequest) -> String {
    http_request.headers().get("X-Request-ID").and_then(|v| v.to_str().ok().map(std::string::ToString::to_string)).unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/**
 * Retrieves the user ID from the HTTP request headers.
 * Returns None if the user ID is not present.
 *
 * # Arguments
 * `http_request` - The HTTP request from which to extract the user ID.
 *
 * # Returns
 * `Result<String, ApplicationError>` - The user ID if found, or an application error.
 */
fn get_userid(http_request: &HttpRequest) -> Result<String, ApplicationError> {
    http_request
        .headers()
        .get("X-fd-Userid")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| ApplicationError::new(ErrorType::Validation, "User id not found in request headers".to_string()))
}

/**
 * Adds signature headers to the HTTP response.
 *
 * This function checks if HTTPS signatures are enabled in the application configuration.
 * If enabled, it generates the necessary signature headers for the given HTTP response.
 *
 * # Arguments
 * `http_response` - The HTTP response to which the signature headers will be added.
 * `app_state` - The application state containing services and configuration.
 *
 * # Returns
 * `HttpResponse` - The HTTP response with added signature headers if generated
 */
fn add_signature_headers(mut http_response: HttpResponse, app_state: &web::Data<AppState>) -> HttpResponse {
    let sig = get_signature_headers(&http_response, app_state);
    if let Some((signature_header, signature_input_header)) = sig {
        http_response.headers_mut().insert(HeaderName::from_static("signature"), signature_header);
        http_response.headers_mut().insert(HeaderName::from_static("signature-input"), signature_input_header);
    } else {
        warn!("HTTPS signatures are not enabled or signature generation failed.");
    }
    http_response
}

/**
 * Generate signature headers for the response if HTTPS signatures are enabled.
 *
 * This function checks if HTTPS signatures are enabled in the application configuration.
 * If enabled, it generates the necessary signature headers for the given HTTP response.
 *
 * # Arguments
 * `response` - The HTTP response for which to generate signature headers.
 * `app_state` - The application state containing services and configuration.
 *
 * # Returns
 * `Option<(HeaderValue, HeaderValue)>` - A tuple containing the signature and signature-input headers if generated, otherwise None.
 */
fn get_signature_headers(response: &HttpResponse, app_state: &web::Data<AppState>) -> Option<(HeaderValue, HeaderValue)> {
    let headers = convert_headers_to_lowercase(response.headers());
    let derive_elements = DeriveInputElements::from(response);
    let generated_signature = app_state.security_service.generate_response_signature(&headers, &derive_elements);
    if let Ok(Some(signature)) = &generated_signature {
        let signature_header = HeaderValue::from_str(&signature.0).map_err(|err| {
            error!("Failed to create signature header: {err:?}");
        });
        let signature_input_header = HeaderValue::from_str(&signature.1).map_err(|err| {
            error!("Failed to create signature input header: {err:?}");
        });
        if let (Ok(signature_header), Ok(signature_input_header)) = (signature_header, signature_input_header) {
            return Some((signature_header, signature_input_header));
        }
    }
    None
}

/**
 * Verifies the signature of the incoming HTTP request.
 *
 * # Arguments
 * `http_request` - The HTTP request to verify.
 * `app_state` - The application state containing services and configuration.
 *
 * # Returns
 * `Result<(), HttpResponse>` - Ok if the signature is valid, or an error response if verification fails.
 */
fn verify_signature(http_request: &HttpRequest, app_state: &web::Data<AppState>) -> Result<(), ApplicationError> {
    app_state.security_service.verify_signature(&convert_headers_to_lowercase(http_request.headers()), &DeriveInputElements::from(http_request)).map_err(|err| {
        info!("Signature verification failed: {err}");
        // We do not return specific error details to the client.
        ApplicationError::new(ErrorType::SignatureVerification, "Signature verification failed".to_string())
    })?;
    Ok(())
}

/**
 * Verify the digest of the request body.   
 *
 * # Arguments
 * `digest`: The digest header value, expected to be in the format "SHA-256=base64hash".
 * `body`: The request body as a byte slice.
 *
 * # Returns
 * `Result<(), ApplicationError>` - Ok if the digest is valid, or an application error if verification fails.
 */
fn verify_digest(http_request: &HttpRequest, body: &[u8]) -> Result<(), ApplicationError> {
    if body.is_empty() && http_request.headers().get("Content-Digest").is_none() {
        return Ok(());
    }
    let digest = http_request
        .headers()
        .get("Content-Digest")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::DigestVerification, "Missing Content-Digest header".to_string()))?;
    let (algorithm, expected_digest) = digest.split_once('=').ok_or_else(|| ApplicationError::new(crate::model::apperror::ErrorType::DigestVerification, "Invalid digest format".to_string()))?;
    let expected_hash = str::replace(expected_digest, ":", "");
    let hash_result = match algorithm.to_uppercase().as_str() {
        "SHA-256" => Sha256::digest(body).to_vec(),
        "SHA-384" => {
            let mut algorithm = Sha384::new();
            algorithm.update(body);
            algorithm.finalize().to_vec()
        }
        "SHA-512" => {
            let mut algorithm = Sha512::new();
            algorithm.update(body);
            algorithm.finalize().to_vec()
        }
        _ => {
            info!("Unsupported digest algorithm: {algorithm}");
            return Err(ApplicationError::new(crate::model::apperror::ErrorType::Application, "Unsupported digest algorithm".to_string()));
        }
    };
    let result = STANDARD.encode(hash_result);
    debug!("Calculated digest: {result}");
    if result == expected_hash { Ok(()) } else { Err(ApplicationError::new(crate::model::apperror::ErrorType::DigestVerification, "Digest verification failed".to_string())) }
}

/**
 * Converts the request payload into a JSON object.
 *
 * # Arguments
 * `payload` - The request payload to convert.
 *
 * # Returns
 * `Result<web::Json<T>, ApplicationError>` - The JSON object if successful, or an error if conversion fails.
 */
async fn convert_payload_body<T>(payload: &Bytes) -> Result<web::Json<T>, ApplicationError>
where
    T: serde::de::DeserializeOwned,
{
    let val: T = serde_json::from_slice(payload).map_err(|err| ApplicationError::new(ErrorType::Application, format!("Failed to read request body: {err}")))?;
    Ok(web::Json(val))
}

/**
 * Gets the request payload and verifies its digest and signature.
 *
 * # Arguments
 * `http_request` - The HTTP request to verify.
 * `payload` - The request payload to verify.
 *
 * # Returns
 * `Result<Bytes, ApplicationError>` - The request payload if successful, or an application error if verification fails.
 */
async fn get_payload_and_verify(http_request: &HttpRequest, payload: web::Payload, app_state: &actix_web::web::Data<AppState>) -> Result<Bytes, ApplicationError> {
    let payload: Bytes = match payload.to_bytes().await {
        Ok(bytes) => {
            verify_digest(http_request, &bytes)?;
            bytes
        }
        Err(err_response) => return Err(ApplicationError::new(ErrorType::Application, format!("Failed to read request body: {err_response}"))),
    };
    verify_signature(http_request, app_state)?;
    Ok(payload)
}

#[cfg(test)]
mod test {
    use actix_web::test::TestRequest;

    use super::*;

    #[actix_web::test]
    async fn test_get_trace_id_exists() {
        let request = TestRequest::default().insert_header(("X-Request-ID", "test")).to_http_request();
        let trace_id = get_trace_id(&request);
        assert_eq!(trace_id, "test");
    }

    #[actix_web::test]
    async fn test_get_trace_id_not_exists() {
        let request = TestRequest::default().to_http_request();
        let trace_id = get_trace_id(&request);
        assert!(!trace_id.is_empty());
    }
}
