use std::collections::HashMap;

use actix_web::{http::{header::HeaderMap, StatusCode}, HttpRequest, HttpResponse, ResponseError};
use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use tracing::debug;

use crate::{api::httpsignatures::DeriveInputElements, model::{
    apperror::{ApplicationError, ErrorType},
    models::{MunicipalityDetailType, MunicipalityListOutputType, PaginationOutput, StatisticDetailType, StatisticsListOutputType, ValueDetailType, ValuesListOutputType},
}};
use base64::{Engine, engine::general_purpose::STANDARD};

/***************** Municipality:list models *********************/

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MunicipalityListRequest {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MunicipalityListResponse {
    /**
     * A vector of `MunicipalityDetailElement` representing the municipality details.
     */
    pub municipalities: Vec<MunicipalityDetailElement>,
    /**
     * Pagination information for the response.
     */
    pub pagination: PaginationResponse,
}

impl MunicipalityListResponse {
    /**
     * Creates a new instance of `MunicipalityListResponse`.
     *
     * # Arguments
     * `municipalities`: A vector of `StatisticsDetailElement` representing the statistics details.
     * `pagination`: `PaginationResponse` containing pagination information.
     *
     * # Returns
     * A new instance of `MunicipalityListResponse`.
     */
    pub fn new(municipalities: Vec<MunicipalityDetailElement>, pagination: PaginationResponse) -> Self {
        MunicipalityListResponse { municipalities, pagination }
    }
}
impl From<MunicipalityListOutputType> for MunicipalityListResponse {
    fn from(output: MunicipalityListOutputType) -> Self {
        let municipalities: Vec<MunicipalityDetailElement> = output.municipalities.into_iter().map(MunicipalityDetailElement::from).collect();
        let pagination = PaginationResponse::from(output.pagination);
        MunicipalityListResponse::new(municipalities, pagination)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MunicipalityDetailElement {
    /**
     * The unique identifier for the municipality.
     */
    pub id: i64,
    /**
     * The name of the municipality.
     */
    pub name: String,
    /**
     * The timestamp when the municipality was created.
     */
    pub created_at: chrono::DateTime<Utc>,
    /**
     * The user who created the municipality.
     */
    pub created_by: String,
}

impl MunicipalityDetailElement {
    /**
     * Creates a new instance of `MunicipalityDetailElement`.
     *
     * # Arguments
     * `id`: The unique identifier for the municipality.
     * `name`: The name of the municipality.
     * `created_at`: The timestamp when the municipality was created.
     * `created_by`: The user who created the municipality.
     *
     * # Returns
     * A new instance of `MunicipalityDetailElement`.
     */
    pub fn new(id: i64, name: String, created_at: chrono::DateTime<Utc>, created_by: String) -> Self {
        MunicipalityDetailElement { id, name, created_at, created_by }
    }
}

/**
 * Converts from internal model to rest model.
 */
impl From<MunicipalityDetailType> for MunicipalityDetailElement {
    fn from(stat: MunicipalityDetailType) -> Self {
        MunicipalityDetailElement::new(stat.id, stat.name, stat.created_at, stat.created_by)
    }
}

/***************** Municipality:add models *********************/

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MunicipalityAddRequest {
    /**
     * The unique identifier for the municipality.
     */
    pub id: i64,
    /**
     * The name of the municipality.
     */
    pub name: String,
}

/***************** Statistics:list models *********************/

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticsListRequest {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticsListResponse {
    /**
     * A vector of `StatisticDetailElement` representing the statistics details.
     */
    pub statistics: Vec<StatisticDetailElement>,
    /**
     * Pagination information for the response.
     */
    pub pagination: PaginationResponse,
}

impl StatisticsListResponse {
    /**
     * Creates a new instance of `StatisticsListResponse`.
     *
     * # Arguments
     * `statistics`: A vector of `StatisticsDetailElement` representing the statistics details.
     * `pagination`: `PaginationResponse` containing pagination information.
     *
     * # Returns
     * A new instance of `StatisticsListResponse`.
     */
    pub fn new(statistics: Vec<StatisticDetailElement>, pagination: PaginationResponse) -> Self {
        StatisticsListResponse { statistics, pagination }
    }
}
impl From<StatisticsListOutputType> for StatisticsListResponse {
    fn from(output: StatisticsListOutputType) -> Self {
        let statistics: Vec<StatisticDetailElement> = output.statistics.into_iter().map(StatisticDetailElement::from).collect();
        let pagination = PaginationResponse::from(output.pagination);
        StatisticsListResponse::new(statistics, pagination)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticDetailElement {
    /**
     * The unique identifier for the statistic.
     */
    pub id: i64,
    /**
     * The name of the statistic.
     */
    pub name: String,
    /**
     * The timestamp when the statistic was created.
     */
    pub created_at: chrono::DateTime<Utc>,
    /**
     * The user who created the statistic.
     */
    pub created_by: String,
}

impl StatisticDetailElement {
    /**
     * Creates a new instance of `StatisticDetailElement`.
     *
     * # Arguments
     * `id`: The unique identifier for the statistic.
     * `name`: The name of the statistic.
     * `created_at`: The timestamp when the statistic was created.
     * `created_by`: The user who created the statistic.
     *
     * # Returns
     * A new instance of `StatisticDetailElement`.
     */
    pub fn new(id: i64, name: String, created_at: chrono::DateTime<Utc>, created_by: String) -> Self {
        StatisticDetailElement { id, name, created_at, created_by }
    }
}

/**
 * Converts from internal model to rest model.
 */
impl From<StatisticDetailType> for StatisticDetailElement {
    fn from(stat: StatisticDetailType) -> Self {
        StatisticDetailElement::new(stat.id, stat.name, stat.created_at, stat.created_by)
    }
}

/***************** Statistics:add models *********************/

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticsAddRequest {
    /**
     * The unique identifier for the statistic.
     */
    pub id: i64,
    /**
     * The name of the statistic.
     */
    pub name: String,
}

/***************** Values:list models *********************/

/**
 * Request structure for listing values.
 *
 * This structure is used to filter the values based on municipality ID, statistic ID, and year.
 */
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValuesListRequest {
    pub municipality_id: Option<i64>,
    pub statistic_id: Option<i64>,
    pub year: Option<i64>,
}

/**
 * Response structure for listing values.
 *
 * This structure contains a list of statistics details and pagination information.
 */
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValuesListResponse {
    /**
     * A vector of `ValueDetailElement` representing the statistics details.
     */
    statistics: Vec<ValueDetailElement>,
    /**
     * Pagination information for the response.
     */
    pagination: PaginationResponse,
}

impl ValuesListResponse {
    /**
     * Creates a new instance of `ValuesListResponse`.
     *
     * # Arguments
     * `statistics`: A vector of `ValueDetailElement` representing the statistics details.
     *
     * # Returns
     * A new instance of `ValuesListResponse`.
     */
    pub fn new(statistics: Vec<ValueDetailElement>, pagination: PaginationResponse) -> Self {
        ValuesListResponse { statistics, pagination }
    }
}

/**
 * Converts from `ValuesListOutputType` to `ValuesListResponse`.
 *
 * This conversion is used to transform the output of the values list service into a response format suitable for API responses.
 */
impl From<ValuesListOutputType> for ValuesListResponse {
    fn from(output: ValuesListOutputType) -> Self {
        let statistics: Vec<ValueDetailElement> = output.statistics.into_iter().map(ValueDetailElement::from).collect();
        let pagination = PaginationResponse::from(output.pagination);
        ValuesListResponse::new(statistics, pagination)
    }
}

/**
 * Represents the details of a value in the Values List API.
 *
 * This structure contains information about the statistic, municipality, value, year, and timestamps.
 */
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ValueDetailElement {
    /**
     * The unique identifier for the statistic.
     */
    id: i64,
    /**
     * The ID of the municipality.
     */
    municipality_id: i64,
    /**
     * The name of the municipality.
     */
    municipality_name: String,
    /**
     * The ID of the statistic.
     */
    statistic_id: i64,
    /**
     * The name of the statistic.
     */
    statistic_name: String,
    /**
     * The value of the statistic.
     */
    value: Decimal,
    /**
     * The year of the statistic.
     */
    year: i64,
    /**
     * The timestamp when the statistic was last updated.
     */
    updated_at: chrono::DateTime<Utc>,
    /**
     * The timestamp when the statistic was created.
     */
    created_at: chrono::DateTime<Utc>,
    /**
     * The user who last updated the statistic.
     */
    updated_by: String,
    /**
     * The user who created the statistic.
     */
    created_by: String,
}

impl ValueDetailElement {
    /**
     * Creates a new instance of `ValueDetailElement`.
     *
     * # Arguments
     * `id`: The unique identifier for the statistic.
     * `municipality_id`: The ID of the municipality.
     * `municipality_name`: The name of the municipality.
     * `statistic_id`: The ID of the statistic.
     * `statistic_name`: The name of the statistic.
     * `value`: The value of the statistic.
     * `year`: The year of the statistic.
     * `updated_at`: The timestamp when the statistic was last updated.
     * `created_at`: The timestamp when the statistic was created.
     * `updated_by`: The user who last updated the statistic.
     * `created_by`: The user who created the statistic.
     *
     * # Returns
     * A new instance of `ValueDetailElement`.
     */
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: i64,
        municipality_id: i64,
        municipality_name: String,
        statistic_id: i64,
        statistic_name: String,
        value: Decimal,
        year: i64,
        updated_at: chrono::DateTime<Utc>,
        created_at: chrono::DateTime<Utc>,
        updated_by: String,
        created_by: String,
    ) -> Self {
        ValueDetailElement { id, municipality_id, municipality_name, statistic_id, statistic_name, value, year, updated_at, created_at, updated_by, created_by }
    }
}

/**
 * Converts from `ValueDetailType` to `ValueDetailElement`.
 *
 * This conversion is used to transform the internal value detail type into a response format suitable for API responses.
 */
impl From<ValueDetailType> for ValueDetailElement {
    fn from(stat: ValueDetailType) -> Self {
        ValueDetailElement::new(
            stat.id,
            stat.municipality_id,
            stat.municipality_name,
            stat.statistic_id,
            stat.statistic_name,
            stat.value,
            stat.year,
            stat.updated_at,
            stat.created_at,
            stat.updated_by,
            stat.created_by,
        )
    }
}

/***************** Values:add and update models *********************/

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValuesAddUpdateRequest {
    /**
     * The ID of the municipality.
     */
    pub municipality_id: i64,
    /**
     * The ID of the statistic.
     */
    pub statistic_id: i64,
    /**
     * The value of the statistic.
     */
    pub value: Decimal,
    /**
     * The year of the statistic.
     */
    pub year: i64,
}

/***************** Error models *********************/

/**
 * Custom error response for the application.
 */
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /**
     * The error code associated with the error type.
     */
    pub code: u16,
    /**
     * A human-readable message describing the error.
     */
    pub message: String,
}

impl ResponseError for ApplicationError {
    /**
     * Generates an error response for the application error.
     */
    fn error_response(&self) -> HttpResponse {
        let error_response = ErrorResponse { code: get_error_code(&self.error_type), message: self.message.clone() };
        let binding = serde_json::to_string_pretty(&error_response)
            .map_err(|_| ApplicationError::new(ErrorType::Application, "Failed to serialize error response".to_string()))
            .unwrap_or_else(|_| get_serde_conversion_error());
        let bytes = binding.into_bytes();
        let digest = format!("sha-512=:{}:", generate_digest(&bytes));
        HttpResponse::build(get_statuscode(&self.error_type.clone())).append_header(("Content-Digest", digest)).body(bytes)
    }
}

/**
 * Converts the headers to lowercase.
 *
 * # Arguments
 * `headers`: The headers to convert.
 * # Returns
 * A `HashMap<String, String>` containing the headers with lowercase keys.
 */
pub fn convert_headers_to_lowercase(headers: &HeaderMap) -> HashMap<String, String> {
    headers.iter().map(|(k, v)| (k.as_str().to_lowercase(), v.to_str().unwrap_or("").to_string())).collect()
}

impl From<&HttpRequest> for DeriveInputElements {
    /**
     * Converts an `HttpRequest` into `DeriveInputElements`.
     *
     * # Arguments
     * `http_request`: The HTTP request to derive elements from.
     *
     * # Returns
     * A new instance of `DeriveInputElements` derived from the HTTP request.
     */
    fn from(http_request: &HttpRequest) -> Self {
        let derive_elements = DeriveInputElements::new(
            Some(http_request.method().as_str()),
            Some(http_request.uri().path_and_query().map_or("/", |p| p.as_str())),
            Some(http_request.uri().path()),
            Some(http_request.uri().path_and_query().map_or("/", |p| p.as_str())),
            Some(http_request.full_url().authority()),
            Some(http_request.uri().scheme_str().unwrap_or("http")),
            Some(http_request.uri().query().unwrap_or("")),
            None
        );
        debug!("Derived Elements: {:?}", derive_elements);
        derive_elements
    }
}


impl From<&HttpResponse> for DeriveInputElements {
    /**
     * Converts an `HttpResponse` into `DeriveInputElements`.
     *
     * # Arguments
     * `http_request`: The HTTP request to derive elements from.
     *
     * # Returns
     * A new instance of `DeriveInputElements` derived from the HTTP response.
     */
    fn from(http_response: &HttpResponse) -> Self {
        let derive_elements = DeriveInputElements::new(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(http_response.status().as_u16())
        );
        debug!("Derived Elements: {:?}", derive_elements);
        derive_elements
    }
}


/**
 * Generates a SHA-512 digest of the given body.
 *
 * # Arguments
 * `body`: The request body as a byte slice.
 *
 * # Returns
 * A base64 encoded string of the SHA-512 digest.
 */
pub fn generate_digest(body: &[u8]) -> String {
    let mut hasher = Sha512::new();
    hasher.update(body);
    let result = hasher.finalize();
    STANDARD.encode(result)
}

/**
 * Returns a default error response for serialization errors.
 *
 * This function is used when the application fails to convert data to a JSON format.
 *
 * # Returns
 * A string representing the default error response.
 */
pub fn get_serde_conversion_error() -> String {
    "{\"code\": 1006, \"message\": \"Failed to convert data\"}".to_string()
}

/**
* Maps application errors to HTTP status codes.
*
* # Arguments
* `application_error`: The type of error that occurred.
*
* # Returns
* The corresponding HTTP status code.
*/
fn get_statuscode(application_error: &ErrorType) -> StatusCode {
    match application_error {
        ErrorType::Validation | ErrorType::DigestVerification => StatusCode::BAD_REQUEST,
        ErrorType::SignatureVerification => StatusCode::UNAUTHORIZED,
        ErrorType::Initialization | ErrorType::DatabaseError | ErrorType::Application => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorType::NotFound => StatusCode::NOT_FOUND,
        ErrorType::ConstraintViolation => StatusCode::CONFLICT,
    }
}

/**
 * Maps application errors to error codes.
 *
 * # Arguments
 * `application_error`: The type of error that occurred.
 *
 * # Returns
 * The corresponding error code.
 */
fn get_error_code(application_error: &ErrorType) -> u16 {
    match application_error {
        ErrorType::Initialization => 1001,
        ErrorType::DatabaseError => 1003,
        ErrorType::Validation => 1004,
        ErrorType::NotFound => 1005,
        ErrorType::Application => 1006,
        ErrorType::ConstraintViolation => 1007,
        ErrorType::DigestVerification => 1008,
        ErrorType::SignatureVerification => 1009,
    }
}

/***************** Common models *********************/

/**
 * Pagination query parameters for API requests.
 */
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationQuery {
    /**
     * The index of the first item to return.
     */
    pub start_index: Option<i64>,
    /**
     * The size of the page to return.
     */
    pub page_size: Option<i64>,
}

/**
 * Pagination response structure.
 */
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PaginationResponse {
    /**
     * The starting index of the returned items.
     */
    pub start_index: Option<i64>,
    /**
     * The size of the page.
     */
    pub page_size: Option<i64>,
    /**
     * Indicates if there are more items available.
     */
    pub has_more_elements: bool,
}

impl From<PaginationOutput> for PaginationResponse {
    fn from(pagination_output: PaginationOutput) -> Self {
        PaginationResponse { start_index: Some(pagination_output.start_index), page_size: Some(pagination_output.page_size), has_more_elements: pagination_output.has_more }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::model::apperror::ErrorType;

    #[test]
    fn test_get_error_codes() {
        assert_eq!(get_error_code(&ErrorType::Initialization), 1001);
        assert_eq!(get_error_code(&ErrorType::DatabaseError), 1003);
        assert_eq!(get_error_code(&ErrorType::Validation), 1004);
        assert_eq!(get_error_code(&ErrorType::NotFound), 1005);
        assert_eq!(get_error_code(&ErrorType::Application), 1006);
        assert_eq!(get_error_code(&ErrorType::ConstraintViolation), 1007);
    }

    #[test]
    fn test_get_status_codes() {
        assert_eq!(get_statuscode(&ErrorType::Validation), StatusCode::BAD_REQUEST);
        assert_eq!(get_statuscode(&ErrorType::SignatureVerification), StatusCode::UNAUTHORIZED);
        assert_eq!(get_statuscode(&ErrorType::Initialization), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(get_statuscode(&ErrorType::DatabaseError), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(get_statuscode(&ErrorType::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(get_statuscode(&ErrorType::Application), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(get_statuscode(&ErrorType::ConstraintViolation), StatusCode::CONFLICT);
    }

    #[test]
    fn test_application_error_to_response() {
        let error = ApplicationError::new(ErrorType::NotFound, "Resource not found".to_string());
        let response = error.error_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_pagination_response_from_output() {
        let pagination_output = PaginationOutput { start_index: 0, page_size: 10, has_more: true };
        let pagination_response = PaginationResponse::from(pagination_output);
        assert_eq!(pagination_response.start_index, Some(0));
        assert_eq!(pagination_response.page_size, Some(10));
        assert!(pagination_response.has_more_elements);
    }

    #[test]
    fn test_municipality_detail_element_from_type() {
        let detail_type = MunicipalityDetailType { id: 1, name: "Test Municipality".to_string(), created_at: Utc::now(), created_by: "admin".to_string() };
        let detail_element: MunicipalityDetailElement = detail_type.into();
        assert_eq!(detail_element.id, 1);
        assert_eq!(detail_element.name, "Test Municipality");
        assert!(detail_element.created_at.timestamp() > 0);
        assert_eq!(detail_element.created_by, "admin");
    }

    #[test]
    fn test_statistic_detail_element_from_type() {
        let detail_type = StatisticDetailType { id: 1, name: "Test Statistic".to_string(), created_at: Utc::now(), created_by: "admin".to_string() };
        let detail_element: StatisticDetailElement = detail_type.into();
        assert_eq!(detail_element.id, 1);
        assert_eq!(detail_element.name, "Test Statistic");
        assert!(detail_element.created_at.timestamp() > 0);
        assert_eq!(detail_element.created_by, "admin");
    }

    #[test]
    fn test_value_detail_element_from_type() {
        let detail_type = ValueDetailType {
            id: 1,
            municipality_id: 1,
            municipality_name: "Test Municipality".to_string(),
            statistic_id: 1,
            statistic_name: "Test Statistic".to_string(),
            value: Decimal::new(100, 2),
            year: 2023,
            updated_at: Utc::now(),
            created_at: Utc::now(),
            updated_by: "admin".to_string(),
            created_by: "admin".to_string(),
        };
        let detail_element: ValueDetailElement = detail_type.into();
        assert_eq!(detail_element.id, 1);
        assert_eq!(detail_element.municipality_id, 1);
        assert_eq!(detail_element.municipality_name, "Test Municipality");
        assert_eq!(detail_element.statistic_id, 1);
        assert_eq!(detail_element.statistic_name, "Test Statistic");
        assert_eq!(detail_element.value, Decimal::new(100, 2));
        assert_eq!(detail_element.year, 2023);
        assert!(detail_element.updated_at.timestamp() > 0);
        assert!(detail_element.created_at.timestamp() > 0);
        assert_eq!(detail_element.updated_by, "admin");
        assert_eq!(detail_element.created_by, "admin");
    }

    #[test]
    fn test_generate_digest() {
        let body = b"Test body for digest generation";
        let digest = generate_digest(body);
        assert!(!digest.is_empty());
        assert_eq!(digest.len(), 88); // SHA-512 base64 encoded length
        assert_eq!(digest, "FQBDjZib7K6sZVOUimsMY9c8L9i7hss0BHVEGbNJgkTpFVjMZuJEhcuoyySLZjYgIVZ4Q5cqtgVOLyshuWrvWQ==");
    }
}
