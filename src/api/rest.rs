use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use chrono::Utc;
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};

use crate::model::{
    apperror::{ApplicationError, ErrorType},
    models::{PaginationOutput, ValueDetailType, ValuesListOutputType},
};

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
     * A vector of StatisticsDetailElement representing the statistics details.
     */
    statistics: Vec<ValueDetailElement>,
    /**
     * Pagination information for the response.
     */
    pagination: PaginationResponse,
}

impl ValuesListResponse {
    /**
     * Creates a new instance of ValuesListResponse.
     *
     * # Arguments
     * `statistics`: A vector of ValueDetailElement representing the statistics details.
     *
     * # Returns
     * A new instance of ValuesListResponse.
     */
    pub fn new(statistics: Vec<ValueDetailElement>, pagination: PaginationResponse) -> Self {
        ValuesListResponse { statistics, pagination }
    }
}

/**
 * Converts from ValuesListOutputType to ValuesListResponse.
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
    id: u64,
    /**
     * The ID of the municipality.
     */
    municipality_id: u64,
    /**
     * The name of the municipality.
     */
    municipality_name: String,
    /**
     * The ID of the statistic.
     */
    statistic_id: u64,
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
     * Creates a new instance of ValueDetailElement.
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
     * A new instance of ValueDetailElement.
     */
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        municipality_id: u64,
        municipality_name: String,
        statistic_id: u64,
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
 * Converts from ValueDetailType to ValueDetailElement.
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
        HttpResponse::build(get_statuscode(&self.error_type.clone())).json(&error_response)
    }
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
        ErrorType::JwtAuthorization => StatusCode::UNAUTHORIZED,
        ErrorType::Initialization => StatusCode::INTERNAL_SERVER_ERROR,
        ErrorType::DatabaseError => StatusCode::INTERNAL_SERVER_ERROR,
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
        ErrorType::JwtAuthorization => 1000,
        ErrorType::Initialization => 1001,
        ErrorType::DatabaseError => 1003,
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
