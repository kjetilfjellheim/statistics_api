use actix_web::{HttpResponse, ResponseError, http::StatusCode};
use chrono::Utc;
use serde::Serialize;

use crate::model::{apperror::{ApplicationError, ErrorType}, models::{StatisticsDetailType, StatisticsListType}};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticsListResponse {
    /**
     * A vector of StatisticsDetailElement representing the statistics details.
     */
    statistics: Vec<StatisticsDetailElement>,
}

impl StatisticsListResponse {
    /**
     * Creates a new instance of StatisticsListResponse.
     *
     * # Arguments
     * `statistics`: A vector of StatisticsDetailElement representing the statistics details.
     *
     * # Returns
     * A new instance of StatisticsListResponse.
     */
    pub fn new(statistics: Vec<StatisticsDetailElement>) -> Self {
        StatisticsListResponse { statistics }
    }
}

impl From<StatisticsListType> for StatisticsListResponse {
    fn from(statistics_list: StatisticsListType) -> Self {
        let statistics_elements: Vec<StatisticsDetailElement> = statistics_list.statistics.into_iter().map(StatisticsDetailElement::from).collect();
        StatisticsListResponse::new(statistics_elements)
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticsDetailElement {
    id: u64,
    municipality_id: u64,
    municipality_name: String,
    statistic_id: u64,
    statistic_name: String,
    value: f64,
    year: u16,
    updated_at: chrono::DateTime<Utc>,
    created_at: chrono::DateTime<Utc>,
    updated_by: String,
    created_by: String,
}

impl StatisticsDetailElement {
    /**
     * Creates a new instance of StatisticsDetailElement.
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
     * A new instance of StatisticsDetailElement.
     */
    pub fn new(
        id: u64,
        municipality_id: u64,
        municipality_name: String,
        statistic_id: u64,
        statistic_name: String,
        value: f64,
        year: u16,
        updated_at: chrono::DateTime<Utc>,
        created_at: chrono::DateTime<Utc>,
        updated_by: String,
        created_by: String,
    ) -> Self {
        StatisticsDetailElement {
            id,
            municipality_id,
            municipality_name,
            statistic_id,
            statistic_name,
            value,
            year,
            updated_at,
            created_at,
            updated_by,
            created_by,
        }
    }
}

impl From<StatisticsDetailType> for StatisticsDetailElement {
    fn from(stat: StatisticsDetailType) -> Self {
        StatisticsDetailElement::new(
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
        ErrorType::NotImplemented => StatusCode::NOT_IMPLEMENTED,
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
        ErrorType::NotImplemented => 1002,
    }
}
