use actix_web::web::{self, Query};
use chrono::{DateTime, Utc};
use rust_decimal::Decimal;

use crate::{
    api::rest::{PaginationQuery, ValuesListRequest},
    dao::statistics::QueryValuesListDbResp,
};

/***************** Values:list models *********************/

/**
 * Represents the input type for the Values List API.
 */
#[derive(Debug)]
pub struct ValuesListInputType {
    /**
     * Optional municipality ID to filter the values.
     */
    pub id_municipality: Option<i64>,
    /**
     * Optional statistic ID to filter the values.
     */
    pub id_statistic: Option<i64>,
    /**
     * Optional year to filter the values.
     */
    pub year: Option<i64>,
}

/**
 * Converts from web::Json<ValuesListRequest> to ValuesListInputType.
 */
impl From<web::Json<ValuesListRequest>> for ValuesListInputType {
    fn from(request: web::Json<ValuesListRequest>) -> Self {
        ValuesListInputType { id_municipality: request.municipality_id, id_statistic: request.statistic_id, year: request.year }
    }
}

/**
 * Represents the output type for the Values List API.
 */
pub struct ValuesListOutputType {
    /**
     * A list of value details.
     */
    pub statistics: Vec<ValueDetailType>,
    /**
     * Pagination information for the values list.
     */
    pub pagination: PaginationOutput,
}

/**
 * Creates a new ValuesListOutputType.
 *
 * # Arguments
 * `statistics`: A vector of ValueDetailType representing the values.
 * `pagination`: PaginationOutput containing pagination information.
 */
impl ValuesListOutputType {
    pub fn new(statistics: Vec<ValueDetailType>, pagination: PaginationOutput) -> Self {
        ValuesListOutputType { statistics, pagination }
    }
}

/**
 * Represents the details of a value in the Values List API.
 */
pub struct ValueDetailType {
    pub id: u64,
    pub municipality_id: u64,
    pub municipality_name: String,
    pub statistic_id: u64,
    pub statistic_name: String,
    pub value: Decimal,
    pub year: i64,
    pub updated_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub updated_by: String,
    pub created_by: String,
}

impl ValueDetailType {
    /**
     * Creates a new ValueDetailType.
     *
     * # Arguments
     * `id`: The unique identifier for the value.
     * `municipality_id`: The ID of the municipality.
     * `municipality_name`: The name of the municipality.
     * `statistic_id`: The ID of the statistic.
     * `statistic_name`: The name of the statistic.
     * `value`: The value associated with the statistic.
     * `year`: The year of the statistic.
     * `updated_at`: The timestamp when the value was last updated.
     * `created_at`: The timestamp when the value was created.
     * `updated_by`: The user who last updated the value.
     * `created_by`: The user who created the value.
     *
     * # Returns
     * A new instance of ValueDetailType.
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
        updated_at: DateTime<Utc>,
        created_at: DateTime<Utc>,
        updated_by: String,
        created_by: String,
    ) -> Self {
        ValueDetailType { id, municipality_id, municipality_name, statistic_id, statistic_name, value, year, updated_at, created_at, updated_by, created_by }
    }
}

/**
 * Converts from db query.
 */
impl From<QueryValuesListDbResp> for ValueDetailType {
    fn from(value: QueryValuesListDbResp) -> Self {
        ValueDetailType::new(value.0 as u64, value.1 as u64, value.9, value.2 as u64, value.10, value.3, value.4, value.5, value.6, value.7, value.8)
    }
}

/***************** Common models *********************/

/**
 * Input structure for pagination.
 */
#[derive(Debug)]
pub struct PaginationInput {
    /**
     * The starting index for pagination.
     */
    pub start_index: i64,
    /**
     * The number of items per page.
     */
    pub page_size: i64,
}

impl PaginationInput {
    /**
     * Creates a new PaginationInput.
     *
     * # Arguments
     * `start_index`: The starting index for pagination.
     * `page_size`: The number of items per page.
     */
    pub fn new(start_index: i64, page_size: i64) -> Self {
        PaginationInput { start_index, page_size }
    }
}

/**
 * Converts from web query to PaginationInput.
 */
impl From<Query<PaginationQuery>> for PaginationInput {
    fn from(query: Query<PaginationQuery>) -> Self {
        PaginationInput::new(query.start_index.unwrap_or(0), query.page_size.unwrap_or(100))
    }
}

/**
 * Output structure for pagination.
 */
pub struct PaginationOutput {
    pub start_index: i64,
    pub page_size: i64,
    pub has_more: bool,
}

/**
 * Creates a new PaginationOutput.
 *
 * # Arguments
 * `start_index`: The starting index for pagination.
 * `page_size`: The number of items per page.
 * `has_more`: Indicates if there are more items available.
 */
impl PaginationOutput {
    pub fn new(start_index: i64, page_size: i64, has_more: bool) -> Self {
        PaginationOutput { start_index, page_size, has_more }
    }
}
